/* SPDX-License-Identifier: BSD-3-Clause */
#include "config.h"
#ifdef IOR_HAVE_SPLICE
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#endif
#include "ior_backend.h"
#include "ior_threads_pool.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <time.h>
#include <poll.h>
#include <limits.h>

#ifndef __linux__
typedef off_t loff_t;
#endif

// Forward declarations
static void *ior_threads_pool_worker_thread_func(void *arg);
static void ior_threads_pool_process_chain(ior_threads_pool *pool, ior_work *head);
static void ior_threads_pool_process_single_sqe(
		ior_threads_pool *pool, const ior_sqe *sqe, ior_cqe *cqe);
static void ior_threads_pool_process_single_sqe_timed(
		ior_threads_pool *pool, const ior_sqe *sqe, ior_cqe *cqe, int timeout_ms);
static void ior_threads_pool_post_completion(ior_threads_pool *pool, const ior_cqe *cqe);
static int ior_threads_pool_try_create_thread(ior_threads_pool *pool);
static void *ior_threads_pool_timer_thread_func(void *arg);
static void ior_threads_pool_arm_timer(ior_threads_pool *pool, ior_work *work);
static void ior_threads_pool_finish_op(ior_threads_pool *pool, ior_work *work, const ior_cqe *cqe);
static uint64_t ior_threads_pool_monotonic_ns(void);
#ifndef IOR_HAVE_SPLICE
static ssize_t ior_threads_pool_emulate_splice(
		int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);
#endif

// Round up to a power of two (>= 1).
static uint32_t ior_threads_pool_round_up_pow2(uint32_t n)
{
	if (n < 2) {
		return 1;
	}
	n--;
	n |= n >> 1;
	n |= n >> 2;
	n |= n >> 4;
	n |= n >> 8;
	n |= n >> 16;
	return n + 1;
}

// ===== Work-item pool, dispatch FIFO and drain tracking =====
// All of the work-pool / dispatch helpers below must be called with pool_lock
// held; the drain helpers take drain_lock themselves.

static ior_work *ior_threads_pool_work_alloc(ior_threads_pool *pool)
{
	ior_work *w = pool->work_free;
	pool->work_free = w->next;
	return w;
}

static void ior_threads_pool_work_release(ior_threads_pool *pool, ior_work *w)
{
	w->next = pool->work_free;
	pool->work_free = w;
}

static void ior_threads_pool_disp_push(ior_threads_pool *pool, ior_work *w)
{
	w->next = NULL;
	if (pool->disp_tail) {
		pool->disp_tail->next = w;
	} else {
		pool->disp_head = w;
	}
	pool->disp_tail = w;
}

static ior_work *ior_threads_pool_disp_pop(ior_threads_pool *pool)
{
	ior_work *w = pool->disp_head;
	if (w) {
		pool->disp_head = w->next;
		if (!pool->disp_head) {
			pool->disp_tail = NULL;
		}
	}
	return w;
}

// Mark a submission sequence completed and advance the contiguous drain front,
// waking any IO_DRAIN op waiting for earlier ops to finish.
static void ior_threads_pool_drain_complete(ior_threads_pool *pool, uint64_t seq)
{
	pthread_mutex_lock(&pool->drain_lock);
	pool->drain_done[seq & pool->drain_mask] = 1;
	while (pool->drain_done[pool->drain_upto & pool->drain_mask]) {
		pool->drain_done[pool->drain_upto & pool->drain_mask] = 0;
		pool->drain_upto++;
	}
	pthread_cond_broadcast(&pool->drain_cond);
	pthread_mutex_unlock(&pool->drain_lock);
}

// Block until every op submitted before `seq` has completed (for IO_DRAIN).
static void ior_threads_pool_drain_wait(ior_threads_pool *pool, uint64_t seq)
{
	pthread_mutex_lock(&pool->drain_lock);
	while (pool->drain_upto < seq) {
		pthread_cond_wait(&pool->drain_cond, &pool->drain_lock);
	}
	pthread_mutex_unlock(&pool->drain_lock);
}

/*
 * Retire one operation: post its completion, record it for drain ordering,
 * return its work item to the pool, and drop the in-flight/outstanding counts so
 * get_sqe and worker provisioning see the freed capacity.
 */
static void ior_threads_pool_finish_op(ior_threads_pool *pool, ior_work *work, const ior_cqe *cqe)
{
	ior_threads_pool_post_completion(pool, cqe);
	ior_threads_pool_drain_complete(pool, work->seq);

	pthread_mutex_lock(&pool->pool_lock);
	ior_threads_pool_work_release(pool, work);
	pthread_mutex_unlock(&pool->pool_lock);

	atomic_fetch_sub(&pool->outstanding, 1);
	atomic_fetch_sub(&pool->num_inflight, 1);
}

ior_threads_pool *ior_threads_pool_create(ior_ctx_threads *ctx, uint32_t num_threads)
{
	ior_threads_pool_config config = {
		.min_threads = 0,
		.max_threads = num_threads > 0 ? num_threads : 32,
		.stack_size = 0,
		.thread_priority = 0,
	};

	return ior_threads_pool_create_ex(ctx, &config);
}

ior_threads_pool *ior_threads_pool_create_ex(
		ior_ctx_threads *ctx, const ior_threads_pool_config *config)
{
	if (!ctx || !config) {
		return NULL;
	}

	ior_threads_pool *pool = calloc(1, sizeof(*pool));
	if (!pool) {
		return NULL;
	}

	pool->ctx = ctx;
	pool->num_threads_min = config->min_threads;
	pool->num_threads_max = config->max_threads;

	if (pool->num_threads_max == 0) {
		pool->num_threads_max = 32;
	}

	if (pool->num_threads_min > pool->num_threads_max) {
		pool->num_threads_min = pool->num_threads_max;
	}

	if (pthread_mutex_init(&pool->pool_lock, NULL) != 0) {
		free(pool);
		return NULL;
	}

	if (pthread_cond_init(&pool->work_cond, NULL) != 0) {
		pthread_mutex_destroy(&pool->pool_lock);
		free(pool);
		return NULL;
	}

	atomic_init(&pool->shutdown, 0);
	atomic_init(&pool->tasks_completed, 0);

	pool->threads = NULL;
	pool->num_threads_current = 0;
	pool->num_threads_idle = 0;

	/*
	 * Work-item pool + dispatch FIFO (free-at-submit). Capacity matches the CQ
	 * (the in-flight bound). The drain bitmap is sized past the worst-case
	 * in-flight seq span so sequence numbers never alias.
	 */
	pool->work_cap = ctx->cq_ring.size;
	pool->work_free = NULL;
	pool->disp_head = NULL;
	pool->disp_tail = NULL;
	pool->next_seq = 0;
	atomic_init(&pool->outstanding, 0);
	atomic_init(&pool->num_inflight, 0);
	pool->drain_upto = 0;
	pool->drain_done = NULL;

	pool->work_items = calloc(pool->work_cap, sizeof(*pool->work_items));
	uint32_t drain_cap = ior_threads_pool_round_up_pow2(pool->work_cap * 2);
	pool->drain_mask = drain_cap - 1;
	pool->drain_done = calloc(drain_cap, sizeof(*pool->drain_done));
	if (!pool->work_items || !pool->drain_done
			|| pthread_mutex_init(&pool->drain_lock, NULL) != 0) {
		free(pool->drain_done);
		free(pool->work_items);
		pthread_cond_destroy(&pool->work_cond);
		pthread_mutex_destroy(&pool->pool_lock);
		free(pool);
		return NULL;
	}
	if (pthread_cond_init(&pool->drain_cond, NULL) != 0) {
		pthread_mutex_destroy(&pool->drain_lock);
		free(pool->drain_done);
		free(pool->work_items);
		pthread_cond_destroy(&pool->work_cond);
		pthread_mutex_destroy(&pool->pool_lock);
		free(pool);
		return NULL;
	}
	for (uint32_t i = 0; i < pool->work_cap; i++) {
		pool->work_items[i].next = pool->work_free;
		pool->work_free = &pool->work_items[i];
	}

	// Timer manager: small min-heap plus a dedicated thread.
	pool->timer_thread_started = 0;
	pool->timer_heap = NULL;
	pool->timer_heap_len = 0;
	pool->timer_heap_cap = 16;

	if (pthread_mutex_init(&pool->timer_lock, NULL) != 0) {
		pthread_cond_destroy(&pool->work_cond);
		pthread_mutex_destroy(&pool->pool_lock);
		free(pool);
		return NULL;
	}

	if (pthread_cond_init(&pool->timer_cond, NULL) != 0) {
		pthread_mutex_destroy(&pool->timer_lock);
		pthread_cond_destroy(&pool->work_cond);
		pthread_mutex_destroy(&pool->pool_lock);
		free(pool);
		return NULL;
	}

	pool->timer_heap = calloc(pool->timer_heap_cap, sizeof(*pool->timer_heap));
	if (!pool->timer_heap) {
		pthread_cond_destroy(&pool->timer_cond);
		pthread_mutex_destroy(&pool->timer_lock);
		pthread_cond_destroy(&pool->work_cond);
		pthread_mutex_destroy(&pool->pool_lock);
		free(pool);
		return NULL;
	}

	if (pthread_create(&pool->timer_thread, NULL, ior_threads_pool_timer_thread_func, pool) != 0) {
		free(pool->timer_heap);
		pthread_cond_destroy(&pool->timer_cond);
		pthread_mutex_destroy(&pool->timer_lock);
		pthread_cond_destroy(&pool->work_cond);
		pthread_mutex_destroy(&pool->pool_lock);
		free(pool);
		return NULL;
	}
	pool->timer_thread_started = 1;

	// Create minimum number of threads if specified
	pthread_attr_t attr;
	pthread_attr_init(&attr);

	if (config->stack_size > 0) {
		pthread_attr_setstacksize(&attr, config->stack_size);
	}

	pthread_mutex_lock(&pool->pool_lock);
	for (uint32_t i = 0; i < pool->num_threads_min; i++) {
		ior_threads_pool_worker_thread_t *worker = calloc(1, sizeof(*worker));
		if (!worker) {
			break;
		}

		worker->pool = pool;
		atomic_init(&worker->state, IOR_THREADS_POOL_THREAD_STATE_IDLE);

		int ret = pthread_create(
				&worker->thread_id, &attr, ior_threads_pool_worker_thread_func, worker);
		if (ret != 0) {
			free(worker);
			break;
		}

		worker->next = pool->threads;
		pool->threads = worker;
		pool->num_threads_current++;
		pool->num_threads_idle++;
	}
	pthread_mutex_unlock(&pool->pool_lock);

	pthread_attr_destroy(&attr);

	return pool;
}

void ior_threads_pool_notify(ior_threads_pool *pool, uint32_t count)
{
	(void) count;
	if (!pool) {
		return;
	}

	ior_ctx_threads *ctx = pool->ctx;

	pthread_mutex_lock(&pool->pool_lock);

	/*
	 * Copy every newly staged SQE out of the ring into a work item and enqueue
	 * it, freeing the SQ slots immediately. Consecutive IO_LINK ops form one
	 * chain: only the head is enqueued, the rest hang off head->chain, so a
	 * worker drains a chain as a unit (no mid-chain race).
	 */
	uint32_t consumed = atomic_load_explicit(&ctx->sq_ring.consumed, memory_order_relaxed);
	uint32_t cached = atomic_load_explicit(&ctx->sq_ring.cached_tail, memory_order_acquire);
	uint32_t n = cached - consumed;
	const ior_sqe *sqes = (const ior_sqe *) ctx->sq_ring.entries;

	ior_work *prev = NULL;
	int prev_link = 0;
	for (uint32_t p = consumed; p != cached; p++) {
		ior_work *w = ior_threads_pool_work_alloc(pool);
		w->sqe = sqes[p & ctx->sq_ring.mask];
		w->seq = pool->next_seq++;
		w->chain = NULL;
		int has_link = (w->sqe.threads.flags & IOR_SQE_IO_LINK) != 0;
		if (prev_link) {
			prev->chain = w;
		} else {
			ior_threads_pool_disp_push(pool, w);
		}
		prev = w;
		prev_link = has_link;
	}

	atomic_fetch_add(&pool->num_inflight, n);

	/*
	 * Keep one worker thread per in-flight op (capped at max). A blocking op
	 * holds its thread until it completes, so matching threads to the in-flight
	 * count guarantees every op - including a newer one behind a blocked op - has
	 * a thread to run it.
	 */
	uint32_t want = atomic_load(&pool->num_inflight);
	if (want > pool->num_threads_max) {
		want = pool->num_threads_max;
	}
	while (pool->num_threads_current < want) {
		if (ior_threads_pool_try_create_thread(pool) != 0) {
			break;
		}
	}

	pthread_cond_broadcast(&pool->work_cond);
	pthread_mutex_unlock(&pool->pool_lock);

	// Staging slots are now free for reuse by get_sqe.
	ior_threads_ring_consume(&ctx->sq_ring);
}

void ior_threads_pool_destroy(ior_threads_pool *pool)
{
	if (!pool) {
		return;
	}

	// Signal shutdown
	atomic_store(&pool->shutdown, 1);

	// Wake the timer thread so it observes shutdown immediately rather than
	// sleeping out a pending deadline, then join it. Pending timers are
	// dropped without posting completions (the queue is being torn down).
	if (pool->timer_thread_started) {
		pthread_mutex_lock(&pool->timer_lock);
		pthread_cond_signal(&pool->timer_cond);
		pthread_mutex_unlock(&pool->timer_lock);
		pthread_join(pool->timer_thread, NULL);
	}
	pthread_cond_destroy(&pool->timer_cond);
	pthread_mutex_destroy(&pool->timer_lock);
	free(pool->timer_heap);
	pool->timer_heap = NULL;

	// Wake all threads
	pthread_mutex_lock(&pool->pool_lock);
	pthread_cond_broadcast(&pool->work_cond);
	pthread_mutex_unlock(&pool->pool_lock);

	// Wait for all threads to finish
	pthread_mutex_lock(&pool->pool_lock);
	ior_threads_pool_worker_thread_t *worker = pool->threads;
	while (worker) {
		ior_threads_pool_worker_thread_t *next = worker->next;
		pthread_mutex_unlock(&pool->pool_lock);

		pthread_join(worker->thread_id, NULL);
		free(worker);

		pthread_mutex_lock(&pool->pool_lock);
		worker = next;
	}
	pool->threads = NULL;
	pthread_mutex_unlock(&pool->pool_lock);

	// Cleanup
	pthread_cond_destroy(&pool->drain_cond);
	pthread_mutex_destroy(&pool->drain_lock);
	free(pool->drain_done);
	free(pool->work_items);
	pthread_cond_destroy(&pool->work_cond);
	pthread_mutex_destroy(&pool->pool_lock);
	free(pool);
}

uint32_t ior_threads_pool_get_num_threads(ior_threads_pool *pool)
{
	if (!pool) {
		return 0;
	}

	pthread_mutex_lock(&pool->pool_lock);
	uint32_t count = pool->num_threads_current;
	pthread_mutex_unlock(&pool->pool_lock);

	return count;
}

void ior_threads_pool_get_stats(ior_threads_pool *pool, ior_threads_pool_stats *stats)
{
	if (!pool || !stats) {
		return;
	}

	memset(stats, 0, sizeof(*stats));

	pthread_mutex_lock(&pool->pool_lock);
	stats->threads_active = pool->num_threads_current - pool->num_threads_idle;
	stats->threads_idle = pool->num_threads_idle;
	pthread_mutex_unlock(&pool->pool_lock);

	stats->tasks_completed = atomic_load(&pool->tasks_completed);
	stats->tasks_pending = ior_threads_ring_count(&pool->ctx->sq_ring);
}

// ===== Worker Thread Implementation =====

static void *ior_threads_pool_worker_thread_func(void *arg)
{
	ior_threads_pool_worker_thread_t *worker = (ior_threads_pool_worker_thread_t *) arg;
	ior_threads_pool *pool = worker->pool;

	struct timeval last_work_time;
	gettimeofday(&last_work_time, NULL);
	const uint32_t idle_timeout_ms = 30000; // 30 seconds

	IOR_LOG_TRACE("thread created");

	while (1) {
		pthread_mutex_lock(&pool->pool_lock);

		// Wait for a dispatched chain, exiting on shutdown or after being idle
		// too long (excess thread above the minimum).
		while (!pool->disp_head) {
			if (atomic_load(&pool->shutdown)) {
				pthread_mutex_unlock(&pool->pool_lock);
				return NULL;
			}

			struct timeval now;
			gettimeofday(&now, NULL);
			long idle_ms = (now.tv_sec - last_work_time.tv_sec) * 1000
					+ (now.tv_usec - last_work_time.tv_usec) / 1000;
			if (pool->num_threads_current > pool->num_threads_min
					&& idle_ms > (long) idle_timeout_ms) {
				atomic_store(&worker->state, IOR_THREADS_POOL_THREAD_STATE_STOPPING);
				pool->num_threads_current--;
				pool->num_threads_idle--;
				pthread_mutex_unlock(&pool->pool_lock);
				return NULL;
			}

			struct timespec timeout;
			timeout.tv_sec = now.tv_sec + 1;
			timeout.tv_nsec = now.tv_usec * 1000;
			pthread_cond_timedwait(&pool->work_cond, &pool->pool_lock, &timeout);
		}

		ior_work *head = ior_threads_pool_disp_pop(pool);
		pool->num_threads_idle--;
		pthread_mutex_unlock(&pool->pool_lock);

		atomic_store(&worker->state, IOR_THREADS_POOL_THREAD_STATE_ACTIVE);
		gettimeofday(&last_work_time, NULL);

		ior_threads_pool_process_chain(pool, head);

		atomic_store(&worker->state, IOR_THREADS_POOL_THREAD_STATE_IDLE);
		pthread_mutex_lock(&pool->pool_lock);
		pool->num_threads_idle++;
		pthread_mutex_unlock(&pool->pool_lock);
	}

	return NULL;
}

// ===== Operation Processing =====

/*
 * Process one dispatched work chain. A chain is a run of IO_LINK ops claimed as
 * a unit (head plus head->chain->...), so the whole chain is owned by this one
 * worker - no other worker can run a mid-chain op out of order. Ops run in order
 * until one fails, after which the remainder are cancelled (-ECANCELED), matching
 * io_uring link semantics.
 */
static void ior_threads_pool_process_chain(ior_threads_pool *pool, ior_work *head)
{
	uint64_t count = 0;
	ior_work *w = head;
	int cancel = 0; // a prior linked op failed/timed out; cancel the rest

	while (w) {
		ior_work *next = w->chain;

		if (cancel) {
			ior_cqe cqe;
			memset(&cqe, 0, sizeof(cqe));
			cqe.threads.user_data = w->sqe.threads.user_data;
			cqe.threads.res = -ECANCELED;
			ior_threads_pool_finish_op(pool, w, &cqe);
			count++;
			w = next;
			continue;
		}

		// DRAIN: wait until every earlier-submitted op has completed.
		if (w->sqe.threads.flags & IOR_SQE_IO_DRAIN) {
			ior_threads_pool_drain_wait(pool, w->seq);
		}

		// Timers run on the dedicated timer thread, which finishes the op on
		// expiry. A timeout completes with -ETIME, breaking any following link.
		if (w->sqe.threads.opcode == IOR_OP_TIMER) {
			int linked = (w->sqe.threads.flags & IOR_SQE_IO_LINK) != 0;
			ior_threads_pool_arm_timer(pool, w);
			count++;
			if (linked) {
				cancel = 1;
			}
			w = next;
			continue;
		}

		int has_link = (w->sqe.threads.flags & IOR_SQE_IO_LINK) != 0;

		/*
		 * Link timeout: a linked op immediately followed by a LINK_TIMEOUT runs
		 * poll-gated against the timeout's deadline; both are completed here. The
		 * pair is owned by this worker (claimed as one chain), so there is no race
		 * over the link-timeout slot.
		 */
		if (has_link && next && next->sqe.threads.opcode == IOR_OP_LINK_TIMEOUT) {
			// Capture the post-timeout successor before finishing (which frees the
			// work items and may hand them to another thread).
			ior_work *after = next->chain;
			ior_timespec *ts = (ior_timespec *) (uintptr_t) next->sqe.threads.addr;
			int timeout_ms = -1;
			if (ts) {
				uint64_t ns = (uint64_t) ts->tv_sec * 1000000000ULL + (uint64_t) ts->tv_nsec;
				if (next->sqe.threads.timeout_flags & IOR_TIMEOUT_ABS) {
					uint64_t now = ior_threads_pool_monotonic_ns();
					ns = (ns > now) ? ns - now : 0;
				}
				uint64_t ms = (ns + 999999ULL) / 1000000ULL;
				timeout_ms = ms > (uint64_t) INT_MAX ? INT_MAX : (int) ms;
			}

			ior_cqe gcqe;
			ior_threads_pool_process_single_sqe_timed(pool, &w->sqe, &gcqe, timeout_ms);
			int cancelled = (gcqe.threads.res == -ECANCELED);
			ior_threads_pool_finish_op(pool, w, &gcqe);
			count++;

			// -ETIME if the timeout cancelled the guarded op, else -ECANCELED.
			ior_cqe lcqe;
			memset(&lcqe, 0, sizeof(lcqe));
			lcqe.threads.user_data = next->sqe.threads.user_data;
			lcqe.threads.res = cancelled ? -ETIME : -ECANCELED;
			ior_threads_pool_finish_op(pool, next, &lcqe);
			count++;

			if (cancelled) {
				cancel = 1; // guarded op was cancelled; break the rest of the chain
			}
			w = after;
			continue;
		}

		// Normal op.
		ior_cqe cqe;
		ior_threads_pool_process_single_sqe(pool, &w->sqe, &cqe);
		ior_threads_pool_finish_op(pool, w, &cqe);
		count++;

		if (has_link && cqe.threads.res < 0) {
			cancel = 1; // a failed linked op breaks the chain
		}
		w = next;
	}

	atomic_fetch_add(&pool->tasks_completed, count);
}

/*
 * Run a guarded op bounded by a link timeout. For read/recv (POLLIN) and
 * write/send (POLLOUT) on pollable descriptors, wait for readiness up to
 * timeout_ms; on timeout the op is cancelled with -ECANCELED. Other opcodes
 * cannot be poll-gated and run to completion unbounded (the link timeout then
 * resolves as "op finished first"). On a regular file the poll returns ready
 * immediately, so the op runs uncancelled - matching io_uring.
 */
static void ior_threads_pool_process_single_sqe_timed(
		ior_threads_pool *pool, const ior_sqe *sqe, ior_cqe *cqe, int timeout_ms)
{
	short events;
	switch (sqe->threads.opcode) {
		case IOR_OP_READ:
		case IOR_OP_RECV:
			events = POLLIN;
			break;
		case IOR_OP_WRITE:
		case IOR_OP_SEND:
			events = POLLOUT;
			break;
		default:
			ior_threads_pool_process_single_sqe(pool, sqe, cqe);
			return;
	}

	struct pollfd pfd = { .fd = sqe->threads.fd, .events = events };
	int pret;
	do {
		pret = poll(&pfd, 1, timeout_ms);
	} while (pret < 0 && errno == EINTR);

	if (pret > 0) {
		// Ready: the syscall will not block significantly.
		ior_threads_pool_process_single_sqe(pool, sqe, cqe);
		return;
	}

	memset(cqe, 0, sizeof(*cqe));
	cqe->threads.user_data = sqe->threads.user_data;
	// pret == 0 is the deadline (cancel); pret < 0 is a poll error.
	cqe->threads.res = (pret == 0) ? -ECANCELED : -errno;
}

static void ior_threads_pool_process_single_sqe(
		ior_threads_pool *pool, const ior_sqe *sqe, ior_cqe *cqe)
{
	(void) pool;

	memset(cqe, 0, sizeof(*cqe));
	cqe->threads.user_data = sqe->threads.user_data;
	cqe->threads.flags = 0;

	// Process based on operation type
	switch (sqe->threads.opcode) {
		case IOR_OP_NOP:
			cqe->threads.res = 0;
			break;

		case IOR_OP_READ: {
			IOR_LOG_TRACE("read start: fd=%d, addr=%p, len=%u, flags=%lu", sqe->threads.fd,
					(void *) (uintptr_t) sqe->threads.addr, sqe->threads.len, sqe->threads.off);
			void *buf = (void *) (uintptr_t) sqe->threads.addr;
			ssize_t ret;
			/*
			 * Use pread() for seekable fds (regular files). For non-seekable
			 * fds (sockets, pipes, FIFOs) pread() fails with ESPIPE, so fall
			 * back to read(), which uses the fd's own position. The explicit
			 * IOR_OFF_NONE sentinel also selects read() directly. This matches
			 * io_uring, whose read op works uniformly on files and sockets.
			 */
			if (sqe->threads.off == IOR_OFF_NONE) {
				ret = read(sqe->threads.fd, buf, sqe->threads.len);
			} else {
				ret = pread(sqe->threads.fd, buf, sqe->threads.len, sqe->threads.off);
				if (ret < 0 && errno == ESPIPE) {
					ret = read(sqe->threads.fd, buf, sqe->threads.len);
				}
			}
			cqe->threads.res = (ret < 0) ? -errno : ret;
			IOR_LOG_TRACE("read end: res=%d", cqe->threads.res);
			break;
		}

		case IOR_OP_WRITE: {
			IOR_LOG_TRACE("write start: fd=%d, addr=%p, len=%u, flags=%lu", sqe->threads.fd,
					(void *) (uintptr_t) sqe->threads.addr, sqe->threads.len, sqe->threads.off);
			const void *buf = (const void *) (uintptr_t) sqe->threads.addr;
			ssize_t ret;
			/* See IOR_OP_READ above: pwrite() for seekable fds, write() for
			 * non-seekable ones (sockets/pipes) or the IOR_OFF_NONE sentinel. */
			if (sqe->threads.off == IOR_OFF_NONE) {
				ret = write(sqe->threads.fd, buf, sqe->threads.len);
			} else {
				ret = pwrite(sqe->threads.fd, buf, sqe->threads.len, sqe->threads.off);
				if (ret < 0 && errno == ESPIPE) {
					ret = write(sqe->threads.fd, buf, sqe->threads.len);
				}
			}
			cqe->threads.res = (ret < 0) ? -errno : ret;
			IOR_LOG_TRACE("write end: res=%d", cqe->threads.res);
			break;
		}

		case IOR_OP_SPLICE: {
			int fd_in = sqe->threads.splice_fd_in, fd_out = sqe->threads.fd;
			loff_t *off_in = sqe->threads.splice_off_in == IOR_OFF_NONE
					? NULL
					: (loff_t *) sqe->threads.splice_off_in;
			loff_t *off_out = sqe->threads.off == IOR_OFF_NONE ? NULL : (loff_t *) sqe->threads.off;
			IOR_LOG_TRACE("splice start: fd_in=%d, off_in=%lu, fd_out=%d, off_out=%lu, size=%u, "
						  "flags=%u",
					fd_in, sqe->threads.splice_off_in, fd_out, sqe->threads.off, sqe->threads.len,
					sqe->threads.splice_flags);
#ifdef IOR_HAVE_SPLICE
			ssize_t ret = splice(
					fd_in, off_in, fd_out, off_out, sqe->threads.len, sqe->threads.splice_flags);
#else
			// Emulate splice using read/write loop
			ssize_t ret = ior_threads_pool_emulate_splice(
					fd_in, off_in, fd_out, off_out, sqe->threads.len, sqe->threads.splice_flags);
#endif
			cqe->threads.res = (ret < 0) ? -errno : ret;
			IOR_LOG_TRACE("splice end: res=%d", cqe->threads.res);
			break;
		}

		case IOR_OP_SEND: {
			IOR_LOG_TRACE("send start: fd=%d, addr=%p, len=%u, flags=%u", sqe->threads.fd,
					(void *) (uintptr_t) sqe->threads.addr, sqe->threads.len,
					sqe->threads.rw_flags);
			const void *buf = (const void *) (uintptr_t) sqe->threads.addr;
			ssize_t ret = send(sqe->threads.fd, buf, sqe->threads.len, (int) sqe->threads.rw_flags);
			cqe->threads.res = (ret < 0) ? -errno : ret;
			IOR_LOG_TRACE("send end: res=%d", cqe->threads.res);
			break;
		}

		case IOR_OP_RECV: {
			IOR_LOG_TRACE("recv start: fd=%d, addr=%p, len=%u, flags=%u", sqe->threads.fd,
					(void *) (uintptr_t) sqe->threads.addr, sqe->threads.len,
					sqe->threads.rw_flags);
			void *buf = (void *) (uintptr_t) sqe->threads.addr;
			ssize_t ret = recv(sqe->threads.fd, buf, sqe->threads.len, (int) sqe->threads.rw_flags);
			cqe->threads.res = (ret < 0) ? -errno : ret;
			IOR_LOG_TRACE("recv end: res=%d", cqe->threads.res);
			break;
		}

		case IOR_OP_LINK_TIMEOUT:
			// A link timeout is normally consumed alongside its guarded op in
			// process_sqe_chain. Reaching here means it was picked standalone;
			// resolve it as "guarded op already finished" rather than failing.
			cqe->threads.res = -ECANCELED;
			break;

		case IOR_OP_ACCEPT:
		case IOR_OP_CONNECT:
		case IOR_OP_LISTEN:
		case IOR_OP_BIND:
			cqe->threads.res = -ENOSYS;
			break;

		default:
			cqe->threads.res = -EINVAL;
			break;
	}
}

static void ior_threads_pool_post_completion(ior_threads_pool *pool, const ior_cqe *cqe)
{
	ior_ctx_threads *ctx = pool->ctx;

	// Try to post CQE to completion ring
	int ret = ior_threads_ring_post_cqe(&ctx->cq_ring, cqe);

	if (ret == -EOVERFLOW) {
		IOR_LOG_WARN("cqe overlow");
		// CQ ring full - exponential backoff
		int backoff_us = 100;
		const int max_backoff_us = 10000;

		while (ior_threads_ring_post_cqe(&ctx->cq_ring, cqe) == -EOVERFLOW) {
			usleep(backoff_us);

			if (backoff_us < max_backoff_us) {
				backoff_us *= 2;
			}

			// Signal event to wake consumer
			ior_threads_event_signal(&ctx->event);
		}
	}

	IOR_LOG_TRACE("signaling completion");
	// Signal event to wake waiting thread
	ior_threads_event_signal(&ctx->event);
}

static int ior_threads_pool_try_create_thread(ior_threads_pool *pool)
{
	// Must be called with pool_lock held

	if (pool->num_threads_current >= pool->num_threads_max) {
		return -EAGAIN;
	}

	ior_threads_pool_worker_thread_t *worker = calloc(1, sizeof(*worker));
	if (!worker) {
		return -ENOMEM;
	}

	worker->pool = pool;
	atomic_init(&worker->state, IOR_THREADS_POOL_THREAD_STATE_IDLE);

	int ret = pthread_create(&worker->thread_id, NULL, ior_threads_pool_worker_thread_func, worker);
	if (ret != 0) {
		free(worker);
		return -ret;
	}

	// Add to linked list
	worker->next = pool->threads;
	pool->threads = worker;
	pool->num_threads_current++;
	pool->num_threads_idle++;

	return 0;
}

// ===== Timer Thread =====

static uint64_t ior_threads_pool_monotonic_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

/* Min-heap keyed on deadline_ns. All helpers run under pool->timer_lock. */
static void ior_threads_pool_timer_swap(ior_threads_pool *pool, uint32_t i, uint32_t j)
{
	ior_threads_pool_timer tmp = pool->timer_heap[i];
	pool->timer_heap[i] = pool->timer_heap[j];
	pool->timer_heap[j] = tmp;
}

static void ior_threads_pool_timer_sift_up(ior_threads_pool *pool, uint32_t idx)
{
	while (idx > 0) {
		uint32_t parent = (idx - 1) / 2;
		if (pool->timer_heap[idx].deadline_ns >= pool->timer_heap[parent].deadline_ns) {
			break;
		}
		ior_threads_pool_timer_swap(pool, idx, parent);
		idx = parent;
	}
}

static void ior_threads_pool_timer_sift_down(ior_threads_pool *pool, uint32_t idx)
{
	uint32_t len = pool->timer_heap_len;
	while (1) {
		uint32_t left = 2 * idx + 1;
		uint32_t right = 2 * idx + 2;
		uint32_t smallest = idx;

		if (left < len
				&& pool->timer_heap[left].deadline_ns < pool->timer_heap[smallest].deadline_ns) {
			smallest = left;
		}
		if (right < len
				&& pool->timer_heap[right].deadline_ns < pool->timer_heap[smallest].deadline_ns) {
			smallest = right;
		}
		if (smallest == idx) {
			break;
		}
		ior_threads_pool_timer_swap(pool, idx, smallest);
		idx = smallest;
	}
}

static int ior_threads_pool_timer_push(ior_threads_pool *pool, ior_threads_pool_timer timer)
{
	if (pool->timer_heap_len >= pool->timer_heap_cap) {
		uint32_t new_cap = pool->timer_heap_cap * 2;
		ior_threads_pool_timer *new_heap = realloc(pool->timer_heap, new_cap * sizeof(*new_heap));
		if (!new_heap) {
			return -ENOMEM;
		}
		pool->timer_heap = new_heap;
		pool->timer_heap_cap = new_cap;
	}

	pool->timer_heap[pool->timer_heap_len] = timer;
	ior_threads_pool_timer_sift_up(pool, pool->timer_heap_len);
	pool->timer_heap_len++;
	return 0;
}

static ior_threads_pool_timer ior_threads_pool_timer_pop(ior_threads_pool *pool)
{
	ior_threads_pool_timer top = pool->timer_heap[0];
	pool->timer_heap_len--;
	if (pool->timer_heap_len > 0) {
		pool->timer_heap[0] = pool->timer_heap[pool->timer_heap_len];
		ior_threads_pool_timer_sift_down(pool, 0);
	}
	return top;
}

/*
 * Arm a timeout. Validates the timespec and enqueues the work item for the timer
 * thread, which finishes it on expiry. Invalid timespecs (and a heap allocation
 * failure) finish inline so the caller never has to special-case them.
 */
static void ior_threads_pool_arm_timer(ior_threads_pool *pool, ior_work *work)
{
	ior_timespec *ts = (ior_timespec *) (uintptr_t) work->sqe.threads.addr;
	int err = 0;

	if (!ts || ts->tv_sec < 0 || ts->tv_nsec < 0 || ts->tv_nsec >= 1000000000L) {
		err = EINVAL;
	}

	if (!err) {
		// IOR_TIMEOUT_ABS: ts is an absolute CLOCK_MONOTONIC deadline; otherwise
		// it is a relative duration from now.
		uint64_t ts_ns = (uint64_t) ts->tv_sec * 1000000000ULL + (uint64_t) ts->tv_nsec;
		uint64_t deadline_ns = (work->sqe.threads.timeout_flags & IOR_TIMEOUT_ABS)
				? ts_ns
				: ior_threads_pool_monotonic_ns() + ts_ns;

		ior_threads_pool_timer timer = {
			.deadline_ns = deadline_ns,
			.work = work,
		};

		pthread_mutex_lock(&pool->timer_lock);
		int ret = ior_threads_pool_timer_push(pool, timer);
		if (ret == 0) {
			pthread_cond_signal(&pool->timer_cond);
		}
		pthread_mutex_unlock(&pool->timer_lock);

		if (ret < 0) {
			err = ENOMEM;
		}
	}

	if (err) {
		ior_cqe cqe;
		memset(&cqe, 0, sizeof(cqe));
		cqe.threads.user_data = work->sqe.threads.user_data;
		cqe.threads.res = -err;
		ior_threads_pool_finish_op(pool, work, &cqe);
	}
}

static void *ior_threads_pool_timer_thread_func(void *arg)
{
	ior_threads_pool *pool = (ior_threads_pool *) arg;

	IOR_LOG_TRACE("timer thread created");

	pthread_mutex_lock(&pool->timer_lock);

	while (!atomic_load(&pool->shutdown)) {
		// Wait for a timer to be queued.
		while (pool->timer_heap_len == 0 && !atomic_load(&pool->shutdown)) {
			pthread_cond_wait(&pool->timer_cond, &pool->timer_lock);
		}
		if (atomic_load(&pool->shutdown)) {
			break;
		}

		uint64_t now = ior_threads_pool_monotonic_ns();
		uint64_t deadline = pool->timer_heap[0].deadline_ns;

		if (deadline > now) {
			/*
			 * Sleep until the earliest deadline. pthread_cond_timedwait uses
			 * CLOCK_REALTIME, so convert the monotonic remaining time into an
			 * absolute realtime deadline. A wall-clock step only causes an
			 * early wakeup, after which we recompute against the monotonic
			 * clock and wait again - so the duration stays monotonic-based.
			 */
			uint64_t remaining_ns = deadline - now;
			struct timespec rt;
			clock_gettime(CLOCK_REALTIME, &rt);
			uint64_t abs_ns
					= (uint64_t) rt.tv_sec * 1000000000ULL + (uint64_t) rt.tv_nsec + remaining_ns;
			struct timespec until = {
				.tv_sec = (time_t) (abs_ns / 1000000000ULL),
				.tv_nsec = (long) (abs_ns % 1000000000ULL),
			};
			pthread_cond_timedwait(&pool->timer_cond, &pool->timer_lock, &until);
			continue;
		}

		// Earliest timer has expired: pop it and fire outside the lock.
		ior_threads_pool_timer fired = ior_threads_pool_timer_pop(pool);
		pthread_mutex_unlock(&pool->timer_lock);

		ior_cqe cqe;
		memset(&cqe, 0, sizeof(cqe));
		cqe.threads.user_data = fired.work->sqe.threads.user_data;
		cqe.threads.res = -ETIME;

		ior_threads_pool_finish_op(pool, fired.work, &cqe);

		pthread_mutex_lock(&pool->timer_lock);
	}

	pthread_mutex_unlock(&pool->timer_lock);
	IOR_LOG_TRACE("timer thread exiting");
	return NULL;
}

// ===== Splice Emulation =====

#ifndef IOR_HAVE_SPLICE
static ssize_t ior_threads_pool_emulate_splice(
		int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags)
{
	(void) flags;

	const size_t BUFFER_SIZE = 65536; // 64KB buffer
	char *buffer = malloc(BUFFER_SIZE);
	if (!buffer) {
		errno = ENOMEM;
		return -1;
	}

	size_t total_transferred = 0;

	while (total_transferred < len) {
		size_t to_read = len - total_transferred;
		if (to_read > BUFFER_SIZE) {
			to_read = BUFFER_SIZE;
		}

		ssize_t nread;
		if (off_in) {
			nread = pread(fd_in, buffer, to_read, *off_in);
			if (nread > 0) {
				*off_in += nread;
			}
		} else {
			nread = read(fd_in, buffer, to_read);
		}

		if (nread < 0) {
			free(buffer);
			return -1;
		}

		if (nread == 0) {
			break; // EOF
		}

		ssize_t nwritten;
		if (off_out) {
			nwritten = pwrite(fd_out, buffer, nread, *off_out);
			if (nwritten > 0) {
				*off_out += nwritten;
			}
		} else {
			nwritten = write(fd_out, buffer, nread);
		}

		if (nwritten < 0) {
			free(buffer);
			return -1;
		}

		if (nwritten != nread) {
			// Partial write
			total_transferred += nwritten;
			break;
		}

		total_transferred += nwritten;
	}

	free(buffer);
	return (ssize_t) total_transferred;
}
#endif
