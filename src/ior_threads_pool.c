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
#include <stddef.h>
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
static void ior_threads_pool_run_job(void *owner, ior_worker_pool_job *job);
static void ior_threads_pool_process_chain(ior_threads_pool *pool, ior_work *head);
static void ior_threads_pool_process_single_sqe(
		ior_threads_pool *pool, const ior_sqe *sqe, ior_cqe *cqe, ior_work_token *token);
static void ior_threads_pool_process_single_sqe_timed(
		ior_threads_pool *pool, const ior_sqe *sqe, ior_cqe *cqe, int timeout_ms);
static int ior_threads_pool_process_work_timed(
		ior_threads_pool *pool, ior_work *w, ior_work *lt, ior_cqe *gcqe, ior_cqe *lcqe);
static void ior_threads_pool_post_completion(ior_threads_pool *pool, const ior_cqe *cqe);
static void ior_threads_pool_arm_timer(ior_threads_pool *pool, ior_work *work);
static void ior_threads_pool_finish_op(ior_threads_pool *pool, ior_work *work, const ior_cqe *cqe);
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

// ===== Work-item pool and drain tracking =====
// The work-pool helpers below must be called with work_lock held; the drain
// helpers take drain_lock themselves. Dispatch itself (FIFO + worker wakeup)
// lives in the shared ior_worker_pool.

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

	pthread_mutex_lock(&pool->work_lock);
	ior_threads_pool_work_release(pool, work);
	pthread_mutex_unlock(&pool->work_lock);

	atomic_fetch_sub(&pool->outstanding, 1);
	atomic_fetch_sub(&pool->num_inflight, 1);
}

/*
 * Resolve a poll op handed off to the poller thread. The chain layout is
 * recovered from the work item itself: an immediately following LINK_TIMEOUT
 * is the guarding pair, anything after belongs to the chain remainder, which
 * resumes on the worker pool on success or is cancelled on failure.
 */
static void ior_threads_pool_poll_done(void *owner, void *req, int res)
{
	ior_threads_pool *pool = owner;
	ior_work *w = req;
	uint64_t count = 1;

	ior_work *lt = NULL;
	if ((w->sqe.threads.flags & IOR_SQE_IO_LINK) && w->chain
			&& w->chain->sqe.threads.opcode == IOR_OP_LINK_TIMEOUT) {
		lt = w->chain;
	}
	ior_work *rest = lt ? lt->chain : w->chain;
	int failed = res < 0;

	ior_cqe cqe;
	memset(&cqe, 0, sizeof(cqe));
	cqe.threads.user_data = w->sqe.threads.user_data;
	// A poller deadline is a fired link timeout: the guarded poll is cancelled.
	cqe.threads.res = (res == -ETIME) ? -ECANCELED : res;
	ior_threads_pool_finish_op(pool, w, &cqe);

	if (lt) {
		ior_cqe lcqe;
		memset(&lcqe, 0, sizeof(lcqe));
		lcqe.threads.user_data = lt->sqe.threads.user_data;
		lcqe.threads.res = (res == -ETIME) ? -ETIME : -ECANCELED;
		ior_threads_pool_finish_op(pool, lt, &lcqe);
		count++;
	}

	if (rest) {
		if (failed) {
			// A failed linked op cancels the remainder, matching io_uring.
			ior_work *r = rest;
			while (r) {
				ior_work *next = r->chain;
				ior_cqe rcqe;
				memset(&rcqe, 0, sizeof(rcqe));
				rcqe.threads.user_data = r->sqe.threads.user_data;
				rcqe.threads.res = -ECANCELED;
				ior_threads_pool_finish_op(pool, r, &rcqe);
				count++;
				r = next;
			}
		} else {
			rest->job.next = NULL;
			ior_worker_pool_submit(pool->wp, &rest->job, &rest->job, 1);
		}
	}

	atomic_fetch_add(&pool->tasks_completed, count);
}

/* Get or lazily create the shared poller (NULL on allocation failure). */
static ior_threads_poller *ior_threads_pool_get_poller(ior_threads_pool *pool)
{
	ior_threads_poller *poller = atomic_load_explicit(&pool->poller, memory_order_acquire);
	if (poller) {
		return poller;
	}

	pthread_mutex_lock(&pool->work_lock);
	poller = atomic_load_explicit(&pool->poller, memory_order_relaxed);
	if (!poller) {
		if (ior_threads_poller_create(&poller, pool, ior_threads_pool_poll_done) < 0) {
			poller = NULL;
		} else {
			atomic_store_explicit(&pool->poller, poller, memory_order_release);
		}
	}
	pthread_mutex_unlock(&pool->work_lock);
	return poller;
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
	atomic_init(&pool->tasks_completed, 0);
	atomic_init(&pool->poller, NULL);

	/*
	 * Work-item pool (free-at-submit). Capacity matches the CQ (the in-flight
	 * bound). The drain bitmap is sized past the worst-case in-flight seq span
	 * so sequence numbers never alias.
	 */
	pool->work_cap = ctx->cq_ring.size;
	pool->next_seq = 0;
	atomic_init(&pool->outstanding, 0);
	atomic_init(&pool->num_inflight, 0);
	pool->drain_upto = 0;

	if (pthread_mutex_init(&pool->work_lock, NULL) != 0) {
		free(pool);
		return NULL;
	}

	pool->work_items = calloc(pool->work_cap, sizeof(*pool->work_items));
	uint32_t drain_cap = ior_threads_pool_round_up_pow2(pool->work_cap * 2);
	pool->drain_mask = drain_cap - 1;
	pool->drain_done = calloc(drain_cap, sizeof(*pool->drain_done));
	if (!pool->work_items || !pool->drain_done
			|| pthread_mutex_init(&pool->drain_lock, NULL) != 0) {
		free(pool->drain_done);
		free(pool->work_items);
		pthread_mutex_destroy(&pool->work_lock);
		free(pool);
		return NULL;
	}
	if (pthread_cond_init(&pool->drain_cond, NULL) != 0) {
		pthread_mutex_destroy(&pool->drain_lock);
		free(pool->drain_done);
		free(pool->work_items);
		pthread_mutex_destroy(&pool->work_lock);
		free(pool);
		return NULL;
	}
	for (uint32_t i = 0; i < pool->work_cap; i++) {
		pool->work_items[i].next = pool->work_free;
		pool->work_free = &pool->work_items[i];
	}

	// Worker lifecycle, dispatch FIFO and timers live in the shared pool.
	ior_worker_pool_config wp_config = {
		.min_threads = config->min_threads,
		.max_threads = config->max_threads > 0 ? config->max_threads : 32,
		.stack_size = config->stack_size,
	};
	pool->wp = ior_worker_pool_create(&wp_config, ior_threads_pool_run_job, pool);
	if (!pool->wp) {
		pthread_cond_destroy(&pool->drain_cond);
		pthread_mutex_destroy(&pool->drain_lock);
		free(pool->drain_done);
		free(pool->work_items);
		pthread_mutex_destroy(&pool->work_lock);
		free(pool);
		return NULL;
	}

	return pool;
}

void ior_threads_pool_notify(ior_threads_pool *pool, uint32_t count)
{
	(void) count;
	if (!pool) {
		return;
	}

	ior_ctx_threads *ctx = pool->ctx;

	pthread_mutex_lock(&pool->work_lock);

	/*
	 * Copy every newly staged SQE out of the ring into a work item, freeing the
	 * SQ slots immediately. Consecutive IO_LINK ops form one chain: only the
	 * head is enqueued, the rest hang off head->chain, so a worker drains a
	 * chain as a unit (no mid-chain race). Chain heads are collected into a
	 * local list here and handed to the worker pool in one submit below.
	 */
	uint32_t consumed = atomic_load_explicit(&ctx->sq_ring.consumed, memory_order_relaxed);
	uint32_t cached = atomic_load_explicit(&ctx->sq_ring.cached_tail, memory_order_acquire);
	uint32_t n = cached - consumed;
	const ior_sqe *sqes = (const ior_sqe *) ctx->sq_ring.entries;

	ior_worker_pool_job *first = NULL;
	ior_worker_pool_job *last = NULL;
	uint32_t njobs = 0;
	ior_work *prev = NULL;
	int prev_link = 0;
	for (uint32_t p = consumed; p != cached; p++) {
		ior_work *w = ior_threads_pool_work_alloc(pool);
		w->sqe = sqes[p & ctx->sq_ring.mask];
		w->seq = pool->next_seq++;
		w->chain = NULL;
		if (w->sqe.threads.opcode == IOR_OP_WORK) {
			atomic_init(&w->token.cancelled, 0);
			w->token.shutdown = &pool->wp->shutdown;
		}
		int has_link = (w->sqe.threads.flags & IOR_SQE_IO_LINK) != 0;
		if (prev_link) {
			prev->chain = w;
		} else {
			w->job.next = NULL;
			if (last) {
				last->next = &w->job;
			} else {
				first = &w->job;
			}
			last = &w->job;
			njobs++;
		}
		prev = w;
		prev_link = has_link;
	}

	atomic_fetch_add(&pool->num_inflight, n);

	pthread_mutex_unlock(&pool->work_lock);

	if (njobs > 0) {
		ior_worker_pool_submit(pool->wp, first, last, njobs);
	}

	// Staging slots are now free for reuse by get_sqe.
	ior_threads_ring_consume(&ctx->sq_ring);
}

void ior_threads_pool_destroy(ior_threads_pool *pool)
{
	if (!pool) {
		return;
	}

	// Shut down the shared pool: drains dispatched chains, drops pending
	// timers without posting completions, and joins all threads.
	ior_worker_pool_destroy(pool->wp);

	// Workers are joined, so no new poll registrations can arrive; pending
	// polls complete with -ECANCELED before the poller thread exits.
	ior_threads_poller_destroy(atomic_load(&pool->poller));

	// Cleanup
	pthread_cond_destroy(&pool->drain_cond);
	pthread_mutex_destroy(&pool->drain_lock);
	free(pool->drain_done);
	free(pool->work_items);
	pthread_mutex_destroy(&pool->work_lock);
	free(pool);
}

uint32_t ior_threads_pool_get_num_threads(ior_threads_pool *pool)
{
	if (!pool) {
		return 0;
	}

	return ior_worker_pool_num_threads(pool->wp);
}

void ior_threads_pool_get_stats(ior_threads_pool *pool, ior_threads_pool_stats *stats)
{
	if (!pool || !stats) {
		return;
	}

	memset(stats, 0, sizeof(*stats));

	ior_worker_pool_thread_stats(pool->wp, &stats->threads_active, &stats->threads_idle);

	stats->tasks_completed = atomic_load(&pool->tasks_completed);
	stats->tasks_pending = ior_threads_ring_count(&pool->ctx->sq_ring);
}

// ===== Worker-pool job trampoline =====

static void ior_threads_pool_run_job(void *owner, ior_worker_pool_job *job)
{
	ior_threads_pool *pool = owner;
	ior_work *head = (ior_work *) ((char *) job - offsetof(ior_work, job));

	ior_threads_pool_process_chain(pool, head);
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

		/*
		 * Poll ops never block a worker: hand them (with their guarding link
		 * timeout and chain remainder) to the poller thread, which resolves
		 * them in ior_threads_pool_poll_done.
		 */
		if (w->sqe.threads.opcode == IOR_OP_POLL) {
			ior_work *lt = NULL;
			if ((w->sqe.threads.flags & IOR_SQE_IO_LINK) && next
					&& next->sqe.threads.opcode == IOR_OP_LINK_TIMEOUT) {
				lt = next;
			}
			uint64_t deadline_ns = 0;
			if (lt) {
				ior_timespec *ts = (ior_timespec *) (uintptr_t) lt->sqe.threads.addr;
				if (ts) {
					uint64_t ns = (uint64_t) ts->tv_sec * 1000000000ULL + (uint64_t) ts->tv_nsec;
					if (!(lt->sqe.threads.timeout_flags & IOR_TIMEOUT_ABS)) {
						ns += ior_worker_pool_monotonic_ns();
					}
					deadline_ns = ns ? ns : 1; // 0 means "no deadline"
				}
			}

			ior_threads_poller *poller = ior_threads_pool_get_poller(pool);
			int ret = poller ? ior_threads_poller_add(poller, w->sqe.threads.fd,
									  w->sqe.threads.poll_events, deadline_ns, w)
							 : -ENOMEM;
			if (ret == 0) {
				// Ownership of w and its whole chain moved to the poller.
				atomic_fetch_add(&pool->tasks_completed, count);
				return;
			}

			// Registration failed: fail the op here, cancel any linked rest.
			int linked = (w->sqe.threads.flags & IOR_SQE_IO_LINK) != 0;
			ior_cqe cqe;
			memset(&cqe, 0, sizeof(cqe));
			cqe.threads.user_data = w->sqe.threads.user_data;
			cqe.threads.res = ret;
			ior_threads_pool_finish_op(pool, w, &cqe);
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

			/*
			 * A guarded work op cannot be poll-gated: the callback runs on this
			 * worker while the timer thread arbitrates the deadline and flags
			 * the token so the callback can bail out.
			 */
			if (w->sqe.threads.opcode == IOR_OP_WORK) {
				ior_cqe gcqe, lcqe;
				ior_threads_pool_process_work_timed(pool, w, next, &gcqe, &lcqe);
				int failed = gcqe.threads.res < 0;
				ior_threads_pool_finish_op(pool, w, &gcqe);
				ior_threads_pool_finish_op(pool, next, &lcqe);
				count += 2;

				if (failed) {
					cancel = 1; // a failed linked op breaks the chain
				}
				w = after;
				continue;
			}

			ior_timespec *ts = (ior_timespec *) (uintptr_t) next->sqe.threads.addr;
			int timeout_ms = -1;
			if (ts) {
				uint64_t ns = (uint64_t) ts->tv_sec * 1000000000ULL + (uint64_t) ts->tv_nsec;
				if (next->sqe.threads.timeout_flags & IOR_TIMEOUT_ABS) {
					uint64_t now = ior_worker_pool_monotonic_ns();
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
		ior_threads_pool_process_single_sqe(pool, &w->sqe, &cqe, &w->token);
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
			ior_threads_pool_process_single_sqe(pool, sqe, cqe, NULL);
			return;
	}

	struct pollfd pfd = { .fd = sqe->threads.fd, .events = events };
	int pret;
	do {
		pret = poll(&pfd, 1, timeout_ms);
	} while (pret < 0 && errno == EINTR);

	if (pret > 0) {
		// Ready: the syscall will not block significantly.
		ior_threads_pool_process_single_sqe(pool, sqe, cqe, NULL);
		return;
	}

	memset(cqe, 0, sizeof(*cqe));
	cqe->threads.user_data = sqe->threads.user_data;
	// pret == 0 is the deadline (cancel); pret < 0 is a poll error.
	cqe->threads.res = (pret == 0) ? -ECANCELED : -errno;
}

/*
 * Arbitration node for a work op guarded by a link timeout. Heap-allocated and
 * shared between the worker running the callback and the timer thread: `state`
 * decides how the link timeout resolves, the embedded token lets the callback
 * observe a fired deadline, and the refcount (worker + timer) keeps the node
 * alive until whichever side finishes last - the timer always fires or is
 * dropped eventually, even if the pair completed long before.
 */
typedef struct ior_threads_pool_lt_arb {
	struct ior_work_token token;
	_Atomic int state; /* 0 = armed, 1 = callback finished first, 2 = timer fired first */
	_Atomic int refs;
} ior_threads_pool_lt_arb;

static void ior_threads_pool_lt_arb_release(ior_threads_pool_lt_arb *arb)
{
	if (atomic_fetch_sub(&arb->refs, 1) == 1) {
		free(arb);
	}
}

// Timer-thread side: flag the token and claim the "fired first" outcome. Late
// firings (callback already resolved the pair) only touch the private node.
static void ior_threads_pool_lt_fired(void *owner, void *arg)
{
	(void) owner;
	ior_threads_pool_lt_arb *arb = arg;

	atomic_store_explicit(&arb->token.cancelled, 1, memory_order_release);
	int expected = 0;
	atomic_compare_exchange_strong(&arb->state, &expected, 2);

	ior_threads_pool_lt_arb_release(arb);
}

// Pool destroyed before the deadline: just drop the timer's reference.
static void ior_threads_pool_lt_dropped(void *owner, void *arg)
{
	(void) owner;
	ior_threads_pool_lt_arb_release(arg);
}

/*
 * Run a work op guarded by a link timeout. The callback cannot be poll-gated
 * or killed, so it always runs to completion on this worker; the deadline is
 * armed on the timer thread and only flags the token so the callback can
 * return early. Resolution (matching io_uring):
 *   - callback finishes first: work res = callback's return, LT = -ECANCELED;
 *   - deadline fires while the callback runs: work res = callback's return
 *     (posted when it returns), LT = -ETIME.
 * With no valid deadline (NULL/invalid ts, alloc failure) the pair degrades to
 * "op finished first", like an unbounded poll gate. Returns non-zero if the
 * deadline fired.
 */
static int ior_threads_pool_process_work_timed(
		ior_threads_pool *pool, ior_work *w, ior_work *lt, ior_cqe *gcqe, ior_cqe *lcqe)
{
	ior_timespec *ts = (ior_timespec *) (uintptr_t) lt->sqe.threads.addr;
	ior_threads_pool_lt_arb *arb = NULL;

	if (ts && ts->tv_sec >= 0 && ts->tv_nsec >= 0 && ts->tv_nsec < 1000000000L) {
		arb = calloc(1, sizeof(*arb));
		if (arb) {
			atomic_init(&arb->token.cancelled, 0);
			arb->token.shutdown = &pool->wp->shutdown;
			atomic_init(&arb->state, 0);
			atomic_init(&arb->refs, 2); // this worker + the timer thread

			uint64_t ts_ns = (uint64_t) ts->tv_sec * 1000000000ULL + (uint64_t) ts->tv_nsec;
			uint64_t deadline_ns = (lt->sqe.threads.timeout_flags & IOR_TIMEOUT_ABS)
					? ts_ns
					: ior_worker_pool_monotonic_ns() + ts_ns;

			if (ior_worker_pool_arm_timer(pool->wp, deadline_ns, ior_threads_pool_lt_fired,
						ior_threads_pool_lt_dropped, arb)
					< 0) {
				free(arb);
				arb = NULL;
			}
		}
	}

	ior_threads_pool_process_single_sqe(pool, &w->sqe, gcqe, arb ? &arb->token : &w->token);

	int fired = 0;
	if (arb) {
		int expected = 0;
		if (!atomic_compare_exchange_strong(&arb->state, &expected, 1)) {
			fired = 1; // timer thread claimed the deadline while the callback ran
		}
		ior_threads_pool_lt_arb_release(arb);
	}

	memset(lcqe, 0, sizeof(*lcqe));
	lcqe->threads.user_data = lt->sqe.threads.user_data;
	lcqe->threads.res = fired ? -ETIME : -ECANCELED;

	return fired;
}

static void ior_threads_pool_process_single_sqe(
		ior_threads_pool *pool, const ior_sqe *sqe, ior_cqe *cqe, ior_work_token *token)
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

		case IOR_OP_WORK: {
			ior_work_fn fn = (ior_work_fn) (uintptr_t) sqe->threads.addr;
			void *arg = (void *) (uintptr_t) sqe->threads.off;
			IOR_LOG_TRACE("work start: fn=%p, arg=%p", (void *) (uintptr_t) sqe->threads.addr, arg);
			cqe->threads.res = fn(token, arg);
			IOR_LOG_TRACE("work end: res=%d", cqe->threads.res);
			break;
		}

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

// ===== Timers =====

// Fires on the worker pool's timer thread when a timeout op expires.
static void ior_threads_pool_timer_fired(void *owner, void *arg)
{
	ior_threads_pool *pool = owner;
	ior_work *work = arg;

	ior_cqe cqe;
	memset(&cqe, 0, sizeof(cqe));
	cqe.threads.user_data = work->sqe.threads.user_data;
	cqe.threads.res = -ETIME;

	ior_threads_pool_finish_op(pool, work, &cqe);
}

/*
 * Arm a timeout. Validates the timespec and hands the work item to the shared
 * pool's timer thread, which finishes it on expiry. Invalid timespecs (and a
 * heap allocation failure) finish inline so the caller never has to
 * special-case them.
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
				: ior_worker_pool_monotonic_ns() + ts_ns;

		int ret = ior_worker_pool_arm_timer(
				pool->wp, deadline_ns, ior_threads_pool_timer_fired, NULL, work);
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
