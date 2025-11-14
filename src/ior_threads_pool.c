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

// Forward declarations
static void *ior_threads_pool_worker_thread_func(void *arg);
static int ior_threads_pool_process_sqe_chain(ior_threads_pool *pool, uint64_t start_position);
static void ior_threads_pool_process_single_sqe(
		ior_threads_pool *pool, const ior_sqe *sqe, ior_cqe *cqe);
static void ior_threads_pool_post_completion(ior_threads_pool *pool, const ior_cqe *cqe);
static int ior_threads_pool_try_create_thread(ior_threads_pool *pool);
#ifndef IOR_HAVE_SPLICE
static ssize_t ior_threads_pool_emulate_splice(
		int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);
#endif

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
	if (!pool) {
		return;
	}

	IOR_LOG_TRACE("enter: count=%u", count);

	// Submit all pending SQEs first
	if (count > 0) {
		ior_threads_ring_submit(&pool->ctx->sq_ring);
	}

	pthread_mutex_lock(&pool->pool_lock);

	// Check if we need more threads
	uint32_t pending = ior_threads_ring_count(&pool->ctx->sq_ring);
	uint32_t idle = pool->num_threads_idle;

	// If we have pending work and no idle threads, try to create more
	if (pending > 0 && idle == 0 && pool->num_threads_current < pool->num_threads_max) {
		IOR_LOG_TRACE("creating thread: pending=%u, idle=%u, nthreads=%u", pending, idle,
				pool->num_threads_current);
		ior_threads_pool_try_create_thread(pool);
	}

	// Wake up all idle threads
	pthread_cond_broadcast(&pool->work_cond);
	pthread_mutex_unlock(&pool->pool_lock);
}

void ior_threads_pool_destroy(ior_threads_pool *pool)
{
	if (!pool) {
		return;
	}

	// Signal shutdown
	atomic_store(&pool->shutdown, 1);

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
	ior_ctx_threads *ctx = pool->ctx;

	struct timeval last_work_time;
	gettimeofday(&last_work_time, NULL);
	const uint32_t idle_timeout_ms = 30000; // 30 seconds

	IOR_LOG_TRACE("thread created");

	while (1) {
		// Check for shutdown
		if (atomic_load(&pool->shutdown)) {
			break;
		}

		uint64_t sqe_position = 0;

		// Try to pick work from SQ ring
		ior_sqe *sqe = ior_threads_ring_pick_sqe(&ctx->sq_ring, &sqe_position);

		if (sqe) {
			// Got work
			pthread_mutex_lock(&pool->pool_lock);
			pool->num_threads_idle--;
			IOR_LOG_TRACE("pool idle: %u", pool->num_threads_idle);
			pthread_mutex_unlock(&pool->pool_lock);

			atomic_store(&worker->state, IOR_THREADS_POOL_THREAD_STATE_ACTIVE);
			gettimeofday(&last_work_time, NULL);

			// Process SQE chain (handles LINK)
			int processed = ior_threads_pool_process_sqe_chain(pool, sqe_position);

			worker->tasks_completed += processed;

			IOR_LOG_TRACE("active processing: processed=%d, total=%lu", processed,
					worker->tasks_completed);

			// Mark thread as idle again
			pthread_mutex_lock(&pool->pool_lock);
			pool->num_threads_idle++;
			IOR_LOG_TRACE("pool idle: %u", pool->num_threads_idle);
			pthread_mutex_unlock(&pool->pool_lock);

			atomic_store(&worker->state, IOR_THREADS_POOL_THREAD_STATE_IDLE);

		} else {
			// No work available
			pthread_mutex_lock(&pool->pool_lock);

			// Double-check shutdown
			if (atomic_load(&pool->shutdown)) {
				IOR_LOG_TRACE("in shutdown");
				pthread_mutex_unlock(&pool->pool_lock);
				break;
			}

			// Check if we should exit due to being excess thread
			struct timeval now;
			gettimeofday(&now, NULL);
			long idle_ms = (now.tv_sec - last_work_time.tv_sec) * 1000
					+ (now.tv_usec - last_work_time.tv_usec) / 1000;

			if (pool->num_threads_current > pool->num_threads_min && idle_ms > idle_timeout_ms) {
				// This thread has been idle too long, exit
				atomic_store(&worker->state, IOR_THREADS_POOL_THREAD_STATE_STOPPING);
				pool->num_threads_current--;
				pool->num_threads_idle--;
				IOR_LOG_TRACE("stopping: threads=%u, idle=%u", pool->num_threads_current,
						pool->num_threads_idle);
				pthread_mutex_unlock(&pool->pool_lock);
				break;
			}

			// Wait for work with timeout
			struct timespec timeout;
			timeout.tv_sec = now.tv_sec + 1;
			timeout.tv_nsec = now.tv_usec * 1000;

			pthread_cond_timedwait(&pool->work_cond, &pool->pool_lock, &timeout);
			pthread_mutex_unlock(&pool->pool_lock);
		}
	}

	return NULL;
}

// ===== Operation Processing =====

static int ior_threads_pool_process_sqe_chain(ior_threads_pool *pool, uint64_t start_position)
{
	ior_ctx_threads *ctx = pool->ctx;
	int count = 0;
	uint64_t current_position = start_position;
	int continue_chain = 1;

	while (continue_chain) {
		continue_chain = 0;

		ior_sqe *sqe;
		uint64_t next_position = 0; // Initialize to avoid garbage

		// For first iteration, we already have the SQE from worker
		if (current_position == start_position) {
			// Need to peek at the already-picked SQE
			uint32_t index = current_position & ctx->sq_ring.mask;
			ior_sqe *sqes = (ior_sqe *) ctx->sq_ring.entries;
			sqe = &sqes[index];
			IOR_LOG_TRACE("processing first: index=%u", index);
		} else {
			// Pick next SQE in chain
			sqe = ior_threads_ring_pick_sqe(&ctx->sq_ring, &next_position);
			IOR_LOG_TRACE("picked next: position=%lu", next_position);
		}

		if (!sqe) {
			break;
		}

		// Make a copy of the SQE
		ior_sqe sqe_copy = *sqe;
		int has_link = (sqe_copy.threads.flags & IOR_SQE_IO_LINK) != 0;
		int has_drain = (sqe_copy.threads.flags & IOR_SQE_IO_DRAIN) != 0;

		IOR_LOG_TRACE("processing flags: link=%d, drain=%d", has_link, has_drain);

		// Handle DRAIN: wait until all prior SQEs complete
		if (has_drain) {
			IOR_LOG_TRACE("drain waiting: current_pos=%lu", current_position);
			ior_threads_ring_wait_until_head(&ctx->sq_ring, current_position);
		}

		// Process this SQE
		ior_cqe cqe;
		ior_threads_pool_process_single_sqe(pool, &sqe_copy, &cqe);

		// Post completion
		ior_threads_pool_post_completion(pool, &cqe);

		// Mark this SQE as completed
		ior_threads_ring_complete_sqe(&ctx->sq_ring, current_position);

		count++;

		IOR_LOG_TRACE("completed: count=%d", count);

		// If this SQE had IO_LINK flag and succeeded, continue to next
		if (has_link && cqe.threads.res >= 0) {
			// For first iteration, next_position needs to be calculated
			if (current_position == start_position) {
				next_position = start_position + 1;
			}
			continue_chain = 1;
			current_position = next_position;
			IOR_LOG_TRACE("link continue: next_position=%lu", next_position);
		}
	}

	atomic_fetch_add(&pool->tasks_completed, count);

	return count;
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
			ssize_t ret = pread(sqe->threads.fd, (void *) (uintptr_t) sqe->threads.addr,
					sqe->threads.len, sqe->threads.off);
			IOR_LOG_TRACE("read end: res=%ld", ret);
			cqe->threads.res = (ret < 0) ? -errno : ret;
			break;
		}

		case IOR_OP_WRITE: {
			IOR_LOG_TRACE("write start: fd=%d, addr=%p, len=%u, flags=%lu", sqe->threads.fd,
					(void *) (uintptr_t) sqe->threads.addr, sqe->threads.len, sqe->threads.off);
			ssize_t ret = pwrite(sqe->threads.fd, (const void *) (uintptr_t) sqe->threads.addr,
					sqe->threads.len, sqe->threads.off);
			IOR_LOG_TRACE("write end: res=%ld", ret);
			cqe->threads.res = (ret < 0) ? -errno : ret;
			break;
		}

		case IOR_OP_TIMER: {
			ior_timespec *ts = (ior_timespec *) (uintptr_t) sqe->threads.addr;
			if (ts) {
				struct timespec sts = {
					.tv_sec = ts->tv_sec,
					.tv_nsec = ts->tv_nsec,
				};
				IOR_LOG_TRACE("timer start: sec=%ld, nsec=%lld", ts->tv_sec, ts->tv_nsec);
				nanosleep(&sts, NULL);
				IOR_LOG_TRACE("timer end: res=%d", -ETIME);
				cqe->threads.res = -ETIME;
			} else {
				IOR_LOG_TRACE("timer failed: no addr");
				cqe->threads.res = -EINVAL;
			}
			break;
		}

		case IOR_OP_SPLICE: {
#ifdef IOR_HAVE_SPLICE
			ssize_t ret = splice(sqe->threads.splice_fd_in,
					(loff_t *) (sqe->threads.addr ? &sqe->threads.addr : NULL), sqe->threads.fd,
					(loff_t *) (sqe->threads.off ? &sqe->threads.off : NULL), sqe->threads.len,
					sqe->threads.splice_flags);
			cqe->threads.res = (ret < 0) ? -errno : ret;
#else
			// Emulate splice using read/write loop
			ssize_t ret = ior_threads_pool_emulate_splice(sqe->threads.splice_fd_in,
					(loff_t *) (sqe->threads.addr ? &sqe->threads.addr : NULL), sqe->threads.fd,
					(loff_t *) (sqe->threads.off ? &sqe->threads.off : NULL), sqe->threads.len,
					sqe->threads.splice_flags);
			cqe->threads.res = (ret < 0) ? -errno : ret;
#endif
			break;
		}

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
