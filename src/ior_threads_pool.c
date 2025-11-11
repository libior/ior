/* SPDX-License-Identifier: BSD-3-Clause */
#include "config.h"
#ifdef IOR_HAVE_SPLICE
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#endif
#include "ior_threads_pool.h"
#include "ior_threads.h"
#include "ior_threads_ring.h"
#include "ior_threads_event.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

// Work item structure
typedef struct ior_work_item {
	ior_sqe sqe; // Copy of submission queue entry
	ior_ctx_threads *ctx; // Context for posting completion
} ior_work_item;

// Thread pool structure
struct ior_threads_pool {
	ior_ctx_threads *ctx; // Parent context

	pthread_t *threads; // Worker threads
	uint32_t num_threads; // Number of threads

	// Work notification
	pthread_mutex_t work_lock; // Protects work_available condition
	pthread_cond_t work_cond; // Signals new work available

	// Shutdown flag
	_Atomic int shutdown; // Set to 1 to shutdown pool

	// Statistics
	_Atomic uint64_t tasks_completed;
	_Atomic uint32_t threads_active;
};

// Forward declarations
static void *worker_thread_func(void *arg);
static void process_sqe(ior_threads_pool *pool, const ior_sqe *sqe);
static void post_completion(ior_threads_pool *pool, const ior_cqe *cqe);

// Auto-detect number of threads based on CPU count
static uint32_t get_default_thread_count(void)
{
	long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
	if (nprocs <= 0) {
		return 4; // Default fallback
	}

	// Use number of CPUs, but cap at reasonable limit
	uint32_t count = (uint32_t) nprocs;
	if (count > 64) {
		count = 64; // Max 64 threads
	}

	return count;
}

ior_threads_pool *ior_threads_pool_create(ior_ctx_threads *ctx, uint32_t num_threads)
{
	ior_threads_pool_config config = {
		.num_threads = num_threads,
		.max_threads = num_threads,
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
	pool->num_threads = config->num_threads;

	if (pool->num_threads == 0) {
		pool->num_threads = get_default_thread_count();
	}

	// Initialize synchronization primitives
	if (pthread_mutex_init(&pool->work_lock, NULL) != 0) {
		free(pool);
		return NULL;
	}

	if (pthread_cond_init(&pool->work_cond, NULL) != 0) {
		pthread_mutex_destroy(&pool->work_lock);
		free(pool);
		return NULL;
	}

	atomic_init(&pool->shutdown, 0);
	atomic_init(&pool->tasks_completed, 0);
	atomic_init(&pool->threads_active, 0);

	// Allocate thread array
	pool->threads = calloc(pool->num_threads, sizeof(pthread_t));
	if (!pool->threads) {
		pthread_cond_destroy(&pool->work_cond);
		pthread_mutex_destroy(&pool->work_lock);
		free(pool);
		return NULL;
	}

	// Create worker threads
	pthread_attr_t attr;
	pthread_attr_init(&attr);

	if (config->stack_size > 0) {
		pthread_attr_setstacksize(&attr, config->stack_size);
	}

	for (uint32_t i = 0; i < pool->num_threads; i++) {
		int ret = pthread_create(&pool->threads[i], &attr, worker_thread_func, pool);
		if (ret != 0) {
			// Failed to create thread, cleanup
			atomic_store(&pool->shutdown, 1);
			pthread_cond_broadcast(&pool->work_cond);

			// Wait for already created threads
			for (uint32_t j = 0; j < i; j++) {
				pthread_join(pool->threads[j], NULL);
			}

			pthread_attr_destroy(&attr);
			free(pool->threads);
			pthread_cond_destroy(&pool->work_cond);
			pthread_mutex_destroy(&pool->work_lock);
			free(pool);
			return NULL;
		}
	}

	pthread_attr_destroy(&attr);

	return pool;
}

void ior_threads_pool_notify(ior_threads_pool *pool, uint32_t count)
{
	if (!pool || count == 0) {
		return;
	}

	// Signal worker threads that work is available
	pthread_mutex_lock(&pool->work_lock);
	pthread_cond_broadcast(&pool->work_cond); // Wake all threads
	pthread_mutex_unlock(&pool->work_lock);
}

void ior_threads_pool_destroy(ior_threads_pool *pool)
{
	if (!pool) {
		return;
	}

	// Signal shutdown
	atomic_store(&pool->shutdown, 1);

	// Wake all threads
	pthread_mutex_lock(&pool->work_lock);
	pthread_cond_broadcast(&pool->work_cond);
	pthread_mutex_unlock(&pool->work_lock);

	// Wait for all threads to finish
	for (uint32_t i = 0; i < pool->num_threads; i++) {
		pthread_join(pool->threads[i], NULL);
	}

	// Cleanup
	free(pool->threads);
	pthread_cond_destroy(&pool->work_cond);
	pthread_mutex_destroy(&pool->work_lock);
	free(pool);
}

uint32_t ior_threads_pool_get_num_threads(ior_threads_pool *pool)
{
	return pool ? pool->num_threads : 0;
}

void ior_threads_pool_get_stats(ior_threads_pool *pool, ior_threads_pool_stats *stats)
{
	if (!pool || !stats) {
		return;
	}

	memset(stats, 0, sizeof(*stats));

	stats->tasks_completed = atomic_load(&pool->tasks_completed);
	stats->threads_active = atomic_load(&pool->threads_active);
	stats->threads_idle = pool->num_threads - stats->threads_active;

	// Pending tasks = items in SQ ring
	stats->tasks_pending = ior_threads_ring_count(&pool->ctx->sq_ring);
}

// ===== Worker Thread Implementation =====

static void *worker_thread_func(void *arg)
{
	ior_threads_pool *pool = (ior_threads_pool *) arg;
	ior_ctx_threads *ctx = pool->ctx;

	while (1) {
		// Check for shutdown
		if (atomic_load(&pool->shutdown)) {
			break;
		}

		// Try to get work from SQ ring
		ior_sqe *sqe = ior_threads_ring_peek_sqe(&ctx->sq_ring);

		if (sqe) {
			// Got work - mark thread as active
			atomic_fetch_add(&pool->threads_active, 1);

			// Make a copy of the SQE (so ring slot can be reused)
			ior_sqe sqe_copy = *sqe;

			// Mark SQE as consumed
			ior_threads_ring_consume_sqe(&ctx->sq_ring);

			// Process the operation
			process_sqe(pool, &sqe_copy);

			// Mark thread as idle
			atomic_fetch_sub(&pool->threads_active, 1);
			atomic_fetch_add(&pool->tasks_completed, 1);

		} else {
			// No work available - wait for notification
			pthread_mutex_lock(&pool->work_lock);

			// Double-check shutdown flag while holding lock
			if (atomic_load(&pool->shutdown)) {
				pthread_mutex_unlock(&pool->work_lock);
				break;
			}

			// Check again if work appeared
			if (!ior_threads_ring_empty(&ctx->sq_ring)) {
				pthread_mutex_unlock(&pool->work_lock);
				continue;
			}

			// Wait for work or shutdown
			pthread_cond_wait(&pool->work_cond, &pool->work_lock);
			pthread_mutex_unlock(&pool->work_lock);
		}
	}

	return NULL;
}

// ===== Operation Processing =====

static void process_sqe(ior_threads_pool *pool, const ior_sqe *sqe)
{
	ior_cqe cqe = {
		.user_data = sqe->user_data,
		.res = 0,
		.flags = 0,
	};

	// Process based on operation type
	switch (sqe->opcode) {
		case IOR_OP_NOP:
			// No-op: just complete successfully
			cqe.res = 0;
			break;

		case IOR_OP_READ: {
			// Perform blocking read
			ssize_t ret = pread(sqe->fd, (void *) (uintptr_t) sqe->addr, sqe->len, sqe->off);
			cqe.res = (ret < 0) ? -errno : ret;
			break;
		}

		case IOR_OP_WRITE: {
			// Perform blocking write
			ssize_t ret = pwrite(sqe->fd, (const void *) (uintptr_t) sqe->addr, sqe->len, sqe->off);
			cqe.res = (ret < 0) ? -errno : ret;
			break;
		}

		case IOR_OP_TIMER: {
			// Sleep for specified time
			struct timespec *ts = (struct timespec *) (uintptr_t) sqe->addr;
			if (ts) {
				nanosleep(ts, NULL);
				cqe.res = 0;
			} else {
				cqe.res = -EINVAL;
			}
			break;
		}

		case IOR_OP_SPLICE: {
			// Splice between two file descriptors
#ifdef IOR_HAVE_SPLICE
			ssize_t ret = splice(sqe->splice_fd_in, (loff_t *) (sqe->addr ? &sqe->addr : NULL),
					sqe->fd, (loff_t *) (sqe->off ? &sqe->off : NULL), sqe->len, sqe->splice_flags);
			cqe.res = (ret < 0) ? -errno : ret;
#else
			// splice not available on non-Linux
			// TODO: emulate it
			cqe.res = -ENOSYS;
#endif
			break;
		}

		// Stage 2 operations (placeholders for now)
		case IOR_OP_ACCEPT:
		case IOR_OP_CONNECT:
		case IOR_OP_LISTEN:
		case IOR_OP_BIND:
			cqe.res = -ENOSYS; // Not yet implemented
			break;

		default:
			cqe.res = -EINVAL; // Unknown operation
			break;
	}

	// Post completion
	post_completion(pool, &cqe);
}

static void post_completion(ior_threads_pool *pool, const ior_cqe *cqe)
{
	ior_ctx_threads *ctx = pool->ctx;

	// Post CQE to completion ring
	int ret = ior_threads_ring_post_cqe(&ctx->cq_ring, cqe);

	if (ret == -EOVERFLOW) {
		// CQ ring full - this is a serious problem
		// In production, might want to log or handle this differently
		// For now, busy-wait until space available
		while (ior_threads_ring_post_cqe(&ctx->cq_ring, cqe) == -EOVERFLOW) {
			usleep(100); // Brief sleep to avoid burning CPU
		}
	}

	// Signal event to wake waiting thread
	ior_threads_event_signal(&ctx->event);
}
