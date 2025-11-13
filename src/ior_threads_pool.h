/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef IOR_THREADS_POOL_H
#define IOR_THREADS_POOL_H

#include <stdint.h>
#include <pthread.h>
#include <sys/time.h>
#include "ior_threads_event.h"
#include "ior_threads_ring.h"

// Forward declaration
typedef struct ior_threads_pool ior_threads_pool;

/* Thread backend context */
typedef struct ior_ctx_threads {
	ior_threads_ring sq_ring; // Submission queue
	ior_threads_ring cq_ring; // Completion queue

	ior_threads_event event; // Completion notification
	ior_threads_pool *pool; // Worker thread pool

	uint32_t flags;
	uint32_t features;
} ior_ctx_threads;

// Thread state enumeration
typedef enum {
	IOR_THREADS_POOL_THREAD_STATE_IDLE = 0,
	IOR_THREADS_POOL_THREAD_STATE_ACTIVE = 1,
	IOR_THREADS_POOL_THREAD_STATE_STOPPING = 2,
} ior_threads_pool_thread_state_t;

// Per-thread data structure
typedef struct ior_threads_pool_worker_thread {
	pthread_t thread_id;
	_Atomic ior_threads_pool_thread_state_t state;
	struct ior_threads_pool *pool;
	uint64_t tasks_completed;
	struct ior_threads_pool_worker_thread *next;
} ior_threads_pool_worker_thread_t;

// Thread pool structure
struct ior_threads_pool {
	ior_ctx_threads *ctx;

	// Thread management
	pthread_mutex_t pool_lock;
	ior_threads_pool_worker_thread_t *threads;
	uint32_t num_threads_current;
	uint32_t num_threads_idle;
	uint32_t num_threads_min;
	uint32_t num_threads_max;

	// Work notification
	pthread_cond_t work_cond;

	// Shutdown flag
	_Atomic int shutdown;

	// Statistics
	_Atomic uint64_t tasks_completed;

	// Thread creation throttling
	struct timeval last_thread_create;
	uint32_t thread_create_cooldown_ms;
};

// Thread pool configuration
typedef struct ior_threads_pool_config {
	uint32_t min_threads; // Minimum threads to maintain (0 = fully on-demand)
	uint32_t max_threads; // Maximum threads allowed
	uint32_t stack_size; // Thread stack size in bytes (0 = default)
	int thread_priority; // Thread priority (currently unused)
} ior_threads_pool_config;

// Thread pool statistics
typedef struct ior_threads_pool_stats {
	uint64_t tasks_completed; // Total tasks completed since pool creation
	uint32_t tasks_pending; // Tasks currently waiting in submission queue
	uint32_t threads_active; // Threads currently executing work
	uint32_t threads_idle; // Threads waiting for work
} ior_threads_pool_stats;

// Create thread pool with simple configuration
// num_threads becomes max_threads, creates 0 threads initially
ior_threads_pool *ior_threads_pool_create(ior_ctx_threads *ctx, uint32_t num_threads);

// Create thread pool with extended configuration
ior_threads_pool *ior_threads_pool_create_ex(
		ior_ctx_threads *ctx, const ior_threads_pool_config *config);

// Notify pool that work is available (submits pending SQEs and wakes workers)
void ior_threads_pool_notify(ior_threads_pool *pool, uint32_t count);

// Shutdown pool and wait for all threads to finish
void ior_threads_pool_destroy(ior_threads_pool *pool);

// Get number of worker threads
uint32_t ior_threads_pool_get_num_threads(ior_threads_pool *pool);

// Get statistics
void ior_threads_pool_get_stats(ior_threads_pool *pool, ior_threads_pool_stats *stats);

#endif /* IOR_THREADS_POOL_H */
