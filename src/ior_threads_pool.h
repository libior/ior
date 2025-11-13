/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef IOR_THREADS_POOL_H
#define IOR_THREADS_POOL_H

#include <stdint.h>
#include <pthread.h>
#include "ior_threads_event.h"
#include "ior_threads_ring.h"

// Forward declarations
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
	_Atomic uint64_t tasks_in_progress;

	// Thread creation throttling
	struct timeval last_thread_create;
	uint32_t thread_create_cooldown_ms;

	// SQE tracking for ordering
	pthread_mutex_t sqe_lock;
	uint64_t next_sqe_id;
	_Atomic uint64_t last_completed_sqe_id;
};

/**
 * Thread pool configuration
 *
 * For on-demand pools:
 *   - Set min_threads = 0, max_threads = desired limit
 *   - Threads created only when work arrives and no idle threads available
 *
 * For pre-warmed pools:
 *   - Set min_threads = baseline, max_threads = peak capacity
 *   - min_threads created at pool creation and never exit
 *   - Additional threads created on-demand up to max_threads
 *
 * For fixed pools:
 *   - Set min_threads = max_threads
 *   - All threads created at startup, none created/destroyed dynamically
 */
typedef struct ior_threads_pool_config {
	uint32_t num_threads; // Deprecated: use min_threads/max_threads instead
	uint32_t min_threads; // Minimum threads to maintain (0 = fully on-demand)
	uint32_t max_threads; // Maximum threads allowed
	uint32_t stack_size; // Thread stack size in bytes (0 = default)
	int thread_priority; // Thread priority (currently unused)
} ior_threads_pool_config;

/**
 * Thread pool statistics
 */
typedef struct ior_threads_pool_stats {
	uint64_t tasks_completed; // Total tasks completed since pool creation
	uint64_t tasks_pending; // Tasks currently waiting in submission queue
	uint32_t threads_active; // Threads currently executing work
	uint32_t threads_idle; // Threads waiting for work
} ior_threads_pool_stats;

/**
 * Create a thread pool with simple configuration
 *
 * NOTE: Behavior changed from old implementation!
 * - Now creates 0 threads initially (fully on-demand)
 * - num_threads becomes the max_threads limit
 * - Threads created automatically when work arrives
 *
 * @param ctx The thread context (provides access to SQ/CQ rings and event)
 * @param num_threads Maximum number of threads (0 = default of 32)
 * @return Thread pool handle or NULL on error
 *
 * Example:
 *   ior_threads_pool *pool = ior_threads_pool_create(ctx, 16);
 *   // Creates pool with 0 initial threads, max 16
 */
ior_threads_pool *ior_threads_pool_create(ior_ctx_threads *ctx, uint32_t num_threads);

/**
 * Create a thread pool with extended configuration
 *
 * Provides fine-grained control over thread pool behavior.
 *
 * @param ctx The thread context
 * @param config Configuration structure
 * @return Thread pool handle or NULL on error
 *
 * Configuration examples:
 *
 * 1. Fully on-demand (recommended for variable workloads):
 *    ior_threads_pool_config config = {
 *        .min_threads = 0,
 *        .max_threads = 32,
 *    };
 *
 * 2. Pre-warmed with scaling (good for consistent baseline + bursts):
 *    ior_threads_pool_config config = {
 *        .min_threads = 4,
 *        .max_threads = 64,
 *    };
 *
 * 3. Fixed size (old behavior equivalent):
 *    ior_threads_pool_config config = {
 *        .min_threads = 8,
 *        .max_threads = 8,
 *    };
 */
ior_threads_pool *ior_threads_pool_create_ex(
		ior_ctx_threads *ctx, const ior_threads_pool_config *config);

/**
 * Notify the thread pool that work is available
 *
 * This function:
 * 1. Wakes all idle threads to check for work
 * 2. Creates new threads if needed (when no idle threads and pending work exists)
 *
 * Thread creation logic:
 * - Only creates threads if current_count < max_threads
 * - Respects cooldown period between thread creation (50ms default)
 * - New threads start in IDLE state and immediately check for work
 *
 * @param pool The thread pool
 * @param count Number of new items submitted (informational, not used for logic)
 */
void ior_threads_pool_notify(ior_threads_pool *pool, uint32_t count);

/**
 * Destroy the thread pool and free all resources
 *
 * This function:
 * 1. Sets shutdown flag
 * 2. Wakes all threads
 * 3. Waits for all threads to complete their current work and exit
 * 4. Frees all memory
 *
 * Safe to call even with pending work - threads will finish current
 * operations before exiting. However, any work still in the submission
 * queue will not be processed.
 *
 * @param pool The thread pool to destroy (NULL-safe)
 */
void ior_threads_pool_destroy(ior_threads_pool *pool);

/**
 * Get the current number of threads in the pool
 *
 * Note: This count can change over time with on-demand pools:
 * - Increases when work arrives and threads are created
 * - Decreases when threads idle timeout (after 30s idle if count > min_threads)
 *
 * @param pool The thread pool
 * @return Current number of threads (0 if pool is NULL)
 */
uint32_t ior_threads_pool_get_num_threads(ior_threads_pool *pool);

/**
 * Get thread pool statistics
 *
 * Provides snapshot of pool state for monitoring/debugging.
 *
 * @param pool The thread pool
 * @param stats Structure to fill with statistics (zeroed if pool is NULL)
 */
void ior_threads_pool_get_stats(ior_threads_pool *pool, ior_threads_pool_stats *stats);

#endif /* IOR_THREADS_POOL_H */
