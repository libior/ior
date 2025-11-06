/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef IOR_THREADS_POOL_H
#define IOR_THREADS_POOL_H

#include <stdint.h>
#include <pthread.h>

// Forward declarations
typedef struct ior_threads_pool ior_threads_pool;
typedef struct ior_ctx_threads ior_ctx_threads;

// Thread pool configuration
typedef struct ior_threads_pool_config {
	uint32_t num_threads; // Number of worker threads (0 = auto-detect)
	uint32_t max_threads; // Maximum threads (for future dynamic scaling)
	uint32_t stack_size; // Thread stack size (0 = default)
	int thread_priority; // Thread priority (0 = default)
} ior_threads_pool_config;

// Create thread pool
// ctx: The ior_ctx_threads context (for accessing rings and event)
// num_threads: Number of worker threads (0 = auto based on CPU count)
ior_threads_pool *ior_threads_pool_create(ior_ctx_threads *ctx, uint32_t num_threads);

// Create with full configuration
ior_threads_pool *ior_threads_pool_create_ex(
		ior_ctx_threads *ctx, const ior_threads_pool_config *config);

// Notify pool that new work is available
// count: Number of new SQEs submitted
void ior_threads_pool_notify(ior_threads_pool *pool, uint32_t count);

// Shutdown pool and wait for all threads to finish
void ior_threads_pool_destroy(ior_threads_pool *pool);

// Get number of worker threads
uint32_t ior_threads_pool_get_num_threads(ior_threads_pool *pool);

// Statistics (optional, for debugging/monitoring)
typedef struct ior_threads_pool_stats {
	uint64_t tasks_completed; // Total tasks completed
	uint64_t tasks_pending; // Current pending tasks
	uint32_t threads_active; // Threads currently processing
	uint32_t threads_idle; // Threads waiting for work
} ior_threads_pool_stats;

void ior_threads_pool_get_stats(ior_threads_pool *pool, ior_threads_pool_stats *stats);

#endif /* IOR_THREADS_POOL_H */
