/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef IOR_THREADS_POOL_H
#define IOR_THREADS_POOL_H

#include <stdint.h>
#include <pthread.h>
#include <sys/time.h>
#include "ior_backend.h"
#include "ior_threads_event.h"
#include "ior_threads_poller.h"
#include "ior_threads_ring.h"
#include "ior_worker_pool.h"

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

/*
 * A submitted operation, copied out of the SQ ring at submit time. Workers
 * consume these from the shared worker pool's dispatch queue, so a slow op
 * never pins an SQ slot. Items live in a fixed pool and move between the free
 * list (via `next`) and the pool FIFO (via the embedded job node); `chain`
 * links the ops of one IO_LINK chain.
 */
typedef struct ior_work {
	ior_worker_pool_job job; // FIFO node while queued as a chain head
	ior_sqe sqe; // copied submission entry
	uint64_t seq; // submission order, for IO_DRAIN
	struct ior_work *next; // free-list link
	struct ior_work *chain; // next op in an IO_LINK chain (NULL at tail)
	struct ior_work_token token; // IOR_OP_WORK only: cancellation handle
} ior_work;

/*
 * Thread pool structure. Worker/timer thread lifecycle and the dispatch FIFO
 * live in the shared ior_worker_pool; this struct keeps only what is specific
 * to the threads backend: the work-item pool, the in-flight accounting that
 * backs get_sqe backpressure, and IO_DRAIN ordering.
 */
struct ior_threads_pool {
	ior_ctx_threads *ctx;

	ior_worker_pool *wp; // shared worker lifecycle + job FIFO + timers

	/*
	 * Readiness multiplexer for IOR_OP_POLL. Created lazily on the first poll
	 * op (guarded by work_lock); destroyed after the worker pool so drained
	 * chains can still hand off to it.
	 */
	_Atomic(ior_threads_poller *) poller;

	// Statistics
	_Atomic uint64_t tasks_completed;

	/*
	 * Free-at-submit dispatch. submit() copies each SQE into a work item and
	 * enqueues it (chains as a unit) onto the worker pool FIFO, freeing the SQ
	 * slot immediately; workers consume from the FIFO. The work pool is fixed at
	 * cq_entries, the in-flight bound. Protected by work_lock.
	 */
	pthread_mutex_t work_lock;
	ior_work *work_items; // pool array [work_cap]
	ior_work *work_free; // free list
	uint32_t work_cap;
	uint64_t next_seq; // next submission sequence to assign

	/*
	 * outstanding = reserved-but-not-completed (get_sqe backpressure);
	 * num_inflight = submitted-but-not-completed. Both decrement at completion,
	 * in any order - no lock-free-pick skew.
	 */
	_Atomic uint32_t outstanding;
	_Atomic uint32_t num_inflight;

	/*
	 * IO_DRAIN ordering, keyed on submission sequence. A drain op waits until
	 * every earlier seq has completed. drain_done marks completed seqs and
	 * drain_upto is the contiguous front; sized past the in-flight span so seqs
	 * never alias.
	 */
	uint8_t *drain_done;
	uint32_t drain_mask;
	uint64_t drain_upto;
	pthread_mutex_t drain_lock;
	pthread_cond_t drain_cond;
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
