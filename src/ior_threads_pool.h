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

/*
 * A pending timer managed by the dedicated timer thread.
 *
 * Timeout SQEs are not run on worker threads (a long sleep would tie up a
 * worker and, worse, block shutdown until it elapsed). Instead the worker
 * hands the timer to the timer thread, which sleeps on a condition variable
 * until the earliest deadline, then posts the completion and releases the SQ
 * slot itself. The condition variable also lets shutdown interrupt the wait
 * immediately.
 */
/*
 * A submitted operation, copied out of the SQ ring at submit time. Workers
 * consume these from the dispatch queue, so a slow op never pins an SQ slot.
 * Items live in a fixed pool and move between the free list and the dispatch
 * FIFO via `next`; `chain` links the ops of one IO_LINK chain.
 */
typedef struct ior_work {
	ior_sqe sqe; // copied submission entry
	uint64_t seq; // submission order, for IO_DRAIN
	struct ior_work *next; // free-list / dispatch-FIFO link
	struct ior_work *chain; // next op in an IO_LINK chain (NULL at tail)
} ior_work;

typedef struct ior_threads_pool_timer {
	uint64_t deadline_ns; // Absolute CLOCK_MONOTONIC deadline
	ior_work *work; // the timeout op; freed when it expires
} ior_threads_pool_timer;

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

	// Timer management (single thread, min-heap of pending timers by deadline)
	pthread_t timer_thread;
	int timer_thread_started;
	pthread_mutex_t timer_lock;
	pthread_cond_t timer_cond;
	ior_threads_pool_timer *timer_heap;
	uint32_t timer_heap_len;
	uint32_t timer_heap_cap;

	// Statistics
	_Atomic uint64_t tasks_completed;

	/*
	 * Free-at-submit dispatch. submit() copies each SQE into a work item and
	 * enqueues it (chains as a unit) onto the dispatch FIFO, freeing the SQ slot
	 * immediately; workers consume from the FIFO. The work pool is fixed at
	 * cq_entries, the in-flight bound. All of this is protected by pool_lock.
	 */
	ior_work *work_items; // pool array [work_cap]
	ior_work *work_free; // free list
	ior_work *disp_head; // dispatch FIFO head (oldest)
	ior_work *disp_tail; // dispatch FIFO tail
	uint32_t work_cap;
	uint64_t next_seq; // next submission sequence to assign

	/*
	 * outstanding = reserved-but-not-completed (get_sqe backpressure);
	 * num_inflight = submitted-but-not-completed (worker provisioning target).
	 * Both decrement at completion, in any order - no lock-free-pick skew.
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
