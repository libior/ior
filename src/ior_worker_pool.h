/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef IOR_WORKER_POOL_H
#define IOR_WORKER_POOL_H

#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>

/*
 * Generic POSIX worker-thread pool shared by the threads and io_uring backends.
 * It owns the worker lifecycle (on-demand spawn up to a cap, idle exit above the
 * minimum, shutdown/join), a FIFO of intrusive jobs, and a deadline timer heap
 * served by a dedicated timer thread. What a job *does* is entirely the owner's
 * business: the pool calls the run callback given at creation with the popped
 * job, and the owner recovers its enclosing work structure from the node.
 */

typedef struct ior_worker_pool ior_worker_pool;

/* Intrusive job node: embed in the owner's work struct and recover the owner
 * with container-of arithmetic in the run callback. The pool owns `next` from
 * submit until the node is handed to the run callback. */
typedef struct ior_worker_pool_job {
	struct ior_worker_pool_job *next;
} ior_worker_pool_job;

/* Executes one job on a worker thread. `owner` is the pointer given at create. */
typedef void (*ior_worker_pool_run_fn)(void *owner, ior_worker_pool_job *job);

/* Fires on the timer thread at/after the armed deadline. Must not block. */
typedef void (*ior_worker_pool_timer_fn)(void *owner, void *arg);

typedef struct ior_worker_pool_config {
	uint32_t min_threads; /* threads kept alive when idle (0 = fully on-demand) */
	uint32_t max_threads; /* hard cap (0 = default 32) */
	uint32_t stack_size; /* worker stack size in bytes (0 = platform default) */
} ior_worker_pool_config;

/* Worker thread state (exposed for tests/diagnostics). */
typedef enum {
	IOR_WORKER_POOL_THREAD_STATE_IDLE = 0,
	IOR_WORKER_POOL_THREAD_STATE_ACTIVE = 1,
	IOR_WORKER_POOL_THREAD_STATE_STOPPING = 2,
} ior_worker_pool_thread_state_t;

typedef struct ior_worker_pool_worker {
	pthread_t thread_id;
	_Atomic ior_worker_pool_thread_state_t state;
	ior_worker_pool *pool;
	struct ior_worker_pool_worker *next;
} ior_worker_pool_worker_t;

/* One armed deadline in the timer heap. */
typedef struct ior_worker_pool_timer {
	uint64_t deadline_ns; /* absolute CLOCK_MONOTONIC deadline */
	ior_worker_pool_timer_fn fire;
	ior_worker_pool_timer_fn drop; /* may be NULL; see arm_timer */
	void *arg;
} ior_worker_pool_timer;

struct ior_worker_pool {
	ior_worker_pool_run_fn run;
	void *owner;

	/* Thread management + job FIFO, all under `lock`. */
	pthread_mutex_t lock;
	pthread_cond_t work_cond;
	ior_worker_pool_worker_t *threads;
	uint32_t num_threads_current;
	uint32_t num_threads_idle;
	uint32_t num_threads_min;
	uint32_t num_threads_max;
	uint32_t stack_size;

	ior_worker_pool_job *job_head; /* FIFO head (oldest) */
	ior_worker_pool_job *job_tail;
	uint32_t jobs_pending; /* queued, not yet claimed */
	uint32_t jobs_running; /* claimed by a worker, run() not returned */

	_Atomic int shutdown;

	/*
	 * Timer manager: a single thread sleeping on a condition variable until the
	 * earliest deadline in a min-heap, then firing the callback. Timers are not
	 * run on workers (a long sleep would tie up a worker and block shutdown until
	 * it elapsed); the condition variable lets shutdown interrupt the wait.
	 */
	pthread_t timer_thread;
	int timer_thread_started;
	pthread_mutex_t timer_lock;
	pthread_cond_t timer_cond;
	ior_worker_pool_timer *timer_heap;
	uint32_t timer_heap_len;
	uint32_t timer_heap_cap;
};

ior_worker_pool *ior_worker_pool_create(
		const ior_worker_pool_config *config, ior_worker_pool_run_fn run, void *owner);

/*
 * Shut down and reclaim the pool. Jobs already queued are still executed
 * (workers drain the FIFO before exiting); pending timers are dropped without
 * firing - each dropped timer's drop callback (if any) runs after all worker
 * threads have been joined, so owners can release per-timer state. Safe to
 * call with NULL.
 */
void ior_worker_pool_destroy(ior_worker_pool *pool);

/*
 * Enqueue `count` jobs linked first..last via job->next (last->next is
 * terminated by the pool) and provision worker threads so every queued or
 * running job can have one, capped at max_threads.
 */
void ior_worker_pool_submit(
		ior_worker_pool *pool, ior_worker_pool_job *first, ior_worker_pool_job *last, uint32_t count);

/*
 * Arm a one-shot timer: fire(owner, arg) runs on the timer thread at/after
 * deadline_ns (absolute CLOCK_MONOTONIC). Returns 0 or -ENOMEM. There is no
 * cancel: owners that may resolve a deadline early arbitrate in the callback
 * (e.g. via an atomic state on `arg`) and treat a late firing as a no-op.
 * If the pool is destroyed before the deadline, fire never runs and
 * drop(owner, arg) - if non-NULL - runs instead during destroy.
 */
int ior_worker_pool_arm_timer(ior_worker_pool *pool, uint64_t deadline_ns,
		ior_worker_pool_timer_fn fire, ior_worker_pool_timer_fn drop, void *arg);

uint32_t ior_worker_pool_num_threads(ior_worker_pool *pool);

/* active = workers currently running a job, idle = workers waiting for work. */
void ior_worker_pool_thread_stats(ior_worker_pool *pool, uint32_t *active, uint32_t *idle);

uint64_t ior_worker_pool_monotonic_ns(void);

#endif /* IOR_WORKER_POOL_H */
