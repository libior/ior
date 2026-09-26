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
 * Where a submitted op currently is, for IOR_OP_ASYNC_CANCEL. Every hand-over
 * to a worker, the poller or the timer thread is a compare-and-swap that
 * fails once a cancel has claimed the op (CANCELLED), and every cancel claim
 * is a compare-and-swap from the specific waiting state, so exactly one side
 * decides how the op completes.
 */
enum {
	IOR_WORK_FREE = 0, /* on the free list */
	IOR_WORK_QUEUED, /* chain head in the worker pool FIFO, or just popped */
	IOR_WORK_LINKED, /* chain member behind its head; not cancellable */
	IOR_WORK_RUNNING, /* on a worker: syscall or callback in progress */
	IOR_WORK_TRYING, /* on a worker: non-blocking attempt that may park on the poller */
	IOR_WORK_DRAINING, /* on a worker: waiting for IO_DRAIN */
	IOR_WORK_TIMER, /* armed on the timer thread */
	IOR_WORK_POLLING, /* registered with the poller */
	IOR_WORK_CANCELLED, /* claimed by a cancel; completes with -ECANCELED */
	IOR_WORK_DONE, /* completion posted; item about to return to the free list */
};

/*
 * How a positionless read or write is issued. Only the first form has a
 * per-call non-blocking flag; the others are the plain syscall, either on a
 * descriptor whose mode the op has taken over (see ior_threads_pool_fdmode)
 * or on one that runs to completion anyway (a regular file).
 */
enum {
	IOR_RW_NOWAIT = 0, /* preadv2/pwritev2 with RWF_NOWAIT (Linux) */
	IOR_RW_PLAIN_MODE, /* read/write; the descriptor's mode is taken over */
	IOR_RW_PLAIN, /* read/write; the descriptor's mode does not matter */
};

/*
 * A descriptor whose blocking mode the backend has looked at for the ops in
 * flight on it. One entry per descriptor, keyed by number, holding one
 * reference per op that needed a non-blocking descriptor; `owned` records
 * that the switch is ior's to undo, and the last op to complete restores the
 * mode. A descriptor the caller keeps non-blocking gets an entry that owns
 * nothing; under IOR_SETUP_FD_NONBLOCK there are no entries at all.
 */
typedef struct ior_threads_pool_fdmode {
	struct ior_threads_pool_fdmode *next; // bucket chain, or free-list link
	int fd;
	uint32_t refs;
	_Atomic int owned; // set once the switch has been made (outside the lock)
} ior_threads_pool_fdmode;

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
	int32_t fail_res; // submit: the entry's own error when its chain failed
	struct ior_work *next; // free-list link (scratch link while allocated)
	struct ior_work *chain; // next op in an IO_LINK chain (NULL at tail)
	/*
	 * Fields a worker writes while it owns the op, kept together (and off the
	 * neighbouring item's SQE) so the submitter's alloc and copy do not share
	 * cache lines with them.
	 */
	_Atomic int state; // IOR_WORK_*
	int ready; // rw op: the poller reported readiness, skip the probe
	int fdmode; // holds a reference on the descriptor's mode entry (see ior_threads_pool_fdmode)
	int rw_plain; // positionless read/write: IOR_RW_* form the syscall takes
	int connecting; // connect op: started, the next pass reads SO_ERROR
	int pidfd; // waitpid op: the pidfd parked on the poller, -1 if none
	struct ior_work_token *cur_token; // token the running callback observes
	uint64_t deadline_ns; // link-timeout deadline once computed (0 = none)
	struct ior_threads_pool_lt_arb
			*arb; // link-timeout arbitration of a work, signal or process wait
	uint64_t probe_ns; // waitpid op probed from the timer: the next interval
	struct ior_work_token token; // IOR_OP_WORK, IOR_OP_SIGWAIT: cancellation handle
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
	 * Set (under work_lock) when destroy begins: the poller must then fail
	 * ops it would otherwise hand back to the worker pool.
	 */
	_Atomic int shutdown;

	/*
	 * Free-at-submit dispatch. submit() copies each SQE into a work item and
	 * enqueues it (chains as a unit) onto the worker pool FIFO, freeing the SQ
	 * slot immediately; workers consume from the FIFO. The work pool is fixed at
	 * cq_entries, the in-flight bound. Protected by work_lock.
	 */
	pthread_mutex_t work_lock;
	ior_work *work_items; // pool array [work_cap]

	/*
	 * Serializes arming a timer op (with the worker's post-arm cancel check)
	 * against a cancel claiming it, so neither side can miss the other; kept
	 * off work_lock, which every completion takes. Order: work_lock, then
	 * arm_lock, then the worker pool's timer lock.
	 */
	pthread_mutex_t arm_lock;
	ior_work *work_free; // free list
	uint32_t work_cap;
	uint64_t next_seq; // next submission sequence to assign

	/*
	 * Switched descriptors (see ior_threads_pool_fdmode), a chained hash by
	 * descriptor number. Nodes come from a fixed array of work_cap, one per
	 * in-flight op at most. fdmode_lock covers the table and the ioctl that
	 * restores, so a restore is never interleaved with a new op's look at
	 * the mode; the look and the switch themselves run outside it. A leaf
	 * lock, taken with no other held, and kept off work_lock so that taking
	 * a mode over does not contend with completions.
	 */
	pthread_mutex_t fdmode_lock;
	ior_threads_pool_fdmode **fdmode_buckets;
	ior_threads_pool_fdmode *fdmode_nodes;
	ior_threads_pool_fdmode *fdmode_free;
	uint32_t fdmode_mask;

	/*
	 * outstanding = SQEs handed out whose op has not finished: get_sqe stops
	 * at work_cap so a submit always finds a work item. cq_pending = CQ
	 * slots promised: one per SQE handed out, for its op's last completion,
	 * plus one per multishot edge posted, each released as the consumer
	 * reaps it. get_sqe stops at the CQ size and an edge is posted only if
	 * a slot is free, so posting a completion never finds the CQ full and
	 * never waits on the consumer.
	 */
	_Atomic uint32_t outstanding;
	_Atomic uint32_t cq_pending;

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

// Submit the staged SQEs to the pool; returns how many were taken
uint32_t ior_threads_pool_notify(ior_threads_pool *pool);

// Shutdown pool and wait for all threads to finish
void ior_threads_pool_destroy(ior_threads_pool *pool);

/*
 * Promise a CQ slot (see cq_pending): 0, or -EBUSY when every slot is
 * promised already. Release returns nr slots once their completions are
 * reaped; releasing more than are promised is logged and clamped.
 */
int ior_threads_pool_cq_reserve(ior_threads_pool *pool);
void ior_threads_pool_cq_release(ior_threads_pool *pool, uint32_t nr);

// Get number of worker threads
uint32_t ior_threads_pool_get_num_threads(ior_threads_pool *pool);

// Get statistics
void ior_threads_pool_get_stats(ior_threads_pool *pool, ior_threads_pool_stats *stats);

#endif /* IOR_THREADS_POOL_H */
