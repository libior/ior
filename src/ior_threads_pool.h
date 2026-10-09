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
	/*
	 * A posted completion signals the event only while a thread waits for
	 * one in ior (waiters), once per wait (signalled, reset by the waiter it
	 * woke), or for every completion once the event has been handed out as
	 * the notification descriptor (notify_armed, for good): a write per
	 * completion is most of what posting costs. Padded to a cache line of
	 * their own: every posting worker reads them, and sharing the line with
	 * the fields around them costs more than the writes they save.
	 */
	char pad_before[64];
	_Atomic uint32_t waiters;
	_Atomic int signalled;
	_Atomic int notify_armed;
	char pad_after[64];
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
 * never pins an SQ slot. Items live in chunks the pool grows as needed and
 * move between the free list (via `next`) and the pool FIFO (via the
 * embedded job node); `chain` links the ops of one IO_LINK chain.
 */
typedef struct ior_work {
	ior_worker_pool_job job; // FIFO node while queued as a chain head
	ior_sqe sqe; // copied submission entry
	uint64_t seq; // submission order, for IO_DRAIN
	/*
	 * Submit's own result for an op it completes itself (see
	 * ior_threads_pool_notify): the entry's error when its chain failed, or
	 * the readiness of a poll found ready, and 0 for an op it cancels with
	 * them. Meaningless once a chain reaches a worker.
	 */
	int32_t fail_res;
	struct ior_work *next; // free-list link (scratch link while allocated)
	struct ior_work *chain; // next op in an IO_LINK chain (NULL at tail)
	/*
	 * Cancel lookup while allocated (see ior_threads_pool_index_add): the
	 * items with this one's user data, and those on its descriptor if the
	 * op takes one (fd_indexed). Guarded by work_lock.
	 */
	struct ior_work *ud_next;
	struct ior_work *ud_prev;
	struct ior_work *fd_next;
	struct ior_work *fd_prev;
	int fd_indexed;
	// The IO_DRAIN epoch it was submitted in (see ior_threads_pool_epoch).
	struct ior_threads_pool_epoch *epoch;
	/*
	 * A completion that found the CQ full waits here, carried by its own
	 * item, until the consumer makes room (see ior_threads_pool_post).
	 * Guarded by the CQ ring's tail_lock.
	 */
	struct ior_work *ovf_next;
	ior_cqe ovf_cqe;
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
	/*
	 * Multishot accept (see ior_threads_pool_accept_edge): the listener's
	 * mode could not be taken over, so readiness is probed before each
	 * accept; and what a declined edge left for the last completion, an
	 * accepted descriptor (>= 0) or an error, IOR_ACCEPT_LAST_NONE if nothing.
	 */
	int accept_probe;
	int32_t accept_last;
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
	 * slot immediately; workers consume from the FIFO. Nothing bounds the ops
	 * in flight but memory, as on io_uring: submit grows the items in chunks
	 * when the free list runs short. Protected by work_lock.
	 */
	pthread_mutex_t work_lock;
	struct ior_threads_pool_chunk *chunks; // every item, for forget and destroy
	uint32_t work_total; // items in all chunks
	uint32_t work_free_count;
	/*
	 * Allocated items by user data and by descriptor, so a cancel looks at
	 * the items it may match rather than at every one. index_mask + 1 buckets,
	 * a power of two, grown with the items. Protected by work_lock.
	 */
	ior_work **ud_index;
	ior_work **fd_index;
	uint32_t index_mask;

	/*
	 * Serializes arming a timer op (with the worker's post-arm cancel check)
	 * against a cancel claiming it, so neither side can miss the other; kept
	 * off work_lock, which every completion takes. Order: work_lock, then
	 * arm_lock, then the worker pool's timer lock.
	 */
	pthread_mutex_t arm_lock;
	ior_work *work_free; // free list
	uint64_t next_seq; // next submission sequence to assign

	/*
	 * Switched descriptors (see ior_threads_pool_fdmode), a chained hash by
	 * descriptor number, grown as descriptors are added; nodes are allocated
	 * on demand and kept on a free list. fdmode_lock covers the table and the ioctl that
	 * restores, so a restore is never interleaved with a new op's look at
	 * the mode; the look and the switch themselves run outside it. A leaf
	 * lock, taken with no other held, and kept off work_lock so that taking
	 * a mode over does not contend with completions.
	 */
	pthread_mutex_t fdmode_lock;
	ior_threads_pool_fdmode **fdmode_buckets;
	ior_threads_pool_fdmode *fdmode_free;
	uint32_t fdmode_mask;
	uint32_t fdmode_count; // entries in the table

	/*
	 * Completions that found the CQ full, oldest first, each carried by its
	 * op's work item: posting never waits on the consumer, which moves them
	 * into the ring as it makes room (ior_threads_pool_flush_overflow), as
	 * io_uring keeps its overflowing completions (IORING_FEAT_NODROP). While
	 * any is waiting, later completions queue behind it, so the order they
	 * were posted in is kept. Guarded by the CQ ring's tail_lock; the count
	 * lets the consumer skip the lock while there are none.
	 */
	ior_work *ovf_head;
	ior_work *ovf_tail;
	_Atomic uint32_t ovf_count;

	/*
	 * IO_DRAIN ordering by epochs: every op counts in the epoch current when
	 * it was submitted, and each drain op starts a new one, then waits until
	 * the older ones are empty. epochs is the list of those not freed yet,
	 * oldest first, epoch_cur the newest; an epoch goes once it is empty and
	 * no longer current. The counts are atomic, so an op takes drain_lock
	 * only when it empties an epoch. Unbounded however long an op stays in
	 * flight, and one atomic add and subtract per op while no drain is used.
	 */
	struct ior_threads_pool_epoch *epochs;
	struct ior_threads_pool_epoch *epoch_cur;
	uint32_t drain_waiters;
	pthread_mutex_t drain_lock;
	pthread_cond_t drain_cond;
};

#define IOR_ACCEPT_LAST_NONE INT32_MIN

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

// Submit the staged SQEs to the pool; returns how many were taken, or
// -EAGAIN when no memory could be had for their work items (all stay staged)
int ior_threads_pool_notify(ior_threads_pool *pool);

// Shutdown pool and wait for all threads to finish
void ior_threads_pool_destroy(ior_threads_pool *pool);
void ior_threads_pool_forget(ior_threads_pool *pool);

/*
 * Move completions waiting on the overflow list into the CQ ring as far as
 * it has room. The consumer calls it once it has made room, and before it
 * looks at the ring. Cheap when nothing is waiting.
 */
void ior_threads_pool_flush_overflow(ior_threads_pool *pool);

// Get number of worker threads
uint32_t ior_threads_pool_get_num_threads(ior_threads_pool *pool);

// Get statistics
void ior_threads_pool_get_stats(ior_threads_pool *pool, ior_threads_pool_stats *stats);

#endif /* IOR_THREADS_POOL_H */
