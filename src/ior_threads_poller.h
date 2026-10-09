/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef IOR_THREADS_POLLER_H
#define IOR_THREADS_POLLER_H

#include "config.h"
#include "ior.h"
#include <poll.h>
#include <stdint.h>

/*
 * Single-thread readiness multiplexer for the threads backend. All pending
 * IOR_OP_POLL requests (and, in the future, readiness gates for blocking I/O
 * ops) share one poller thread instead of each blocking a worker.
 *
 * Implementations selected at configure time: epoll on Linux
 * (ior_threads_poller_epoll.c), kqueue on BSD/macOS
 * (ior_threads_poller_kqueue.c), portable poll() elsewhere
 * (ior_threads_poller_poll.c).
 */

typedef struct ior_threads_poller ior_threads_poller;

/*
 * Mask bit of a process watch: fd is a pid and the request completes with
 * IOR_POLL_IN once that process exits. Only the kqueue poller (EVFILT_PROC)
 * takes it; on Linux a pidfd is polled instead and elsewhere the thread
 * backend never asks.
 */
#define IOR_THREADS_POLLER_PROC (1U << 31)

/*
 * Mask bit of a persistent (multishot) request: the callback runs with the
 * ready mask at every readiness edge and the request stays registered, until
 * it is cancelled, reaches its deadline or fails, which runs the callback a
 * last time with the negative result and drops it. The epoll and kqueue
 * pollers watch such a request edge-triggered (EPOLLET, EV_CLEAR), on a
 * dup(2) of the descriptor so that one-shot requests on the same descriptor
 * keep their level-triggered registration. The poll(2) poller cannot see
 * edges: it reports readiness that persists again after
 * IOR_THREADS_POLLER_MULTI_REARM_NS.
 */
#define IOR_THREADS_POLLER_MULTI (1U << 30)
#define IOR_THREADS_POLLER_MULTI_REARM_NS 1000000ULL

/*
 * An IOR_POLL_* request mask as poll(2) events, for the poll(2) poller and
 * the readiness probes the thread pool makes with poll(2) itself. ERR, HUP
 * and NVAL are output-only for poll(2).
 */
static inline short ior_threads_poller_to_poll(uint32_t ior_mask)
{
	short ev = 0;
	if (ior_mask & IOR_POLL_IN) {
		ev |= POLLIN;
	}
	if (ior_mask & IOR_POLL_OUT) {
		ev |= POLLOUT;
	}
	return ev;
}

/* The IOR_POLL_* mask of what poll(2) reported; POLLNVAL is for the caller. */
static inline uint32_t ior_threads_poller_from_poll(short revents)
{
	uint32_t mask = 0;
	if (revents & POLLIN) {
		mask |= IOR_POLL_IN;
	}
	if (revents & POLLOUT) {
		mask |= IOR_POLL_OUT;
	}
	if (revents & POLLERR) {
		mask |= IOR_POLL_ERR;
	}
	if (revents & POLLHUP) {
		mask |= IOR_POLL_HUP;
	}
	return mask;
}

/*
 * Completion callback, invoked on the poller thread with no poller lock held.
 * res is the ready IOR_POLL_* mask (> 0), -ETIME (deadline reached),
 * -ECANCELED (cancelled or poller shutdown), or another negative errno (e.g.
 * -EBADF). `more` is non-zero for an edge of a multishot request, which stays
 * registered; the request is done with any other call (a multishot one can
 * also end with a positive res, its last readiness, when there are no edges
 * to watch). Must not block for long and must not call back into the poller.
 *
 * The return value matters only for an edge: non-zero declines it, which
 * ends the request. The callback then runs a last time, with that readiness
 * as the result, or with -ECANCELED if a cancel got in first.
 */
typedef int (*ior_threads_poller_cb)(void *owner, void *req, int res, int more);

/* Create the poller and start its thread. */
int ior_threads_poller_create(
		ior_threads_poller **poller_out, void *owner, ior_threads_poller_cb cb);

/*
 * Register a readiness request. ior_mask is an IOR_POLL_* mask, one-shot
 * unless IOR_THREADS_POLLER_MULTI is set; deadline_ns is an absolute monotonic
 * deadline (0 = none). Thread-safe against the poller thread, but not against
 * destroy().
 */
int ior_threads_poller_add(
		ior_threads_poller *poller, int fd, uint32_t ior_mask, uint64_t deadline_ns, void *req);

/*
 * Cancel a pending request. Returns 0 if it was found: it then completes with
 * -ECANCELED on the poller thread, whatever readiness it may see meanwhile.
 * Returns -ENOENT if it has already been dispatched (its callback has run or
 * is running) or was never added. Thread-safe against add() and the poller
 * thread, but not against destroy().
 */
int ior_threads_poller_cancel(ior_threads_poller *poller, void *req);

/*
 * Complete all pending requests with -ECANCELED, then stop and join the
 * poller thread. No add() or cancel() may run concurrently or after.
 */
void ior_threads_poller_destroy(ior_threads_poller *poller);

/*
 * In a forked child, which has no poller thread: close the child's copies of
 * the poller's descriptors and leave the rest. The per-descriptor lists are
 * walked only if no thread held the poller's lock at the fork.
 */
void ior_threads_poller_forget(ior_threads_poller *poller);

#endif /* IOR_THREADS_POLLER_H */
