/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef IOR_THREADS_POLLER_H
#define IOR_THREADS_POLLER_H

#include "config.h"
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
 * Completion callback, invoked on the poller thread. res is the ready
 * IOR_POLL_* mask (> 0), -ETIME (deadline reached), -ECANCELED (poller
 * shutdown), or another negative errno (e.g. -EBADF). Must not block for
 * long and must not call back into the poller.
 */
typedef void (*ior_threads_poller_cb)(void *owner, void *req, int res);

/* Create the poller and start its thread. */
int ior_threads_poller_create(ior_threads_poller **poller_out, void *owner,
		ior_threads_poller_cb cb);

/*
 * Register a one-shot readiness request. ior_mask is an IOR_POLL_* mask;
 * deadline_ns is an absolute monotonic deadline (0 = none). Thread-safe
 * against the poller thread, but not against destroy().
 */
int ior_threads_poller_add(ior_threads_poller *poller, int fd, uint32_t ior_mask,
		uint64_t deadline_ns, void *req);

/*
 * Complete all pending requests with -ECANCELED, then stop and join the
 * poller thread. No add() may run concurrently or after.
 */
void ior_threads_poller_destroy(ior_threads_poller *poller);

#endif /* IOR_THREADS_POLLER_H */
