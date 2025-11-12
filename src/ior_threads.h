/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef IOR_THREADS_H
#define IOR_THREADS_H

#include "ior_threads_ring.h"
#include "ior_threads_event.h"
#include "ior_threads_pool.h"

/* Thread backend context */
typedef struct ior_ctx_threads {
	ior_threads_ring sq_ring; // Submission queue
	ior_threads_ring cq_ring; // Completion queue

	ior_threads_event event; // Completion notification
	ior_threads_pool *pool; // Worker thread pool

	uint32_t flags;
	uint32_t features;
} ior_ctx_threads;

/* Default CQ size multiplier if not specified */
#define IOR_THREADS_CQ_MULTIPLIER 2

/* Default minimum number of entries */
#define IOR_THREADS_MIN_ENTRIES 32

#endif /* IOR_THREADS_BACKEND_H */
