/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef IOR_THREADS_H
#define IOR_THREADS_H

#include "ior.h"
#include "ior_threads_ring.h"
#include "ior_threads_event.h"
#include "ior_threads_pool.h"

// Thread backend context
typedef struct ior_ctx_threads {
	ior_threads_ring sq_ring; // Submission queue
	ior_threads_ring cq_ring; // Completion queue

	ior_threads_event event; // Completion notification
	ior_threads_pool *pool; // Worker thread pool

	uint32_t flags; // Setup flags
	uint32_t features; // Supported features
} ior_ctx_threads;

// Initialize thread backend
int ior_threads_init(ior_ctx_threads **ctx_out, ior_params *params);

// Destroy thread backend
void ior_threads_destroy(ior_ctx_threads *ctx);

// Get submission queue entry
ior_sqe *ior_threads_get_sqe(ior_ctx_threads *ctx);

// Submit operations
int ior_threads_submit(ior_ctx_threads *ctx);
int ior_threads_submit_and_wait(ior_ctx_threads *ctx, unsigned wait_nr);

// Completion handling
int ior_threads_peek_cqe(ior_ctx_threads *ctx, ior_cqe **cqe_out);
int ior_threads_wait_cqe(ior_ctx_threads *ctx, ior_cqe **cqe_out);
int ior_threads_wait_cqe_timeout(ior_ctx_threads *ctx, ior_cqe **cqe_out, struct timespec *timeout);
void ior_threads_cqe_seen(ior_ctx_threads *ctx, ior_cqe *cqe);

// Batch completion handling
unsigned ior_threads_peek_batch_cqe(ior_ctx_threads *ctx, ior_cqe **cqes, unsigned max);
void ior_threads_cq_advance(ior_ctx_threads *ctx, unsigned nr);

// Backend info
const char *ior_threads_backend_name(void);
uint32_t ior_threads_get_features(ior_ctx_threads *ctx);

#endif /* IOR_THREADS_H */
