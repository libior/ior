/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef IOR_URING_H
#define IOR_URING_H

#include "config.h"
#include "ior.h"

#ifdef IOR_HAVE_URING

#include <liburing.h>

// io_uring backend context
typedef struct ior_ctx_uring {
	struct io_uring ring; // Native io_uring
	uint32_t flags; // Setup flags
	uint32_t features; // Supported features
} ior_ctx_uring;

// Initialize io_uring backend
int ior_uring_init(ior_ctx_uring **ctx_out, ior_params *params);

// Destroy io_uring backend
void ior_uring_destroy(ior_ctx_uring *ctx);

// Get submission queue entry
ior_sqe *ior_uring_get_sqe(ior_ctx_uring *ctx);

// Submit operations
int ior_uring_submit(ior_ctx_uring *ctx);
int ior_uring_submit_and_wait(ior_ctx_uring *ctx, unsigned wait_nr);

// Completion handling
int ior_uring_peek_cqe(ior_ctx_uring *ctx, ior_cqe **cqe_out);
int ior_uring_wait_cqe(ior_ctx_uring *ctx, ior_cqe **cqe_out);
int ior_uring_wait_cqe_timeout(ior_ctx_uring *ctx, ior_cqe **cqe_out, struct timespec *timeout);
void ior_uring_cqe_seen(ior_ctx_uring *ctx, ior_cqe *cqe);

// Batch completion handling
unsigned ior_uring_peek_batch_cqe(ior_ctx_uring *ctx, ior_cqe **cqes, unsigned max);
void ior_uring_cq_advance(ior_ctx_uring *ctx, unsigned nr);

// Backend info
const char *ior_uring_backend_name(void);
uint32_t ior_uring_get_features(ior_ctx_uring *ctx);

#endif /* IOR_HAVE_URING */

#endif /* IOR_URING_H */
