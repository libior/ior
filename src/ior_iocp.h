/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef IOR_IOCP_H
#define IOR_IOCP_H

#include "config.h"
#include "ior.h"

#ifdef IOR_HAVE_IOCP

#include <windows.h>

// IOCP backend context
typedef struct ior_ctx_iocp {
	HANDLE iocp_handle; // I/O Completion Port handle

	// Submission queue (software emulation)
	ior_sqe *sq_ring;
	uint32_t sq_size;
	uint32_t sq_mask;
	uint32_t sq_head;
	uint32_t sq_tail;

	// Completion queue (software emulation)
	ior_cqe *cq_ring;
	uint32_t cq_size;
	uint32_t cq_mask;
	uint32_t cq_head;
	uint32_t cq_tail;

	CRITICAL_SECTION sq_lock; // Protect submission queue
	CRITICAL_SECTION cq_lock; // Protect completion queue

	HANDLE *worker_threads; // Worker thread handles
	uint32_t num_workers; // Number of worker threads

	volatile LONG shutdown; // Shutdown flag

	uint32_t flags; // Setup flags
	uint32_t features; // Supported features
} ior_ctx_iocp;

// IOCP overlapped structure extension
typedef struct ior_overlapped {
	OVERLAPPED overlapped; // Must be first
	ior_sqe sqe; // Copy of submission
	ior_ctx_iocp *ctx; // Context pointer
} ior_overlapped;

// Initialize IOCP backend
int ior_iocp_init(ior_ctx_iocp **ctx_out, ior_params *params);

// Destroy IOCP backend
void ior_iocp_destroy(ior_ctx_iocp *ctx);

// Get submission queue entry
ior_sqe *ior_iocp_get_sqe(ior_ctx_iocp *ctx);

// Submit operations
int ior_iocp_submit(ior_ctx_iocp *ctx);
int ior_iocp_submit_and_wait(ior_ctx_iocp *ctx, unsigned wait_nr);

// Completion handling
int ior_iocp_peek_cqe(ior_ctx_iocp *ctx, ior_cqe **cqe_out);
int ior_iocp_wait_cqe(ior_ctx_iocp *ctx, ior_cqe **cqe_out);
int ior_iocp_wait_cqe_timeout(ior_ctx_iocp *ctx, ior_cqe **cqe_out, struct timespec *timeout);
void ior_iocp_cqe_seen(ior_ctx_iocp *ctx, ior_cqe *cqe);

// Batch completion handling
unsigned ior_iocp_peek_batch_cqe(ior_ctx_iocp *ctx, ior_cqe **cqes, unsigned max);
void ior_iocp_cq_advance(ior_ctx_iocp *ctx, unsigned nr);

// Backend info
const char *ior_iocp_backend_name(void);
uint32_t ior_iocp_get_features(ior_ctx_iocp *ctx);

#endif /* IOR_HAVE_IOCP */

#endif /* IOR_IOCP_H */
