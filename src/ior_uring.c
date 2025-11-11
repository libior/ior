/* SPDX-License-Identifier: BSD-3-Clause */
#include "config.h"
#include "ior_uring.h"

#ifdef IOR_HAVE_URING

#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Convert ior_sqe to io_uring_sqe
static inline void ior_to_uring_sqe(struct io_uring_sqe *uring_sqe, const ior_sqe *ior_sqe)
{
	// Zero out the io_uring sqe first
	memset(uring_sqe, 0, sizeof(*uring_sqe));

	// Copy fields - most map directly
	uring_sqe->opcode = ior_sqe->opcode;
	uring_sqe->flags = ior_sqe->flags;
	uring_sqe->ioprio = ior_sqe->ioprio;
	uring_sqe->fd = ior_sqe->fd;
	uring_sqe->off = ior_sqe->off;
	uring_sqe->addr = ior_sqe->addr;
	uring_sqe->len = ior_sqe->len;
	uring_sqe->user_data = ior_sqe->user_data;

	// Copy union fields based on operation
	switch (ior_sqe->opcode) {
		case IOR_OP_READ:
		case IOR_OP_WRITE:
			uring_sqe->rw_flags = ior_sqe->rw_flags;
			break;
		case IOR_OP_SPLICE:
			uring_sqe->splice_flags = ior_sqe->splice_flags;
			uring_sqe->splice_fd_in = ior_sqe->splice_fd_in;
			break;
		case IOR_OP_TIMER:
			uring_sqe->timeout_flags = ior_sqe->timeout_flags;
			break;
	}

	uring_sqe->buf_index = ior_sqe->buf_index;
	uring_sqe->personality = ior_sqe->personality;
	uring_sqe->file_index = ior_sqe->file_index;
}

// Convert io_uring_cqe to ior_cqe
static inline void uring_to_ior_cqe(ior_cqe *ior_cqe, const struct io_uring_cqe *uring_cqe)
{
	ior_cqe->user_data = uring_cqe->user_data;
	ior_cqe->res = uring_cqe->res;
	ior_cqe->flags = uring_cqe->flags;
}

int ior_uring_init(ior_ctx_uring **ctx_out, ior_params *params)
{
	if (!ctx_out || !params) {
		return -EINVAL;
	}

	// Allocate context
	ior_ctx_uring *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return -ENOMEM;
	}

	ctx->flags = params->flags;

	// Prepare io_uring params
	struct io_uring_params uring_params;
	memset(&uring_params, 0, sizeof(uring_params));

	// Map flags
	if (params->flags & IOR_SETUP_SQPOLL) {
		uring_params.flags |= IORING_SETUP_SQPOLL;
		uring_params.sq_thread_cpu = params->sq_thread_cpu;
		uring_params.sq_thread_idle = params->sq_thread_idle;
	}
	if (params->flags & IOR_SETUP_IOPOLL) {
		uring_params.flags |= IORING_SETUP_IOPOLL;
	}

	// Set CQ size if specified
	if (params->cq_entries > 0) {
		uring_params.flags |= IORING_SETUP_CQSIZE;
		uring_params.cq_entries = params->cq_entries;
	}

	// Initialize io_uring
	int ret = io_uring_queue_init_params(params->sq_entries, &ctx->ring, &uring_params);
	if (ret < 0) {
		free(ctx);
		return ret;
	}

	// Extract features
	ctx->features = IOR_FEAT_NATIVE_ASYNC;

	if (uring_params.features & IORING_FEAT_FAST_POLL) {
		ctx->features |= IOR_FEAT_POLL_ADD;
	}
	if (uring_params.features & IORING_FEAT_SQPOLL_NONFIXED) {
		ctx->features |= IOR_FEAT_SQPOLL;
	}

#ifdef IOR_HAVE_SPLICE
	// Check if splice is supported (Linux-specific)
	ctx->features |= IOR_FEAT_SPLICE;
#endif

	params->features = ctx->features;

	*ctx_out = ctx;
	return 0;
}

void ior_uring_destroy(ior_ctx_uring *ctx)
{
	if (!ctx) {
		return;
	}

	io_uring_queue_exit(&ctx->ring);
	free(ctx);
}

ior_sqe *ior_uring_get_sqe(ior_ctx_uring *ctx)
{
	if (!ctx) {
		return NULL;
	}

	// Get io_uring sqe
	struct io_uring_sqe *uring_sqe = io_uring_get_sqe(&ctx->ring);
	if (!uring_sqe) {
		return NULL;
	}

	// Return as ior_sqe (they have compatible layout for basic fields)
	// User will fill it in using ior_prep_* functions
	// We'll convert to proper io_uring format on submit
	return (ior_sqe *) uring_sqe;
}

int ior_uring_submit(ior_ctx_uring *ctx)
{
	if (!ctx) {
		return -EINVAL;
	}

	// For io_uring, we can submit directly since the SQE layout is compatible
	// The ior_prep_* functions write the fields that io_uring expects
	int ret = io_uring_submit(&ctx->ring);
	return ret < 0 ? -errno : ret;
}

int ior_uring_submit_and_wait(ior_ctx_uring *ctx, unsigned wait_nr)
{
	if (!ctx) {
		return -EINVAL;
	}

	int ret = io_uring_submit_and_wait(&ctx->ring, wait_nr);
	return ret < 0 ? -errno : ret;
}

int ior_uring_peek_cqe(ior_ctx_uring *ctx, ior_cqe **cqe_out)
{
	if (!ctx || !cqe_out) {
		return -EINVAL;
	}

	struct io_uring_cqe *uring_cqe;
	int ret = io_uring_peek_cqe(&ctx->ring, &uring_cqe);

	if (ret < 0) {
		return ret;
	}

	// CQE layout is compatible, just cast
	*cqe_out = (ior_cqe *) uring_cqe;
	return 0;
}

int ior_uring_wait_cqe(ior_ctx_uring *ctx, ior_cqe **cqe_out)
{
	if (!ctx || !cqe_out) {
		return -EINVAL;
	}

	struct io_uring_cqe *uring_cqe;
	int ret = io_uring_wait_cqe(&ctx->ring, &uring_cqe);

	if (ret < 0) {
		return ret;
	}

	*cqe_out = (ior_cqe *) uring_cqe;
	return 0;
}

int ior_uring_wait_cqe_timeout(ior_ctx_uring *ctx, ior_cqe **cqe_out, struct timespec *timeout)
{
	if (!ctx || !cqe_out) {
		return -EINVAL;
	}

	struct io_uring_cqe *uring_cqe;
	struct __kernel_timespec ts;

	if (timeout) {
		ts.tv_sec = timeout->tv_sec;
		ts.tv_nsec = timeout->tv_nsec;
	}

	int ret = io_uring_wait_cqe_timeout(&ctx->ring, &uring_cqe, timeout ? &ts : NULL);

	if (ret < 0) {
		return ret;
	}

	*cqe_out = (ior_cqe *) uring_cqe;
	return 0;
}

void ior_uring_cqe_seen(ior_ctx_uring *ctx, ior_cqe *cqe)
{
	if (!ctx || !cqe) {
		return;
	}

	io_uring_cqe_seen(&ctx->ring, (struct io_uring_cqe *) cqe);
}

unsigned ior_uring_peek_batch_cqe(ior_ctx_uring *ctx, ior_cqe **cqes, unsigned max)
{
	if (!ctx || !cqes || max == 0) {
		return 0;
	}

	struct io_uring_cqe **uring_cqes = (struct io_uring_cqe **) cqes;
	return io_uring_peek_batch_cqe(&ctx->ring, uring_cqes, max);
}

void ior_uring_cq_advance(ior_ctx_uring *ctx, unsigned nr)
{
	if (!ctx || nr == 0) {
		return;
	}

	io_uring_cq_advance(&ctx->ring, nr);
}

const char *ior_uring_backend_name(void)
{
	return "io_uring";
}

uint32_t ior_uring_get_features(ior_ctx_uring *ctx)
{
	if (!ctx) {
		return 0;
	}

	return ctx->features;
}

#endif /* IOR_HAVE_URING */
