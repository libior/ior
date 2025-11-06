/* SPDX-License-Identifier: BSD-3-Clause */
#include "config.h"
#include "ior.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Backend includes
#ifdef IOR_HAVE_URING
#include "ior_uring.h"
#endif

#include "ior_threads.h"

#ifdef IOR_HAVE_IOCP
#include "ior_iocp.h"
#endif

// Main context structure
struct ior_ctx {
	ior_backend_type backend;

	union {
#ifdef IOR_HAVE_URING
		ior_ctx_uring *uring;
#endif
		ior_ctx_threads *threads;
#ifdef IOR_HAVE_IOCP
		ior_ctx_iocp *iocp;
#endif
		void *ptr;
	} backend_ctx;
};

// Detect best available backend for the platform
static ior_backend_type detect_backend(void)
{
#ifdef IOR_HAVE_URING
	// On Linux with liburing, prefer io_uring
	return IOR_BACKEND_IOURING;
#elif defined(IOR_HAVE_IOCP)
	// On Windows, prefer IOCP
	return IOR_BACKEND_IOCP;
#else
	// Fallback to threads everywhere else
	return IOR_BACKEND_THREADS;
#endif
}

int ior_queue_init_params(unsigned entries, ior_ctx **ctx_out, ior_params *params)
{
	if (!ctx_out || !params) {
		return -EINVAL;
	}

	if (entries == 0) {
		return -EINVAL;
	}

	// Set defaults if not specified
	if (params->sq_entries == 0) {
		params->sq_entries = entries;
	}

	// Determine backend
	ior_backend_type backend = params->backend;
	if (backend == IOR_BACKEND_AUTO) {
		backend = detect_backend();
	}

	// Validate backend availability
	switch (backend) {
		case IOR_BACKEND_IOURING:
#ifndef IOR_HAVE_URING
			return -ENOSYS; // io_uring not available
#endif
			break;

		case IOR_BACKEND_IOCP:
#ifndef IOR_HAVE_IOCP
			return -ENOSYS; // IOCP not available
#endif
			break;

		case IOR_BACKEND_THREADS:
			// Always available
			break;

		default:
			return -EINVAL; // Unknown backend
	}

	// Allocate main context
	ior_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return -ENOMEM;
	}

	ctx->backend = backend;

	int ret = 0;

	// Initialize backend-specific context
	switch (backend) {
#ifdef IOR_HAVE_URING
		case IOR_BACKEND_IOURING:
			ret = ior_uring_init(&ctx->backend_ctx.uring, params);
			break;
#endif

		case IOR_BACKEND_THREADS:
			ret = ior_threads_init(&ctx->backend_ctx.threads, params);
			break;

#ifdef IOR_HAVE_IOCP
		case IOR_BACKEND_IOCP:
			ret = ior_iocp_init(&ctx->backend_ctx.iocp, params);
			break;
#endif

		default:
			ret = -ENOSYS;
			break;
	}

	if (ret < 0) {
		free(ctx);
		return ret;
	}

	*ctx_out = ctx;
	return 0;
}

int ior_queue_init(unsigned entries, ior_ctx **ctx_out)
{
	ior_params params = {
		.sq_entries = entries,
		.cq_entries = 0, // Auto
		.flags = 0,
		.backend = IOR_BACKEND_AUTO,
	};

	return ior_queue_init_params(entries, ctx_out, &params);
}

void ior_queue_exit(ior_ctx *ctx)
{
	if (!ctx) {
		return;
	}

	switch (ctx->backend) {
#ifdef IOR_HAVE_URING
		case IOR_BACKEND_IOURING:
			ior_uring_destroy(ctx->backend_ctx.uring);
			break;
#endif

		case IOR_BACKEND_THREADS:
			ior_threads_destroy(ctx->backend_ctx.threads);
			break;

#ifdef IOR_HAVE_IOCP
		case IOR_BACKEND_IOCP:
			ior_iocp_destroy(ctx->backend_ctx.iocp);
			break;
#endif

		default:
			break;
	}

	free(ctx);
}

ior_sqe *ior_get_sqe(ior_ctx *ctx)
{
	if (!ctx) {
		return NULL;
	}

	switch (ctx->backend) {
#ifdef IOR_HAVE_URING
		case IOR_BACKEND_IOURING:
			return ior_uring_get_sqe(ctx->backend_ctx.uring);
#endif

		case IOR_BACKEND_THREADS:
			return ior_threads_get_sqe(ctx->backend_ctx.threads);

#ifdef IOR_HAVE_IOCP
		case IOR_BACKEND_IOCP:
			return ior_iocp_get_sqe(ctx->backend_ctx.iocp);
#endif

		default:
			return NULL;
	}
}

int ior_submit(ior_ctx *ctx)
{
	if (!ctx) {
		return -EINVAL;
	}

	switch (ctx->backend) {
#ifdef IOR_HAVE_URING
		case IOR_BACKEND_IOURING:
			return ior_uring_submit(ctx->backend_ctx.uring);
#endif

		case IOR_BACKEND_THREADS:
			return ior_threads_submit(ctx->backend_ctx.threads);

#ifdef IOR_HAVE_IOCP
		case IOR_BACKEND_IOCP:
			return ior_iocp_submit(ctx->backend_ctx.iocp);
#endif

		default:
			return -ENOSYS;
	}
}

int ior_submit_and_wait(ior_ctx *ctx, unsigned wait_nr)
{
	if (!ctx) {
		return -EINVAL;
	}

	switch (ctx->backend) {
#ifdef IOR_HAVE_URING
		case IOR_BACKEND_IOURING:
			return ior_uring_submit_and_wait(ctx->backend_ctx.uring, wait_nr);
#endif

		case IOR_BACKEND_THREADS:
			return ior_threads_submit_and_wait(ctx->backend_ctx.threads, wait_nr);

#ifdef IOR_HAVE_IOCP
		case IOR_BACKEND_IOCP:
			return ior_iocp_submit_and_wait(ctx->backend_ctx.iocp, wait_nr);
#endif

		default:
			return -ENOSYS;
	}
}

int ior_peek_cqe(ior_ctx *ctx, ior_cqe **cqe_out)
{
	if (!ctx || !cqe_out) {
		return -EINVAL;
	}

	switch (ctx->backend) {
#ifdef IOR_HAVE_URING
		case IOR_BACKEND_IOURING:
			return ior_uring_peek_cqe(ctx->backend_ctx.uring, cqe_out);
#endif

		case IOR_BACKEND_THREADS:
			return ior_threads_peek_cqe(ctx->backend_ctx.threads, cqe_out);

#ifdef IOR_HAVE_IOCP
		case IOR_BACKEND_IOCP:
			return ior_iocp_peek_cqe(ctx->backend_ctx.iocp, cqe_out);
#endif

		default:
			return -ENOSYS;
	}
}

int ior_wait_cqe(ior_ctx *ctx, ior_cqe **cqe_out)
{
	if (!ctx || !cqe_out) {
		return -EINVAL;
	}

	switch (ctx->backend) {
#ifdef IOR_HAVE_URING
		case IOR_BACKEND_IOURING:
			return ior_uring_wait_cqe(ctx->backend_ctx.uring, cqe_out);
#endif

		case IOR_BACKEND_THREADS:
			return ior_threads_wait_cqe(ctx->backend_ctx.threads, cqe_out);

#ifdef IOR_HAVE_IOCP
		case IOR_BACKEND_IOCP:
			return ior_iocp_wait_cqe(ctx->backend_ctx.iocp, cqe_out);
#endif

		default:
			return -ENOSYS;
	}
}

int ior_wait_cqe_timeout(ior_ctx *ctx, ior_cqe **cqe_out, struct timespec *timeout)
{
	if (!ctx || !cqe_out) {
		return -EINVAL;
	}

	switch (ctx->backend) {
#ifdef IOR_HAVE_URING
		case IOR_BACKEND_IOURING:
			return ior_uring_wait_cqe_timeout(ctx->backend_ctx.uring, cqe_out, timeout);
#endif

		case IOR_BACKEND_THREADS:
			return ior_threads_wait_cqe_timeout(ctx->backend_ctx.threads, cqe_out, timeout);

#ifdef IOR_HAVE_IOCP
		case IOR_BACKEND_IOCP:
			return ior_iocp_wait_cqe_timeout(ctx->backend_ctx.iocp, cqe_out, timeout);
#endif

		default:
			return -ENOSYS;
	}
}

void ior_cqe_seen(ior_ctx *ctx, ior_cqe *cqe)
{
	if (!ctx) {
		return;
	}

	switch (ctx->backend) {
#ifdef IOR_HAVE_URING
		case IOR_BACKEND_IOURING:
			ior_uring_cqe_seen(ctx->backend_ctx.uring, cqe);
			break;
#endif

		case IOR_BACKEND_THREADS:
			ior_threads_cqe_seen(ctx->backend_ctx.threads, cqe);
			break;

#ifdef IOR_HAVE_IOCP
		case IOR_BACKEND_IOCP:
			ior_iocp_cqe_seen(ctx->backend_ctx.iocp, cqe);
			break;
#endif

		default:
			break;
	}
}

unsigned ior_peek_batch_cqe(ior_ctx *ctx, ior_cqe **cqes, unsigned max)
{
	if (!ctx || !cqes || max == 0) {
		return 0;
	}

	switch (ctx->backend) {
#ifdef IOR_HAVE_URING
		case IOR_BACKEND_IOURING:
			return ior_uring_peek_batch_cqe(ctx->backend_ctx.uring, cqes, max);
#endif

		case IOR_BACKEND_THREADS:
			return ior_threads_peek_batch_cqe(ctx->backend_ctx.threads, cqes, max);

#ifdef IOR_HAVE_IOCP
		case IOR_BACKEND_IOCP:
			return ior_iocp_peek_batch_cqe(ctx->backend_ctx.iocp, cqes, max);
#endif

		default:
			return 0;
	}
}

void ior_cq_advance(ior_ctx *ctx, unsigned nr)
{
	if (!ctx || nr == 0) {
		return;
	}

	switch (ctx->backend) {
#ifdef IOR_HAVE_URING
		case IOR_BACKEND_IOURING:
			ior_uring_cq_advance(ctx->backend_ctx.uring, nr);
			break;
#endif

		case IOR_BACKEND_THREADS:
			ior_threads_cq_advance(ctx->backend_ctx.threads, nr);
			break;

#ifdef IOR_HAVE_IOCP
		case IOR_BACKEND_IOCP:
			ior_iocp_cq_advance(ctx->backend_ctx.iocp, nr);
			break;
#endif

		default:
			break;
	}
}

ior_backend_type ior_get_backend_type(ior_ctx *ctx)
{
	return ctx ? ctx->backend : IOR_BACKEND_AUTO;
}

const char *ior_get_backend_name(ior_ctx *ctx)
{
	if (!ctx) {
		return "unknown";
	}

	switch (ctx->backend) {
#ifdef IOR_HAVE_URING
		case IOR_BACKEND_IOURING:
			return ior_uring_backend_name();
#endif

		case IOR_BACKEND_THREADS:
			return ior_threads_backend_name();

#ifdef IOR_HAVE_IOCP
		case IOR_BACKEND_IOCP:
			return ior_iocp_backend_name();
#endif

		default:
			return "unknown";
	}
}

uint32_t ior_get_features(ior_ctx *ctx)
{
	if (!ctx) {
		return 0;
	}

	switch (ctx->backend) {
#ifdef IOR_HAVE_URING
		case IOR_BACKEND_IOURING:
			return ior_uring_get_features(ctx->backend_ctx.uring);
#endif

		case IOR_BACKEND_THREADS:
			return ior_threads_get_features(ctx->backend_ctx.threads);

#ifdef IOR_HAVE_IOCP
		case IOR_BACKEND_IOCP:
			return ior_iocp_get_features(ctx->backend_ctx.iocp);
#endif

		default:
			return 0;
	}
}
