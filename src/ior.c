#include "config.h"
#include "ior.h"
#include "ior_backend.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static ior_backend_type detect_backend(void)
{
#ifdef IOR_HAVE_URING
	return IOR_BACKEND_IOURING;
#elif defined(IOR_HAVE_IOCP)
	return IOR_BACKEND_IOCP;
#else
	return IOR_BACKEND_THREADS;
#endif
}

static const ior_backend_ops *get_backend_ops(ior_backend_type backend)
{
	switch (backend) {
#ifdef IOR_HAVE_URING
		case IOR_BACKEND_IOURING:
			return &ior_uring_ops;
#endif
		case IOR_BACKEND_THREADS:
			return &ior_threads_ops;
#ifdef IOR_HAVE_IOCP
		case IOR_BACKEND_IOCP:
			return &ior_iocp_ops;
#endif
		default:
			return NULL;
	}
}

int ior_queue_init_params(unsigned entries, ior_ctx **ctx_out, ior_params *params)
{
	if (!ctx_out || !params || entries == 0) {
		return -EINVAL;
	}

	if (params->sq_entries == 0) {
		params->sq_entries = entries;
	}

	ior_backend_type backend = params->backend;
	if (backend == IOR_BACKEND_AUTO) {
		backend = detect_backend();
	}

	const ior_backend_ops *ops = get_backend_ops(backend);
	if (!ops) {
		return -ENOSYS;
	}

	ior_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return -ENOMEM;
	}

	ctx->backend = backend;
	ctx->ops = ops;

	int ret = ops->init(&ctx->backend_ctx, params);
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
		.cq_entries = 0,
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
	ctx->ops->destroy(ctx->backend_ctx);
	free(ctx);
}

/* Submission operations - just call through vtable */
ior_sqe *ior_get_sqe(ior_ctx *ctx)
{
	return ctx ? ctx->ops->get_sqe(ctx->backend_ctx) : NULL;
}

int ior_submit(ior_ctx *ctx)
{
	return ctx ? ctx->ops->submit(ctx->backend_ctx) : -EINVAL;
}

int ior_submit_and_wait(ior_ctx *ctx, unsigned wait_nr)
{
	return ctx ? ctx->ops->submit_and_wait(ctx->backend_ctx, wait_nr) : -EINVAL;
}

/* Completion operations */
int ior_peek_cqe(ior_ctx *ctx, ior_cqe **cqe_out)
{
	return (ctx && cqe_out) ? ctx->ops->peek_cqe(ctx->backend_ctx, cqe_out) : -EINVAL;
}

int ior_wait_cqe(ior_ctx *ctx, ior_cqe **cqe_out)
{
	return (ctx && cqe_out) ? ctx->ops->wait_cqe(ctx->backend_ctx, cqe_out) : -EINVAL;
}

int ior_wait_cqe_timeout(ior_ctx *ctx, ior_cqe **cqe_out, ior_timespec *timeout)
{
	return (ctx && cqe_out) ? ctx->ops->wait_cqe_timeout(ctx->backend_ctx, cqe_out, timeout)
							: -EINVAL;
}

void ior_cqe_seen(ior_ctx *ctx, ior_cqe *cqe)
{
	if (ctx) {
		ctx->ops->cqe_seen(ctx->backend_ctx, cqe);
	}
}

unsigned ior_peek_batch_cqe(ior_ctx *ctx, ior_cqe **cqes, unsigned max)
{
	return (ctx && cqes) ? ctx->ops->peek_batch_cqe(ctx->backend_ctx, cqes, max) : 0;
}

void ior_cq_advance(ior_ctx *ctx, unsigned nr)
{
	if (ctx) {
		ctx->ops->cq_advance(ctx->backend_ctx, nr);
	}
}

/* Helper functions */
void ior_prep_nop(ior_ctx *ctx, ior_sqe *sqe)
{
	if (ctx && sqe) {
		ctx->ops->prep_nop(sqe);
	}
}

void ior_prep_read(ior_ctx *ctx, ior_sqe *sqe, int fd, void *buf, unsigned nbytes, uint64_t offset)
{
	if (ctx && sqe) {
		ctx->ops->prep_read(sqe, fd, buf, nbytes, offset);
	}
}

void ior_prep_write(
		ior_ctx *ctx, ior_sqe *sqe, int fd, const void *buf, unsigned nbytes, uint64_t offset)
{
	if (ctx && sqe) {
		ctx->ops->prep_write(sqe, fd, buf, nbytes, offset);
	}
}

void ior_prep_splice(ior_ctx *ctx, ior_sqe *sqe, int fd_in, uint64_t off_in, int fd_out,
		uint64_t off_out, unsigned nbytes, unsigned flags)
{
	if (ctx && sqe) {
		ctx->ops->prep_splice(sqe, fd_in, off_in, fd_out, off_out, nbytes, flags);
	}
}

void ior_prep_timeout(ior_ctx *ctx, ior_sqe *sqe, ior_timespec *ts, unsigned count, unsigned flags)
{
	if (ctx && sqe) {
		ctx->ops->prep_timeout(sqe, ts, count, flags);
	}
}

void ior_sqe_set_data(ior_ctx *ctx, ior_sqe *sqe, void *data)
{
	if (ctx && sqe) {
		ctx->ops->sqe_set_data(sqe, data);
	}
}

void ior_sqe_set_flags(ior_ctx *ctx, ior_sqe *sqe, uint8_t flags)
{
	if (ctx && sqe) {
		ctx->ops->sqe_set_flags(sqe, flags);
	}
}

void *ior_cqe_get_data(ior_ctx *ctx, ior_cqe *cqe)
{
	return (ctx && cqe) ? ctx->ops->cqe_get_data(cqe) : NULL;
}

int32_t ior_cqe_get_res(ior_ctx *ctx, ior_cqe *cqe)
{
	return (ctx && cqe) ? ctx->ops->cqe_get_res(cqe) : 0;
}

uint32_t ior_cqe_get_flags(ior_ctx *ctx, ior_cqe *cqe)
{
	return (ctx && cqe) ? ctx->ops->cqe_get_flags(cqe) : 0;
}

/* Backend info */
ior_backend_type ior_get_backend_type(ior_ctx *ctx)
{
	return ctx ? ctx->backend : IOR_BACKEND_AUTO;
}

const char *ior_get_backend_name(ior_ctx *ctx)
{
	return ctx ? ctx->ops->backend_name() : "unknown";
}

uint32_t ior_get_features(ior_ctx *ctx)
{
	return ctx ? ctx->ops->get_features(ctx->backend_ctx) : 0;
}
