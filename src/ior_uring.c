/* SPDX-License-Identifier: BSD-3-Clause */
#include "config.h"

#ifdef IOR_HAVE_URING

#include "ior_backend.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <liburing.h>

/* Backend context */
typedef struct ior_ctx_uring {
	struct io_uring ring;
	uint32_t flags;
	uint32_t features;
} ior_ctx_uring;

/* Backend operations */

static int ior_uring_backend_init(void **backend_ctx, ior_params *params)
{
	if (!backend_ctx || !params) {
		return -EINVAL;
	}

	ior_ctx_uring *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return -ENOMEM;
	}

	ctx->flags = params->flags;

	// Prepare io_uring params
	struct io_uring_params uring_params = { 0 };

	if (params->cq_entries > 0) {
		uring_params.flags |= IORING_SETUP_CQSIZE;
		uring_params.cq_entries = params->cq_entries;
	}

	// Initialize io_uring - if kernel doesn't support it, this fails
	int ret = io_uring_queue_init_params(params->sq_entries, &ctx->ring, &uring_params);
	if (ret < 0) {
		free(ctx);
		return ret;
	}

	// Set features
	ctx->features = IOR_FEAT_NATIVE_ASYNC;

#ifdef IORING_FEAT_FAST_POLL
	if (uring_params.features & IORING_FEAT_FAST_POLL) {
		ctx->features |= IOR_FEAT_POLL_ADD;
	}
#endif

#ifdef IOR_HAVE_SPLICE
	ctx->features |= IOR_FEAT_SPLICE;
#endif

	params->features = ctx->features;
	*backend_ctx = ctx;
	return 0;
}

static void ior_uring_backend_destroy(void *backend_ctx)
{
	if (!backend_ctx) {
		return;
	}

	ior_ctx_uring *ctx = backend_ctx;
	io_uring_queue_exit(&ctx->ring);
	free(ctx);
}

static ior_sqe *ior_uring_backend_get_sqe(void *backend_ctx)
{
	if (!backend_ctx) {
		return NULL;
	}

	ior_ctx_uring *ctx = backend_ctx;
	struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
	if (sqe) {
		memset(sqe, 0, sizeof(*sqe));
	}
	return (ior_sqe *) sqe;
}

static int ior_uring_backend_submit(void *backend_ctx)
{
	if (!backend_ctx) {
		return -EINVAL;
	}

	ior_ctx_uring *ctx = backend_ctx;
	int ret = io_uring_submit(&ctx->ring);
	return ret < 0 ? -errno : ret;
}

static int ior_uring_backend_submit_and_wait(void *backend_ctx, unsigned wait_nr)
{
	if (!backend_ctx) {
		return -EINVAL;
	}

	ior_ctx_uring *ctx = backend_ctx;
	int ret = io_uring_submit_and_wait(&ctx->ring, wait_nr);
	return ret < 0 ? -errno : ret;
}

static int ior_uring_backend_peek_cqe(void *backend_ctx, ior_cqe **cqe_out)
{
	if (!backend_ctx || !cqe_out) {
		return -EINVAL;
	}

	ior_ctx_uring *ctx = backend_ctx;
	struct io_uring_cqe *cqe;
	int ret = io_uring_peek_cqe(&ctx->ring, &cqe);

	if (ret < 0) {
		return ret;
	}

	*cqe_out = (ior_cqe *) cqe;
	return 0;
}

static int ior_uring_backend_wait_cqe(void *backend_ctx, ior_cqe **cqe_out)
{
	if (!backend_ctx || !cqe_out) {
		return -EINVAL;
	}

	ior_ctx_uring *ctx = backend_ctx;
	struct io_uring_cqe *cqe;
	int ret = io_uring_wait_cqe(&ctx->ring, &cqe);

	if (ret < 0) {
		return ret;
	}

	*cqe_out = (ior_cqe *) cqe;
	return 0;
}

static int ior_uring_backend_wait_cqe_timeout(
		void *backend_ctx, ior_cqe **cqe_out, ior_timespec *timeout)
{
	if (!backend_ctx || !cqe_out) {
		return -EINVAL;
	}

	ior_ctx_uring *ctx = backend_ctx;
	struct io_uring_cqe *cqe;

	int ret = io_uring_wait_cqe_timeout(&ctx->ring, &cqe, (struct __kernel_timespec *) timeout);

	if (ret < 0) {
		return ret;
	}

	*cqe_out = (ior_cqe *) cqe;
	return 0;
}

static void ior_uring_backend_cqe_seen(void *backend_ctx, ior_cqe *cqe)
{
	if (!backend_ctx || !cqe) {
		return;
	}

	ior_ctx_uring *ctx = backend_ctx;
	io_uring_cqe_seen(&ctx->ring, (struct io_uring_cqe *) cqe);
}

static unsigned ior_uring_backend_peek_batch_cqe(void *backend_ctx, ior_cqe **cqes, unsigned max)
{
	if (!backend_ctx || !cqes || max == 0) {
		return 0;
	}

	ior_ctx_uring *ctx = backend_ctx;
	struct io_uring_cqe **uring_cqes = (struct io_uring_cqe **) cqes;
	return io_uring_peek_batch_cqe(&ctx->ring, uring_cqes, max);
}

static void ior_uring_backend_cq_advance(void *backend_ctx, unsigned nr)
{
	if (!backend_ctx || nr == 0) {
		return;
	}

	ior_ctx_uring *ctx = backend_ctx;
	io_uring_cq_advance(&ctx->ring, nr);
}

/* SQE preparation helpers - use liburing's helpers directly */

static void ior_uring_backend_prep_nop(ior_sqe *sqe)
{
	struct io_uring_sqe *s = &sqe->uring.sqe;
	io_uring_prep_nop(s);
}

static void ior_uring_backend_prep_read(
		ior_sqe *sqe, int fd, void *buf, unsigned nbytes, uint64_t offset)
{
	struct io_uring_sqe *s = &sqe->uring.sqe;
	io_uring_prep_read(s, fd, buf, nbytes, offset);
}

static void ior_uring_backend_prep_write(
		ior_sqe *sqe, int fd, const void *buf, unsigned nbytes, uint64_t offset)
{
	struct io_uring_sqe *s = &sqe->uring.sqe;
	io_uring_prep_write(s, fd, buf, nbytes, offset);
}

static void ior_uring_backend_prep_splice(ior_sqe *sqe, int fd_in, uint64_t off_in, int fd_out,
		uint64_t off_out, unsigned nbytes, unsigned flags)
{
	struct io_uring_sqe *s = &sqe->uring.sqe;
	io_uring_prep_splice(s, fd_in, off_in, fd_out, off_out, nbytes, flags);
}

static void ior_uring_backend_prep_timeout(
		ior_sqe *sqe, ior_timespec *ts, unsigned count, unsigned flags)
{
	struct io_uring_sqe *s = &sqe->uring.sqe;

	io_uring_prep_timeout(s, (struct __kernel_timespec *) ts, count, flags);
}

static void ior_uring_backend_sqe_set_data(ior_sqe *sqe, void *data)
{
	struct io_uring_sqe *s = &sqe->uring.sqe;
	io_uring_sqe_set_data(s, data);
}

static void ior_uring_backend_sqe_set_flags(ior_sqe *sqe, uint8_t flags)
{
	struct io_uring_sqe *s = &sqe->uring.sqe;
	s->flags = flags;
}

/* CQE accessors */

static void *ior_uring_backend_cqe_get_data(ior_cqe *cqe)
{
	ior_cqe_uring *c = &cqe->uring;
	return io_uring_cqe_get_data((const struct io_uring_cqe *) c);
}

static int32_t ior_uring_backend_cqe_get_res(ior_cqe *cqe)
{
	ior_cqe_uring *c = &cqe->uring;
	return c->res;
}

static uint32_t ior_uring_backend_cqe_get_flags(ior_cqe *cqe)
{
	ior_cqe_uring *c = &cqe->uring;
	return c->flags;
}

/* Backend info */

static const char *ior_uring_backend_name(void)
{
	return "io_uring";
}

static uint32_t ior_uring_backend_get_features(void *backend_ctx)
{
	if (!backend_ctx) {
		return 0;
	}

	ior_ctx_uring *ctx = backend_ctx;
	return ctx->features;
}

/* Export vtable */
const ior_backend_ops ior_uring_ops = {
	.init = ior_uring_backend_init,
	.destroy = ior_uring_backend_destroy,
	.get_sqe = ior_uring_backend_get_sqe,
	.submit = ior_uring_backend_submit,
	.submit_and_wait = ior_uring_backend_submit_and_wait,
	.peek_cqe = ior_uring_backend_peek_cqe,
	.wait_cqe = ior_uring_backend_wait_cqe,
	.wait_cqe_timeout = ior_uring_backend_wait_cqe_timeout,
	.cqe_seen = ior_uring_backend_cqe_seen,
	.peek_batch_cqe = ior_uring_backend_peek_batch_cqe,
	.cq_advance = ior_uring_backend_cq_advance,
	.prep_nop = ior_uring_backend_prep_nop,
	.prep_read = ior_uring_backend_prep_read,
	.prep_write = ior_uring_backend_prep_write,
	.prep_splice = ior_uring_backend_prep_splice,
	.prep_timeout = ior_uring_backend_prep_timeout,
	.sqe_set_data = ior_uring_backend_sqe_set_data,
	.sqe_set_flags = ior_uring_backend_sqe_set_flags,
	.cqe_get_data = ior_uring_backend_cqe_get_data,
	.cqe_get_res = ior_uring_backend_cqe_get_res,
	.cqe_get_flags = ior_uring_backend_cqe_get_flags,
	.backend_name = ior_uring_backend_name,
	.get_features = ior_uring_backend_get_features,
};

#endif /* IOR_HAVE_URING */
