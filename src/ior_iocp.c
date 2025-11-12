/* SPDX-License-Identifier: BSD-3-Clause */ /* SPDX-License-Identifier: BSD-3-Clause */
#include "config.h"

#ifdef IOR_HAVE_IOCP

#include "ior_backend.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <windows.h>

/* For IOCP backend, we'll have our own SQE/CQE structures (similar to threads) */
typedef struct ior_sqe ior_sqe;
typedef struct ior_cqe ior_cqe;

/* SQE structure - our own format */
struct ior_sqe {
	uint8_t opcode;
	uint8_t flags;
	uint16_t ioprio;
	int32_t fd;
	uint64_t off;
	uint64_t addr;
	uint32_t len;
	union {
		uint32_t rw_flags;
		uint32_t timeout_flags;
	};
	uint64_t user_data;
	uint32_t file_index;
	uint64_t __pad[3];
};

/* CQE structure - our own format */
struct ior_cqe {
	uint64_t user_data;
	int32_t res;
	uint32_t flags;
};

/* IOCP backend context */
typedef struct ior_ctx_iocp {
	HANDLE iocp_handle;

	// TODO: Add actual IOCP structures
	// - Pending operations tracking
	// - Overlapped structures pool
	// - Worker threads (if needed)

	uint32_t flags;
	uint32_t features;
} ior_ctx_iocp;

/* Backend operations - all stubs for now */

static int ior_iocp_backend_init(void **backend_ctx, ior_params *params)
{
	if (!backend_ctx || !params) {
		return -EINVAL;
	}

	// TODO: Implement IOCP initialization
	return -ENOSYS;
}

static void ior_iocp_backend_destroy(void *backend_ctx)
{
	if (!backend_ctx) {
		return;
	}

	// TODO: Implement IOCP cleanup
	free(backend_ctx);
}

static ior_sqe *ior_iocp_backend_get_sqe(void *backend_ctx)
{
	if (!backend_ctx) {
		return NULL;
	}

	// TODO: Implement
	return NULL;
}

static int ior_iocp_backend_submit(void *backend_ctx)
{
	if (!backend_ctx) {
		return -EINVAL;
	}

	// TODO: Implement
	return -ENOSYS;
}

static int ior_iocp_backend_submit_and_wait(void *backend_ctx, unsigned wait_nr)
{
	if (!backend_ctx) {
		return -EINVAL;
	}

	// TODO: Implement
	return -ENOSYS;
}

static int ior_iocp_backend_peek_cqe(void *backend_ctx, ior_cqe **cqe_out)
{
	if (!backend_ctx || !cqe_out) {
		return -EINVAL;
	}

	// TODO: Implement
	return -EAGAIN;
}

static int ior_iocp_backend_wait_cqe(void *backend_ctx, ior_cqe **cqe_out)
{
	if (!backend_ctx || !cqe_out) {
		return -EINVAL;
	}

	// TODO: Implement
	return -ENOSYS;
}

static int ior_iocp_backend_wait_cqe_timeout(
		void *backend_ctx, ior_cqe **cqe_out, struct timespec *timeout)
{
	if (!backend_ctx || !cqe_out) {
		return -EINVAL;
	}

	// TODO: Implement
	return -ENOSYS;
}

static void ior_iocp_backend_cqe_seen(void *backend_ctx, ior_cqe *cqe)
{
	if (!backend_ctx || !cqe) {
		return;
	}

	// TODO: Implement
}

static unsigned ior_iocp_backend_peek_batch_cqe(void *backend_ctx, ior_cqe **cqes, unsigned max)
{
	if (!backend_ctx || !cqes || max == 0) {
		return 0;
	}

	// TODO: Implement
	return 0;
}

static void ior_iocp_backend_cq_advance(void *backend_ctx, unsigned nr)
{
	if (!backend_ctx || nr == 0) {
		return;
	}

	// TODO: Implement
}

/* SQE preparation helpers */

static void ior_iocp_backend_prep_nop(ior_sqe *sqe)
{
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IOR_OP_NOP;
	sqe->fd = -1;
}

static void ior_iocp_backend_prep_read(
		ior_sqe *sqe, int fd, void *buf, unsigned nbytes, uint64_t offset)
{
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IOR_OP_READ;
	sqe->fd = fd;
	sqe->addr = (uint64_t) (uintptr_t) buf;
	sqe->len = nbytes;
	sqe->off = offset;
}

static void ior_iocp_backend_prep_write(
		ior_sqe *sqe, int fd, const void *buf, unsigned nbytes, uint64_t offset)
{
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IOR_OP_WRITE;
	sqe->fd = fd;
	sqe->addr = (uint64_t) (uintptr_t) buf;
	sqe->len = nbytes;
	sqe->off = offset;
}

static void ior_iocp_backend_prep_splice(ior_sqe *sqe, int fd_in, uint64_t off_in, int fd_out,
		uint64_t off_out, unsigned nbytes, unsigned flags)
{
	// Splice not supported on Windows
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IOR_OP_SPLICE;
	sqe->fd = -1;
}

static void ior_iocp_backend_prep_timeout(
		ior_sqe *sqe, struct timespec *ts, unsigned count, unsigned flags)
{
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IOR_OP_TIMER;
	sqe->fd = -1;
	sqe->addr = (uint64_t) (uintptr_t) ts;
	sqe->len = 1;
	sqe->off = count;
	sqe->timeout_flags = flags;
}

static void ior_iocp_backend_sqe_set_data(ior_sqe *sqe, void *data)
{
	sqe->user_data = (uint64_t) (uintptr_t) data;
}

static void ior_iocp_backend_sqe_set_flags(ior_sqe *sqe, uint8_t flags)
{
	sqe->flags = flags;
}

/* CQE accessors */

static void *ior_iocp_backend_cqe_get_data(ior_cqe *cqe)
{
	return (void *) (uintptr_t) cqe->user_data;
}

static int32_t ior_iocp_backend_cqe_get_res(ior_cqe *cqe)
{
	return cqe->res;
}

static uint32_t ior_iocp_backend_cqe_get_flags(ior_cqe *cqe)
{
	return cqe->flags;
}

/* Backend info */

static const char *ior_iocp_backend_name(void)
{
	return "iocp";
}

static uint32_t ior_iocp_backend_get_features(void *backend_ctx)
{
	if (!backend_ctx) {
		return 0;
	}

	ior_ctx_iocp *ctx = backend_ctx;
	return ctx->features;
}

/* Export vtable */
const ior_backend_ops ior_iocp_ops = {
	.init = ior_iocp_backend_init,
	.destroy = ior_iocp_backend_destroy,
	.get_sqe = ior_iocp_backend_get_sqe,
	.submit = ior_iocp_backend_submit,
	.submit_and_wait = ior_iocp_backend_submit_and_wait,
	.peek_cqe = ior_iocp_backend_peek_cqe,
	.wait_cqe = ior_iocp_backend_wait_cqe,
	.wait_cqe_timeout = ior_iocp_backend_wait_cqe_timeout,
	.cqe_seen = ior_iocp_backend_cqe_seen,
	.peek_batch_cqe = ior_iocp_backend_peek_batch_cqe,
	.cq_advance = ior_iocp_backend_cq_advance,
	.prep_nop = ior_iocp_backend_prep_nop,
	.prep_read = ior_iocp_backend_prep_read,
	.prep_write = ior_iocp_backend_prep_write,
	.prep_splice = ior_iocp_backend_prep_splice,
	.prep_timeout = ior_iocp_backend_prep_timeout,
	.sqe_set_data = ior_iocp_backend_sqe_set_data,
	.sqe_set_flags = ior_iocp_backend_sqe_set_flags,
	.cqe_get_data = ior_iocp_backend_cqe_get_data,
	.cqe_get_res = ior_iocp_backend_cqe_get_res,
	.cqe_get_flags = ior_iocp_backend_cqe_get_flags,
	.backend_name = ior_iocp_backend_name,
	.get_features = ior_iocp_backend_get_features,
};

#endif /* IOR_HAVE_IOCP */
