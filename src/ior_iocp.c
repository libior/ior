/* SPDX-License-Identifier: BSD-3-Clause */
#include "config.h"
#include "ior_iocp.h"

#ifdef IOR_HAVE_IOCP

#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Convert errno-style error to Windows error
static int win32_error_to_errno(DWORD error)
{
	switch (error) {
		case ERROR_SUCCESS:
			return 0;
		case ERROR_INVALID_HANDLE:
			return -EBADF;
		case ERROR_ACCESS_DENIED:
			return -EACCES;
		case ERROR_NOT_ENOUGH_MEMORY:
			return -ENOMEM;
		case ERROR_INVALID_PARAMETER:
			return -EINVAL;
		case ERROR_OPERATION_ABORTED:
			return -ECANCELED;
		case ERROR_IO_PENDING:
			return -EINPROGRESS;
		case ERROR_TIMEOUT:
			return -ETIMEDOUT;
		default:
			return -EIO;
	}
}

int ior_iocp_init(ior_ctx_iocp **ctx_out, ior_params *params)
{
	if (!ctx_out || !params) {
		return -EINVAL;
	}

	// TODO: Full IOCP implementation
	// This is a stub for now

	return -ENOSYS; // Not yet implemented
}

void ior_iocp_destroy(ior_ctx_iocp *ctx)
{
	if (!ctx) {
		return;
	}

	// TODO: Implementation

	free(ctx);
}

ior_sqe *ior_iocp_get_sqe(ior_ctx_iocp *ctx)
{
	if (!ctx) {
		return NULL;
	}

	// TODO: Implementation
	return NULL;
}

int ior_iocp_submit(ior_ctx_iocp *ctx)
{
	if (!ctx) {
		return -EINVAL;
	}

	// TODO: Implementation
	return -ENOSYS;
}

int ior_iocp_submit_and_wait(ior_ctx_iocp *ctx, unsigned wait_nr)
{
	if (!ctx) {
		return -EINVAL;
	}

	// TODO: Implementation
	return -ENOSYS;
}

int ior_iocp_peek_cqe(ior_ctx_iocp *ctx, ior_cqe **cqe_out)
{
	if (!ctx || !cqe_out) {
		return -EINVAL;
	}

	// TODO: Implementation
	return -EAGAIN;
}

int ior_iocp_wait_cqe(ior_ctx_iocp *ctx, ior_cqe **cqe_out)
{
	if (!ctx || !cqe_out) {
		return -EINVAL;
	}

	// TODO: Implementation
	return -ENOSYS;
}

int ior_iocp_wait_cqe_timeout(ior_ctx_iocp *ctx, ior_cqe **cqe_out, struct timespec *timeout)
{
	if (!ctx || !cqe_out) {
		return -EINVAL;
	}

	// TODO: Implementation
	return -ENOSYS;
}

void ior_iocp_cqe_seen(ior_ctx_iocp *ctx, ior_cqe *cqe)
{
	if (!ctx) {
		return;
	}

	// TODO: Implementation
}

unsigned ior_iocp_peek_batch_cqe(ior_ctx_iocp *ctx, ior_cqe **cqes, unsigned max)
{
	if (!ctx || !cqes || max == 0) {
		return 0;
	}

	// TODO: Implementation
	return 0;
}

void ior_iocp_cq_advance(ior_ctx_iocp *ctx, unsigned nr)
{
	if (!ctx || nr == 0) {
		return;
	}

	// TODO: Implementation
}

const char *ior_iocp_backend_name(void)
{
	return "iocp";
}

uint32_t ior_iocp_get_features(ior_ctx_iocp *ctx)
{
	if (!ctx) {
		return 0;
	}

	return ctx->features;
}

#endif /* IOR_HAVE_IOCP */
