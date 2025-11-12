/* SPDX-License-Identifier: BSD-3-Clause */
#include "config.h"
#include "ior_backend.h"
#include "ior_threads.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>

/* Ensure size is power of 2 */
static uint32_t ior_threads_round_up_pow2(uint32_t n)
{
	if (n == 0) {
		return 1;
	}

	n--;
	n |= n >> 1;
	n |= n >> 2;
	n |= n >> 4;
	n |= n >> 8;
	n |= n >> 16;
	n++;

	return n;
}

/* Backend operations */

static int ior_threads_backend_init(void **backend_ctx, ior_params *params)
{
	if (!backend_ctx || !params) {
		return -EINVAL;
	}

	// Allocate context
	ior_ctx_threads *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return -ENOMEM;
	}

	ctx->flags = params->flags;

	// Determine ring sizes
	uint32_t sq_entries = params->sq_entries;
	if (sq_entries < IOR_THREADS_MIN_ENTRIES) {
		sq_entries = IOR_THREADS_MIN_ENTRIES;
	}
	sq_entries = ior_threads_round_up_pow2(sq_entries);

	uint32_t cq_entries = params->cq_entries;
	if (cq_entries == 0) {
		cq_entries = sq_entries * IOR_THREADS_CQ_MULTIPLIER;
	}
	if (cq_entries < IOR_THREADS_MIN_ENTRIES) {
		cq_entries = IOR_THREADS_MIN_ENTRIES;
	}
	cq_entries = ior_threads_round_up_pow2(cq_entries);

	// Initialize submission queue ring
	int ret = ior_threads_ring_init(&ctx->sq_ring, sq_entries, 1);
	if (ret < 0) {
		free(ctx);
		return ret;
	}

	// Initialize completion queue ring
	ret = ior_threads_ring_init(&ctx->cq_ring, cq_entries, 0);
	if (ret < 0) {
		ior_threads_ring_destroy(&ctx->sq_ring);
		free(ctx);
		return ret;
	}

	// Initialize event notification
	ret = ior_threads_event_init(&ctx->event);
	if (ret < 0) {
		ior_threads_ring_destroy(&ctx->cq_ring);
		ior_threads_ring_destroy(&ctx->sq_ring);
		free(ctx);
		return ret;
	}

	// Create thread pool (0 = auto-detect based on CPU count)
	ctx->pool = ior_threads_pool_create(ctx, 0);
	if (!ctx->pool) {
		ior_threads_event_destroy(&ctx->event);
		ior_threads_ring_destroy(&ctx->cq_ring);
		ior_threads_ring_destroy(&ctx->sq_ring);
		free(ctx);
		return -ENOMEM;
	}

	// Set supported features
	ctx->features = 0; // No special features for basic thread backend
#ifdef IOR_HAVE_SPLICE
	ctx->features |= IOR_FEAT_SPLICE;
#endif

	params->features = ctx->features;

	*backend_ctx = ctx;
	return 0;
}

static void ior_threads_backend_destroy(void *backend_ctx)
{
	if (!backend_ctx) {
		return;
	}

	ior_ctx_threads *ctx = backend_ctx;

	// Destroy thread pool first (waits for threads to finish)
	ior_threads_pool_destroy(ctx->pool);

	// Cleanup event notification
	ior_threads_event_destroy(&ctx->event);

	// Cleanup rings
	ior_threads_ring_destroy(&ctx->cq_ring);
	ior_threads_ring_destroy(&ctx->sq_ring);

	// Free context
	free(ctx);
}

static ior_sqe *ior_threads_backend_get_sqe(void *backend_ctx)
{
	if (!backend_ctx) {
		return NULL;
	}

	ior_ctx_threads *ctx = backend_ctx;
	return ior_threads_ring_get_sqe(&ctx->sq_ring);
}

static int ior_threads_backend_submit(void *backend_ctx)
{
	if (!backend_ctx) {
		return -EINVAL;
	}

	ior_ctx_threads *ctx = backend_ctx;

	// Get number of pending submissions
	uint32_t count = ior_threads_ring_count(&ctx->sq_ring);
	if (count == 0) {
		return 0;
	}

	// Notify thread pool of new work
	ior_threads_pool_notify(ctx->pool, count);

	return (int) count;
}

static int ior_threads_backend_submit_and_wait(void *backend_ctx, unsigned wait_nr)
{
	if (!backend_ctx) {
		return -EINVAL;
	}

	ior_ctx_threads *ctx = backend_ctx;

	// Submit pending operations
	int submitted = ior_threads_backend_submit(backend_ctx);
	if (submitted < 0) {
		return submitted;
	}

	// Wait for at least wait_nr completions
	if (wait_nr == 0) {
		return submitted;
	}

	// Wait for completions to become available
	while (ior_threads_ring_count(&ctx->cq_ring) < wait_nr) {
		int ret = ior_threads_event_wait(&ctx->event, -1);
		if (ret < 0) {
			return ret;
		}
		ior_threads_event_clear(&ctx->event);
	}

	return submitted;
}

static int ior_threads_backend_peek_cqe(void *backend_ctx, ior_cqe **cqe_out)
{
	if (!backend_ctx || !cqe_out) {
		return -EINVAL;
	}

	ior_ctx_threads *ctx = backend_ctx;

	ior_cqe *cqe = ior_threads_ring_peek_cqe(&ctx->cq_ring);
	if (!cqe) {
		return -EAGAIN;
	}

	*cqe_out = cqe;
	return 0;
}

static int ior_threads_backend_wait_cqe(void *backend_ctx, ior_cqe **cqe_out)
{
	if (!backend_ctx || !cqe_out) {
		return -EINVAL;
	}

	ior_ctx_threads *ctx = backend_ctx;

	// Fast path: check if CQE already available
	ior_cqe *cqe = ior_threads_ring_peek_cqe(&ctx->cq_ring);
	if (cqe) {
		*cqe_out = cqe;
		return 0;
	}

	// Wait for notification
	int ret = ior_threads_event_wait(&ctx->event, -1);
	if (ret < 0) {
		return ret;
	}

	// Clear all pending notifications
	ior_threads_event_clear(&ctx->event);

	// Get CQE
	cqe = ior_threads_ring_peek_cqe(&ctx->cq_ring);
	if (!cqe) {
		return -EAGAIN; // Spurious wakeup
	}

	*cqe_out = cqe;
	return 0;
}

static int ior_threads_backend_wait_cqe_timeout(
		void *backend_ctx, ior_cqe **cqe_out, ior_timespec *timeout)
{
	if (!backend_ctx || !cqe_out) {
		return -EINVAL;
	}

	ior_ctx_threads *ctx = backend_ctx;

	// Fast path: check if CQE already available
	ior_cqe *cqe = ior_threads_ring_peek_cqe(&ctx->cq_ring);
	if (cqe) {
		*cqe_out = cqe;
		return 0;
	}

	// Convert timespec to milliseconds for event_wait
	int timeout_ms = -1; // Infinite by default

	if (timeout) {
		if (timeout->tv_sec < 0 || timeout->tv_nsec < 0 || timeout->tv_nsec >= 1000000000L) {
			return -EINVAL;
		}

		// Convert to milliseconds
		timeout_ms = (int) (timeout->tv_sec * 1000 + timeout->tv_nsec / 1000000);

		// Handle zero timeout specially
		if (timeout_ms == 0 && (timeout->tv_sec > 0 || timeout->tv_nsec > 0)) {
			timeout_ms = 1; // At least 1ms
		}
	}

	// Wait with timeout
	int ret = ior_threads_event_wait(&ctx->event, timeout_ms);
	if (ret < 0) {
		return ret; // -ETIMEDOUT or other error
	}

	// Clear notifications
	ior_threads_event_clear(&ctx->event);

	// Get CQE
	cqe = ior_threads_ring_peek_cqe(&ctx->cq_ring);
	if (!cqe) {
		return -EAGAIN; // Spurious wakeup or timeout
	}

	*cqe_out = cqe;
	return 0;
}

static void ior_threads_backend_cqe_seen(void *backend_ctx, ior_cqe *cqe)
{
	if (!backend_ctx) {
		return;
	}

	ior_ctx_threads *ctx = backend_ctx;
	ior_threads_ring_cqe_seen(&ctx->cq_ring);
}

static unsigned ior_threads_backend_peek_batch_cqe(void *backend_ctx, ior_cqe **cqes, unsigned max)
{
	if (!backend_ctx || !cqes || max == 0) {
		return 0;
	}

	ior_ctx_threads *ctx = backend_ctx;
	return ior_threads_ring_peek_batch_cqe(&ctx->cq_ring, cqes, max);
}

static void ior_threads_backend_cq_advance(void *backend_ctx, unsigned nr)
{
	if (!backend_ctx || nr == 0) {
		return;
	}

	ior_ctx_threads *ctx = backend_ctx;
	ior_threads_ring_advance(&ctx->cq_ring, nr);
}

/* SQE preparation helpers */

static void ior_threads_backend_prep_nop(ior_sqe *sqe)
{
	memset(sqe, 0, sizeof(*sqe));
	sqe->threads.opcode = IOR_OP_NOP;
	sqe->threads.fd = -1;
}

static void ior_threads_backend_prep_read(
		ior_sqe *sqe, int fd, void *buf, unsigned nbytes, uint64_t offset)
{
	memset(sqe, 0, sizeof(*sqe));
	sqe->threads.opcode = IOR_OP_READ;
	sqe->threads.fd = fd;
	sqe->threads.addr = (uint64_t) (uintptr_t) buf;
	sqe->threads.len = nbytes;
	sqe->threads.off = offset;
}

static void ior_threads_backend_prep_write(
		ior_sqe *sqe, int fd, const void *buf, unsigned nbytes, uint64_t offset)
{
	memset(sqe, 0, sizeof(*sqe));
	sqe->threads.opcode = IOR_OP_WRITE;
	sqe->threads.fd = fd;
	sqe->threads.addr = (uint64_t) (uintptr_t) buf;
	sqe->threads.len = nbytes;
	sqe->threads.off = offset;
}

static void ior_threads_backend_prep_splice(ior_sqe *sqe, int fd_in, uint64_t off_in, int fd_out,
		uint64_t off_out, unsigned nbytes, unsigned flags)
{
	memset(sqe, 0, sizeof(*sqe));
	sqe->threads.opcode = IOR_OP_SPLICE;
	sqe->threads.fd = fd_out;
	sqe->threads.len = nbytes;
	sqe->threads.off = off_out;
	sqe->threads.splice_off_in = off_in;
	sqe->threads.splice_fd_in = fd_in;
	sqe->threads.splice_flags = flags;
}

static void ior_threads_backend_prep_timeout(
		ior_sqe *sqe, ior_timespec *ts, unsigned count, unsigned flags)
{
	memset(sqe, 0, sizeof(*sqe));
	sqe->threads.opcode = IOR_OP_TIMER;
	sqe->threads.fd = -1;
	sqe->threads.addr = (uint64_t) (uintptr_t) ts;
	sqe->threads.len = 1;
	sqe->threads.off = count;
	sqe->threads.timeout_flags = flags;
}

static void ior_threads_backend_sqe_set_data(ior_sqe *sqe, void *data)
{
	sqe->threads.user_data = (uint64_t) (uintptr_t) data;
}

static void ior_threads_backend_sqe_set_flags(ior_sqe *sqe, uint8_t flags)
{
	sqe->threads.flags = flags;
}

/* CQE accessors */

static void *ior_threads_backend_cqe_get_data(ior_cqe *cqe)
{
	return (void *) (uintptr_t) cqe->threads.user_data;
}

static int32_t ior_threads_backend_cqe_get_res(ior_cqe *cqe)
{
	return cqe->threads.res;
}

static uint32_t ior_threads_backend_cqe_get_flags(ior_cqe *cqe)
{
	return cqe->threads.flags;
}

/* Backend info */

static const char *ior_threads_backend_name(void)
{
	return "threads";
}

static uint32_t ior_threads_backend_get_features(void *backend_ctx)
{
	if (!backend_ctx) {
		return 0;
	}

	ior_ctx_threads *ctx = backend_ctx;
	return ctx->features;
}

/* Export vtable */
const ior_backend_ops ior_threads_ops = {
	.init = ior_threads_backend_init,
	.destroy = ior_threads_backend_destroy,
	.get_sqe = ior_threads_backend_get_sqe,
	.submit = ior_threads_backend_submit,
	.submit_and_wait = ior_threads_backend_submit_and_wait,
	.peek_cqe = ior_threads_backend_peek_cqe,
	.wait_cqe = ior_threads_backend_wait_cqe,
	.wait_cqe_timeout = ior_threads_backend_wait_cqe_timeout,
	.cqe_seen = ior_threads_backend_cqe_seen,
	.peek_batch_cqe = ior_threads_backend_peek_batch_cqe,
	.cq_advance = ior_threads_backend_cq_advance,
	.prep_nop = ior_threads_backend_prep_nop,
	.prep_read = ior_threads_backend_prep_read,
	.prep_write = ior_threads_backend_prep_write,
	.prep_splice = ior_threads_backend_prep_splice,
	.prep_timeout = ior_threads_backend_prep_timeout,
	.sqe_set_data = ior_threads_backend_sqe_set_data,
	.sqe_set_flags = ior_threads_backend_sqe_set_flags,
	.cqe_get_data = ior_threads_backend_cqe_get_data,
	.cqe_get_res = ior_threads_backend_cqe_get_res,
	.cqe_get_flags = ior_threads_backend_cqe_get_flags,
	.backend_name = ior_threads_backend_name,
	.get_features = ior_threads_backend_get_features,
};
