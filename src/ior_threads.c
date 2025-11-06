/* SPDX-License-Identifier: BSD-3-Clause */
#include "ior_threads.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>

// Default CQ size multiplier if not specified
#define IOR_THREADS_CQ_MULTIPLIER 2

// Default minimum number of entries
#define IOR_THREADS_MIN_ENTRIES 32

// Ensure size is power of 2
static uint32_t round_up_pow2(uint32_t n)
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

int ior_threads_init(ior_ctx_threads **ctx_out, ior_params *params)
{
	if (!ctx_out || !params) {
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
	sq_entries = round_up_pow2(sq_entries);

	uint32_t cq_entries = params->cq_entries;
	if (cq_entries == 0) {
		cq_entries = sq_entries * IOR_THREADS_CQ_MULTIPLIER;
	}
	if (cq_entries < IOR_THREADS_MIN_ENTRIES) {
		cq_entries = IOR_THREADS_MIN_ENTRIES;
	}
	cq_entries = round_up_pow2(cq_entries);

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

	// Create thread pool
	// Use 0 for auto-detect based on CPU count
	uint32_t num_threads = 0; // TODO: Could be configurable via params
	ctx->pool = ior_threads_pool_create(ctx, num_threads);
	if (!ctx->pool) {
		ior_threads_event_destroy(&ctx->event);
		ior_threads_ring_destroy(&ctx->cq_ring);
		ior_threads_ring_destroy(&ctx->sq_ring);
		free(ctx);
		return -ENOMEM;
	}

	// Set supported features
	ctx->features = 0; // No special features for basic thread backend
	params->features = ctx->features;

	*ctx_out = ctx;
	return 0;
}

void ior_threads_destroy(ior_ctx_threads *ctx)
{
	if (!ctx) {
		return;
	}

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

ior_sqe *ior_threads_get_sqe(ior_ctx_threads *ctx)
{
	if (!ctx) {
		return NULL;
	}

	return ior_threads_ring_get_sqe(&ctx->sq_ring);
}

int ior_threads_submit(ior_ctx_threads *ctx)
{
	if (!ctx) {
		return -EINVAL;
	}

	// Get number of pending submissions
	uint32_t count = ior_threads_ring_count(&ctx->sq_ring);
	if (count == 0) {
		return 0;
	}

	// Notify thread pool of new work
	ior_threads_pool_notify(ctx->pool, count);

	return (int) count;
}

int ior_threads_submit_and_wait(ior_ctx_threads *ctx, unsigned wait_nr)
{
	if (!ctx) {
		return -EINVAL;
	}

	// Submit pending operations
	int submitted = ior_threads_submit(ctx);
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

int ior_threads_peek_cqe(ior_ctx_threads *ctx, ior_cqe **cqe_out)
{
	if (!ctx || !cqe_out) {
		return -EINVAL;
	}

	ior_cqe *cqe = ior_threads_ring_peek_cqe(&ctx->cq_ring);
	if (!cqe) {
		return -EAGAIN;
	}

	*cqe_out = cqe;
	return 0;
}

int ior_threads_wait_cqe(ior_ctx_threads *ctx, ior_cqe **cqe_out)
{
	if (!ctx || !cqe_out) {
		return -EINVAL;
	}

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

int ior_threads_wait_cqe_timeout(ior_ctx_threads *ctx, ior_cqe **cqe_out, struct timespec *timeout)
{
	if (!ctx || !cqe_out) {
		return -EINVAL;
	}

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

void ior_threads_cqe_seen(ior_ctx_threads *ctx, ior_cqe *cqe)
{
	if (!ctx) {
		return;
	}

	ior_threads_ring_cqe_seen(&ctx->cq_ring);
}

unsigned ior_threads_peek_batch_cqe(ior_ctx_threads *ctx, ior_cqe **cqes, unsigned max)
{
	if (!ctx || !cqes || max == 0) {
		return 0;
	}

	return ior_threads_ring_peek_batch_cqe(&ctx->cq_ring, cqes, max);
}

void ior_threads_cq_advance(ior_ctx_threads *ctx, unsigned nr)
{
	if (!ctx || nr == 0) {
		return;
	}

	ior_threads_ring_advance(&ctx->cq_ring, nr);
}

const char *ior_threads_backend_name(void)
{
	return "threads";
}

uint32_t ior_threads_get_features(ior_ctx_threads *ctx)
{
	if (!ctx) {
		return 0;
	}

	return ctx->features;
}
