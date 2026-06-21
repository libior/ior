/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * test_sq_reuse.c - a slow in-flight operation must not block submission-queue
 * slot reuse for other operations.
 *
 * This mirrors io_uring: an SQE is consumed at submit time, so the SQ only ever
 * bounds how many entries are staged/in flight - never how long any one
 * operation takes. We keep a single operation in flight indefinitely (a recv on
 * a socket that never receives data), then submit and complete many more fast
 * nops than the SQ depth. get_sqe must keep handing out slots; a backend that
 * frees an SQ slot only when its operation completes would pin the queue behind
 * the blocked recv and start returning NULL well before this many nops.
 */
#include "test_utils.h"

#define SQ_DEPTH 32
#define NOP_COUNT (SQ_DEPTH * 4)

#define TAG_RECV ((void *) 0x1)
#define TAG_NOP ((void *) 0x2)
#define TAG_SEND ((void *) 0x3)

typedef struct sqr_state {
	ior_ctx *ctx;
	ior_fd_t sock[2];
	char rbuf[64];
} sqr_state;

static int setup_sqr(void **state)
{
	sqr_state *s = calloc(1, sizeof(*s));
	assert_non_null(s);

	int ret = ior_queue_init(SQ_DEPTH, &s->ctx);
	assert_return_code(ret, 0);
	assert_non_null(s->ctx);

	ret = test_make_socketpair(s->sock);
	assert_return_code(ret, 0);

	*state = s;
	return 0;
}

static int teardown_sqr(void **state)
{
	sqr_state *s = (sqr_state *) *state;
	if (s) {
		if (test_fd_is_valid(s->sock[0])) {
			test_close_fd(s->sock[0]);
		}
		if (test_fd_is_valid(s->sock[1])) {
			test_close_fd(s->sock[1]);
		}
		if (s->ctx) {
			ior_queue_exit(s->ctx);
		}
		free(s);
	}
	return 0;
}

/*
 * Wait for one completion with a bound, returning its tag and result. Fails the
 * test on timeout so a wedged queue surfaces here rather than hanging until the
 * overall test timeout.
 */
static void wait_one(ior_ctx *ctx, uintptr_t *tag, int32_t *res)
{
	for (;;) {
		ior_cqe *cqe = NULL;
		ior_timespec to = { .tv_sec = 3, .tv_nsec = 0 };
		int ret = ior_wait_cqe_timeout(ctx, &cqe, &to);
		if (ret == -EAGAIN || ret == -EINTR) {
			continue;
		}
		if (ret == -ETIME) {
			fail_msg("no completion within timeout (wedged queue)");
		}
		assert_return_code(ret, 0);
		assert_non_null(cqe);
		*tag = (uintptr_t) ior_cqe_get_data(ctx, cqe);
		*res = ior_cqe_get_res(ctx, cqe);
		ior_cqe_seen(ctx, cqe);
		return;
	}
}

static void test_sq_slot_not_pinned_by_slow_op(void **state)
{
	sqr_state *s = (sqr_state *) *state;

	/*
	 * One operation that stays in flight for the whole test: a recv on a socket
	 * with no data. It occupies a slot/worker but never completes.
	 */
	ior_sqe *r = ior_get_sqe(s->ctx);
	assert_non_null(r);
	ior_prep_recv(s->ctx, r, s->sock[1], s->rbuf, sizeof(s->rbuf), 0);
	ior_sqe_set_data(s->ctx, r, TAG_RECV);
	assert_true(ior_submit(s->ctx) >= 0);

	/*
	 * Far more fast nops than the SQ depth, one at a time, each reaped. With the
	 * slow recv still in flight, a completion-gated backend runs out of slots
	 * here; get_sqe must instead keep succeeding.
	 */
	for (int k = 0; k < NOP_COUNT; k++) {
		ior_sqe *n = ior_get_sqe(s->ctx);
		assert_non_null(n);
		ior_prep_nop(s->ctx, n);
		ior_sqe_set_data(s->ctx, n, TAG_NOP);
		assert_true(ior_submit(s->ctx) >= 0);

		uintptr_t tag = 0;
		int32_t res = 0;
		wait_one(s->ctx, &tag, &res);
		assert_int_equal(tag, (uintptr_t) TAG_NOP); // the recv is still pending
		assert_int_equal(res, 0);
	}

	// Unblock the recv so teardown does not hang on a worker stuck in recv().
	ior_sqe *w = ior_get_sqe(s->ctx);
	assert_non_null(w);
	ior_prep_send(s->ctx, w, s->sock[0], "x", 1, 0);
	ior_sqe_set_data(s->ctx, w, TAG_SEND);
	assert_true(ior_submit(s->ctx) >= 0);

	// Reap the send and the now-satisfied recv, in either order.
	for (int i = 0; i < 2; i++) {
		uintptr_t tag = 0;
		int32_t res = 0;
		wait_one(s->ctx, &tag, &res);
		assert_true(tag == (uintptr_t) TAG_SEND || tag == (uintptr_t) TAG_RECV);
		assert_true(res >= 0);
	}
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_sq_slot_not_pinned_by_slow_op, setup_sqr, teardown_sqr),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
