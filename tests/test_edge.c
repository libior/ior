/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * test_edge.c - Cross-platform edge-case coverage for the IOR public API.
 *
 * These tests use ONLY the public API and make no backend-specific
 * assumptions, so they run on every backend (io_uring, threads, IOCP).
 *
 * All tests here are expected to pass on every backend. If a test exercises
 * behaviour that is only conditionally guaranteed on a given platform, the
 * relevant assumption is noted in a comment above that test.
 */
#include "test_utils.h"

/* ===================================================================== */
/* Init / teardown edge cases                                            */
/* ===================================================================== */

/* Zero entries must be rejected: ior_queue_init_params checks entries==0. */
static void test_init_zero_entries(void **state)
{
	(void) state;
	ior_ctx *ctx = NULL;
	int ret = ior_queue_init(0, &ctx);
	assert_int_equal(ret, -EINVAL);
	assert_null(ctx);
}

/* NULL ctx_out must be rejected, not crash. */
static void test_init_null_out(void **state)
{
	(void) state;
	int ret = ior_queue_init(32, NULL);
	assert_int_equal(ret, -EINVAL);
}

/* exit(NULL) must be a safe no-op. */
static void test_exit_null(void **state)
{
	(void) state;
	ior_queue_exit(NULL); /* must not crash */
}

/* Init/exit repeated many times must not leak or corrupt global state
 * (e.g. the one-shot QPC frequency init on IOCP, or thread pools). */
static void test_init_exit_churn(void **state)
{
	(void) state;
	for (int i = 0; i < 64; i++) {
		ior_ctx *ctx = NULL;
		int ret = ior_queue_init(32, &ctx);
		assert_return_code(ret, 0);
		assert_non_null(ctx);
		ior_queue_exit(ctx);
	}
}

/* A non-power-of-2 entry count must still init (backend rounds up). */
static void test_init_odd_entries(void **state)
{
	(void) state;
	ior_ctx *ctx = NULL;
	int ret = ior_queue_init(33, &ctx);
	assert_return_code(ret, 0);
	assert_non_null(ctx);
	ior_queue_exit(ctx);
}

/* ===================================================================== */
/* NULL-argument robustness on the hot path                              */
/* ===================================================================== */

/* All accessor/submit calls with NULL ctx must return sane error codes
 * rather than dereferencing NULL. */
static void test_null_ctx_calls(void **state)
{
	(void) state;

	assert_null(ior_get_sqe(NULL));
	assert_int_equal(ior_submit(NULL), -EINVAL);
	assert_int_equal(ior_submit_and_wait(NULL, 1), -EINVAL);

	ior_cqe *cqe = NULL;
	assert_int_equal(ior_peek_cqe(NULL, &cqe), -EINVAL);
	assert_int_equal(ior_wait_cqe(NULL, &cqe), -EINVAL);

	/* cqe_seen / cq_advance on NULL must be no-ops, not crashes. */
	ior_cqe_seen(NULL, NULL);
	ior_cq_advance(NULL, 1);

	/* Backend info on NULL ctx returns documented defaults. */
	assert_int_equal(ior_get_backend_type(NULL), IOR_BACKEND_AUTO);
	assert_string_equal(ior_get_backend_name(NULL), "unknown");
	assert_int_equal(ior_get_features(NULL), 0);
}

/* peek_cqe with NULL out-pointer must be rejected. */
static void test_peek_null_out(void **state)
{
	test_state *ts = (test_state *) *state;
	assert_int_equal(ior_peek_cqe(ts->ctx, NULL), -EINVAL);
}

/* ===================================================================== */
/* Completion-queue empty / ordering semantics                           */
/* ===================================================================== */

/* peek_cqe on an empty queue (nothing submitted) must report "nothing
 * ready" without blocking. The exact code is backend-dependent but must
 * be negative (e.g. -EAGAIN). */
static void test_peek_empty(void **state)
{
	test_state *ts = (test_state *) *state;
	ior_cqe *cqe = NULL;
	int ret = ior_peek_cqe(ts->ctx, &cqe);
	assert_true(ret < 0);
}

/* A NOP must complete and be reapable, carrying its user_data through. */
static void test_nop_roundtrip(void **state)
{
	test_state *ts = (test_state *) *state;

	ior_sqe *sqe = ior_get_sqe(ts->ctx);
	assert_non_null(sqe);
	ior_prep_nop(ts->ctx, sqe);
	ior_sqe_set_data(ts->ctx, sqe, (void *) (uintptr_t) 0xABCD1234u);

	int ret = ior_submit_and_wait(ts->ctx, 1);
	assert_true(ret >= 0);

	ior_cqe *cqe = NULL;
	ret = ior_wait_cqe(ts->ctx, &cqe);
	assert_return_code(ret, 0);
	assert_non_null(cqe);
	assert_int_equal((uintptr_t) ior_cqe_get_data(ts->ctx, cqe), 0xABCD1234u);

	ior_cqe_seen(ts->ctx, cqe);
}

/* Submit with an empty SQ ring: submit() with nothing queued returns 0
 * (zero submitted), not an error. */
static void test_submit_empty(void **state)
{
	test_state *ts = (test_state *) *state;
	int ret = ior_submit(ts->ctx);
	assert_int_equal(ret, 0);
}

/* submit_and_wait(0) must submit and return without blocking for any
 * completion, even when an op is in flight. */
static void test_submit_and_wait_zero(void **state)
{
	test_state *ts = (test_state *) *state;

	ior_sqe *sqe = ior_get_sqe(ts->ctx);
	assert_non_null(sqe);
	ior_prep_nop(ts->ctx, sqe);
	ior_sqe_set_data(ts->ctx, sqe, NULL);

	int ret = ior_submit_and_wait(ts->ctx, 0);
	assert_true(ret >= 0);

	/* Drain it so teardown is clean. */
	ior_cqe *cqe = NULL;
	if (ior_wait_cqe(ts->ctx, &cqe) == 0) {
		ior_cqe_seen(ts->ctx, cqe);
	}
}

/* ===================================================================== */
/* Batch reaping + cq_advance                                            */
/* ===================================================================== */

/* Submit several NOPs, reap them with peek_batch_cqe + cq_advance.
 * Verifies the batch path and the advance-based consumption path, which
 * are distinct from the wait_cqe/cqe_seen path the other tests cover. */
static void test_batch_reap_and_advance(void **state)
{
	test_state *ts = (test_state *) *state;

	const unsigned N = 4;
	for (unsigned i = 0; i < N; i++) {
		ior_sqe *sqe = ior_get_sqe(ts->ctx);
		assert_non_null(sqe);
		ior_prep_nop(ts->ctx, sqe);
		ior_sqe_set_data(ts->ctx, sqe, (void *) (uintptr_t) (0x100u + i));
	}

	int ret = ior_submit_and_wait(ts->ctx, N);
	assert_true(ret >= 0);

	ior_cqe *cqes[8] = { 0 };
	unsigned got = ior_peek_batch_cqe(ts->ctx, cqes, N);
	assert_true(got >= 1 && got <= N);

	/* Every returned CQE must be non-NULL and carry one of our tags. */
	for (unsigned i = 0; i < got; i++) {
		assert_non_null(cqes[i]);
		uintptr_t d = (uintptr_t) ior_cqe_get_data(ts->ctx, cqes[i]);
		assert_true(d >= 0x100u && d < 0x100u + N);
	}

	ior_cq_advance(ts->ctx, got);

	/* Reap any stragglers the batch didn't cover. */
	unsigned remaining = N - got;
	for (unsigned i = 0; i < remaining; i++) {
		ior_cqe *cqe = NULL;
		ret = ior_wait_cqe(ts->ctx, &cqe);
		assert_return_code(ret, 0);
		ior_cqe_seen(ts->ctx, cqe);
	}
}

/* cq_advance(0) is a documented no-op and must not consume anything. */
static void test_cq_advance_zero(void **state)
{
	test_state *ts = (test_state *) *state;

	ior_sqe *sqe = ior_get_sqe(ts->ctx);
	assert_non_null(sqe);
	ior_prep_nop(ts->ctx, sqe);
	ior_sqe_set_data(ts->ctx, sqe, (void *) 0x7);

	assert_true(ior_submit_and_wait(ts->ctx, 1) >= 0);

	ior_cq_advance(ts->ctx, 0); /* no-op */

	/* The completion must still be there. */
	ior_cqe *cqe = NULL;
	int ret = ior_wait_cqe(ts->ctx, &cqe);
	assert_return_code(ret, 0);
	assert_int_equal((uintptr_t) ior_cqe_get_data(ts->ctx, cqe), 0x7);
	ior_cqe_seen(ts->ctx, cqe);
}

/* ===================================================================== */
/* SQ-ring / pool exhaustion boundary                                    */
/* ===================================================================== */

/*
 * get_sqe must eventually return NULL when the submission ring is full,
 * rather than corrupting state. With 32 requested entries the SQ ring is
 * 32 slots but holds 31 before "full" (one slot kept empty by the
 * head==tail+1 convention). We assert that we get a healthy number of
 * SQEs and then a NULL, and that after submitting + draining we can get
 * SQEs again (pool is recycled).
 */
static void test_sqe_exhaustion_and_recycle(void **state)
{
	test_state *ts = (test_state *) *state;

	unsigned got = 0;
	for (unsigned i = 0; i < 1024; i++) {
		ior_sqe *sqe = ior_get_sqe(ts->ctx);
		if (!sqe) {
			break;
		}
		ior_prep_nop(ts->ctx, sqe);
		ior_sqe_set_data(ts->ctx, sqe, NULL);
		got++;
	}

	/* Must have hit a finite limit, not looped forever or segfaulted. */
	assert_true(got >= 16);
	assert_true(got < 1024);

	int ret = ior_submit_and_wait(ts->ctx, got);
	assert_true(ret >= 0);

	for (unsigned i = 0; i < got; i++) {
		ior_cqe *cqe = NULL;
		ret = ior_wait_cqe(ts->ctx, &cqe);
		assert_return_code(ret, 0);
		ior_cqe_seen(ts->ctx, cqe);
	}

	/* Pool must be recycled: we can get an SQE again. */
	ior_sqe *sqe = ior_get_sqe(ts->ctx);
	assert_non_null(sqe);
	ior_prep_nop(ts->ctx, sqe);
	ior_sqe_set_data(ts->ctx, sqe, NULL);
	assert_true(ior_submit_and_wait(ts->ctx, 1) >= 0);
	ior_cqe *cqe = NULL;
	if (ior_wait_cqe(ts->ctx, &cqe) == 0) {
		ior_cqe_seen(ts->ctx, cqe);
	}
}

/* ===================================================================== */
/* Read/write boundary cases (file-backed)                               */
/* ===================================================================== */

/* A zero-length read must complete with res == 0, not error or hang. */
static void test_zero_length_read(void **state)
{
	test_state *ts = (test_state *) *state;

	char *buf = malloc(16);
	assert_non_null(buf);

	ior_sqe *sqe = ior_get_sqe(ts->ctx);
	assert_non_null(sqe);
	ior_prep_read(ts->ctx, sqe, ts->test_fd, buf, 0, 0);
	ior_sqe_set_data(ts->ctx, sqe, NULL);

	int ret = ior_submit_and_wait(ts->ctx, 1);
	assert_true(ret >= 0);

	ior_cqe *cqe = NULL;
	ret = ior_wait_cqe(ts->ctx, &cqe);
	assert_return_code(ret, 0);
	assert_int_equal(ior_cqe_get_res(ts->ctx, cqe), 0);

	ior_cqe_seen(ts->ctx, cqe);
	free(buf);
}

/*
 * Reading at an offset far past EOF must complete cleanly with res == 0
 * (EOF), not an error and not a hang. This is a normal short-read on every
 * backend (io_uring/threads return 0 bytes; IOCP maps ERROR_HANDLE_EOF to
 * res == 0). Expected to pass everywhere.
 *
 * Note: on IOCP this exercises the path where an overlapped read past EOF
 * still posts a completion packet (the ERROR_HANDLE_EOF case handled in
 * issue_read). That holds for regular overlapped file handles, which is
 * what the temp-file fixture uses.
 */
static void test_read_past_eof(void **state)
{
	test_state *ts = (test_state *) *state;

	char *buf = malloc(64);
	assert_non_null(buf);

	ior_sqe *sqe = ior_get_sqe(ts->ctx);
	assert_non_null(sqe);
	/* The temp file is ~35 bytes; read at offset 1<<20 is well past EOF. */
	ior_prep_read(ts->ctx, sqe, ts->test_fd, buf, 64, (uint64_t) 1 << 20);
	ior_sqe_set_data(ts->ctx, sqe, NULL);

	int ret = ior_submit_and_wait(ts->ctx, 1);
	assert_true(ret >= 0);

	ior_cqe *cqe = NULL;
	ret = ior_wait_cqe(ts->ctx, &cqe);
	assert_return_code(ret, 0);

	int32_t res = ior_cqe_get_res(ts->ctx, cqe);
	assert_int_equal(res, 0); /* EOF -> 0 bytes */

	ior_cqe_seen(ts->ctx, cqe);
	free(buf);
}

/* ===================================================================== */
/* LINK / DRAIN ordering (portable contract)                             */
/* ===================================================================== */

/*
 * A LINK chain where the FIRST op fails must cancel the rest with
 * -ECANCELED. We force failure by reading into a valid buffer from an
 * invalid fd is not portable, so instead we link two NOPs and just assert
 * both complete - the cancellation-on-failure path is covered in the IOCP
 * suite where we can force a deterministic failure. Here we assert the
 * ordering guarantee: a linked op never completes before its predecessor.
 */
static void test_link_two_nops_order(void **state)
{
	test_state *ts = (test_state *) *state;

	ior_sqe *a = ior_get_sqe(ts->ctx);
	assert_non_null(a);
	ior_prep_nop(ts->ctx, a);
	ior_sqe_set_data(ts->ctx, a, (void *) 0x1);
	ior_sqe_set_flags(ts->ctx, a, IOR_SQE_IO_LINK);

	ior_sqe *b = ior_get_sqe(ts->ctx);
	assert_non_null(b);
	ior_prep_nop(ts->ctx, b);
	ior_sqe_set_data(ts->ctx, b, (void *) 0x2);

	int ret = ior_submit_and_wait(ts->ctx, 2);
	assert_true(ret >= 0);

	int a_seen = 0;
	for (int i = 0; i < 2; i++) {
		ior_cqe *cqe = NULL;
		ret = ior_wait_cqe(ts->ctx, &cqe);
		assert_return_code(ret, 0);
		uintptr_t d = (uintptr_t) ior_cqe_get_data(ts->ctx, cqe);
		if (d == 0x1) {
			a_seen = 1;
		} else if (d == 0x2) {
			/* Linked op: predecessor must already have been reaped. */
			assert_true(a_seen);
		}
		ior_cqe_seen(ts->ctx, cqe);
	}
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_init_zero_entries),
		cmocka_unit_test(test_init_null_out),
		cmocka_unit_test(test_exit_null),
		cmocka_unit_test(test_init_exit_churn),
		cmocka_unit_test(test_init_odd_entries),
		cmocka_unit_test_setup_teardown(test_null_ctx_calls, setup_ior_ctx, teardown_ior_ctx),
		cmocka_unit_test_setup_teardown(test_peek_null_out, setup_ior_ctx, teardown_ior_ctx),
		cmocka_unit_test_setup_teardown(test_peek_empty, setup_ior_ctx, teardown_ior_ctx),
		cmocka_unit_test_setup_teardown(test_nop_roundtrip, setup_ior_ctx, teardown_ior_ctx),
		cmocka_unit_test_setup_teardown(test_submit_empty, setup_ior_ctx, teardown_ior_ctx),
		cmocka_unit_test_setup_teardown(test_submit_and_wait_zero, setup_ior_ctx, teardown_ior_ctx),
		cmocka_unit_test_setup_teardown(
				test_batch_reap_and_advance, setup_ior_ctx, teardown_ior_ctx),
		cmocka_unit_test_setup_teardown(test_cq_advance_zero, setup_ior_ctx, teardown_ior_ctx),
		cmocka_unit_test_setup_teardown(
				test_sqe_exhaustion_and_recycle, setup_ior_ctx, teardown_ior_ctx),
		cmocka_unit_test_setup_teardown(test_zero_length_read, setup_temp_file, teardown_temp_file),
		cmocka_unit_test_setup_teardown(test_read_past_eof, setup_temp_file, teardown_temp_file),
		cmocka_unit_test_setup_teardown(
				test_link_two_nops_order, setup_temp_file, teardown_temp_file),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
