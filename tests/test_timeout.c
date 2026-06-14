/* SPDX-License-Identifier: BSD-3-Clause */
#include "test_utils.h"

static void test_timeout_basic(void **state)
{
	test_state *ts = (test_state *) *state;

	ior_timespec timeout = {
		.tv_sec = 0,
		.tv_nsec = 100000000 // 100ms
	};

	ior_sqe *sqe = ior_get_sqe(ts->ctx);
	assert_non_null(sqe);

	ior_prep_timeout(ts->ctx, sqe, &timeout, 0, 0);
	ior_sqe_set_data(ts->ctx, sqe, NULL);

	int ret = ior_submit_and_wait(ts->ctx, 1);
	assert_true(ret >= 0);

	ior_cqe *cqe;
	ret = ior_wait_cqe(ts->ctx, &cqe);
	assert_return_code(ret, 0);

	int32_t res = ior_cqe_get_res(ts->ctx, cqe);
	assert_true(res == -ETIME || res == -ETIMEDOUT);

	ior_cqe_seen(ts->ctx, cqe);
}

static void test_wait_cqe_timeout(void **state)
{
	test_state *ts = (test_state *) *state;

	ior_timespec timeout = {
		.tv_sec = 0,
		.tv_nsec = 100000000 // 100ms
	};

	// Submit a timeout operation that will complete after (takes 2s) the wait timeout
	ior_timespec long_timeout = { .tv_sec = 2, .tv_nsec = 0 };

	ior_sqe *sqe = ior_get_sqe(ts->ctx);
	assert_non_null(sqe);

	ior_prep_timeout(ts->ctx, sqe, &long_timeout, 0, 0);
	ior_sqe_set_data(ts->ctx, sqe, NULL);

	int ret = ior_submit(ts->ctx);
	assert_true(ret >= 0);

	// Now wait with short timeout - should timeout before the operation completes
	ior_cqe *cqe;
	ret = ior_wait_cqe_timeout(ts->ctx, &cqe, &timeout);

	// The 2s operation outlasts the 100ms wait, so the wait must time out with
	// the canonical -ETIME (same on every backend).
	assert_int_equal(ret, -ETIME);

	// Clean up - the timeout operation will still complete eventually
	// We can just exit the context to cancel it
}

/*
 * Absolute timeout: an IOR_TIMEOUT_ABS timeout whose deadline is now + 100ms (in
 * the backend's monotonic clock) must fire with -ETIME. This also discriminates
 * abs from relative handling: the absolute deadline is ~uptime seconds, so if it
 * were (mis)treated as a relative duration the wait would far exceed the test
 * timeout instead of completing in ~100ms.
 */
static void test_timeout_abs(void **state)
{
	test_state *ts = (test_state *) *state;

	uint64_t deadline = test_monotonic_now_ns() + 100000000ULL; /* now + 100ms */
	ior_timespec abs = {
		.tv_sec = (int64_t) (deadline / 1000000000ULL),
		.tv_nsec = (long long) (deadline % 1000000000ULL),
	};

	ior_sqe *sqe = ior_get_sqe(ts->ctx);
	assert_non_null(sqe);
	ior_prep_timeout(ts->ctx, sqe, &abs, 0, IOR_TIMEOUT_ABS);
	ior_sqe_set_data(ts->ctx, sqe, NULL);

	int ret = ior_submit_and_wait(ts->ctx, 1);
	assert_true(ret >= 0);

	ior_cqe *cqe;
	ret = ior_wait_cqe(ts->ctx, &cqe);
	assert_return_code(ret, 0);
	int32_t res = ior_cqe_get_res(ts->ctx, cqe);
	assert_true(res == -ETIME || res == -ETIMEDOUT);
	ior_cqe_seen(ts->ctx, cqe);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_timeout_basic, setup_ior_ctx, teardown_ior_ctx),
		cmocka_unit_test_setup_teardown(test_wait_cqe_timeout, setup_ior_ctx, teardown_ior_ctx),
		cmocka_unit_test_setup_teardown(test_timeout_abs, setup_ior_ctx, teardown_ior_ctx),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
