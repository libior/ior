/* SPDX-License-Identifier: BSD-3-Clause */
#include "test_utils.h"

static void test_timeout_basic(void **state)
{
	test_state *ts = (test_state *) *state;

	struct timespec timeout = {
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

	struct timespec timeout = {
		.tv_sec = 0,
		.tv_nsec = 100000000 // 100ms
	};

	ior_cqe *cqe;
	int ret = ior_wait_cqe_timeout(ts->ctx, &cqe, &timeout);

	// Should timeout since no operations submitted
	assert_true(ret == -EAGAIN || ret == -ETIMEDOUT);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_timeout_basic, setup_ior_ctx, teardown_ior_ctx),
		cmocka_unit_test_setup_teardown(test_wait_cqe_timeout, setup_ior_ctx, teardown_ior_ctx),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
