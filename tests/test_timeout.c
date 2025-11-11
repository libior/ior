/* SPDX-License-Identifier: BSD-3-Clause */
#include "test_utils.h"
#include <time.h>

// Test timeout operation
static void test_timeout(void **state)
{
	test_state *ts = (test_state *) *state;

	struct timespec ts_timeout = {
		.tv_sec = 0,
		.tv_nsec = 100000000, // 100ms
	};

	// Queue timeout
	ior_sqe *sqe = ior_get_sqe(ts->ctx);
	assert_non_null(sqe);

	ior_prep_timeout(sqe, &ts_timeout, 0, 0);
	ior_sqe_set_data(sqe, NULL);

	// Submit and wait
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);

	int ret = ior_submit_and_wait(ts->ctx, 1);
	assert_true(ret >= 0);

	// Get completion
	ior_cqe *cqe;
	ret = ior_wait_cqe(ts->ctx, &cqe);
	assert_return_code(ret, 0);

	clock_gettime(CLOCK_MONOTONIC, &end);

	// Check it completed
	assert_int_equal(cqe->res, 0);

	// Check elapsed time (should be at least 100ms)
	long elapsed_ms = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;
	printf("Elapsed: %ld ms\n", elapsed_ms);
	assert_true(elapsed_ms >= 90); // Allow some slack

	ior_cqe_seen(ts->ctx, cqe);
}

// Test wait with timeout
static void test_wait_cqe_timeout(void **state)
{
	test_state *ts = (test_state *) *state;

	struct timespec timeout = {
		.tv_sec = 0,
		.tv_nsec = 100000000, // 100ms
	};

	// Don't submit anything, just wait with timeout
	ior_cqe *cqe;
	struct timespec start, end;

	clock_gettime(CLOCK_MONOTONIC, &start);
	int ret = ior_wait_cqe_timeout(ts->ctx, &cqe, &timeout);
	clock_gettime(CLOCK_MONOTONIC, &end);

	// Should timeout
	assert_int_equal(ret, -ETIMEDOUT);

	// Check elapsed time
	long elapsed_ms = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;
	printf("Elapsed: %ld ms\n", elapsed_ms);
	assert_true(elapsed_ms >= 90 && elapsed_ms < 200);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_timeout, setup_ior_ctx, teardown_ior_ctx),
		cmocka_unit_test_setup_teardown(test_wait_cqe_timeout, setup_ior_ctx, teardown_ior_ctx),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
