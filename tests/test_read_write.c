/* SPDX-License-Identifier: BSD-3-Clause */
#include "test_utils.h"

static void test_read(void **state)
{
	test_state *ts = (test_state *) *state;

	char *buffer = malloc(1024);
	assert_non_null(buffer);

	ior_sqe *sqe = ior_get_sqe(ts->ctx);
	assert_non_null(sqe);

	ior_prep_read(ts->ctx, sqe, ts->test_fd, buffer, 1024, 0);
	ior_sqe_set_data(ts->ctx, sqe, NULL);

	// Submit and wait for completion
	int ret = ior_submit_and_wait(ts->ctx, 1);
	assert_true(ret >= 0);

	// Get completion
	ior_cqe *cqe;
	ret = ior_wait_cqe(ts->ctx, &cqe);
	assert_return_code(ret, 0);

	assert_true(ior_cqe_get_res(ts->ctx, cqe) > 0);

	ior_cqe_seen(ts->ctx, cqe);
	free(buffer);
}

static void test_write(void **state)
{
	test_state *ts = (test_state *) *state;

	const char *data = "Hello, IOR!";
	size_t len = strlen(data);

	ior_sqe *sqe = ior_get_sqe(ts->ctx);
	assert_non_null(sqe);

	ior_prep_write(ts->ctx, sqe, ts->test_fd, data, len, 0);
	ior_sqe_set_data(ts->ctx, sqe, NULL);

	// Submit and wait
	int ret = ior_submit_and_wait(ts->ctx, 1);
	assert_true(ret >= 0);

	// Get completion
	ior_cqe *cqe;
	ret = ior_wait_cqe(ts->ctx, &cqe);
	assert_return_code(ret, 0);

	assert_int_equal(ior_cqe_get_res(ts->ctx, cqe), len);

	ior_cqe_seen(ts->ctx, cqe);
}

static void test_read_write_chain(void **state)
{
	test_state *ts = (test_state *) *state;

	const char *write_data = "Chain test";
	size_t write_len = strlen(write_data);
	char *read_buffer = malloc(1024);
	assert_non_null(read_buffer);

	// Write operation
	ior_sqe *write_sqe = ior_get_sqe(ts->ctx);
	assert_non_null(write_sqe);

	ior_prep_write(ts->ctx, write_sqe, ts->test_fd, write_data, write_len, 0);
	ior_sqe_set_data(ts->ctx, write_sqe, (void *) 0x1);

	// Read operation
	ior_sqe *read_sqe = ior_get_sqe(ts->ctx);
	assert_non_null(read_sqe);

	ior_prep_read(ts->ctx, read_sqe, ts->test_fd, read_buffer, write_len, 0);
	ior_sqe_set_data(ts->ctx, read_sqe, (void *) 0x2);

	// Submit both
	int ret = ior_submit_and_wait(ts->ctx, 2);
	assert_true(ret >= 0);

	// Process completions
	for (int i = 0; i < 2; i++) {
		ior_cqe *cqe;
		ret = ior_wait_cqe(ts->ctx, &cqe);
		assert_return_code(ret, 0);

		void *data = ior_cqe_get_data(ts->ctx, cqe);
		int32_t res = ior_cqe_get_res(ts->ctx, cqe);

		if (data == (void *) 0x1) {
			// Write completion
			assert_int_equal(res, write_len);
		} else if (data == (void *) 0x2) {
			// Read completion
			assert_int_equal(res, write_len);
			assert_memory_equal(read_buffer, write_data, write_len);
		}

		ior_cqe_seen(ts->ctx, cqe);
	}

	free(read_buffer);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_read, setup_temp_file, teardown_temp_file),
		cmocka_unit_test_setup_teardown(test_write, setup_temp_file, teardown_temp_file),
		cmocka_unit_test_setup_teardown(test_read_write_chain, setup_temp_file, teardown_temp_file),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
