/* SPDX-License-Identifier: BSD-3-Clause */
#include "test_utils.h"

static void test_read(void **state) {
	test_state *ts = (test_state *)*state;

	char *buffer = malloc(1024);
	assert_non_null(buffer);

	ior_sqe *sqe = ior_get_sqe(ts->ctx);
	assert_non_null(sqe);

	ior_prep_read(ts->ctx, sqe, ts->test_fd, buffer, 1024, 0);
	ior_sqe_set_data(ts->ctx, sqe, NULL);

	int ret = ior_submit_and_wait(ts->ctx, 1);
	assert_true(ret >= 0);

	ior_cqe *cqe;
	ret = ior_wait_cqe(ts->ctx, &cqe);
	assert_return_code(ret, 0);

	assert_true(ior_cqe_get_res(ts->ctx, cqe) > 0);

	ior_cqe_seen(ts->ctx, cqe);
	free(buffer);
}

static void test_write(void **state) {
	test_state *ts = (test_state *)*state;

	const char *data = "Hello, IOR!";
	size_t len = strlen(data);

	ior_sqe *sqe = ior_get_sqe(ts->ctx);
	assert_non_null(sqe);

	ior_prep_write(ts->ctx, sqe, ts->test_fd, data, len, 0);
	ior_sqe_set_data(ts->ctx, sqe, NULL);

	int ret = ior_submit_and_wait(ts->ctx, 1);
	assert_true(ret >= 0);

	ior_cqe *cqe;
	ret = ior_wait_cqe(ts->ctx, &cqe);
	assert_return_code(ret, 0);

	assert_int_equal(ior_cqe_get_res(ts->ctx, cqe), len);

	ior_cqe_seen(ts->ctx, cqe);
}

static void test_read_write_link(void **state) {
	test_state *ts = (test_state *)*state;

	const char *write_data = "Link test";
	size_t write_len = strlen(write_data);
	char *read_buffer = calloc(1, 1024);
	assert_non_null(read_buffer);

	// Write operation with LINK flag - read must wait for this
	ior_sqe *write_sqe = ior_get_sqe(ts->ctx);
	assert_non_null(write_sqe);

	ior_prep_write(ts->ctx, write_sqe, ts->test_fd, write_data, write_len, 0);
	ior_sqe_set_data(ts->ctx, write_sqe, (void *)0x1);
	ior_sqe_set_flags(ts->ctx, write_sqe, IOR_SQE_IO_LINK);

	// Read operation - linked to write, will execute after write completes
	ior_sqe *read_sqe = ior_get_sqe(ts->ctx);
	assert_non_null(read_sqe);

	ior_prep_read(ts->ctx, read_sqe, ts->test_fd, read_buffer, write_len, 0);
	ior_sqe_set_data(ts->ctx, read_sqe, (void *)0x2);

	// Submit both - read is guaranteed to happen after write due to LINK
	int ret = ior_submit_and_wait(ts->ctx, 2);
	assert_true(ret >= 0);

	// Process completions - should be in order (write, then read)
	int write_seen = 0;
	int read_seen = 0;

	for (int i = 0; i < 2; i++) {
		ior_cqe *cqe;
		ret = ior_wait_cqe(ts->ctx, &cqe);
		assert_return_code(ret, 0);

		void *data = ior_cqe_get_data(ts->ctx, cqe);
		int32_t res = ior_cqe_get_res(ts->ctx, cqe);

		if (data == (void *)0x1) {
			// Write completion
			assert_int_equal(res, write_len);
			write_seen = 1;
		} else if (data == (void *)0x2) {
			// Read completion - write must have completed first due to LINK
			assert_true(write_seen); // Write should complete before read
			assert_int_equal(res, write_len);
			assert_memory_equal(read_buffer, write_data, write_len);
			read_seen = 1;
		}

		ior_cqe_seen(ts->ctx, cqe);
	}

	assert_true(write_seen && read_seen);
	free(read_buffer);
}

static void test_read_write_drain(void **state) {
	test_state *ts = (test_state *)*state;

	const char *write_data1 = "First write";
	const char *write_data2 = "Second write";
	size_t write_len1 = strlen(write_data1);
	size_t write_len2 = strlen(write_data2);
	char *read_buffer = calloc(1, 1024);
	assert_non_null(read_buffer);

	// First write
	ior_sqe *write_sqe1 = ior_get_sqe(ts->ctx);
	assert_non_null(write_sqe1);

	ior_prep_write(ts->ctx, write_sqe1, ts->test_fd, write_data1, write_len1, 0);
	ior_sqe_set_data(ts->ctx, write_sqe1, (void *)0x1);

	// Second write
	ior_sqe *write_sqe2 = ior_get_sqe(ts->ctx);
	assert_non_null(write_sqe2);

	ior_prep_write(ts->ctx, write_sqe2, ts->test_fd, write_data2, write_len2, 100);
	ior_sqe_set_data(ts->ctx, write_sqe2, (void *)0x2);

	// Read with DRAIN - must wait for ALL previous operations to complete
	ior_sqe *read_sqe = ior_get_sqe(ts->ctx);
	assert_non_null(read_sqe);

	ior_prep_read(ts->ctx, read_sqe, ts->test_fd, read_buffer, write_len1, 0);
	ior_sqe_set_data(ts->ctx, read_sqe, (void *)0x3);
	ior_sqe_set_flags(ts->ctx, read_sqe, IOR_SQE_IO_DRAIN);

	// Submit all three
	int ret = ior_submit_and_wait(ts->ctx, 3);
	assert_true(ret >= 0);

	// Process completions
	int write1_seen = 0;
	int write2_seen = 0;
	int read_seen = 0;

	for (int i = 0; i < 3; i++) {
		ior_cqe *cqe;
		ret = ior_wait_cqe(ts->ctx, &cqe);
		assert_return_code(ret, 0);

		void *data = ior_cqe_get_data(ts->ctx, cqe);
		int32_t res = ior_cqe_get_res(ts->ctx, cqe);

		if (data == (void *)0x1) {
			// First write
			assert_int_equal(res, write_len1);
			write1_seen = 1;
		} else if (data == (void *)0x2) {
			// Second write
			assert_int_equal(res, write_len2);
			write2_seen = 1;
		} else if (data == (void *)0x3) {
			// Read with DRAIN - both writes must be complete
			assert_true(write1_seen && write2_seen);
			assert_int_equal(res, write_len1);
			assert_memory_equal(read_buffer, write_data1, write_len1);
			read_seen = 1;
		}

		ior_cqe_seen(ts->ctx, cqe);
	}

	assert_true(write1_seen && write2_seen && read_seen);
	free(read_buffer);
}

static void test_multiple_operations(void **state) {
	test_state *ts = (test_state *)*state;

	const char *data1 = "First";
	const char *data2 = "Second";
	const char *data3 = "Third";

	// Submit multiple writes to different offsets
	ior_sqe *sqe1 = ior_get_sqe(ts->ctx);
	assert_non_null(sqe1);
	ior_prep_write(ts->ctx, sqe1, ts->test_fd, data1, strlen(data1), 0);
	ior_sqe_set_data(ts->ctx, sqe1, (void *)0x1);

	ior_sqe *sqe2 = ior_get_sqe(ts->ctx);
	assert_non_null(sqe2);
	ior_prep_write(ts->ctx, sqe2, ts->test_fd, data2, strlen(data2), 100);
	ior_sqe_set_data(ts->ctx, sqe2, (void *)0x2);

	ior_sqe *sqe3 = ior_get_sqe(ts->ctx);
	assert_non_null(sqe3);
	ior_prep_write(ts->ctx, sqe3, ts->test_fd, data3, strlen(data3), 200);
	ior_sqe_set_data(ts->ctx, sqe3, (void *)0x3);

	int ret = ior_submit_and_wait(ts->ctx, 3);
	assert_true(ret >= 0);

	// Collect all completions
	int seen[3] = {0, 0, 0};

	for (int i = 0; i < 3; i++) {
		ior_cqe *cqe;
		ret = ior_wait_cqe(ts->ctx, &cqe);
		assert_return_code(ret, 0);

		void *data = ior_cqe_get_data(ts->ctx, cqe);
		int32_t res = ior_cqe_get_res(ts->ctx, cqe);
		assert_true(res > 0);

		if (data == (void *)0x1) seen[0] = 1;
		else if (data == (void *)0x2) seen[1] = 1;
		else if (data == (void *)0x3) seen[2] = 1;

		ior_cqe_seen(ts->ctx, cqe);
	}

	assert_true(seen[0] && seen[1] && seen[2]);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_read, setup_temp_file, teardown_temp_file),
		cmocka_unit_test_setup_teardown(test_write, setup_temp_file, teardown_temp_file),
		cmocka_unit_test_setup_teardown(test_read_write_link, setup_temp_file, teardown_temp_file),
		cmocka_unit_test_setup_teardown(test_read_write_drain, setup_temp_file, teardown_temp_file),
		cmocka_unit_test_setup_teardown(test_multiple_operations, setup_temp_file, teardown_temp_file),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
