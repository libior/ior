/* SPDX-License-Identifier: BSD-3-Clause */
#include "test_utils.h"

// Test read operation
static void test_read(void **state)
{
	test_state *ts = (test_state *) *state;

	char *buffer = malloc(1024);

	// Queue read
	ior_sqe *sqe = ior_get_sqe(ts->ctx);
	assert_non_null(sqe);

	ior_prep_read(sqe, ts->test_fd, buffer, 1024, 0);
	ior_sqe_set_data(sqe, NULL);

	// Submit and wait
	int ret = ior_submit_and_wait(ts->ctx, 1);
	assert_true(ret >= 0);

	// Get completion
	ior_cqe *cqe;
	ret = ior_wait_cqe(ts->ctx, &cqe);
	assert_return_code(ret, 0);

	// Check result
	assert_true(cqe->res > 0);
	printf("Read %d bytes: %s\n", cqe->res, buffer);

	// Verify content
	assert_true(strstr(buffer, "Hello, World!") != NULL);

	ior_cqe_seen(ts->ctx, cqe);
	free(buffer);
}

// Test write operation
static void test_write(void **state)
{
	test_state *ts = (test_state *) *state;

	const char *data = "Test write data";
	size_t len = strlen(data);

	// Queue write
	ior_sqe *sqe = ior_get_sqe(ts->ctx);
	assert_non_null(sqe);

	ior_prep_write(sqe, ts->test_fd, data, len, 0);
	ior_sqe_set_data(sqe, NULL);

	// Submit and wait
	int ret = ior_submit_and_wait(ts->ctx, 1);
	assert_true(ret >= 0);

	// Get completion
	ior_cqe *cqe;
	ret = ior_wait_cqe(ts->ctx, &cqe);
	assert_return_code(ret, 0);

	// Check result
	assert_int_equal(cqe->res, (int) len);

	ior_cqe_seen(ts->ctx, cqe);

	// Verify by reading back
	char buffer[1024] = { 0 };
	lseek(ts->test_fd, 0, SEEK_SET);
	ssize_t nread = read(ts->test_fd, buffer, sizeof(buffer));
	assert_true(nread >= (ssize_t) len);
	assert_memory_equal(buffer, data, len);
}

// Test multiple operations
static void test_multiple_operations(void **state)
{
	test_state *ts = (test_state *) *state;

	char buffer1[256] = { 0 };
	char buffer2[256] = { 0 };

	// Queue two reads
	ior_sqe *sqe1 = ior_get_sqe(ts->ctx);
	assert_non_null(sqe1);
	ior_prep_read(sqe1, ts->test_fd, buffer1, sizeof(buffer1), 0);
	ior_sqe_set_data(sqe1, (void *) 0x1);

	ior_sqe *sqe2 = ior_get_sqe(ts->ctx);
	assert_non_null(sqe2);
	ior_prep_read(sqe2, ts->test_fd, buffer2, sizeof(buffer2), 0);
	ior_sqe_set_data(sqe2, (void *) 0x2);

	// Submit both
	int ret = ior_submit_and_wait(ts->ctx, 2);
	assert_true(ret >= 0);

	// Get both completions
	int count = 0;
	while (count < 2) {
		ior_cqe *cqe;
		ret = ior_wait_cqe(ts->ctx, &cqe);
		assert_return_code(ret, 0);

		assert_true(cqe->res > 0);
		void *data = ior_cqe_get_data(cqe);
		assert_true(data == (void *) 0x1 || data == (void *) 0x2);

		ior_cqe_seen(ts->ctx, cqe);
		count++;
	}
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_read, setup_temp_file, teardown_temp_file),
		cmocka_unit_test_setup_teardown(test_write, setup_temp_file, teardown_temp_file),
		cmocka_unit_test_setup_teardown(
				test_multiple_operations, setup_temp_file, teardown_temp_file),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
