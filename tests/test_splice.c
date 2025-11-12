/* SPDX-License-Identifier: BSD-3-Clause */
#include "test_utils.h"

static void test_splice_basic(void **state)
{
	test_state *ts = (test_state *) *state;

	// Check if backend supports splice
	uint32_t features = ior_get_features(ts->ctx);
	if (!(features & IOR_FEAT_SPLICE)) {
		skip();
		return;
	}

	// Create a pipe
	int pipefd[2];
	int ret = pipe(pipefd);
	assert_return_code(ret, 0);

	const char *data = "Splice test data";
	size_t len = strlen(data);

	// Write data to test file
	ssize_t written = write(ts->test_fd, data, len);
	assert_int_equal(written, len);
	lseek(ts->test_fd, 0, SEEK_SET);

	// Splice from file to pipe
	ior_sqe *sqe = ior_get_sqe(ts->ctx);
	assert_non_null(sqe);

	ior_prep_splice(ts->ctx, sqe, ts->test_fd, 0, pipefd[1], IOR_SPLICE_OFF_NONE, len, 0);
	ior_sqe_set_data(ts->ctx, sqe, NULL);

	ret = ior_submit_and_wait(ts->ctx, 1);
	assert_true(ret >= 0);

	ior_cqe *cqe;
	ret = ior_wait_cqe(ts->ctx, &cqe);
	assert_return_code(ret, 0);

	int32_t res = ior_cqe_get_res(ts->ctx, cqe);
	assert_int_equal(res, len);

	ior_cqe_seen(ts->ctx, cqe);

	// Verify data in pipe
	char read_buffer[1024];
	ssize_t read_bytes = read(pipefd[0], read_buffer, sizeof(read_buffer));
	assert_int_equal(read_bytes, len);
	assert_memory_equal(read_buffer, data, len);

	close(pipefd[0]);
	close(pipefd[1]);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_splice_basic, setup_temp_file, teardown_temp_file),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
