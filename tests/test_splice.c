/* SPDX-License-Identifier: BSD-3-Clause */
#include "test_utils.h"

#ifdef __linux__

// Test splice operation
static void test_splice_basic(void **state)
{
	test_state *ts = (test_state *) *state;

	// Create a pipe
	int pipe_fds[2];
	int ret = pipe(pipe_fds);
	assert_return_code(ret, 0);

	// Splice from file to pipe
	ior_sqe *sqe = ior_get_sqe(ts->ctx);
	assert_non_null(sqe);

	size_t bytes_to_splice = 20;
	ior_prep_splice(sqe, ts->test_fd, 0, pipe_fds[1], 0, bytes_to_splice, 0);
	ior_sqe_set_data(sqe, NULL);

	// Submit and wait
	ret = ior_submit_and_wait(ts->ctx, 1);
	assert_true(ret >= 0);

	// Get completion
	ior_cqe *cqe;
	ret = ior_wait_cqe(ts->ctx, &cqe);
	assert_return_code(ret, 0);

	printf("Spliced %d bytes\n", cqe->res);

	// Check result - should have spliced some bytes
	// Note: might be less than requested if file is smaller
	assert_true(cqe->res >= 0);

	if (cqe->res > 0) {
		// Read from pipe to verify
		char buffer[256] = { 0 };
		ssize_t nread = read(pipe_fds[0], buffer, sizeof(buffer));
		assert_int_equal(nread, cqe->res);

		printf("Read from pipe: %.*s\n", (int) nread, buffer);
	}

	ior_cqe_seen(ts->ctx, cqe);

	close(pipe_fds[0]);
	close(pipe_fds[1]);
}

// Test splice between two pipes
static void test_splice_pipe_to_pipe(void **state)
{
	test_state *ts = (test_state *) *state;

	int pipe_in[2], pipe_out[2];
	assert_return_code(pipe(pipe_in), 0);
	assert_return_code(pipe(pipe_out), 0);

	// Write some data to input pipe
	const char *data = "Hello from pipe!";
	size_t len = strlen(data);
	ssize_t written = write(pipe_in[1], data, len);
	assert_int_equal(written, (ssize_t) len);

	// Splice from input pipe to output pipe
	ior_sqe *sqe = ior_get_sqe(ts->ctx);
	assert_non_null(sqe);

	ior_prep_splice(sqe, pipe_in[0], 0, pipe_out[1], 0, len, 0);
	ior_sqe_set_data(sqe, NULL);

	// Submit and wait
	int ret = ior_submit_and_wait(ts->ctx, 1);
	assert_true(ret >= 0);

	// Get completion
	ior_cqe *cqe;
	ret = ior_wait_cqe(ts->ctx, &cqe);
	assert_return_code(ret, 0);

	printf("Spliced %d bytes between pipes\n", cqe->res);
	assert_int_equal(cqe->res, (int) len);

	// Verify data
	char buffer[256] = { 0 };
	ssize_t nread = read(pipe_out[0], buffer, sizeof(buffer));
	assert_int_equal(nread, (ssize_t) len);
	assert_memory_equal(buffer, data, len);

	ior_cqe_seen(ts->ctx, cqe);

	close(pipe_in[0]);
	close(pipe_in[1]);
	close(pipe_out[0]);
	close(pipe_out[1]);
}

// Test splice with large data
static void test_splice_large(void **state)
{
	test_state *ts = (test_state *) *state;

	// Create a larger temp file
	char large_data[8192];
	memset(large_data, 'A', sizeof(large_data));

	char *large_file = create_temp_file(large_data, sizeof(large_data));
	assert_non_null(large_file);

	int fd = open(large_file, O_RDONLY);
	assert_true(fd >= 0);

	// Create pipe
	int pipe_fds[2];
	assert_return_code(pipe(pipe_fds), 0);

	// Splice large amount
	ior_sqe *sqe = ior_get_sqe(ts->ctx);
	assert_non_null(sqe);

	ior_prep_splice(sqe, fd, 0, pipe_fds[1], 0, sizeof(large_data), 0);
	ior_sqe_set_data(sqe, NULL);

	// Submit and wait
	int ret = ior_submit_and_wait(ts->ctx, 1);
	assert_true(ret >= 0);

	// Get completion
	ior_cqe *cqe;
	ret = ior_wait_cqe(ts->ctx, &cqe);
	assert_return_code(ret, 0);

	printf("Spliced %d bytes (large)\n", cqe->res);
	assert_int_equal(cqe->res, (int) sizeof(large_data));

	ior_cqe_seen(ts->ctx, cqe);

	close(fd);
	close(pipe_fds[0]);
	close(pipe_fds[1]);
	remove_temp_file(large_file);
	free(large_file);
}

#endif /* __linux__ */

int main(void)
{
#ifdef __linux__
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_splice_basic, setup_temp_file, teardown_temp_file),
		cmocka_unit_test_setup_teardown(test_splice_pipe_to_pipe, setup_ior_ctx, teardown_ior_ctx),
		cmocka_unit_test_setup_teardown(test_splice_large, setup_ior_ctx, teardown_ior_ctx),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
#else
	printf("Splice tests only available on Linux\n");
	return 0;
#endif
}
