/* SPDX-License-Identifier: BSD-3-Clause */
#include "test_utils.h"

#ifdef IOR_HAVE_URING

// Test forcing io_uring backend
static void test_uring_backend_selection(void **state)
{
	(void) state;

	ior_ctx *ctx;
	ior_params params = {
		.sq_entries = 32,
		.cq_entries = 64,
		.flags = 0,
		.backend = IOR_BACKEND_IOURING, // Force io_uring
	};

	int ret = ior_queue_init_params(32, &ctx, &params);
	assert_return_code(ret, 0);

	// Verify it's using io_uring backend
	assert_int_equal(ior_get_backend_type(ctx), IOR_BACKEND_IOURING);
	assert_string_equal(ior_get_backend_name(ctx), "io_uring");

	// Check features
	uint32_t features = ior_get_features(ctx);
	printf("io_uring features: 0x%x\n", features);
	assert_true(features & IOR_FEAT_NATIVE_ASYNC);

	ior_queue_exit(ctx);
}

// Test io_uring with read operation
static void test_uring_read(void **state)
{
	test_state *ts = (test_state *) *state;

	// Force io_uring backend
	ior_backend_type backend = ior_get_backend_type(ts->ctx);
	if (backend != IOR_BACKEND_IOURING) {
		skip();
		return;
	}

	char buffer[1024] = { 0 };

	// Queue read
	ior_sqe *sqe = ior_get_sqe(ts->ctx);
	assert_non_null(sqe);

	ior_prep_read(ts->ctx, sqe, ts->test_fd, buffer, sizeof(buffer), 0);
	ior_sqe_set_data(ts->ctx, sqe, (void *) 0x1234);

	// Submit and wait
	int ret = ior_submit_and_wait(ts->ctx, 1);
	assert_true(ret >= 0);

	// Get completion
	ior_cqe *cqe;
	ret = ior_wait_cqe(ts->ctx, &cqe);
	assert_return_code(ret, 0);

	// Check result
	int32_t res = ior_cqe_get_res(ts->ctx, cqe);
	assert_true(res > 0);
	assert_ptr_equal(ior_cqe_get_data(ts->ctx, cqe), (void *) 0x1234);

	printf("io_uring read %d bytes: %s\n", res, buffer);

	ior_cqe_seen(ts->ctx, cqe);
}

// Test io_uring with write operation
static void test_uring_write(void **state)
{
	test_state *ts = (test_state *) *state;

	// Force io_uring backend
	ior_backend_type backend = ior_get_backend_type(ts->ctx);
	if (backend != IOR_BACKEND_IOURING) {
		skip();
		return;
	}

	const char *data = "io_uring write test";
	size_t len = strlen(data);

	// Queue write
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

	// Check result
	int32_t res = ior_cqe_get_res(ts->ctx, cqe);
	assert_int_equal(res, (int) len);

	printf("io_uring wrote %d bytes\n", res);

	ior_cqe_seen(ts->ctx, cqe);

	// Verify by reading back
	char buffer[1024] = { 0 };
	lseek(ts->test_fd, 0, SEEK_SET);
	ssize_t nread = read(ts->test_fd, buffer, sizeof(buffer));
	assert_true(nread >= (ssize_t) len);
	assert_memory_equal(buffer, data, len);
}

// Test io_uring batch operations
static void test_uring_batch(void **state)
{
	test_state *ts = (test_state *) *state;

	// Force io_uring backend
	ior_backend_type backend = ior_get_backend_type(ts->ctx);
	if (backend != IOR_BACKEND_IOURING) {
		skip();
		return;
	}

	char buffer1[256] = { 0 };
	char buffer2[256] = { 0 };
	char buffer3[256] = { 0 };

	// Queue multiple reads
	ior_sqe *sqe1 = ior_get_sqe(ts->ctx);
	assert_non_null(sqe1);
	ior_prep_read(ts->ctx, sqe1, ts->test_fd, buffer1, sizeof(buffer1), 0);
	ior_sqe_set_data(ts->ctx, sqe1, (void *) 0x1);

	ior_sqe *sqe2 = ior_get_sqe(ts->ctx);
	assert_non_null(sqe2);
	ior_prep_read(ts->ctx, sqe2, ts->test_fd, buffer2, sizeof(buffer2), 0);
	ior_sqe_set_data(ts->ctx, sqe2, (void *) 0x2);

	ior_sqe *sqe3 = ior_get_sqe(ts->ctx);
	assert_non_null(sqe3);
	ior_prep_read(ts->ctx, sqe3, ts->test_fd, buffer3, sizeof(buffer3), 0);
	ior_sqe_set_data(ts->ctx, sqe3, (void *) 0x3);

	// Submit all
	int ret = ior_submit_and_wait(ts->ctx, 3);
	assert_true(ret >= 0);

	// Get completions in batch
	ior_cqe *cqes[3];
	unsigned count = ior_peek_batch_cqe(ts->ctx, cqes, 3);

	printf("Got %u completions in batch\n", count);
	assert_true(count >= 1); // Should get at least one

	// Verify completions
	for (unsigned i = 0; i < count; i++) {
		assert_non_null(cqes[i]);
		int32_t res = ior_cqe_get_res(ts->ctx, cqes[i]);
		assert_true(res > 0);

		void *data = ior_cqe_get_data(ts->ctx, cqes[i]);
		printf("CQE %u: res=%d, data=%p\n", i, res, data);
	}

	// Advance by batch count
	ior_cq_advance(ts->ctx, count);

	// Get remaining if any
	if (count < 3) {
		for (unsigned i = count; i < 3; i++) {
			ior_cqe *cqe;
			ret = ior_wait_cqe(ts->ctx, &cqe);
			assert_return_code(ret, 0);
			ior_cqe_seen(ts->ctx, cqe);
		}
	}
}

// Test io_uring specific features
static void test_uring_features(void **state)
{
	(void) state;

	ior_ctx *ctx;
	ior_params params = {
		.sq_entries = 32,
		.cq_entries = 64,
		.flags = 0,
		.backend = IOR_BACKEND_IOURING,
	};

	int ret = ior_queue_init_params(32, &ctx, &params);
	assert_return_code(ret, 0);

	// Check that io_uring reports native async feature
	uint32_t features = ior_get_features(ctx);
	assert_true(features & IOR_FEAT_NATIVE_ASYNC);

	printf("io_uring features:\n");
	if (features & IOR_FEAT_NATIVE_ASYNC) {
		printf("  - Native async\n");
	}
	if (features & IOR_FEAT_SPLICE) {
		printf("  - Splice\n");
	}
	if (features & IOR_FEAT_FIXED_FILE) {
		printf("  - Fixed files\n");
	}
	if (features & IOR_FEAT_POLL_ADD) {
		printf("  - Poll add\n");
	}
	if (features & IOR_FEAT_SQPOLL) {
		printf("  - SQPOLL\n");
	}

	ior_queue_exit(ctx);
}

// Setup function that forces io_uring
static int setup_uring_ctx(void **state)
{
	test_state *ts = calloc(1, sizeof(test_state));
	assert_non_null(ts);

	ior_params params = {
		.sq_entries = 32,
		.cq_entries = 64,
		.flags = 0,
		.backend = IOR_BACKEND_IOURING,
	};

	int ret = ior_queue_init_params(32, &ts->ctx, &params);
	assert_return_code(ret, 0);
	assert_non_null(ts->ctx);

	// Verify we got io_uring
	assert_int_equal(ior_get_backend_type(ts->ctx), IOR_BACKEND_IOURING);

	*state = ts;
	return 0;
}

// Setup function for temp file with io_uring
static int setup_uring_temp_file(void **state)
{
	setup_uring_ctx(state);

	test_state *ts = (test_state *) *state;

	const char *content = "Hello from io_uring!\nTesting native backend.\n";
	ts->temp_file = create_temp_file(content, strlen(content));
	assert_non_null(ts->temp_file);

	ts->test_fd = open(ts->temp_file, O_RDWR);
	assert_true(ts->test_fd >= 0);

	return 0;
}

#endif /* IOR_HAVE_URING */

int main(void)
{
#ifdef IOR_HAVE_URING
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_uring_backend_selection),
		cmocka_unit_test_setup_teardown(test_uring_read, setup_uring_temp_file, teardown_temp_file),
		cmocka_unit_test_setup_teardown(
				test_uring_write, setup_uring_temp_file, teardown_temp_file),
		cmocka_unit_test_setup_teardown(
				test_uring_batch, setup_uring_temp_file, teardown_temp_file),
		cmocka_unit_test(test_uring_features),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
#else
	printf("io_uring backend tests require IOR_HAVE_URING\n");
	return 0;
#endif
}
