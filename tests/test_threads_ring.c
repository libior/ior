/* SPDX-License-Identifier: BSD-3-Clause */
#include "test_utils.h"
#include "../src/ior_backend.h"
#include "../src/ior_threads_ring.h"

// Test ring initialization
static void test_threads_ring_init(void **state)
{
	(void) state;

	ior_threads_ring ring;
	int ret = ior_threads_ring_init(&ring, 32, 0); // CQ ring

	assert_return_code(ret, 0);
	assert_int_equal(ring.size, 32);
	assert_true(ior_threads_ring_empty(&ring));
	assert_false(ior_threads_ring_full(&ring));

	ior_threads_ring_destroy(&ring);
}

// Test ring operations
static void test_threads_ring_operations(void **state)
{
	(void) state;

	ior_threads_ring ring;
	ior_threads_ring_init(&ring, 16, 0); // CQ ring

	// Post some CQEs
	for (int i = 0; i < 5; i++) {
		ior_cqe cqe = { .threads = {
								.user_data = i,
								.res = i * 10,
								.flags = 0,
						} };

		int ret = ior_threads_ring_post_cqe(&ring, &cqe);
		assert_return_code(ret, 0);
	}

	assert_int_equal(ior_threads_ring_count(&ring), 5);

	// Consume them
	for (int i = 0; i < 5; i++) {
		ior_cqe *cqe = ior_threads_ring_peek_cqe(&ring);
		assert_non_null(cqe);
		assert_int_equal(cqe->threads.user_data, i);
		assert_int_equal(cqe->threads.res, i * 10);

		ior_threads_ring_cqe_seen(&ring);
	}

	assert_true(ior_threads_ring_empty(&ring));

	ior_threads_ring_destroy(&ring);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_threads_ring_init),
		cmocka_unit_test(test_threads_ring_operations),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
