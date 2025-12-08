/* SPDX-License-Identifier: BSD-3-Clause */
#include "test_utils.h"
#include "../src/ior_threads_event.h"
#include <pthread.h>

static void *signal_thread(void *arg)
{
	ior_threads_event *event = (ior_threads_event *) arg;

	usleep(100000); // 100ms
	ior_threads_event_signal(event);

	return NULL;
}

// Test event initialization
static void test_threads_event_init(void **state)
{
	(void) state;

	ior_threads_event event;
	int ret = ior_threads_event_init(&event);

	assert_return_code(ret, 0);
	assert_true(event.read_fd >= 0);

	printf("Event implementation: %s\n", ior_threads_event_implementation());

	ior_threads_event_destroy(&event);
}

// Test event signaling
static void test_threads_event_signal_wait(void **state)
{
	(void) state;

	ior_threads_event event;
	ior_threads_event_init(&event);

	// Start thread that will signal
	pthread_t thread;
	pthread_create(&thread, NULL, signal_thread, &event);

	// Wait for signal
	int ret = ior_threads_event_wait(&event, 1000); // 1 second timeout
	assert_return_code(ret, 0);

	pthread_join(thread, NULL);

	ior_threads_event_destroy(&event);
}

// Test event timeout
static void test_threads_event_timeout(void **state)
{
	(void) state;

	ior_threads_event event;
	ior_threads_event_init(&event);

	// Wait with short timeout, should timeout
	int ret = ior_threads_event_wait(&event, 100); // 100ms
	assert_int_equal(ret, -ETIMEDOUT);

	ior_threads_event_destroy(&event);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_threads_event_init),
		cmocka_unit_test(test_threads_event_signal_wait),
		cmocka_unit_test(test_threads_event_timeout),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
