/* SPDX-License-Identifier: BSD-3-Clause */
#include "ior_threads_event.h"

#if IOR_THREADS_EVENT_USE_EVENTFD

#include <sys/eventfd.h>
#include <errno.h>
#include <poll.h>

int ior_threads_event_init(ior_threads_event *event)
{
	event->read_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (event->read_fd < 0) {
		return -errno;
	}

	event->write_fd = event->read_fd; // Same fd for eventfd
	return 0;
}

int ior_threads_event_signal(ior_threads_event *event)
{
	uint64_t val = 1;
	if (eventfd_write(event->write_fd, val) < 0) {
		// EAGAIN means counter would overflow (very unlikely)
		if (errno == EAGAIN) {
			return 0; // Event already signaled, ok to ignore
		}
		return -errno;
	}
	return 0;
}

int ior_threads_event_wait(ior_threads_event *event, int timeout_ms)
{
	struct pollfd pfd = {
		.fd = event->read_fd,
		.events = POLLIN,
	};

	int ret = poll(&pfd, 1, timeout_ms);
	if (ret < 0) {
		return -errno;
	}
	if (ret == 0) {
		return -ETIMEDOUT;
	}

	return 0;
}

int ior_threads_event_clear(ior_threads_event *event)
{
	uint64_t val;

	// eventfd_read is atomic: reads and resets counter
	if (eventfd_read(event->read_fd, &val) < 0) {
		if (errno == EAGAIN) {
			return 0; // No events pending
		}
		return -errno;
	}

	// Return count (though we treat it as just "signaled" anyway)
	return (int) val;
}

#endif /* IOR_THREADS_EVENT_USE_EVENTFD */
