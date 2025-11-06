/* SPDX-License-Identifier: BSD-3-Clause */
#include "ior_threads_event.h"

#if !IOR_THREADS_EVENT_USE_EVENTFD

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>

int ior_threads_event_init(ior_threads_event *event)
{
	int fds[2];

#ifdef __linux__
	// Linux has pipe2 with flags
	if (pipe2(fds, O_CLOEXEC | O_NONBLOCK) < 0) {
		return -errno;
	}
#else
	// Other systems need manual flag setting
	if (pipe(fds) < 0) {
		return -errno;
	}

	// Set non-blocking on both ends
	int flags;
	flags = fcntl(fds[0], F_GETFL);
	if (flags >= 0) {
		fcntl(fds[0], F_SETFL, flags | O_NONBLOCK);
	}

	flags = fcntl(fds[1], F_GETFL);
	if (flags >= 0) {
		fcntl(fds[1], F_SETFL, flags | O_NONBLOCK);
	}

	// Set close-on-exec
	fcntl(fds[0], F_SETFD, FD_CLOEXEC);
	fcntl(fds[1], F_SETFD, FD_CLOEXEC);
#endif

	event->read_fd = fds[0];
	event->write_fd = fds[1];
	return 0;
}

int ior_threads_event_signal(ior_threads_event *event)
{
	// Write single byte as notification
	char dummy = 1;
	ssize_t ret = write(event->write_fd, &dummy, 1);

	if (ret < 0) {
		// Pipe full is ok - event is already signaled
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
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
	char buf[256];
	int total = 0;
	ssize_t ret;

	// Drain all bytes from pipe
	while ((ret = read(event->read_fd, buf, sizeof(buf))) > 0) {
		total += ret;
	}

	if (ret < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
		return -errno;
	}

	return total;
}

#endif /* !IOR_THREADS_EVENT_USE_EVENTFD */
