/* SPDX-License-Identifier: BSD-3-Clause */
#include "ior_threads_event.h"
#include <unistd.h>

// Common implementations that don't depend on backend

int ior_threads_event_get_fd(ior_threads_event *event)
{
	return event->read_fd;
}

void ior_threads_event_destroy(ior_threads_event *event)
{
	if (event->read_fd >= 0) {
		close(event->read_fd);
		event->read_fd = -1;
	}

#if !IOR_THREADS_EVENT_USE_EVENTFD
	// Only close write_fd separately for pipe
	if (event->write_fd >= 0 && event->write_fd != event->read_fd) {
		close(event->write_fd);
		event->write_fd = -1;
	}
#endif
}

const char *ior_threads_event_implementation(void)
{
#if IOR_THREADS_EVENT_USE_EVENTFD
	return "eventfd";
#else
	return "pipe";
#endif
}
