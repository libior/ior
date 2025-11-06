/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef IOR_THREADS_EVENT_H
#define IOR_THREADS_EVENT_H

#include "config.h"
#include <stdint.h>

// Use eventfd if available and not forced to use pipe
#if defined(IOR_HAVE_EVENTFD) && !defined(IOR_FORCE_PIPE)
#define IOR_THREADS_EVENT_USE_EVENTFD 1
#else
#define IOR_THREADS_EVENT_USE_EVENTFD 0
#endif

// Event handle structure
typedef struct ior_threads_event {
	int read_fd;
	int write_fd;
} ior_threads_event;

// Initialize event
int ior_threads_event_init(ior_threads_event *event);

// Signal the event (from worker thread)
int ior_threads_event_signal(ior_threads_event *event);

// Wait for event (blocking, with optional timeout)
// timeout_ms: -1 for infinite, 0 for non-blocking, >0 for timeout
int ior_threads_event_wait(ior_threads_event *event, int timeout_ms);

// Clear all pending notifications (non-blocking drain)
// Returns number of notifications cleared, or negative error
int ior_threads_event_clear(ior_threads_event *event);

// Get file descriptor for external polling (if needed)
int ior_threads_event_get_fd(ior_threads_event *event);

// Cleanup
void ior_threads_event_destroy(ior_threads_event *event);

// Query which implementation is being used (for testing/debugging)
const char *ior_threads_event_implementation(void);

#endif /* IOR_THREADS_EVENT_H */
