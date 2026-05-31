/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif
#include <cmocka.h>
#include "config.h"
#include "../src/ior.h"

/*
 * Platform file-descriptor abstraction for tests.
 *
 * The IOR public type ior_fd_t is an int on POSIX and a HANDLE on Windows.
 * Tests open real files and pass the descriptor straight to prep_read/write,
 * so the test fixture must store the native descriptor type and compare it
 * against the right "invalid" sentinel (HANDLEs are not comparable with >= 0).
 *
 * On Windows the IOCP backend issues overlapped ReadFile/WriteFile against the
 * handle, so the file MUST be opened with FILE_FLAG_OVERLAPPED. The helper in
 * test_utils.c does that; do not substitute a CRT _open() descriptor here.
 */
#ifdef _WIN32
#define IOR_TEST_INVALID_FD NULL
#else
#define IOR_TEST_INVALID_FD (-1)
#endif

// Test fixture structure
typedef struct test_state {
	ior_ctx *ctx;
	ior_fd_t test_fd;
	char *temp_file;
} test_state;

// Setup/teardown helpers
int setup_ior_ctx(void **state);
int teardown_ior_ctx(void **state);
int setup_temp_file(void **state);
int teardown_temp_file(void **state);

// Utility functions
char *create_temp_file(const char *content, size_t len);
void remove_temp_file(const char *path);

// Open/close a file as a descriptor usable by the active IOR backend.
// On Windows this returns an overlapped HANDLE; on POSIX, an int fd.
ior_fd_t test_open_fd(const char *path);
void test_close_fd(ior_fd_t fd);
int test_fd_is_valid(ior_fd_t fd);

/*
 * Create a connected pair of stream sockets usable by the active backend.
 *
 * fds[0] and fds[1] are two ends of a connected, blocking-by-default stream
 * socket: bytes written to one are readable from the other. On POSIX this is
 * socketpair(AF_UNIX). On Windows there is no socketpair(), so this builds a
 * loopback AF_INET TCP connection; the sockets are created with
 * WSA_FLAG_OVERLAPPED so the IOCP backend can issue overlapped I/O on them.
 *
 * Returns 0 on success, negative errno-style on failure. On success the
 * caller must close both ends with test_close_fd().
 */
int test_make_socketpair(ior_fd_t fds[2]);

#ifdef IOR_HAVE_IOCP
/*
 * IOCP-only helpers (Windows). These open overlapped handles with
 * restricted access so that an issued ReadFile/WriteFile fails immediately
 * with a non-IO_PENDING error, deterministically exercising the synthetic-
 * completion path. No sockets involved.
 */

// Overlapped handle opened GENERIC_READ only -> writing to it fails
// synchronously with ERROR_ACCESS_DENIED.
ior_fd_t test_open_fd_readonly(const char *path);

// Overlapped handle opened GENERIC_WRITE only -> reading from it fails
// synchronously with ERROR_ACCESS_DENIED.
ior_fd_t test_open_fd_writeonly(const char *path);
#endif /* IOR_HAVE_IOCP */

#endif /* TEST_UTILS_H */
