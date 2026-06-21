/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * bench_platform.h - OS resource primitives for the ior benchmark.
 *
 * The ior API abstracts the I/O *operations* themselves, so the benchmark
 * driver, scenarios and metrics are fully portable and free of #ifdefs. The
 * only platform-divergent surface is the setup/teardown of the OS resources a
 * scenario runs against: real loopback TCP sockets, temp files, and a
 * high-resolution monotonic clock. That surface lives behind this header and is
 * implemented once per platform (bench_platform_posix.c / bench_platform_win.c);
 * CMake compiles only the matching one.
 */
#ifndef BENCH_PLATFORM_H
#define BENCH_PLATFORM_H

#include <stdint.h>
#include "../src/ior.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Process-wide init/shutdown for the platform layer (e.g. WSAStartup on
 * Windows). Call once at program start / end. Returns 0 on success, negative on
 * failure.
 */
int bench_platform_init(void);
void bench_platform_shutdown(void);

/*
 * Current value of the monotonic clock, in nanoseconds: CLOCK_MONOTONIC on
 * POSIX, QueryPerformanceCounter on Windows. Used for all benchmark timing.
 */
uint64_t bench_now_ns(void);

/*
 * Create a connected pair of real loopback TCP sockets (AF_INET, 127.0.0.1).
 *
 * Unlike a Unix-domain socketpair, this goes through the real kernel TCP/IP
 * stack - which is what the PHP socket-offload workload this benchmark models
 * actually exercises - and it is the only portable option on Windows anyway.
 *
 * fds[0] and fds[1] are the two connected ends; bytes sent on one are received
 * on the other. TCP_NODELAY is set on both ends so request/response latency is
 * not distorted by Nagle. On Windows both ends are created WSA_FLAG_OVERLAPPED
 * so the IOCP backend can issue overlapped I/O on them.
 *
 * Returns 0 on success; on success the caller closes both ends with
 * bench_close_fd(). Returns a negative errno-style code on failure.
 */
int bench_make_tcp_pair(ior_fd_t fds[2]);

/*
 * Default workspace directory for benchmark temp files when the user does not
 * override it on the command line: "/tmp/ior" on POSIX, "%TEMP%\ior" on Windows.
 * Returns a pointer to a static, null-terminated string.
 */
const char *bench_default_workspace(void);

/*
 * Ensure the workspace directory `path` exists (creating it if needed). Only the
 * final component is created, so the parent must already exist (true for the
 * defaults above). Returns 0 on success or if it already exists, negative on
 * failure.
 */
int bench_ensure_dir(const char *path);

/*
 * Create a temp file of exactly `size` bytes inside workspace directory `dir`,
 * filled with data (not sparse), opened for read+write and usable by the active
 * ior backend. On Windows the handle is opened FILE_FLAG_OVERLAPPED (required by
 * IOCP) and FILE_FLAG_DELETE_ON_CLOSE; on POSIX the file is unlinked
 * immediately. In both cases the file lives only while the fd is open and
 * closing it with bench_close_fd() removes it - the workspace dir itself is left
 * in place.
 *
 * Returns IOR_INVALID_FD on failure.
 */
ior_fd_t bench_open_tmpfile(const char *dir, uint64_t size);

/* Close a descriptor returned by bench_make_tcp_pair() or bench_open_tmpfile(). */
void bench_close_fd(ior_fd_t fd);

/* True if fd is a valid descriptor (handles the HANDLE-vs-int difference). */
int bench_fd_is_valid(ior_fd_t fd);

#ifdef __cplusplus
}
#endif

#endif /* BENCH_PLATFORM_H */
