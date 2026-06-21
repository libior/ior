/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * bench_platform_posix.c - POSIX implementation of the benchmark OS primitives.
 * See bench_platform.h for the contract.
 */
#include "bench_platform.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

int bench_platform_init(void)
{
	return 0;
}

void bench_platform_shutdown(void)
{
}

uint64_t bench_now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

int bench_fd_is_valid(ior_fd_t fd)
{
	return fd >= 0;
}

void bench_close_fd(ior_fd_t fd)
{
	if (bench_fd_is_valid(fd)) {
		close(fd);
	}
}

const char *bench_default_workspace(void)
{
	return "/tmp/ior";
}

int bench_ensure_dir(const char *path)
{
	if (mkdir(path, 0700) == 0 || errno == EEXIST) {
		return 0;
	}
	return -errno;
}

int bench_make_tcp_pair(ior_fd_t fds[2])
{
	int listener = -1, client = -1, accepted = -1;
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);
	int one = 1;

	listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listener < 0) {
		goto fail;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0; /* ephemeral */

	if (bind(listener, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		goto fail;
	}
	if (listen(listener, 1) < 0) {
		goto fail;
	}
	if (getsockname(listener, (struct sockaddr *) &addr, &addr_len) < 0) {
		goto fail;
	}

	client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (client < 0) {
		goto fail;
	}
	if (connect(client, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		goto fail;
	}

	accepted = accept(listener, NULL, NULL);
	if (accepted < 0) {
		goto fail;
	}

	close(listener);
	listener = -1;

	/* Disable Nagle so ping-pong latency reflects the I/O path, not coalescing. */
	setsockopt(accepted, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

	fds[0] = accepted;
	fds[1] = client;
	return 0;

fail:
	if (accepted >= 0) {
		close(accepted);
	}
	if (client >= 0) {
		close(client);
	}
	if (listener >= 0) {
		close(listener);
	}
	return -EIO;
}

ior_fd_t bench_open_tmpfile(const char *dir, uint64_t size)
{
	char template[4096];
	int n = snprintf(template, sizeof(template), "%s/ior_bench_XXXXXX", dir);
	if (n < 0 || (size_t) n >= sizeof(template)) {
		return IOR_INVALID_FD;
	}

	int fd = mkstemp(template);
	if (fd < 0) {
		return IOR_INVALID_FD;
	}
	/* Unlink now: the file stays alive while the fd is open and disappears on
	 * close, so callers never need to track a path and the workspace dir stays
	 * clean. */
	unlink(template);

	/* Fill with real data (not a sparse hole) so reads do actual work. */
	if (size > 0) {
		static char buf[65536];
		memset(buf, 0xab, sizeof(buf));
		uint64_t remaining = size;
		while (remaining > 0) {
			size_t chunk = remaining < sizeof(buf) ? (size_t) remaining : sizeof(buf);
			ssize_t w = write(fd, buf, chunk);
			if (w <= 0) {
				close(fd);
				return IOR_INVALID_FD;
			}
			remaining -= (uint64_t) w;
		}
	}

	return fd;
}
