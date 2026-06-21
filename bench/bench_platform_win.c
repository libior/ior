/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * bench_platform_win.c - Windows implementation of the benchmark OS primitives.
 * See bench_platform.h for the contract.
 *
 * winsock2.h MUST be included before windows.h; bench_platform.h pulls in ior.h
 * (which includes windows.h), so Winsock is included here first with
 * WIN32_LEAN_AND_MEAN to keep the legacy winsock.h out.
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "bench_platform.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int bench_platform_init(void)
{
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		return -1;
	}
	return 0;
}

void bench_platform_shutdown(void)
{
	WSACleanup();
}

uint64_t bench_now_ns(void)
{
	LARGE_INTEGER counter, freq;
	QueryPerformanceCounter(&counter);
	QueryPerformanceFrequency(&freq);
	uint64_t c = (uint64_t) counter.QuadPart;
	uint64_t f = (uint64_t) freq.QuadPart;
	return (c / f) * 1000000000ULL + ((c % f) * 1000000000ULL) / f;
}

int bench_fd_is_valid(ior_fd_t fd)
{
	return fd != NULL && fd != INVALID_HANDLE_VALUE;
}

void bench_close_fd(ior_fd_t fd)
{
	if (!bench_fd_is_valid(fd)) {
		return;
	}
	/* Sockets created here are passed around as HANDLEs but must be closed with
	 * closesocket(); files with CloseHandle(). closesocket() on a non-socket
	 * fails harmlessly, so try it first and fall back to CloseHandle(). */
	if (closesocket((SOCKET) fd) != 0) {
		CloseHandle(fd);
	}
}

const char *bench_default_workspace(void)
{
	static char path[MAX_PATH];
	char temp_dir[MAX_PATH];
	DWORD n = GetTempPathA(MAX_PATH, temp_dir);
	if (n == 0 || n > MAX_PATH) {
		return ".\\ior";
	}
	/* GetTempPathA includes a trailing backslash. */
	snprintf(path, sizeof(path), "%sior", temp_dir);
	return path;
}

int bench_ensure_dir(const char *path)
{
	if (CreateDirectoryA(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
		return 0;
	}
	return -1;
}

/*
 * Build a connected loopback TCP pair through the real stack:
 *   listener on 127.0.0.1:0 -> connect a client -> accept -> {accepted, client}.
 * Both data sockets are WSA_FLAG_OVERLAPPED so IOCP can issue overlapped I/O.
 */
int bench_make_tcp_pair(ior_fd_t fds[2])
{
	SOCKET listener = INVALID_SOCKET, client = INVALID_SOCKET, accepted = INVALID_SOCKET;
	struct sockaddr_in addr;
	int addr_len = sizeof(addr);
	BOOL one = TRUE;

	listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listener == INVALID_SOCKET) {
		goto fail;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0; /* ephemeral */

	if (bind(listener, (struct sockaddr *) &addr, sizeof(addr)) == SOCKET_ERROR) {
		goto fail;
	}
	if (listen(listener, 1) == SOCKET_ERROR) {
		goto fail;
	}
	if (getsockname(listener, (struct sockaddr *) &addr, &addr_len) == SOCKET_ERROR) {
		goto fail;
	}

	client = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (client == INVALID_SOCKET) {
		goto fail;
	}
	if (connect(client, (struct sockaddr *) &addr, sizeof(addr)) == SOCKET_ERROR) {
		goto fail;
	}

	accepted = accept(listener, NULL, NULL);
	if (accepted == INVALID_SOCKET) {
		goto fail;
	}

	closesocket(listener);
	listener = INVALID_SOCKET;

	/* Disable Nagle so ping-pong latency reflects the I/O path, not coalescing. */
	setsockopt(accepted, IPPROTO_TCP, TCP_NODELAY, (const char *) &one, sizeof(one));
	setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (const char *) &one, sizeof(one));

	fds[0] = (ior_fd_t) accepted;
	fds[1] = (ior_fd_t) client;
	return 0;

fail:
	if (accepted != INVALID_SOCKET) {
		closesocket(accepted);
	}
	if (client != INVALID_SOCKET) {
		closesocket(client);
	}
	if (listener != INVALID_SOCKET) {
		closesocket(listener);
	}
	return -EIO;
}

ior_fd_t bench_open_tmpfile(const char *dir, uint64_t size)
{
	char path[MAX_PATH];
	/* Unique-ish name; GetTempFileNameA needs an existing dir and a prefix. */
	if (GetTempFileNameA(dir, "iob", 0, path) == 0) {
		return IOR_INVALID_FD;
	}

	/* Reopen overlapped + delete-on-close so IOCP can use it and it cleans up
	 * automatically when the handle is closed. */
	HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | FILE_FLAG_DELETE_ON_CLOSE, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		DeleteFileA(path);
		return IOR_INVALID_FD;
	}

	/* Fill with real data (not a sparse hole) so reads do actual work. The
	 * overlapped handle still supports synchronous WriteFile when lpOverlapped
	 * is NULL for a file opened without an explicit position, so write
	 * sequentially with an OVERLAPPED carrying the running offset. */
	if (size > 0) {
		static char buf[65536];
		memset(buf, 0xab, sizeof(buf));
		uint64_t off = 0;
		uint64_t remaining = size;
		while (remaining > 0) {
			DWORD chunk = remaining < sizeof(buf) ? (DWORD) remaining : (DWORD) sizeof(buf);
			OVERLAPPED ov;
			memset(&ov, 0, sizeof(ov));
			ov.Offset = (DWORD) (off & 0xffffffffULL);
			ov.OffsetHigh = (DWORD) (off >> 32);
			DWORD written = 0;
			if (!WriteFile(h, buf, chunk, &written, &ov) || written != chunk) {
				CloseHandle(h);
				return IOR_INVALID_FD;
			}
			off += written;
			remaining -= written;
		}
	}

	return (ior_fd_t) h;
}
