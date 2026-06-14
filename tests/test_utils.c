/* SPDX-License-Identifier: BSD-3-Clause */

/*
 * On Windows, winsock2.h MUST be included before windows.h. test_utils.h
 * transitively includes windows.h (via ior.h), so we pull in Winsock here,
 * first, and define WIN32_LEAN_AND_MEAN so the later windows.h does not drag
 * in the legacy winsock.h (1.1) that conflicts with winsock2.h.
 */
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif

#include "test_utils.h"

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#endif

uint64_t test_monotonic_now_ns(void)
{
#ifdef _WIN32
	LARGE_INTEGER counter, freq;
	QueryPerformanceCounter(&counter);
	QueryPerformanceFrequency(&freq);
	uint64_t c = (uint64_t) counter.QuadPart;
	uint64_t f = (uint64_t) freq.QuadPart;
	return (c / f) * 1000000000ULL + ((c % f) * 1000000000ULL) / f;
#else
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
#endif
}

int setup_ior_ctx(void **state)
{
	test_state *ts = calloc(1, sizeof(test_state));
	assert_non_null(ts);

	ts->test_fd = IOR_TEST_INVALID_FD;

	int ret = ior_queue_init(32, &ts->ctx);
	assert_return_code(ret, 0);
	assert_non_null(ts->ctx);

	*state = ts;
	return 0;
}

int teardown_ior_ctx(void **state)
{
	test_state *ts = (test_state *) *state;

	if (ts) {
		if (ts->ctx) {
			ior_queue_exit(ts->ctx);
		}
		free(ts);
	}

	return 0;
}

int setup_temp_file(void **state)
{
	setup_ior_ctx(state);

	test_state *ts = (test_state *) *state;

	const char *content = "Hello, World!\nThis is a test file.\n";
	ts->temp_file = create_temp_file(content, strlen(content));
	assert_non_null(ts->temp_file);

	ts->test_fd = test_open_fd(ts->temp_file);
	assert_true(test_fd_is_valid(ts->test_fd));

	return 0;
}

int teardown_temp_file(void **state)
{
	test_state *ts = (test_state *) *state;

	if (ts) {
		if (test_fd_is_valid(ts->test_fd)) {
			test_close_fd(ts->test_fd);
		}
		if (ts->temp_file) {
			remove_temp_file(ts->temp_file);
			free(ts->temp_file);
		}
	}

	return teardown_ior_ctx(state);
}

/* ================= Platform-specific helpers ================= */

#ifdef _WIN32

char *create_temp_file(const char *content, size_t len)
{
	char temp_dir[MAX_PATH];
	DWORD n = GetTempPathA(MAX_PATH, temp_dir);
	if (n == 0 || n > MAX_PATH) {
		return NULL;
	}

	char path[MAX_PATH];
	// "ior" prefix, 0 => system picks a unique number and creates the file.
	if (GetTempFileNameA(temp_dir, "ior", 0, path) == 0) {
		return NULL;
	}

	// GetTempFileNameA created an empty file. Write the content if any.
	if (content && len > 0) {
		HANDLE h = CreateFileA(
				path, GENERIC_WRITE, 0, NULL, TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (h == INVALID_HANDLE_VALUE) {
			DeleteFileA(path);
			return NULL;
		}

		DWORD written = 0;
		BOOL ok = WriteFile(h, content, (DWORD) len, &written, NULL);
		CloseHandle(h);

		if (!ok || written != (DWORD) len) {
			DeleteFileA(path);
			return NULL;
		}
	}

	return _strdup(path);
}

void remove_temp_file(const char *path)
{
	if (path) {
		DeleteFileA(path);
	}
}

ior_fd_t test_open_fd(const char *path)
{
	// The IOCP backend issues overlapped ReadFile/WriteFile, so the handle
	// must be opened with FILE_FLAG_OVERLAPPED.
	HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		return IOR_TEST_INVALID_FD;
	}
	return h;
}

void test_close_fd(ior_fd_t fd)
{
	if (test_fd_is_valid(fd)) {
		CloseHandle(fd);
	}
}

int test_fd_is_valid(ior_fd_t fd)
{
	return fd != NULL && fd != INVALID_HANDLE_VALUE;
}

#ifdef IOR_HAVE_IOCP
ior_fd_t test_open_fd_readonly(const char *path)
{
	HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		return IOR_TEST_INVALID_FD;
	}
	return h;
}

ior_fd_t test_open_fd_writeonly(const char *path)
{
	HANDLE h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		return IOR_TEST_INVALID_FD;
	}
	return h;
}
#endif /* IOR_HAVE_IOCP */

/*
 * Windows has no socketpair(). Build a connected loopback TCP pair:
 *   - create a listener bound to 127.0.0.1:0 (ephemeral port)
 *   - read back the assigned port
 *   - create a client socket and connect() to it (blocking)
 *   - accept() the connection
 *   - return {accepted, client}
 *
 * Sockets are created with WSASocketW(..., WSA_FLAG_OVERLAPPED) so the IOCP
 * backend can issue overlapped reads/writes against the returned HANDLEs.
 * ior_fd_t is HANDLE on Windows; a SOCKET is castable to HANDLE for this use.
 *
 * WSAStartup is performed once per call and matched by WSACleanup only on the
 * failure paths; on success the Winsock refcount is intentionally left raised
 * for the lifetime of the returned sockets (closed by the caller). A matching
 * WSAStartup/WSACleanup balance per process is the caller-of-record's job; for
 * a short-lived test process leaving it raised is harmless.
 */
int test_make_socketpair(ior_fd_t fds[2])
{
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		return -EIO;
	}

	SOCKET listener = INVALID_SOCKET, client = INVALID_SOCKET, accepted = INVALID_SOCKET;
	struct sockaddr_in addr;
	int addr_len = sizeof(addr);

	listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listener == INVALID_SOCKET) {
		goto fail;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0; // ephemeral

	if (bind(listener, (struct sockaddr *) &addr, sizeof(addr)) == SOCKET_ERROR) {
		goto fail;
	}
	if (listen(listener, 1) == SOCKET_ERROR) {
		goto fail;
	}
	if (getsockname(listener, (struct sockaddr *) &addr, &addr_len) == SOCKET_ERROR) {
		goto fail;
	}

	// Overlapped client socket so IOCP can do async I/O on it.
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

	// The accepted socket inherits the listener's properties but is not
	// overlapped-flagged by default on all stacks; re-create coverage is not
	// needed because accept() on an overlapped listener yields a socket usable
	// with overlapped I/O. The listener itself is no longer needed.
	closesocket(listener);

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
	WSACleanup();
	return -EIO;
}

#else /* POSIX */

char *create_temp_file(const char *content, size_t len)
{
	char template[] = "/tmp/ior_test_XXXXXX";
	int fd = mkstemp(template);
	if (fd < 0) {
		return NULL;
	}

	if (content && len > 0) {
		ssize_t written = write(fd, content, len);
		if (written != (ssize_t) len) {
			close(fd);
			unlink(template);
			return NULL;
		}
	}

	close(fd);
	return strdup(template);
}

void remove_temp_file(const char *path)
{
	if (path) {
		unlink(path);
	}
}

ior_fd_t test_open_fd(const char *path)
{
	return open(path, O_RDWR);
}

void test_close_fd(ior_fd_t fd)
{
	if (test_fd_is_valid(fd)) {
		close(fd);
	}
}

int test_fd_is_valid(ior_fd_t fd)
{
	return fd >= 0;
}

int test_make_socketpair(ior_fd_t fds[2])
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		return -errno;
	}
	fds[0] = sv[0];
	fds[1] = sv[1];
	return 0;
}

#endif /* _WIN32 */
