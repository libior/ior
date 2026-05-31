/* SPDX-License-Identifier: BSD-3-Clause */
#include "test_utils.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

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
		HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, TRUNCATE_EXISTING,
				FILE_ATTRIBUTE_NORMAL, NULL);
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
	HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
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

#endif /* _WIN32 */
