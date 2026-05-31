/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * test_socket.c - Read/write coverage over connected stream sockets.
 *
 * These tests use a connected stream socket pair (test_make_socketpair):
 * AF_UNIX socketpair on POSIX, a loopback AF_INET TCP pair on Windows. They
 * exercise ONLY plain ior_prep_read / ior_prep_write on socket fds - the
 * dedicated socket operations (accept/connect/send/recv) are not part of the
 * public API yet, so there is nothing to test for those here.
 *
 * NOTE ON IOCP: socket support in the IOCP backend is incomplete - read/write
 * are routed through ReadFile/WriteFile rather than WSARecv/WSASend. On
 * io_uring the kernel treats socket fds uniformly, so these pass. On IOCP a
 * failure or 30s-timeout hang here is LEGITIMATE signal that the socket I/O
 * routing still needs the WSARecv/WSASend work, not a flaky test. The whole
 * suite uses offset 0 because sockets are not seekable and the backend must
 * not treat the offset as a file position for a socket fd.
 */
#include "test_utils.h"

/* Fixture: a ctx plus a connected stream socket pair. sock[0] and sock[1]
 * are the two ends; bytes written to one are readable from the other. */
typedef struct sock_state {
	ior_ctx *ctx;
	ior_fd_t sock[2];
} sock_state;

static int setup_socketpair(void **state)
{
	sock_state *s = calloc(1, sizeof(*s));
	assert_non_null(s);

	int ret = ior_queue_init(32, &s->ctx);
	assert_return_code(ret, 0);
	assert_non_null(s->ctx);

	ret = test_make_socketpair(s->sock);
	assert_return_code(ret, 0);
	assert_true(test_fd_is_valid(s->sock[0]));
	assert_true(test_fd_is_valid(s->sock[1]));

	*state = s;
	return 0;
}

static int teardown_socketpair(void **state)
{
	sock_state *s = (sock_state *) *state;
	if (s) {
		if (test_fd_is_valid(s->sock[0])) {
			test_close_fd(s->sock[0]);
		}
		if (test_fd_is_valid(s->sock[1])) {
			test_close_fd(s->sock[1]);
		}
		if (s->ctx) {
			ior_queue_exit(s->ctx);
		}
		free(s);
	}
	return 0;
}

/* Small helper: submit a single op and reap its one completion, returning
 * the res. Asserts the submit and the wait both succeed. */
static int32_t submit_one_and_get_res(ior_ctx *ctx, ior_sqe *sqe, void *tag)
{
	ior_sqe_set_data(ctx, sqe, tag);

	int ret = ior_submit_and_wait(ctx, 1);
	assert_true(ret >= 0);

	ior_cqe *cqe = NULL;
	ret = ior_wait_cqe(ctx, &cqe);
	assert_return_code(ret, 0);
	assert_int_equal((uintptr_t) ior_cqe_get_data(ctx, cqe), (uintptr_t) tag);

	int32_t res = ior_cqe_get_res(ctx, cqe);
	ior_cqe_seen(ctx, cqe);
	return res;
}

/* ===================================================================== */
/* Basic round-trip                                                      */
/* ===================================================================== */

/* Write a payload into sock[0], read it back from sock[1], verify bytes. */
static void test_socket_write_then_read(void **state)
{
	sock_state *s = (sock_state *) *state;

	const char *msg = "socket roundtrip";
	unsigned len = (unsigned) strlen(msg);

	ior_sqe *w = ior_get_sqe(s->ctx);
	assert_non_null(w);
	ior_prep_write(s->ctx, w, s->sock[0], msg, len, 0);
	assert_int_equal(submit_one_and_get_res(s->ctx, w, (void *) 0x1), (int32_t) len);

	char buf[64];
	memset(buf, 0, sizeof(buf));

	ior_sqe *r = ior_get_sqe(s->ctx);
	assert_non_null(r);
	ior_prep_read(s->ctx, r, s->sock[1], buf, len, 0);
	assert_int_equal(submit_one_and_get_res(s->ctx, r, (void *) 0x2), (int32_t) len);

	assert_memory_equal(buf, msg, len);
}

/* Same in the reverse direction, to confirm the pair is bidirectional and
 * neither end is special-cased. */
static void test_socket_read_other_direction(void **state)
{
	sock_state *s = (sock_state *) *state;

	const char *msg = "reverse path";
	unsigned len = (unsigned) strlen(msg);

	ior_sqe *w = ior_get_sqe(s->ctx);
	assert_non_null(w);
	ior_prep_write(s->ctx, w, s->sock[1], msg, len, 0);
	assert_int_equal(submit_one_and_get_res(s->ctx, w, (void *) 0x3), (int32_t) len);

	char buf[64];
	memset(buf, 0, sizeof(buf));

	ior_sqe *r = ior_get_sqe(s->ctx);
	assert_non_null(r);
	ior_prep_read(s->ctx, r, s->sock[0], buf, len, 0);
	assert_int_equal(submit_one_and_get_res(s->ctx, r, (void *) 0x4), (int32_t) len);

	assert_memory_equal(buf, msg, len);
}

/* ===================================================================== */
/* Partial read: read buffer smaller than what was written               */
/* ===================================================================== */

/*
 * Write N bytes, then read with a buffer that only holds part of them. A
 * stream read must return only as many bytes as the buffer allows (a "short
 * read"), and a second read must return the remainder. This pins down that
 * the backend honours the requested length rather than over-reading.
 */
static void test_socket_partial_read(void **state)
{
	sock_state *s = (sock_state *) *state;

	const char *msg = "0123456789ABCDEF"; /* 16 bytes */
	unsigned len = (unsigned) strlen(msg);

	ior_sqe *w = ior_get_sqe(s->ctx);
	assert_non_null(w);
	ior_prep_write(s->ctx, w, s->sock[0], msg, len, 0);
	assert_int_equal(submit_one_and_get_res(s->ctx, w, (void *) 0x10), (int32_t) len);

	/* First read: only ask for 6 bytes. */
	char buf[32];
	memset(buf, 0, sizeof(buf));

	ior_sqe *r1 = ior_get_sqe(s->ctx);
	assert_non_null(r1);
	ior_prep_read(s->ctx, r1, s->sock[1], buf, 6, 0);
	int32_t got1 = submit_one_and_get_res(s->ctx, r1, (void *) 0x11);
	assert_int_equal(got1, 6);
	assert_memory_equal(buf, "012345", 6);

	/* Second read: the remaining 10 bytes. */
	memset(buf, 0, sizeof(buf));
	ior_sqe *r2 = ior_get_sqe(s->ctx);
	assert_non_null(r2);
	ior_prep_read(s->ctx, r2, s->sock[1], buf, len - 6, 0);
	int32_t got2 = submit_one_and_get_res(s->ctx, r2, (void *) 0x12);
	assert_int_equal(got2, (int32_t) (len - 6));
	assert_memory_equal(buf, "6789ABCDEF", len - 6);
}

/* ===================================================================== */
/* Read after the peer closes -> EOF (res == 0)                          */
/* ===================================================================== */

/*
 * Close one end, then read from the other. On a stream socket this is the
 * orderly-shutdown case: the read must complete with res == 0 (EOF), not an
 * error and not a hang. This is the socket analogue of reading past EOF on a
 * file and is a common real-world path (peer hung up).
 */
static void test_socket_read_after_peer_close(void **state)
{
	sock_state *s = (sock_state *) *state;

	/* Close the write end. */
	test_close_fd(s->sock[0]);
	s->sock[0] = IOR_TEST_INVALID_FD;

	char buf[32];
	memset(buf, 0, sizeof(buf));

	ior_sqe *r = ior_get_sqe(s->ctx);
	assert_non_null(r);
	ior_prep_read(s->ctx, r, s->sock[1], buf, sizeof(buf), 0);
	int32_t res = submit_one_and_get_res(s->ctx, r, (void *) 0x20);

	/* Orderly peer shutdown surfaces as a 0-byte read (EOF). */
	assert_int_equal(res, 0);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(
				test_socket_write_then_read, setup_socketpair, teardown_socketpair),
		cmocka_unit_test_setup_teardown(
				test_socket_read_other_direction, setup_socketpair, teardown_socketpair),
		cmocka_unit_test_setup_teardown(
				test_socket_partial_read, setup_socketpair, teardown_socketpair),
		cmocka_unit_test_setup_teardown(
				test_socket_read_after_peer_close, setup_socketpair, teardown_socketpair),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
