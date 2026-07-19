/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * test_poll.c - IOR_OP_POLL readiness coverage over connected stream sockets.
 *
 * Uses a connected stream socket pair per case (test_make_socketpair). All
 * writes that make the peer readable go through the ring itself (ior_prep_write)
 * so the test stays portable across backends and platforms; each such write
 * produces its own CQE, so tests collect completions and match them by tag.
 */
#include "test_utils.h"

#define POLL_TAG(i) ((void *) (uintptr_t) (0x100 + (i)))
#define WRITE_TAG(i) ((void *) (uintptr_t) (0x200 + (i)))

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

/* Reap one completion and return its res, asserting the expected tag. */
static int32_t wait_res_for_tag(ior_ctx *ctx, void *tag)
{
	ior_cqe *cqe = NULL;
	int ret = ior_wait_cqe(ctx, &cqe);
	assert_return_code(ret, 0);
	assert_ptr_equal(ior_cqe_get_data(ctx, cqe), tag);
	int32_t res = ior_cqe_get_res(ctx, cqe);
	ior_cqe_seen(ctx, cqe);
	return res;
}

/*
 * Reap completions until the one carrying `tag` arrives, returning its res.
 * Other completions reaped along the way are ignored (e.g. helper writes).
 */
static int32_t wait_res_find_tag(ior_ctx *ctx, void *tag)
{
	for (int guard = 0; guard < 64; guard++) {
		ior_cqe *cqe = NULL;
		int ret = ior_wait_cqe(ctx, &cqe);
		assert_return_code(ret, 0);
		void *data = ior_cqe_get_data(ctx, cqe);
		int32_t res = ior_cqe_get_res(ctx, cqe);
		ior_cqe_seen(ctx, cqe);
		if (data == tag) {
			return res;
		}
	}
	fail_msg("completion with expected tag never arrived");
	return 0;
}

/* The backend must advertise poll support. */
static void test_poll_feature_flag(void **state)
{
	sock_state *s = (sock_state *) *state;
	assert_true(ior_get_features(s->ctx) & IOR_FEAT_POLL_ADD);
}

/* Poll on an already-readable socket completes with IOR_POLL_IN. */
static void test_poll_already_readable(void **state)
{
	sock_state *s = (sock_state *) *state;

	ior_sqe *w = ior_get_sqe(s->ctx);
	assert_non_null(w);
	ior_prep_write(s->ctx, w, s->sock[0], "x", 1, 0);
	ior_sqe_set_data(s->ctx, w, WRITE_TAG(0));
	assert_true(ior_submit_and_wait(s->ctx, 1) >= 0);
	assert_int_equal(wait_res_for_tag(s->ctx, WRITE_TAG(0)), 1);

	ior_sqe *p = ior_get_sqe(s->ctx);
	assert_non_null(p);
	ior_prep_poll_add(s->ctx, p, s->sock[1], IOR_POLL_IN);
	ior_sqe_set_data(s->ctx, p, POLL_TAG(0));
	assert_true(ior_submit_and_wait(s->ctx, 1) >= 0);

	int32_t res = wait_res_for_tag(s->ctx, POLL_TAG(0));
	assert_true(res > 0);
	assert_true(res & IOR_POLL_IN);
}

/* Poll armed before data exists completes once the peer writes. */
static void test_poll_becomes_readable(void **state)
{
	sock_state *s = (sock_state *) *state;

	ior_sqe *p = ior_get_sqe(s->ctx);
	assert_non_null(p);
	ior_prep_poll_add(s->ctx, p, s->sock[1], IOR_POLL_IN);
	ior_sqe_set_data(s->ctx, p, POLL_TAG(0));
	assert_true(ior_submit(s->ctx) >= 0);

	ior_sqe *w = ior_get_sqe(s->ctx);
	assert_non_null(w);
	ior_prep_write(s->ctx, w, s->sock[0], "x", 1, 0);
	ior_sqe_set_data(s->ctx, w, WRITE_TAG(0));
	assert_true(ior_submit(s->ctx) >= 0);

	int32_t res = wait_res_find_tag(s->ctx, POLL_TAG(0));
	assert_true(res > 0);
	assert_true(res & IOR_POLL_IN);
}

/* An idle stream socket is immediately writable. */
static void test_poll_writable(void **state)
{
	sock_state *s = (sock_state *) *state;

	ior_sqe *p = ior_get_sqe(s->ctx);
	assert_non_null(p);
	ior_prep_poll_add(s->ctx, p, s->sock[0], IOR_POLL_OUT);
	ior_sqe_set_data(s->ctx, p, POLL_TAG(0));
	assert_true(ior_submit_and_wait(s->ctx, 1) >= 0);

	int32_t res = wait_res_for_tag(s->ctx, POLL_TAG(0));
	assert_true(res > 0);
	assert_true(res & IOR_POLL_OUT);
}

/*
 * Multiplexing: arm polls over several socketpairs at once, then satisfy them
 * one at a time in reverse submission order. Each poll must complete with its
 * own readiness, proving pending polls do not block one another.
 */
#define NPAIRS 8
static void test_poll_multiplex(void **state)
{
	sock_state *s = (sock_state *) *state;

	ior_fd_t pairs[NPAIRS][2];
	for (int i = 0; i < NPAIRS; i++) {
		assert_return_code(test_make_socketpair(pairs[i]), 0);
	}

	for (int i = 0; i < NPAIRS; i++) {
		ior_sqe *p = ior_get_sqe(s->ctx);
		assert_non_null(p);
		ior_prep_poll_add(s->ctx, p, pairs[i][1], IOR_POLL_IN);
		ior_sqe_set_data(s->ctx, p, POLL_TAG(i));
	}
	assert_int_equal(ior_submit(s->ctx), NPAIRS);

	for (int i = NPAIRS - 1; i >= 0; i--) {
		ior_sqe *w = ior_get_sqe(s->ctx);
		assert_non_null(w);
		ior_prep_write(s->ctx, w, pairs[i][0], "x", 1, 0);
		ior_sqe_set_data(s->ctx, w, WRITE_TAG(i));
		assert_true(ior_submit(s->ctx) >= 0);

		int32_t res = wait_res_find_tag(s->ctx, POLL_TAG(i));
		assert_true(res > 0);
		assert_true(res & IOR_POLL_IN);
	}

	for (int i = 0; i < NPAIRS; i++) {
		test_close_fd(pairs[i][0]);
		test_close_fd(pairs[i][1]);
	}
}

/*
 * Two polls on the same fd with different masks: the OUT poll completes
 * immediately (idle socket is writable), the IN poll only after the peer
 * writes. Exercises per-fd registration merging in the epoll poller.
 */
static void test_poll_same_fd(void **state)
{
	sock_state *s = (sock_state *) *state;

	ior_sqe *pin = ior_get_sqe(s->ctx);
	assert_non_null(pin);
	ior_prep_poll_add(s->ctx, pin, s->sock[1], IOR_POLL_IN);
	ior_sqe_set_data(s->ctx, pin, POLL_TAG(1));

	ior_sqe *pout = ior_get_sqe(s->ctx);
	assert_non_null(pout);
	ior_prep_poll_add(s->ctx, pout, s->sock[1], IOR_POLL_OUT);
	ior_sqe_set_data(s->ctx, pout, POLL_TAG(2));

	assert_int_equal(ior_submit(s->ctx), 2);

	int32_t res = wait_res_find_tag(s->ctx, POLL_TAG(2));
	assert_true(res > 0);
	assert_true(res & IOR_POLL_OUT);

	ior_sqe *w = ior_get_sqe(s->ctx);
	assert_non_null(w);
	ior_prep_write(s->ctx, w, s->sock[0], "x", 1, 0);
	ior_sqe_set_data(s->ctx, w, WRITE_TAG(0));
	assert_true(ior_submit(s->ctx) >= 0);

	res = wait_res_find_tag(s->ctx, POLL_TAG(1));
	assert_true(res > 0);
	assert_true(res & IOR_POLL_IN);
}

/*
 * A poll guarded by a link timeout on a silent socket: the timeout fires, the
 * poll completes with -ECANCELED and the link timeout with -ETIME.
 */
static void test_poll_link_timeout(void **state)
{
	sock_state *s = (sock_state *) *state;

	ior_timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000000LL };

	ior_sqe *p = ior_get_sqe(s->ctx);
	assert_non_null(p);
	ior_prep_poll_add(s->ctx, p, s->sock[1], IOR_POLL_IN);
	ior_sqe_set_flags(s->ctx, p, IOR_SQE_IO_LINK);
	ior_sqe_set_data(s->ctx, p, POLL_TAG(0));

	ior_sqe *lt = ior_get_sqe(s->ctx);
	assert_non_null(lt);
	ior_prep_link_timeout(s->ctx, lt, &ts, 0);
	ior_sqe_set_data(s->ctx, lt, POLL_TAG(1));

	assert_int_equal(ior_submit(s->ctx), 2);

	int32_t poll_res = 0, lt_res = 0;
	for (int i = 0; i < 2; i++) {
		ior_cqe *cqe = NULL;
		assert_return_code(ior_wait_cqe(s->ctx, &cqe), 0);
		void *data = ior_cqe_get_data(s->ctx, cqe);
		int32_t res = ior_cqe_get_res(s->ctx, cqe);
		ior_cqe_seen(s->ctx, cqe);
		if (data == POLL_TAG(0)) {
			poll_res = res;
		} else {
			assert_ptr_equal(data, POLL_TAG(1));
			lt_res = res;
		}
	}

	assert_int_equal(poll_res, -ECANCELED);
	assert_int_equal(lt_res, -ETIME);
}

/* Closing the peer completes an IN poll (readable EOF and/or hangup). */
static void test_poll_peer_hangup(void **state)
{
	sock_state *s = (sock_state *) *state;

	ior_sqe *p = ior_get_sqe(s->ctx);
	assert_non_null(p);
	ior_prep_poll_add(s->ctx, p, s->sock[1], IOR_POLL_IN);
	ior_sqe_set_data(s->ctx, p, POLL_TAG(0));
	assert_true(ior_submit(s->ctx) >= 0);

	test_close_fd(s->sock[0]);
	s->sock[0] = IOR_TEST_INVALID_FD;

	int32_t res = wait_res_for_tag(s->ctx, POLL_TAG(0));
	assert_true(res > 0);
	// Which of IN/HUP is set on peer close is platform-dependent.
	assert_true(res & (IOR_POLL_IN | IOR_POLL_HUP));
}

/* Tearing down the context with a pending poll must not hang. */
static void test_poll_pending_at_exit(void **state)
{
	(void) state;

	ior_ctx *ctx = NULL;
	assert_return_code(ior_queue_init(32, &ctx), 0);

	ior_fd_t sock[2];
	assert_return_code(test_make_socketpair(sock), 0);

	ior_sqe *p = ior_get_sqe(ctx);
	assert_non_null(p);
	ior_prep_poll_add(ctx, p, sock[1], IOR_POLL_IN);
	assert_true(ior_submit(ctx) >= 0);

	// The socket never becomes readable; exit must cancel the pending poll.
	ior_queue_exit(ctx);

	test_close_fd(sock[0]);
	test_close_fd(sock[1]);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(
				test_poll_feature_flag, setup_socketpair, teardown_socketpair),
		cmocka_unit_test_setup_teardown(
				test_poll_already_readable, setup_socketpair, teardown_socketpair),
		cmocka_unit_test_setup_teardown(
				test_poll_becomes_readable, setup_socketpair, teardown_socketpair),
		cmocka_unit_test_setup_teardown(test_poll_writable, setup_socketpair, teardown_socketpair),
		cmocka_unit_test_setup_teardown(test_poll_multiplex, setup_socketpair, teardown_socketpair),
		cmocka_unit_test_setup_teardown(test_poll_same_fd, setup_socketpair, teardown_socketpair),
		cmocka_unit_test_setup_teardown(
				test_poll_link_timeout, setup_socketpair, teardown_socketpair),
		cmocka_unit_test_setup_teardown(
				test_poll_peer_hangup, setup_socketpair, teardown_socketpair),
		cmocka_unit_test(test_poll_pending_at_exit),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
