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

/*
 * Reap the poll carrying poll_tag and the write carrying write_tag, in either
 * order, and return the poll's res. The write must be reaped too: the poll
 * may complete (from the poller thread) before the worker's write() has
 * returned, and a teardown that closes the socket under an op still in flight
 * is a use of a closed descriptor the backend cannot prevent.
 */
static int32_t wait_poll_and_write(ior_ctx *ctx, void *poll_tag, void *write_tag)
{
	int32_t poll_res = 0;
	int got_poll = 0, got_write = 0;
	while (!got_poll || !got_write) {
		ior_cqe *cqe = NULL;
		assert_return_code(ior_wait_cqe(ctx, &cqe), 0);
		void *data = ior_cqe_get_data(ctx, cqe);
		int32_t res = ior_cqe_get_res(ctx, cqe);
		ior_cqe_seen(ctx, cqe);
		if (data == poll_tag) {
			poll_res = res;
			got_poll = 1;
		} else if (data == write_tag) {
			assert_int_equal(res, 1);
			got_write = 1;
		} else {
			fail_msg("unexpected completion tag %p", data);
		}
	}
	return poll_res;
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

	int32_t res = wait_poll_and_write(s->ctx, POLL_TAG(0), WRITE_TAG(0));
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

		int32_t res = wait_poll_and_write(s->ctx, POLL_TAG(i), WRITE_TAG(i));
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

	res = wait_poll_and_write(s->ctx, POLL_TAG(1), WRITE_TAG(0));
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

/*
 * A poll of a socket ready at submit, guarded by a zero link timeout (a
 * liveness check that must not wait): the poll completes with the readiness
 * and the timeout, never armed, with -ECANCELED. io_uring (6.16 and later)
 * arms the timeout around the poll's issue, so a zero one can fire while the
 * poll's completion is still being flushed and find nothing to cancel:
 * -ENOENT.
 */
static void test_poll_ready_zero_link_timeout(void **state)
{
	sock_state *s = (sock_state *) *state;

	ior_sqe *w = ior_get_sqe(s->ctx);
	assert_non_null(w);
	ior_prep_write(s->ctx, w, s->sock[0], "x", 1, 0);
	ior_sqe_set_data(s->ctx, w, WRITE_TAG(0));
	assert_true(ior_submit_and_wait(s->ctx, 1) >= 0);
	assert_int_equal(wait_res_for_tag(s->ctx, WRITE_TAG(0)), 1);

	int rounds = 20;
	for (int round = 0; round < rounds; round++) {
		ior_timespec ts = { .tv_sec = 0, .tv_nsec = 0 };

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

		assert_true(poll_res > 0);
		assert_true(poll_res & IOR_POLL_IN);
		if (ior_get_backend_type(s->ctx) == IOR_BACKEND_IOURING && lt_res == -ENOENT) {
			continue;
		}
		assert_int_equal(lt_res, -ECANCELED);
	}
}

/*
 * A poll answered at submit splits its chain: the poll completes with its
 * mask, its link timeout with -ECANCELED, and what is linked behind them (a
 * nop) runs as a chain of its own.
 */
static void test_poll_ready_link_timeout_chain(void **state)
{
	sock_state *s = (sock_state *) *state;

	ior_sqe *w = ior_get_sqe(s->ctx);
	assert_non_null(w);
	ior_prep_write(s->ctx, w, s->sock[0], "x", 1, 0);
	ior_sqe_set_data(s->ctx, w, WRITE_TAG(0));
	assert_true(ior_submit_and_wait(s->ctx, 1) >= 0);
	assert_int_equal(wait_res_for_tag(s->ctx, WRITE_TAG(0)), 1);

	ior_timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000000LL };

	ior_sqe *p = ior_get_sqe(s->ctx);
	assert_non_null(p);
	ior_prep_poll_add(s->ctx, p, s->sock[1], IOR_POLL_IN);
	ior_sqe_set_flags(s->ctx, p, IOR_SQE_IO_LINK);
	ior_sqe_set_data(s->ctx, p, POLL_TAG(0));

	ior_sqe *lt = ior_get_sqe(s->ctx);
	assert_non_null(lt);
	ior_prep_link_timeout(s->ctx, lt, &ts, 0);
	ior_sqe_set_flags(s->ctx, lt, IOR_SQE_IO_LINK);
	ior_sqe_set_data(s->ctx, lt, POLL_TAG(1));

	ior_sqe *nop = ior_get_sqe(s->ctx);
	assert_non_null(nop);
	ior_prep_nop(s->ctx, nop);
	ior_sqe_set_data(s->ctx, nop, POLL_TAG(2));

	assert_int_equal(ior_submit(s->ctx), 3);

	int32_t poll_res = 0, lt_res = 0, nop_res = -1;
	for (int i = 0; i < 3; i++) {
		ior_cqe *cqe = NULL;
		assert_return_code(ior_wait_cqe(s->ctx, &cqe), 0);
		void *data = ior_cqe_get_data(s->ctx, cqe);
		int32_t res = ior_cqe_get_res(s->ctx, cqe);
		ior_cqe_seen(s->ctx, cqe);
		if (data == POLL_TAG(0)) {
			poll_res = res;
		} else if (data == POLL_TAG(1)) {
			lt_res = res;
		} else {
			assert_ptr_equal(data, POLL_TAG(2));
			nop_res = res;
		}
	}

	assert_true(poll_res > 0);
	assert_true(poll_res & IOR_POLL_IN);
	assert_int_equal(lt_res, -ECANCELED);
	assert_int_equal(nop_res, 0);
}

/*
 * A cancel submitted in the same batch as a poll of a ready descriptor finds
 * nothing: the poll was answered at submit, before the cancel ran.
 */
static void test_poll_ready_cancel_same_batch(void **state)
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

	ior_sqe *c = ior_get_sqe(s->ctx);
	assert_non_null(c);
	ior_prep_cancel(s->ctx, c, POLL_TAG(0));
	ior_sqe_set_data(s->ctx, c, POLL_TAG(1));

	assert_int_equal(ior_submit(s->ctx), 2);

	int32_t poll_res = 0, cancel_res = 0;
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
			cancel_res = res;
		}
	}

	assert_true(poll_res > 0);
	assert_true(poll_res & IOR_POLL_IN);
	assert_int_equal(cancel_res, -ENOENT);
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

/* ===== Multishot polls ===== */

/*
 * Whether this build reports one completion per readiness edge and nothing
 * while readiness merely persists: io_uring, and the thread backend on epoll
 * or kqueue. The poll(2) and WSAPoll pollers repeat persisting readiness
 * (see ior_prep_poll_multishot), so tests only check for silence here.
 */
static int poll_edges_exact(ior_ctx *ctx)
{
#if defined(IOR_HAVE_EPOLL) || defined(IOR_HAVE_KQUEUE)
	int threads_exact = 1;
#else
	int threads_exact = 0;
#endif
	ior_backend_type backend = ior_get_backend_type(ctx);
	return backend == IOR_BACKEND_IOURING || (backend == IOR_BACKEND_THREADS && threads_exact);
}

typedef struct cqe_rec {
	void *data;
	int32_t res;
	uint32_t flags;
} cqe_rec;

/* Reap one completion within timeout_ms into *out, or return -ETIME. */
static int reap_rec(ior_ctx *ctx, cqe_rec *out, int timeout_ms)
{
	ior_timespec ts = { .tv_sec = timeout_ms / 1000, .tv_nsec = (timeout_ms % 1000) * 1000000LL };
	ior_cqe *cqe = NULL;
	int ret = ior_wait_cqe_timeout(ctx, &cqe, &ts);
	if (ret == -ETIME) {
		return -ETIME;
	}
	assert_return_code(ret, 0);
	out->data = ior_cqe_get_data(ctx, cqe);
	out->res = ior_cqe_get_res(ctx, cqe);
	out->flags = ior_cqe_get_flags(ctx, cqe);
	ior_cqe_seen(ctx, cqe);
	return 0;
}

/* Nothing may complete for ms. */
static void expect_quiet(ior_ctx *ctx, int ms)
{
	cqe_rec r;
	assert_int_equal(reap_rec(ctx, &r, ms), -ETIME);
}

/*
 * Reap until an edge of the multishot poll carrying poll_tag (res > 0 with
 * IOR_CQE_F_MORE) has arrived, and the write carrying write_tag too if
 * non-NULL. Further edges of the same poll are tolerated: the level-triggered
 * pollers repeat readiness that persists. Returns the first edge's res.
 */
static int32_t wait_edge(ior_ctx *ctx, void *poll_tag, void *write_tag)
{
	int32_t edge_res = 0;
	int got_edge = 0, got_write = write_tag == NULL;
	while (!got_edge || !got_write) {
		cqe_rec r;
		assert_return_code(reap_rec(ctx, &r, 2000), 0);
		if (r.data == poll_tag) {
			assert_true(r.res > 0);
			assert_true(r.flags & IOR_CQE_F_MORE);
			if (!got_edge) {
				edge_res = r.res;
				got_edge = 1;
			}
		} else if (r.data == write_tag) {
			assert_int_equal(r.res, 1);
			got_write = 1;
		} else {
			fail_msg("unexpected completion tag %p", r.data);
		}
	}
	return edge_res;
}

/*
 * Reap until the last completion of the multishot poll carrying poll_tag
 * (no IOR_CQE_F_MORE) and, if other_tag is non-NULL, the completion carrying
 * it (a cancel, a link timeout). Edges of the poll arriving meanwhile are
 * skipped. The two results are stored.
 */
static void wait_final(
		ior_ctx *ctx, void *poll_tag, int32_t *final_res, void *other_tag, int32_t *other_res)
{
	int got_final = 0, got_other = other_tag == NULL;
	while (!got_final || !got_other) {
		cqe_rec r;
		assert_return_code(reap_rec(ctx, &r, 2000), 0);
		if (r.data == poll_tag) {
			if (r.flags & IOR_CQE_F_MORE) {
				assert_true(r.res > 0);
				continue;
			}
			assert_false(got_final);
			*final_res = r.res;
			got_final = 1;
		} else if (r.data == other_tag) {
			*other_res = r.res;
			got_other = 1;
		} else {
			fail_msg("unexpected completion tag %p", r.data);
		}
	}
}

static void submit_write(ior_ctx *ctx, ior_fd_t fd, void *tag)
{
	ior_sqe *w = ior_get_sqe(ctx);
	assert_non_null(w);
	ior_prep_write(ctx, w, fd, "x", 1, 0);
	ior_sqe_set_data(ctx, w, tag);
	assert_true(ior_submit(ctx) >= 0);
}

/* Read what is pending on fd through the ring; returns the byte count. */
static int32_t drain_fd(ior_ctx *ctx, ior_fd_t fd, void *tag)
{
	char buf[16];
	ior_sqe *r = ior_get_sqe(ctx);
	assert_non_null(r);
	ior_prep_read(ctx, r, fd, buf, sizeof(buf), IOR_OFF_NONE);
	ior_sqe_set_data(ctx, r, tag);
	assert_true(ior_submit(ctx) >= 0);
	return wait_res_find_tag(ctx, tag);
}

static void submit_poll_multishot(ior_ctx *ctx, ior_fd_t fd, uint32_t mask, void *tag)
{
	ior_sqe *p = ior_get_sqe(ctx);
	assert_non_null(p);
	ior_prep_poll_multishot(ctx, p, fd, mask);
	ior_sqe_set_data(ctx, p, tag);
	assert_true(ior_submit(ctx) >= 0);
}

#define READ_TAG(i) ((void *) (uintptr_t) (0x300 + (i)))
#define CANCEL_TAG ((void *) (uintptr_t) 0x400)

/*
 * A multishot poll posts one completion per readiness edge, flagged
 * IOR_CQE_F_MORE, stays silent while readiness merely persists, fires again
 * for new data, and ends with -ECANCELED (no IOR_CQE_F_MORE) when cancelled.
 */
static void test_poll_multishot_edges(void **state)
{
	sock_state *s = (sock_state *) *state;
	int exact = poll_edges_exact(s->ctx);

	submit_poll_multishot(s->ctx, s->sock[1], IOR_POLL_IN, POLL_TAG(0));
	expect_quiet(s->ctx, 50);

	submit_write(s->ctx, s->sock[0], WRITE_TAG(0));
	assert_true(wait_edge(s->ctx, POLL_TAG(0), WRITE_TAG(0)) & IOR_POLL_IN);
	if (exact) {
		// Still readable, but no new edge.
		expect_quiet(s->ctx, 50);
	}

	// More data on an undrained socket is a new edge.
	submit_write(s->ctx, s->sock[0], WRITE_TAG(1));
	assert_true(wait_edge(s->ctx, POLL_TAG(0), WRITE_TAG(1)) & IOR_POLL_IN);

	assert_int_equal(drain_fd(s->ctx, s->sock[1], READ_TAG(0)), 2);
	if (exact) {
		// Draining is not an edge either.
		expect_quiet(s->ctx, 50);
	}

	submit_write(s->ctx, s->sock[0], WRITE_TAG(2));
	assert_true(wait_edge(s->ctx, POLL_TAG(0), WRITE_TAG(2)) & IOR_POLL_IN);
	assert_int_equal(drain_fd(s->ctx, s->sock[1], READ_TAG(1)), 1);

	ior_sqe *c = ior_get_sqe(s->ctx);
	assert_non_null(c);
	ior_prep_cancel(s->ctx, c, POLL_TAG(0));
	ior_sqe_set_data(s->ctx, c, CANCEL_TAG);
	assert_true(ior_submit(s->ctx) >= 0);

	int32_t final_res = 0, cancel_res = 0;
	wait_final(s->ctx, POLL_TAG(0), &final_res, CANCEL_TAG, &cancel_res);
	assert_int_equal(cancel_res, 0);
	assert_int_equal(final_res, -ECANCELED);
	expect_quiet(s->ctx, 20);
}

/* Each write-drain cycle is one edge; the watch survives many re-arms. */
static void test_poll_multishot_cycles(void **state)
{
	sock_state *s = (sock_state *) *state;

	submit_poll_multishot(s->ctx, s->sock[1], IOR_POLL_IN, POLL_TAG(0));
	for (int i = 0; i < 16; i++) {
		submit_write(s->ctx, s->sock[0], WRITE_TAG(i));
		assert_true(wait_edge(s->ctx, POLL_TAG(0), WRITE_TAG(i)) & IOR_POLL_IN);
		assert_int_equal(drain_fd(s->ctx, s->sock[1], READ_TAG(i)), 1);
	}

	ior_sqe *c = ior_get_sqe(s->ctx);
	assert_non_null(c);
	ior_prep_cancel(s->ctx, c, POLL_TAG(0));
	ior_sqe_set_data(s->ctx, c, CANCEL_TAG);
	assert_true(ior_submit(s->ctx) >= 0);

	int32_t final_res = 0, cancel_res = 0;
	wait_final(s->ctx, POLL_TAG(0), &final_res, CANCEL_TAG, &cancel_res);
	assert_int_equal(cancel_res, 0);
	assert_int_equal(final_res, -ECANCELED);
}

/*
 * An idle socket is writable once: one edge, then silence. Cancelling by
 * descriptor ends the poll.
 */
static void test_poll_multishot_writable(void **state)
{
	sock_state *s = (sock_state *) *state;

	submit_poll_multishot(s->ctx, s->sock[0], IOR_POLL_OUT, POLL_TAG(0));
	assert_true(wait_edge(s->ctx, POLL_TAG(0), NULL) & IOR_POLL_OUT);
	if (poll_edges_exact(s->ctx)) {
		expect_quiet(s->ctx, 50);
	}

	ior_sqe *c = ior_get_sqe(s->ctx);
	assert_non_null(c);
	ior_prep_cancel_fd(s->ctx, c, s->sock[0]);
	ior_sqe_set_data(s->ctx, c, CANCEL_TAG);
	assert_true(ior_submit(s->ctx) >= 0);

	int32_t final_res = 0, cancel_res = 0;
	wait_final(s->ctx, POLL_TAG(0), &final_res, CANCEL_TAG, &cancel_res);
	assert_int_equal(cancel_res, 0);
	assert_int_equal(final_res, -ECANCELED);
}

/*
 * A link timeout bounds the whole multishot poll: it stays armed across
 * edges, and when it fires the poll ends with -ECANCELED and the timeout
 * completes with -ETIME.
 */
static void test_poll_multishot_link_timeout(void **state)
{
	sock_state *s = (sock_state *) *state;

	ior_timespec ts = { .tv_sec = 0, .tv_nsec = 150 * 1000000LL };

	ior_sqe *p = ior_get_sqe(s->ctx);
	assert_non_null(p);
	ior_prep_poll_multishot(s->ctx, p, s->sock[1], IOR_POLL_IN);
	ior_sqe_set_flags(s->ctx, p, IOR_SQE_IO_LINK);
	ior_sqe_set_data(s->ctx, p, POLL_TAG(0));

	ior_sqe *lt = ior_get_sqe(s->ctx);
	assert_non_null(lt);
	ior_prep_link_timeout(s->ctx, lt, &ts, 0);
	ior_sqe_set_data(s->ctx, lt, POLL_TAG(1));

	assert_int_equal(ior_submit(s->ctx), 2);

	submit_write(s->ctx, s->sock[0], WRITE_TAG(0));
	assert_true(wait_edge(s->ctx, POLL_TAG(0), WRITE_TAG(0)) & IOR_POLL_IN);
	assert_int_equal(drain_fd(s->ctx, s->sock[1], READ_TAG(0)), 1);

	int32_t final_res = 0, lt_res = 0;
	wait_final(s->ctx, POLL_TAG(0), &final_res, POLL_TAG(1), &lt_res);
	assert_int_equal(final_res, -ECANCELED);
	assert_int_equal(lt_res, -ETIME);
}

/* A peer hang-up is one edge; the poll stays armed until cancelled. */
static void test_poll_multishot_peer_hangup(void **state)
{
	sock_state *s = (sock_state *) *state;

	submit_poll_multishot(s->ctx, s->sock[1], IOR_POLL_IN, POLL_TAG(0));
	expect_quiet(s->ctx, 20);

	test_close_fd(s->sock[0]);
	s->sock[0] = IOR_TEST_INVALID_FD;

	// Which of IN/HUP is set on peer close is platform-dependent.
	assert_true(wait_edge(s->ctx, POLL_TAG(0), NULL) & (IOR_POLL_IN | IOR_POLL_HUP));
	if (poll_edges_exact(s->ctx)) {
		expect_quiet(s->ctx, 50);
	}

	ior_sqe *c = ior_get_sqe(s->ctx);
	assert_non_null(c);
	ior_prep_cancel(s->ctx, c, POLL_TAG(0));
	ior_sqe_set_data(s->ctx, c, CANCEL_TAG);
	assert_true(ior_submit(s->ctx) >= 0);

	int32_t final_res = 0, cancel_res = 0;
	wait_final(s->ctx, POLL_TAG(0), &final_res, CANCEL_TAG, &cancel_res);
	assert_int_equal(cancel_res, 0);
	assert_int_equal(final_res, -ECANCELED);
}

/*
 * A multishot and a one-shot poll on the same descriptor: the one-shot
 * completes for good, the multishot reports the edge and stays. Exercises
 * the separate edge-triggered registration next to the shared level one.
 */
static void test_poll_multishot_with_oneshot(void **state)
{
	sock_state *s = (sock_state *) *state;

	submit_poll_multishot(s->ctx, s->sock[1], IOR_POLL_IN, POLL_TAG(0));

	ior_sqe *p = ior_get_sqe(s->ctx);
	assert_non_null(p);
	ior_prep_poll_add(s->ctx, p, s->sock[1], IOR_POLL_IN);
	ior_sqe_set_data(s->ctx, p, POLL_TAG(1));
	assert_true(ior_submit(s->ctx) >= 0);
	expect_quiet(s->ctx, 20);

	submit_write(s->ctx, s->sock[0], WRITE_TAG(0));

	int got_multi = 0, got_one = 0, got_write = 0;
	while (!got_multi || !got_one || !got_write) {
		cqe_rec r;
		assert_return_code(reap_rec(s->ctx, &r, 2000), 0);
		if (r.data == POLL_TAG(0)) {
			assert_true(r.res & IOR_POLL_IN);
			assert_true(r.flags & IOR_CQE_F_MORE);
			got_multi = 1;
		} else if (r.data == POLL_TAG(1)) {
			assert_true(r.res & IOR_POLL_IN);
			assert_false(r.flags & IOR_CQE_F_MORE);
			assert_false(got_one);
			got_one = 1;
		} else if (r.data == WRITE_TAG(0)) {
			assert_int_equal(r.res, 1);
			got_write = 1;
		} else {
			fail_msg("unexpected completion tag %p", r.data);
		}
	}

	ior_sqe *c = ior_get_sqe(s->ctx);
	assert_non_null(c);
	ior_prep_cancel(s->ctx, c, POLL_TAG(0));
	ior_sqe_set_data(s->ctx, c, CANCEL_TAG);
	assert_true(ior_submit(s->ctx) >= 0);

	int32_t final_res = 0, cancel_res = 0;
	wait_final(s->ctx, POLL_TAG(0), &final_res, CANCEL_TAG, &cancel_res);
	assert_int_equal(cancel_res, 0);
	assert_int_equal(final_res, -ECANCELED);
}

/*
 * A regular file is always ready and has no edges: the multishot completes
 * at once with its mask as the last completion (on IOCP only sockets are
 * pollable: -ENOTSOCK), and a cancel afterwards finds nothing.
 */
static void test_poll_multishot_regular_file(void **state)
{
	sock_state *s = (sock_state *) *state;

	char *path = create_temp_file("data", 4);
	assert_non_null(path);
	ior_fd_t fd = test_open_fd(path);
	assert_true(test_fd_is_valid(fd));

	submit_poll_multishot(s->ctx, fd, IOR_POLL_IN, POLL_TAG(0));

	cqe_rec r;
	assert_return_code(reap_rec(s->ctx, &r, 2000), 0);
	assert_ptr_equal(r.data, POLL_TAG(0));
	assert_false(r.flags & IOR_CQE_F_MORE);
#ifdef _WIN32
	assert_int_equal(r.res, -ENOTSOCK);
#else
	assert_true(r.res & IOR_POLL_IN);
#endif

	ior_sqe *c = ior_get_sqe(s->ctx);
	assert_non_null(c);
	ior_prep_cancel(s->ctx, c, POLL_TAG(0));
	ior_sqe_set_data(s->ctx, c, CANCEL_TAG);
	assert_true(ior_submit(s->ctx) >= 0);
	assert_int_equal(wait_res_for_tag(s->ctx, CANCEL_TAG), -ENOENT);

	test_close_fd(fd);
	remove_temp_file(path);
	free(path);
}

/*
 * A one-shot poll of a regular file: always ready, so it completes at once
 * (on IOCP only sockets are pollable: -ENOTSOCK).
 */
static void test_poll_regular_file(void **state)
{
	sock_state *s = (sock_state *) *state;

	char *path = create_temp_file("data", 4);
	assert_non_null(path);
	ior_fd_t fd = test_open_fd(path);
	assert_true(test_fd_is_valid(fd));

	ior_sqe *p = ior_get_sqe(s->ctx);
	assert_non_null(p);
	ior_prep_poll_add(s->ctx, p, fd, IOR_POLL_IN);
	ior_sqe_set_data(s->ctx, p, POLL_TAG(0));
	assert_true(ior_submit(s->ctx) >= 0);

	cqe_rec r;
	assert_return_code(reap_rec(s->ctx, &r, 2000), 0);
	assert_ptr_equal(r.data, POLL_TAG(0));
	assert_false(r.flags & IOR_CQE_F_MORE);
#ifdef _WIN32
	assert_int_equal(r.res, -ENOTSOCK);
#else
	assert_true(r.res & IOR_POLL_IN);
#endif

	test_close_fd(fd);
	remove_temp_file(path);
	free(path);
}

/* Tearing down the context with a pending multishot poll must not hang. */
static void test_poll_multishot_pending_at_exit(void **state)
{
	(void) state;

	ior_ctx *ctx = NULL;
	assert_return_code(ior_queue_init(32, &ctx), 0);

	ior_fd_t sock[2];
	assert_return_code(test_make_socketpair(sock), 0);

	submit_poll_multishot(ctx, sock[1], IOR_POLL_IN, POLL_TAG(0));
	// One edge has been reported; the poll is still armed at exit.
	submit_write(ctx, sock[0], WRITE_TAG(0));
	assert_true(wait_edge(ctx, POLL_TAG(0), WRITE_TAG(0)) & IOR_POLL_IN);

	ior_queue_exit(ctx);

	test_close_fd(sock[0]);
	test_close_fd(sock[1]);
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
				test_poll_ready_zero_link_timeout, setup_socketpair, teardown_socketpair),
		cmocka_unit_test_setup_teardown(
				test_poll_ready_link_timeout_chain, setup_socketpair, teardown_socketpair),
		cmocka_unit_test_setup_teardown(
				test_poll_ready_cancel_same_batch, setup_socketpair, teardown_socketpair),
		cmocka_unit_test_setup_teardown(
				test_poll_peer_hangup, setup_socketpair, teardown_socketpair),
		cmocka_unit_test(test_poll_pending_at_exit),
		cmocka_unit_test_setup_teardown(
				test_poll_multishot_edges, setup_socketpair, teardown_socketpair),
		cmocka_unit_test_setup_teardown(
				test_poll_multishot_cycles, setup_socketpair, teardown_socketpair),
		cmocka_unit_test_setup_teardown(
				test_poll_multishot_writable, setup_socketpair, teardown_socketpair),
		cmocka_unit_test_setup_teardown(
				test_poll_multishot_link_timeout, setup_socketpair, teardown_socketpair),
		cmocka_unit_test_setup_teardown(
				test_poll_multishot_peer_hangup, setup_socketpair, teardown_socketpair),
		cmocka_unit_test_setup_teardown(
				test_poll_multishot_with_oneshot, setup_socketpair, teardown_socketpair),
		cmocka_unit_test_setup_teardown(
				test_poll_multishot_regular_file, setup_socketpair, teardown_socketpair),
		cmocka_unit_test_setup_teardown(
				test_poll_regular_file, setup_socketpair, teardown_socketpair),
		cmocka_unit_test(test_poll_multishot_pending_at_exit),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
