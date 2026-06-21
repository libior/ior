/* SPDX-License-Identifier: BSD-3-Clause */
#include "test_utils.h"

#define TAG_OP ((void *) 0x1) // the guarded recv
#define TAG_TMO ((void *) 0x2) // the link timeout

typedef struct lt_state {
	ior_ctx *ctx;
	ior_fd_t sock[2];
} lt_state;

static int setup_lt(void **state)
{
	lt_state *s = calloc(1, sizeof(*s));
	assert_non_null(s);

	int ret = ior_queue_init(32, &s->ctx);
	assert_return_code(ret, 0);
	assert_non_null(s->ctx);

	ret = test_make_socketpair(s->sock);
	assert_return_code(ret, 0);

	*state = s;
	return 0;
}

static int teardown_lt(void **state)
{
	lt_state *s = (lt_state *) *state;
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

// Reap exactly the guarded-op and link-timeout completions, by tag.
static void reap_pair(ior_ctx *ctx, int32_t *res_op, int32_t *res_tmo)
{
	int have_op = 0, have_tmo = 0;

	while (!have_op || !have_tmo) {
		ior_cqe *cqe = NULL;
		int ret = ior_wait_cqe(ctx, &cqe);
		if (ret == -EAGAIN || ret == -EINTR) {
			continue;
		}
		assert_return_code(ret, 0);
		assert_non_null(cqe);

		uintptr_t tag = (uintptr_t) ior_cqe_get_data(ctx, cqe);
		int32_t res = ior_cqe_get_res(ctx, cqe);
		if (tag == (uintptr_t) TAG_OP) {
			*res_op = res;
			have_op = 1;
		} else if (tag == (uintptr_t) TAG_TMO) {
			*res_tmo = res;
			have_tmo = 1;
		} else {
			fail_msg("unexpected completion tag %p", (void *) tag);
		}
		ior_cqe_seen(ctx, cqe);
	}
}

// Timer wins: nothing is sent, so the recv is cancelled at the deadline.
static void test_link_timeout_fires(void **state)
{
	lt_state *s = (lt_state *) *state;
	char buf[64];
	memset(buf, 0, sizeof(buf));

	ior_sqe *r = ior_get_sqe(s->ctx);
	assert_non_null(r);
	ior_prep_recv(s->ctx, r, s->sock[1], buf, sizeof(buf), 0);
	ior_sqe_set_data(s->ctx, r, TAG_OP);
	ior_sqe_set_flags(s->ctx, r, IOR_SQE_IO_LINK);

	ior_sqe *t = ior_get_sqe(s->ctx);
	assert_non_null(t);
	ior_timespec ts = { .tv_sec = 0, .tv_nsec = 50000000 }; // 50ms
	ior_prep_link_timeout(s->ctx, t, &ts, 0);
	ior_sqe_set_data(s->ctx, t, TAG_TMO);

	int ret = ior_submit_and_wait(s->ctx, 2);
	assert_true(ret >= 0);

	int32_t res_op = 0, res_tmo = 0;
	reap_pair(s->ctx, &res_op, &res_tmo);

	assert_int_equal(res_op, -ECANCELED);
	assert_true(res_tmo == -ETIME || res_tmo == -ETIMEDOUT);
}

/*
 * Guarded op wins: data is already waiting, so the recv completes first and the
 * link timeout is cancelled.
 */
static void test_link_timeout_op_first(void **state)
{
	lt_state *s = (lt_state *) *state;

	const char *msg = "ready";
	unsigned len = (unsigned) strlen(msg);

	// Put data in the pipe so the guarded recv can complete immediately.
	ior_sqe *w = ior_get_sqe(s->ctx);
	assert_non_null(w);
	ior_prep_send(s->ctx, w, s->sock[0], msg, len, 0);
	ior_sqe_set_data(s->ctx, w, (void *) 0x9);
	int ret = ior_submit_and_wait(s->ctx, 1);
	assert_true(ret >= 0);

	ior_cqe *wc = NULL;
	while ((ret = ior_wait_cqe(s->ctx, &wc)) == -EAGAIN || ret == -EINTR) {
		;
	}
	assert_return_code(ret, 0);
	assert_int_equal((uintptr_t) ior_cqe_get_data(s->ctx, wc), 0x9);
	assert_int_equal(ior_cqe_get_res(s->ctx, wc), (int32_t) len);
	ior_cqe_seen(s->ctx, wc);

	// Guarded recv with a generous timeout - the data is already there.
	char buf[64];
	memset(buf, 0, sizeof(buf));

	ior_sqe *r = ior_get_sqe(s->ctx);
	assert_non_null(r);
	ior_prep_recv(s->ctx, r, s->sock[1], buf, sizeof(buf), 0);
	ior_sqe_set_data(s->ctx, r, TAG_OP);
	ior_sqe_set_flags(s->ctx, r, IOR_SQE_IO_LINK);

	ior_sqe *t = ior_get_sqe(s->ctx);
	assert_non_null(t);
	ior_timespec ts = { .tv_sec = 5, .tv_nsec = 0 };
	ior_prep_link_timeout(s->ctx, t, &ts, 0);
	ior_sqe_set_data(s->ctx, t, TAG_TMO);

	ret = ior_submit_and_wait(s->ctx, 2);
	assert_true(ret >= 0);

	int32_t res_op = 0, res_tmo = 0;
	reap_pair(s->ctx, &res_op, &res_tmo);

	assert_int_equal(res_op, (int32_t) len);
	assert_int_equal(res_tmo, -ECANCELED);
}

/*
 * Timer wins with an absolute deadline (IOR_TIMEOUT_ABS): same outcome as the
 * relative case, exercising the abs path of the link timeout.
 */
static void test_link_timeout_fires_abs(void **state)
{
	lt_state *s = (lt_state *) *state;
	char buf[64];
	memset(buf, 0, sizeof(buf));

	ior_sqe *r = ior_get_sqe(s->ctx);
	assert_non_null(r);
	ior_prep_recv(s->ctx, r, s->sock[1], buf, sizeof(buf), 0);
	ior_sqe_set_data(s->ctx, r, TAG_OP);
	ior_sqe_set_flags(s->ctx, r, IOR_SQE_IO_LINK);

	uint64_t deadline = test_monotonic_now_ns() + 50000000ULL; // now + 50ms
	ior_timespec abs = {
		.tv_sec = (int64_t) (deadline / 1000000000ULL),
		.tv_nsec = (long long) (deadline % 1000000000ULL),
	};

	ior_sqe *t = ior_get_sqe(s->ctx);
	assert_non_null(t);
	ior_prep_link_timeout(s->ctx, t, &abs, IOR_TIMEOUT_ABS);
	ior_sqe_set_data(s->ctx, t, TAG_TMO);

	int ret = ior_submit_and_wait(s->ctx, 2);
	assert_true(ret >= 0);

	int32_t res_op = 0, res_tmo = 0;
	reap_pair(s->ctx, &res_op, &res_tmo);

	assert_int_equal(res_op, -ECANCELED);
	assert_true(res_tmo == -ETIME || res_tmo == -ETIMEDOUT);
}

/*
 * Concurrency stress: many guarded recvs, each with its own link timeout, in
 * flight at once over many rounds. Data is pre-loaded so every guarded op wins
 * and every link timeout resolves as -ECANCELED. On the threads backend each
 * linked pair is drained by a worker that must bind the link-timeout slot to
 * itself; if that binding races, the link timeout is completed twice (a
 * duplicate CQE) or its SQ slot leaks (a missing CQE / wedged ring). Both show
 * up here as a per-tag exactly-once violation, caught quickly via bounded waits.
 */
#define LT_CONC_PAIRS 64
#define LT_CONC_ROUNDS 200
#define LT_CONC_MSG 8

typedef struct lt_conc_state {
	ior_ctx *ctx;
	ior_fd_t sock[LT_CONC_PAIRS][2];
	char rbuf[LT_CONC_PAIRS][LT_CONC_MSG];
} lt_conc_state;

// user_data tag: connection index in the high bits, op kind (0=op, 1=tmo) low.
static void *lt_tag(uint32_t i, unsigned kind)
{
	return (void *) (((uintptr_t) i << 1) | (kind & 1u));
}

static int setup_lt_conc(void **state)
{
	lt_conc_state *s = calloc(1, sizeof(*s));
	assert_non_null(s);

	// Room for every pair's recv + link timeout in flight simultaneously.
	int ret = ior_queue_init(2 * LT_CONC_PAIRS + 64, &s->ctx);
	assert_return_code(ret, 0);
	assert_non_null(s->ctx);

	for (uint32_t i = 0; i < LT_CONC_PAIRS; i++) {
		ret = test_make_socketpair(s->sock[i]);
		assert_return_code(ret, 0);
	}

	*state = s;
	return 0;
}

static int teardown_lt_conc(void **state)
{
	lt_conc_state *s = (lt_conc_state *) *state;
	if (s) {
		for (uint32_t i = 0; i < LT_CONC_PAIRS; i++) {
			if (test_fd_is_valid(s->sock[i][0])) {
				test_close_fd(s->sock[i][0]);
			}
			if (test_fd_is_valid(s->sock[i][1])) {
				test_close_fd(s->sock[i][1]);
			}
		}
		if (s->ctx) {
			ior_queue_exit(s->ctx);
		}
		free(s);
	}
	return 0;
}

/*
 * Reap exactly `n` completions, invoking on_cqe for each. Fails if one does not
 * arrive within a bounded wait, which means a completion was lost (a leaked or
 * wedged SQ slot) rather than hanging until the overall test timeout.
 */
static void reap_exactly(ior_ctx *ctx, int n, void (*on_cqe)(ior_ctx *, ior_cqe *))
{
	int got = 0;
	while (got < n) {
		ior_cqe *cqe = NULL;
		ior_timespec to = { .tv_sec = 3, .tv_nsec = 0 };
		int ret = ior_wait_cqe_timeout(ctx, &cqe, &to);
		if (ret == -EAGAIN || ret == -EINTR) {
			continue;
		}
		if (ret == -ETIME) {
			fail_msg("missing completion after %d/%d (leaked/wedged SQ slot)", got, n);
		}
		assert_return_code(ret, 0);
		assert_non_null(cqe);
		on_cqe(ctx, cqe);
		ior_cqe_seen(ctx, cqe);
		got++;
	}
}

// Per-round bookkeeping for the linked phase, shared with the reap callback.
static char g_seen_op[LT_CONC_PAIRS];
static char g_seen_tmo[LT_CONC_PAIRS];

static void lt_conc_on_send(ior_ctx *ctx, ior_cqe *cqe)
{
	assert_int_equal(ior_cqe_get_res(ctx, cqe), LT_CONC_MSG);
}

static void lt_conc_on_linked(ior_ctx *ctx, ior_cqe *cqe)
{
	uintptr_t tag = (uintptr_t) ior_cqe_get_data(ctx, cqe);
	uint32_t i = (uint32_t) (tag >> 1);
	unsigned kind = (unsigned) (tag & 1u);
	int32_t res = ior_cqe_get_res(ctx, cqe);

	assert_true(i < LT_CONC_PAIRS);
	if (kind == 0) {
		// exactly-once: a duplicate guarded op would find the flag already set
		assert_int_equal(g_seen_op[i], 0);
		g_seen_op[i] = 1;
		assert_int_equal(res, LT_CONC_MSG);
	} else {
		// exactly-once: a duplicate link timeout would find the flag already set
		assert_int_equal(g_seen_tmo[i], 0);
		g_seen_tmo[i] = 1;
		// the guarded op won, so the timeout resolves as cancelled
		assert_int_equal(res, -ECANCELED);
	}
}

static void test_link_timeout_concurrency(void **state)
{
	lt_conc_state *s = (lt_conc_state *) *state;
	const char msg[LT_CONC_MSG] = "linkstr";
	// Stable storage: the backend keeps the timespec pointer until the op runs.
	ior_timespec ts = { .tv_sec = 5, .tv_nsec = 0 };

	for (int r = 0; r < LT_CONC_ROUNDS; r++) {
		// Pre-load data so every guarded recv can complete immediately.
		for (uint32_t i = 0; i < LT_CONC_PAIRS; i++) {
			ior_sqe *w = ior_get_sqe(s->ctx);
			assert_non_null(w);
			ior_prep_send(s->ctx, w, s->sock[i][0], msg, LT_CONC_MSG, 0);
			ior_sqe_set_data(s->ctx, w, lt_tag(i, 0));
		}
		assert_true(ior_submit(s->ctx) >= 0);
		reap_exactly(s->ctx, LT_CONC_PAIRS, lt_conc_on_send);

		// Each guarded recv carries its own link timeout (generous deadline).
		memset(g_seen_op, 0, sizeof(g_seen_op));
		memset(g_seen_tmo, 0, sizeof(g_seen_tmo));
		for (uint32_t i = 0; i < LT_CONC_PAIRS; i++) {
			ior_sqe *rcv = ior_get_sqe(s->ctx);
			assert_non_null(rcv);
			ior_prep_recv(s->ctx, rcv, s->sock[i][1], s->rbuf[i], LT_CONC_MSG, 0);
			ior_sqe_set_data(s->ctx, rcv, lt_tag(i, 0));
			ior_sqe_set_flags(s->ctx, rcv, IOR_SQE_IO_LINK);

			ior_sqe *tmo = ior_get_sqe(s->ctx);
			assert_non_null(tmo);
			ior_prep_link_timeout(s->ctx, tmo, &ts, 0);
			ior_sqe_set_data(s->ctx, tmo, lt_tag(i, 1));
		}
		assert_true(ior_submit(s->ctx) >= 0);
		reap_exactly(s->ctx, 2 * LT_CONC_PAIRS, lt_conc_on_linked);

		// Neither the guarded op nor its link timeout may be lost.
		for (uint32_t i = 0; i < LT_CONC_PAIRS; i++) {
			assert_int_equal(g_seen_op[i], 1);
			assert_int_equal(g_seen_tmo[i], 1);
		}
	}
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_link_timeout_fires, setup_lt, teardown_lt),
		cmocka_unit_test_setup_teardown(test_link_timeout_op_first, setup_lt, teardown_lt),
		cmocka_unit_test_setup_teardown(test_link_timeout_fires_abs, setup_lt, teardown_lt),
		cmocka_unit_test_setup_teardown(
				test_link_timeout_concurrency, setup_lt_conc, teardown_lt_conc),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
