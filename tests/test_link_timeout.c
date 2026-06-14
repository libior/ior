/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * test_link_timeout.c - Linked-timeout (watchdog) semantics, identical across
 * backends.
 *
 * A guarded operation is submitted with IOR_SQE_IO_LINK, immediately followed by
 * a link timeout (ior_prep_link_timeout). Both entries always produce a CQE:
 *   - timer fires first  -> guarded op res == -ECANCELED, link timeout == -ETIME
 *   - guarded op first    -> guarded op its normal result, link timeout == -ECANCELED
 *
 * These run over a connected stream socket pair (test_make_socketpair), the
 * target use case being "recv with a timeout".
 */
#include "test_utils.h"

#define TAG_OP ((void *) 0x1) /* the guarded recv */
#define TAG_TMO ((void *) 0x2) /* the link timeout */

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

/* Reap exactly the guarded-op and link-timeout completions, by tag. */
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

/* Timer wins: nothing is sent, so the recv is cancelled at the deadline. */
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
	ior_timespec ts = { .tv_sec = 0, .tv_nsec = 50000000 }; /* 50ms */
	ior_prep_link_timeout(s->ctx, t, &ts, 0);
	ior_sqe_set_data(s->ctx, t, TAG_TMO);

	int ret = ior_submit_and_wait(s->ctx, 2);
	assert_true(ret >= 0);

	int32_t res_op = 0, res_tmo = 0;
	reap_pair(s->ctx, &res_op, &res_tmo);

	assert_int_equal(res_op, -ECANCELED);
	assert_true(res_tmo == -ETIME || res_tmo == -ETIMEDOUT);
}

/* Guarded op wins: data is already waiting, so the recv completes first and the
 * link timeout is cancelled. */
static void test_link_timeout_op_first(void **state)
{
	lt_state *s = (lt_state *) *state;

	const char *msg = "ready";
	unsigned len = (unsigned) strlen(msg);

	/* Put data in the pipe so the guarded recv can complete immediately. */
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

	/* Guarded recv with a generous timeout - the data is already there. */
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

/* Timer wins with an absolute deadline (IOR_TIMEOUT_ABS): same outcome as the
 * relative case, exercising the abs path of the link timeout. */
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

	uint64_t deadline = test_monotonic_now_ns() + 50000000ULL; /* now + 50ms */
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

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_link_timeout_fires, setup_lt, teardown_lt),
		cmocka_unit_test_setup_teardown(test_link_timeout_op_first, setup_lt, teardown_lt),
		cmocka_unit_test_setup_teardown(test_link_timeout_fires_abs, setup_lt, teardown_lt),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
