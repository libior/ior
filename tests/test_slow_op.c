/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * test_slow_op.c - a slow or blocking in-flight operation must not stall other
 * operations.
 *
 * On the thread-pool backend a blocking op (a recv on a socket with no data)
 * occupies its worker thread until it completes. Newer operations must still get
 * a worker and run; if worker provisioning only reacts to an "idle" count, a
 * worker that has just claimed an earlier blocking op - but is not yet marked
 * busy - is mistaken for spare capacity, and the newer op never runs. Here we
 * hold several blocking recvs in flight and require a stream of nops behind them
 * to all complete. The queue is sized large so this exercises worker
 * availability, not submission-queue slot reuse.
 */
#include "test_utils.h"

#define BLOCKERS 8
#define NOPS 32
#define SQ_DEPTH 256

#define TAG_RECV ((void *) 0x1)
#define TAG_NOP ((void *) 0x2)
#define TAG_SEND ((void *) 0x3)

typedef struct slow_state {
	ior_ctx *ctx;
	ior_fd_t sock[BLOCKERS][2];
	char rbuf[BLOCKERS][16];
} slow_state;

static int setup_slow(void **state)
{
	slow_state *s = calloc(1, sizeof(*s));
	assert_non_null(s);

	int ret = ior_queue_init(SQ_DEPTH, &s->ctx);
	assert_return_code(ret, 0);
	assert_non_null(s->ctx);

	for (int i = 0; i < BLOCKERS; i++) {
		ret = test_make_socketpair(s->sock[i]);
		assert_return_code(ret, 0);
	}

	*state = s;
	return 0;
}

static int teardown_slow(void **state)
{
	slow_state *s = (slow_state *) *state;
	if (s) {
		for (int i = 0; i < BLOCKERS; i++) {
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
 * Wait for one completion with a bound, returning its tag. Fails the test on
 * timeout so a starved operation surfaces here rather than hanging until the
 * overall test timeout.
 */
static uintptr_t wait_one(ior_ctx *ctx)
{
	for (;;) {
		ior_cqe *cqe = NULL;
		ior_timespec to = { .tv_sec = 3, .tv_nsec = 0 };
		int ret = ior_wait_cqe_timeout(ctx, &cqe, &to);
		if (ret == -EAGAIN || ret == -EINTR) {
			continue;
		}
		if (ret == -ETIME) {
			fail_msg("operation starved: no completion within timeout");
		}
		assert_return_code(ret, 0);
		assert_non_null(cqe);
		uintptr_t tag = (uintptr_t) ior_cqe_get_data(ctx, cqe);
		ior_cqe_seen(ctx, cqe);
		return tag;
	}
}

static void test_blocking_ops_do_not_starve(void **state)
{
	slow_state *s = (slow_state *) *state;

	// Several recvs that never receive data: each holds a worker thread.
	for (int i = 0; i < BLOCKERS; i++) {
		ior_sqe *r = ior_get_sqe(s->ctx);
		assert_non_null(r);
		ior_prep_recv(s->ctx, r, s->sock[i][1], s->rbuf[i], sizeof(s->rbuf[i]), 0);
		ior_sqe_set_data(s->ctx, r, TAG_RECV);
	}
	assert_true(ior_submit(s->ctx) >= 0);

	// Nops submitted behind the blockers must each get a worker and complete.
	for (int k = 0; k < NOPS; k++) {
		ior_sqe *n = ior_get_sqe(s->ctx);
		assert_non_null(n);
		ior_prep_nop(s->ctx, n);
		ior_sqe_set_data(s->ctx, n, TAG_NOP);
		assert_true(ior_submit(s->ctx) >= 0);

		assert_int_equal(wait_one(s->ctx), (uintptr_t) TAG_NOP);
	}

	// Unblock every recv so teardown does not hang on a worker stuck in recv().
	for (int i = 0; i < BLOCKERS; i++) {
		ior_sqe *w = ior_get_sqe(s->ctx);
		assert_non_null(w);
		ior_prep_send(s->ctx, w, s->sock[i][0], "x", 1, 0);
		ior_sqe_set_data(s->ctx, w, TAG_SEND);
	}
	assert_true(ior_submit(s->ctx) >= 0);

	// Reap the sends and the now-satisfied recvs (2 per pair).
	for (int i = 0; i < 2 * BLOCKERS; i++) {
		uintptr_t tag = wait_one(s->ctx);
		assert_true(tag == (uintptr_t) TAG_SEND || tag == (uintptr_t) TAG_RECV);
	}
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_blocking_ops_do_not_starve, setup_slow, teardown_slow),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
