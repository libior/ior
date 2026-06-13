/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * test_concurrency.c - Completion-queue integrity under heavy fan-out.
 *
 * These tests submit large batches so that, on the threads backend, many
 * worker threads (and the timer thread) post completions concurrently. The
 * completion queue is multi-producer / single-consumer: if the producer side
 * is not serialized, two producers can claim the same CQ slot and a completion
 * is lost or duplicated.
 *
 * Each test reaps every completion and checks exactly-once delivery via a
 * per-round "seen" array keyed on the SQE's user_data tag. A lost completion
 * shows up as a missing tag (and a count mismatch); a duplicated completion
 * shows up as a tag seen twice. The tests use only the public API, so they are
 * valid on every backend, but they are primarily a regression guard for the
 * threads backend's MPSC completion path. They are best run under
 * ThreadSanitizer in CI.
 */
#include "test_utils.h"

/* Kept modest so the suite stays fast even under TSan, but large enough that
 * many completions are produced concurrently on the threads backend. */
#define FANOUT 256
#define ROUNDS 50

/* Tag bit distinguishing timer completions from nop completions. FANOUT is far
 * below this, so the low bits remain a clean per-round index. */
#define TIMER_TAG_BIT (1u << 30)

/*
 * Submit `n` NOPs tagged 0..n-1, reap exactly n completions, and assert each
 * tag is seen exactly once with res == 0. Repeated over many rounds.
 */
static void test_concurrency_nop_fanout(void **state)
{
	test_state *ts = (test_state *) *state;

	for (int r = 0; r < ROUNDS; r++) {
		char seen[FANOUT];
		memset(seen, 0, sizeof(seen));

		int submitted = 0;
		for (int i = 0; i < FANOUT; i++) {
			ior_sqe *sqe = ior_get_sqe(ts->ctx);
			assert_non_null(sqe);
			ior_prep_nop(ts->ctx, sqe);
			ior_sqe_set_data(ts->ctx, sqe, (void *) (uintptr_t) i);
			submitted++;
		}

		int ret = ior_submit(ts->ctx);
		assert_true(ret >= 0);

		int got = 0;
		while (got < submitted) {
			ior_cqe *cqe = NULL;
			ret = ior_wait_cqe(ts->ctx, &cqe);
			/* The threads backend may report a spurious wakeup; just retry.
			 * A genuinely lost completion would instead spin here until the
			 * CI test timeout fires - which is the intended failure signal. */
			if (ret == -EAGAIN || ret == -EINTR) {
				continue;
			}
			assert_return_code(ret, 0);
			assert_non_null(cqe);

			uintptr_t tag = (uintptr_t) ior_cqe_get_data(ts->ctx, cqe);
			assert_true(tag < (uintptr_t) FANOUT);
			assert_int_equal(seen[tag], 0); /* no duplicate completion */
			seen[tag] = 1;

			assert_int_equal(ior_cqe_get_res(ts->ctx, cqe), 0);
			ior_cqe_seen(ts->ctx, cqe);
			got++;
		}

		for (int i = 0; i < FANOUT; i++) {
			assert_int_equal(seen[i], 1); /* no lost completion */
		}
	}
}

/*
 * Same fan-out, but each round also submits a few short timeouts so the timer
 * thread posts completions concurrently with the worker threads. Verifies all
 * complete exactly once: NOPs with res == 0, timers with res == -ETIME.
 */
static void test_concurrency_fanout_with_timers(void **state)
{
	test_state *ts = (test_state *) *state;

	const int n_timers = FANOUT;
	/* Zero timeout: each timer fires immediately, so the timer thread is busy
	 * posting completions over the same window the workers post the NOPs. */
	ior_timespec t = { .tv_sec = 0, .tv_nsec = 0 };

	for (int r = 0; r < ROUNDS; r++) {
		char seen_nop[FANOUT];
		char seen_timer[FANOUT];
		memset(seen_nop, 0, sizeof(seen_nop));
		memset(seen_timer, 0, sizeof(seen_timer));

		/* Interleave NOPs and timers so worker threads and the timer thread
		 * produce completions concurrently rather than in separate phases. */
		for (int i = 0; i < FANOUT; i++) {
			ior_sqe *nop = ior_get_sqe(ts->ctx);
			assert_non_null(nop);
			ior_prep_nop(ts->ctx, nop);
			ior_sqe_set_data(ts->ctx, nop, (void *) (uintptr_t) i);

			ior_sqe *tmr = ior_get_sqe(ts->ctx);
			assert_non_null(tmr);
			ior_prep_timeout(ts->ctx, tmr, &t, 0, 0);
			ior_sqe_set_data(ts->ctx, tmr, (void *) (uintptr_t) (TIMER_TAG_BIT | (unsigned) i));
		}

		int submitted = FANOUT + n_timers;
		int ret = ior_submit(ts->ctx);
		assert_true(ret >= 0);

		int got = 0;
		while (got < submitted) {
			ior_cqe *cqe = NULL;
			ret = ior_wait_cqe(ts->ctx, &cqe);
			if (ret == -EAGAIN || ret == -EINTR) {
				continue;
			}
			assert_return_code(ret, 0);
			assert_non_null(cqe);

			uintptr_t tag = (uintptr_t) ior_cqe_get_data(ts->ctx, cqe);
			int32_t res = ior_cqe_get_res(ts->ctx, cqe);

			if (tag & TIMER_TAG_BIT) {
				unsigned j = (unsigned) (tag & ~((uintptr_t) TIMER_TAG_BIT));
				assert_true(j < (unsigned) n_timers);
				assert_int_equal(seen_timer[j], 0);
				seen_timer[j] = 1;
				assert_true(res == -ETIME || res == -ETIMEDOUT);
			} else {
				assert_true(tag < (uintptr_t) FANOUT);
				assert_int_equal(seen_nop[tag], 0);
				seen_nop[tag] = 1;
				assert_int_equal(res, 0);
			}
			ior_cqe_seen(ts->ctx, cqe);
			got++;
		}

		for (int i = 0; i < FANOUT; i++) {
			assert_int_equal(seen_nop[i], 1);
		}
		for (int j = 0; j < n_timers; j++) {
			assert_int_equal(seen_timer[j], 1);
		}
	}
}

static int setup_concurrency_ctx(void **state)
{
	test_state *ts = calloc(1, sizeof(*ts));
	assert_non_null(ts);

	/* Room for the full per-round fan-out plus the timers, in flight at once. */
	int ret = ior_queue_init(1024, &ts->ctx);
	assert_return_code(ret, 0);
	assert_non_null(ts->ctx);

	*state = ts;
	return 0;
}

static int teardown_concurrency_ctx(void **state)
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

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(
				test_concurrency_nop_fanout, setup_concurrency_ctx, teardown_concurrency_ctx),
		cmocka_unit_test_setup_teardown(test_concurrency_fanout_with_timers, setup_concurrency_ctx,
				teardown_concurrency_ctx),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
