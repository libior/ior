/* SPDX-License-Identifier: BSD-3-Clause */
#include "test_utils.h"
#include <stdatomic.h>

#define TAG_OP ((void *) 0x1) // the (guarded) work op
#define TAG_TMO ((void *) 0x2) // the link timeout

// Portable short sleep for callbacks that need to outlast a deadline.
static void work_msleep(unsigned ms)
{
#ifdef _WIN32
	Sleep(ms);
#else
	struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (long) (ms % 1000) * 1000000L };
	nanosleep(&ts, NULL);
#endif
}

typedef struct work_state {
	ior_ctx *ctx;
} work_state;

static int setup_work(void **state)
{
	work_state *s = calloc(1, sizeof(*s));
	assert_non_null(s);

	int ret = ior_queue_init(32, &s->ctx);
	assert_return_code(ret, 0);
	assert_non_null(s->ctx);

	*state = s;
	return 0;
}

static int teardown_work(void **state)
{
	work_state *s = (work_state *) *state;
	if (s) {
		if (s->ctx) {
			ior_queue_exit(s->ctx);
		}
		free(s);
	}
	return 0;
}

// Skip the test (returning 1) when the backend lacks IOR_FEAT_WORK.
static int work_supported(ior_ctx *ctx)
{
	if (ior_get_features(ctx) & IOR_FEAT_WORK) {
		return 1;
	}
	print_message("IOR_FEAT_WORK not supported by backend %s - skipping\n",
			ior_get_backend_name(ctx));
	return 0;
}

// Reap exactly the work-op and link-timeout completions, by tag.
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

// ===== Basic execution =====

typedef struct basic_arg {
	_Atomic int ran;
	int value;
} basic_arg;

static int32_t work_basic_fn(ior_work_token *token, void *arg)
{
	(void) token;
	basic_arg *a = arg;
	a->value = 1234;
	atomic_fetch_add(&a->ran, 1);
	return 42;
}

/*
 * A submitted work op runs its callback exactly once with the given argument
 * and its return value becomes the CQE result; user_data flows independently.
 */
static void test_work_basic(void **state)
{
	work_state *s = (work_state *) *state;
	if (!work_supported(s->ctx)) {
		return;
	}

	basic_arg arg;
	atomic_init(&arg.ran, 0);
	arg.value = 0;

	ior_sqe *sqe = ior_get_sqe(s->ctx);
	assert_non_null(sqe);
	assert_return_code(ior_prep_work(s->ctx, sqe, work_basic_fn, &arg), 0);
	ior_sqe_set_data(s->ctx, sqe, TAG_OP);

	int ret = ior_submit_and_wait(s->ctx, 1);
	assert_true(ret >= 0);

	ior_cqe *cqe = NULL;
	while ((ret = ior_wait_cqe(s->ctx, &cqe)) == -EAGAIN || ret == -EINTR) {
		;
	}
	assert_return_code(ret, 0);
	assert_non_null(cqe);
	assert_ptr_equal(ior_cqe_get_data(s->ctx, cqe), TAG_OP);
	assert_int_equal(ior_cqe_get_res(s->ctx, cqe), 42);
	ior_cqe_seen(s->ctx, cqe);

	assert_int_equal(atomic_load(&arg.ran), 1);
	assert_int_equal(arg.value, 1234);
}

// Negative return values surface as the CQE result unchanged.
static int32_t work_fail_fn(ior_work_token *token, void *arg)
{
	(void) token;
	(void) arg;
	return -EIO;
}

static void test_work_error_result(void **state)
{
	work_state *s = (work_state *) *state;
	if (!work_supported(s->ctx)) {
		return;
	}

	ior_sqe *sqe = ior_get_sqe(s->ctx);
	assert_non_null(sqe);
	assert_return_code(ior_prep_work(s->ctx, sqe, work_fail_fn, NULL), 0);
	ior_sqe_set_data(s->ctx, sqe, TAG_OP);

	int ret = ior_submit_and_wait(s->ctx, 1);
	assert_true(ret >= 0);

	ior_cqe *cqe = NULL;
	while ((ret = ior_wait_cqe(s->ctx, &cqe)) == -EAGAIN || ret == -EINTR) {
		;
	}
	assert_return_code(ret, 0);
	assert_int_equal(ior_cqe_get_res(s->ctx, cqe), -EIO);
	ior_cqe_seen(s->ctx, cqe);
}

// Bad arguments are rejected at prep time.
static void test_work_invalid_args(void **state)
{
	work_state *s = (work_state *) *state;

	ior_sqe *sqe = ior_get_sqe(s->ctx);
	assert_non_null(sqe);
	assert_int_equal(ior_prep_work(s->ctx, sqe, NULL, NULL), -EINVAL);
	assert_int_equal(ior_prep_work(NULL, sqe, work_basic_fn, NULL), -EINVAL);

	// Leave the reserved SQE as a harmless no-op so the queue stays consistent.
	ior_prep_nop(s->ctx, sqe);
	assert_true(ior_submit_and_wait(s->ctx, 1) >= 0);
	ior_cqe *cqe = NULL;
	int ret;
	while ((ret = ior_wait_cqe(s->ctx, &cqe)) == -EAGAIN || ret == -EINTR) {
		;
	}
	assert_return_code(ret, 0);
	ior_cqe_seen(s->ctx, cqe);
}

// ===== Many concurrent callbacks =====

#define WORK_MANY_N 64

typedef struct many_arg {
	_Atomic int *counter;
	int idx;
} many_arg;

static int32_t work_many_fn(ior_work_token *token, void *arg)
{
	(void) token;
	many_arg *a = arg;
	atomic_fetch_add(a->counter, 1);
	return a->idx + 1; // distinct positive result per op
}

/*
 * Many work ops in flight at once: every callback runs exactly once and every
 * op completes with its own result.
 */
static void test_work_many(void **state)
{
	work_state *s = (work_state *) *state;
	if (!work_supported(s->ctx)) {
		return;
	}

	ior_ctx *ctx = NULL;
	int ret = ior_queue_init(2 * WORK_MANY_N, &ctx);
	assert_return_code(ret, 0);

	_Atomic int counter;
	atomic_init(&counter, 0);
	many_arg args[WORK_MANY_N];
	char seen[WORK_MANY_N];
	memset(seen, 0, sizeof(seen));

	for (int i = 0; i < WORK_MANY_N; i++) {
		args[i].counter = &counter;
		args[i].idx = i;
		ior_sqe *sqe = ior_get_sqe(ctx);
		assert_non_null(sqe);
		assert_return_code(ior_prep_work(ctx, sqe, work_many_fn, &args[i]), 0);
		ior_sqe_set_data(ctx, sqe, (void *) (uintptr_t) (i + 1));
	}

	ret = ior_submit(ctx);
	assert_int_equal(ret, WORK_MANY_N);

	for (int got = 0; got < WORK_MANY_N; got++) {
		ior_cqe *cqe = NULL;
		ior_timespec to = { .tv_sec = 5, .tv_nsec = 0 };
		ret = ior_wait_cqe_timeout(ctx, &cqe, &to);
		if (ret == -EAGAIN || ret == -EINTR) {
			got--;
			continue;
		}
		if (ret == -ETIME) {
			fail_msg("missing work completion after %d/%d", got, WORK_MANY_N);
		}
		assert_return_code(ret, 0);

		uintptr_t tag = (uintptr_t) ior_cqe_get_data(ctx, cqe);
		int32_t res = ior_cqe_get_res(ctx, cqe);
		assert_true(tag >= 1 && tag <= WORK_MANY_N);
		assert_int_equal(seen[tag - 1], 0); // exactly-once per op
		seen[tag - 1] = 1;
		assert_int_equal(res, (int32_t) tag); // result matches the op
		ior_cqe_seen(ctx, cqe);
	}

	assert_int_equal(atomic_load(&counter), WORK_MANY_N);
	ior_queue_exit(ctx);
}

// ===== Link timeout =====

static int32_t work_quick_fn(ior_work_token *token, void *arg)
{
	(void) token;
	(void) arg;
	return 7;
}

/*
 * Callback finishes before the deadline: the work op reports its return value
 * and the link timeout resolves as -ECANCELED, matching io_uring.
 */
static void test_work_lt_op_first(void **state)
{
	work_state *s = (work_state *) *state;
	if (!work_supported(s->ctx)) {
		return;
	}

	ior_sqe *w = ior_get_sqe(s->ctx);
	assert_non_null(w);
	assert_return_code(ior_prep_work(s->ctx, w, work_quick_fn, NULL), 0);
	ior_sqe_set_data(s->ctx, w, TAG_OP);
	ior_sqe_set_flags(s->ctx, w, IOR_SQE_IO_LINK);

	ior_sqe *t = ior_get_sqe(s->ctx);
	assert_non_null(t);
	ior_timespec ts = { .tv_sec = 5, .tv_nsec = 0 };
	ior_prep_link_timeout(s->ctx, t, &ts, 0);
	ior_sqe_set_data(s->ctx, t, TAG_TMO);

	int ret = ior_submit_and_wait(s->ctx, 2);
	assert_true(ret >= 0);

	int32_t res_op = 0, res_tmo = 0;
	reap_pair(s->ctx, &res_op, &res_tmo);

	assert_int_equal(res_op, 7);
	assert_int_equal(res_tmo, -ECANCELED);
}

/*
 * A callback that cooperates with cancellation: works "forever" but polls its
 * token and bails out once the link timeout fires. Fails the test via the
 * result (99) if cancellation is never observed within ~5s.
 */
static int32_t work_cancellable_fn(ior_work_token *token, void *arg)
{
	(void) arg;
	for (int i = 0; i < 500; i++) {
		if (ior_work_cancelled(token)) {
			return -ECANCELED;
		}
		work_msleep(10);
	}
	return 99;
}

/*
 * Deadline fires while the callback runs: the callback cannot be killed, but
 * the token is flagged so it can return early; the link timeout reports -ETIME
 * and the work op reports whatever the callback returned after bailing out.
 */
static void test_work_lt_fires_while_running(void **state)
{
	work_state *s = (work_state *) *state;
	if (!work_supported(s->ctx)) {
		return;
	}

	ior_sqe *w = ior_get_sqe(s->ctx);
	assert_non_null(w);
	assert_return_code(ior_prep_work(s->ctx, w, work_cancellable_fn, NULL), 0);
	ior_sqe_set_data(s->ctx, w, TAG_OP);
	ior_sqe_set_flags(s->ctx, w, IOR_SQE_IO_LINK);

	ior_sqe *t = ior_get_sqe(s->ctx);
	assert_non_null(t);
	ior_timespec ts = { .tv_sec = 0, .tv_nsec = 50000000 }; // 50ms
	ior_prep_link_timeout(s->ctx, t, &ts, 0);
	ior_sqe_set_data(s->ctx, t, TAG_TMO);

	int ret = ior_submit_and_wait(s->ctx, 2);
	assert_true(ret >= 0);

	int32_t res_op = 0, res_tmo = 0;
	reap_pair(s->ctx, &res_op, &res_tmo);

	assert_int_equal(res_op, -ECANCELED); // callback observed the token
	assert_true(res_tmo == -ETIME || res_tmo == -ETIMEDOUT);
}

// ===== Cancel-before-start (io_uring backend) =====

#define WORK_SAT_N 32 // matches the backend's worker-pool cap

static int32_t work_block_fn(ior_work_token *token, void *arg)
{
	(void) token;
	(void) arg;
	work_msleep(500);
	return 0;
}

static int32_t work_never_fn(ior_work_token *token, void *arg)
{
	(void) token;
	atomic_fetch_add((_Atomic int *) arg, 1);
	return 0;
}

/*
 * A link timeout that fires while the work op is still queued behind a
 * saturated pool kills it: the callback never runs and the op completes with
 * -ECANCELED (io_uring arms linked timeouts at submit, so queue-wait counts
 * against the deadline). Backend-specific: the threads backend arms the
 * deadline only when a worker claims the pair, so the row does not occur there.
 */
static void test_work_lt_cancels_queued(void **state)
{
	work_state *s = (work_state *) *state;
	if (!work_supported(s->ctx)) {
		return;
	}
	if (ior_get_backend_type(s->ctx) != IOR_BACKEND_IOURING) {
		print_message("queued-cancel semantics are io_uring-specific - skipping\n");
		return;
	}

	ior_ctx *ctx = NULL;
	int ret = ior_queue_init(2 * WORK_SAT_N + 8, &ctx);
	assert_return_code(ret, 0);

	// Occupy every worker so the guarded job cannot start before the deadline.
	for (int i = 0; i < WORK_SAT_N; i++) {
		ior_sqe *sqe = ior_get_sqe(ctx);
		assert_non_null(sqe);
		assert_return_code(ior_prep_work(ctx, sqe, work_block_fn, NULL), 0);
		ior_sqe_set_data(ctx, sqe, (void *) 0x9);
	}

	_Atomic int ran;
	atomic_init(&ran, 0);

	ior_sqe *w = ior_get_sqe(ctx);
	assert_non_null(w);
	assert_return_code(ior_prep_work(ctx, w, work_never_fn, &ran), 0);
	ior_sqe_set_data(ctx, w, TAG_OP);
	ior_sqe_set_flags(ctx, w, IOR_SQE_IO_LINK);

	ior_sqe *t = ior_get_sqe(ctx);
	assert_non_null(t);
	ior_timespec ts = { .tv_sec = 0, .tv_nsec = 100000000 }; // 100ms
	ior_prep_link_timeout(ctx, t, &ts, 0);
	ior_sqe_set_data(ctx, t, TAG_TMO);

	ret = ior_submit(ctx);
	assert_int_equal(ret, WORK_SAT_N + 2);

	int32_t res_op = 0, res_tmo = 0;
	reap_pair(ctx, &res_op, &res_tmo);

	assert_int_equal(res_op, -ECANCELED);
	assert_true(res_tmo == -ETIME || res_tmo == -ETIMEDOUT);
	assert_int_equal(atomic_load(&ran), 0); // the callback never started

	// Teardown drains the blockers; the cancelled callback must still never run.
	ior_queue_exit(ctx);
	assert_int_equal(atomic_load(&ran), 0);
}

// ===== Teardown semantics =====

#define WORK_EXIT_N 16

static int32_t work_slow_count_fn(ior_work_token *token, void *arg)
{
	(void) token;
	work_msleep(5);
	atomic_fetch_add((_Atomic int *) arg, 1);
	return 0;
}

/*
 * ior_queue_exit() waits for already-submitted callbacks: every one of them
 * must have run by the time exit returns, even though none were reaped.
 */
static void test_work_queue_exit_runs_all(void **state)
{
	(void) state;

	ior_ctx *ctx = NULL;
	int ret = ior_queue_init(2 * WORK_EXIT_N, &ctx);
	assert_return_code(ret, 0);

	if (!work_supported(ctx)) {
		ior_queue_exit(ctx);
		return;
	}

	_Atomic int counter;
	atomic_init(&counter, 0);

	for (int i = 0; i < WORK_EXIT_N; i++) {
		ior_sqe *sqe = ior_get_sqe(ctx);
		assert_non_null(sqe);
		assert_return_code(ior_prep_work(ctx, sqe, work_slow_count_fn, &counter), 0);
	}
	assert_int_equal(ior_submit(ctx), WORK_EXIT_N);

	// Exit without reaping anything: it must wait for all callbacks.
	ior_queue_exit(ctx);

	assert_int_equal(atomic_load(&counter), WORK_EXIT_N);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_work_basic, setup_work, teardown_work),
		cmocka_unit_test_setup_teardown(test_work_error_result, setup_work, teardown_work),
		cmocka_unit_test_setup_teardown(test_work_invalid_args, setup_work, teardown_work),
		cmocka_unit_test_setup_teardown(test_work_many, setup_work, teardown_work),
		cmocka_unit_test_setup_teardown(test_work_lt_op_first, setup_work, teardown_work),
		cmocka_unit_test_setup_teardown(test_work_lt_fires_while_running, setup_work, teardown_work),
		cmocka_unit_test_setup_teardown(test_work_lt_cancels_queued, setup_work, teardown_work),
		cmocka_unit_test(test_work_queue_exit_runs_all),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
