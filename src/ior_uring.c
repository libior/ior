/* SPDX-License-Identifier: BSD-3-Clause */
#include "config.h"

#ifdef IOR_HAVE_URING

#include "ior_backend.h"
#include "ior_worker_pool.h"
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <poll.h>
#include <liburing.h>

typedef struct ior_uring_job ior_uring_job;

/* Backend context */
typedef struct ior_ctx_uring {
	struct io_uring ring;
	uint32_t flags;
	uint32_t features;

	/*
	 * IOR_OP_WORK support. Callbacks run on a lazily created shared worker
	 * pool; completions are injected into the main ring's CQ from worker/timer
	 * threads with IORING_OP_MSG_RING submitted on a small side ring (the main
	 * ring's SQ belongs to the submitter thread and cannot be shared).
	 */
	ior_worker_pool *wp; // lazy; NULL until the first prep_work
	_Atomic int shutdown; // lets running callbacks observe teardown via token
	pthread_mutex_t poster_lock; // serializes msg_ring posters
	struct io_uring poster; // side ring, valid when wp != NULL
	ior_uring_job *pending_head; // prepped-not-dispatched jobs (submitter thread only)
	ior_uring_job *pending_tail;
} ior_ctx_uring;

/*
 * Lifecycle/arbitration state of one work op. QUEUED -> RUNNING -> DONE is the
 * worker path; a fired link timeout claims QUEUED -> CANCELLED to kill a job
 * that has not started (its callback then never runs). The refcount is held by
 * the worker (via the pool FIFO) and, when a link timeout is armed, by the
 * timer; the job is freed by whichever side finishes last.
 */
enum {
	IOR_URING_JOB_QUEUED = 0,
	IOR_URING_JOB_RUNNING = 1,
	IOR_URING_JOB_DONE = 2,
	IOR_URING_JOB_CANCELLED = 3,
};

struct ior_uring_job {
	ior_worker_pool_job pj; // pool FIFO node
	ior_uring_job *next_pending; // prep-to-submit list link
	ior_ctx_uring *ctx;
	ior_work_fn fn;
	void *arg;
	uint64_t user_data; // harvested from the kernel SQE at submit
	struct io_uring_sqe *ksqe; // the placeholder NOP; valid only until submit

	// Link timeout guarding this job (detected at submit)
	int has_lt; // a LINK_TIMEOUT sqe followed and was intercepted
	int lt_armed; // its deadline was valid and the timer is armed
	uint64_t lt_user_data;
	_Atomic int lt_fired;

	struct ior_work_token token;
	_Atomic int state;
	_Atomic int refs;
};

static void ior_uring_job_release(ior_uring_job *job)
{
	if (atomic_fetch_sub(&job->refs, 1) == 1) {
		free(job);
	}
}

/*
 * Inject a completion into the main ring's CQ via the poster ring. Runs on
 * worker/timer threads under poster_lock. The msg_ring op's own completion on
 * the poster ring is skipped on success; failures are drained and logged (the
 * target CQE is then lost, but modern kernels buffer CQ overflow, so this is
 * not expected in practice).
 */
static void ior_uring_post_cqe(ior_ctx_uring *ctx, uint64_t user_data, int32_t res)
{
	pthread_mutex_lock(&ctx->poster_lock);

	struct io_uring_sqe *s = io_uring_get_sqe(&ctx->poster);
	if (!s) {
		// Cannot happen: each poster SQE is submitted while the lock is held.
		IOR_LOG_ERROR("poster ring full");
		pthread_mutex_unlock(&ctx->poster_lock);
		return;
	}
	io_uring_prep_msg_ring(s, ctx->ring.ring_fd, (unsigned int) res, user_data, 0);
	s->flags |= IOSQE_CQE_SKIP_SUCCESS;

	int ret = io_uring_submit(&ctx->poster);
	if (ret < 0) {
		IOR_LOG_ERROR("msg_ring submit failed: %d", -errno);
	}

	struct io_uring_cqe *cqe;
	while (io_uring_peek_cqe(&ctx->poster, &cqe) == 0) {
		IOR_LOG_ERROR("msg_ring post failed: res=%d", cqe->res);
		io_uring_cqe_seen(&ctx->poster, cqe);
	}

	pthread_mutex_unlock(&ctx->poster_lock);
}

// Executes one work job on a pool worker thread.
static void ior_uring_run_job(void *owner, ior_worker_pool_job *pj)
{
	ior_ctx_uring *ctx = owner;
	ior_uring_job *job = (ior_uring_job *) ((char *) pj - offsetof(ior_uring_job, pj));

	int expected = IOR_URING_JOB_QUEUED;
	if (!atomic_compare_exchange_strong(&job->state, &expected, IOR_URING_JOB_RUNNING)) {
		// Cancelled by a fired link timeout before starting; the timer thread
		// already posted both CQEs. The callback never runs.
		ior_uring_job_release(job);
		return;
	}

	int32_t res = job->fn(&job->token, job->arg);
	atomic_store(&job->state, IOR_URING_JOB_DONE);

	ior_uring_post_cqe(ctx, job->user_data, res);
	if (job->has_lt) {
		// -ETIME if the deadline passed while the callback ran, else the
		// timeout resolves as "op finished first". A concurrent firing decides
		// this race either way, matching io_uring's inherent cancel/complete
		// race; the timer only posts when it wins the QUEUED state.
		int fired = atomic_load(&job->lt_fired);
		ior_uring_post_cqe(ctx, job->lt_user_data, fired ? -ETIME : -ECANCELED);
	}

	ior_uring_job_release(job);
}

// Timer-thread side of a link timeout on a work op.
static void ior_uring_lt_fired(void *owner, void *arg)
{
	ior_ctx_uring *ctx = owner;
	ior_uring_job *job = arg;

	atomic_store(&job->lt_fired, 1);
	atomic_store_explicit(&job->token.cancelled, 1, memory_order_release);

	int expected = IOR_URING_JOB_QUEUED;
	if (atomic_compare_exchange_strong(&job->state, &expected, IOR_URING_JOB_CANCELLED)) {
		// Job had not started: it never will. Post both completions here.
		ior_uring_post_cqe(ctx, job->user_data, -ECANCELED);
		ior_uring_post_cqe(ctx, job->lt_user_data, -ETIME);
	}

	ior_uring_job_release(job);
}

// Pool destroyed before the deadline: just drop the timer's reference.
static void ior_uring_lt_dropped(void *owner, void *arg)
{
	(void) owner;
	ior_uring_job_release(arg);
}

// One-time (per context) setup of the worker pool and the poster ring.
static int ior_uring_work_ensure(ior_ctx_uring *ctx)
{
	if (ctx->wp) {
		return 0;
	}

	if (io_uring_queue_init(8, &ctx->poster, 0) < 0) {
		return -ENOMEM;
	}

	ior_worker_pool_config cfg = {
		.min_threads = 0,
		.max_threads = 32,
		.stack_size = 0,
	};
	ctx->wp = ior_worker_pool_create(&cfg, ior_uring_run_job, ctx);
	if (!ctx->wp) {
		io_uring_queue_exit(&ctx->poster);
		return -ENOMEM;
	}

	return 0;
}

/*
 * Hand all prepped work jobs to the pool. Called from submit paths before
 * io_uring_submit() flushes the SQ, while each job's placeholder NOP is still
 * staged: the user may have attached user_data or flags after prep_work, so
 * they are harvested here, and a LINK_TIMEOUT prepped right behind a linked
 * work op is intercepted (the kernel would resolve it against the instantly
 * completing NOP) and rewritten into another skipped NOP; its deadline is
 * handled by the pool's timer thread instead.
 */
static void ior_uring_dispatch_pending(ior_ctx_uring *ctx)
{
	ior_uring_job *job = ctx->pending_head;
	if (!job) {
		return;
	}
	ctx->pending_head = NULL;
	ctx->pending_tail = NULL;

	struct io_uring_sq *sq = &ctx->ring.sq;
	unsigned mask = sq->ring_entries - 1;

	ior_worker_pool_job *first = NULL;
	ior_worker_pool_job *last = NULL;
	uint32_t count = 0;

	for (; job; job = job->next_pending) {
		job->user_data = job->ksqe->user_data;
		int had_link = (job->ksqe->flags & (IOSQE_IO_LINK | IOSQE_IO_HARDLINK)) != 0;

		// The placeholder NOP must not produce a CQE and must not take part in
		// kernel link chains (set_flags after prep_work may have overwritten it).
		job->ksqe->flags = (uint8_t) ((job->ksqe->flags | IOSQE_CQE_SKIP_SUCCESS)
				& ~(IOSQE_IO_LINK | IOSQE_IO_HARDLINK));

		uint64_t lt_deadline_ns = 0;
		if (had_link) {
			/*
			 * Locate the SQE staged right after this one. sqes[] positions are
			 * handed out in get_sqe order; recover this NOP's absolute position
			 * within the unflushed [sqe_head, sqe_tail) window from its array
			 * index, then bound-check its successor.
			 */
			unsigned idx = (unsigned) (job->ksqe - sq->sqes);
			unsigned pos = sq->sqe_head + ((idx - (sq->sqe_head & mask)) & mask);
			unsigned staged = sq->sqe_tail - sq->sqe_head;
			if (pos + 1 - sq->sqe_head < staged) {
				struct io_uring_sqe *next = &sq->sqes[(pos + 1) & mask];
				if (next->opcode == IORING_OP_LINK_TIMEOUT) {
					job->has_lt = 1;
					job->lt_user_data = next->user_data;

					struct __kernel_timespec *kts
							= (struct __kernel_timespec *) (uintptr_t) next->addr;
					if (kts && kts->tv_sec >= 0 && kts->tv_nsec >= 0
							&& kts->tv_nsec < 1000000000LL) {
						uint64_t ts_ns = (uint64_t) kts->tv_sec * 1000000000ULL
								+ (uint64_t) kts->tv_nsec;
						lt_deadline_ns = (next->timeout_flags & IORING_TIMEOUT_ABS)
								? ts_ns
								: ior_worker_pool_monotonic_ns() + ts_ns;
						job->lt_armed = 1;
					}

					// Neutralize the kernel-side LINK_TIMEOUT: another skipped NOP.
					io_uring_prep_nop(next);
					next->flags = IOSQE_CQE_SKIP_SUCCESS;
					next->user_data = 0;
				}
			}
		}
		job->ksqe = NULL; // stale once the SQ is flushed

		if (job->lt_armed) {
			atomic_store(&job->refs, 2); // worker + timer
			if (ior_worker_pool_arm_timer(ctx->wp, lt_deadline_ns, ior_uring_lt_fired,
						ior_uring_lt_dropped, job)
					< 0) {
				job->lt_armed = 0;
				atomic_store(&job->refs, 1);
			}
		}

		job->pj.next = NULL;
		if (last) {
			last->next = &job->pj;
		} else {
			first = &job->pj;
		}
		last = &job->pj;
		count++;
	}

	ior_worker_pool_submit(ctx->wp, first, last, count);
}

/* Backend operations */

static int ior_uring_backend_init(void **backend_ctx, ior_params *params)
{
	if (!backend_ctx || !params) {
		return -EINVAL;
	}

	ior_ctx_uring *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return -ENOMEM;
	}

	ctx->flags = params->flags;
	atomic_init(&ctx->shutdown, 0);

	if (pthread_mutex_init(&ctx->poster_lock, NULL) != 0) {
		free(ctx);
		return -ENOMEM;
	}

	// Prepare io_uring params
	struct io_uring_params uring_params = { 0 };

	if (params->cq_entries > 0) {
		uring_params.flags |= IORING_SETUP_CQSIZE;
		uring_params.cq_entries = params->cq_entries;
	}

	// Initialize io_uring - if kernel doesn't support it, this fails
	int ret = io_uring_queue_init_params(params->sq_entries, &ctx->ring, &uring_params);
	if (ret < 0) {
		pthread_mutex_destroy(&ctx->poster_lock);
		free(ctx);
		return ret;
	}

	// Set features. IORING_OP_POLL_ADD exists on every supported kernel.
	ctx->features = IOR_FEAT_NATIVE_ASYNC | IOR_FEAT_POLL_ADD | IOR_FEAT_SPLICE;

	/*
	 * Work ops are mandatory and need CQE_SKIP (5.17) + MSG_RING (5.18).
	 * Refuse init on an older runtime kernel rather than produce a context
	 * without them.
	 */
	int msg_ring_ok = 0;
	if (uring_params.features & IORING_FEAT_CQE_SKIP) {
		struct io_uring_probe *probe = io_uring_get_probe_ring(&ctx->ring);
		if (probe) {
			msg_ring_ok = io_uring_opcode_supported(probe, IORING_OP_MSG_RING);
			io_uring_free_probe(probe);
		}
	}
	if (!msg_ring_ok) {
		io_uring_queue_exit(&ctx->ring);
		pthread_mutex_destroy(&ctx->poster_lock);
		free(ctx);
		return -ENOSYS;
	}
	ctx->features |= IOR_FEAT_WORK;

	params->features = ctx->features;
	*backend_ctx = ctx;
	return 0;
}

static void ior_uring_backend_destroy(void *backend_ctx)
{
	if (!backend_ctx) {
		return;
	}

	ior_ctx_uring *ctx = backend_ctx;

	// Let running work callbacks observe teardown through their tokens, then
	// drain the pool: queued callbacks still run and post their completions
	// (via msg_ring into the still-live main ring); they are never reaped.
	atomic_store(&ctx->shutdown, 1);
	if (ctx->wp) {
		ior_worker_pool_destroy(ctx->wp);
		io_uring_queue_exit(&ctx->poster);
	}

	// Work ops prepped but never submitted: their callbacks never run.
	ior_uring_job *job = ctx->pending_head;
	while (job) {
		ior_uring_job *next = job->next_pending;
		free(job);
		job = next;
	}

	pthread_mutex_destroy(&ctx->poster_lock);
	io_uring_queue_exit(&ctx->ring);
	free(ctx);
}

static ior_sqe *ior_uring_backend_get_sqe(void *backend_ctx)
{
	if (!backend_ctx) {
		return NULL;
	}

	ior_ctx_uring *ctx = backend_ctx;
	struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
	if (sqe) {
		memset(sqe, 0, sizeof(*sqe));
	}
	return (ior_sqe *) sqe;
}

static int ior_uring_backend_submit(void *backend_ctx)
{
	if (!backend_ctx) {
		return -EINVAL;
	}

	ior_ctx_uring *ctx = backend_ctx;
	// Work jobs must be harvested while their placeholder SQEs are still staged.
	ior_uring_dispatch_pending(ctx);
	int ret = io_uring_submit(&ctx->ring);
	return ret < 0 ? -errno : ret;
}

static int ior_uring_backend_submit_and_wait(void *backend_ctx, unsigned wait_nr)
{
	if (!backend_ctx) {
		return -EINVAL;
	}

	ior_ctx_uring *ctx = backend_ctx;
	// Work jobs must be harvested while their placeholder SQEs are still staged.
	ior_uring_dispatch_pending(ctx);
	int ret = io_uring_submit_and_wait(&ctx->ring, wait_nr);
	return ret < 0 ? -errno : ret;
}

static int ior_uring_backend_peek_cqe(void *backend_ctx, ior_cqe **cqe_out)
{
	if (!backend_ctx || !cqe_out) {
		return -EINVAL;
	}

	ior_ctx_uring *ctx = backend_ctx;
	struct io_uring_cqe *cqe;
	int ret = io_uring_peek_cqe(&ctx->ring, &cqe);

	if (ret < 0) {
		return ret;
	}

	*cqe_out = (ior_cqe *) cqe;
	return 0;
}

static int ior_uring_backend_wait_cqe(void *backend_ctx, ior_cqe **cqe_out)
{
	if (!backend_ctx || !cqe_out) {
		return -EINVAL;
	}

	ior_ctx_uring *ctx = backend_ctx;
	struct io_uring_cqe *cqe;
	int ret = io_uring_wait_cqe(&ctx->ring, &cqe);

	if (ret < 0) {
		return ret;
	}

	*cqe_out = (ior_cqe *) cqe;
	return 0;
}

static int ior_uring_backend_wait_cqe_timeout(
		void *backend_ctx, ior_cqe **cqe_out, ior_timespec *timeout)
{
	if (!backend_ctx || !cqe_out) {
		return -EINVAL;
	}

	ior_ctx_uring *ctx = backend_ctx;
	struct io_uring_cqe *cqe;

	int ret = io_uring_wait_cqe_timeout(&ctx->ring, &cqe, (struct __kernel_timespec *) timeout);

	if (ret < 0) {
		return ret;
	}

	*cqe_out = (ior_cqe *) cqe;
	return 0;
}

static void ior_uring_backend_cqe_seen(void *backend_ctx, ior_cqe *cqe)
{
	if (!backend_ctx || !cqe) {
		return;
	}

	ior_ctx_uring *ctx = backend_ctx;
	io_uring_cqe_seen(&ctx->ring, (struct io_uring_cqe *) cqe);
}

static unsigned ior_uring_backend_peek_batch_cqe(void *backend_ctx, ior_cqe **cqes, unsigned max)
{
	if (!backend_ctx || !cqes || max == 0) {
		return 0;
	}

	ior_ctx_uring *ctx = backend_ctx;
	struct io_uring_cqe **uring_cqes = (struct io_uring_cqe **) cqes;
	return io_uring_peek_batch_cqe(&ctx->ring, uring_cqes, max);
}

static void ior_uring_backend_cq_advance(void *backend_ctx, unsigned nr)
{
	if (!backend_ctx || nr == 0) {
		return;
	}

	ior_ctx_uring *ctx = backend_ctx;
	io_uring_cq_advance(&ctx->ring, nr);
}

/* SQE preparation helpers - use liburing's helpers directly, cast ior_fd_t to int */

static void ior_uring_backend_prep_nop(ior_sqe *sqe)
{
	struct io_uring_sqe *s = &sqe->uring.sqe;
	io_uring_prep_nop(s);
}

static void ior_uring_backend_prep_read(
		ior_sqe *sqe, ior_fd_t fd, void *buf, unsigned nbytes, uint64_t offset)
{
	struct io_uring_sqe *s = &sqe->uring.sqe;
	// io_uring uses int fd - cast from ior_fd_t (which is int on Linux)
	io_uring_prep_read(s, (int) fd, buf, nbytes, offset);
}

static void ior_uring_backend_prep_write(
		ior_sqe *sqe, ior_fd_t fd, const void *buf, unsigned nbytes, uint64_t offset)
{
	struct io_uring_sqe *s = &sqe->uring.sqe;
	// io_uring uses int fd - cast from ior_fd_t (which is int on Linux)
	io_uring_prep_write(s, (int) fd, buf, nbytes, offset);
}

static void ior_uring_backend_prep_splice(ior_sqe *sqe, ior_fd_t fd_in, uint64_t off_in,
		ior_fd_t fd_out, uint64_t off_out, unsigned nbytes, unsigned flags)
{
	struct io_uring_sqe *s = &sqe->uring.sqe;
	// io_uring uses int fd - cast from ior_fd_t (which is int on Linux)
	io_uring_prep_splice(s, (int) fd_in, off_in, (int) fd_out, off_out, nbytes, flags);
}

// Map ior's public timeout flags to liburing's IORING_TIMEOUT_* flags.
static unsigned ior_uring_timeout_flags(unsigned flags)
{
	unsigned uflags = 0;
	if (flags & IOR_TIMEOUT_ABS) {
		uflags |= IORING_TIMEOUT_ABS;
	}
	return uflags;
}

static void ior_uring_backend_prep_timeout(
		ior_sqe *sqe, ior_timespec *ts, unsigned count, unsigned flags)
{
	struct io_uring_sqe *s = &sqe->uring.sqe;

	io_uring_prep_timeout(
			s, (struct __kernel_timespec *) ts, count, ior_uring_timeout_flags(flags));
}

static void ior_uring_backend_prep_link_timeout(ior_sqe *sqe, ior_timespec *ts, unsigned flags)
{
	struct io_uring_sqe *s = &sqe->uring.sqe;
	io_uring_prep_link_timeout(s, (struct __kernel_timespec *) ts, ior_uring_timeout_flags(flags));
}

static void ior_uring_backend_prep_send(
		ior_sqe *sqe, ior_fd_t sockfd, const void *buf, unsigned nbytes, int flags)
{
	struct io_uring_sqe *s = &sqe->uring.sqe;
	// io_uring uses int fd - cast from ior_fd_t (which is int on Linux)
	io_uring_prep_send(s, (int) sockfd, buf, nbytes, flags);
}

static void ior_uring_backend_prep_recv(
		ior_sqe *sqe, ior_fd_t sockfd, void *buf, unsigned nbytes, int flags)
{
	struct io_uring_sqe *s = &sqe->uring.sqe;
	// io_uring uses int fd - cast from ior_fd_t (which is int on Linux)
	io_uring_prep_recv(s, (int) sockfd, buf, nbytes, flags);
}

/* IOR_POLL_* values match the kernel's poll bits, so masks and the CQE res
 * pass through unchanged. */
_Static_assert(IOR_POLL_IN == POLLIN, "IOR_POLL_IN must match POLLIN");
_Static_assert(IOR_POLL_OUT == POLLOUT, "IOR_POLL_OUT must match POLLOUT");
_Static_assert(IOR_POLL_ERR == POLLERR, "IOR_POLL_ERR must match POLLERR");
_Static_assert(IOR_POLL_HUP == POLLHUP, "IOR_POLL_HUP must match POLLHUP");
_Static_assert(IOR_POLL_NVAL == POLLNVAL, "IOR_POLL_NVAL must match POLLNVAL");

static void ior_uring_backend_prep_poll_add(ior_sqe *sqe, ior_fd_t fd, uint32_t poll_mask)
{
	struct io_uring_sqe *s = &sqe->uring.sqe;
	io_uring_prep_poll_add(s, (int) fd, poll_mask);
}

static int ior_uring_backend_prep_work(void *backend_ctx, ior_sqe *sqe, ior_work_fn fn, void *arg)
{
	ior_ctx_uring *ctx = backend_ctx;

	int ret = ior_uring_work_ensure(ctx);
	if (ret < 0) {
		return ret;
	}

	ior_uring_job *job = calloc(1, sizeof(*job));
	if (!job) {
		return -ENOMEM;
	}

	/*
	 * The kernel never executes the callback; its SQE becomes a placeholder
	 * NOP whose successful completion is skipped, keeping SQ accounting (and
	 * the submit() return count) consistent. The job itself is dispatched to
	 * the worker pool when submit() flushes the queue.
	 */
	struct io_uring_sqe *s = &sqe->uring.sqe;
	io_uring_prep_nop(s);
	s->flags |= IOSQE_CQE_SKIP_SUCCESS;

	job->ctx = ctx;
	job->fn = fn;
	job->arg = arg;
	job->ksqe = s;
	atomic_init(&job->state, IOR_URING_JOB_QUEUED);
	atomic_init(&job->refs, 1);
	atomic_init(&job->lt_fired, 0);
	atomic_init(&job->token.cancelled, 0);
	job->token.shutdown = &ctx->shutdown;

	job->next_pending = NULL;
	if (ctx->pending_tail) {
		ctx->pending_tail->next_pending = job;
	} else {
		ctx->pending_head = job;
	}
	ctx->pending_tail = job;

	return 0;
}

static void ior_uring_backend_sqe_set_data(ior_sqe *sqe, void *data)
{
	struct io_uring_sqe *s = &sqe->uring.sqe;
	io_uring_sqe_set_data(s, data);
}

static void ior_uring_backend_sqe_set_flags(ior_sqe *sqe, uint8_t flags)
{
	struct io_uring_sqe *s = &sqe->uring.sqe;

	// Map ior's public SQE flags to liburing's IOSQE_* flags.
	uint8_t uflags = 0;
	if (flags & IOR_SQE_FIXED_FILE) {
		uflags |= IOSQE_FIXED_FILE;
	}
	if (flags & IOR_SQE_IO_DRAIN) {
		uflags |= IOSQE_IO_DRAIN;
	}
	if (flags & IOR_SQE_IO_LINK) {
		uflags |= IOSQE_IO_LINK;
	}
	if (flags & IOR_SQE_ASYNC) {
		uflags |= IOSQE_ASYNC;
	}
	s->flags = uflags;
}

/* CQE accessors */

static void *ior_uring_backend_cqe_get_data(ior_cqe *cqe)
{
	ior_cqe_uring *c = &cqe->uring;
	return io_uring_cqe_get_data((const struct io_uring_cqe *) c);
}

static int32_t ior_uring_backend_cqe_get_res(ior_cqe *cqe)
{
	ior_cqe_uring *c = &cqe->uring;
	return c->res;
}

static uint32_t ior_uring_backend_cqe_get_flags(ior_cqe *cqe)
{
	ior_cqe_uring *c = &cqe->uring;
	return c->flags;
}

/* Backend info */

static const char *ior_uring_backend_name(void)
{
	return "io_uring";
}

static uint32_t ior_uring_backend_get_features(void *backend_ctx)
{
	if (!backend_ctx) {
		return 0;
	}

	ior_ctx_uring *ctx = backend_ctx;
	return ctx->features;
}

/* Export vtable */
const ior_backend_ops ior_uring_ops = {
	.init = ior_uring_backend_init,
	.destroy = ior_uring_backend_destroy,
	.get_sqe = ior_uring_backend_get_sqe,
	.submit = ior_uring_backend_submit,
	.submit_and_wait = ior_uring_backend_submit_and_wait,
	.peek_cqe = ior_uring_backend_peek_cqe,
	.wait_cqe = ior_uring_backend_wait_cqe,
	.wait_cqe_timeout = ior_uring_backend_wait_cqe_timeout,
	.cqe_seen = ior_uring_backend_cqe_seen,
	.peek_batch_cqe = ior_uring_backend_peek_batch_cqe,
	.cq_advance = ior_uring_backend_cq_advance,
	.prep_nop = ior_uring_backend_prep_nop,
	.prep_read = ior_uring_backend_prep_read,
	.prep_write = ior_uring_backend_prep_write,
	.prep_splice = ior_uring_backend_prep_splice,
	.prep_timeout = ior_uring_backend_prep_timeout,
	.prep_link_timeout = ior_uring_backend_prep_link_timeout,
	.prep_send = ior_uring_backend_prep_send,
	.prep_recv = ior_uring_backend_prep_recv,
	.prep_poll_add = ior_uring_backend_prep_poll_add,
	.prep_work = ior_uring_backend_prep_work,
	.sqe_set_data = ior_uring_backend_sqe_set_data,
	.sqe_set_flags = ior_uring_backend_sqe_set_flags,
	.cqe_get_data = ior_uring_backend_cqe_get_data,
	.cqe_get_res = ior_uring_backend_cqe_get_res,
	.cqe_get_flags = ior_uring_backend_cqe_get_flags,
	.backend_name = ior_uring_backend_name,
	.get_features = ior_uring_backend_get_features,
};

#endif /* IOR_HAVE_URING */
