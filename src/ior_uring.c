/* SPDX-License-Identifier: BSD-3-Clause */
#include "config.h"

#ifdef IOR_HAVE_URING

#include "ior_backend.h"
#include "ior_worker_pool.h"
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <poll.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#ifdef IOR_HAVE_PIDFD_OPEN
#include <sys/syscall.h>
#endif
#include <liburing.h>

typedef struct ior_uring_job ior_uring_job;
typedef struct ior_uring_wait ior_uring_wait;

/* Backend context */
typedef struct ior_ctx_uring {
	struct io_uring ring;
	uint32_t flags;
	uint32_t features;
	uint32_t sq_entries; // ring sizes as the kernel set them up
	uint32_t cq_entries;

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
	/*
	 * Completions the kernel has not taken yet (see ior_uring_post_cqe),
	 * under poster_lock. post_queued counts those on the list, post_live
	 * those not yet confirmed delivered, on the list or in the poster ring.
	 */
	struct ior_uring_post *post_head;
	struct ior_uring_post *post_tail;
	_Atomic uint32_t post_queued;
	_Atomic uint32_t post_live;
	/*
	 * Released by every msg_ring post and acquired by every reap: what a
	 * worker wrote before posting (a callback's output, a wait status) is
	 * ordered before the caller's reading of the CQE. The kernel path gives
	 * that in practice; this states it in C, where sanitizers can see it.
	 */
	_Atomic uint64_t posted;
	ior_uring_job *pending_head; // prepped-not-dispatched jobs (submitter thread only)
	ior_uring_job *pending_tail;

	/*
	 * Dispatched jobs, for IOR_OP_ASYNC_CANCEL: the kernel only ever sees
	 * their placeholder NOPs, so a cancel by user data is matched against
	 * this list at submit time and resolved in userspace.
	 */
	pthread_mutex_t jobs_lock;
	ior_uring_job *jobs_head; // doubly linked via live_next/live_prev

	/*
	 * IOR_OP_WAITPID and IOR_OP_SIGWAIT: an IORING_OP_WAITID, or a POLL_ADD
	 * on a pidfd or a signalfd, whose kernel user_data is the wait record, so
	 * its CQE can be told apart on the way out and rewritten into the
	 * waitpid or sigwait result (see ior_uring_resolve_waits). Records are
	 * prepped on waits_pending and moved into waits_live at submit: lists
	 * hashed by the record's address, since every reaped CQE is looked up
	 * there while any wait is live. Shared with the reaping thread and with
	 * cancel interception, under jobs_lock; the count lets a reap skip the
	 * lock when nothing is live.
	 */
	ior_uring_wait *waits_pending;
	ior_uring_wait *waits_live[64];
	_Atomic uint32_t waits_live_count;

	int notify_fd; // eventfd registered with the ring; -1 until requested
	int has_waitid; // the kernel has IORING_OP_WAITID (6.7)

	/*
	 * Per SQ slot, set by ior_uring_scan_staged(): the entry is in a chain the
	 * kernel will fail, so no userspace work may be done for it.
	 */
	uint8_t *sq_failed;
	int sq_any_failed; // some byte of sq_failed is set, for this submit only
	int sq_needs_scan; // an entry submit checks may be staged (prep_checked)
} ior_ctx_uring;

/*
 * What a wait record stands for. A WAITID the kernel cancels, from a cancel
 * or a link timeout, has the canceller complete with the number of requests
 * cancelled (1) rather than 0 or -ETIME, so ior keys those two by a record
 * of their own too and puts the io_uring result back.
 */
enum {
	IOR_URING_WAIT_PIDFD = 0, // a POLL_ADD on a pidfd: the child exited
	IOR_URING_WAIT_SIG, // a POLL_ADD on a signalfd: info gets the signal
	IOR_URING_WAIT_WAITID, // an IORING_OP_WAITID
	IOR_URING_WAIT_CANCEL, // a cancel aimed at a WAITID: 0, not the count
	IOR_URING_WAIT_LT, // a link timeout guarding a WAITID: -ETIME, not the count
};

struct ior_uring_wait {
	ior_uring_wait *next;
	ior_uring_wait *prev; // live lists only
	int kind; // IOR_URING_WAIT_*
	int fd; // the pidfd or signalfd polled, -1 for the other kinds
	pid_t pid;
	int *status;
	ior_siginfo_t *info;
	siginfo_t si; // WAITID: the kernel writes it until the CQE is out
	uint64_t user_data; // the caller's, harvested at submit
	struct io_uring_sqe *ksqe; // the kernel op; valid only until submit
};

/*
 * Lifecycle/arbitration state of one work op. QUEUED -> RUNNING -> DONE is the
 * worker path; a fired link timeout claims QUEUED -> CANCELLED to kill a job
 * that has not started (its callback then never runs). The refcount is held by
 * the worker (via the pool FIFO) and, when a link timeout is armed, by the
 * timer; the job is freed by whichever side finishes last. The link timeout's
 * CQE is posted by whoever takes lt_posted first: the timer at the deadline
 * while the callback runs (-EALREADY), else the worker once it returned.
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
	ior_uring_job *live_next; // ctx->jobs_head list, under jobs_lock
	ior_uring_job *live_prev;
	int live_linked;
	int cancel_drop; // refs a cancel took over (worker's, timer's) to drop
	ior_ctx_uring *ctx;
	ior_work_fn fn;
	void *arg;
	uint64_t user_data; // harvested from the kernel SQE at submit
	struct io_uring_sqe *ksqe; // the placeholder NOP; valid only until submit

	// Link timeout guarding this job (detected at submit)
	int has_lt; // a LINK_TIMEOUT sqe followed and was intercepted
	int lt_armed; // its deadline was valid and the timer is armed
	uint64_t lt_user_data;
	_Atomic int lt_posted;

	// IOR_OP_WAITPID probed from the timer thread (no IORING_OP_WAITID).
	pid_t wait_pid;
	int *wait_status;
	int wait_options;
	int probe; // not a callback: the timer probes the wait, see below
	uint64_t probe_ns; // the next probe interval; its address keys the timer

	struct ior_work_token token;
	_Atomic int state;
	_Atomic int refs;
};

// The live list a wait record keyed by `key` (its address) belongs to.
static ior_uring_wait **ior_uring_wait_bucket(ior_ctx_uring *ctx, uint64_t key)
{
	size_t n = sizeof(ctx->waits_live) / sizeof(ctx->waits_live[0]);
	return &ctx->waits_live[((key >> 6) ^ (key >> 14)) & (n - 1)];
}

// jobs_lock held.
static void ior_uring_job_unlink_locked(ior_ctx_uring *ctx, ior_uring_job *job)
{
	if (!job->live_linked) {
		return;
	}
	if (job->live_prev) {
		job->live_prev->live_next = job->live_next;
	} else {
		ctx->jobs_head = job->live_next;
	}
	if (job->live_next) {
		job->live_next->live_prev = job->live_prev;
	}
	job->live_linked = 0;
}

static void ior_uring_job_release(ior_uring_job *job)
{
	if (atomic_fetch_sub(&job->refs, 1) == 1) {
		ior_ctx_uring *ctx = job->ctx;
		pthread_mutex_lock(&ctx->jobs_lock);
		ior_uring_job_unlink_locked(ctx, job);
		pthread_mutex_unlock(&ctx->jobs_lock);
		free(job);
	}
}

/*
 * A completion on its way to the main ring. It is kept until the poster
 * ring's CQE for its MSG_RING says it arrived, so none is lost when the
 * kernel refuses one (the target's CQ full with no memory for overflow, or
 * the poster's submit failing): it is queued again and retried.
 */
typedef struct ior_uring_post {
	uint64_t user_data;
	int32_t res;
	struct ior_uring_post *next;
} ior_uring_post;

// Settle the posts the kernel has answered; a refused one goes back to the front.
static void ior_uring_poster_reap_locked(ior_ctx_uring *ctx)
{
	ior_uring_post *retry = NULL;
	ior_uring_post *retry_tail = NULL;
	struct io_uring_cqe *cqe;
	while (io_uring_peek_cqe(&ctx->poster, &cqe) == 0) {
		ior_uring_post *post = (ior_uring_post *) (uintptr_t) cqe->user_data;
		int32_t res = cqe->res;
		io_uring_cqe_seen(&ctx->poster, cqe);
		if (!post) {
			IOR_LOG_ERROR("msg_ring post failed: res=%d, lost", res);
			continue;
		}
		if (res >= 0) {
			free(post);
			atomic_fetch_sub(&ctx->post_live, 1);
			continue;
		}
		IOR_LOG_ERROR("msg_ring post failed: res=%d, retrying", res);
		post->next = NULL;
		if (retry_tail) {
			retry_tail->next = post;
		} else {
			retry = post;
		}
		retry_tail = post;
		atomic_fetch_add(&ctx->post_queued, 1);
	}
	if (retry) {
		retry_tail->next = ctx->post_head;
		if (!ctx->post_head) {
			ctx->post_tail = retry_tail;
		}
		ctx->post_head = retry;
	}
}

// Hand the queued posts to the kernel, in order, and settle what it answered.
static void ior_uring_poster_flush_locked(ior_ctx_uring *ctx)
{
	ior_uring_poster_reap_locked(ctx);
	while (ctx->post_head) {
		struct io_uring_sqe *s = io_uring_get_sqe(&ctx->poster);
		if (!s) {
			break; // a failed submit left entries staged; they go first
		}
		ior_uring_post *post = ctx->post_head;
		ctx->post_head = post->next;
		if (!ctx->post_head) {
			ctx->post_tail = NULL;
		}
		atomic_fetch_sub(&ctx->post_queued, 1);
		io_uring_prep_msg_ring(s, ctx->ring.ring_fd, (unsigned int) post->res, post->user_data, 0);
		io_uring_sqe_set_data(s, post);
	}
	int ret = io_uring_submit(&ctx->poster);
	if (ret < 0) {
		IOR_LOG_ERROR("msg_ring submit failed: %d, retrying", ret);
	}
	// A MSG_RING is delivered inline, so its CQE is normally here already.
	ior_uring_poster_reap_locked(ctx);
}

/*
 * Inject a completion into the main ring's CQ via the poster ring. Runs on
 * worker/timer threads (and the submitter, for cancels) under poster_lock.
 */
static void ior_uring_post_cqe(ior_ctx_uring *ctx, uint64_t user_data, int32_t res)
{
	ior_uring_post *post = malloc(sizeof(*post));

	pthread_mutex_lock(&ctx->poster_lock);
	atomic_fetch_add_explicit(&ctx->posted, 1, memory_order_release);
	if (!post) {
		// Nothing to keep it in: one attempt, as a last resort.
		IOR_LOG_ERROR("no memory to keep a completion, posting it once");
		struct io_uring_sqe *s = io_uring_get_sqe(&ctx->poster);
		if (s) {
			io_uring_prep_msg_ring(s, ctx->ring.ring_fd, (unsigned int) res, user_data, 0);
			s->flags |= IOSQE_CQE_SKIP_SUCCESS;
			io_uring_sqe_set_data(s, NULL);
		}
		(void) io_uring_submit(&ctx->poster);
		pthread_mutex_unlock(&ctx->poster_lock);
		return;
	}
	post->user_data = user_data;
	post->res = res;
	post->next = NULL;
	if (ctx->post_tail) {
		ctx->post_tail->next = post;
	} else {
		ctx->post_head = post;
	}
	ctx->post_tail = post;
	atomic_fetch_add(&ctx->post_queued, 1);
	atomic_fetch_add(&ctx->post_live, 1);
	ior_uring_poster_flush_locked(ctx);
	pthread_mutex_unlock(&ctx->poster_lock);
}

// From the reaping side: retry posts the kernel refused, if there are any.
static void ior_uring_poster_retry(ior_ctx_uring *ctx)
{
	if (atomic_load_explicit(&ctx->post_live, memory_order_relaxed) == 0) {
		return;
	}
	pthread_mutex_lock(&ctx->poster_lock);
	ior_uring_poster_flush_locked(ctx);
	pthread_mutex_unlock(&ctx->poster_lock);
}

#define IOR_URING_POST_RETRY_NS 10000000ULL

static uint64_t ior_uring_now_ns(void)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return (uint64_t) now.tv_sec * 1000000000ULL + (uint64_t) now.tv_nsec;
}

/*
 * Wait for wait_nr completions, no longer than ts (NULL: no limit). While a
 * refused post is queued, wait in slices and retry it between them: the
 * completion waited for may be that one.
 */
static int ior_uring_wait_cqes(
		ior_ctx_uring *ctx, struct io_uring_cqe **cqe, unsigned wait_nr, const ior_timespec *ts)
{
	uint64_t deadline = ts ? ior_uring_now_ns() + ior_timespec_ns(ts) : 0;
	for (;;) {
		ior_uring_poster_retry(ctx);
		int queued = atomic_load(&ctx->post_queued) != 0;
		if (!ts && !queued) {
			return io_uring_wait_cqes(&ctx->ring, cqe, wait_nr, NULL, NULL);
		}
		uint64_t rem = 0;
		if (ts) {
			uint64_t now = ior_uring_now_ns();
			rem = deadline > now ? deadline - now : 0;
		}
		uint64_t span = ts ? rem : UINT64_MAX;
		if (queued && span > IOR_URING_POST_RETRY_NS) {
			span = IOR_URING_POST_RETRY_NS;
		}
		struct __kernel_timespec kts = {
			.tv_sec = (long long) (span / 1000000000ULL),
			.tv_nsec = (long long) (span % 1000000000ULL),
		};
		int ret = io_uring_wait_cqes(&ctx->ring, cqe, wait_nr, &kts, NULL);
		if (ret != -ETIME || (ts && span == rem)) {
			return ret;
		}
	}
}

// Post a job's result, and its link timeout's unless the timer did.
static void ior_uring_job_finish(ior_ctx_uring *ctx, ior_uring_job *job, int32_t res)
{
	// Unless the timer posted it while the op ran, the link timeout resolves
	// as "op finished first".
	int post_lt = job->has_lt && !atomic_exchange(&job->lt_posted, 1);
	atomic_store(&job->state, IOR_URING_JOB_DONE);

	ior_uring_post_cqe(ctx, job->user_data, res);
	if (post_lt) {
		ior_uring_post_cqe(ctx, job->lt_user_data, -ECANCELED);
	}

	ior_uring_job_release(job);
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

	ior_uring_job_finish(ctx, job, job->fn(&job->token, job->arg));
}

static void ior_uring_probe_dropped(void *owner, void *arg);

/*
 * Timer side of a probed process wait. Claimed like a job a worker starts
 * (QUEUED -> RUNNING), so a cancel or a link timeout that got there first
 * wins and the child is left alone. waitpid(WNOHANG) cannot block; with
 * nothing to report the wait goes back to QUEUED and the timer, at an
 * interval that doubles up to IOR_WAITPID_PROBE_MAX_NS. A cancel that came
 * during the probe (-EALREADY) ends it then, unreaped.
 */
static void ior_uring_probe_fired(void *owner, void *arg)
{
	ior_ctx_uring *ctx = owner;
	ior_uring_job *job = (ior_uring_job *) ((char *) arg - offsetof(ior_uring_job, probe_ns));

	int expected = IOR_URING_JOB_QUEUED;
	if (!atomic_compare_exchange_strong(&job->state, &expected, IOR_URING_JOB_RUNNING)) {
		ior_uring_job_release(job); // cancelled; its completions are out
		return;
	}
	pid_t r;
	do {
		r = waitpid(job->wait_pid, job->wait_status, job->wait_options | WNOHANG);
	} while (r < 0 && errno == EINTR);
	int32_t res = r < 0 ? -errno : r;

	if (res == 0 && !(job->wait_options & WNOHANG)) {
		if (atomic_load_explicit(&job->token.cancelled, memory_order_acquire)) {
			res = -ECANCELED;
		} else {
			job->probe_ns *= 2;
			if (job->probe_ns > IOR_WAITPID_PROBE_MAX_NS) {
				job->probe_ns = IOR_WAITPID_PROBE_MAX_NS;
			}
			atomic_store(&job->state, IOR_URING_JOB_QUEUED);
			if (ior_worker_pool_arm_timer(ctx->wp, ior_worker_pool_monotonic_ns() + job->probe_ns,
						ior_uring_probe_fired, ior_uring_probe_dropped, &job->probe_ns)
					== 0) {
				return;
			}
			// No memory to wait on: claim it back to fail it.
			expected = IOR_URING_JOB_QUEUED;
			if (!atomic_compare_exchange_strong(&job->state, &expected, IOR_URING_JOB_RUNNING)) {
				ior_uring_job_release(job);
				return;
			}
			res = -ENOMEM;
		}
	}
	ior_uring_job_finish(ctx, job, res);
}

// Pool destroyed with the wait pending: drop the ref the probe held.
static void ior_uring_probe_dropped(void *owner, void *arg)
{
	(void) owner;
	ior_uring_job_release((ior_uring_job *) ((char *) arg - offsetof(ior_uring_job, probe_ns)));
}

// Timer-thread side of a link timeout on a work op.
static void ior_uring_lt_fired(void *owner, void *arg)
{
	ior_ctx_uring *ctx = owner;
	ior_uring_job *job = arg;

	atomic_store_explicit(&job->token.cancelled, 1, memory_order_release);

	int expected = IOR_URING_JOB_QUEUED;
	if (atomic_compare_exchange_strong(&job->state, &expected, IOR_URING_JOB_CANCELLED)) {
		// Job had not started: it never will. Post both completions here.
		atomic_store(&job->lt_posted, 1);
		ior_uring_post_cqe(ctx, job->user_data, -ECANCELED);
		ior_uring_post_cqe(ctx, job->lt_user_data, -ETIME);
	} else if (expected == IOR_URING_JOB_RUNNING && !atomic_exchange(&job->lt_posted, 1)) {
		/* The callback cannot be stopped: as io_uring's link timeout on a
		 * running request, complete now with the cancel's -EALREADY and
		 * leave the op's CQE to the worker. */
		ior_uring_post_cqe(ctx, job->lt_user_data, -EALREADY);
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
 * Publish prepped pidfd and signalfd waits: harvest the user data the caller
 * attached and key the kernel op by the record instead, so its completion is
 * recognised whatever user data the caller uses elsewhere.
 */
static unsigned ior_uring_timeout_flags_from(unsigned uflags);

// Absolute position of a staged, unflushed SQE, from its slot in sqes[].
static unsigned ior_uring_sq_pos(ior_ctx_uring *ctx, const struct io_uring_sqe *s)
{
	struct io_uring_sq *sq = &ctx->ring.sq;
	unsigned mask = sq->ring_entries - 1;
	unsigned idx = (unsigned) (s - sq->sqes);
	return sq->sqe_head + ((idx - (sq->sqe_head & mask)) & mask);
}

/*
 * Find where the kernel will stop taking the staged entries: right after one
 * that fails the checks it makes on taking it, unless that one links on. The
 * entries of a chain holding such an entry are flagged in sq_failed, as the
 * kernel fails them all. Returns the position to stop at.
 */
static unsigned ior_uring_scan_staged(ior_ctx_uring *ctx)
{
	struct io_uring_sq *sq = &ctx->ring.sq;
	if (!ctx->sq_needs_scan) {
		return sq->sqe_tail; // nothing staged that could fail the checks
	}
	unsigned mask = sq->ring_entries - 1;
	unsigned chain_start = sq->sqe_head;
	int in_chain = 0;
	int prev_lt = 0;
	int chain_failed = 0;

	for (unsigned pos = sq->sqe_head; pos != sq->sqe_tail; pos++) {
		const struct io_uring_sqe *s = &sq->sqes[pos & mask];
		if (!in_chain) {
			chain_start = pos;
			chain_failed = 0;
		}
		int ret = 0;
		if (s->opcode == IORING_OP_TIMEOUT || s->opcode == IORING_OP_LINK_TIMEOUT) {
			const ior_timespec *ts = (const ior_timespec *) (uintptr_t) s->addr;
			unsigned flags = ior_uring_timeout_flags_from(s->timeout_flags);
			ret = s->opcode == IORING_OP_TIMEOUT
					? ior_timeout_check(ts, flags)
					: ior_link_timeout_check(ts, flags, in_chain, prev_lt);
		} else if (s->opcode == IORING_OP_ACCEPT) {
			ret = ior_accept_check(s->accept_flags);
		}
		int link = (s->flags & (IOSQE_IO_LINK | IOSQE_IO_HARDLINK)) != 0;
		if (ret < 0) {
			chain_failed = 1;
		}
		if (chain_failed && (!link || pos + 1 == sq->sqe_tail)) {
			for (unsigned q = chain_start; q != pos + 1; q++) {
				ctx->sq_failed[q & mask] = 1;
			}
			ctx->sq_any_failed = 1;
			chain_failed = 0;
			if (ret < 0 && !link) {
				return pos + 1; // what is left stays staged: scanned again next time
			}
		}
		prev_lt = s->opcode == IORING_OP_LINK_TIMEOUT;
		in_chain = link;
	}
	ctx->sq_needs_scan = 0;
	return sq->sqe_tail;
}

static void ior_uring_backend_prep_checked(void *backend_ctx)
{
	((ior_ctx_uring *) backend_ctx)->sq_needs_scan = 1;
}

// Make a record live under its own address (jobs_lock held).
static void ior_uring_wait_link_locked(ior_ctx_uring *ctx, ior_uring_wait *wait)
{
	ior_uring_wait **head = ior_uring_wait_bucket(ctx, (uint64_t) (uintptr_t) wait);
	wait->prev = NULL;
	wait->next = *head;
	if (*head) {
		(*head)->prev = wait;
	}
	*head = wait;
	atomic_fetch_add(&ctx->waits_live_count, 1);
}

/*
 * Key the staged entry s (a cancel or a link timeout aimed at a WAITID) by a
 * record that puts its io_uring result back (jobs_lock held). Without memory
 * for one it keeps the kernel's count.
 */
static void ior_uring_wait_fixup_locked(ior_ctx_uring *ctx, struct io_uring_sqe *s, int kind)
{
	ior_uring_wait *fix = calloc(1, sizeof(*fix));
	if (!fix) {
		return;
	}
	fix->kind = kind;
	fix->fd = -1;
	fix->user_data = s->user_data;
	s->user_data = (uint64_t) (uintptr_t) fix;
	ior_uring_wait_link_locked(ctx, fix);
}

static void ior_uring_dispatch_waits(ior_ctx_uring *ctx, unsigned bound)
{
	ior_uring_wait *wait = ctx->waits_pending;
	if (!wait) {
		return;
	}
	ctx->waits_pending = NULL;
	unsigned head = ctx->ring.sq.sqe_head;

	pthread_mutex_lock(&ctx->jobs_lock);
	while (wait) {
		ior_uring_wait *next = wait->next;
		if (ior_uring_sq_pos(ctx, wait->ksqe) - head >= bound - head) {
			// Not taken by this submit: stays prepped for the next one.
			wait->next = ctx->waits_pending;
			ctx->waits_pending = wait;
			wait = next;
			continue;
		}
		wait->user_data = wait->ksqe->user_data;
		wait->ksqe->user_data = (uint64_t) (uintptr_t) wait;
		// The pidfd or signalfd is ior's own, never a registered file.
		wait->ksqe->flags &= (uint8_t) ~IOSQE_FIXED_FILE;
		if (wait->kind == IOR_URING_WAIT_WAITID && (wait->ksqe->flags & IOSQE_IO_LINK)) {
			unsigned pos = ior_uring_sq_pos(ctx, wait->ksqe);
			struct io_uring_sqe *lt
					= &ctx->ring.sq.sqes[(pos + 1) & (ctx->ring.sq.ring_entries - 1)];
			if (pos + 1 - head < bound - head && lt->opcode == IORING_OP_LINK_TIMEOUT) {
				ior_uring_wait_fixup_locked(ctx, lt, IOR_URING_WAIT_LT);
			}
		}
		wait->ksqe = NULL;
		ior_uring_wait_link_locked(ctx, wait);
		wait = next;
	}
	pthread_mutex_unlock(&ctx->jobs_lock);
}

// jobs_lock held.
static void ior_uring_wait_unlink_locked(ior_ctx_uring *ctx, ior_uring_wait *wait)
{
	if (wait->prev) {
		wait->prev->next = wait->next;
	} else {
		*ior_uring_wait_bucket(ctx, (uint64_t) (uintptr_t) wait) = wait->next;
	}
	if (wait->next) {
		wait->next->prev = wait->prev;
	}
	atomic_fetch_sub(&ctx->waits_live_count, 1);
}

/*
 * What signalfd(2) reports, as sigwaitinfo(2) would report it. The fields
 * of a siginfo_t overlay one another, so which are set follows the kernel's
 * own layout choice for the code and signal.
 */
static void ior_uring_siginfo_from_signalfd(siginfo_t *info, const struct signalfd_siginfo *ssi)
{
	memset(info, 0, sizeof(*info));
	info->si_signo = (int) ssi->ssi_signo;
	info->si_errno = ssi->ssi_errno;
	info->si_code = ssi->ssi_code;
	if (ssi->ssi_code == SI_TIMER) {
		info->si_timerid = (int) ssi->ssi_tid;
		info->si_overrun = (int) ssi->ssi_overrun;
		info->si_value.sival_ptr = (void *) (uintptr_t) ssi->ssi_ptr;
		info->si_value.sival_int = ssi->ssi_int;
		return;
	}
	if (ssi->ssi_code <= 0 && ssi->ssi_code != SI_USER && ssi->ssi_code != SI_TKILL) {
		// sigqueue(3), a message queue, asynchronous I/O: a value came along.
		info->si_pid = (pid_t) ssi->ssi_pid;
		info->si_uid = (uid_t) ssi->ssi_uid;
		info->si_value.sival_ptr = (void *) (uintptr_t) ssi->ssi_ptr;
		info->si_value.sival_int = ssi->ssi_int;
		return;
	}
	if (ssi->ssi_code > 0) {
		switch (ssi->ssi_signo) {
			case SIGCHLD:
				info->si_pid = (pid_t) ssi->ssi_pid;
				info->si_uid = (uid_t) ssi->ssi_uid;
				info->si_status = ssi->ssi_status;
				info->si_utime = (clock_t) ssi->ssi_utime;
				info->si_stime = (clock_t) ssi->ssi_stime;
				return;
			case SIGILL:
			case SIGFPE:
			case SIGSEGV:
			case SIGBUS:
			case SIGTRAP:
				info->si_addr = (void *) (uintptr_t) ssi->ssi_addr;
				return;
			case SIGPOLL:
				info->si_band = (long) ssi->ssi_band;
				info->si_fd = ssi->ssi_fd;
				return;
			default:
				break;
		}
	}
	info->si_pid = (pid_t) ssi->ssi_pid;
	info->si_uid = (uid_t) ssi->ssi_uid;
}

/*
 * A readable signalfd: one signal of the set is pending, so take it now
 * (nothing else ior does consumes it). It may be gone if another wait took
 * it first: a second op on the same signal in this context, whose poll the
 * same arrival woke, or a sigwaitinfo(2) of the caller's own. The op then
 * reports -EAGAIN, since its CQE is already out and cannot be re-armed here.
 */
static int32_t ior_uring_collect_signal(const ior_uring_wait *wait)
{
	struct signalfd_siginfo ssi;
	ssize_t n = read(wait->fd, &ssi, sizeof(ssi));
	if (n != (ssize_t) sizeof(ssi)) {
		return n < 0 ? -errno : -EIO;
	}
	if (wait->info) {
		ior_uring_siginfo_from_signalfd(wait->info, &ssi);
	}
	return (int32_t) ssi.ssi_signo;
}

// The waitpid(2) status of what waitid(2) reported.
static int ior_uring_status_from_siginfo(const siginfo_t *si)
{
	switch (si->si_code) {
		case CLD_EXITED:
			return (si->si_status & 0xff) << 8;
		case CLD_KILLED:
			return si->si_status & 0x7f;
		case CLD_DUMPED:
			return (si->si_status & 0x7f) | 0x80;
		case CLD_STOPPED:
		case CLD_TRAPPED:
			return ((si->si_status & 0xff) << 8) | 0x7f;
		case CLD_CONTINUED:
			return 0xffff;
		default:
			return 0;
	}
}

/*
 * Turn the completions of wait records among cqes[] into waitpid and
 * sigwait results, in place (the CQ ring is mapped writable and the kernel
 * never reads a CQE back): a readable pidfd means the child exited, so
 * waitpid(2) collects its state now, on the reaping thread, a readable
 * signalfd is read for its signal, and a WAITID's siginfo becomes the pid and
 * its status; a failed or cancelled op keeps its error. The caller's user data is restored either
 * way and the record retired, so seeing the same CQE again finds nothing to do.
 */
static void ior_uring_resolve_waits(ior_ctx_uring *ctx, struct io_uring_cqe **cqes, unsigned n)
{
	pthread_mutex_lock(&ctx->jobs_lock);
	for (unsigned i = 0;
			i < n && atomic_load_explicit(&ctx->waits_live_count, memory_order_relaxed); i++) {
		struct io_uring_cqe *cqe = cqes[i];
		ior_uring_wait *wait = *ior_uring_wait_bucket(ctx, cqe->user_data);
		while (wait && (uint64_t) (uintptr_t) wait != cqe->user_data) {
			wait = wait->next;
		}
		if (!wait) {
			continue;
		}
		int32_t res = cqe->res;
		switch (wait->kind) {
			case IOR_URING_WAIT_SIG:
				if (res >= 0) {
					res = ior_uring_collect_signal(wait);
				}
				break;
			case IOR_URING_WAIT_PIDFD:
				if (res >= 0) {
					pid_t r = waitpid(wait->pid, wait->status, WNOHANG);
					res = r < 0 ? -errno : r;
				}
				break;
			case IOR_URING_WAIT_WAITID:
				// No si_pid: WNOHANG and nothing changed, as waitpid's 0.
				if (res >= 0) {
					res = wait->si.si_pid;
					if (res > 0 && wait->status) {
						*wait->status = ior_uring_status_from_siginfo(&wait->si);
					}
				}
				break;
			case IOR_URING_WAIT_CANCEL:
				if (res > 0) {
					res = 0;
				}
				break;
			case IOR_URING_WAIT_LT:
				if (res > 0) {
					res = -ETIME;
				}
				break;
		}
		if (wait->fd >= 0) {
			close(wait->fd);
		}
		cqe->user_data = wait->user_data;
		cqe->res = res;
		ior_uring_wait_unlink_locked(ctx, wait);
		free(wait);
	}
	pthread_mutex_unlock(&ctx->jobs_lock);
}

/*
 * Post-process CQEs about to be handed to the caller: pair with the
 * posters' release (see `posted`) and turn pidfd and signalfd poll
 * completions into waitpid and sigwait results.
 */
static void ior_uring_reaped(ior_ctx_uring *ctx, struct io_uring_cqe **cqes, unsigned n)
{
	(void) atomic_load_explicit(&ctx->posted, memory_order_acquire);
	if (atomic_load_explicit(&ctx->waits_live_count, memory_order_relaxed)) {
		ior_uring_resolve_waits(ctx, cqes, n);
	}
}

/*
 * Hand the prepped work jobs this submit takes (those before bound, not in a
 * failed chain) to the pool. Called from submit paths before
 * io_uring_submit() flushes the SQ, while each job's placeholder NOP is still
 * staged: the user may have attached user_data or flags after prep_work, so
 * they are harvested here, and a LINK_TIMEOUT prepped right behind a linked
 * work op is intercepted (the kernel would resolve it against the instantly
 * completing NOP) and rewritten into another skipped NOP; its deadline is
 * handled by the pool's timer thread instead.
 */
static void ior_uring_dispatch_pending(ior_ctx_uring *ctx, unsigned bound)
{
	ior_uring_dispatch_waits(ctx, bound);

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

	ior_uring_job *next;
	for (; job; job = next) {
		next = job->next_pending;
		unsigned at = ior_uring_sq_pos(ctx, job->ksqe);
		if (at - sq->sqe_head >= bound - sq->sqe_head) {
			// Not taken by this submit: stays prepped for the next one.
			job->next_pending = NULL;
			if (ctx->pending_tail) {
				ctx->pending_tail->next_pending = job;
			} else {
				ctx->pending_head = job;
			}
			ctx->pending_tail = job;
			continue;
		}
		if (ctx->sq_any_failed && ctx->sq_failed[at & mask]) {
			/* The kernel fails the placeholder NOP with the rest of its
			 * chain, and that is the op's completion: never run it. */
			free(job);
			continue;
		}
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
					if (kts && kts->tv_sec >= 0 && kts->tv_nsec >= 0) {
						/* Same layout as ior_timespec; the pool's timer runs on
						 * CLOCK_MONOTONIC, so a deadline on another clock is
						 * converted here, at submit. */
						lt_deadline_ns = ior_worker_pool_deadline_ns((const ior_timespec *) kts,
								ior_uring_timeout_flags_from(next->timeout_flags));
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
			if (ior_worker_pool_arm_timer(
						ctx->wp, lt_deadline_ns, ior_uring_lt_fired, ior_uring_lt_dropped, job)
					< 0) {
				job->lt_armed = 0;
				atomic_store(&job->refs, 1);
			}
		}

		pthread_mutex_lock(&ctx->jobs_lock);
		job->live_prev = NULL;
		job->live_next = ctx->jobs_head;
		if (ctx->jobs_head) {
			ctx->jobs_head->live_prev = job;
		}
		ctx->jobs_head = job;
		job->live_linked = 1;
		pthread_mutex_unlock(&ctx->jobs_lock);

		if (job->probe) {
			// First look at once; the probe holds the ref a worker would.
			if (ior_worker_pool_arm_timer(ctx->wp, ior_worker_pool_monotonic_ns(),
						ior_uring_probe_fired, ior_uring_probe_dropped, &job->probe_ns)
					< 0) {
				int expected = IOR_URING_JOB_QUEUED;
				if (atomic_compare_exchange_strong(&job->state, &expected, IOR_URING_JOB_RUNNING)) {
					ior_uring_job_finish(ctx, job, -ENOMEM);
				} else {
					ior_uring_job_release(job);
				}
			}
			continue;
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

	if (count) {
		ior_worker_pool_submit(ctx->wp, first, last, count);
	}
}

/*
 * Cancel one dispatched job per io_uring semantics (jobs_lock held). A job
 * that has not started is taken out of the pool FIFO (or, if a worker just
 * popped it, flagged so the worker skips it) and both its CQEs are posted
 * here; a running one only gets its token flagged (-EALREADY). A cancelled
 * job is pushed on *drop (via next_pending) with the refs it took over, to be
 * released once the lock is gone.
 */
static int ior_uring_cancel_job_locked(ior_ctx_uring *ctx, ior_uring_job *job, ior_uring_job **drop)
{
	int expected = IOR_URING_JOB_QUEUED;
	if (atomic_compare_exchange_strong(&job->state, &expected, IOR_URING_JOB_CANCELLED)) {
		atomic_store_explicit(&job->token.cancelled, 1, memory_order_release);
		ior_uring_job_unlink_locked(ctx, job);
		job->cancel_drop = 0;
		// Off the FIFO (or the probe timer): the worker's ref is ours to
		// drop. Otherwise a worker (the timer) already took it and drops its
		// own ref when it sees CANCELLED.
		int off = job->probe ? ior_worker_pool_cancel_timer(ctx->wp, &job->probe_ns)
							 : ior_worker_pool_cancel_job(ctx->wp, &job->pj);
		if (off == 0) {
			job->cancel_drop++;
		}
		// The link timeout no longer needs to fire.
		if (job->lt_armed && ior_worker_pool_cancel_timer(ctx->wp, job) == 0) {
			job->cancel_drop++;
		}
		atomic_store(&job->lt_posted, 1);
		ior_uring_post_cqe(ctx, job->user_data, -ECANCELED);
		if (job->has_lt) {
			ior_uring_post_cqe(ctx, job->lt_user_data, -ECANCELED);
		}
		job->next_pending = *drop;
		*drop = job;
		return 0;
	}
	if (expected == IOR_URING_JOB_RUNNING) {
		atomic_store_explicit(&job->token.cancelled, 1, memory_order_release);
		return -EALREADY;
	}
	return -ENOENT;
}

/*
 * Resolve staged ASYNC_CANCEL sqes against the dispatched work jobs, which
 * the kernel cannot see. A cancel by user data that matches a job is
 * executed here: its sqe becomes a skipped NOP and its result is posted
 * through the poster ring. Cancels by fd never match a job. Runs on the
 * submitter thread while the SQ is still staged.
 */
static void ior_uring_intercept_cancels(ior_ctx_uring *ctx, unsigned bound)
{
	struct io_uring_sq *sq = &ctx->ring.sq;
	unsigned mask = sq->ring_entries - 1;

	for (unsigned pos = sq->sqe_head; pos != bound; pos++) {
		struct io_uring_sqe *s = &sq->sqes[pos & mask];
		if (s->opcode != IORING_OP_ASYNC_CANCEL
				|| (ctx->sq_any_failed && ctx->sq_failed[pos & mask])) {
			continue;
		}
		if (s->cancel_flags & IORING_ASYNC_CANCEL_FD) {
			continue;
		}
		uint64_t key = s->addr;

		int ret = -ENOENT;
		ior_uring_job *drop = NULL;
		pthread_mutex_lock(&ctx->jobs_lock);
		for (ior_uring_job *job = ctx->jobs_head; job; job = job->live_next) {
			if (job->user_data != key) {
				continue;
			}
			ret = ior_uring_cancel_job_locked(ctx, job, &drop);
			if (ret != -ENOENT) {
				break;
			}
		}
		if (ret == -ENOENT) {
			// A pidfd or signalfd wait is a kernel op under its record's
			// key: retarget the cancel and let the kernel resolve it.
			size_t nb = sizeof(ctx->waits_live) / sizeof(ctx->waits_live[0]);
			ior_uring_wait *found = NULL;
			for (size_t b = 0; b < nb && !found; b++) {
				for (ior_uring_wait *wait = ctx->waits_live[b]; wait; wait = wait->next) {
					if (wait->user_data == key) {
						found = wait;
						break;
					}
				}
			}
			if (found) {
				s->addr = (uint64_t) (uintptr_t) found;
				if (found->kind == IOR_URING_WAIT_WAITID) {
					ior_uring_wait_fixup_locked(ctx, s, IOR_URING_WAIT_CANCEL);
				}
			}
		}
		pthread_mutex_unlock(&ctx->jobs_lock);

		// Drop the refs of jobs that will never be run or timed now.
		while (drop) {
			ior_uring_job *j = drop;
			drop = j->next_pending;
			int n = j->cancel_drop; // the last release frees j
			for (int i = 0; i < n; i++) {
				ior_uring_job_release(j);
			}
		}

		if (ret == -ENOENT) {
			continue; // no job matched: the kernel handles it
		}

		uint64_t user_data = s->user_data;
		io_uring_prep_nop(s);
		s->flags |= IOSQE_CQE_SKIP_SUCCESS;
		s->user_data = 0;
		ior_uring_post_cqe(ctx, user_data, ret);
	}
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
	ctx->notify_fd = -1;
	atomic_init(&ctx->shutdown, 0);
	atomic_init(&ctx->posted, 0);
	atomic_init(&ctx->waits_live_count, 0);

	if (pthread_mutex_init(&ctx->poster_lock, NULL) != 0) {
		free(ctx);
		return -ENOMEM;
	}
	if (pthread_mutex_init(&ctx->jobs_lock, NULL) != 0) {
		pthread_mutex_destroy(&ctx->poster_lock);
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
		pthread_mutex_destroy(&ctx->jobs_lock);
		pthread_mutex_destroy(&ctx->poster_lock);
		free(ctx);
		return ret;
	}

	// Set features. IORING_OP_POLL_ADD exists on every supported kernel.
	ctx->features = IOR_FEAT_NATIVE_ASYNC | IOR_FEAT_POLL_ADD | IOR_FEAT_SPLICE;

	/*
	 * Work ops need CQE_SKIP (5.17) + MSG_RING (5.18) and cancel by
	 * descriptor needs ASYNC_CANCEL_FD (5.19). Refuse an older kernel with
	 * -ENOSYS so AUTO falls back to the thread backend. This also implies
	 * FEAT_EXT_ARG (5.11): liburing never injects internal timeout CQEs.
	 */
	int kernel_ok = 0;
	if (uring_params.features & IORING_FEAT_CQE_SKIP) {
		struct io_uring_probe *probe = io_uring_get_probe_ring(&ctx->ring);
		if (probe) {
			kernel_ok = io_uring_opcode_supported(probe, IORING_OP_MSG_RING);
#ifdef IOR_HAVE_URING_WAITID
			ctx->has_waitid = io_uring_opcode_supported(probe, IORING_OP_WAITID);
#endif
			io_uring_free_probe(probe);
		}
	}
	if (kernel_ok) {
		/*
		 * Before 5.19 the flag is rejected with -EINVAL; after it the empty
		 * ring reports no match (-ENOENT).
		 */
		struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
		struct io_uring_cqe *cqe;
		kernel_ok = 0;
		if (sqe) {
			io_uring_prep_cancel_fd(sqe, 0, 0);
			if (io_uring_submit_and_wait(&ctx->ring, 1) == 1
					&& io_uring_peek_cqe(&ctx->ring, &cqe) == 0) {
				kernel_ok = cqe->res != -EINVAL;
				io_uring_cqe_seen(&ctx->ring, cqe);
			}
		}
	}
	if (!kernel_ok) {
		io_uring_queue_exit(&ctx->ring);
		pthread_mutex_destroy(&ctx->jobs_lock);
		pthread_mutex_destroy(&ctx->poster_lock);
		free(ctx);
		return -ENOSYS;
	}
	ctx->features |= IOR_FEAT_WORK;

	ctx->sq_failed = calloc(ctx->ring.sq.ring_entries, 1);
	if (!ctx->sq_failed) {
		io_uring_queue_exit(&ctx->ring);
		pthread_mutex_destroy(&ctx->jobs_lock);
		pthread_mutex_destroy(&ctx->poster_lock);
		free(ctx);
		return -ENOMEM;
	}

	ctx->sq_entries = uring_params.sq_entries;
	ctx->cq_entries = uring_params.cq_entries;
	params->sq_entries = ctx->sq_entries;
	params->cq_entries = ctx->cq_entries;
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
		// No poster is left: deliver what is queued, free the rest.
		ior_uring_poster_flush_locked(ctx);
		while (ctx->post_head) {
			ior_uring_post *post = ctx->post_head;
			ctx->post_head = post->next;
			free(post);
		}
		io_uring_queue_exit(&ctx->poster);
	}

	// Work ops prepped but never submitted: their callbacks never run.
	ior_uring_job *job = ctx->pending_head;
	while (job) {
		ior_uring_job *next = job->next_pending;
		free(job);
		job = next;
	}

	// Pidfd and signalfd waits, submitted or not: their completions are
	// never reaped.
	ior_uring_wait *wait = ctx->waits_pending;
	while (wait) {
		ior_uring_wait *next = wait->next;
		if (wait->fd >= 0) {
			close(wait->fd);
		}
		free(wait);
		wait = next;
	}
	for (size_t b = 0; b < sizeof(ctx->waits_live) / sizeof(ctx->waits_live[0]); b++) {
		wait = ctx->waits_live[b];
		while (wait) {
			ior_uring_wait *next = wait->next;
#ifdef IOR_HAVE_URING_WAITID
			/* The kernel writes a WAITID's siginfo even when it cancels it,
			 * and the ring's own teardown cancels asynchronously: cancel it
			 * now, which returns once it completed (or finds it done). */
			if (wait->kind == IOR_URING_WAIT_WAITID) {
				struct io_uring_sync_cancel_reg reg;
				memset(&reg, 0, sizeof(reg));
				reg.addr = (uint64_t) (uintptr_t) wait;
				reg.timeout.tv_sec = -1;
				reg.timeout.tv_nsec = -1;
				(void) io_uring_register_sync_cancel(&ctx->ring, &reg);
			}
#endif
			if (wait->fd >= 0) {
				close(wait->fd);
			}
			free(wait);
			wait = next;
		}
	}

	if (ctx->notify_fd >= 0) {
		io_uring_unregister_eventfd(&ctx->ring);
		close(ctx->notify_fd);
	}
	pthread_mutex_destroy(&ctx->jobs_lock);
	pthread_mutex_destroy(&ctx->poster_lock);
	io_uring_queue_exit(&ctx->ring);
	free(ctx->sq_failed);
	free(ctx);
}

static int ior_uring_backend_get_sqe(void *backend_ctx, ior_sqe **sqe_out)
{
	if (!backend_ctx) {
		return -EINVAL;
	}

	ior_ctx_uring *ctx = backend_ctx;
	/*
	 * A full CQ is refused rather than overflowed: the kernel would buffer
	 * the completions, but off the ring and on a slow path, and the other
	 * backends refuse here too. Reaping makes room.
	 */
	if (io_uring_cq_ready(&ctx->ring) >= ctx->cq_entries) {
		return -EBUSY;
	}
	struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
	if (!sqe) {
		return -ENOSPC;
	}
	memset(sqe, 0, sizeof(*sqe));
	*sqe_out = (ior_sqe *) sqe;
	return 0;
}

static unsigned ior_uring_backend_sq_entries(void *backend_ctx)
{
	return ((ior_ctx_uring *) backend_ctx)->sq_entries;
}

static unsigned ior_uring_backend_cq_entries(void *backend_ctx)
{
	return ((ior_ctx_uring *) backend_ctx)->cq_entries;
}

static unsigned ior_uring_backend_sq_space_left(void *backend_ctx)
{
	return io_uring_sq_space_left(&((ior_ctx_uring *) backend_ctx)->ring);
}

static unsigned ior_uring_backend_cq_space_left(void *backend_ctx)
{
	ior_ctx_uring *ctx = backend_ctx;
	unsigned ready = io_uring_cq_ready(&ctx->ring);
	return ready < ctx->cq_entries ? ctx->cq_entries - ready : 0;
}

static int ior_uring_backend_submit_and_wait(void *backend_ctx, unsigned wait_nr)
{
	if (!backend_ctx) {
		return -EINVAL;
	}

	ior_ctx_uring *ctx = backend_ctx;
	struct io_uring_sq *sq = &ctx->ring.sq;
	unsigned tail = sq->sqe_tail;
	unsigned bound = ior_uring_scan_staged(ctx);

	// Work jobs and pidfd/signalfd waits must be harvested while their
	// placeholder SQEs are still staged; cancels then see the ops submitted
	// just before them.
	ior_uring_dispatch_pending(ctx, bound);
	if (ctx->wp || atomic_load(&ctx->waits_live_count)) {
		ior_uring_intercept_cancels(ctx, bound);
	}

	/*
	 * Publish only what the kernel will take, so it cannot run past entries
	 * whose userspace side was held back. With entries left over it would
	 * have stopped short and not waited; the bound makes that explicit.
	 */
	if (bound != tail) {
		wait_nr = 0;
	}
	if (wait_nr) {
		ior_uring_poster_retry(ctx);
	}
	int slow = wait_nr && atomic_load(&ctx->post_queued);
	unsigned head = sq->sqe_head;
	sq->sqe_tail = bound;
	int ret = io_uring_submit_and_wait(&ctx->ring, slow ? 0 : wait_nr);
	sq->sqe_tail = tail;
	if (ctx->sq_any_failed) {
		// Marks are only set on a failed chain; drop them with it.
		for (unsigned q = head; q != bound; q++) {
			ctx->sq_failed[q & (sq->ring_entries - 1)] = 0;
		}
		ctx->sq_any_failed = 0;
	}
	if (slow && ret >= 0) {
		// A refused post is queued: wait in slices that retry it.
		struct io_uring_cqe *cqe;
		int waited = ior_uring_wait_cqes(ctx, &cqe, wait_nr, NULL);
		if (waited < 0 && ret == 0) {
			return waited;
		}
	}
	return ret;
}

static int ior_uring_backend_submit(void *backend_ctx)
{
	return ior_uring_backend_submit_and_wait(backend_ctx, 0);
}

static int ior_uring_backend_peek_cqe(void *backend_ctx, ior_cqe **cqe_out)
{
	if (!backend_ctx || !cqe_out) {
		return -EINVAL;
	}

	ior_ctx_uring *ctx = backend_ctx;
	struct io_uring_cqe *cqe;
	ior_uring_poster_retry(ctx);
	int ret = io_uring_peek_cqe(&ctx->ring, &cqe);

	if (ret < 0) {
		return ret;
	}

	ior_uring_reaped(ctx, &cqe, 1);
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
	// The inline peek of io_uring_wait_cqe unless a post is held back.
	int ret = atomic_load_explicit(&ctx->post_live, memory_order_relaxed)
			? ior_uring_wait_cqes(ctx, &cqe, 1, NULL)
			: io_uring_wait_cqe(&ctx->ring, &cqe);

	if (ret < 0) {
		return ret;
	}

	ior_uring_reaped(ctx, &cqe, 1);
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

	int ret;
	if (timeout && !atomic_load_explicit(&ctx->post_live, memory_order_relaxed)) {
		uint64_t ns = ior_timespec_ns(timeout);
		struct __kernel_timespec kts = {
			.tv_sec = (long long) (ns / 1000000000ULL),
			.tv_nsec = (long long) (ns % 1000000000ULL),
		};
		ret = io_uring_wait_cqe_timeout(&ctx->ring, &cqe, &kts);
	} else {
		ret = ior_uring_wait_cqes(ctx, &cqe, 1, timeout);
	}

	if (ret < 0) {
		return ret;
	}

	ior_uring_reaped(ctx, &cqe, 1);
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
	ior_uring_poster_retry(ctx);
	unsigned n = io_uring_peek_batch_cqe(&ctx->ring, uring_cqes, max);
	if (n) {
		ior_uring_reaped(ctx, uring_cqes, n);
	}
	return n;
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
	if (flags & IOR_TIMEOUT_BOOTTIME) {
		uflags |= IORING_TIMEOUT_BOOTTIME;
	}
	if (flags & IOR_TIMEOUT_REALTIME) {
		uflags |= IORING_TIMEOUT_REALTIME;
	}
	return uflags;
}

// The reverse, for a LINK_TIMEOUT intercepted at submit (see dispatch_pending).
static unsigned ior_uring_timeout_flags_from(unsigned uflags)
{
	unsigned flags = 0;
	if (uflags & IORING_TIMEOUT_ABS) {
		flags |= IOR_TIMEOUT_ABS;
	}
	if (uflags & IORING_TIMEOUT_BOOTTIME) {
		flags |= IOR_TIMEOUT_BOOTTIME;
	}
	if (uflags & IORING_TIMEOUT_REALTIME) {
		flags |= IOR_TIMEOUT_REALTIME;
	}
	return flags;
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

/* The kernel's own flag marks the edge completions of a multishot poll. */
_Static_assert(IOR_CQE_F_MORE == IORING_CQE_F_MORE, "IOR_CQE_F_MORE must match");
_Static_assert(IOR_POLL_ADD_MULTI == IORING_POLL_ADD_MULTI, "IOR_POLL_ADD_MULTI must match");

static void ior_uring_backend_prep_poll_multishot(ior_sqe *sqe, ior_fd_t fd, uint32_t poll_mask)
{
	struct io_uring_sqe *s = &sqe->uring.sqe;
	io_uring_prep_poll_multishot(s, (int) fd, poll_mask);
}

/* IOR_ACCEPT_* equal SOCK_* on Linux, so the flags pass through. */
_Static_assert(IOR_ACCEPT_NONBLOCK == SOCK_NONBLOCK, "IOR_ACCEPT_NONBLOCK must match");
_Static_assert(IOR_ACCEPT_CLOEXEC == SOCK_CLOEXEC, "IOR_ACCEPT_CLOEXEC must match");

static void ior_uring_backend_prep_accept(
		ior_sqe *sqe, ior_fd_t fd, struct sockaddr *addr, socklen_t *addrlen, unsigned flags)
{
	struct io_uring_sqe *s = &sqe->uring.sqe;
	io_uring_prep_accept(s, (int) fd, addr, addrlen, (int) flags);
}

static void ior_uring_backend_prep_connect(
		ior_sqe *sqe, ior_fd_t fd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct io_uring_sqe *s = &sqe->uring.sqe;
	io_uring_prep_connect(s, (int) fd, addr, addrlen);
}

static void ior_uring_backend_prep_cancel(ior_sqe *sqe, uint64_t user_data)
{
	struct io_uring_sqe *s = &sqe->uring.sqe;
	io_uring_prep_cancel64(s, user_data, 0);
}

// Cancel by descriptor needs kernel 5.19+ (checked at configure time).
static void ior_uring_backend_prep_cancel_fd(ior_sqe *sqe, ior_fd_t fd)
{
	struct io_uring_sqe *s = &sqe->uring.sqe;
	// io_uring uses int fd - cast from ior_fd_t (which is int on Linux)
	io_uring_prep_cancel_fd(s, (int) fd, 0);
}

/*
 * Prep a job that runs fn(arg) on the worker pool. The kernel never
 * executes the callback; its SQE becomes a placeholder NOP whose successful
 * completion is skipped, keeping SQ accounting (and the submit() return
 * count) consistent. The job itself is dispatched to the worker pool when
 * submit() flushes the queue.
 */
static int ior_uring_job_new(
		ior_ctx_uring *ctx, struct io_uring_sqe *s, ior_work_fn fn, void *arg, ior_uring_job **out)
{
	int ret = ior_uring_work_ensure(ctx);
	if (ret < 0) {
		return ret;
	}

	ior_uring_job *job = calloc(1, sizeof(*job));
	if (!job) {
		return -ENOMEM;
	}

	io_uring_prep_nop(s);
	s->flags |= IOSQE_CQE_SKIP_SUCCESS;

	job->ctx = ctx;
	job->fn = fn;
	job->arg = arg;
	job->ksqe = s;
	atomic_init(&job->state, IOR_URING_JOB_QUEUED);
	atomic_init(&job->refs, 1);
	atomic_init(&job->lt_posted, 0);
	atomic_init(&job->token.cancelled, 0);
	job->token.shutdown = &ctx->shutdown;

	job->next_pending = NULL;
	if (ctx->pending_tail) {
		ctx->pending_tail->next_pending = job;
	} else {
		ctx->pending_head = job;
	}
	ctx->pending_tail = job;

	*out = job;
	return 0;
}

static int ior_uring_backend_prep_work(void *backend_ctx, ior_sqe *sqe, ior_work_fn fn, void *arg)
{
	ior_uring_job *job;
	return ior_uring_job_new(backend_ctx, &sqe->uring.sqe, fn, arg, &job);
}

/*
 * Prep a POLL_ADD for readability of fd (a pidfd or signalfd) keyed, from
 * submit on, by a wait record that turns its completion into the op's
 * result. The record owns fd.
 */
static ior_uring_wait *ior_uring_wait_new(ior_ctx_uring *ctx, struct io_uring_sqe *s, int fd)
{
	ior_uring_wait *wait = calloc(1, sizeof(*wait));
	if (!wait) {
		return NULL;
	}
	wait->kind = IOR_URING_WAIT_PIDFD;
	wait->fd = fd;
	wait->ksqe = s;
	io_uring_prep_poll_add(s, fd, POLLIN);
	wait->next = ctx->waits_pending;
	ctx->waits_pending = wait;
	return wait;
}

/*
 * A signalfd for the set, polled for readability: the kernel wakes the poll
 * when a signal of the set is queued for the process (or for the polling
 * thread), and a signal pending already reads as ready at once. The signal
 * itself is read on the reaping thread, see ior_uring_collect_signal.
 */
static int ior_uring_backend_prep_sigwait(
		void *backend_ctx, ior_sqe *sqe, const ior_sigset_t *set, ior_siginfo_t *info)
{
	ior_ctx_uring *ctx = backend_ctx;
	struct io_uring_sqe *s = &sqe->uring.sqe;

	int sfd = signalfd(-1, set, SFD_NONBLOCK | SFD_CLOEXEC);
	if (sfd < 0) {
		return -errno;
	}
	ior_uring_wait *wait = ior_uring_wait_new(ctx, s, sfd);
	if (!wait) {
		close(sfd);
		return -ENOMEM;
	}
	wait->kind = IOR_URING_WAIT_SIG;
	wait->info = info;
	return 0;
}

// Never run: a probed wait's job goes to the timer, not to a worker.
static int32_t ior_uring_waitpid_job(ior_work_token *token, void *arg)
{
	(void) token;
	(void) arg;
	return -EINVAL;
}

/*
 * Every wait the kernel can do goes to IORING_OP_WAITID where it has one
 * (6.7): no thread, and a cancel or a link timeout takes it back without
 * reaping. Otherwise one child with nothing else asked gets a pidfd poll,
 * which does the same, and anything else (any child, a group, WNOHANG, job
 * control, no pidfd) is probed from the timer thread (see
 * ior_uring_probe_fired). Nothing is consumed here: prep has no completion
 * to carry an answer, and an op that is never submitted, or fails to prep,
 * must leave the child as it found it.
 */
static int ior_uring_backend_prep_waitpid(
		void *backend_ctx, ior_sqe *sqe, ior_pid_t pid, int *status, int options)
{
	ior_ctx_uring *ctx = backend_ctx;
	struct io_uring_sqe *s = &sqe->uring.sqe;

#ifdef IOR_HAVE_URING_WAITID
	if (ctx->has_waitid && pid != INT_MIN) {
		// waitpid's pid as waitid's: 0 is the caller's own group.
		idtype_t idtype = pid > 0 ? P_PID : pid == -1 ? P_ALL : P_PGID;
		id_t id = pid > 0 ? (id_t) pid : pid < -1 ? (id_t) -pid : 0;
		ior_uring_wait *wait = calloc(1, sizeof(*wait));
		if (!wait) {
			return -ENOMEM;
		}
		wait->kind = IOR_URING_WAIT_WAITID;
		wait->fd = -1;
		wait->status = status;
		wait->ksqe = s;
		// WUNTRACED is WSTOPPED; waitid asks for exits explicitly.
		io_uring_prep_waitid(s, idtype, id, &wait->si, options | WEXITED, 0);
		wait->next = ctx->waits_pending;
		ctx->waits_pending = wait;
		return 0;
	}
#endif

#ifdef IOR_HAVE_PIDFD_OPEN
	if (pid > 0 && options == 0) {
		/*
		 * Is it a child at all? pidfd_open watches any process, and a poll
		 * on one that is nobody's child would never answer -ECHILD; asked
		 * with WNOWAIT the question reaps nothing, so an exited child stays
		 * collectable (its pidfd is readable at once).
		 */
		siginfo_t info;
		memset(&info, 0, sizeof(info));
		int pidfd = waitid(P_PID, (id_t) pid, &info, WEXITED | WNOHANG | WNOWAIT) == 0
				? (int) syscall(SYS_pidfd_open, pid, 0)
				: -1;
		if (pidfd >= 0) {
			ior_uring_wait *wait = ior_uring_wait_new(ctx, s, pidfd);
			if (!wait) {
				close(pidfd);
				return -ENOMEM;
			}
			wait->pid = pid;
			wait->status = status;
			return 0;
		}
	}
#endif

	ior_uring_job *job;
	int ret = ior_uring_job_new(ctx, s, ior_uring_waitpid_job, NULL, &job);
	if (ret < 0) {
		return ret;
	}
	job->arg = job;
	job->wait_pid = pid;
	job->wait_status = status;
	job->wait_options = options;
	job->probe = 1;
	job->probe_ns = IOR_WAITPID_PROBE_MIN_NS;
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

/*
 * Completion notification: an eventfd the kernel signals for every CQE,
 * including those the poster ring injects with MSG_RING. Registered lazily.
 */

static ior_fd_t ior_uring_backend_notify_fd(void *backend_ctx)
{
	if (!backend_ctx) {
		return IOR_INVALID_FD;
	}
	ior_ctx_uring *ctx = backend_ctx;
	if (ctx->notify_fd >= 0) {
		return ctx->notify_fd;
	}

	int efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (efd < 0) {
		return IOR_INVALID_FD;
	}
	if (io_uring_register_eventfd(&ctx->ring, efd) < 0) {
		close(efd);
		return IOR_INVALID_FD;
	}
	ctx->notify_fd = efd;

	// Completions posted before the registration are not announced by the
	// kernel; signal once for them so the caller's first wait sees them,
	// as it would on the other backends.
	if (io_uring_cq_ready(&ctx->ring) > 0) {
		uint64_t one = 1;
		(void) !write(efd, &one, sizeof(one));
	}
	return efd;
}

static int ior_uring_backend_notify_clear(void *backend_ctx)
{
	if (!backend_ctx) {
		return -EINVAL;
	}
	ior_ctx_uring *ctx = backend_ctx;
	if (ctx->notify_fd < 0) {
		return -EINVAL;
	}
	uint64_t val;
	if (read(ctx->notify_fd, &val, sizeof(val)) < 0 && errno != EAGAIN) {
		return -errno;
	}
	return 0;
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
	.prep_poll_multishot = ior_uring_backend_prep_poll_multishot,
	.prep_accept = ior_uring_backend_prep_accept,
	.prep_checked = ior_uring_backend_prep_checked,
	.prep_connect = ior_uring_backend_prep_connect,
	.prep_cancel = ior_uring_backend_prep_cancel,
	.prep_cancel_fd = ior_uring_backend_prep_cancel_fd,
	.prep_waitpid = ior_uring_backend_prep_waitpid,
	.prep_sigwait = ior_uring_backend_prep_sigwait,
	.prep_work = ior_uring_backend_prep_work,
	.sqe_set_data = ior_uring_backend_sqe_set_data,
	.sqe_set_flags = ior_uring_backend_sqe_set_flags,
	.cqe_get_data = ior_uring_backend_cqe_get_data,
	.cqe_get_res = ior_uring_backend_cqe_get_res,
	.cqe_get_flags = ior_uring_backend_cqe_get_flags,
	.notify_fd = ior_uring_backend_notify_fd,
	.notify_clear = ior_uring_backend_notify_clear,
	.backend_name = ior_uring_backend_name,
	.get_features = ior_uring_backend_get_features,
	.sq_entries = ior_uring_backend_sq_entries,
	.cq_entries = ior_uring_backend_cq_entries,
	.sq_space_left = ior_uring_backend_sq_space_left,
	.cq_space_left = ior_uring_backend_cq_space_left,
};

#endif /* IOR_HAVE_URING */
