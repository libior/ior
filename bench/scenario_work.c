/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * scenario_work.c - user work callbacks (IOR_OP_WORK) at a target queue depth.
 *
 * Keeps `depth` work operations in flight; each callback spins on the backend's
 * worker pool for --work-us microseconds of CPU time and returns a per-slot
 * value that the harvester verifies, so a misrouted argument or result under
 * load is caught as a correctness error, not just a perf blip. This stresses
 * the pool's dispatch/completion path with pure userspace jobs - no I/O - and
 * its scaling when the queue is deeper than the worker count.
 *
 * With --timer linked every work op is guarded by a generous link timeout,
 * mirroring how a caller would bound a user job: the callback polls its
 * cancellation token while spinning, so a guard that fires (an anomaly at
 * these timeouts) surfaces both as a -ETIME timeout CQE and as a -ECANCELED
 * work result, and both are counted as errors.
 */
#include "bench_platform.h"
#include "bench_scenario.h"
#include "bench_trace.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Tag layout: slot index shifted over one kind bit (work op vs link timeout). */
enum {
	WORK_OP = 0,
	WORK_LINK_TIMEOUT = 1,
	WORK_KIND_BITS = 1,
	WORK_KIND_MASK = (1u << WORK_KIND_BITS) - 1,
};

typedef struct work_slot {
	uint32_t idx; /* this slot's index; the callback returns idx + 1 */
	uint32_t spin_us; /* CPU time the callback burns before returning */
	uint64_t start_ns;
} work_slot;

typedef struct work_ctx {
	ior_ctx *ior;
	const bench_options *opts;
	bench_metrics *m;
	work_slot *slots;
	uint32_t depth;
	ior_timespec timeout;
	int linked;
	uint64_t inflight; /* work ops + link timeouts not yet reaped */
	uint64_t completed;
	uint32_t *free_slots; /* stack of slot indices not currently in flight */
	uint32_t free_count;
	int draining;
} work_ctx;

/*
 * The benchmarked callback: burn spin_us of CPU on the pool thread, polling the
 * cancellation token so a fired guard (or teardown) is honoured promptly, then
 * report this slot's distinct result.
 */
static int32_t work_spin_fn(ior_work_token *token, void *arg)
{
	work_slot *s = arg;
	uint64_t end_ns = bench_now_ns() + (uint64_t) s->spin_us * 1000;

	while (bench_now_ns() < end_ns) {
		if (ior_work_cancelled(token)) {
			return -ECANCELED;
		}
	}
	return (int32_t) (s->idx + 1);
}

/* Try to issue one work op (guarded when linked) from a free slot; returns 0
 * if the SQ is momentarily full so the caller harvests completions and
 * retries (io_uring NULL-SQE handling). */
static int issue_one(work_ctx *w)
{
	if (w->free_count == 0) {
		return 0;
	}
	ior_sqe *sqe = ior_get_sqe(w->ior);
	if (!sqe) {
		return 0;
	}

	uint32_t si = w->free_slots[--w->free_count];
	work_slot *s = &w->slots[si];
	s->start_ns = bench_now_ns();

	ior_prep_work(w->ior, sqe, work_spin_fn, s);
	ior_sqe_set_data(w->ior, sqe, (void *) (((uintptr_t) si << WORK_KIND_BITS) | WORK_OP));
	w->inflight++;

	if (w->linked) {
		ior_sqe *lsqe = ior_get_sqe(w->ior);
		if (lsqe) {
			ior_sqe_set_flags(w->ior, sqe, IOR_SQE_IO_LINK);
			ior_prep_link_timeout(w->ior, lsqe, &w->timeout, 0);
			ior_sqe_set_data(w->ior, lsqe,
					(void *) (((uintptr_t) si << WORK_KIND_BITS) | WORK_LINK_TIMEOUT));
			w->inflight++;
		}
		/* else: only one slot was free - run this op unguarded rather than
		 * leaving a dangling IO_LINK. Rare, under transient SQ pressure. */
	}

	BENCH_TRACE2("issue slot=%llu inflight=%llu", si, w->inflight);
	return 1;
}

static void harvest_one(work_ctx *w, ior_cqe *cqe)
{
	void *data = ior_cqe_get_data(w->ior, cqe);
	uint32_t si = (uint32_t) ((uintptr_t) data >> WORK_KIND_BITS);
	unsigned kind = (unsigned) ((uintptr_t) data & WORK_KIND_MASK);
	int32_t res = ior_cqe_get_res(w->ior, cqe);

	w->inflight--;
	BENCH_TRACE3("cqe slot=%llu kind=%llu res=%lld", si, kind, (int64_t) res);

	if (kind == WORK_LINK_TIMEOUT) {
		/* Normal: the callback finished first and the guard was cancelled.
		 * -ETIME means the deadline fired - an anomaly given the generous
		 * timeout. The slot is recycled by the work op's own CQE. */
		if (res != -ECANCELED) {
			bench_metrics_error(w->m);
		}
		return;
	}

	if (res == (int32_t) (si + 1)) {
		bench_metrics_record(w->m, bench_now_ns() - w->slots[si].start_ns, 0);
		w->completed++;
	} else {
		bench_metrics_error(w->m);
	}
	w->free_slots[w->free_count++] = si;
}

static int run_loop(work_ctx *w)
{
	const bench_options *o = w->opts;
	uint64_t deadline_ns = o->ops ? 0 : bench_now_ns() + (uint64_t) (o->duration_s * 1e9);
	ior_cqe *batch[256];

	while (1) {
		/* Harvest completions (frees slots, drains the CQ). */
		unsigned n = ior_peek_batch_cqe(w->ior, batch, 256);
		for (unsigned i = 0; i < n; i++) {
			harvest_one(w, batch[i]);
		}
		if (n > 0) {
			ior_cq_advance(w->ior, n);
		}

		if (!w->draining) {
			int done = o->ops ? (w->completed >= o->ops) : (bench_now_ns() >= deadline_ns);
			if (done) {
				w->draining = 1;
				bench_metrics_stop(w->m);
			}
		}

		/* Refill to depth; issue_one() stops if the SQ is momentarily full. */
		if (!w->draining) {
			while (issue_one(w)) { }
		}

		/* Publish refilled ops, then terminate or block for progress. */
		ior_submit(w->ior);

		if (w->draining && w->inflight == 0) {
			break;
		}
		if (n == 0 && w->inflight > 0) {
			ior_cqe *cqe = NULL;
			int ret = BENCH_WAIT_CQE(w->ior, &cqe, w->completed);
			if (ret < 0 && ret != -EAGAIN && ret != -EINTR && ret != -ETIME) {
				return ret;
			}
		}
	}
	return 0;
}

int bench_run_work(const bench_options *opts, bench_metrics *m, const char **backend_name_out)
{
	int ret = 0;
	work_ctx w;
	memset(&w, 0, sizeof(w));
	w.opts = opts;
	w.m = m;
	w.depth = opts->depth ? opts->depth : 64;
	w.linked = (opts->timer_mode == BENCH_TIMER_LINKED);
	w.timeout.tv_sec = opts->timeout_ms / 1000;
	w.timeout.tv_nsec = (long long) (opts->timeout_ms % 1000) * 1000000LL;

	uint32_t sq = opts->sq_entries;
	/* Guarded ops take two SQEs each. */
	if (sq < w.depth * (w.linked ? 4 : 2)) {
		sq = w.depth * (w.linked ? 4 : 2);
	}
	if (sq < 256) {
		sq = 256;
	}

	ret = ior_queue_init(sq, &w.ior);
	if (ret < 0) {
		return ret;
	}
	if (backend_name_out) {
		*backend_name_out = ior_get_backend_name(w.ior);
	}

	w.slots = calloc(w.depth, sizeof(*w.slots));
	w.free_slots = calloc(w.depth, sizeof(*w.free_slots));
	if (!w.slots || !w.free_slots) {
		ret = -ENOMEM;
		goto out;
	}
	for (uint32_t i = 0; i < w.depth; i++) {
		w.slots[i].idx = i;
		w.slots[i].spin_us = opts->work_us;
		w.free_slots[w.free_count++] = i; /* all slots free; refill issues them */
	}

	bench_metrics_start(m);
	ret = run_loop(&w);
	if (m->wall_end_ns == 0) {
		bench_metrics_stop(m);
	}

out:
	free(w.slots);
	free(w.free_slots);
	ior_queue_exit(w.ior);
	return ret;
}
