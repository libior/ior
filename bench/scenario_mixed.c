/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * scenario_mixed.c - mixed operation blend at a target queue depth.
 *
 * Keeps `depth` operations in flight, cycling each completion slot through
 * read, write, nop and timeout. This deliberately drives all three completion
 * sources at once - worker threads (read/write), the immediate path (nop) and
 * the timer thread (timeout) - so completions are posted into the queue
 * concurrently from several producers. It is the heaviest stress on the
 * multi-producer completion path and a scaled-up sibling of test_concurrency,
 * but as a throughput/latency benchmark rather than a pass/fail test.
 *
 * (Socket I/O has its own dedicated scenario; mixing real connections in here
 * would add ordering constraints that obscure the completion-path stress.)
 */
#include "bench_platform.h"
#include "bench_scenario.h"
#include "bench_trace.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum {
	MIX_READ = 0,
	MIX_WRITE = 1,
	MIX_NOP = 2,
	MIX_TIMEOUT = 3,
	MIX_KINDS = 4,
	MIX_KIND_BITS = 2,
	MIX_KIND_MASK = (1u << MIX_KIND_BITS) - 1,
};

typedef struct mix_slot {
	unsigned kind;
	uint64_t start_ns;
	char *buf;
} mix_slot;

typedef struct mix_ctx {
	ior_ctx *ior;
	const bench_options *opts;
	bench_metrics *m;
	ior_fd_t *files;
	uint32_t nfiles;
	mix_slot *slots;
	uint32_t depth;
	uint32_t block;
	uint64_t max_off;
	uint64_t inflight;
	uint64_t completed;
	uint64_t op_counter;
	uint32_t *free_slots; /* stack of slot indices not currently in flight */
	uint32_t free_count;
	int draining;
} mix_ctx;

/* Zero relative timeout: fires immediately, exercising the timer path without
 * adding wall-clock delay. File-scope so the pointer handed to ior_prep_timeout
 * stays valid until the op is submitted/processed (both backends keep it). */
static ior_timespec bench_zero_timeout = { 0, 0 };

/* Try to issue one op from a free slot; returns 0 if the SQ is momentarily
 * full so the caller harvests completions and retries (io_uring NULL-SQE
 * handling) rather than assuming get_sqe always succeeds. */
static int issue_one(mix_ctx *x)
{
	if (x->free_count == 0) {
		return 0;
	}
	ior_sqe *sqe = ior_get_sqe(x->ior);
	if (!sqe) {
		return 0;
	}

	uint32_t si = x->free_slots[--x->free_count];
	mix_slot *s = &x->slots[si];
	uint64_t n = x->op_counter++;
	s->kind = (unsigned) (n % MIX_KINDS);
	s->start_ns = bench_now_ns();

	void *tag = (void *) (((uintptr_t) si << MIX_KIND_BITS) | s->kind);

	switch (s->kind) {
		case MIX_READ:
		case MIX_WRITE: {
			uint32_t fi = (uint32_t) (n % x->nfiles);
			uint64_t pos
					= x->max_off ? ((n / x->nfiles) % (x->max_off / x->block + 1)) * x->block : 0;
			if (s->kind == MIX_WRITE) {
				ior_prep_write(x->ior, sqe, x->files[fi], s->buf, x->block, pos);
			} else {
				ior_prep_read(x->ior, sqe, x->files[fi], s->buf, x->block, pos);
			}
			break;
		}
		case MIX_NOP:
			ior_prep_nop(x->ior, sqe);
			break;
		case MIX_TIMEOUT:
			ior_prep_timeout(x->ior, sqe, &bench_zero_timeout, 0, 0);
			break;
	}
	ior_sqe_set_data(x->ior, sqe, tag);
	x->inflight++;
	BENCH_TRACE3("issue slot=%llu kind=%llu inflight=%llu", si, s->kind, x->inflight);
	return 1;
}

static void harvest_one(mix_ctx *x, ior_cqe *cqe)
{
	void *data = ior_cqe_get_data(x->ior, cqe);
	uint32_t si = (uint32_t) ((uintptr_t) data >> MIX_KIND_BITS);
	unsigned kind = (unsigned) ((uintptr_t) data & MIX_KIND_MASK);
	int32_t res = ior_cqe_get_res(x->ior, cqe);

	x->inflight--;
	BENCH_TRACE3("cqe slot=%llu kind=%llu res=%lld", si, kind, (int64_t) res);

	int ok;
	uint64_t bytes = 0;
	switch (kind) {
		case MIX_READ:
		case MIX_WRITE:
			ok = (res == (int32_t) x->block);
			bytes = ok ? x->block : 0;
			break;
		case MIX_NOP:
			ok = (res == 0);
			break;
		case MIX_TIMEOUT:
			ok = (res == -ETIME || res == -ETIMEDOUT);
			break;
		default:
			ok = 0;
			break;
	}

	if (ok) {
		bench_metrics_record(x->m, bench_now_ns() - x->slots[si].start_ns, bytes);
		x->completed++;
	} else {
		bench_metrics_error(x->m);
	}
	x->free_slots[x->free_count++] = si;
}

static int run_loop(mix_ctx *x)
{
	const bench_options *o = x->opts;
	uint64_t deadline_ns = o->ops ? 0 : bench_now_ns() + (uint64_t) (o->duration_s * 1e9);
	ior_cqe *batch[256];

	while (1) {
		/* Harvest completions (frees slots, drains the CQ). */
		unsigned n = ior_peek_batch_cqe(x->ior, batch, 256);
		for (unsigned i = 0; i < n; i++) {
			harvest_one(x, batch[i]);
		}
		if (n > 0) {
			ior_cq_advance(x->ior, n);
		}

		if (!x->draining) {
			int done = o->ops ? (x->completed >= o->ops) : (bench_now_ns() >= deadline_ns);
			if (done) {
				x->draining = 1;
				bench_metrics_stop(x->m);
			}
		}

		/* Refill to depth; issue_one() stops if the SQ is momentarily full. */
		if (!x->draining) {
			while (issue_one(x)) { }
		}

		/* Publish refilled ops, then terminate or block for progress. */
		ior_submit(x->ior);

		if (x->draining && x->inflight == 0) {
			break;
		}
		if (n == 0 && x->inflight > 0) {
			ior_cqe *cqe = NULL;
			int ret = BENCH_WAIT_CQE(x->ior, &cqe, x->completed);
			if (ret < 0 && ret != -EAGAIN && ret != -EINTR && ret != -ETIME) {
				return ret;
			}
		}
	}
	return 0;
}

int bench_run_mixed(const bench_options *opts, bench_metrics *m, const char **backend_name_out)
{
	int ret = 0;
	mix_ctx x;
	memset(&x, 0, sizeof(x));
	x.opts = opts;
	x.m = m;
	x.nfiles = opts->files ? opts->files : 4;
	x.depth = opts->depth ? opts->depth : 64;
	x.block = opts->block_size ? opts->block_size : 4096;

	uint64_t file_size = opts->file_size ? opts->file_size : (16ULL * 1024 * 1024);
	if (file_size < x.block) {
		file_size = x.block;
	}
	x.max_off = file_size - x.block;

	const char *ws = opts->workspace ? opts->workspace : bench_default_workspace();
	if (bench_ensure_dir(ws) < 0) {
		return -EIO;
	}

	uint32_t sq = opts->sq_entries;
	if (sq < x.depth * 2) {
		sq = x.depth * 2;
	}
	if (sq < 256) {
		sq = 256;
	}

	ret = ior_queue_init(sq, &x.ior);
	if (ret < 0) {
		return ret;
	}
	if (backend_name_out) {
		*backend_name_out = ior_get_backend_name(x.ior);
	}

	x.files = calloc(x.nfiles, sizeof(*x.files));
	x.slots = calloc(x.depth, sizeof(*x.slots));
	x.free_slots = calloc(x.depth, sizeof(*x.free_slots));
	if (!x.files || !x.slots || !x.free_slots) {
		ret = -ENOMEM;
		goto out;
	}
	for (uint32_t i = 0; i < x.nfiles; i++) {
		x.files[i] = IOR_INVALID_FD;
	}

	uint32_t opened = 0;
	for (uint32_t i = 0; i < x.nfiles; i++) {
		x.files[i] = bench_open_tmpfile(ws, file_size);
		if (!bench_fd_is_valid(x.files[i])) {
			x.files[i] = IOR_INVALID_FD;
			break;
		}
		opened++;
	}
	x.nfiles = opened;
	if (opened == 0) {
		ret = -EIO;
		goto out;
	}

	for (uint32_t i = 0; i < x.depth; i++) {
		x.slots[i].buf = malloc(x.block);
		if (!x.slots[i].buf) {
			ret = -ENOMEM;
			goto out;
		}
		memset(x.slots[i].buf, 0xef, x.block);
		x.free_slots[x.free_count++] = i; /* all slots free; refill issues them */
	}

	bench_metrics_start(m);
	ret = run_loop(&x);
	if (m->wall_end_ns == 0) {
		bench_metrics_stop(m);
	}

out:
	if (x.slots) {
		for (uint32_t i = 0; i < x.depth; i++) {
			free(x.slots[i].buf);
		}
		free(x.slots);
	}
	free(x.free_slots);
	if (x.files) {
		for (uint32_t i = 0; i < x.nfiles; i++) {
			bench_close_fd(x.files[i]);
		}
		free(x.files);
	}
	ior_queue_exit(x.ior);
	return ret;
}
