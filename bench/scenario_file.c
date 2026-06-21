/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * scenario_file.c - file read/write throughput at a target queue depth.
 *
 * Opens N temp files in the workspace and keeps `depth` read/write operations in
 * flight across them, re-issuing a fresh op from each completion slot until the
 * run ends, then draining. This stresses the backend's I/O offload path (worker
 * threads on the threads backend, overlapped ReadFile/WriteFile on IOCP, native
 * SQEs on io_uring) and its scaling with queue depth.
 *
 * Regular-file reads/writes always complete (the data is present / the page
 * cache absorbs writes), so deeper-than-worker-count queues simply wait for a
 * free worker rather than deadlocking, and the run drains cleanly before exit.
 */
#include "bench_platform.h"
#include "bench_scenario.h"
#include "bench_trace.h"

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct slot {
	uint32_t file; /* index into files[] */
	uint64_t offset; /* current byte offset for this slot */
	int is_write; /* this slot's pending op is a write */
	uint64_t start_ns; /* op start, for latency */
	char *buf;
} slot;

typedef struct file_ctx {
	ior_ctx *ior;
	const bench_options *opts;
	bench_metrics *m;
	ior_fd_t *files;
	uint32_t nfiles;
	slot *slots;
	uint32_t depth;
	uint32_t block;
	uint64_t max_off; /* highest aligned offset an op may use */
	uint64_t inflight;
	uint64_t completed;
	uint64_t op_counter; /* drives read/write alternation and offset rotation */
	uint32_t *free_slots; /* stack of slot indices not currently in flight */
	uint32_t free_count;
	int draining;
} file_ctx;

/*
 * Try to issue one operation from a free slot. Returns 1 on success, 0 if no
 * SQE was available (the SQ is momentarily full) - the caller harvests
 * completions and retries, matching how io_uring code handles a NULL SQE rather
 * than assuming get_sqe always succeeds.
 */
static int issue_one(file_ctx *f)
{
	if (f->free_count == 0) {
		return 0;
	}
	ior_sqe *sqe = ior_get_sqe(f->ior);
	if (!sqe) {
		return 0;
	}

	uint32_t si = f->free_slots[--f->free_count];
	slot *s = &f->slots[si];
	uint64_t n = f->op_counter++;

	s->file = (uint32_t) (n % f->nfiles);
	/* Rotate the offset deterministically across the file in block steps. */
	uint64_t slots_off = (n / f->nfiles);
	s->offset = f->max_off ? (slots_off % (f->max_off / f->block + 1)) * f->block : 0;
	s->is_write = (n & 1u) != 0;
	s->start_ns = bench_now_ns();

	if (s->is_write) {
		ior_prep_write(f->ior, sqe, f->files[s->file], s->buf, f->block, s->offset);
	} else {
		ior_prep_read(f->ior, sqe, f->files[s->file], s->buf, f->block, s->offset);
	}
	ior_sqe_set_data(f->ior, sqe, (void *) (uintptr_t) si);
	f->inflight++;
	BENCH_TRACE4("issue slot=%llu file=%llu off=%llu write=%llu", si, s->file, s->offset,
			(uint64_t) s->is_write);
	return 1;
}

/* Account one completion and return its slot to the free stack. */
static void harvest_one(file_ctx *f, ior_cqe *cqe)
{
	uint32_t si = (uint32_t) (uintptr_t) ior_cqe_get_data(f->ior, cqe);
	int32_t res = ior_cqe_get_res(f->ior, cqe);
	slot *s = &f->slots[si];

	f->inflight--;
	BENCH_TRACE3("cqe slot=%llu res=%lld inflight=%llu", si, (int64_t) res, f->inflight);

	if (res != (int32_t) f->block) {
		bench_metrics_error(f->m);
	} else {
		bench_metrics_record(f->m, bench_now_ns() - s->start_ns, (uint64_t) f->block);
		f->completed++;
	}
	f->free_slots[f->free_count++] = si;
}

static int run_loop(file_ctx *f)
{
	const bench_options *o = f->opts;
	uint64_t deadline_ns = o->ops ? 0 : bench_now_ns() + (uint64_t) (o->duration_s * 1e9);
	ior_cqe *batch[256];

	while (1) {
		/* Harvest whatever has completed (frees slots and drains the CQ). */
		unsigned n = ior_peek_batch_cqe(f->ior, batch, 256);
		for (unsigned i = 0; i < n; i++) {
			harvest_one(f, batch[i]);
		}
		if (n > 0) {
			ior_cq_advance(f->ior, n);
		}

		if (!f->draining) {
			int done = o->ops ? (f->completed >= o->ops) : (bench_now_ns() >= deadline_ns);
			if (done) {
				f->draining = 1;
				bench_metrics_stop(f->m);
			}
		}

		/* Refill up to the target depth. issue_one() stops early if the SQ is
		 * momentarily full; we retry after the next harvest. */
		if (!f->draining) {
			while (issue_one(f)) { }
		}

		/* Publish the refilled ops so workers can pick them up. */
		ior_submit(f->ior);

		if (f->draining && f->inflight == 0) {
			break;
		}

		/* Nothing harvested but work is outstanding (or the SQ was full): block
		 * for the next completion instead of spinning. */
		if (n == 0 && f->inflight > 0) {
			ior_cqe *cqe = NULL;
			int ret = BENCH_WAIT_CQE(f->ior, &cqe, f->completed);
			if (ret < 0 && ret != -EAGAIN && ret != -EINTR && ret != -ETIME) {
				return ret;
			}
		}
	}
	return 0;
}

int bench_run_file(const bench_options *opts, bench_metrics *m, const char **backend_name_out)
{
	int ret = 0;
	file_ctx f;
	memset(&f, 0, sizeof(f));
	f.opts = opts;
	f.m = m;
	f.nfiles = opts->files ? opts->files : 1;
	f.depth = opts->depth ? opts->depth : 32;
	f.block = opts->block_size ? opts->block_size : 4096;

	uint64_t file_size = opts->file_size ? opts->file_size : (16ULL * 1024 * 1024);
	if (file_size < f.block) {
		file_size = f.block;
	}
	f.max_off = file_size - f.block;

	const char *ws = opts->workspace ? opts->workspace : bench_default_workspace();
	if (bench_ensure_dir(ws) < 0) {
		return -EIO;
	}

	uint32_t sq = opts->sq_entries;
	if (sq < f.depth * 2) {
		sq = f.depth * 2;
	}
	if (sq < 256) {
		sq = 256;
	}

	ret = ior_queue_init(sq, &f.ior);
	if (ret < 0) {
		return ret;
	}
	if (backend_name_out) {
		*backend_name_out = ior_get_backend_name(f.ior);
	}

	f.files = calloc(f.nfiles, sizeof(*f.files));
	f.slots = calloc(f.depth, sizeof(*f.slots));
	f.free_slots = calloc(f.depth, sizeof(*f.free_slots));
	if (!f.files || !f.slots || !f.free_slots) {
		ret = -ENOMEM;
		goto out;
	}
	for (uint32_t i = 0; i < f.nfiles; i++) {
		f.files[i] = IOR_INVALID_FD;
	}

	uint32_t opened = 0;
	for (uint32_t i = 0; i < f.nfiles; i++) {
		f.files[i] = bench_open_tmpfile(ws, file_size);
		if (!bench_fd_is_valid(f.files[i])) {
			f.files[i] = IOR_INVALID_FD;
			break;
		}
		opened++;
	}
	f.nfiles = opened;
	if (opened == 0) {
		ret = -EIO;
		goto out;
	}

	for (uint32_t i = 0; i < f.depth; i++) {
		f.slots[i].buf = malloc(f.block);
		if (!f.slots[i].buf) {
			ret = -ENOMEM;
			goto out;
		}
		memset(f.slots[i].buf, 0xcd, f.block);
		/* All slots start free; run_loop's refill issues the initial depth. */
		f.free_slots[f.free_count++] = i;
	}

	bench_metrics_start(m);
	ret = run_loop(&f);
	if (m->wall_end_ns == 0) {
		bench_metrics_stop(m);
	}

out:
	if (f.slots) {
		for (uint32_t i = 0; i < f.depth; i++) {
			free(f.slots[i].buf);
		}
		free(f.slots);
	}
	free(f.free_slots);
	if (f.files) {
		for (uint32_t i = 0; i < f.nfiles; i++) {
			bench_close_fd(f.files[i]);
		}
		free(f.files);
	}
	ior_queue_exit(f.ior);
	return ret;
}
