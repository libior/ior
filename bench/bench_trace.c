/* SPDX-License-Identifier: BSD-3-Clause */
/* bench_trace.c - see bench_trace.h. Empty translation unit when BENCH_TRACE=0. */
#include "bench_trace.h"

#if BENCH_TRACE

#include "bench_platform.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
	uint64_t ts_ns;
	const char *fmt;
	uint64_t a, b, c, d;
} bench_trace_rec;

/* Single-producer (the driver thread); no locking needed. The buffer wraps, so
 * after capacity events only the most recent `capacity` are retained. */
static bench_trace_rec *g_recs;
static size_t g_cap;
static size_t g_count; /* total recorded (may exceed g_cap) */

void bench_trace_init(size_t capacity)
{
	g_cap = capacity ? capacity : (1u << 20);
	g_recs = calloc(g_cap, sizeof(*g_recs));
	if (!g_recs) {
		g_cap = 0;
	}
	g_count = 0;
}

void bench_trace_reset(void)
{
	g_count = 0;
}

void bench_trace_shutdown(void)
{
	free(g_recs);
	g_recs = NULL;
	g_cap = 0;
	g_count = 0;
}

void bench_trace_record(const char *fmt, uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
	if (!g_recs) {
		return;
	}
	bench_trace_rec *r = &g_recs[g_count % g_cap];
	r->ts_ns = bench_now_ns();
	r->fmt = fmt;
	r->a = a;
	r->b = b;
	r->c = c;
	r->d = d;
	g_count++;
}

void bench_trace_flush(void)
{
	if (!g_recs || g_count == 0) {
		return;
	}
	size_t n = g_count < g_cap ? g_count : g_cap;
	size_t start = g_count < g_cap ? 0 : (g_count % g_cap);
	uint64_t t0 = g_recs[start].ts_ns;

	fprintf(stderr, "--- bench trace (%zu events%s) ---\n", n,
			g_count > g_cap ? ", oldest dropped" : "");
	for (size_t i = 0; i < n; i++) {
		bench_trace_rec *r = &g_recs[(start + i) % g_cap];
		fprintf(stderr, "[%10.3f us] ", (double) (r->ts_ns - t0) / 1000.0);
		fprintf(stderr, r->fmt, (unsigned long long) r->a, (unsigned long long) r->b,
				(unsigned long long) r->c, (unsigned long long) r->d);
		fputc('\n', stderr);
	}
	fprintf(stderr, "--- end bench trace ---\n");
	fflush(stderr);
}

int bench_trace_wait_cqe(ior_ctx *ctx, ior_cqe **cqe, uint64_t progress)
{
	static uint64_t last_progress;
	static uint64_t last_change_ns;
	static int armed;

	if (!armed) {
		last_progress = progress;
		last_change_ns = bench_now_ns();
		armed = 1;
	}

	const uint64_t stall_limit_ns = 3000000000ULL; /* 3s without progress */
	for (;;) {
		ior_timespec to = { .tv_sec = 1, .tv_nsec = 0 };
		int ret = ior_wait_cqe_timeout(ctx, cqe, &to);
		if (ret == 0) {
			return 0;
		}
		if (ret != -ETIME && ret != -EAGAIN && ret != -EINTR) {
			return ret;
		}
		/* No completion this interval: check the stall watchdog. */
		uint64_t now = bench_now_ns();
		if (progress != last_progress) {
			last_progress = progress;
			last_change_ns = now;
		} else if (now - last_change_ns > stall_limit_ns) {
			fprintf(stderr, "[bench] STALL: no progress for >%llus (progress=%llu)\n",
					(unsigned long long) (stall_limit_ns / 1000000000ULL),
					(unsigned long long) progress);
			bench_trace_flush();
			abort();
		}
	}
}

#endif /* BENCH_TRACE */
