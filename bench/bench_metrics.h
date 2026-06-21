/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * bench_metrics.h - portable throughput / latency accounting for ior_bench.
 *
 * A scenario records one completed unit of work (one round trip, one I/O op)
 * with bench_metrics_record(), then prints a summary. Latency is kept in a
 * coarse log2-bucketed histogram so memory is O(1) regardless of op count, which
 * is enough for p50/p99/p999 to study scaling and spot regressions.
 */
#ifndef BENCH_METRICS_H
#define BENCH_METRICS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 64 buckets cover 1ns .. ~18s by power of two, which spans every realistic
 * I/O latency. */
#define BENCH_HIST_BUCKETS 64

typedef struct bench_metrics {
	uint64_t ops; /* completed units of work counted for latency/throughput */
	uint64_t bytes; /* payload bytes transferred (0 for nop/timer) */
	uint64_t errors; /* operations that completed with an unexpected result */

	uint64_t lat_min_ns;
	uint64_t lat_max_ns;
	uint64_t lat_sum_ns;
	uint64_t hist[BENCH_HIST_BUCKETS]; /* histogram of latency, log2(ns) bucketed */

	uint64_t wall_start_ns;
	uint64_t wall_end_ns;
} bench_metrics;

/* Reset all counters. Call before the measured phase. */
void bench_metrics_init(bench_metrics *m);

/* Stamp the start of the measured wall-clock window. */
void bench_metrics_start(bench_metrics *m);

/* Stamp the end of the measured wall-clock window. */
void bench_metrics_stop(bench_metrics *m);

/* Record one completed unit: its latency and the payload bytes it moved. */
void bench_metrics_record(bench_metrics *m, uint64_t latency_ns, uint64_t bytes);

/* Record an operation that completed with an unexpected result. */
void bench_metrics_error(bench_metrics *m);

/* Approximate latency percentile in ns (p in [0,1]) from the histogram. */
uint64_t bench_metrics_percentile(const bench_metrics *m, double p);

/*
 * Print a human-readable summary. `scenario` and `backend` label the run;
 * `label` is a short qualifier (e.g. "timer=linked") or NULL.
 */
void bench_metrics_print(
		const bench_metrics *m, const char *scenario, const char *backend, const char *label);

/* Print one CSV row (header printed once by bench_metrics_print_csv_header). */
void bench_metrics_print_csv_header(void);
void bench_metrics_print_csv(
		const bench_metrics *m, const char *scenario, const char *backend, const char *label);

#ifdef __cplusplus
}
#endif

#endif /* BENCH_METRICS_H */
