/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * bench_trace.h - optional, low-overhead tracing for the benchmark.
 *
 * Benchmarks are timing-sensitive: formatting and writing log lines on the hot
 * path would perturb the very scheduling we are trying to measure, and the
 * library's own IOR_LOG may not be compiled in. So this is a self-contained
 * facility that records events into a preallocated in-memory ring buffer (just a
 * timestamp, a static format string, and up to four integer args - no
 * formatting, no I/O) and only formats/flushes them on demand: at the end of a
 * run or when the stall watchdog trips.
 *
 * It is gated entirely at compile time by BENCH_TRACE. When BENCH_TRACE is 0
 * (the default) every macro expands to nothing and there is zero runtime cost;
 * enable it with -DIOR_BENCH_TRACE=ON (CMake) when debugging a hang or anomaly.
 */
#ifndef BENCH_TRACE_H
#define BENCH_TRACE_H

#include <stddef.h>
#include <stdint.h>
#include "../src/ior.h"

#ifndef BENCH_TRACE
#define BENCH_TRACE 0
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if BENCH_TRACE

/* Allocate the ring buffer (capacity = number of records). */
void bench_trace_init(size_t capacity);
/* Clear recorded events (call at the start of each scenario). */
void bench_trace_reset(void);
/* Free the ring buffer. */
void bench_trace_shutdown(void);
/* Record one event. `fmt` must be a static string using %llu for its args. */
void bench_trace_record(const char *fmt, uint64_t a, uint64_t b, uint64_t c, uint64_t d);
/* Format and print all recorded events (oldest first) to stderr. */
void bench_trace_flush(void);

/*
 * Block until a completion is ready, like ior_wait_cqe, but with a stall
 * watchdog: `progress` is any monotonically increasing counter (e.g. completed
 * ops); if it does not advance for several seconds while we are still waiting,
 * the trace is flushed and the process aborts with a diagnostic. Returns the
 * underlying ior_wait_cqe-style result.
 */
int bench_trace_wait_cqe(ior_ctx *ctx, ior_cqe **cqe, uint64_t progress);

#define BENCH_TRACE0(f) bench_trace_record((f), 0, 0, 0, 0)
#define BENCH_TRACE1(f, a) bench_trace_record((f), (uint64_t) (a), 0, 0, 0)
#define BENCH_TRACE2(f, a, b) bench_trace_record((f), (uint64_t) (a), (uint64_t) (b), 0, 0)
#define BENCH_TRACE3(f, a, b, c) \
	bench_trace_record((f), (uint64_t) (a), (uint64_t) (b), (uint64_t) (c), 0)
#define BENCH_TRACE4(f, a, b, c, d) \
	bench_trace_record((f), (uint64_t) (a), (uint64_t) (b), (uint64_t) (c), (uint64_t) (d))

#define BENCH_WAIT_CQE(ctx, cqe, progress) bench_trace_wait_cqe((ctx), (cqe), (progress))

#else /* BENCH_TRACE disabled: everything compiles away */

#define bench_trace_init(capacity) ((void) 0)
#define bench_trace_reset() ((void) 0)
#define bench_trace_shutdown() ((void) 0)
#define bench_trace_flush() ((void) 0)
#define BENCH_TRACE0(f) ((void) 0)
#define BENCH_TRACE1(f, a) ((void) 0)
#define BENCH_TRACE2(f, a, b) ((void) 0)
#define BENCH_TRACE3(f, a, b, c) ((void) 0)
#define BENCH_TRACE4(f, a, b, c, d) ((void) 0)
#define BENCH_WAIT_CQE(ctx, cqe, progress) ior_wait_cqe((ctx), (cqe))

#endif /* BENCH_TRACE */

#ifdef __cplusplus
}
#endif

#endif /* BENCH_TRACE_H */
