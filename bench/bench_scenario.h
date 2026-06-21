/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * bench_scenario.h - shared options and entry points for benchmark scenarios.
 *
 * Each scenario is a portable driver built on the ior public API: it sets up its
 * OS resources via bench_platform, drives operations at a target in-flight
 * depth, and records results into a bench_metrics. The CLI in ior_bench.c fills
 * in bench_options and dispatches to the right scenario.
 */
#ifndef BENCH_SCENARIO_H
#define BENCH_SCENARIO_H

#include <stdint.h>
#include "bench_metrics.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Timer guarding mode for socket I/O ops. */
typedef enum {
	BENCH_TIMER_NONE = 0, /* plain send/recv */
	BENCH_TIMER_LINKED, /* each blocking op guarded by a linked timeout */
} bench_timer_mode;

typedef struct bench_options {
	/* How long / how much to run. If ops > 0 it bounds the run by completed
	 * units; otherwise the run lasts duration_s seconds. */
	double duration_s;
	uint64_t ops;

	uint32_t conns; /* socket scenario: concurrent connections */
	uint32_t files; /* file scenario: concurrent files */
	uint32_t depth; /* file/mixed: operations in flight */
	uint32_t msg_size; /* socket/mixed payload size in bytes */
	uint64_t file_size; /* file scenario: size of each temp file */
	uint32_t block_size; /* file scenario: bytes per read/write op */

	bench_timer_mode timer_mode; /* socket scenario timer guard */
	uint32_t timeout_ms; /* guard timeout (generous; firing is an error) */

	const char *workspace; /* directory for temp files */

	uint32_t sq_entries; /* ior submission queue size */
} bench_options;

/*
 * Run a scenario. Each fills `m` (already init'd by the caller) and returns 0 on
 * success or a negative errno on setup failure. Correctness violations under
 * load are reported via m->errors, not the return value, so the caller can print
 * results and still fail the process.
 */
int bench_run_socket(const bench_options *opts, bench_metrics *m, const char **backend_name_out);
int bench_run_file(const bench_options *opts, bench_metrics *m, const char **backend_name_out);
int bench_run_mixed(const bench_options *opts, bench_metrics *m, const char **backend_name_out);

#ifdef __cplusplus
}
#endif

#endif /* BENCH_SCENARIO_H */
