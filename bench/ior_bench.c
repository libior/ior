/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * ior_bench.c - benchmark driver for the ior library.
 *
 * Reproduces representative ior workloads to study throughput / latency and
 * scaling across backends (primarily the threads pool and Windows IOCP), and to
 * catch correctness regressions under load. Backend selection follows the build
 * (io_uring / threads / IOCP); the active backend is printed with every result.
 *
 * Usage:
 *   ior_bench <socket|file|mixed|all> [options]
 *   ior_bench --smoke      bounded run of every scenario; non-zero exit on any
 *                          correctness violation. Wired into CTest/CI.
 *
 * Run `ior_bench --help` for the full option list.
 */
#include "bench_metrics.h"
#include "bench_platform.h"
#include "bench_scenario.h"
#include "bench_trace.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*scenario_fn)(const bench_options *, bench_metrics *, const char **);

static void usage(const char *prog)
{
	printf("Usage: %s <socket|file|mixed|work|all> [options]\n", prog);
	printf("       %s --smoke\n\n", prog);
	printf("Scenarios:\n");
	printf("  socket   real loopback TCP request/response (PHP-style guarded recv)\n");
	printf("  file     file read/write at a target queue depth\n");
	printf("  mixed    read/write/nop/timeout/work blend (multi-producer completion stress)\n");
	printf("  work     user work callbacks on the worker pool at a target queue depth\n");
	printf("  all      run socket (none+linked), file, mixed and work (none+linked)\n\n");
	printf("Run length (default: --duration 2.0):\n");
	printf("  --duration SEC     run each scenario for SEC seconds\n");
	printf("  --ops N            instead, stop after N completed units of work\n\n");
	printf("Workload:\n");
	printf("  --conns N          socket: concurrent connections (default 64)\n");
	printf("  --files N          file/mixed: number of files (default 8/4)\n");
	printf("  --depth N          file/mixed/work: operations in flight (default 32/64/64)\n");
	printf("  --msg-size B       socket: payload bytes per direction (default 256)\n");
	printf("  --block-size B     file/mixed: bytes per read/write (default 4096)\n");
	printf("  --file-size B      file/mixed: size of each temp file (default 16MiB)\n");
	printf("  --work-us U        work: CPU spin per callback in microseconds (default 5)\n");
	printf("  --timer none|linked  socket/work: guard ops with a linked timeout (default none)\n");
	printf("  --timeout-ms M     socket/work: guard timeout in ms (default 5000)\n");
	printf("  --workspace DIR    directory for temp files (default platform tmp/ior)\n");
	printf("  --sq-entries N     submission queue size hint\n\n");
	printf("Output:\n");
	printf("  --csv              print machine-readable CSV instead of a table\n");
	printf("  --help             show this help\n");
}

static uint64_t parse_u64(const char *s)
{
	return strtoull(s, NULL, 0);
}

static void defaults(bench_options *o)
{
	memset(o, 0, sizeof(*o));
	o->duration_s = 2.0;
	o->conns = 64;
	o->files = 0; /* per-scenario default chosen in the scenario */
	o->depth = 0;
	o->msg_size = 256;
	o->block_size = 4096;
	o->file_size = 16ULL * 1024 * 1024;
	o->work_us = 5;
	o->timer_mode = BENCH_TIMER_NONE;
	o->timeout_ms = 5000;
	o->workspace = NULL;
	o->sq_entries = 0;
}

/* Run one scenario, print results, and return the number of correctness errors
 * (or a large value on setup failure so callers can treat it as failure). */
static uint64_t run_one(
		scenario_fn fn, const char *name, const char *label, const bench_options *opts, int csv)
{
	bench_metrics m;
	bench_metrics_init(&m);
	bench_trace_reset();
	const char *backend = "unknown";

	int ret = fn(opts, &m, &backend);
	if (ret < 0) {
		fprintf(stderr, "scenario %s setup failed: %d\n", name, ret);
		return UINT64_MAX;
	}
	if (csv) {
		bench_metrics_print_csv(&m, name, backend, label);
	} else {
		bench_metrics_print(&m, name, backend, label);
	}
	return m.errors;
}

/* Bounded, correctness-gated run of every scenario for CTest/CI. */
static int run_smoke(void)
{
	uint64_t errors = 0;
	printf("ior_bench smoke: bounded correctness run of all scenarios\n");

	bench_options o;

	/* socket, no timer */
	defaults(&o);
	o.conns = 64;
	o.ops = 2000;
	o.duration_s = 0;
	o.timer_mode = BENCH_TIMER_NONE;
	errors += run_one(bench_run_socket, "socket", "timer=none", &o, 0);

	/* socket, linked timeout guard */
	o.timer_mode = BENCH_TIMER_LINKED;
	errors += run_one(bench_run_socket, "socket", "timer=linked", &o, 0);

	/* file */
	defaults(&o);
	o.files = 8;
	o.depth = 32;
	o.file_size = 4ULL * 1024 * 1024;
	o.ops = 4000;
	o.duration_s = 0;
	errors += run_one(bench_run_file, "file", NULL, &o, 0);

	/* mixed */
	defaults(&o);
	o.files = 4;
	o.depth = 64;
	o.file_size = 4ULL * 1024 * 1024;
	o.ops = 4000;
	o.duration_s = 0;
	errors += run_one(bench_run_mixed, "mixed", NULL, &o, 0);

	/* work, unguarded and guarded (short spin keeps the run bounded) */
	defaults(&o);
	o.depth = 64;
	o.work_us = 2;
	o.ops = 4000;
	o.duration_s = 0;
	o.timer_mode = BENCH_TIMER_NONE;
	errors += run_one(bench_run_work, "work", "timer=none", &o, 0);
	o.timer_mode = BENCH_TIMER_LINKED;
	errors += run_one(bench_run_work, "work", "timer=linked", &o, 0);

	printf("\nsmoke result: %s (errors=%llu)\n", errors ? "FAIL" : "PASS",
			(unsigned long long) errors);
	return errors ? 1 : 0;
}

int main(int argc, char **argv)
{
	if (bench_platform_init() < 0) {
		fprintf(stderr, "platform init failed\n");
		return 2;
	}
	bench_trace_init(1u << 20);

	int rc = 0;
	bench_options o;
	defaults(&o);
	const char *scenario = NULL;
	int csv = 0;
	int smoke = 0;

	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
#define NEXT() (i + 1 < argc ? argv[++i] : "")
		if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
			usage(argv[0]);
			goto done;
		} else if (strcmp(a, "--smoke") == 0) {
			smoke = 1;
		} else if (strcmp(a, "--csv") == 0) {
			csv = 1;
		} else if (strcmp(a, "--duration") == 0) {
			o.duration_s = strtod(NEXT(), NULL);
			o.ops = 0;
		} else if (strcmp(a, "--ops") == 0) {
			o.ops = parse_u64(NEXT());
			o.duration_s = 0;
		} else if (strcmp(a, "--conns") == 0) {
			o.conns = (uint32_t) parse_u64(NEXT());
		} else if (strcmp(a, "--files") == 0) {
			o.files = (uint32_t) parse_u64(NEXT());
		} else if (strcmp(a, "--depth") == 0) {
			o.depth = (uint32_t) parse_u64(NEXT());
		} else if (strcmp(a, "--msg-size") == 0) {
			o.msg_size = (uint32_t) parse_u64(NEXT());
		} else if (strcmp(a, "--block-size") == 0) {
			o.block_size = (uint32_t) parse_u64(NEXT());
		} else if (strcmp(a, "--file-size") == 0) {
			o.file_size = parse_u64(NEXT());
		} else if (strcmp(a, "--work-us") == 0) {
			o.work_us = (uint32_t) parse_u64(NEXT());
		} else if (strcmp(a, "--timeout-ms") == 0) {
			o.timeout_ms = (uint32_t) parse_u64(NEXT());
		} else if (strcmp(a, "--sq-entries") == 0) {
			o.sq_entries = (uint32_t) parse_u64(NEXT());
		} else if (strcmp(a, "--workspace") == 0) {
			o.workspace = NEXT();
		} else if (strcmp(a, "--timer") == 0) {
			const char *v = NEXT();
			if (strcmp(v, "linked") == 0) {
				o.timer_mode = BENCH_TIMER_LINKED;
			} else if (strcmp(v, "none") == 0) {
				o.timer_mode = BENCH_TIMER_NONE;
			} else {
				fprintf(stderr, "unknown --timer value: %s\n", v);
				rc = 2;
				goto done;
			}
		} else if (a[0] == '-') {
			fprintf(stderr, "unknown option: %s\n", a);
			usage(argv[0]);
			rc = 2;
			goto done;
		} else if (!scenario) {
			scenario = a;
		} else {
			fprintf(stderr, "unexpected argument: %s\n", a);
			rc = 2;
			goto done;
		}
#undef NEXT
	}

	if (smoke) {
		rc = run_smoke();
		goto done;
	}

	if (!scenario) {
		usage(argv[0]);
		rc = 2;
		goto done;
	}

	if (csv) {
		bench_metrics_print_csv_header();
	}

	uint64_t errors = 0;
	if (strcmp(scenario, "socket") == 0) {
		const char *label = o.timer_mode == BENCH_TIMER_LINKED ? "timer=linked" : "timer=none";
		errors = run_one(bench_run_socket, "socket", label, &o, csv);
	} else if (strcmp(scenario, "file") == 0) {
		errors = run_one(bench_run_file, "file", NULL, &o, csv);
	} else if (strcmp(scenario, "mixed") == 0) {
		errors = run_one(bench_run_mixed, "mixed", NULL, &o, csv);
	} else if (strcmp(scenario, "work") == 0) {
		const char *label = o.timer_mode == BENCH_TIMER_LINKED ? "timer=linked" : "timer=none";
		errors = run_one(bench_run_work, "work", label, &o, csv);
	} else if (strcmp(scenario, "all") == 0) {
		bench_options so = o;
		so.timer_mode = BENCH_TIMER_NONE;
		errors += run_one(bench_run_socket, "socket", "timer=none", &so, csv);
		so.timer_mode = BENCH_TIMER_LINKED;
		errors += run_one(bench_run_socket, "socket", "timer=linked", &so, csv);
		errors += run_one(bench_run_file, "file", NULL, &o, csv);
		errors += run_one(bench_run_mixed, "mixed", NULL, &o, csv);
		so = o;
		so.timer_mode = BENCH_TIMER_NONE;
		errors += run_one(bench_run_work, "work", "timer=none", &so, csv);
		so.timer_mode = BENCH_TIMER_LINKED;
		errors += run_one(bench_run_work, "work", "timer=linked", &so, csv);
	} else {
		fprintf(stderr, "unknown scenario: %s\n", scenario);
		usage(argv[0]);
		rc = 2;
		goto done;
	}

	/* A standalone perf run reports correctness errors but only fails the
	 * process when something actually went wrong, mirroring the smoke gate. */
	if (errors == UINT64_MAX) {
		rc = 2;
	} else if (errors > 0) {
		fprintf(stderr, "WARNING: %llu correctness errors observed\n", (unsigned long long) errors);
		rc = 1;
	}

done:
	bench_trace_shutdown();
	bench_platform_shutdown();
	return rc;
}
