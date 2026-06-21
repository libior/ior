/* SPDX-License-Identifier: BSD-3-Clause */
/* bench_metrics.c - see bench_metrics.h. */
#include "bench_metrics.h"
#include "bench_platform.h"

#include <stdio.h>
#include <string.h>

void bench_metrics_init(bench_metrics *m)
{
	memset(m, 0, sizeof(*m));
	m->lat_min_ns = UINT64_MAX;
}

void bench_metrics_start(bench_metrics *m)
{
	m->wall_start_ns = bench_now_ns();
}

void bench_metrics_stop(bench_metrics *m)
{
	m->wall_end_ns = bench_now_ns();
}

/* Index of the highest set bit (floor(log2(v))); 0 for v==0. */
static unsigned floor_log2_u64(uint64_t v)
{
	unsigned b = 0;
	while (v >>= 1) {
		b++;
	}
	return b;
}

void bench_metrics_record(bench_metrics *m, uint64_t latency_ns, uint64_t bytes)
{
	m->ops++;
	m->bytes += bytes;
	m->lat_sum_ns += latency_ns;
	if (latency_ns < m->lat_min_ns) {
		m->lat_min_ns = latency_ns;
	}
	if (latency_ns > m->lat_max_ns) {
		m->lat_max_ns = latency_ns;
	}
	unsigned bucket = latency_ns ? floor_log2_u64(latency_ns) : 0;
	if (bucket >= BENCH_HIST_BUCKETS) {
		bucket = BENCH_HIST_BUCKETS - 1;
	}
	m->hist[bucket]++;
}

void bench_metrics_error(bench_metrics *m)
{
	m->errors++;
}

uint64_t bench_metrics_percentile(const bench_metrics *m, double p)
{
	if (m->ops == 0) {
		return 0;
	}
	uint64_t target = (uint64_t) (p * (double) m->ops);
	if (target >= m->ops) {
		target = m->ops - 1;
	}
	uint64_t cum = 0;
	for (unsigned b = 0; b < BENCH_HIST_BUCKETS; b++) {
		cum += m->hist[b];
		if (cum > target) {
			/* Report the upper edge of the bucket (2^(b+1) ns) as a conservative
			 * estimate, clamped to the observed max. */
			uint64_t edge = (b + 1 >= 64) ? UINT64_MAX : (1ULL << (b + 1));
			return edge < m->lat_max_ns ? edge : m->lat_max_ns;
		}
	}
	return m->lat_max_ns;
}

static double ns_to_us(uint64_t ns)
{
	return (double) ns / 1000.0;
}

void bench_metrics_print(
		const bench_metrics *m, const char *scenario, const char *backend, const char *label)
{
	uint64_t wall_ns = m->wall_end_ns > m->wall_start_ns ? m->wall_end_ns - m->wall_start_ns : 0;
	double wall_s = (double) wall_ns / 1e9;
	double ops_per_s = wall_s > 0 ? (double) m->ops / wall_s : 0.0;
	double mb_per_s = wall_s > 0 ? (double) m->bytes / (1024.0 * 1024.0) / wall_s : 0.0;
	double avg_us = m->ops ? ns_to_us(m->lat_sum_ns / m->ops) : 0.0;

	printf("\n");
	printf("=== %s", scenario);
	if (label && label[0]) {
		printf(" [%s]", label);
	}
	printf(" === backend=%s\n", backend);
	printf("  duration   : %.3f s\n", wall_s);
	printf("  operations : %llu", (unsigned long long) m->ops);
	if (m->errors) {
		printf("   ERRORS=%llu", (unsigned long long) m->errors);
	}
	printf("\n");
	printf("  throughput : %.0f ops/s", ops_per_s);
	if (m->bytes) {
		printf("   %.1f MiB/s", mb_per_s);
	}
	printf("\n");
	printf("  latency us : avg=%.1f min=%.1f p50=%.1f p99=%.1f p999=%.1f max=%.1f\n", avg_us,
			m->ops ? ns_to_us(m->lat_min_ns) : 0.0, ns_to_us(bench_metrics_percentile(m, 0.50)),
			ns_to_us(bench_metrics_percentile(m, 0.99)),
			ns_to_us(bench_metrics_percentile(m, 0.999)), ns_to_us(m->lat_max_ns));
}

void bench_metrics_print_csv_header(void)
{
	printf("scenario,label,backend,duration_s,ops,errors,ops_per_s,mib_per_s,"
		   "avg_us,p50_us,p99_us,p999_us,max_us\n");
}

void bench_metrics_print_csv(
		const bench_metrics *m, const char *scenario, const char *backend, const char *label)
{
	uint64_t wall_ns = m->wall_end_ns > m->wall_start_ns ? m->wall_end_ns - m->wall_start_ns : 0;
	double wall_s = (double) wall_ns / 1e9;
	double ops_per_s = wall_s > 0 ? (double) m->ops / wall_s : 0.0;
	double mb_per_s = wall_s > 0 ? (double) m->bytes / (1024.0 * 1024.0) / wall_s : 0.0;
	double avg_us = m->ops ? ns_to_us(m->lat_sum_ns / m->ops) : 0.0;

	printf("%s,%s,%s,%.3f,%llu,%llu,%.0f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f\n", scenario,
			label ? label : "", backend, wall_s, (unsigned long long) m->ops,
			(unsigned long long) m->errors, ops_per_s, mb_per_s, avg_us,
			ns_to_us(bench_metrics_percentile(m, 0.50)),
			ns_to_us(bench_metrics_percentile(m, 0.99)),
			ns_to_us(bench_metrics_percentile(m, 0.999)), ns_to_us(m->lat_max_ns));
}
