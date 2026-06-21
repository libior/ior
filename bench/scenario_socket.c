/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * scenario_socket.c - real loopback TCP request/response benchmark.
 *
 * Models the PHP socket-offload workload: many concurrent connections, each
 * doing a request/response round trip, optionally with a (linked) timeout
 * guarding the blocking receive - exactly how PHP issues a guarded recv.
 *
 * Each connection runs a strict 4-step round trip:
 *   SEND_REQ (client->server) -> RECV_REQ (server) ->
 *   SEND_RESP (server->client) -> RECV_RESP (client) -> repeat.
 *
 * A receive is posted only after its matching send has completed, so the data is
 * already in the kernel socket buffer and the recv never blocks a worker thread
 * for long. That keeps the bounded thread pool from starving even with far more
 * connections than worker threads, and lets the run drain to zero in-flight
 * operations cleanly before teardown (an outstanding blocking recv at
 * ior_queue_exit would otherwise hang the join).
 *
 * Round-trip latency is measured from posting SEND_REQ to RECV_RESP completing.
 */
#include "bench_platform.h"
#include "bench_scenario.h"
#include "bench_trace.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Operation kinds, packed with the connection index into the SQE user_data. */
enum {
	OP_SEND_REQ = 0,
	OP_RECV_REQ = 1,
	OP_SEND_RESP = 2,
	OP_RECV_RESP = 3,
	OP_LINK_TIMEOUT = 4,
	OP_NONE = 7, /* sentinel: no pending action (fits OP_KIND_MASK, never tagged) */
	OP_KIND_BITS = 3,
	OP_KIND_MASK = (1u << OP_KIND_BITS) - 1,
};

static inline void *make_tag(uint32_t conn, unsigned kind)
{
	return (void *) (((uintptr_t) conn << OP_KIND_BITS) | (kind & OP_KIND_MASK));
}
static inline uint32_t tag_conn(void *data)
{
	return (uint32_t) ((uintptr_t) data >> OP_KIND_BITS);
}
static inline unsigned tag_kind(void *data)
{
	return (unsigned) ((uintptr_t) data & OP_KIND_MASK);
}

typedef struct conn {
	ior_fd_t client; /* fds[1] */
	ior_fd_t server; /* fds[0] */
	char *rbuf; /* per-connection receive buffer (one op outstanding at a time) */
	uint64_t rt_start_ns;
	unsigned pending; /* next action to issue (OP_*), or OP_NONE when idle */
} conn;

typedef struct sock_ctx {
	ior_ctx *ior;
	const bench_options *opts;
	bench_metrics *m;
	conn *conns;
	uint32_t nconns;
	char *send_buf; /* shared request/response payload */
	uint32_t msg_size;
	ior_timespec timeout;
	int linked;
	uint64_t inflight; /* operations + link timeouts not yet reaped */
	uint64_t completed_rt;
	uint32_t *ready; /* queue of connection indices with a pending action */
	uint32_t ready_count;
	int draining;
} sock_ctx;

/* Queue a connection's next action to be issued during the refill phase. */
static void set_pending(sock_ctx *s, uint32_t ci, unsigned kind)
{
	s->conns[ci].pending = kind;
	s->ready[s->ready_count++] = ci;
}

/* The fd a given action operates on. */
static ior_fd_t action_fd(sock_ctx *s, uint32_t ci, unsigned kind)
{
	conn *c = &s->conns[ci];
	return (kind == OP_SEND_REQ || kind == OP_RECV_RESP) ? c->client : c->server;
}

/*
 * Try to issue a connection's pending action. Returns 1 if issued (or dropped
 * because we are draining), 0 if the SQ was momentarily full and the caller
 * should retry after harvesting more completions.
 */
static int issue_pending(sock_ctx *s, uint32_t ci)
{
	conn *c = &s->conns[ci];
	unsigned kind = c->pending;

	/* Do not start a new round trip once draining; let in-flight ones finish. */
	if (s->draining && kind == OP_SEND_REQ) {
		c->pending = OP_NONE;
		return 1;
	}

	int is_recv = (kind == OP_RECV_REQ || kind == OP_RECV_RESP);
	ior_fd_t fd = action_fd(s, ci, kind);

	if (!is_recv) {
		ior_sqe *sqe = ior_get_sqe(s->ior);
		if (!sqe) {
			return 0;
		}
		if (kind == OP_SEND_REQ) {
			c->rt_start_ns = bench_now_ns();
		}
		ior_prep_send(s->ior, sqe, fd, s->send_buf, s->msg_size, 0);
		ior_sqe_set_data(s->ior, sqe, make_tag(ci, kind));
		s->inflight++;
	} else if (s->linked) {
		ior_sqe *rsqe = ior_get_sqe(s->ior);
		if (!rsqe) {
			return 0;
		}
		ior_prep_recv(s->ior, rsqe, fd, c->rbuf, s->msg_size, 0);
		ior_sqe_set_data(s->ior, rsqe, make_tag(ci, kind));
		ior_sqe *lsqe = ior_get_sqe(s->ior);
		if (lsqe) {
			ior_sqe_set_flags(s->ior, rsqe, IOR_SQE_IO_LINK);
			ior_prep_link_timeout(s->ior, lsqe, &s->timeout, 0);
			ior_sqe_set_data(s->ior, lsqe, make_tag(ci, OP_LINK_TIMEOUT));
			s->inflight += 2;
		} else {
			/* Only one slot was free: issue the recv unguarded this round rather
			 * than leaving a dangling IO_LINK. Rare, under transient SQ pressure. */
			s->inflight++;
		}
	} else {
		ior_sqe *rsqe = ior_get_sqe(s->ior);
		if (!rsqe) {
			return 0;
		}
		ior_prep_recv(s->ior, rsqe, fd, c->rbuf, s->msg_size, 0);
		ior_sqe_set_data(s->ior, rsqe, make_tag(ci, kind));
		s->inflight++;
	}

	BENCH_TRACE3("issue conn=%llu kind=%llu inflight=%llu", ci, kind, s->inflight);
	c->pending = OP_NONE;
	return 1;
}

/* Validate a received payload and count integrity errors. */
static int check_payload(sock_ctx *s, uint32_t ci, int32_t res)
{
	if (res != (int32_t) s->msg_size || memcmp(s->conns[ci].rbuf, s->send_buf, s->msg_size) != 0) {
		bench_metrics_error(s->m);
		return -1;
	}
	return 0;
}

/* Account one completion and queue the connection's next action (no I/O here). */
static void harvest_one(sock_ctx *s, ior_cqe *cqe)
{
	void *data = ior_cqe_get_data(s->ior, cqe);
	int32_t res = ior_cqe_get_res(s->ior, cqe);
	uint32_t ci = tag_conn(data);
	unsigned kind = tag_kind(data);
	conn *c = &s->conns[ci];

	s->inflight--;
	BENCH_TRACE4("cqe        conn=%llu kind=%llu res=%lld inflight=%llu", ci, kind, (int64_t) res,
			s->inflight);

	switch (kind) {
		case OP_LINK_TIMEOUT:
			/* Normal: guarded recv finished first, timeout cancelled (-ECANCELED).
			 * -ETIME means the deadline fired (recv stalled past the guard) - an
			 * anomaly given the generous timeout. */
			if (res == -ETIME) {
				bench_metrics_error(s->m);
			}
			break;

		case OP_SEND_REQ:
			if (res != (int32_t) s->msg_size) {
				bench_metrics_error(s->m);
				break;
			}
			set_pending(s, ci, OP_RECV_REQ);
			break;

		case OP_RECV_REQ:
			if (res == -ECANCELED) {
				break; /* guard fired; counted via the link timeout CQE */
			}
			if (check_payload(s, ci, res) == 0) {
				set_pending(s, ci, OP_SEND_RESP);
			}
			break;

		case OP_SEND_RESP:
			if (res != (int32_t) s->msg_size) {
				bench_metrics_error(s->m);
				break;
			}
			set_pending(s, ci, OP_RECV_RESP);
			break;

		case OP_RECV_RESP:
			if (res == -ECANCELED) {
				break;
			}
			if (check_payload(s, ci, res) == 0) {
				bench_metrics_record(
						s->m, bench_now_ns() - c->rt_start_ns, (uint64_t) s->msg_size * 2);
				s->completed_rt++;
				if (!s->draining) {
					set_pending(s, ci, OP_SEND_REQ); /* next round trip */
				}
			}
			break;
	}
}

static int run_loop(sock_ctx *s)
{
	const bench_options *o = s->opts;
	uint64_t deadline_ns = o->ops ? 0 : bench_now_ns() + (uint64_t) (o->duration_s * 1e9);
	ior_cqe *batch[256];

	while (1) {
		/* Harvest completions (advances connection state, drains the CQ). */
		unsigned n = ior_peek_batch_cqe(s->ior, batch, 256);
		for (unsigned i = 0; i < n; i++) {
			harvest_one(s, batch[i]);
		}
		if (n > 0) {
			ior_cq_advance(s->ior, n);
		}

		if (!s->draining) {
			int done = o->ops ? (s->completed_rt >= o->ops) : (bench_now_ns() >= deadline_ns);
			if (done) {
				s->draining = 1;
				bench_metrics_stop(s->m);
				BENCH_TRACE2("drain start completed_rt=%llu inflight=%llu", s->completed_rt,
						s->inflight);
			}
		}

		/* Issue queued actions. Stop early if the SQ fills (retry next harvest). */
		while (s->ready_count > 0) {
			uint32_t ci = s->ready[s->ready_count - 1];
			if (!issue_pending(s, ci)) {
				break;
			}
			s->ready_count--;
		}

		ior_submit(s->ior);

		if (s->draining && s->inflight == 0 && s->ready_count == 0) {
			break;
		}

		/* Nothing harvested but work is outstanding: block for a completion. */
		if (n == 0 && s->inflight > 0) {
			ior_cqe *cqe = NULL;
			int ret = BENCH_WAIT_CQE(s->ior, &cqe, s->completed_rt);
			if (ret < 0 && ret != -EAGAIN && ret != -EINTR && ret != -ETIME) {
				return ret;
			}
		}
	}
	return 0;
}

int bench_run_socket(const bench_options *opts, bench_metrics *m, const char **backend_name_out)
{
	int ret = 0;
	sock_ctx s;
	memset(&s, 0, sizeof(s));
	s.opts = opts;
	s.m = m;
	s.nconns = opts->conns ? opts->conns : 1;
	s.msg_size = opts->msg_size ? opts->msg_size : 256;
	s.linked = (opts->timer_mode == BENCH_TIMER_LINKED);
	s.timeout.tv_sec = opts->timeout_ms / 1000;
	s.timeout.tv_nsec = (long long) (opts->timeout_ms % 1000) * 1000000LL;

	uint32_t sq = opts->sq_entries;
	if (sq < s.nconns * 4) {
		sq = s.nconns * 4;
	}
	if (sq < 256) {
		sq = 256;
	}

	ret = ior_queue_init(sq, &s.ior);
	if (ret < 0) {
		return ret;
	}
	if (backend_name_out) {
		*backend_name_out = ior_get_backend_name(s.ior);
	}

	s.send_buf = malloc(s.msg_size);
	s.conns = calloc(s.nconns, sizeof(*s.conns));
	s.ready = calloc(s.nconns, sizeof(*s.ready));
	if (!s.send_buf || !s.conns || !s.ready) {
		ret = -ENOMEM;
		goto out;
	}
	memset(s.send_buf, 0x5a, s.msg_size);

	uint32_t established = 0;
	for (uint32_t i = 0; i < s.nconns; i++) {
		ior_fd_t fds[2];
		if (bench_make_tcp_pair(fds) < 0) {
			ret = -EIO;
			break;
		}
		s.conns[i].server = fds[0];
		s.conns[i].client = fds[1];
		s.conns[i].rbuf = malloc(s.msg_size);
		if (!s.conns[i].rbuf) {
			bench_close_fd(fds[0]);
			bench_close_fd(fds[1]);
			ret = -ENOMEM;
			break;
		}
		established++;
	}
	/* Only the first `established` connections hold valid fds/buffers; cap nconns
	 * so the run and the cleanup loop never touch the calloc-zeroed remainder
	 * (fd 0 is stdin on POSIX). */
	s.nconns = established;
	if (established == 0) {
		if (ret == 0) {
			ret = -EIO;
		}
		goto out;
	}

	bench_metrics_start(m);
	/* Each connection starts a round trip; run_loop's refill issues them. */
	for (uint32_t i = 0; i < s.nconns; i++) {
		set_pending(&s, i, OP_SEND_REQ);
	}
	ret = run_loop(&s);
	if (m->wall_end_ns == 0) {
		bench_metrics_stop(m);
	}

out:
	if (s.conns) {
		for (uint32_t i = 0; i < s.nconns; i++) {
			bench_close_fd(s.conns[i].server);
			bench_close_fd(s.conns[i].client);
			free(s.conns[i].rbuf);
		}
		free(s.conns);
	}
	free(s.ready);
	free(s.send_buf);
	ior_queue_exit(s.ior);
	return ret;
}
