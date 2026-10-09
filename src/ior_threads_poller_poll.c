/* SPDX-License-Identifier: BSD-3-Clause */
#include "config.h"

#ifdef IOR_HAVE_THREADS

#include "ior.h"
#include "ior_threads_poller.h"
#include "ior_threads_event.h"
#include "ior_worker_pool.h"
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

typedef struct ior_poller_req {
	int fd;
	uint32_t mask;
	uint64_t deadline_ns; /* absolute monotonic, 0 = none */
	void *req;
	int multi; /* persistent: completes at every readiness until dropped */
	uint64_t rearm_ns; /* multi: left out of the poll set until then (0 = polled) */
	int cancelled; /* set by cancel(); completes with -ECANCELED */
	int ended; /* a readiness was declined: retires with res as its last result */
	int res; /* staged result on the done list */
	int retired; /* staged with its last result: unlinked, freed after the callback */
	struct ior_poller_req *next; /* incoming queue, then the active list */
	struct ior_poller_req *done_next; /* staged completions */
} ior_poller_req;

/*
 * `lock` guards the incoming queue and the active list so that cancel() can
 * find a request from any thread. The poller thread holds it for all list
 * work and drops it only around poll() and around completion callbacks, which
 * run with no poller lock held. cancel() only marks a request; the poller
 * thread unlinks it, so the active list keeps matching the pfds it filled.
 *
 * poll() is level-triggered, so a multishot request would report the same
 * readiness on every call: after a report it is left out of the poll set for
 * IOR_THREADS_POLLER_MULTI_REARM_NS, then polled again. Readiness that is
 * still there is reported again, so no edge is lost; one that went away is
 * waited for.
 */
struct ior_threads_poller {
	pthread_t thread;
	ior_threads_event event; /* wakeup for add()/cancel()/destroy() */
	pthread_mutex_t lock;
	ior_poller_req *incoming_head;
	ior_poller_req *incoming_tail;
	_Atomic int shutdown;
	void *owner;
	ior_threads_poller_cb cb;
	ior_poller_req *active;
	struct pollfd *pfds; /* scratch, grown on demand; poller thread only */
	size_t pfds_cap;
};

/*
 * Stage r for completion with res on the done list (lock held). A retired
 * request has been unlinked and is freed after its callback; a multishot
 * request reporting readiness stays on the active list.
 */
static void ior_poller_stage(ior_poller_req **done, ior_poller_req *r, int res, int retired)
{
	r->res = res;
	r->retired = retired;
	r->done_next = *done;
	*done = r;
}

/* Complete a batch of staged requests; runs with the lock released. */
static void ior_poller_complete_list(ior_threads_poller *poller, ior_poller_req *done)
{
	while (done) {
		ior_poller_req *next = done->done_next;
		int declined = poller->cb(poller->owner, done->req, done->res, !done->retired);
		if (done->retired) {
			free(done);
		} else if (declined) {
			/* Only this thread reads the flag: the next pass retires the
			 * request, with res still holding the declined readiness. */
			done->ended = 1;
		}
		done = next;
	}
}

/*
 * Lock held. A request cancelled before it got here completes now: the
 * wakeup its cancel sent may have been consumed by a pass that resolved only
 * the active list, and polled it would wait for readiness that may never
 * come. A multishot request on a regular file ends at once with its mask: the
 * file is always ready and has no edges to wait for (poll() would report it
 * at every call), matching epoll's refusal and io_uring.
 */
static void ior_poller_ingest_incoming(ior_threads_poller *poller, ior_poller_req **done)
{
	ior_poller_req *r = poller->incoming_head;
	poller->incoming_head = NULL;
	poller->incoming_tail = NULL;

	while (r) {
		ior_poller_req *next = r->next;
		struct stat st;
		if (r->cancelled) {
			ior_poller_stage(done, r, -ECANCELED, 1);
		} else if (r->multi && fstat(r->fd, &st) == 0 && S_ISREG(st.st_mode)) {
			uint32_t ready = r->mask & (IOR_POLL_IN | IOR_POLL_OUT);
			ior_poller_stage(done, r, ready ? (int) ready : -EINVAL, 1);
		} else {
			r->next = poller->active;
			poller->active = r;
		}
		r = next;
	}
}

/*
 * Unlink every request that declined its last readiness, staging it as the
 * last result, or -ECANCELED if a cancel got in first. Lock held.
 */
static void ior_poller_retire_ended(ior_threads_poller *poller, ior_poller_req **done)
{
	ior_poller_req **pp = &poller->active;
	while (*pp) {
		ior_poller_req *r = *pp;
		if (r->ended) {
			*pp = r->next;
			ior_poller_stage(done, r, r->cancelled ? -ECANCELED : r->res, 1);
		} else {
			pp = &r->next;
		}
	}
}

/* Nearest deadline or re-arm time as a poll timeout in ms (-1 = none). Lock held. */
static int ior_poller_timeout_ms(ior_threads_poller *poller)
{
	uint64_t nearest = 0;
	for (ior_poller_req *r = poller->active; r; r = r->next) {
		if (r->deadline_ns && (!nearest || r->deadline_ns < nearest)) {
			nearest = r->deadline_ns;
		}
		if (r->rearm_ns && (!nearest || r->rearm_ns < nearest)) {
			nearest = r->rearm_ns;
		}
	}
	if (!nearest) {
		return -1;
	}
	uint64_t now = ior_worker_pool_monotonic_ns();
	if (nearest <= now) {
		return 0;
	}
	uint64_t ms = (nearest - now + 999999ULL) / 1000000ULL;
	return ms > (uint64_t) INT_MAX ? INT_MAX : (int) ms;
}

/* Lock held. */
static void ior_poller_cancel_all(ior_threads_poller *poller, ior_poller_req **done)
{
	ior_poller_req *r = poller->active;
	poller->active = NULL;
	while (r) {
		ior_poller_req *next = r->next;
		ior_poller_stage(done, r, -ECANCELED, 1);
		r = next;
	}
}

/*
 * Resolve the active list after poll(): cancelled requests (-ECANCELED),
 * ready ones (mask or -EBADF), then expired deadlines (-ETIME). A ready
 * multishot request stays, held out of the next polls for a while; one whose
 * hold has ended is polled again. pret <= 0 means no revents are valid. Lock
 * held.
 */
static void ior_poller_resolve(ior_threads_poller *poller, int pret, ior_poller_req **done)
{
	uint64_t now = ior_worker_pool_monotonic_ns();
	size_t i = 1;
	ior_poller_req **pp = &poller->active;
	while (*pp) {
		ior_poller_req *r = *pp;
		short revents = pret > 0 ? poller->pfds[i].revents : 0;
		i++;
		if (r->cancelled) {
			*pp = r->next;
			ior_poller_stage(done, r, -ECANCELED, 1);
		} else if (revents & POLLNVAL) {
			*pp = r->next;
			ior_poller_stage(done, r, -EBADF, 1);
		} else if (revents && r->multi) {
			ior_poller_stage(done, r, (int) ior_threads_poller_from_poll(revents), 0);
			r->rearm_ns = now + IOR_THREADS_POLLER_MULTI_REARM_NS;
			pp = &r->next;
		} else if (revents) {
			*pp = r->next;
			ior_poller_stage(done, r, (int) ior_threads_poller_from_poll(revents), 1);
		} else if (r->deadline_ns && r->deadline_ns <= now) {
			*pp = r->next;
			ior_poller_stage(done, r, -ETIME, 1);
		} else {
			if (r->rearm_ns && r->rearm_ns <= now) {
				r->rearm_ns = 0;
			}
			pp = &r->next;
		}
	}
}

static void *ior_poller_thread(void *arg)
{
	ior_threads_poller *poller = arg;

	for (;;) {
		ior_poller_req *done = NULL;

		pthread_mutex_lock(&poller->lock);
		ior_poller_ingest_incoming(poller, &done);
		ior_poller_retire_ended(poller, &done);
		if (atomic_load_explicit(&poller->shutdown, memory_order_acquire)) {
			pthread_mutex_unlock(&poller->lock);
			ior_poller_complete_list(poller, done);
			break;
		}
		if (done) {
			pthread_mutex_unlock(&poller->lock);
			ior_poller_complete_list(poller, done);
			continue;
		}

		/* Slot 0 is the wakeup fd; one slot per active request after it. */
		size_t nreqs = 0;
		for (ior_poller_req *r = poller->active; r; r = r->next) {
			nreqs++;
		}
		if (nreqs + 1 > poller->pfds_cap) {
			size_t cap = poller->pfds_cap ? poller->pfds_cap * 2 : 16;
			while (cap < nreqs + 1) {
				cap *= 2;
			}
			struct pollfd *pfds = realloc(poller->pfds, cap * sizeof(*pfds));
			if (!pfds) {
				ior_poller_cancel_all(poller, &done);
				pthread_mutex_unlock(&poller->lock);
				ior_poller_complete_list(poller, done);
				continue;
			}
			poller->pfds = pfds;
			poller->pfds_cap = cap;
		}

		poller->pfds[0].fd = ior_threads_event_get_fd(&poller->event);
		poller->pfds[0].events = POLLIN;
		poller->pfds[0].revents = 0;
		size_t i = 1;
		for (ior_poller_req *r = poller->active; r; r = r->next, i++) {
			/* A negative fd keeps the slot but is ignored by poll(). */
			poller->pfds[i].fd = r->rearm_ns ? -1 : r->fd;
			poller->pfds[i].events = ior_threads_poller_to_poll(r->mask);
			poller->pfds[i].revents = 0;
		}
		int timeout_ms = ior_poller_timeout_ms(poller);
		pthread_mutex_unlock(&poller->lock);

		int pret = poll(poller->pfds, (nfds_t) (nreqs + 1), timeout_ms);
		if (pret < 0 && errno != EINTR) {
			break;
		}

		if (pret > 0 && poller->pfds[0].revents) {
			ior_threads_event_clear(&poller->event);
		}

		/* Walk requests in the same order the pfds were filled: cancel() never
		 * unlinks, and add() only appends to incoming, so the list is intact. */
		pthread_mutex_lock(&poller->lock);
		ior_poller_resolve(poller, pret, &done);
		pthread_mutex_unlock(&poller->lock);
		ior_poller_complete_list(poller, done);
	}

	/* Shutdown: fail everything still pending, including late arrivals. */
	ior_poller_req *done = NULL;
	pthread_mutex_lock(&poller->lock);
	ior_poller_ingest_incoming(poller, &done);
	ior_poller_cancel_all(poller, &done);
	pthread_mutex_unlock(&poller->lock);
	ior_poller_complete_list(poller, done);
	return NULL;
}

int ior_threads_poller_create(
		ior_threads_poller **poller_out, void *owner, ior_threads_poller_cb cb)
{
	if (!poller_out || !cb) {
		return -EINVAL;
	}

	ior_threads_poller *poller = calloc(1, sizeof(*poller));
	if (!poller) {
		return -ENOMEM;
	}
	poller->owner = owner;
	poller->cb = cb;
	atomic_init(&poller->shutdown, 0);

	if (ior_threads_event_init(&poller->event) < 0) {
		free(poller);
		return -ENOMEM;
	}
	if (pthread_mutex_init(&poller->lock, NULL) != 0) {
		ior_threads_event_destroy(&poller->event);
		free(poller);
		return -ENOMEM;
	}
	if (ior_thread_create(&poller->thread, NULL, ior_poller_thread, poller) != 0) {
		pthread_mutex_destroy(&poller->lock);
		ior_threads_event_destroy(&poller->event);
		free(poller);
		return -ENOMEM;
	}

	*poller_out = poller;
	return 0;
}

int ior_threads_poller_add(
		ior_threads_poller *poller, int fd, uint32_t ior_mask, uint64_t deadline_ns, void *req)
{
	if (!poller) {
		return -EINVAL;
	}

	ior_poller_req *r = calloc(1, sizeof(*r));
	if (!r) {
		return -ENOMEM;
	}
	r->fd = fd;
	r->mask = ior_mask & ~IOR_THREADS_POLLER_MULTI;
	r->multi = (ior_mask & IOR_THREADS_POLLER_MULTI) != 0;
	r->deadline_ns = deadline_ns;
	r->req = req;

	pthread_mutex_lock(&poller->lock);
	if (poller->incoming_tail) {
		poller->incoming_tail->next = r;
	} else {
		poller->incoming_head = r;
	}
	poller->incoming_tail = r;
	pthread_mutex_unlock(&poller->lock);

	ior_threads_event_signal(&poller->event);
	return 0;
}

int ior_threads_poller_cancel(ior_threads_poller *poller, void *req)
{
	if (!poller) {
		return -EINVAL;
	}

	int found = 0;
	pthread_mutex_lock(&poller->lock);
	for (ior_poller_req *r = poller->incoming_head; r && !found; r = r->next) {
		if (r->req == req && !r->cancelled) {
			r->cancelled = 1;
			found = 1;
		}
	}
	for (ior_poller_req *r = poller->active; r && !found; r = r->next) {
		if (r->req == req && !r->cancelled) {
			r->cancelled = 1;
			found = 1;
		}
	}
	pthread_mutex_unlock(&poller->lock);

	if (!found) {
		return -ENOENT;
	}
	ior_threads_event_signal(&poller->event);
	return 0;
}

void ior_threads_poller_forget(ior_threads_poller *poller)
{
	ior_threads_event_destroy(&poller->event);
}

void ior_threads_poller_destroy(ior_threads_poller *poller)
{
	if (!poller) {
		return;
	}

	atomic_store_explicit(&poller->shutdown, 1, memory_order_release);
	ior_threads_event_signal(&poller->event);
	pthread_join(poller->thread, NULL);

	pthread_mutex_destroy(&poller->lock);
	ior_threads_event_destroy(&poller->event);
	free(poller->pfds);
	free(poller);
}

#endif /* IOR_HAVE_THREADS */
