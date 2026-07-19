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

typedef struct ior_poller_req {
	int fd;
	uint32_t mask;
	uint64_t deadline_ns; /* absolute monotonic, 0 = none */
	void *req;
	struct ior_poller_req *next;
} ior_poller_req;

struct ior_threads_poller {
	pthread_t thread;
	ior_threads_event event; /* wakeup for add()/destroy() */
	pthread_mutex_t lock;
	ior_poller_req *incoming_head;
	ior_poller_req *incoming_tail;
	_Atomic int shutdown;
	void *owner;
	ior_threads_poller_cb cb;
	ior_poller_req *active; /* owned by the poller thread */
	struct pollfd *pfds;    /* scratch, grown on demand */
	size_t pfds_cap;
};

static short ior_poller_to_poll(uint32_t ior_mask)
{
	short ev = 0;
	if (ior_mask & IOR_POLL_IN) {
		ev |= POLLIN;
	}
	if (ior_mask & IOR_POLL_OUT) {
		ev |= POLLOUT;
	}
	/* ERR/HUP/NVAL are output-only for poll(). */
	return ev;
}

static uint32_t ior_poller_from_poll(short revents)
{
	uint32_t mask = 0;
	if (revents & POLLIN) {
		mask |= IOR_POLL_IN;
	}
	if (revents & POLLOUT) {
		mask |= IOR_POLL_OUT;
	}
	if (revents & POLLERR) {
		mask |= IOR_POLL_ERR;
	}
	if (revents & POLLHUP) {
		mask |= IOR_POLL_HUP;
	}
	return mask;
}

static void ior_poller_complete(ior_threads_poller *poller, ior_poller_req *r, int res)
{
	poller->cb(poller->owner, r->req, res);
	free(r);
}

static void ior_poller_ingest_incoming(ior_threads_poller *poller)
{
	pthread_mutex_lock(&poller->lock);
	ior_poller_req *r = poller->incoming_head;
	poller->incoming_head = NULL;
	poller->incoming_tail = NULL;
	pthread_mutex_unlock(&poller->lock);

	while (r) {
		ior_poller_req *next = r->next;
		r->next = poller->active;
		poller->active = r;
		r = next;
	}
}

/* Nearest deadline as a poll timeout in ms (-1 = none). */
static int ior_poller_timeout_ms(ior_threads_poller *poller)
{
	uint64_t nearest = 0;
	for (ior_poller_req *r = poller->active; r; r = r->next) {
		if (r->deadline_ns && (!nearest || r->deadline_ns < nearest)) {
			nearest = r->deadline_ns;
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

static void ior_poller_cancel_all(ior_threads_poller *poller)
{
	ior_poller_req *r = poller->active;
	poller->active = NULL;
	while (r) {
		ior_poller_req *next = r->next;
		ior_poller_complete(poller, r, -ECANCELED);
		r = next;
	}
}

static void *ior_poller_thread(void *arg)
{
	ior_threads_poller *poller = arg;

	for (;;) {
		ior_poller_ingest_incoming(poller);
		if (atomic_load_explicit(&poller->shutdown, memory_order_acquire)) {
			break;
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
				ior_poller_cancel_all(poller);
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
			poller->pfds[i].fd = r->fd;
			poller->pfds[i].events = ior_poller_to_poll(r->mask);
			poller->pfds[i].revents = 0;
		}

		int pret = poll(poller->pfds, (nfds_t) (nreqs + 1), ior_poller_timeout_ms(poller));
		if (pret < 0 && errno != EINTR) {
			break;
		}

		if (poller->pfds[0].revents) {
			ior_threads_event_clear(&poller->event);
		}

		/* Walk requests in the same order the pfds were filled. */
		uint64_t now = ior_worker_pool_monotonic_ns();
		i = 1;
		ior_poller_req **pp = &poller->active;
		while (*pp) {
			ior_poller_req *r = *pp;
			short revents = pret > 0 ? poller->pfds[i].revents : 0;
			i++;
			if (revents & POLLNVAL) {
				*pp = r->next;
				ior_poller_complete(poller, r, -EBADF);
			} else if (revents) {
				*pp = r->next;
				ior_poller_complete(poller, r, (int) ior_poller_from_poll(revents));
			} else if (r->deadline_ns && r->deadline_ns <= now) {
				*pp = r->next;
				ior_poller_complete(poller, r, -ETIME);
			} else {
				pp = &r->next;
			}
		}
	}

	/* Shutdown: fail everything still pending, including late arrivals. */
	ior_poller_ingest_incoming(poller);
	ior_poller_cancel_all(poller);
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
	if (pthread_create(&poller->thread, NULL, ior_poller_thread, poller) != 0) {
		pthread_mutex_destroy(&poller->lock);
		ior_threads_event_destroy(&poller->event);
		free(poller);
		return -ENOMEM;
	}

	*poller_out = poller;
	return 0;
}

int ior_threads_poller_add(ior_threads_poller *poller, int fd, uint32_t ior_mask,
		uint64_t deadline_ns, void *req)
{
	if (!poller) {
		return -EINVAL;
	}

	ior_poller_req *r = calloc(1, sizeof(*r));
	if (!r) {
		return -ENOMEM;
	}
	r->fd = fd;
	r->mask = ior_mask;
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
