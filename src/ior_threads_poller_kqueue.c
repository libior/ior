/* SPDX-License-Identifier: BSD-3-Clause */
#include "config.h"

#ifdef IOR_HAVE_THREADS

#include "ior.h"
#include "ior_threads_poller.h"
#include "ior_threads_event.h"
#include "ior_worker_pool.h"
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define IOR_POLLER_MAX_EVENTS 64

typedef struct ior_poller_req {
	int fd;
	uint32_t mask;
	uint64_t deadline_ns; /* absolute monotonic, 0 = none */
	void *req;
	int res; /* staged result while the fd bookkeeping completes */
	struct ior_poller_req *next;
} ior_poller_req;

/*
 * kqueue registers per (fd, filter) pair, so requests are grouped in per-fd
 * nodes and the node tracks which filters are currently registered (`reg`,
 * as IOR_POLL_IN/OUT bits). Plain linked lists: the expected request count
 * is modest.
 */
typedef struct ior_poller_fd_node {
	int fd;
	uint32_t reg;
	ior_poller_req *reqs;
	struct ior_poller_fd_node *next;
} ior_poller_fd_node;

struct ior_threads_poller {
	pthread_t thread;
	int kq;
	ior_threads_event event; /* wakeup for add()/destroy() */
	pthread_mutex_t lock;
	ior_poller_req *incoming_head;
	ior_poller_req *incoming_tail;
	_Atomic int shutdown;
	void *owner;
	ior_threads_poller_cb cb;
	ior_poller_fd_node *fds;
};

static void ior_poller_complete(ior_threads_poller *poller, ior_poller_req *r, int res)
{
	poller->cb(poller->owner, r->req, res);
	free(r);
}

/*
 * Complete a batch of unlinked requests with their staged res. Must run only
 * after the fd's kevent registrations have been updated: once the callback
 * fires, the owner may close the fd, so the poller must no longer reference
 * it.
 */
static void ior_poller_complete_list(ior_threads_poller *poller, ior_poller_req *done)
{
	while (done) {
		ior_poller_req *next = done->next;
		ior_poller_complete(poller, done, done->res);
		done = next;
	}
}

/*
 * Sync the node's kevent registrations to the union of its remaining masks
 * and drop the node once empty. A failed EV_ADD completes the requests that
 * needed that filter: as the requested mask for a regular file (always
 * ready, matching poll()), as -errno otherwise. Callbacks fire only after
 * all kevent calls.
 */
static void ior_poller_node_sync(ior_threads_poller *poller, ior_poller_fd_node *node)
{
	ior_poller_req *done = NULL;

	for (int pass = 0; pass < 2; pass++) {
		uint32_t bit = pass == 0 ? IOR_POLL_IN : IOR_POLL_OUT;
		int16_t filter = pass == 0 ? EVFILT_READ : EVFILT_WRITE;

		uint32_t want = 0;
		for (ior_poller_req *r = node->reqs; r; r = r->next) {
			want |= r->mask;
		}

		struct kevent kev;
		if ((want & bit) && !(node->reg & bit)) {
			EV_SET(&kev, node->fd, filter, EV_ADD, 0, 0, node);
			if (kevent(poller->kq, &kev, 1, NULL, 0, NULL) == 0) {
				node->reg |= bit;
			} else {
				int err = errno;
				struct stat st;
				int regular = fstat(node->fd, &st) == 0 && S_ISREG(st.st_mode);
				ior_poller_req **pp = &node->reqs;
				while (*pp) {
					ior_poller_req *r = *pp;
					if (r->mask & bit) {
						*pp = r->next;
						uint32_t ready = r->mask & (IOR_POLL_IN | IOR_POLL_OUT);
						r->res = regular ? (int) ready : -err;
						r->next = done;
						done = r;
					} else {
						pp = &r->next;
					}
				}
			}
		} else if (!(want & bit) && (node->reg & bit)) {
			EV_SET(&kev, node->fd, filter, EV_DELETE, 0, 0, NULL);
			(void) kevent(poller->kq, &kev, 1, NULL, 0, NULL);
			node->reg &= ~bit;
		}
	}

	if (!node->reqs) {
		for (int pass = 0; pass < 2; pass++) {
			uint32_t bit = pass == 0 ? IOR_POLL_IN : IOR_POLL_OUT;
			if (node->reg & bit) {
				struct kevent kev;
				EV_SET(&kev, node->fd, pass == 0 ? EVFILT_READ : EVFILT_WRITE, EV_DELETE, 0, 0,
						NULL);
				(void) kevent(poller->kq, &kev, 1, NULL, 0, NULL);
			}
		}
		ior_poller_fd_node **pp = &poller->fds;
		while (*pp != node) {
			pp = &(*pp)->next;
		}
		*pp = node->next;
		free(node);
	}

	ior_poller_complete_list(poller, done);
}

static void ior_poller_ingest_one(ior_threads_poller *poller, ior_poller_req *r)
{
	ior_poller_fd_node *node = poller->fds;
	while (node && node->fd != r->fd) {
		node = node->next;
	}

	if (!node) {
		node = calloc(1, sizeof(*node));
		if (!node) {
			ior_poller_complete(poller, r, -ENOMEM);
			return;
		}
		node->fd = r->fd;
		node->next = poller->fds;
		poller->fds = node;
	}

	r->next = node->reqs;
	node->reqs = r;
	ior_poller_node_sync(poller, node);
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
		ior_poller_ingest_one(poller, r);
		r = next;
	}
}

/* Nearest deadline as a kevent timeout (NULL = none). */
static struct timespec *ior_poller_timeout(ior_threads_poller *poller, struct timespec *ts)
{
	uint64_t nearest = 0;
	for (ior_poller_fd_node *node = poller->fds; node; node = node->next) {
		for (ior_poller_req *r = node->reqs; r; r = r->next) {
			if (r->deadline_ns && (!nearest || r->deadline_ns < nearest)) {
				nearest = r->deadline_ns;
			}
		}
	}
	if (!nearest) {
		return NULL;
	}
	uint64_t now = ior_worker_pool_monotonic_ns();
	uint64_t left = nearest > now ? nearest - now : 0;
	ts->tv_sec = (time_t) (left / 1000000000ULL);
	ts->tv_nsec = (long) (left % 1000000000ULL);
	return ts;
}

static void ior_poller_expire_deadlines(ior_threads_poller *poller)
{
	uint64_t now = ior_worker_pool_monotonic_ns();
	ior_poller_fd_node *node = poller->fds;
	while (node) {
		ior_poller_fd_node *next_node = node->next;
		ior_poller_req *done = NULL;
		ior_poller_req **pp = &node->reqs;
		while (*pp) {
			ior_poller_req *r = *pp;
			if (r->deadline_ns && r->deadline_ns <= now) {
				*pp = r->next;
				r->res = -ETIME;
				r->next = done;
				done = r;
			} else {
				pp = &r->next;
			}
		}
		if (done) {
			ior_poller_node_sync(poller, node); /* may free node */
			ior_poller_complete_list(poller, done);
		}
		node = next_node;
	}
}

static void ior_poller_dispatch(
		ior_threads_poller *poller, ior_poller_fd_node *node, uint32_t ready)
{
	ior_poller_req *done = NULL;
	ior_poller_req **pp = &node->reqs;
	while (*pp) {
		ior_poller_req *r = *pp;
		uint32_t res = ready & (r->mask | IOR_POLL_ERR | IOR_POLL_HUP);
		if (res) {
			*pp = r->next;
			r->res = (int) res;
			r->next = done;
			done = r;
		} else {
			pp = &r->next;
		}
	}
	ior_poller_node_sync(poller, node); /* may free node */
	ior_poller_complete_list(poller, done);
}

static void ior_poller_cancel_all(ior_threads_poller *poller)
{
	/* No kevent bookkeeping: the kq is closed right after in destroy. */
	ior_poller_fd_node *node = poller->fds;
	poller->fds = NULL;
	while (node) {
		ior_poller_fd_node *next_node = node->next;
		ior_poller_req *r = node->reqs;
		while (r) {
			ior_poller_req *next = r->next;
			ior_poller_complete(poller, r, -ECANCELED);
			r = next;
		}
		free(node);
		node = next_node;
	}
}

static void *ior_poller_thread(void *arg)
{
	ior_threads_poller *poller = arg;
	struct kevent events[IOR_POLLER_MAX_EVENTS];
	/* One wakeup can deliver a READ and a WRITE event for the same node, and
	 * dispatching one may free it - merge per node before dispatching. */
	struct {
		ior_poller_fd_node *node;
		uint32_t ready;
	} hits[IOR_POLLER_MAX_EVENTS];

	for (;;) {
		ior_poller_ingest_incoming(poller);
		if (atomic_load_explicit(&poller->shutdown, memory_order_acquire)) {
			break;
		}

		struct timespec ts;
		int n = kevent(poller->kq, NULL, 0, events, IOR_POLLER_MAX_EVENTS,
				ior_poller_timeout(poller, &ts));
		if (n < 0 && errno != EINTR) {
			break;
		}

		int nhits = 0;
		for (int i = 0; i < n; i++) {
			if (!events[i].udata) {
				ior_threads_event_clear(&poller->event);
				continue;
			}
			ior_poller_fd_node *node = events[i].udata;
			uint32_t ready;
			if (events[i].flags & EV_ERROR) {
				ready = IOR_POLL_ERR;
			} else {
				ready = events[i].filter == EVFILT_READ ? IOR_POLL_IN : IOR_POLL_OUT;
				if (events[i].flags & EV_EOF) {
					ready |= IOR_POLL_HUP;
					if (events[i].fflags != 0) {
						ready |= IOR_POLL_ERR;
					}
				}
			}
			int j = 0;
			while (j < nhits && hits[j].node != node) {
				j++;
			}
			if (j == nhits) {
				hits[nhits].node = node;
				hits[nhits].ready = 0;
				nhits++;
			}
			hits[j].ready |= ready;
		}
		for (int j = 0; j < nhits; j++) {
			ior_poller_dispatch(poller, hits[j].node, hits[j].ready);
		}
		ior_poller_expire_deadlines(poller);
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

	poller->kq = kqueue();
	if (poller->kq < 0) {
		free(poller);
		return -errno;
	}
	if (ior_threads_event_init(&poller->event) < 0) {
		close(poller->kq);
		free(poller);
		return -ENOMEM;
	}
	if (pthread_mutex_init(&poller->lock, NULL) != 0) {
		ior_threads_event_destroy(&poller->event);
		close(poller->kq);
		free(poller);
		return -ENOMEM;
	}

	/* Wakeup fd is marked by a NULL udata pointer. */
	struct kevent kev;
	EV_SET(&kev, ior_threads_event_get_fd(&poller->event), EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(poller->kq, &kev, 1, NULL, 0, NULL) < 0
			|| pthread_create(&poller->thread, NULL, ior_poller_thread, poller) != 0) {
		pthread_mutex_destroy(&poller->lock);
		ior_threads_event_destroy(&poller->event);
		close(poller->kq);
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
	close(poller->kq);
	free(poller);
}

#endif /* IOR_HAVE_THREADS */
