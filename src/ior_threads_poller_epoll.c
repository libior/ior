/* SPDX-License-Identifier: BSD-3-Clause */
#include "config.h"

#ifdef IOR_HAVE_THREADS

#include "ior.h"
#include "ior_threads_poller.h"
#include "ior_threads_event.h"
#include "ior_worker_pool.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
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
 * epoll allows one registration per fd, so requests are grouped in per-fd
 * nodes registered with the union of their masks. Plain linked lists: the
 * expected request count is modest.
 */
typedef struct ior_poller_fd_node {
	int fd;
	ior_poller_req *reqs;
	struct ior_poller_fd_node *next;
} ior_poller_fd_node;

struct ior_threads_poller {
	pthread_t thread;
	int epfd;
	ior_threads_event event; /* wakeup for add()/destroy() */
	pthread_mutex_t lock;
	ior_poller_req *incoming_head;
	ior_poller_req *incoming_tail;
	_Atomic int shutdown;
	void *owner;
	ior_threads_poller_cb cb;
	ior_poller_fd_node *fds;
};

static uint32_t ior_poller_to_epoll(uint32_t ior_mask)
{
	uint32_t ev = 0;
	if (ior_mask & IOR_POLL_IN) {
		ev |= EPOLLIN;
	}
	if (ior_mask & IOR_POLL_OUT) {
		ev |= EPOLLOUT;
	}
	/* ERR/HUP are always reported by epoll; nothing to request. */
	return ev;
}

static uint32_t ior_poller_from_epoll(uint32_t ep_events)
{
	uint32_t mask = 0;
	if (ep_events & EPOLLIN) {
		mask |= IOR_POLL_IN;
	}
	if (ep_events & EPOLLOUT) {
		mask |= IOR_POLL_OUT;
	}
	if (ep_events & EPOLLERR) {
		mask |= IOR_POLL_ERR;
	}
	if (ep_events & EPOLLHUP) {
		mask |= IOR_POLL_HUP;
	}
	return mask;
}

static uint32_t ior_poller_node_union(const ior_poller_fd_node *node)
{
	uint32_t mask = 0;
	for (const ior_poller_req *r = node->reqs; r; r = r->next) {
		mask |= r->mask;
	}
	return mask;
}

static void ior_poller_complete(
		ior_threads_poller *poller, ior_poller_req *r, int res)
{
	poller->cb(poller->owner, r->req, res);
	free(r);
}

/* Re-register the node with the union of the remaining masks, or drop it. */
static void ior_poller_node_update(ior_threads_poller *poller, ior_poller_fd_node *node)
{
	if (node->reqs) {
		struct epoll_event ev = {
			.events = ior_poller_to_epoll(ior_poller_node_union(node)),
			.data.ptr = node,
		};
		epoll_ctl(poller->epfd, EPOLL_CTL_MOD, node->fd, &ev);
		return;
	}

	epoll_ctl(poller->epfd, EPOLL_CTL_DEL, node->fd, NULL);
	ior_poller_fd_node **pp = &poller->fds;
	while (*pp != node) {
		pp = &(*pp)->next;
	}
	*pp = node->next;
	free(node);
}

static void ior_poller_ingest_one(ior_threads_poller *poller, ior_poller_req *r)
{
	ior_poller_fd_node *node = poller->fds;
	while (node && node->fd != r->fd) {
		node = node->next;
	}

	if (node) {
		r->next = node->reqs;
		node->reqs = r;
		struct epoll_event ev = {
			.events = ior_poller_to_epoll(ior_poller_node_union(node)),
			.data.ptr = node,
		};
		epoll_ctl(poller->epfd, EPOLL_CTL_MOD, node->fd, &ev);
		return;
	}

	node = calloc(1, sizeof(*node));
	if (!node) {
		ior_poller_complete(poller, r, -ENOMEM);
		return;
	}
	node->fd = r->fd;
	node->reqs = r;
	r->next = NULL;

	struct epoll_event ev = {
		.events = ior_poller_to_epoll(r->mask),
		.data.ptr = node,
	};
	if (epoll_ctl(poller->epfd, EPOLL_CTL_ADD, r->fd, &ev) < 0) {
		int err = errno;
		free(node);
		if (err == EPERM) {
			/* Regular file: always ready, matching poll()/io_uring. */
			uint32_t ready = r->mask & (IOR_POLL_IN | IOR_POLL_OUT);
			ior_poller_complete(poller, r, ready ? (int) ready : -EINVAL);
		} else {
			ior_poller_complete(poller, r, -err);
		}
		return;
	}
	node->next = poller->fds;
	poller->fds = node;
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

/* Nearest deadline as an epoll timeout in ms (-1 = none). */
static int ior_poller_timeout_ms(ior_threads_poller *poller)
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
		return -1;
	}
	uint64_t now = ior_worker_pool_monotonic_ns();
	if (nearest <= now) {
		return 0;
	}
	uint64_t ms = (nearest - now + 999999ULL) / 1000000ULL;
	return ms > (uint64_t) INT_MAX ? INT_MAX : (int) ms;
}

/*
 * Complete a batch of unlinked requests. Must run only after the fd's epoll
 * registration has been updated: once the callback fires, the owner may close
 * the fd, so the poller must no longer reference it.
 */
static void ior_poller_complete_list(ior_threads_poller *poller, ior_poller_req *done)
{
	while (done) {
		ior_poller_req *next = done->next;
		ior_poller_complete(poller, done, done->res);
		done = next;
	}
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
			ior_poller_node_update(poller, node);
			ior_poller_complete_list(poller, done);
		}
		node = next_node;
	}
}

static void ior_poller_dispatch(
		ior_threads_poller *poller, ior_poller_fd_node *node, uint32_t ep_events)
{
	uint32_t ready = ior_poller_from_epoll(ep_events);
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
	ior_poller_node_update(poller, node);
	ior_poller_complete_list(poller, done);
}

static void ior_poller_cancel_all(ior_threads_poller *poller)
{
	ior_poller_fd_node *node = poller->fds;
	poller->fds = NULL;
	while (node) {
		ior_poller_fd_node *next_node = node->next;
		epoll_ctl(poller->epfd, EPOLL_CTL_DEL, node->fd, NULL);
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
	struct epoll_event events[IOR_POLLER_MAX_EVENTS];

	for (;;) {
		ior_poller_ingest_incoming(poller);
		if (atomic_load_explicit(&poller->shutdown, memory_order_acquire)) {
			break;
		}

		int n = epoll_wait(poller->epfd, events, IOR_POLLER_MAX_EVENTS,
				ior_poller_timeout_ms(poller));
		if (n < 0 && errno != EINTR) {
			break;
		}

		for (int i = 0; i < n; i++) {
			if (!events[i].data.ptr) {
				ior_threads_event_clear(&poller->event);
				continue;
			}
			ior_poller_dispatch(poller, events[i].data.ptr, events[i].events);
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

	poller->epfd = epoll_create1(EPOLL_CLOEXEC);
	if (poller->epfd < 0) {
		free(poller);
		return -errno;
	}
	if (ior_threads_event_init(&poller->event) < 0) {
		close(poller->epfd);
		free(poller);
		return -ENOMEM;
	}
	if (pthread_mutex_init(&poller->lock, NULL) != 0) {
		ior_threads_event_destroy(&poller->event);
		close(poller->epfd);
		free(poller);
		return -ENOMEM;
	}

	/* Wakeup fd is marked by a NULL data pointer. */
	struct epoll_event ev = { .events = EPOLLIN, .data.ptr = NULL };
	if (epoll_ctl(poller->epfd, EPOLL_CTL_ADD, ior_threads_event_get_fd(&poller->event), &ev) < 0
			|| pthread_create(&poller->thread, NULL, ior_poller_thread, poller) != 0) {
		pthread_mutex_destroy(&poller->lock);
		ior_threads_event_destroy(&poller->event);
		close(poller->epfd);
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
	close(poller->epfd);
	free(poller);
}

#endif /* IOR_HAVE_THREADS */
