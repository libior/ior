/* SPDX-License-Identifier: BSD-3-Clause */
#include "config.h"

#if defined(IOR_HAVE_THREADS) || defined(IOR_HAVE_URING)

#include "ior_worker_pool.h"
#include "ior_log.h"
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>

static void *ior_worker_pool_worker_thread_func(void *arg);
static void *ior_worker_pool_timer_thread_func(void *arg);

uint64_t ior_worker_pool_monotonic_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

// Must be called with pool->lock held.
static int ior_worker_pool_try_create_thread(ior_worker_pool *pool)
{
	if (pool->num_threads_current >= pool->num_threads_max) {
		return -EAGAIN;
	}

	ior_worker_pool_worker_t *worker = calloc(1, sizeof(*worker));
	if (!worker) {
		return -ENOMEM;
	}

	worker->pool = pool;
	atomic_init(&worker->state, IOR_WORKER_POOL_THREAD_STATE_IDLE);

	pthread_attr_t attr;
	pthread_attr_init(&attr);
	if (pool->stack_size > 0) {
		pthread_attr_setstacksize(&attr, pool->stack_size);
	}

	int ret = pthread_create(&worker->thread_id, &attr, ior_worker_pool_worker_thread_func, worker);
	pthread_attr_destroy(&attr);
	if (ret != 0) {
		free(worker);
		return -ret;
	}

	worker->next = pool->threads;
	pool->threads = worker;
	pool->num_threads_current++;
	pool->num_threads_idle++;

	return 0;
}

ior_worker_pool *ior_worker_pool_create(
		const ior_worker_pool_config *config, ior_worker_pool_run_fn run, void *owner)
{
	if (!config || !run) {
		return NULL;
	}

	ior_worker_pool *pool = calloc(1, sizeof(*pool));
	if (!pool) {
		return NULL;
	}

	pool->run = run;
	pool->owner = owner;
	pool->num_threads_min = config->min_threads;
	pool->num_threads_max = config->max_threads > 0 ? config->max_threads : 32;
	if (pool->num_threads_min > pool->num_threads_max) {
		pool->num_threads_min = pool->num_threads_max;
	}
	pool->stack_size = config->stack_size;

	atomic_init(&pool->shutdown, 0);

	if (pthread_mutex_init(&pool->lock, NULL) != 0) {
		goto err_free;
	}
	if (pthread_cond_init(&pool->work_cond, NULL) != 0) {
		goto err_lock;
	}

	// Timer manager: small min-heap plus a dedicated thread.
	pool->timer_heap_cap = 16;
	pool->timer_heap = calloc(pool->timer_heap_cap, sizeof(*pool->timer_heap));
	if (!pool->timer_heap) {
		goto err_work_cond;
	}
	if (pthread_mutex_init(&pool->timer_lock, NULL) != 0) {
		goto err_heap;
	}
	if (pthread_cond_init(&pool->timer_cond, NULL) != 0) {
		goto err_timer_lock;
	}
	if (pthread_create(&pool->timer_thread, NULL, ior_worker_pool_timer_thread_func, pool) != 0) {
		goto err_timer_cond;
	}
	pool->timer_thread_started = 1;

	// Create the minimum number of resident workers, if any.
	pthread_mutex_lock(&pool->lock);
	for (uint32_t i = 0; i < pool->num_threads_min; i++) {
		if (ior_worker_pool_try_create_thread(pool) != 0) {
			break;
		}
	}
	pthread_mutex_unlock(&pool->lock);

	return pool;

err_timer_cond:
	pthread_cond_destroy(&pool->timer_cond);
err_timer_lock:
	pthread_mutex_destroy(&pool->timer_lock);
err_heap:
	free(pool->timer_heap);
err_work_cond:
	pthread_cond_destroy(&pool->work_cond);
err_lock:
	pthread_mutex_destroy(&pool->lock);
err_free:
	free(pool);
	return NULL;
}

void ior_worker_pool_destroy(ior_worker_pool *pool)
{
	if (!pool) {
		return;
	}

	atomic_store(&pool->shutdown, 1);

	// Wake the timer thread so it observes shutdown immediately rather than
	// sleeping out a pending deadline, then join it. Pending timers are dropped
	// without firing (the owner is being torn down).
	if (pool->timer_thread_started) {
		pthread_mutex_lock(&pool->timer_lock);
		pthread_cond_signal(&pool->timer_cond);
		pthread_mutex_unlock(&pool->timer_lock);
		pthread_join(pool->timer_thread, NULL);
	}

	// Wake all workers; they drain the job FIFO before exiting on shutdown.
	pthread_mutex_lock(&pool->lock);
	pthread_cond_broadcast(&pool->work_cond);
	pthread_mutex_unlock(&pool->lock);

	pthread_mutex_lock(&pool->lock);
	ior_worker_pool_worker_t *worker = pool->threads;
	while (worker) {
		ior_worker_pool_worker_t *next = worker->next;
		pthread_mutex_unlock(&pool->lock);

		pthread_join(worker->thread_id, NULL);
		free(worker);

		pthread_mutex_lock(&pool->lock);
		worker = next;
	}
	pool->threads = NULL;
	pthread_mutex_unlock(&pool->lock);

	/*
	 * Release dropped timers only now: draining workers may still have armed
	 * new timers (the timer thread is already gone, so they just accumulate in
	 * the heap), and their drop callbacks may release state shared with jobs.
	 */
	for (uint32_t i = 0; i < pool->timer_heap_len; i++) {
		if (pool->timer_heap[i].drop) {
			pool->timer_heap[i].drop(pool->owner, pool->timer_heap[i].arg);
		}
	}
	pthread_cond_destroy(&pool->timer_cond);
	pthread_mutex_destroy(&pool->timer_lock);
	free(pool->timer_heap);
	pool->timer_heap = NULL;

	pthread_cond_destroy(&pool->work_cond);
	pthread_mutex_destroy(&pool->lock);
	free(pool);
}

void ior_worker_pool_submit(
		ior_worker_pool *pool, ior_worker_pool_job *first, ior_worker_pool_job *last, uint32_t count)
{
	if (!pool || !first || count == 0) {
		return;
	}

	pthread_mutex_lock(&pool->lock);

	last->next = NULL;
	if (pool->job_tail) {
		pool->job_tail->next = first;
	} else {
		pool->job_head = first;
	}
	pool->job_tail = last;
	pool->jobs_pending += count;

	/*
	 * Keep one worker per outstanding job (capped at max). A job may block its
	 * worker until other jobs complete (drain waits, poll gates), so matching
	 * threads to the outstanding count guarantees every queued job - including
	 * one behind a blocked job - has a thread to run it.
	 */
	uint32_t want = pool->jobs_pending + pool->jobs_running;
	if (want > pool->num_threads_max) {
		want = pool->num_threads_max;
	}
	while (pool->num_threads_current < want) {
		if (ior_worker_pool_try_create_thread(pool) != 0) {
			break;
		}
	}

	pthread_cond_broadcast(&pool->work_cond);
	pthread_mutex_unlock(&pool->lock);
}

uint32_t ior_worker_pool_num_threads(ior_worker_pool *pool)
{
	if (!pool) {
		return 0;
	}

	pthread_mutex_lock(&pool->lock);
	uint32_t count = pool->num_threads_current;
	pthread_mutex_unlock(&pool->lock);

	return count;
}

void ior_worker_pool_thread_stats(ior_worker_pool *pool, uint32_t *active, uint32_t *idle)
{
	if (!pool) {
		if (active) {
			*active = 0;
		}
		if (idle) {
			*idle = 0;
		}
		return;
	}

	pthread_mutex_lock(&pool->lock);
	if (active) {
		*active = pool->num_threads_current - pool->num_threads_idle;
	}
	if (idle) {
		*idle = pool->num_threads_idle;
	}
	pthread_mutex_unlock(&pool->lock);
}

static void *ior_worker_pool_worker_thread_func(void *arg)
{
	ior_worker_pool_worker_t *worker = (ior_worker_pool_worker_t *) arg;
	ior_worker_pool *pool = worker->pool;

	struct timeval last_work_time;
	gettimeofday(&last_work_time, NULL);
	const uint32_t idle_timeout_ms = 30000; // 30 seconds

	IOR_LOG_TRACE("worker thread created");

	while (1) {
		pthread_mutex_lock(&pool->lock);

		// Wait for a job, exiting on shutdown (once the FIFO is drained) or
		// after being idle too long (excess thread above the minimum).
		while (!pool->job_head) {
			if (atomic_load(&pool->shutdown)) {
				pthread_mutex_unlock(&pool->lock);
				return NULL;
			}

			struct timeval now;
			gettimeofday(&now, NULL);
			long idle_ms = (now.tv_sec - last_work_time.tv_sec) * 1000
					+ (now.tv_usec - last_work_time.tv_usec) / 1000;
			if (pool->num_threads_current > pool->num_threads_min
					&& idle_ms > (long) idle_timeout_ms) {
				atomic_store(&worker->state, IOR_WORKER_POOL_THREAD_STATE_STOPPING);
				pool->num_threads_current--;
				pool->num_threads_idle--;
				pthread_mutex_unlock(&pool->lock);
				return NULL;
			}

			struct timespec timeout;
			timeout.tv_sec = now.tv_sec + 1;
			timeout.tv_nsec = now.tv_usec * 1000;
			pthread_cond_timedwait(&pool->work_cond, &pool->lock, &timeout);
		}

		ior_worker_pool_job *job = pool->job_head;
		pool->job_head = job->next;
		if (!pool->job_head) {
			pool->job_tail = NULL;
		}
		pool->jobs_pending--;
		pool->jobs_running++;
		pool->num_threads_idle--;
		pthread_mutex_unlock(&pool->lock);

		atomic_store(&worker->state, IOR_WORKER_POOL_THREAD_STATE_ACTIVE);
		gettimeofday(&last_work_time, NULL);

		pool->run(pool->owner, job);

		atomic_store(&worker->state, IOR_WORKER_POOL_THREAD_STATE_IDLE);
		pthread_mutex_lock(&pool->lock);
		pool->jobs_running--;
		pool->num_threads_idle++;
		pthread_mutex_unlock(&pool->lock);
	}

	return NULL;
}

/* Min-heap keyed on deadline_ns. All helpers run under pool->timer_lock. */
static void ior_worker_pool_timer_swap(ior_worker_pool *pool, uint32_t i, uint32_t j)
{
	ior_worker_pool_timer tmp = pool->timer_heap[i];
	pool->timer_heap[i] = pool->timer_heap[j];
	pool->timer_heap[j] = tmp;
}

static void ior_worker_pool_timer_sift_up(ior_worker_pool *pool, uint32_t idx)
{
	while (idx > 0) {
		uint32_t parent = (idx - 1) / 2;
		if (pool->timer_heap[idx].deadline_ns >= pool->timer_heap[parent].deadline_ns) {
			break;
		}
		ior_worker_pool_timer_swap(pool, idx, parent);
		idx = parent;
	}
}

static void ior_worker_pool_timer_sift_down(ior_worker_pool *pool, uint32_t idx)
{
	uint32_t len = pool->timer_heap_len;
	while (1) {
		uint32_t left = 2 * idx + 1;
		uint32_t right = 2 * idx + 2;
		uint32_t smallest = idx;

		if (left < len
				&& pool->timer_heap[left].deadline_ns < pool->timer_heap[smallest].deadline_ns) {
			smallest = left;
		}
		if (right < len
				&& pool->timer_heap[right].deadline_ns < pool->timer_heap[smallest].deadline_ns) {
			smallest = right;
		}
		if (smallest == idx) {
			break;
		}
		ior_worker_pool_timer_swap(pool, idx, smallest);
		idx = smallest;
	}
}

static int ior_worker_pool_timer_push(ior_worker_pool *pool, ior_worker_pool_timer timer)
{
	if (pool->timer_heap_len >= pool->timer_heap_cap) {
		uint32_t new_cap = pool->timer_heap_cap * 2;
		ior_worker_pool_timer *new_heap = realloc(pool->timer_heap, new_cap * sizeof(*new_heap));
		if (!new_heap) {
			return -ENOMEM;
		}
		pool->timer_heap = new_heap;
		pool->timer_heap_cap = new_cap;
	}

	pool->timer_heap[pool->timer_heap_len] = timer;
	ior_worker_pool_timer_sift_up(pool, pool->timer_heap_len);
	pool->timer_heap_len++;
	return 0;
}

static ior_worker_pool_timer ior_worker_pool_timer_pop(ior_worker_pool *pool)
{
	ior_worker_pool_timer top = pool->timer_heap[0];
	pool->timer_heap_len--;
	if (pool->timer_heap_len > 0) {
		pool->timer_heap[0] = pool->timer_heap[pool->timer_heap_len];
		ior_worker_pool_timer_sift_down(pool, 0);
	}
	return top;
}

int ior_worker_pool_arm_timer(ior_worker_pool *pool, uint64_t deadline_ns,
		ior_worker_pool_timer_fn fire, ior_worker_pool_timer_fn drop, void *arg)
{
	if (!pool || !fire) {
		return -EINVAL;
	}

	ior_worker_pool_timer timer = {
		.deadline_ns = deadline_ns,
		.fire = fire,
		.drop = drop,
		.arg = arg,
	};

	pthread_mutex_lock(&pool->timer_lock);
	int ret = ior_worker_pool_timer_push(pool, timer);
	if (ret == 0) {
		pthread_cond_signal(&pool->timer_cond);
	}
	pthread_mutex_unlock(&pool->timer_lock);

	return ret;
}

static void *ior_worker_pool_timer_thread_func(void *arg)
{
	ior_worker_pool *pool = (ior_worker_pool *) arg;

	IOR_LOG_TRACE("timer thread created");

	pthread_mutex_lock(&pool->timer_lock);

	while (!atomic_load(&pool->shutdown)) {
		// Wait for a timer to be queued.
		while (pool->timer_heap_len == 0 && !atomic_load(&pool->shutdown)) {
			pthread_cond_wait(&pool->timer_cond, &pool->timer_lock);
		}
		if (atomic_load(&pool->shutdown)) {
			break;
		}

		uint64_t now = ior_worker_pool_monotonic_ns();
		uint64_t deadline = pool->timer_heap[0].deadline_ns;

		if (deadline > now) {
			/*
			 * Sleep until the earliest deadline. pthread_cond_timedwait uses
			 * CLOCK_REALTIME, so convert the monotonic remaining time into an
			 * absolute realtime deadline. A wall-clock step only causes an
			 * early wakeup, after which we recompute against the monotonic
			 * clock and wait again - so the duration stays monotonic-based.
			 */
			uint64_t remaining_ns = deadline - now;
			struct timespec rt;
			clock_gettime(CLOCK_REALTIME, &rt);
			uint64_t abs_ns
					= (uint64_t) rt.tv_sec * 1000000000ULL + (uint64_t) rt.tv_nsec + remaining_ns;
			struct timespec until = {
				.tv_sec = (time_t) (abs_ns / 1000000000ULL),
				.tv_nsec = (long) (abs_ns % 1000000000ULL),
			};
			pthread_cond_timedwait(&pool->timer_cond, &pool->timer_lock, &until);
			continue;
		}

		// Earliest timer has expired: pop it and fire outside the lock.
		ior_worker_pool_timer fired = ior_worker_pool_timer_pop(pool);
		pthread_mutex_unlock(&pool->timer_lock);

		fired.fire(pool->owner, fired.arg);

		pthread_mutex_lock(&pool->timer_lock);
	}

	pthread_mutex_unlock(&pool->timer_lock);
	IOR_LOG_TRACE("timer thread exiting");
	return NULL;
}

#endif /* IOR_HAVE_THREADS || IOR_HAVE_URING */
