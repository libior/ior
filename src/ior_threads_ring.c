/* SPDX-License-Identifier: BSD-3-Clause */
#include "ior_threads_ring.h"
#include "ior_backend.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Maximum ring sizes
#define IOR_THREADS_RING_MAX_ENTRIES 32768
#define IOR_THREADS_RING_MAX_CQ_ENTRIES 65536

static inline int ior_threads_ring_is_power_of_2(uint32_t n)
{
	return n && !(n & (n - 1));
}

int ior_threads_ring_init(ior_threads_ring *ring, uint32_t size, uint8_t is_sq)
{
	if (!ring || size == 0 || !ior_threads_ring_is_power_of_2(size)) {
		return -EINVAL;
	}

	uint32_t max_size = is_sq ? IOR_THREADS_RING_MAX_ENTRIES : IOR_THREADS_RING_MAX_CQ_ENTRIES;
	if (size > max_size) {
		return -EINVAL;
	}

	memset(ring, 0, sizeof(*ring));

	ring->entries = calloc(size, is_sq ? sizeof(ior_sqe) : sizeof(ior_cqe));
	if (!ring->entries) {
		return -ENOMEM;
	}

	ring->size = size;
	ring->mask = size - 1;
	ring->is_sq = is_sq;
	ring->entry_size = is_sq ? sizeof(ior_sqe) : sizeof(ior_cqe);

	atomic_init(&ring->head, 0);
	atomic_init(&ring->tail, 0);
	atomic_init(&ring->cached_tail, 0);
	atomic_init(&ring->picked, 0);

	if (is_sq) {
		ring->completed = calloc(size, sizeof(uint8_t));
		if (!ring->completed) {
			free(ring->entries);
			return -ENOMEM;
		}

		if (pthread_mutex_init(&ring->head_lock, NULL) != 0) {
			free(ring->completed);
			free(ring->entries);
			return -ENOMEM;
		}

		if (pthread_cond_init(&ring->head_cond, NULL) != 0) {
			pthread_mutex_destroy(&ring->head_lock);
			free(ring->completed);
			free(ring->entries);
			return -ENOMEM;
		}
	}

	return 0;
}

void ior_threads_ring_destroy(ior_threads_ring *ring)
{
	if (!ring) {
		return;
	}

	if (ring->is_sq) {
		pthread_cond_destroy(&ring->head_cond);
		pthread_mutex_destroy(&ring->head_lock);
		free(ring->completed);
	}

	free(ring->entries);
	ring->entries = NULL;
}

// ===== Helper Functions =====

uint32_t ior_threads_ring_count(ior_threads_ring *ring)
{
	if (!ring) {
		return 0;
	}
	uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
	uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
	return tail - head;
}

uint32_t ior_threads_ring_pending_count(ior_threads_ring *ring)
{
	if (!ring || !ring->is_sq) {
		return 0;
	}
	uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
	uint32_t cached = atomic_load_explicit(&ring->cached_tail, memory_order_acquire);
	return cached - tail;
}

int ior_threads_ring_empty(ior_threads_ring *ring)
{
	return ior_threads_ring_count(ring) == 0;
}

int ior_threads_ring_full(ior_threads_ring *ring)
{
	if (!ring) {
		return 1;
	}
	uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
	uint32_t cached = ring->is_sq ? atomic_load_explicit(&ring->cached_tail, memory_order_acquire)
								  : atomic_load_explicit(&ring->tail, memory_order_acquire);
	return (cached - head) >= ring->size;
}

uint32_t ior_threads_ring_space(ior_threads_ring *ring)
{
	if (!ring) {
		return 0;
	}
	return ring->size
			- (ring->is_sq ? (atomic_load(&ring->cached_tail) - atomic_load(&ring->head))
						   : (atomic_load(&ring->tail) - atomic_load(&ring->head)));
}

// ===== Submission Queue Operations =====

ior_sqe *ior_threads_ring_get_sqe(ior_threads_ring *ring)
{
	if (!ring || !ring->is_sq) {
		return NULL;
	}

	uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
	uint32_t cached = atomic_load_explicit(&ring->cached_tail, memory_order_relaxed);

	if (cached - head >= ring->size) {
		return NULL; // Full
	}

	uint32_t index = cached & ring->mask;
	atomic_store_explicit(&ring->cached_tail, cached + 1, memory_order_release);

	return &((ior_sqe *) ring->entries)[index];
}

void ior_threads_ring_submit(ior_threads_ring *ring)
{
	if (!ring || !ring->is_sq) {
		return;
	}

	uint32_t cached = atomic_load_explicit(&ring->cached_tail, memory_order_acquire);
	atomic_store_explicit(&ring->tail, cached, memory_order_release);
}

ior_sqe *ior_threads_ring_pick_sqe(ior_threads_ring *ring, uint64_t *sqe_position)
{
	if (!ring || !ring->is_sq) {
		return NULL;
	}

	uint32_t picked = atomic_load_explicit(&ring->picked, memory_order_relaxed);
	uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);

	if (picked >= tail) {
		return NULL; // Nothing to pick
	}

	// Atomically claim this position
	if (!atomic_compare_exchange_strong_explicit(
				&ring->picked, &picked, picked + 1, memory_order_acq_rel, memory_order_relaxed)) {
		return NULL; // Another thread got it
	}

	if (sqe_position) {
		*sqe_position = picked;
	}

	uint32_t index = picked & ring->mask;
	return &((ior_sqe *) ring->entries)[index];
}

void ior_threads_ring_complete_sqe(ior_threads_ring *ring, uint64_t sqe_position)
{
	if (!ring || !ring->is_sq) {
		return;
	}

	pthread_mutex_lock(&ring->head_lock);

	// Mark this position as completed
	uint32_t index = sqe_position & ring->mask;
	ring->completed[index] = 1;

	// Try to advance head
	uint32_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
	uint32_t new_head = head;

	// Advance head past all completed entries
	while (ring->completed[new_head & ring->mask]) {
		ring->completed[new_head & ring->mask] = 0; // Clear for reuse
		new_head++;
	}

	if (new_head != head) {
		atomic_store_explicit(&ring->head, new_head, memory_order_release);
		pthread_cond_broadcast(&ring->head_cond); // Wake DRAIN waiters
	}

	pthread_mutex_unlock(&ring->head_lock);
}

int ior_threads_ring_wait_until_head(ior_threads_ring *ring, uint64_t position)
{
	if (!ring || !ring->is_sq) {
		return -EINVAL;
	}

	pthread_mutex_lock(&ring->head_lock);

	while (atomic_load_explicit(&ring->head, memory_order_acquire) < position) {
		pthread_cond_wait(&ring->head_cond, &ring->head_lock);
	}

	pthread_mutex_unlock(&ring->head_lock);
	return 0;
}

// ===== Completion Queue Operations =====

int ior_threads_ring_post_cqe(ior_threads_ring *ring, const ior_cqe *cqe)
{
	if (!ring || ring->is_sq || !cqe) {
		return -EINVAL;
	}

	uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
	uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);

	if (tail - head >= ring->size) {
		return -EOVERFLOW;
	}

	uint32_t index = tail & ring->mask;
	((ior_cqe *) ring->entries)[index] = *cqe;

	atomic_store_explicit(&ring->tail, tail + 1, memory_order_release);
	return 0;
}

ior_cqe *ior_threads_ring_peek_cqe(ior_threads_ring *ring)
{
	if (!ring || ring->is_sq) {
		return NULL;
	}

	uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
	uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);

	if (head == tail) {
		return NULL;
	}

	return &((ior_cqe *) ring->entries)[head & ring->mask];
}

void ior_threads_ring_cqe_seen(ior_threads_ring *ring)
{
	if (!ring || ring->is_sq) {
		return;
	}

	uint32_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
	atomic_store_explicit(&ring->head, head + 1, memory_order_release);
}

uint32_t ior_threads_ring_peek_batch_cqe(ior_threads_ring *ring, ior_cqe **cqes, uint32_t max)
{
	if (!ring || ring->is_sq || !cqes || max == 0) {
		return 0;
	}

	uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
	uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
	uint32_t available = tail - head;

	if (available == 0) {
		return 0;
	}

	uint32_t count = available < max ? available : max;
	ior_cqe *ring_cqes = (ior_cqe *) ring->entries;

	for (uint32_t i = 0; i < count; i++) {
		cqes[i] = &ring_cqes[(head + i) & ring->mask];
	}

	return count;
}

void ior_threads_ring_advance(ior_threads_ring *ring, uint32_t count)
{
	if (!ring || ring->is_sq || count == 0) {
		return;
	}

	uint32_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
	atomic_store_explicit(&ring->head, head + count, memory_order_release);
}

// ===== Ring Management =====

int ior_threads_ring_resize(ior_threads_ring *ring, uint32_t new_size)
{
	if (!ring || new_size == 0 || !ior_threads_ring_is_power_of_2(new_size)) {
		return -EINVAL;
	}

	uint32_t max = ring->is_sq ? IOR_THREADS_RING_MAX_ENTRIES : IOR_THREADS_RING_MAX_CQ_ENTRIES;
	if (new_size > max) {
		return -EINVAL;
	}

	uint32_t head = atomic_load(&ring->head);
	uint32_t tail = atomic_load(&ring->tail);

	if (head != tail) {
		return -EBUSY;
	}

	void *new_entries = calloc(new_size, ring->entry_size);
	if (!new_entries) {
		return -ENOMEM;
	}

	uint8_t *new_completed = NULL;
	if (ring->is_sq) {
		new_completed = calloc(new_size, sizeof(uint8_t));
		if (!new_completed) {
			free(new_entries);
			return -ENOMEM;
		}
	}

	free(ring->entries);
	ring->entries = new_entries;
	ring->size = new_size;
	ring->mask = new_size - 1;

	if (ring->is_sq) {
		free(ring->completed);
		ring->completed = new_completed;
	}

	atomic_store(&ring->head, 0);
	atomic_store(&ring->tail, 0);
	atomic_store(&ring->cached_tail, 0);
	atomic_store(&ring->picked, 0);

	return 0;
}
