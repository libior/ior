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
	atomic_init(&ring->consumed, 0);

	// The SQ ring is pure staging (get_sqe/submit/consume move the cursors above,
	// no extra state). The CQ ring serializes its multiple producers (worker
	// threads and the timer thread) through tail_lock.
	if (!is_sq) {
		if (pthread_mutex_init(&ring->tail_lock, NULL) != 0) {
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

	if (!ring->is_sq) {
		pthread_mutex_destroy(&ring->tail_lock);
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

// ===== Submission Queue Operations =====

ior_sqe *ior_threads_ring_get_sqe(ior_threads_ring *ring)
{
	if (!ring || !ring->is_sq) {
		return NULL;
	}

	/*
	 * The staging ring only holds reserved-but-not-yet-copied SQEs: submit copies
	 * them out and advances `consumed`, so a slot is free again right after submit
	 * regardless of how long the operation runs.
	 */
	uint32_t consumed = atomic_load_explicit(&ring->consumed, memory_order_acquire);
	uint32_t cached = atomic_load_explicit(&ring->cached_tail, memory_order_relaxed);

	if (cached - consumed >= ring->size) {
		return NULL; // Full
	}

	uint32_t index = cached & ring->mask;
	atomic_store_explicit(&ring->cached_tail, cached + 1, memory_order_release);

	return &((ior_sqe *) ring->entries)[index];
}

void ior_threads_ring_consume(ior_threads_ring *ring)
{
	if (!ring || !ring->is_sq) {
		return;
	}

	uint32_t cached = atomic_load_explicit(&ring->cached_tail, memory_order_acquire);
	atomic_store_explicit(&ring->consumed, cached, memory_order_release);
}

// ===== Completion Queue Operations =====

int ior_threads_ring_post_cqe(ior_threads_ring *ring, const ior_cqe *cqe)
{
	if (!ring || ring->is_sq || !cqe) {
		return -EINVAL;
	}

	/*
	 * Multiple producers (worker threads and the timer thread) may post
	 * concurrently, so the read-modify-write of tail must be serialized;
	 * otherwise two producers could claim the same slot and lose a completion.
	 * The single consumer never takes this lock - it only reads tail (acquire)
	 * and owns head - so this stays a lightweight MPSC handoff.
	 */
	pthread_mutex_lock(&ring->tail_lock);

	uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
	uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);

	if (tail - head >= ring->size) {
		pthread_mutex_unlock(&ring->tail_lock);
		return -EOVERFLOW;
	}

	uint32_t index = tail & ring->mask;
	((ior_cqe *) ring->entries)[index] = *cqe;

	atomic_store_explicit(&ring->tail, tail + 1, memory_order_release);

	pthread_mutex_unlock(&ring->tail_lock);
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
