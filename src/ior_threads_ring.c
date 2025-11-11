#include "ior_threads_ring.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Check if size is power of 2
static inline int is_power_of_2(uint32_t n)
{
	return n && !(n & (n - 1));
}

int ior_threads_ring_init(ior_threads_ring *ring, uint32_t size, uint8_t is_sq)
{
	if (!ring || size == 0) {
		return -EINVAL;
	}

	// Size must be power of 2 for fast masking
	if (!is_power_of_2(size)) {
		return -EINVAL;
	}

	memset(ring, 0, sizeof(*ring));

	ring->size = size;
	ring->mask = size - 1;
	ring->is_sq = is_sq;
	ring->entry_size = is_sq ? sizeof(ior_sqe) : sizeof(ior_cqe);

	// Allocate ring buffer
	ring->entries = calloc(size, ring->entry_size);
	if (!ring->entries) {
		return -ENOMEM;
	}

	atomic_init(&ring->head, 0);
	atomic_init(&ring->tail, 0);

	return 0;
}

void ior_threads_ring_destroy(ior_threads_ring *ring)
{
	if (ring && ring->entries) {
		free(ring->entries);
		ring->entries = NULL;
	}
}

// ===== Submission Queue Operations =====

ior_sqe *ior_threads_ring_get_sqe(ior_threads_ring *ring)
{
	if (!ring || !ring->is_sq) {
		return NULL;
	}

	// Check if ring is full
	uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
	uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);

	if (tail - head >= ring->size) {
		return NULL; // Ring full
	}

	// Return pointer to next entry (don't advance tail yet)
	ior_sqe *sqes = (ior_sqe *) ring->entries;
	return &sqes[tail & ring->mask];
}

void ior_threads_ring_submit(ior_threads_ring *ring, uint32_t count)
{
	if (!ring || !ring->is_sq || count == 0) {
		return;
	}

	uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
	atomic_store_explicit(&ring->tail, tail + count, memory_order_release);
}

ior_sqe *ior_threads_ring_peek_sqe(ior_threads_ring *ring)
{
	if (!ring || !ring->is_sq) {
		return NULL;
	}

	uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
	uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);

	if (head == tail) {
		return NULL; // Empty
	}

	ior_sqe *sqes = (ior_sqe *) ring->entries;
	return &sqes[head & ring->mask];
}

void ior_threads_ring_consume_sqe(ior_threads_ring *ring)
{
	if (!ring || !ring->is_sq) {
		return;
	}

	uint32_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
	atomic_store_explicit(&ring->head, head + 1, memory_order_release);
}

// ===== Completion Queue Operations =====

int ior_threads_ring_post_cqe(ior_threads_ring *ring, const ior_cqe *cqe)
{
	if (!ring || ring->is_sq || !cqe) {
		return -EINVAL;
	}

	// Check if ring is full
	uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
	uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);

	if (tail - head >= ring->size) {
		return -EOVERFLOW; // Ring full - should be rare with proper sizing
	}

	// Write CQE data
	ior_cqe *cqes = (ior_cqe *) ring->entries;
	uint32_t idx = tail & ring->mask;
	cqes[idx] = *cqe;

	// Publish by advancing tail
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
		return NULL; // Empty
	}

	ior_cqe *cqes = (ior_cqe *) ring->entries;
	return &cqes[head & ring->mask];
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

// ===== Ring Expansion =====

int ior_threads_ring_resize(ior_threads_ring *ring, uint32_t new_size)
{
	if (!ring || new_size == 0) {
		return -EINVAL;
	}

	if (!is_power_of_2(new_size)) {
		return -EINVAL;
	}

	// Check if ring is empty (required for safe resize)
	uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
	uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);

	if (head != tail) {
		return -EBUSY; // Ring must be drained first
	}

	// Allocate new buffer
	void *new_entries = calloc(new_size, ring->entry_size);
	if (!new_entries) {
		return -ENOMEM;
	}

	// Free old buffer and update
	free(ring->entries);
	ring->entries = new_entries;
	ring->size = new_size;
	ring->mask = new_size - 1;

	// Reset indices
	atomic_store_explicit(&ring->head, 0, memory_order_release);
	atomic_store_explicit(&ring->tail, 0, memory_order_release);

	return 0;
}
