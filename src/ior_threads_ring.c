/* SPDX-License-Identifier: BSD-3-Clause */
#include "ior_threads_ring.h"
#include "ior_backend.h"
#include "ior.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Maximum ring sizes (mirror io_uring kernel limits)
#define IOR_THREADS_RING_MAX_ENTRIES 32768 // 32K max SQ entries
#define IOR_THREADS_RING_MAX_CQ_ENTRIES 65536 // 64K max CQ entries (2x SQ)

// Check if size is power of 2
static inline int ior_threads_ring_is_power_of_2(uint32_t n)
{
	return n && !(n & (n - 1));
}

int ior_threads_ring_init(ior_threads_ring *ring, uint32_t size, uint8_t is_sq)
{
	if (!ring || size == 0) {
		return -EINVAL;
	}

	// Size must be power of 2
	if (!ior_threads_ring_is_power_of_2(size)) {
		return -EINVAL;
	}

	// Check maximum size limits
	uint32_t max_size = is_sq ? IOR_THREADS_RING_MAX_ENTRIES : IOR_THREADS_RING_MAX_CQ_ENTRIES;
	if (size > max_size) {
		return -EINVAL;
	}

	memset(ring, 0, sizeof(*ring));

	ring->size = size;
	ring->mask = size - 1;
	ring->is_sq = is_sq;
	ring->entry_size = is_sq ? sizeof(ior_sqe) : sizeof(ior_cqe);

	// Allocate continuous array
	ring->entries = calloc(size, ring->entry_size);
	if (!ring->entries) {
		return -ENOMEM;
	}

	atomic_init(&ring->head, 0);
	atomic_init(&ring->tail, 0);
	ring->cached_tail = 0;

	return 0;
}

void ior_threads_ring_destroy(ior_threads_ring *ring)
{
	if (ring && ring->entries) {
		free(ring->entries);
		ring->entries = NULL;
	}
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

uint32_t ior_threads_ring_cached_count(ior_threads_ring *ring)
{
	if (!ring) {
		return 0;
	}

	return atomic_load_explicit(&ring->cached_tail, memory_order_acquire);
}

int ior_threads_ring_empty(ior_threads_ring *ring)
{
	if (!ring) {
		return 1;
	}

	uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
	uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);

	return head == tail;
}

int ior_threads_ring_full(ior_threads_ring *ring)
{
	if (!ring) {
		return 1;
	}

	uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
	uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);

	return (tail - head) >= ring->size;
}

uint32_t ior_threads_ring_space(ior_threads_ring *ring)
{
	if (!ring) {
		return 0;
	}

	uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
	uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
	uint32_t used = tail - head;

	return ring->size - used;
}

// ===== Submission Queue Operations =====

// Get next available SQE slot for filling
// This increments cached_tail (local counter) but does NOT publish to consumers
// Call ior_threads_ring_submit() to publish entries and make them visible
//
// Usage pattern:
//   ior_sqe *sqe1 = ior_threads_ring_get_sqe(&ring);  // cached_tail = 1
//   sqe1->opcode = ...;
//   ior_sqe *sqe2 = ior_threads_ring_get_sqe(&ring);  // cached_tail = 2
//   sqe2->opcode = ...;
//   ior_threads_ring_submit(&ring, 2);  // tail = 2, now visible to workers
//
ior_sqe *ior_threads_ring_get_sqe(ior_threads_ring *ring)
{
	if (!ring || !ring->is_sq) {
		return NULL;
	}

	// Check if ring is full using cached_tail (local pending count)
	uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);

	if (ring->cached_tail - head >= ring->size) {
		return NULL; // Ring full
	}

	// Get index using cached_tail (not yet published tail)
	uint32_t index = ring->cached_tail & ring->mask;

	// Increment cached_tail for next get_sqe call
	ring->cached_tail++;

	// Return pointer to entry (tail not advanced until submit)
	ior_sqe *sqes = (ior_sqe *) ring->entries;
	return &sqes[index];
}

void ior_threads_ring_submit(ior_threads_ring *ring, uint32_t count)
{
	if (!ring || !ring->is_sq || count == 0) {
		return;
	}

	// Get current tail and advance by count
	uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);

	// Publish entries by advancing tail
	// This makes the entries visible to consumers
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

	// Get index using mask
	uint32_t index = head & ring->mask;

	ior_sqe *sqes = (ior_sqe *) ring->entries;
	return &sqes[index];
}

void ior_threads_ring_consume_sqe(ior_threads_ring *ring)
{
	if (!ring || !ring->is_sq) {
		return;
	}

	// Advance head to consume entry
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
		return -EOVERFLOW; // Ring full (caller must handle)
	}

	// Get index using mask
	uint32_t index = tail & ring->mask;

	// Write CQE data
	ior_cqe *cqes = (ior_cqe *) ring->entries;
	cqes[index] = *cqe;

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

	// Get index using mask
	uint32_t index = head & ring->mask;

	ior_cqe *cqes = (ior_cqe *) ring->entries;
	return &cqes[index];
}

void ior_threads_ring_cqe_seen(ior_threads_ring *ring)
{
	if (!ring || ring->is_sq) {
		return;
	}

	// Advance head to consume entry
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
		uint32_t index = (head + i) & ring->mask;
		cqes[i] = &ring_cqes[index];
	}

	return count;
}

void ior_threads_ring_advance(ior_threads_ring *ring, uint32_t count)
{
	if (!ring || ring->is_sq || count == 0) {
		return;
	}

	// Advance head by multiple entries
	uint32_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
	atomic_store_explicit(&ring->head, head + count, memory_order_release);
}

// ===== Ring Expansion =====

int ior_threads_ring_resize(ior_threads_ring *ring, uint32_t new_size)
{
	if (!ring || new_size == 0) {
		return -EINVAL;
	}

	if (!ior_threads_ring_is_power_of_2(new_size)) {
		return -EINVAL;
	}

	// Check maximum size limits
	uint32_t max_size
			= ring->is_sq ? IOR_THREADS_RING_MAX_ENTRIES : IOR_THREADS_RING_MAX_CQ_ENTRIES;
	if (new_size > max_size) {
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
	ring->cached_tail = 0;

	return 0;
}
