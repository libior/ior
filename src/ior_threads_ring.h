/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef IOR_THREADS_RING_H
#define IOR_THREADS_RING_H

#include <stdint.h>
#include <stdatomic.h>
#include "ior.h" // For ior_cqe, ior_sqe

// Ring buffer structure
typedef struct ior_threads_ring {
	void *entries; // Array of entries (ior_sqe or ior_cqe)
	uint32_t size; // Number of entries (must be power of 2)
	uint32_t mask; // size - 1 (for fast modulo)
	size_t entry_size; // sizeof(ior_sqe) or sizeof(ior_cqe)

	_Atomic uint32_t head; // Consumer index
	_Atomic uint32_t tail; // Producer index

	uint8_t is_sq; // 1 if submission queue, 0 if completion queue
} ior_threads_ring;

// Initialize ring with given size (must be power of 2)
// is_sq: 1 for SQ, 0 for CQ
int ior_threads_ring_init(ior_threads_ring *ring, uint32_t size, uint8_t is_sq);

// Destroy ring and free memory
void ior_threads_ring_destroy(ior_threads_ring *ring);

// Check if ring is empty
static inline int ior_threads_ring_empty(ior_threads_ring *ring)
{
	uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
	uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
	return head == tail;
}

// Check if ring is full
static inline int ior_threads_ring_full(ior_threads_ring *ring)
{
	uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
	uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
	return (tail - head) >= ring->size;
}

// Get number of available entries to consume
static inline uint32_t ior_threads_ring_count(ior_threads_ring *ring)
{
	uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
	uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
	return tail - head;
}

// Get available space for producing
static inline uint32_t ior_threads_ring_space(ior_threads_ring *ring)
{
	uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
	uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
	return ring->size - (tail - head);
}

// ===== Submission Queue Operations =====

// Get next available SQE slot (returns NULL if full)
ior_sqe *ior_threads_ring_get_sqe(ior_threads_ring *ring);

// Submit all pending SQEs (advance tail)
void ior_threads_ring_submit(ior_threads_ring *ring, uint32_t count);

// Peek at next SQE to process (for workers)
ior_sqe *ior_threads_ring_peek_sqe(ior_threads_ring *ring);

// Mark SQE as consumed (advance head)
void ior_threads_ring_consume_sqe(ior_threads_ring *ring);

// ===== Completion Queue Operations =====

// Post a completion (returns 0 on success, -EOVERFLOW if full)
int ior_threads_ring_post_cqe(ior_threads_ring *ring, const ior_cqe *cqe);

// Peek at next CQE (returns NULL if empty)
ior_cqe *ior_threads_ring_peek_cqe(ior_threads_ring *ring);

// Mark CQE as seen/consumed (advance head)
void ior_threads_ring_cqe_seen(ior_threads_ring *ring);

// Batch peek multiple CQEs
uint32_t ior_threads_ring_peek_batch_cqe(ior_threads_ring *ring, ior_cqe **cqes, uint32_t max);

// Advance head by multiple entries
void ior_threads_ring_advance(ior_threads_ring *ring, uint32_t count);

// ===== Ring Expansion (Optional - for future) =====

// Resize ring (requires draining first - not lock-free!)
// Returns 0 on success, negative on error
int ior_threads_ring_resize(ior_threads_ring *ring, uint32_t new_size);

#endif /* IOR_THREADS_RING_H */
