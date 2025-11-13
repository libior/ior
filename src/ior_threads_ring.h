/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef IOR_THREADS_RING_H
#define IOR_THREADS_RING_H

#include <stdint.h>
#include <stdatomic.h>
#include "ior.h" // For ior_cqe, ior_sqe

// Maximum ring sizes (mirror io_uring kernel limits)
#define IOR_THREADS_RING_MAX_ENTRIES 32768 // 32K max SQ entries
#define IOR_THREADS_RING_MAX_CQ_ENTRIES 65536 // 64K max CQ entries (2x SQ)

// Ring buffer structure - fixed size, continuous array
typedef struct ior_threads_ring {
	void *entries; // Continuous array of entries
	uint32_t size; // Number of entries (power of 2)
	uint32_t mask; // size - 1 (for fast masking)
	size_t entry_size; // sizeof(ior_sqe) or sizeof(ior_cqe)
	uint8_t is_sq; // 1 for SQ, 0 for CQ

	_Atomic uint32_t head; // Consumer index (free-flowing)
	_Atomic uint32_t tail; // Producer index (free-flowing)

	// For SQ only: track pending submissions
	_Atomic uint32_t cached_tail; // Local tail for get_sqe (not yet published)
} ior_threads_ring;

// Initialize ring with given size (must be power of 2)
// size: Number of entries (64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768)
// is_sq: 1 for submission queue, 0 for completion queue
int ior_threads_ring_init(ior_threads_ring *ring, uint32_t size, uint8_t is_sq);

// Destroy ring and free memory
void ior_threads_ring_destroy(ior_threads_ring *ring);

// ===== Helper Functions =====

// Get number of entries currently in ring
uint32_t ior_threads_ring_count(ior_threads_ring *ring);

// Get number of cached entries currently in ring
uint32_t ior_threads_ring_cached_count(ior_threads_ring *ring);

// Check if ring is empty
int ior_threads_ring_empty(ior_threads_ring *ring);

// Check if ring is full
int ior_threads_ring_full(ior_threads_ring *ring);

// Get available space in ring
uint32_t ior_threads_ring_space(ior_threads_ring *ring);

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

// ===== Ring Expansion =====

// Resize ring (requires draining first - not lock-free!)
// Returns 0 on success, negative on error
// NOTE: Ring must be empty (head == tail) for resize to succeed
int ior_threads_ring_resize(ior_threads_ring *ring, uint32_t new_size);

#endif /* IOR_THREADS_RING_H */
