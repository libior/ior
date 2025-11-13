/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef IOR_THREADS_RING_H
#define IOR_THREADS_RING_H

#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include "ior.h" // For ior_cqe, ior_sqe

// Maximum ring sizes (mirror io_uring kernel limits)
#define IOR_THREADS_RING_MAX_ENTRIES 32768 // 32K max SQ entries
#define IOR_THREADS_RING_MAX_CQ_ENTRIES 65536 // 64K max CQ entries (2x SQ)

/*
 * Ring buffer with out-of-order completion support:
 *
 *   head        picked         tail         cached_tail
 *    |            |             |                |
 *    v            v             v                v
 *    [completed][picked/processing][submitted][reserved]
 *
 * Out-of-order completion:
 * - Workers complete SQEs in any order
 * - completed[] bitmap tracks which positions finished
 * - head advances when SQE at head position completes
 * - head_cond signals when head moves (for DRAIN)
 */
typedef struct ior_threads_ring {
	void *entries; // Continuous array of entries
	uint32_t size; // Number of entries (power of 2)
	uint32_t mask; // size - 1 (for fast masking)
	size_t entry_size; // sizeof(ior_sqe) or sizeof(ior_cqe)
	uint8_t is_sq; // 1 for SQ, 0 for CQ

	_Atomic uint32_t head; // Next to consume (moves when head completes)
	_Atomic uint32_t tail; // Submitted/visible to workers

	// For SQ only:
	_Atomic uint32_t cached_tail; // Reserved (get_sqe increments)
	_Atomic uint32_t picked; // Picked by workers

	// Out-of-order completion tracking (SQ only)
	uint8_t *completed; // Bitmap: 1 if position completed
	pthread_mutex_t head_lock; // Protects head advancement
	pthread_cond_t head_cond; // Signals when head moves
} ior_threads_ring;

// Initialize ring with given size (must be power of 2)
int ior_threads_ring_init(ior_threads_ring *ring, uint32_t size, uint8_t is_sq);

// Destroy ring and free memory
void ior_threads_ring_destroy(ior_threads_ring *ring);

// ===== Helper Functions =====

uint32_t ior_threads_ring_count(ior_threads_ring *ring);
uint32_t ior_threads_ring_pending_count(ior_threads_ring *ring);
int ior_threads_ring_empty(ior_threads_ring *ring);
int ior_threads_ring_full(ior_threads_ring *ring);
uint32_t ior_threads_ring_space(ior_threads_ring *ring);

// ===== Submission Queue Operations =====

// Get next SQE slot (increments cached_tail)
ior_sqe *ior_threads_ring_get_sqe(ior_threads_ring *ring);

// Submit pending SQEs (moves tail to cached_tail)
void ior_threads_ring_submit(ior_threads_ring *ring);

// Pick next SQE for processing (increments picked, returns position)
ior_sqe *ior_threads_ring_pick_sqe(ior_threads_ring *ring, uint64_t *sqe_position);

// Mark SQE at position as completed (advances head if possible, broadcasts head_cond)
void ior_threads_ring_complete_sqe(ior_threads_ring *ring, uint64_t sqe_position);

// Wait until head >= position (for DRAIN)
int ior_threads_ring_wait_until_head(ior_threads_ring *ring, uint64_t position);

// ===== Completion Queue Operations =====

int ior_threads_ring_post_cqe(ior_threads_ring *ring, const ior_cqe *cqe);
ior_cqe *ior_threads_ring_peek_cqe(ior_threads_ring *ring);
void ior_threads_ring_cqe_seen(ior_threads_ring *ring);
uint32_t ior_threads_ring_peek_batch_cqe(ior_threads_ring *ring, ior_cqe **cqes, uint32_t max);
void ior_threads_ring_advance(ior_threads_ring *ring, uint32_t count);

// ===== Ring Management =====

int ior_threads_ring_resize(ior_threads_ring *ring, uint32_t new_size);

#endif /* IOR_THREADS_RING_H */
