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
 * A single ring buffer used in two roles, selected by is_sq:
 *
 * - SQ ring (staging only): get_sqe reserves a slot (cached_tail), the caller
 *   fills it, and submit copies it out and advances `consumed` to free the slot.
 *   A slot is therefore free again right after submit, never held for the life of
 *   the operation - matching io_uring, which consumes an SQE at submit time.
 *
 * - CQ ring (MPSC completions): worker threads and the timer thread post CQEs
 *   (serialized by tail_lock) and the single consumer reaps them via head.
 */
typedef struct ior_threads_ring {
	void *entries; // Continuous array of entries
	uint32_t size; // Number of entries (power of 2)
	uint32_t mask; // size - 1 (for fast masking)
	size_t entry_size; // sizeof(ior_sqe) or sizeof(ior_cqe)
	uint8_t is_sq; // 1 for SQ, 0 for CQ

	_Atomic uint32_t head; // CQ: next completion to reap
	_Atomic uint32_t tail; // CQ: next slot to post into

	// SQ only: staging cursors. get_sqe reserves at cached_tail; submit copies
	// the staged SQEs out and advances consumed to free their slots.
	_Atomic uint32_t cached_tail; // Reserved by get_sqe
	_Atomic uint32_t consumed; // Freed once copied out at submit

	// CQ only: serializes the multiple completion producers (worker threads and
	// the timer thread) against the single consumer. Completions are MPSC.
	pthread_mutex_t tail_lock;
} ior_threads_ring;

// Initialize ring with given size (must be power of 2)
int ior_threads_ring_init(ior_threads_ring *ring, uint32_t size, uint8_t is_sq);

// Destroy ring and free memory
void ior_threads_ring_destroy(ior_threads_ring *ring);

// ===== Helper Functions =====

uint32_t ior_threads_ring_count(ior_threads_ring *ring);
int ior_threads_ring_empty(ior_threads_ring *ring);
int ior_threads_ring_full(ior_threads_ring *ring);

// ===== Submission Queue Operations (staging) =====

// Reserve the next SQE slot (advances cached_tail); NULL if the staging ring is
// full of not-yet-submitted entries.
ior_sqe *ior_threads_ring_get_sqe(ior_threads_ring *ring);

// Free all reserved staging slots up to cached_tail (advance consumed). Called
// once submit has copied the staged SQEs out of the ring.
void ior_threads_ring_consume(ior_threads_ring *ring);

// ===== Completion Queue Operations =====

int ior_threads_ring_post_cqe(ior_threads_ring *ring, const ior_cqe *cqe);
ior_cqe *ior_threads_ring_peek_cqe(ior_threads_ring *ring);
void ior_threads_ring_cqe_seen(ior_threads_ring *ring);
uint32_t ior_threads_ring_peek_batch_cqe(ior_threads_ring *ring, ior_cqe **cqes, uint32_t max);
void ior_threads_ring_advance(ior_threads_ring *ring, uint32_t count);

#endif /* IOR_THREADS_RING_H */
