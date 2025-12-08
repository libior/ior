/* SPDX-License-Identifier: BSD-3-Clause */
#include "config.h"

#ifdef IOR_HAVE_IOCP

#include "ior_backend.h"
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <windows.h>
#include <assert.h>
#include <stdatomic.h>

// ETIME is used for timer expiration (matches io_uring semantics)
#ifndef ETIME
#define ETIME 62 // Match Linux value
#endif

/*
 * Handle tracking for IOCP association
 * Windows requires each handle to be associated with exactly one IOCP
 */
#define HANDLE_SET_SIZE 256

typedef struct handle_set_entry {
	HANDLE handle;
	struct handle_set_entry *next;
} handle_set_entry;

typedef struct handle_set {
	handle_set_entry *buckets[HANDLE_SET_SIZE];
	CRITICAL_SECTION lock;
} handle_set;

/* IOCP operation structure - wraps OVERLAPPED */
typedef struct ior_iocp_op {
	OVERLAPPED overlapped; // MUST be first for GetQueuedCompletionStatus casting
	ior_cqe cqe; // Embedded CQE - stable until cqe_seen()

	// Operation metadata (matches SQE fields)
	uint8_t opcode;
	uint8_t sqe_flags;
	uint16_t ioprio;
	ior_fd_t fd;
	uint64_t user_data;

	// I/O parameters
	void *buf;
	uint32_t len;
	uint64_t offset;

	// Timeout-specific fields
	ior_timespec *timeout_ts;
	uint32_t timeout_flags;

	// Timer bookkeeping (for IOR_OP_TIMER)
	uint64_t timer_deadline_ns; // Absolute deadline in monotonic time
	bool timer_armed; // True once enqueued into timer heap
	bool timer_cancelled; // True if timer was cancelled (future use)

	// Scheduling / ordering
	uint64_t seq; // submission sequence (1..)
	uint64_t drain_after; // for DRAIN: must wait until completed_count >= drain_after
	struct ior_iocp_op *link_next;

	bool linked_deferred; // true while waiting for predecessor in a LINK chain
	bool drain_deferred; // true while waiting for DRAIN barrier

	// Pending list linkage (for drain-deferred heads, and link-next heads that hit DRAIN)
	struct ior_iocp_op *next_pending;

	// Result tracking (filled by completion)
	DWORD bytes_transferred;
	DWORD error_code;

	// Flags for completion handling
	bool is_synthetic; // True if synthetic completion

	// Free list linkage (preserved across prep_*)
	struct ior_iocp_op *next_free;
} ior_iocp_op;

/* Ready queue for buffering completed operations */
typedef struct ready_queue {
	ior_iocp_op **ops; // Dynamic array
	uint32_t head;
	uint32_t tail;
	uint32_t count;
	uint32_t size; // Allocated size
} ready_queue;

/* Timer manager - single thread managing all timers */
typedef struct timer_mgr {
	CRITICAL_SECTION lock;
	CONDITION_VARIABLE cv;
	HANDLE thread;
	_Atomic uint32_t stop;

	// Min-heap of ior_iocp_op* ordered by timer_deadline_ns
	ior_iocp_op **heap;
	uint32_t heap_len;
	uint32_t heap_cap;
} timer_mgr;

/* IOCP backend context */
typedef struct ior_ctx_iocp {
	HANDLE iocp_handle;

	// Operation pool (pre-allocated)
	ior_iocp_op *op_pool;
	uint32_t pool_size;

	// Free list (protected because timer thread may free ops on PQCS failure/teardown)
	CRITICAL_SECTION pool_lock;
	ior_iocp_op *free_list_head;
	uint32_t free_count;

	_Atomic uint32_t active_count; // ops published to IOCP but not yet dequeued into ready queue

	// Submission queue (software ring)
	ior_iocp_op **sq_array;
	uint32_t sq_head;
	uint32_t sq_tail;
	uint32_t sq_mask;
	uint32_t sq_size;

	// Ready queue for completed operations
	ready_queue ready;

	// Timer manager
	timer_mgr timers;

	// Handle association tracking
	handle_set handles;

	// Scheduling / ordering
	CRITICAL_SECTION sched_lock;
	ior_iocp_op *pending_head;
	ior_iocp_op *pending_tail;

	atomic_uint_fast64_t submit_seq; // total submitted (sequence generator)
	atomic_uint_fast64_t completed_cnt; // total completions dequeued from IOCP (not “seen”)

	uint32_t flags;
	uint32_t features;
} ior_ctx_iocp;

/*
 * Helper Functions
 */

static int win_error_to_errno(DWORD err)
{
	switch (err) {
		case ERROR_SUCCESS:
			return 0;
		case ERROR_FILE_NOT_FOUND:
		case ERROR_PATH_NOT_FOUND:
			return -ENOENT;
		case ERROR_ACCESS_DENIED:
			return -EACCES;
		case ERROR_NOT_ENOUGH_MEMORY:
		case ERROR_OUTOFMEMORY:
			return -ENOMEM;
		case ERROR_TIMEOUT:
			return -ETIME; // io_uring timeout semantics
		case ERROR_IO_PENDING:
			return 0;
		case ERROR_HANDLE_EOF:
			return 0;
		case ERROR_BROKEN_PIPE:
			return -EPIPE;
		case ERROR_OPERATION_ABORTED:
			return -ECANCELED;
		case ERROR_INVALID_HANDLE:
			return -EBADF;
		case ERROR_NOT_SUPPORTED:
			return -ENOTSUP;
		default:
			return -EIO;
	}
}

static uint32_t round_up_pow2(uint32_t n)
{
	if (n == 0) {
		return 1;
	}
	n--;
	n |= n >> 1;
	n |= n >> 2;
	n |= n >> 4;
	n |= n >> 8;
	n |= n >> 16;
	n++;
	return n;
}

/* ================= Ready queue ================= */

static int ready_queue_init(ready_queue *q, uint32_t size)
{
	q->ops = calloc(size, sizeof(ior_iocp_op *));
	if (!q->ops) {
		return -ENOMEM;
	}
	q->head = 0;
	q->tail = 0;
	q->count = 0;
	q->size = size;
	return 0;
}

static void ready_queue_destroy(ready_queue *q)
{
	if (q->ops) {
		free(q->ops);
		q->ops = NULL;
	}
}

static bool ready_queue_empty(ready_queue *q)
{
	return q->count == 0;
}

static bool ready_queue_full(ready_queue *q)
{
	return q->count >= q->size;
}

static int ready_queue_push(ready_queue *q, ior_iocp_op *op)
{
	if (ready_queue_full(q)) {
		return -EBUSY;
	}
	q->ops[q->tail] = op;
	q->tail = (q->tail + 1) % q->size;
	q->count++;
	return 0;
}

static ior_iocp_op *ready_queue_peek(ready_queue *q)
{
	if (ready_queue_empty(q)) {
		return NULL;
	}
	return q->ops[q->head];
}

static ior_iocp_op *ready_queue_pop(ready_queue *q)
{
	if (ready_queue_empty(q)) {
		return NULL;
	}
	ior_iocp_op *op = q->ops[q->head];
	q->head = (q->head + 1) % q->size;
	q->count--;
	return op;
}

/* ================= Handle set ================= */

static void handle_set_init(handle_set *set)
{
	memset(set->buckets, 0, sizeof(set->buckets));
	InitializeCriticalSection(&set->lock);
}

static void handle_set_destroy(handle_set *set)
{
	for (int i = 0; i < HANDLE_SET_SIZE; i++) {
		handle_set_entry *entry = set->buckets[i];
		while (entry) {
			handle_set_entry *next = entry->next;
			free(entry);
			entry = next;
		}
	}
	DeleteCriticalSection(&set->lock);
}

static uint32_t handle_hash(HANDLE h)
{
	uintptr_t val = (uintptr_t) h;
	return (uint32_t) (val % HANDLE_SET_SIZE);
}

static bool handle_set_contains_locked(handle_set *set, HANDLE h)
{
	uint32_t bucket = handle_hash(h);
	handle_set_entry *entry = set->buckets[bucket];
	while (entry) {
		if (entry->handle == h) {
			return true;
		}
		entry = entry->next;
	}
	return false;
}

static bool handle_set_insert_locked(handle_set *set, HANDLE h)
{
	uint32_t bucket = handle_hash(h);
	handle_set_entry *entry = malloc(sizeof(handle_set_entry));
	if (!entry) {
		return false;
	}
	entry->handle = h;
	entry->next = set->buckets[bucket];
	set->buckets[bucket] = entry;
	return true;
}

/* ================= Op pool ================= */

static int init_op_pool(ior_ctx_iocp *ctx, uint32_t size)
{
	ctx->op_pool = calloc(size, sizeof(ior_iocp_op));
	if (!ctx->op_pool) {
		return -ENOMEM;
	}

	ctx->pool_size = size;
	ctx->free_count = size;

	ctx->free_list_head = &ctx->op_pool[0];
	for (uint32_t i = 0; i < size - 1; i++) {
		ctx->op_pool[i].next_free = &ctx->op_pool[i + 1];
	}
	ctx->op_pool[size - 1].next_free = NULL;

	return 0;
}

static ior_iocp_op *alloc_op(ior_ctx_iocp *ctx)
{
	EnterCriticalSection(&ctx->pool_lock);

	if (!ctx->free_list_head) {
		LeaveCriticalSection(&ctx->pool_lock);
		return NULL;
	}

	ior_iocp_op *op = ctx->free_list_head;
	ctx->free_list_head = op->next_free;
	ctx->free_count--;

	LeaveCriticalSection(&ctx->pool_lock);

	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = 0;
	op->sqe_flags = 0;
	op->ioprio = 0;
	op->fd = NULL;
	op->user_data = 0;
	op->buf = NULL;
	op->len = 0;
	op->offset = 0;

	op->timeout_ts = NULL;
	op->timeout_flags = 0;

	op->timer_deadline_ns = 0;
	op->timer_armed = false;
	op->timer_cancelled = false;

	op->seq = 0;
	op->drain_after = 0;
	op->link_next = NULL;
	op->linked_deferred = false;
	op->drain_deferred = false;
	op->next_pending = NULL;

	op->bytes_transferred = 0;
	op->error_code = 0;
	op->is_synthetic = false;

	return op;
}

static void free_op(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	if (!op) {
		return;
	}

	EnterCriticalSection(&ctx->pool_lock);

	op->next_free = ctx->free_list_head;
	ctx->free_list_head = op;
	ctx->free_count++;

	LeaveCriticalSection(&ctx->pool_lock);
}

/* ================= SQ ring ================= */

static int init_sq_ring(ior_ctx_iocp *ctx, uint32_t size)
{
	size = round_up_pow2(size);

	ctx->sq_array = calloc(size, sizeof(ior_iocp_op *));
	if (!ctx->sq_array) {
		return -ENOMEM;
	}

	ctx->sq_size = size;
	ctx->sq_mask = size - 1;
	ctx->sq_head = 0;
	ctx->sq_tail = 0;

	return 0;
}

static int sq_enqueue(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	uint32_t next_tail = (ctx->sq_tail + 1) & ctx->sq_mask;
	if (next_tail == ctx->sq_head) {
		return -EBUSY;
	}

	ctx->sq_array[ctx->sq_tail] = op;
	ctx->sq_tail = next_tail;
	return 0;
}

/* ================= Scheduling helpers (LINK/DRAIN) ================= */

static void pending_enqueue_locked(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	// ctx->sched_lock must be held
	op->next_pending = NULL;

	if (!ctx->pending_tail) {
		ctx->pending_head = ctx->pending_tail = op;
	} else {
		ctx->pending_tail->next_pending = op;
		ctx->pending_tail = op;
	}
}

static void pending_remove_locked(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	// ctx->sched_lock must be held
	ior_iocp_op *prev = NULL;
	ior_iocp_op *cur = ctx->pending_head;

	while (cur) {
		if (cur == op) {
			if (prev) {
				prev->next_pending = cur->next_pending;
			} else {
				ctx->pending_head = cur->next_pending;
			}
			if (ctx->pending_tail == cur) {
				ctx->pending_tail = prev;
			}
			cur->next_pending = NULL;
			return;
		}
		prev = cur;
		cur = cur->next_pending;
	}
}

static bool drain_satisfied(ior_ctx_iocp *ctx, const ior_iocp_op *op)
{
	uint64_t done = atomic_load(&ctx->completed_cnt);
	return done >= op->drain_after;
}

/* ================= IO issue / completion plumbing ================= */

static int post_synthetic_completion(
		ior_ctx_iocp *ctx, ior_iocp_op *op, DWORD error_code, DWORD bytes_transferred)
{
	op->error_code = error_code;
	op->bytes_transferred = bytes_transferred;
	op->is_synthetic = true;

	MemoryBarrier();

	BOOL result
			= PostQueuedCompletionStatus(ctx->iocp_handle, bytes_transferred, 0, &op->overlapped);

	if (!result) {
		free_op(ctx, op);
		return -EIO;
	}

	atomic_fetch_add(&ctx->active_count, 1);
	return 0;
}

static int ensure_handle_associated(ior_ctx_iocp *ctx, HANDLE h)
{
	if (h == NULL || h == INVALID_HANDLE_VALUE) {
		return -EBADF;
	}

	EnterCriticalSection(&ctx->handles.lock);

	if (handle_set_contains_locked(&ctx->handles, h)) {
		LeaveCriticalSection(&ctx->handles.lock);
		return 0;
	}

	HANDLE result = CreateIoCompletionPort(h, ctx->iocp_handle, (ULONG_PTR) h, 0);
	if (result == NULL) {
		DWORD err = GetLastError();
		LeaveCriticalSection(&ctx->handles.lock);
		return win_error_to_errno(err);
	}

	(void) handle_set_insert_locked(&ctx->handles, h);
	LeaveCriticalSection(&ctx->handles.lock);

	return 0;
}

static int issue_read(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	HANDLE h = op->fd;

	int ret = ensure_handle_associated(ctx, h);
	if (ret < 0) {
		return post_synthetic_completion(ctx, op, ERROR_INVALID_HANDLE, 0);
	}

	op->overlapped.Offset = (DWORD) (op->offset & 0xFFFFFFFF);
	op->overlapped.OffsetHigh = (DWORD) (op->offset >> 32);

	BOOL result = ReadFile(h, op->buf, op->len, NULL, &op->overlapped);
	if (!result) {
		DWORD err = GetLastError();
		if (err != ERROR_IO_PENDING) {
			return post_synthetic_completion(ctx, op, err, 0);
		}
	}

	atomic_fetch_add(&ctx->active_count, 1);
	return 0;
}

static int issue_write(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	HANDLE h = op->fd;

	int ret = ensure_handle_associated(ctx, h);
	if (ret < 0) {
		return post_synthetic_completion(ctx, op, ERROR_INVALID_HANDLE, 0);
	}

	op->overlapped.Offset = (DWORD) (op->offset & 0xFFFFFFFF);
	op->overlapped.OffsetHigh = (DWORD) (op->offset >> 32);

	BOOL result = WriteFile(h, op->buf, op->len, NULL, &op->overlapped);
	if (!result) {
		DWORD err = GetLastError();
		if (err != ERROR_IO_PENDING) {
			return post_synthetic_completion(ctx, op, err, 0);
		}
	}

	atomic_fetch_add(&ctx->active_count, 1);
	return 0;
}

static void op_to_cqe(ior_iocp_op *op)
{
	op->cqe.iocp.user_data = op->user_data;
	op->cqe.iocp.flags = 0;

	if (op->error_code == ERROR_SUCCESS) {
		op->cqe.iocp.res = (int32_t) op->bytes_transferred;
	} else {
		op->cqe.iocp.res = win_error_to_errno(op->error_code);
	}
}

static ior_iocp_op *cqe_to_op(ior_cqe *cqe)
{
	size_t offset = offsetof(ior_iocp_op, cqe);
	return (ior_iocp_op *) ((char *) cqe - offset);
}

/* ================= Timer support ================= */

static uint64_t qpc_now_ns(void)
{
	static LARGE_INTEGER freq = { 0 };
	if (freq.QuadPart == 0) {
		QueryPerformanceFrequency(&freq);
	}

	LARGE_INTEGER counter;
	QueryPerformanceCounter(&counter);

	uint64_t c = (uint64_t) counter.QuadPart;
	uint64_t f = (uint64_t) freq.QuadPart;

	uint64_t sec = c / f;
	uint64_t rem = c % f;

	return sec * 1000000000ULL + (rem * 1000000000ULL) / f;
}

static uint64_t qpc_deadline_from_timespec(const ior_timespec *ts)
{
	uint64_t now = qpc_now_ns();
	uint64_t delta_ns = (uint64_t) ts->tv_sec * 1000000000ULL + (uint64_t) ts->tv_nsec;
	return now + delta_ns;
}

/* Timer heap */
static void timer_heap_swap(timer_mgr *tm, uint32_t i, uint32_t j)
{
	ior_iocp_op *tmp = tm->heap[i];
	tm->heap[i] = tm->heap[j];
	tm->heap[j] = tmp;
}

static void timer_heap_sift_up(timer_mgr *tm, uint32_t idx)
{
	while (idx > 0) {
		uint32_t parent = (idx - 1) / 2;
		if (tm->heap[idx]->timer_deadline_ns >= tm->heap[parent]->timer_deadline_ns) {
			break;
		}
		timer_heap_swap(tm, idx, parent);
		idx = parent;
	}
}

static void timer_heap_sift_down(timer_mgr *tm, uint32_t idx)
{
	uint32_t len = tm->heap_len;
	while (1) {
		uint32_t left = 2 * idx + 1;
		uint32_t right = 2 * idx + 2;
		uint32_t smallest = idx;

		if (left < len
				&& tm->heap[left]->timer_deadline_ns < tm->heap[smallest]->timer_deadline_ns) {
			smallest = left;
		}
		if (right < len
				&& tm->heap[right]->timer_deadline_ns < tm->heap[smallest]->timer_deadline_ns) {
			smallest = right;
		}

		if (smallest == idx) {
			break;
		}

		timer_heap_swap(tm, idx, smallest);
		idx = smallest;
	}
}

static int timer_heap_push(timer_mgr *tm, ior_iocp_op *op)
{
	if (tm->heap_len >= tm->heap_cap) {
		uint32_t new_cap = tm->heap_cap ? tm->heap_cap * 2 : 16;
		if (new_cap < 16) {
			new_cap = 16;
		}
		ior_iocp_op **new_heap = realloc(tm->heap, new_cap * sizeof(ior_iocp_op *));
		if (!new_heap) {
			return -ENOMEM;
		}
		tm->heap = new_heap;
		tm->heap_cap = new_cap;
	}

	tm->heap[tm->heap_len] = op;
	timer_heap_sift_up(tm, tm->heap_len);
	tm->heap_len++;
	return 0;
}

static ior_iocp_op *timer_heap_pop(timer_mgr *tm)
{
	if (tm->heap_len == 0) {
		return NULL;
	}

	ior_iocp_op *op = tm->heap[0];

	tm->heap_len--;
	if (tm->heap_len > 0) {
		tm->heap[0] = tm->heap[tm->heap_len];
		timer_heap_sift_down(tm, 0);
	}

	return op;
}

static ior_iocp_op *timer_heap_peek(timer_mgr *tm)
{
	if (tm->heap_len == 0) {
		return NULL;
	}
	return tm->heap[0];
}

static DWORD WINAPI timer_thread_main(LPVOID arg)
{
	ior_ctx_iocp *ctx = (ior_ctx_iocp *) arg;
	timer_mgr *tm = &ctx->timers;

	EnterCriticalSection(&tm->lock);

	while (!atomic_load(&tm->stop)) {
		while (tm->heap_len == 0 && !atomic_load(&tm->stop)) {
			SleepConditionVariableCS(&tm->cv, &tm->lock, INFINITE);
		}

		if (atomic_load(&tm->stop)) {
			break;
		}

		ior_iocp_op *op = timer_heap_peek(tm);
		if (!op) {
			continue;
		}

		uint64_t now = qpc_now_ns();
		if (op->timer_deadline_ns > now) {
			uint64_t delta_ns = op->timer_deadline_ns - now;
			DWORD wait_ms = (DWORD) (delta_ns / 1000000ULL);
			if (wait_ms == 0) {
				wait_ms = 1;
			}
			SleepConditionVariableCS(&tm->cv, &tm->lock, wait_ms);
			continue;
		}

		op = timer_heap_pop(tm);
		op->timer_armed = false;

		op->is_synthetic = true;
		op->error_code = ERROR_TIMEOUT;
		op->bytes_transferred = 0;

		MemoryBarrier();

		LeaveCriticalSection(&tm->lock);
		BOOL ok = PostQueuedCompletionStatus(ctx->iocp_handle, 0, 0, &op->overlapped);
		EnterCriticalSection(&tm->lock);

		if (!ok) {
			// timer arming already accounted for active_count; undo it if we can't publish
			atomic_fetch_sub(&ctx->active_count, 1);
			free_op(ctx, op);
		}
	}

	LeaveCriticalSection(&tm->lock);
	return 0;
}

static int arm_timer(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	if (!op->timeout_ts) {
		return post_synthetic_completion(ctx, op, ERROR_INVALID_PARAMETER, 0);
	}

	if (op->timeout_ts->tv_sec < 0 || op->timeout_ts->tv_nsec < 0
			|| op->timeout_ts->tv_nsec >= 1000000000L) {
		return post_synthetic_completion(ctx, op, ERROR_INVALID_PARAMETER, 0);
	}

	uint64_t deadline = qpc_deadline_from_timespec(op->timeout_ts);

	timer_mgr *tm = &ctx->timers;

	EnterCriticalSection(&tm->lock);

	op->timer_deadline_ns = deadline;
	op->timer_armed = true;
	op->timer_cancelled = false;

	int ret = timer_heap_push(tm, op);
	if (ret == 0) {
		atomic_fetch_add(&ctx->active_count, 1);
		WakeConditionVariable(&tm->cv);
	}

	LeaveCriticalSection(&tm->lock);

	if (ret < 0) {
		return post_synthetic_completion(ctx, op, ERROR_NOT_ENOUGH_MEMORY, 0);
	}

	return 0;
}

/* ================= LINK/DRAIN core ================= */

static int issue_op(ior_ctx_iocp *ctx, ior_iocp_op *op); // forward

static void cancel_link_chain(ior_ctx_iocp *ctx, ior_iocp_op *first)
{
	// Cancel all remaining linked ops (that were not yet issued) with -ECANCELED.
	ior_iocp_op *cur = first;

	while (cur) {
		ior_iocp_op *next = cur->link_next;
		cur->link_next = NULL;

		// If it might be sitting in the pending drain list, remove it.
		EnterCriticalSection(&ctx->sched_lock);
		if (cur->drain_deferred) {
			pending_remove_locked(ctx, cur);
			cur->drain_deferred = false;
		}
		LeaveCriticalSection(&ctx->sched_lock);

		// It's still not issued (linked_deferred and/or drain_deferred heads). Complete it now.
		// Use ERROR_OPERATION_ABORTED => -ECANCELED via win_error_to_errno().
		(void) post_synthetic_completion(ctx, cur, ERROR_OPERATION_ABORTED, 0);

		cur = next;
	}
}

static void sched_kick_drain(ior_ctx_iocp *ctx)
{
	// Try to issue any drain-deferred ops whose barrier is now satisfied.
	// Runs with ctx->sched_lock held by caller OR takes it internally.
	EnterCriticalSection(&ctx->sched_lock);

	ior_iocp_op *prev = NULL;
	ior_iocp_op *cur = ctx->pending_head;

	while (cur) {
		ior_iocp_op *next = cur->next_pending;

		// Only consider “heads” (not waiting on LINK predecessor).
		if (!cur->linked_deferred && cur->drain_deferred && drain_satisfied(ctx, cur)) {
			// Remove from pending list
			if (prev) {
				prev->next_pending = next;
			} else {
				ctx->pending_head = next;
			}
			if (ctx->pending_tail == cur) {
				ctx->pending_tail = prev;
			}
			cur->next_pending = NULL;
			cur->drain_deferred = false;

			LeaveCriticalSection(&ctx->sched_lock);

			// Issue outside lock
			int ret = issue_op(ctx, cur);
			if (ret < 0) {
				// If issuing failed in a LINK chain, cancel remaining
				if (cur->link_next) {
					cancel_link_chain(ctx, cur->link_next);
					cur->link_next = NULL;
				}
			}

			EnterCriticalSection(&ctx->sched_lock);

			// Restart scan since we dropped the lock and issued work.
			prev = NULL;
			cur = ctx->pending_head;
			continue;
		}

		prev = cur;
		cur = next;
	}

	LeaveCriticalSection(&ctx->sched_lock);
}

static int start_link_next(ior_ctx_iocp *ctx, ior_iocp_op *next)
{
	if (!next) {
		return 0;
	}

	// This op is no longer waiting on predecessor; it becomes the head.
	next->linked_deferred = false;

	// If it also has DRAIN, it must wait until its barrier is satisfied.
	if ((next->sqe_flags & IOR_SQE_IO_DRAIN) && !drain_satisfied(ctx, next)) {
		EnterCriticalSection(&ctx->sched_lock);
		next->drain_deferred = true;
		pending_enqueue_locked(ctx, next);
		LeaveCriticalSection(&ctx->sched_lock);
		return 0;
	}

	int ret = issue_op(ctx, next);
	if (ret < 0) {
		// Issue failed immediately, cancel remainder of chain
		if (next->link_next) {
			cancel_link_chain(ctx, next->link_next);
			next->link_next = NULL;
		}
	}
	return 0;
}

static int issue_op(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	switch (op->opcode) {
		case IOR_OP_NOP:
			return post_synthetic_completion(ctx, op, ERROR_SUCCESS, 0);

		case IOR_OP_READ:
			return issue_read(ctx, op);

		case IOR_OP_WRITE:
			return issue_write(ctx, op);

		case IOR_OP_SPLICE:
			return post_synthetic_completion(ctx, op, ERROR_NOT_SUPPORTED, 0);

		case IOR_OP_TIMER:
			return arm_timer(ctx, op);

		default:
			return post_synthetic_completion(ctx, op, ERROR_NOT_SUPPORTED, 0);
	}
}

/* ================= Backend ops ================= */

static int ior_iocp_backend_init(void **backend_ctx, ior_params *params)
{
	if (!backend_ctx || !params) {
		return -EINVAL;
	}

	ior_ctx_iocp *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return -ENOMEM;
	}

	ctx->flags = params->flags;

	uint32_t sq_entries = params->sq_entries;
	if (sq_entries < 32) {
		sq_entries = 32;
	}
	sq_entries = round_up_pow2(sq_entries);

	uint32_t cq_entries = params->cq_entries;
	if (cq_entries == 0) {
		cq_entries = sq_entries * 2;
	}
	cq_entries = round_up_pow2(cq_entries);

	ctx->iocp_handle = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (ctx->iocp_handle == NULL) {
		free(ctx);
		return win_error_to_errno(GetLastError());
	}

	int ret = ready_queue_init(&ctx->ready, cq_entries);
	if (ret < 0) {
		CloseHandle(ctx->iocp_handle);
		free(ctx);
		return ret;
	}

	handle_set_init(&ctx->handles);

	InitializeCriticalSection(&ctx->pool_lock);
	InitializeCriticalSection(&ctx->sched_lock);
	ctx->pending_head = NULL;
	ctx->pending_tail = NULL;

	atomic_store(&ctx->submit_seq, 0);
	atomic_store(&ctx->completed_cnt, 0);

	ret = init_op_pool(ctx, sq_entries);
	if (ret < 0) {
		DeleteCriticalSection(&ctx->sched_lock);
		DeleteCriticalSection(&ctx->pool_lock);
		ready_queue_destroy(&ctx->ready);
		handle_set_destroy(&ctx->handles);
		CloseHandle(ctx->iocp_handle);
		free(ctx);
		return ret;
	}

	ret = init_sq_ring(ctx, sq_entries);
	if (ret < 0) {
		free(ctx->op_pool);
		DeleteCriticalSection(&ctx->sched_lock);
		DeleteCriticalSection(&ctx->pool_lock);
		ready_queue_destroy(&ctx->ready);
		handle_set_destroy(&ctx->handles);
		CloseHandle(ctx->iocp_handle);
		free(ctx);
		return ret;
	}

	// Timer manager
	InitializeCriticalSection(&ctx->timers.lock);
	InitializeConditionVariable(&ctx->timers.cv);

	ctx->timers.heap_cap = cq_entries;
	if (ctx->timers.heap_cap > 64) {
		ctx->timers.heap_cap = 64;
	}
	if (ctx->timers.heap_cap < 16) {
		ctx->timers.heap_cap = 16;
	}

	ctx->timers.heap = calloc(ctx->timers.heap_cap, sizeof(ior_iocp_op *));
	if (!ctx->timers.heap) {
		DeleteCriticalSection(&ctx->timers.lock);
		free(ctx->sq_array);
		free(ctx->op_pool);
		DeleteCriticalSection(&ctx->sched_lock);
		DeleteCriticalSection(&ctx->pool_lock);
		ready_queue_destroy(&ctx->ready);
		handle_set_destroy(&ctx->handles);
		CloseHandle(ctx->iocp_handle);
		free(ctx);
		return -ENOMEM;
	}

	ctx->timers.heap_len = 0;
	atomic_store(&ctx->timers.stop, 0);

	ctx->timers.thread = CreateThread(NULL, 0, timer_thread_main, ctx, 0, NULL);
	if (!ctx->timers.thread) {
		free(ctx->timers.heap);
		DeleteCriticalSection(&ctx->timers.lock);
		free(ctx->sq_array);
		free(ctx->op_pool);
		DeleteCriticalSection(&ctx->sched_lock);
		DeleteCriticalSection(&ctx->pool_lock);
		ready_queue_destroy(&ctx->ready);
		handle_set_destroy(&ctx->handles);
		CloseHandle(ctx->iocp_handle);
		free(ctx);
		return -ENOMEM;
	}

	ctx->features = IOR_FEAT_NATIVE_ASYNC;
	params->features = ctx->features;

	*backend_ctx = ctx;
	return 0;
}

static void ior_iocp_backend_destroy(void *backend_ctx)
{
	if (!backend_ctx) {
		return;
	}

	ior_ctx_iocp *ctx = backend_ctx;

	// Stop timer thread
	atomic_store(&ctx->timers.stop, 1);
	EnterCriticalSection(&ctx->timers.lock);
	WakeConditionVariable(&ctx->timers.cv);
	LeaveCriticalSection(&ctx->timers.lock);

	WaitForSingleObject(ctx->timers.thread, INFINITE);
	CloseHandle(ctx->timers.thread);

	// Drain timers without posting
	EnterCriticalSection(&ctx->timers.lock);
	while (ctx->timers.heap_len > 0) {
		ior_iocp_op *op = timer_heap_pop(&ctx->timers);
		if (!op) {
			break;
		}
		op->timer_armed = false;
		atomic_fetch_sub(&ctx->active_count, 1);
		free_op(ctx, op);
	}
	LeaveCriticalSection(&ctx->timers.lock);

	DeleteCriticalSection(&ctx->timers.lock);
	if (ctx->timers.heap) {
		free(ctx->timers.heap);
	}

	// Cancel any pending (deferred) ops without posting completions (teardown)
	EnterCriticalSection(&ctx->sched_lock);
	ior_iocp_op *p = ctx->pending_head;
	ctx->pending_head = ctx->pending_tail = NULL;
	LeaveCriticalSection(&ctx->sched_lock);

	while (p) {
		ior_iocp_op *next = p->next_pending;
		p->next_pending = NULL;
		p->drain_deferred = false;
		p->linked_deferred = false;
		// Not published to IOCP -> safe to free
		free_op(ctx, p);
		p = next;
	}

	// Busy-wait for in-flight completions to be dequeued (same as before)
	while (atomic_load(&ctx->active_count) > 0) {
		Sleep(1);
	}

	ready_queue_destroy(&ctx->ready);
	handle_set_destroy(&ctx->handles);

	if (ctx->sq_array) {
		free(ctx->sq_array);
	}
	if (ctx->op_pool) {
		free(ctx->op_pool);
	}

	DeleteCriticalSection(&ctx->sched_lock);
	DeleteCriticalSection(&ctx->pool_lock);

	if (ctx->iocp_handle) {
		CloseHandle(ctx->iocp_handle);
	}

	free(ctx);
}

static ior_sqe *ior_iocp_backend_get_sqe(void *backend_ctx)
{
	if (!backend_ctx) {
		return NULL;
	}

	ior_ctx_iocp *ctx = backend_ctx;

	ior_iocp_op *op = alloc_op(ctx);
	if (!op) {
		return NULL;
	}

	if (sq_enqueue(ctx, op) < 0) {
		free_op(ctx, op);
		return NULL;
	}

	return (ior_sqe *) op;
}

static int ior_iocp_backend_submit(void *backend_ctx)
{
	if (!backend_ctx) {
		return -EINVAL;
	}

	ior_ctx_iocp *ctx = backend_ctx;

	uint32_t submitted = 0;
	int last_error = 0;

	ior_iocp_op *prev = NULL;

	while (ctx->sq_head != ctx->sq_tail) {
		ior_iocp_op *op = ctx->sq_array[ctx->sq_head];
		ctx->sq_head = (ctx->sq_head + 1) & ctx->sq_mask;

		// Assign submission sequence
		op->seq = atomic_fetch_add(&ctx->submit_seq, 1) + 1;

		// DRAIN barrier means “wait for all prior completions”
		if (op->sqe_flags & IOR_SQE_IO_DRAIN) {
			op->drain_after = op->seq - 1;
		} else {
			op->drain_after = 0;
		}

		// Build LINK chain (prev is the predecessor if it had LINK set)
		if (prev && (prev->sqe_flags & IOR_SQE_IO_LINK)) {
			prev->link_next = op;
			op->linked_deferred = true;
		} else {
			op->linked_deferred = false;
		}

		// Decide whether to issue now
		int ret = 0;

		if (op->linked_deferred) {
			// Not a head: will be issued when predecessor completes successfully.
			ret = 0;
		} else if ((op->sqe_flags & IOR_SQE_IO_DRAIN) && !drain_satisfied(ctx, op)) {
			// Head but drain-deferred
			EnterCriticalSection(&ctx->sched_lock);
			op->drain_deferred = true;
			pending_enqueue_locked(ctx, op);
			LeaveCriticalSection(&ctx->sched_lock);
			ret = 0;
		} else {
			op->drain_deferred = false;
			ret = issue_op(ctx, op);
			if (ret < 0) {
				// If issuing the head failed immediately, cancel remaining chain.
				if (op->link_next) {
					cancel_link_chain(ctx, op->link_next);
					op->link_next = NULL;
				}
			}
		}

		if (ret < 0) {
			last_error = ret;
		} else {
			submitted++;
		}

		prev = op;
	}

	// If we deferred drains, a completion might already satisfy them; cheap kick.
	sched_kick_drain(ctx);

	if (last_error < 0 && submitted == 0) {
		return last_error;
	}

	return (int) submitted;
}

/* Dequeue one completion and push into ready queue */
static int dequeue_one_completion(ior_ctx_iocp *ctx, DWORD timeout_ms)
{
	if (ready_queue_full(&ctx->ready)) {
		IOR_LOG_ERROR("Ready queue full - cannot dequeue");
		return -EBUSY;
	}

	DWORD bytes_transferred = 0;
	ULONG_PTR completion_key = 0;
	LPOVERLAPPED overlapped = NULL;

	BOOL ok = GetQueuedCompletionStatus(
			ctx->iocp_handle, &bytes_transferred, &completion_key, &overlapped, timeout_ms);

	DWORD gle = ok ? ERROR_SUCCESS : GetLastError();

	if (!ok) {
		if (overlapped == NULL) {
			if (gle == WAIT_TIMEOUT || gle == ERROR_TIMEOUT) {
				return (timeout_ms == 0) ? -EAGAIN : -ETIMEDOUT;
			}
			return win_error_to_errno(gle);
		}
		// completion with error: proceed (gle carries error)
	}

	if (overlapped == NULL) {
		return -EAGAIN;
	}

	ior_iocp_op *op = (ior_iocp_op *) overlapped;

	if (!op->is_synthetic) {
		op->error_code = gle;
		op->bytes_transferred = ok ? bytes_transferred : 0;
	}

#ifndef NDEBUG
	uint32_t prev_active = atomic_fetch_sub(&ctx->active_count, 1);
	assert(prev_active > 0 && "active_count underflow detected");
#else
	atomic_fetch_sub(&ctx->active_count, 1);
#endif

	// Mark completion (for DRAIN barriers)
	atomic_fetch_add(&ctx->completed_cnt, 1);

	op_to_cqe(op);

	int ret = ready_queue_push(&ctx->ready, op);
	if (ret < 0) {
		IOR_LOG_ERROR("Ready queue push failed unexpectedly");
		return ret;
	}

	// LINK handling: on successful completion, start next; otherwise cancel the chain.
	ior_iocp_op *next = op->link_next;
	op->link_next = NULL;

	if (next) {
		if (op->cqe.iocp.res >= 0) {
			(void) start_link_next(ctx, next);
		} else {
			cancel_link_chain(ctx, next);
		}
	}

	// DRAIN handling: newly completed ops may unblock drain-deferred heads
	sched_kick_drain(ctx);

	return 0;
}

static int ior_iocp_backend_submit_and_wait(void *backend_ctx, unsigned wait_nr)
{
	if (!backend_ctx) {
		return -EINVAL;
	}

	ior_ctx_iocp *ctx = backend_ctx;

	int submitted = ior_iocp_backend_submit(backend_ctx);
	if (submitted < 0) {
		return submitted;
	}

	if (wait_nr == 0) {
		return submitted;
	}

	if (wait_nr > ctx->ready.size) {
		wait_nr = ctx->ready.size;
	}

	while (ctx->ready.count < wait_nr) {
		int ret = dequeue_one_completion(ctx, INFINITE);
		if (ret < 0) {
			return ret;
		}
	}

	return submitted;
}

static int ior_iocp_backend_peek_cqe(void *backend_ctx, ior_cqe **cqe_out)
{
	if (!backend_ctx || !cqe_out) {
		return -EINVAL;
	}

	ior_ctx_iocp *ctx = backend_ctx;

	if (!ready_queue_empty(&ctx->ready)) {
		ior_iocp_op *op = ready_queue_peek(&ctx->ready);
		*cqe_out = &op->cqe;
		return 0;
	}

	int ret = dequeue_one_completion(ctx, 0);
	if (ret < 0) {
		return ret;
	}

	ior_iocp_op *op = ready_queue_peek(&ctx->ready);
	*cqe_out = &op->cqe;
	return 0;
}

static int ior_iocp_backend_wait_cqe(void *backend_ctx, ior_cqe **cqe_out)
{
	if (!backend_ctx || !cqe_out) {
		return -EINVAL;
	}

	ior_ctx_iocp *ctx = backend_ctx;

	if (!ready_queue_empty(&ctx->ready)) {
		ior_iocp_op *op = ready_queue_peek(&ctx->ready);
		*cqe_out = &op->cqe;
		return 0;
	}

	int ret = dequeue_one_completion(ctx, INFINITE);
	if (ret < 0) {
		return ret;
	}

	ior_iocp_op *op = ready_queue_peek(&ctx->ready);
	*cqe_out = &op->cqe;
	return 0;
}

static int ior_iocp_backend_wait_cqe_timeout(
		void *backend_ctx, ior_cqe **cqe_out, ior_timespec *timeout)
{
	if (!backend_ctx || !cqe_out) {
		return -EINVAL;
	}

	ior_ctx_iocp *ctx = backend_ctx;

	if (!ready_queue_empty(&ctx->ready)) {
		ior_iocp_op *op = ready_queue_peek(&ctx->ready);
		*cqe_out = &op->cqe;
		return 0;
	}

	DWORD timeout_ms = INFINITE;
	if (timeout) {
		if (timeout->tv_sec < 0 || timeout->tv_nsec < 0 || timeout->tv_nsec >= 1000000000L) {
			return -EINVAL;
		}
		timeout_ms = (DWORD) (timeout->tv_sec * 1000 + timeout->tv_nsec / 1000000);
		if (timeout_ms == 0 && (timeout->tv_sec > 0 || timeout->tv_nsec > 0)) {
			timeout_ms = 1;
		}
	}

	int ret = dequeue_one_completion(ctx, timeout_ms);
	if (ret < 0) {
		return ret;
	}

	ior_iocp_op *op = ready_queue_peek(&ctx->ready);
	*cqe_out = &op->cqe;
	return 0;
}

static void ior_iocp_backend_cqe_seen(void *backend_ctx, ior_cqe *cqe)
{
	if (!backend_ctx || !cqe) {
		return;
	}

	ior_ctx_iocp *ctx = backend_ctx;
	ior_iocp_op *op = cqe_to_op(cqe);

	ior_iocp_op *head_op = ready_queue_peek(&ctx->ready);

	if (head_op != op) {
		IOR_LOG_ERROR("cqe_seen called out of order - expected %p, got %p", (void *) head_op,
				(void *) op);
#ifndef NDEBUG
		abort();
#endif
		return;
	}

	ready_queue_pop(&ctx->ready);
	free_op(ctx, op);
}

static unsigned ior_iocp_backend_peek_batch_cqe(void *backend_ctx, ior_cqe **cqes, unsigned max)
{
	if (!backend_ctx || !cqes || max == 0) {
		return 0;
	}

	ior_ctx_iocp *ctx = backend_ctx;

	if (max > ctx->pool_size) {
		max = ctx->pool_size;
	}
	if (max > ctx->ready.size) {
		max = ctx->ready.size;
	}

	unsigned count = 0;

	while (count < max && !ready_queue_empty(&ctx->ready)) {
		ior_iocp_op *op = ctx->ready.ops[(ctx->ready.head + count) % ctx->ready.size];
		cqes[count] = &op->cqe;
		count++;
	}

	unsigned need = max - count;
	for (unsigned i = 0; i < need; i++) {
		int ret = dequeue_one_completion(ctx, 0);
		if (ret < 0) {
			break;
		}
		ior_iocp_op *op = ctx->ready.ops[(ctx->ready.head + count) % ctx->ready.size];
		cqes[count] = &op->cqe;
		count++;
	}

	return count;
}

static void ior_iocp_backend_cq_advance(void *backend_ctx, unsigned nr)
{
	if (!backend_ctx || nr == 0) {
		return;
	}

	ior_ctx_iocp *ctx = backend_ctx;

	for (unsigned i = 0; i < nr; i++) {
		ior_iocp_op *op = ready_queue_pop(&ctx->ready);
		if (!op) {
			break;
		}
		free_op(ctx, op);
	}
}

/* ================= SQE preparation helpers ================= */

static void ior_iocp_backend_prep_nop(ior_sqe *sqe)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_NOP;
	op->fd = NULL;
}

static void ior_iocp_backend_prep_read(
		ior_sqe *sqe, ior_fd_t fd, void *buf, unsigned nbytes, uint64_t offset)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_READ;
	op->fd = fd;
	op->buf = buf;
	op->len = nbytes;
	op->offset = offset;
}

static void ior_iocp_backend_prep_write(
		ior_sqe *sqe, ior_fd_t fd, const void *buf, unsigned nbytes, uint64_t offset)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_WRITE;
	op->fd = fd;
	op->buf = (void *) buf;
	op->len = nbytes;
	op->offset = offset;
}

static void ior_iocp_backend_prep_splice(ior_sqe *sqe, ior_fd_t fd_in, uint64_t off_in,
		ior_fd_t fd_out, uint64_t off_out, unsigned nbytes, unsigned flags)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_SPLICE;
	op->fd = NULL;
	(void) fd_in;
	(void) off_in;
	(void) fd_out;
	(void) off_out;
	(void) nbytes;
	(void) flags;
}

static void ior_iocp_backend_prep_timeout(
		ior_sqe *sqe, ior_timespec *ts, unsigned count, unsigned flags)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_TIMER;
	op->fd = NULL;
	op->timeout_ts = ts;
	op->timeout_flags = flags;
	(void) count;
}

static void ior_iocp_backend_sqe_set_data(ior_sqe *sqe, void *data)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	op->user_data = (uint64_t) (uintptr_t) data;
}

static void ior_iocp_backend_sqe_set_flags(ior_sqe *sqe, uint8_t flags)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	op->sqe_flags = flags;
}

/* ================= CQE accessors ================= */

static void *ior_iocp_backend_cqe_get_data(ior_cqe *cqe)
{
	return (void *) (uintptr_t) cqe->iocp.user_data;
}

static int32_t ior_iocp_backend_cqe_get_res(ior_cqe *cqe)
{
	return cqe->iocp.res;
}

static uint32_t ior_iocp_backend_cqe_get_flags(ior_cqe *cqe)
{
	return cqe->iocp.flags;
}

/* ================= Backend info ================= */

static const char *ior_iocp_backend_name(void)
{
	return "iocp";
}

static uint32_t ior_iocp_backend_get_features(void *backend_ctx)
{
	if (!backend_ctx) {
		return 0;
	}
	ior_ctx_iocp *ctx = backend_ctx;
	return ctx->features;
}

/* Export vtable */
const ior_backend_ops ior_iocp_ops = {
	.init = ior_iocp_backend_init,
	.destroy = ior_iocp_backend_destroy,
	.get_sqe = ior_iocp_backend_get_sqe,
	.submit = ior_iocp_backend_submit,
	.submit_and_wait = ior_iocp_backend_submit_and_wait,
	.peek_cqe = ior_iocp_backend_peek_cqe,
	.wait_cqe = ior_iocp_backend_wait_cqe,
	.wait_cqe_timeout = ior_iocp_backend_wait_cqe_timeout,
	.cqe_seen = ior_iocp_backend_cqe_seen,
	.peek_batch_cqe = ior_iocp_backend_peek_batch_cqe,
	.cq_advance = ior_iocp_backend_cq_advance,
	.prep_nop = ior_iocp_backend_prep_nop,
	.prep_read = ior_iocp_backend_prep_read,
	.prep_write = ior_iocp_backend_prep_write,
	.prep_splice = ior_iocp_backend_prep_splice,
	.prep_timeout = ior_iocp_backend_prep_timeout,
	.sqe_set_data = ior_iocp_backend_sqe_set_data,
	.sqe_set_flags = ior_iocp_backend_sqe_set_flags,
	.cqe_get_data = ior_iocp_backend_cqe_get_data,
	.cqe_get_res = ior_iocp_backend_cqe_get_res,
	.cqe_get_flags = ior_iocp_backend_cqe_get_flags,
	.backend_name = ior_iocp_backend_name,
	.get_features = ior_iocp_backend_get_features,
};

#endif /* IOR_HAVE_IOCP */
