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

/* IOCP backend context */
typedef struct ior_ctx_iocp {
	HANDLE iocp_handle;

	// Operation pool (pre-allocated)
	ior_iocp_op *op_pool;
	uint32_t pool_size;

	// Free list
	ior_iocp_op *free_list_head;
	uint32_t free_count;
	_Atomic uint32_t active_count; // Operations in IOCP (not yet in ready queue)

	// Submission queue (software ring)
	ior_iocp_op **sq_array;
	uint32_t sq_head;
	uint32_t sq_tail;
	uint32_t sq_mask;
	uint32_t sq_size;

	// Ready queue for completed operations
	ready_queue ready;

	// Handle association tracking
	handle_set handles;

	uint32_t flags;
	uint32_t features;
} ior_ctx_iocp;

/*
 * Helper Functions
 */

// Convert Windows error to errno
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
			return -ETIMEDOUT;
		case ERROR_IO_PENDING:
			return 0; // Not an error - async in progress
		case ERROR_HANDLE_EOF:
			return 0; // EOF - return 0 bytes
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

// Round up to next power of 2
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

// Ready queue operations
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
		return -EBUSY; // Critical: cannot drop completions
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

// Handle set operations
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

// Check if handle is present (must be called under lock)
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

// Insert handle (must be called under lock, assumes not present)
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

// Initialize op pool and free list
static int init_op_pool(ior_ctx_iocp *ctx, uint32_t size)
{
	ctx->op_pool = calloc(size, sizeof(ior_iocp_op));
	if (!ctx->op_pool) {
		return -ENOMEM;
	}

	ctx->pool_size = size;
	ctx->free_count = size;

	// Build free list
	ctx->free_list_head = &ctx->op_pool[0];
	for (uint32_t i = 0; i < size - 1; i++) {
		ctx->op_pool[i].next_free = &ctx->op_pool[i + 1];
	}
	ctx->op_pool[size - 1].next_free = NULL;

	return 0;
}

// Allocate op from free list
static ior_iocp_op *alloc_op(ior_ctx_iocp *ctx)
{
	if (!ctx->free_list_head) {
		return NULL; // Pool exhausted
	}

	ior_iocp_op *op = ctx->free_list_head;
	ctx->free_list_head = op->next_free;
	ctx->free_count--;

	// Clear only the request fields and OVERLAPPED, preserve next_free
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
	op->bytes_transferred = 0;
	op->error_code = 0;
	op->is_synthetic = false;
	// Do NOT clear next_free or cqe

	return op;
}

// Return op to free list
static void free_op(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	if (!op) {
		return;
	}

	op->next_free = ctx->free_list_head;
	ctx->free_list_head = op;
	ctx->free_count++;
}

// Initialize submission queue
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

// Add op to SQ ring
static int sq_enqueue(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	uint32_t next_tail = (ctx->sq_tail + 1) & ctx->sq_mask;

	if (next_tail == ctx->sq_head) {
		return -EBUSY; // Ring full
	}

	ctx->sq_array[ctx->sq_tail] = op;
	ctx->sq_tail = next_tail;

	return 0;
}

// Post synthetic completion for immediate results
static int post_synthetic_completion(
		ior_ctx_iocp *ctx, ior_iocp_op *op, DWORD error_code, DWORD bytes_transferred)
{
	op->error_code = error_code;
	op->bytes_transferred = bytes_transferred;
	op->is_synthetic = true;

	// Post to IOCP so it will be dequeued normally
	BOOL result
			= PostQueuedCompletionStatus(ctx->iocp_handle, bytes_transferred, 0, &op->overlapped);

	if (!result) {
		// PQCS failed - cannot post completion
		// Return op to pool and don't count as active
		free_op(ctx, op);
		return -EIO;
	}

	// Count as active (will be decremented on dequeue)
	atomic_fetch_add(&ctx->active_count, 1);
	return 0;
}

// Ensure handle is associated with IOCP (lazy association)
// Holds lock across entire operation to prevent TOCTOU races
static int ensure_handle_associated(ior_ctx_iocp *ctx, HANDLE h)
{
	if (h == NULL || h == INVALID_HANDLE_VALUE) {
		return -EBADF;
	}

	EnterCriticalSection(&ctx->handles.lock);

	// Check if already associated
	if (handle_set_contains_locked(&ctx->handles, h)) {
		LeaveCriticalSection(&ctx->handles.lock);
		return 0;
	}

	// Associate handle with IOCP (while holding lock to prevent races)
	HANDLE result = CreateIoCompletionPort(h, ctx->iocp_handle, (ULONG_PTR) h, 0);
	if (result == NULL) {
		DWORD err = GetLastError();
		LeaveCriticalSection(&ctx->handles.lock);
		return win_error_to_errno(err);
	}

	// Association succeeded - insert into set
	bool inserted = handle_set_insert_locked(&ctx->handles, h);
	LeaveCriticalSection(&ctx->handles.lock);

	// Insertion failure is non-fatal (we'll try to associate again next time)
	return 0;
}

// Issue a read operation
static int issue_read(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	HANDLE h = op->fd;

	// Ensure handle is associated with IOCP
	int ret = ensure_handle_associated(ctx, h);
	if (ret < 0) {
		return post_synthetic_completion(ctx, op, ERROR_INVALID_HANDLE, 0);
	}

	// Set offset in OVERLAPPED
	op->overlapped.Offset = (DWORD) (op->offset & 0xFFFFFFFF);
	op->overlapped.OffsetHigh = (DWORD) (op->offset >> 32);

	BOOL result = ReadFile(h, op->buf, op->len, NULL, &op->overlapped);

	if (!result) {
		DWORD err = GetLastError();
		if (err != ERROR_IO_PENDING) {
			// Immediate error - post synthetic completion
			return post_synthetic_completion(ctx, op, err, 0);
		}
	}

	// Either pending or completed synchronously
	// In both cases, completion will arrive via IOCP
	atomic_fetch_add(&ctx->active_count, 1);
	return 0;
}

// Issue a write operation
static int issue_write(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	HANDLE h = op->fd;

	// Ensure handle is associated with IOCP
	int ret = ensure_handle_associated(ctx, h);
	if (ret < 0) {
		return post_synthetic_completion(ctx, op, ERROR_INVALID_HANDLE, 0);
	}

	// Set offset in OVERLAPPED
	op->overlapped.Offset = (DWORD) (op->offset & 0xFFFFFFFF);
	op->overlapped.OffsetHigh = (DWORD) (op->offset >> 32);

	BOOL result = WriteFile(h, op->buf, op->len, NULL, &op->overlapped);

	if (!result) {
		DWORD err = GetLastError();
		if (err != ERROR_IO_PENDING) {
			// Immediate error - post synthetic completion
			return post_synthetic_completion(ctx, op, err, 0);
		}
	}

	// Either pending or completed synchronously
	atomic_fetch_add(&ctx->active_count, 1);
	return 0;
}

// Fill CQE from completed operation
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

// Extract op from CQE pointer (reverse of &op->cqe)
static ior_iocp_op *cqe_to_op(ior_cqe *cqe)
{
	size_t offset = offsetof(ior_iocp_op, cqe);
	return (ior_iocp_op *) ((char *) cqe - offset);
}

/*
 * Backend Operations
 */

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

	// Determine sizes
	uint32_t sq_entries = params->sq_entries;
	if (sq_entries < 32) {
		sq_entries = 32;
	}
	sq_entries = round_up_pow2(sq_entries);

	// CQ size (for ready queue)
	uint32_t cq_entries = params->cq_entries;
	if (cq_entries == 0) {
		cq_entries = sq_entries * 2;
	}
	cq_entries = round_up_pow2(cq_entries);

	// Create IOCP handle (0 = let system decide thread count)
	ctx->iocp_handle = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (ctx->iocp_handle == NULL) {
		free(ctx);
		return win_error_to_errno(GetLastError());
	}

	// Initialize ready queue (dynamically sized)
	int ret = ready_queue_init(&ctx->ready, cq_entries);
	if (ret < 0) {
		CloseHandle(ctx->iocp_handle);
		free(ctx);
		return ret;
	}

	// Initialize handle tracking
	handle_set_init(&ctx->handles);

	// Initialize operation pool
	ret = init_op_pool(ctx, sq_entries);
	if (ret < 0) {
		ready_queue_destroy(&ctx->ready);
		handle_set_destroy(&ctx->handles);
		CloseHandle(ctx->iocp_handle);
		free(ctx);
		return ret;
	}

	// Initialize submission queue
	ret = init_sq_ring(ctx, sq_entries);
	if (ret < 0) {
		free(ctx->op_pool);
		ready_queue_destroy(&ctx->ready);
		handle_set_destroy(&ctx->handles);
		CloseHandle(ctx->iocp_handle);
		free(ctx);
		return ret;
	}

	// Set features (no splice on Windows)
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

	// TODO: Better cleanup - cancel pending operations with CancelIoEx
	// For now, busy-wait (not ideal but simple)
	while (atomic_load(&ctx->active_count) > 0) {
		Sleep(1);
	}

	// Note: User must call cqe_seen/cq_advance before destroy
	// Any ops still in ready queue will leak (same as other backends)

	ready_queue_destroy(&ctx->ready);
	handle_set_destroy(&ctx->handles);

	if (ctx->sq_array) {
		free(ctx->sq_array);
	}

	if (ctx->op_pool) {
		free(ctx->op_pool);
	}

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

	// Allocate op from pool
	ior_iocp_op *op = alloc_op(ctx);
	if (!op) {
		return NULL;
	}

	// Add to SQ ring
	if (sq_enqueue(ctx, op) < 0) {
		free_op(ctx, op);
		return NULL;
	}

	// Return as ior_sqe (user will fill in via prep_* functions)
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

	// Process all pending SQ entries
	while (ctx->sq_head != ctx->sq_tail) {
		ior_iocp_op *op = ctx->sq_array[ctx->sq_head];
		ctx->sq_head = (ctx->sq_head + 1) & ctx->sq_mask;

		int ret = 0;

		switch (op->opcode) {
			case IOR_OP_NOP:
				ret = post_synthetic_completion(ctx, op, ERROR_SUCCESS, 0);
				break;

			case IOR_OP_READ:
				ret = issue_read(ctx, op);
				break;

			case IOR_OP_WRITE:
				ret = issue_write(ctx, op);
				break;

			case IOR_OP_SPLICE:
				ret = post_synthetic_completion(ctx, op, ERROR_NOT_SUPPORTED, 0);
				break;

			case IOR_OP_TIMER:
				ret = post_synthetic_completion(ctx, op, ERROR_NOT_SUPPORTED, 0);
				break;

			default:
				ret = post_synthetic_completion(ctx, op, ERROR_NOT_SUPPORTED, 0);
				break;
		}

		if (ret < 0) {
			// Post failed - record error but continue with other ops
			last_error = ret;
		} else {
			submitted++;
		}
	}

	// If any post failed, return error (or could return submitted count)
	if (last_error < 0 && submitted == 0) {
		return last_error;
	}

	return (int) submitted;
}

// Helper to dequeue one completion from IOCP into ready queue
static int dequeue_one_completion(ior_ctx_iocp *ctx, DWORD timeout_ms)
{
	// CRITICAL: Never dequeue if ready queue is full
	if (ready_queue_full(&ctx->ready)) {
		IOR_LOG_ERROR("Ready queue full - cannot dequeue");
		return -EBUSY;
	}

	DWORD bytes_transferred;
	ULONG_PTR completion_key;
	LPOVERLAPPED overlapped;

	BOOL ok = GetQueuedCompletionStatus(
			ctx->iocp_handle, &bytes_transferred, &completion_key, &overlapped, timeout_ms);

	// Capture error immediately if failed
	DWORD gle = ok ? ERROR_SUCCESS : GetLastError();

	if (!ok) {
		if (overlapped == NULL) {
			// Timeout or error with no completion
			// WAIT_TIMEOUT and ERROR_TIMEOUT are the same constant (258)
			if (gle == WAIT_TIMEOUT || gle == ERROR_TIMEOUT) {
				return (timeout_ms == 0) ? -EAGAIN : -ETIMEDOUT;
			}
			return win_error_to_errno(gle);
		}
		// Operation completed with error - process it (gle has the error)
	}

	if (overlapped == NULL) {
		// Should not happen if ok == TRUE
		return -EAGAIN;
	}

	// Extract our operation structure
	ior_iocp_op *op = (ior_iocp_op *) overlapped;

	// Set completion status directly from IOCP dequeue result
	// This is the authoritative source for completion status
	if (op->is_synthetic) {
		// Synthetic completions already have error_code/bytes set
		// Just use what was set by post_synthetic_completion
	} else {
		// Real I/O completion - use the IOCP dequeue status
		op->error_code = gle;
		op->bytes_transferred = ok ? bytes_transferred : 0;
	}

	// Decrement active count
	// Debug check: ensure we don't underflow (would indicate a counting bug)
#ifndef NDEBUG
	uint32_t prev = atomic_fetch_sub(&ctx->active_count, 1);
	assert(prev > 0 && "active_count underflow detected");
#else
	atomic_fetch_sub(&ctx->active_count, 1);
#endif

	// Fill embedded CQE
	op_to_cqe(op);

	// Add to ready queue (we already checked it's not full)
	int ret = ready_queue_push(&ctx->ready, op);
	if (ret < 0) {
		// This should never happen since we checked above
		IOR_LOG_ERROR("Ready queue push failed unexpectedly");
		return ret;
	}

	return 0;
}

static int ior_iocp_backend_submit_and_wait(void *backend_ctx, unsigned wait_nr)
{
	if (!backend_ctx) {
		return -EINVAL;
	}

	ior_ctx_iocp *ctx = backend_ctx;

	// Submit pending operations
	int submitted = ior_iocp_backend_submit(backend_ctx);
	if (submitted < 0) {
		return submitted;
	}

	if (wait_nr == 0) {
		return submitted;
	}

	// Clamp wait_nr to ready queue capacity to prevent deadlock
	if (wait_nr > ctx->ready.size) {
		wait_nr = ctx->ready.size;
	}

	// Ensure at least wait_nr completions are in ready queue
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

	// Check ready queue first
	if (!ready_queue_empty(&ctx->ready)) {
		ior_iocp_op *op = ready_queue_peek(&ctx->ready);
		*cqe_out = &op->cqe;
		return 0;
	}

	// Try to dequeue one from IOCP (non-blocking)
	int ret = dequeue_one_completion(ctx, 0);
	if (ret < 0) {
		return ret;
	}

	// Now ready queue should have it
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

	// Check ready queue first
	if (!ready_queue_empty(&ctx->ready)) {
		ior_iocp_op *op = ready_queue_peek(&ctx->ready);
		*cqe_out = &op->cqe;
		return 0;
	}

	// Wait indefinitely for one completion
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

	// Check ready queue first
	if (!ready_queue_empty(&ctx->ready)) {
		ior_iocp_op *op = ready_queue_peek(&ctx->ready);
		*cqe_out = &op->cqe;
		return 0;
	}

	// Convert timespec to milliseconds
	DWORD timeout_ms = INFINITE;
	if (timeout) {
		if (timeout->tv_sec < 0 || timeout->tv_nsec < 0 || timeout->tv_nsec >= 1000000000L) {
			return -EINVAL;
		}
		timeout_ms = (DWORD) (timeout->tv_sec * 1000 + timeout->tv_nsec / 1000000);
		if (timeout_ms == 0 && (timeout->tv_sec > 0 || timeout->tv_nsec > 0)) {
			timeout_ms = 1; // At least 1ms
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

	// Extract op from CQE
	ior_iocp_op *op = cqe_to_op(cqe);

	// STRICT: Only consume from head (matches thread backend CQ ring semantics)
	// Check head first before popping (non-destructive on misuse)
	ior_iocp_op *head_op = ready_queue_peek(&ctx->ready);

	if (head_op != op) {
		// ERROR: cqe_seen called out of order
		// This violates the consumption contract
		IOR_LOG_ERROR("cqe_seen called out of order - expected %p, got %p", (void *) head_op,
				(void *) op);
#ifdef NDEBUG
		abort(); // Fail fast in debug builds
#endif
		return; // Don't corrupt queue in release builds
	}

	// Now safe to pop since we verified it's the head
	ready_queue_pop(&ctx->ready);

	// Return to free pool
	free_op(ctx, op);
}

static unsigned ior_iocp_backend_peek_batch_cqe(void *backend_ctx, ior_cqe **cqes, unsigned max)
{
	if (!backend_ctx || !cqes || max == 0) {
		return 0;
	}

	ior_ctx_iocp *ctx = backend_ctx;

	// Cap max to safe bounds
	if (max > ctx->pool_size) {
		max = ctx->pool_size;
	}
	if (max > ctx->ready.size) {
		max = ctx->ready.size;
	}

	unsigned count = 0;

	// First, return what's already in ready queue
	while (count < max && !ready_queue_empty(&ctx->ready)) {
		ior_iocp_op *op = ctx->ready.ops[(ctx->ready.head + count) % ctx->ready.size];
		cqes[count] = &op->cqe;
		count++;
	}

	// Try to fetch more from IOCP to fill up to max
	unsigned need = max - count;
	if (need == 0) {
		return count; // Already filled
	}

	// Use single-dequeue loop for correctness
	// GetQueuedCompletionStatusEx doesn't provide per-entry error status reliably
	// Loop dequeue_one_completion with timeout=0 (non-blocking) to get accurate errors
	for (unsigned i = 0; i < need; i++) {
		int ret = dequeue_one_completion(ctx, 0);
		if (ret < 0) {
			// No more available (or error) - return what we have
			break;
		}

		// Completion was added to ready queue
		// Add pointer to output array
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

	// Advance ready queue and return ops to pool
	// This is the batch consumption path (used with peek_batch_cqe)
	for (unsigned i = 0; i < nr; i++) {
		ior_iocp_op *op = ready_queue_pop(&ctx->ready);
		if (!op) {
			break; // No more in queue
		}
		free_op(ctx, op);
	}
}

/* SQE preparation helpers */

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

/* CQE accessors */

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

/* Backend info */

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
