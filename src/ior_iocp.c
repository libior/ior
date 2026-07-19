/* SPDX-License-Identifier: BSD-3-Clause */
#include "config.h"

#ifdef IOR_HAVE_IOCP

/*
 * winsock2.h must be included before windows.h (which ior_backend.h pulls in
 * via ior.h) so that the modern Winsock 2 declarations (WSASend/WSARecv/WSABUF/
 * SOCKET) win over the legacy winsock.h ones. WIN32_LEAN_AND_MEAN keeps
 * windows.h from implicitly including winsock.h; winsock2.h itself includes
 * windows.h in the correct order.
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>

#include "ior_backend.h"
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <windows.h>
#include <assert.h>
#include <stdatomic.h>
#include <stdbool.h>

// ETIME is used for timer expiration (matches io_uring semantics)
#ifndef ETIME
#define ETIME 62 // Match Linux value
#endif

// IOR_TIMEOUT_ABS comes from ior.h. qpc_deadline_from_timespec() honors it, so
// the plain timer and the link timeout both interpret an absolute deadline
// against the QPC monotonic clock.

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

struct ior_ctx_iocp;

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

	// Socket I/O (WSASend/WSARecv) bookkeeping. The WSABUF and flags must stay
	// valid for the whole lifetime of the overlapped operation, so they live in
	// the op rather than on the issuing thread's stack. For WSARecv sock_flags
	// is an in/out parameter.
	WSABUF wsabuf;
	DWORD sock_flags;

	// IOR_OP_POLL: requested IOR_POLL_* mask; the ready mask is delivered in
	// work_res (posted like a work-op result).
	uint32_t poll_mask;

	// Timeout-specific fields
	ior_timespec *timeout_ts;
	uint32_t timeout_flags;

	// Timer bookkeeping (for IOR_OP_TIMER)
	uint64_t timer_deadline_ns; // Absolute deadline in monotonic time
	bool timer_armed; // True once enqueued into timer heap
	bool timer_cancelled; // True if timer was cancelled (future use)

	// Linked timeout (IOR_OP_LINK_TIMEOUT) pairing. On the guarded op,
	// link_timeout points to its watchdog timeout op; on the timeout op, guarded
	// points back to the op it guards. Exactly one of the completion path and the
	// timer thread resolves the pair, arbitrated by timer_armed under timers.lock.
	struct ior_iocp_op *link_timeout;
	struct ior_iocp_op *guarded;

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

	// IOR_OP_WORK: user callback executed on the private Win32 threadpool. The
	// callback's return value (work_res) becomes the CQE result; the token lets
	// it observe a fired link timeout or context teardown.
	ior_work_fn work_fn;
	void *work_arg;
	int32_t work_res;
	struct ior_ctx_iocp *work_owner;
	struct ior_work_token token;

	// Free list linkage (preserved across prep_*)
	struct ior_iocp_op *next_free;
} ior_iocp_op;

/* Ready queue for buffering completed operations */
typedef struct ready_queue {
	ior_iocp_op **ops; // Dynamic array
	uint32_t head;
	uint32_t tail;
	uint32_t count;
	uint32_t size; // Allocated size (power of 2)
	uint32_t mask; // size - 1, for bitmask wrapping
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

/*
 * IOR_OP_POLL multiplexer - one dedicated thread blocking in WSAPoll over
 * every pending poll op (sockets only). Registration and teardown wake it
 * through a loopback UDP socket pair (WSAPoll can only wait on sockets); a
 * fired link timeout flags the op's token from the timer thread and wakes it
 * the same way. The thread and the wakeup sockets are created lazily on the
 * first poll op; incoming ops are linked through next_pending.
 */
typedef struct iocp_poller {
	CRITICAL_SECTION lock;
	HANDLE thread; // NULL until the first poll op
	SOCKET wake_tx;
	SOCKET wake_rx;
	_Atomic uint32_t stop;
	ior_iocp_op *incoming; // protected by lock
	// Active ops and their WSAPOLLFD slots ([0] is wake_rx); poller thread only.
	ior_iocp_op **active;
	WSAPOLLFD *pfds;
	uint32_t active_len;
	uint32_t active_cap;
} iocp_poller;

/* QPC frequency, initialized once during backend init.
 *
 * Stored as an atomic so that the publishing thread's write is observed with
 * release semantics and reader threads acquire it. A non-zero value signals
 * "initialized"; QueryPerformanceFrequency never returns 0 on supported
 * platforms (XP+), so 0 is a safe sentinel. This matters on weakly-ordered
 * architectures (e.g. Windows on ARM64) where a plain store could be observed
 * out of order relative to the init flag. */
static _Atomic int64_t g_qpc_freq = 0;
static LONG g_qpc_freq_init = 0; // 0 = not done, 1 = done

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

	// IOR_OP_POLL readiness multiplexer
	iocp_poller poller;

	// Handle association tracking
	handle_set handles;

	// Scheduling / ordering
	CRITICAL_SECTION sched_lock;
	ior_iocp_op *pending_head;
	ior_iocp_op *pending_tail;

	atomic_uint_fast64_t submit_seq; // total submitted (sequence generator)
	atomic_uint_fast64_t completed_cnt; // total completions dequeued from IOCP (not "seen")

	/*
	 * IOR_OP_WORK support: a private Win32 threadpool (created lazily on the
	 * first work op) runs the callbacks; completions are delivered through
	 * PostQueuedCompletionStatus like any synthetic completion. The cleanup
	 * group lets destroy wait for every submitted callback - queued ones
	 * included - honoring the "submitted callbacks always run" contract.
	 */
	_Atomic int shutdown; // lets running callbacks observe teardown via token
	PTP_POOL work_pool;
	PTP_CLEANUP_GROUP work_cleanup;
	TP_CALLBACK_ENVIRON work_env;

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
		case ERROR_ABANDONED_WAIT_0:
			return -ECANCELED;
		/*
		 * Winsock error codes (10000+) do not overlap with the ERROR_* range
		 * above, so they coexist in this switch. These surface from WSASend/
		 * WSARecv either synchronously (WSAGetLastError) or via the completion
		 * packet's error status.
		 */
		case WSAECONNRESET:
			return -ECONNRESET;
		case WSAECONNREFUSED:
			return -ECONNREFUSED;
		case WSAECONNABORTED:
			return -ECONNABORTED;
		case WSAENOTCONN:
			return -ENOTCONN;
		case WSAENOTSOCK:
			return -ENOTSOCK;
		case WSAESHUTDOWN:
			return -EPIPE;
		case WSAEWOULDBLOCK:
			return -EAGAIN;
		case WSAEMSGSIZE:
			return -EMSGSIZE;
		case WSAETIMEDOUT:
			return -ETIME;
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
	size = round_up_pow2(size);

	q->ops = calloc(size, sizeof(ior_iocp_op *));
	if (!q->ops) {
		return -ENOMEM;
	}
	q->head = 0;
	q->tail = 0;
	q->count = 0;
	q->size = size;
	q->mask = size - 1;
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
	q->tail = (q->tail + 1) & q->mask;
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
	q->head = (q->head + 1) & q->mask;
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

	op->wsabuf.buf = NULL;
	op->wsabuf.len = 0;
	op->sock_flags = 0;

	op->timeout_ts = NULL;
	op->timeout_flags = 0;

	op->timer_deadline_ns = 0;
	op->timer_armed = false;
	op->timer_cancelled = false;

	op->link_timeout = NULL;
	op->guarded = NULL;

	op->seq = 0;
	op->drain_after = 0;
	op->link_next = NULL;
	op->linked_deferred = false;
	op->drain_deferred = false;
	op->next_pending = NULL;

	op->bytes_transferred = 0;
	op->error_code = 0;
	op->is_synthetic = false;

	op->work_fn = NULL;
	op->work_arg = NULL;
	op->work_res = 0;
	op->work_owner = NULL;
	atomic_init(&op->token.cancelled, 0);
	op->token.shutdown = NULL;

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

/*
 * Post a completion for an op whose active_count was already reserved (armed
 * timers, link timeouts, work ops). Unlike post_synthetic_completion it
 * does not increment active_count; on PQCS failure it undoes the reservation and
 * frees the op. Must be called without timers.lock held.
 */
static void post_armed_op(ior_ctx_iocp *ctx, ior_iocp_op *op, DWORD error_code)
{
	op->is_synthetic = true;
	op->error_code = error_code;
	op->bytes_transferred = 0;

	MemoryBarrier();

	if (!PostQueuedCompletionStatus(ctx->iocp_handle, 0, 0, &op->overlapped)) {
		atomic_fetch_sub(&ctx->active_count, 1);
		free_op(ctx, op);
	}
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

/*
 * issue_read / issue_write
 *
 * When ReadFile/WriteFile is called on a handle associated with an IOCP, the
 * default behavior is that a completion packet is posted for BOTH asynchronous
 * completions (ERROR_IO_PENDING) AND synchronous successes (returns TRUE).
 * The only case where no completion is posted is an immediate error that is
 * NOT ERROR_IO_PENDING.
 *
 * Therefore:
 *   - If the call returns TRUE (synchronous success) or fails with
 *     ERROR_IO_PENDING: a completion packet will arrive on the IOCP.
 *     We increment active_count and wait for it.
 *   - If the call fails with any other error: NO completion packet is posted.
 *     We must post a synthetic completion ourselves.
 *
 * Special case: ERROR_HANDLE_EOF means the read reached end-of-file. Windows
 * still posts a completion packet for this on overlapped handles, so we treat
 * it the same as a successful async start.
 */
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
	if (result) {
		// Synchronous success: completion packet will still be posted to IOCP
		atomic_fetch_add(&ctx->active_count, 1);
		return 0;
	}

	DWORD err = GetLastError();
	if (err == ERROR_IO_PENDING || err == ERROR_HANDLE_EOF) {
		// Async in progress, or EOF - completion packet will be posted
		atomic_fetch_add(&ctx->active_count, 1);
		return 0;
	}

	// Immediate error with no completion packet - post synthetic
	return post_synthetic_completion(ctx, op, err, 0);
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
	if (result) {
		// Synchronous success: completion packet will still be posted to IOCP
		atomic_fetch_add(&ctx->active_count, 1);
		return 0;
	}

	DWORD err = GetLastError();
	if (err == ERROR_IO_PENDING) {
		// Async in progress - completion packet will be posted
		atomic_fetch_add(&ctx->active_count, 1);
		return 0;
	}

	// Immediate error with no completion packet - post synthetic
	return post_synthetic_completion(ctx, op, err, 0);
}

/*
 * issue_send / issue_recv
 *
 * Socket counterparts of issue_read/issue_write. WSASend/WSARecv behave like
 * ReadFile/WriteFile with respect to IOCP: a completion packet is posted for
 * both synchronous success (return 0) and asynchronous start (WSA_IO_PENDING).
 * Any other Winsock error means no packet is posted, so we synthesize one.
 *
 * The op's fd is an ior_fd_t (HANDLE); sockets created with WSA_FLAG_OVERLAPPED
 * are valid IOCP targets, so we cast the handle to SOCKET for the Winsock call.
 */
static int issue_send(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	int ret = ensure_handle_associated(ctx, op->fd);
	if (ret < 0) {
		return post_synthetic_completion(ctx, op, ERROR_INVALID_HANDLE, 0);
	}

	op->wsabuf.buf = (CHAR *) op->buf;
	op->wsabuf.len = op->len;

	int rc = WSASend((SOCKET) op->fd, &op->wsabuf, 1, NULL, op->sock_flags, &op->overlapped, NULL);
	if (rc == 0) {
		// Synchronous success: completion packet will still be posted to IOCP
		atomic_fetch_add(&ctx->active_count, 1);
		return 0;
	}

	int err = WSAGetLastError();
	if (err == WSA_IO_PENDING) {
		atomic_fetch_add(&ctx->active_count, 1);
		return 0;
	}

	return post_synthetic_completion(ctx, op, (DWORD) err, 0);
}

static int issue_recv(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	int ret = ensure_handle_associated(ctx, op->fd);
	if (ret < 0) {
		return post_synthetic_completion(ctx, op, ERROR_INVALID_HANDLE, 0);
	}

	op->wsabuf.buf = (CHAR *) op->buf;
	op->wsabuf.len = op->len;

	// sock_flags is an in/out parameter for WSARecv and must remain valid for
	// the whole async operation, hence it lives in the op.
	int rc = WSARecv((SOCKET) op->fd, &op->wsabuf, 1, NULL, &op->sock_flags, &op->overlapped, NULL);
	if (rc == 0) {
		// Synchronous success: completion packet will still be posted to IOCP
		atomic_fetch_add(&ctx->active_count, 1);
		return 0;
	}

	int err = WSAGetLastError();
	if (err == WSA_IO_PENDING) {
		atomic_fetch_add(&ctx->active_count, 1);
		return 0;
	}

	return post_synthetic_completion(ctx, op, (DWORD) err, 0);
}

/*
 * ================= Work op support =================
 *
 * The callback runs on a private Win32 threadpool and delivers its completion
 * with PostQueuedCompletionStatus, so it flows through the same dequeue path
 * (and LINK/DRAIN/link-timeout machinery) as every other op.
 */

static VOID CALLBACK ior_iocp_work_callback(PTP_CALLBACK_INSTANCE instance, PVOID param)
{
	(void) instance;
	ior_iocp_op *op = param;
	ior_ctx_iocp *ctx = op->work_owner;

	op->work_res = op->work_fn(&op->token, op->work_arg);

	/* The active_count slot was reserved in issue_work: posting from this
	 * threadpool thread with a post-PQCS increment would race the consumer's
	 * decrement at dequeue and underflow the counter. */
	post_armed_op(ctx, op, ERROR_SUCCESS);
}

// One-time (per context) creation of the private threadpool.
static int iocp_work_ensure(ior_ctx_iocp *ctx)
{
	if (ctx->work_pool) {
		return 0;
	}

	ctx->work_pool = CreateThreadpool(NULL);
	if (!ctx->work_pool) {
		return -ENOMEM;
	}
	SetThreadpoolThreadMaximum(ctx->work_pool, 32);

	ctx->work_cleanup = CreateThreadpoolCleanupGroup();
	if (!ctx->work_cleanup) {
		CloseThreadpool(ctx->work_pool);
		ctx->work_pool = NULL;
		return -ENOMEM;
	}

	InitializeThreadpoolEnvironment(&ctx->work_env);
	SetThreadpoolCallbackPool(&ctx->work_env, ctx->work_pool);
	SetThreadpoolCallbackCleanupGroup(&ctx->work_env, ctx->work_cleanup, NULL);

	return 0;
}

static int issue_work(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	if (iocp_work_ensure(ctx) < 0) {
		return post_synthetic_completion(ctx, op, ERROR_NOT_ENOUGH_MEMORY, 0);
	}

	op->work_owner = ctx;
	atomic_init(&op->token.cancelled, 0);
	op->token.shutdown = &ctx->shutdown;

	// Reserve the active_count slot up front, like arm_timer: the callback
	// completes from another thread, so it must post with the slot already held.
	atomic_fetch_add(&ctx->active_count, 1);

	if (!TrySubmitThreadpoolCallback(ior_iocp_work_callback, op, &ctx->work_env)) {
		atomic_fetch_sub(&ctx->active_count, 1);
		return post_synthetic_completion(ctx, op, ERROR_NOT_ENOUGH_MEMORY, 0);
	}

	return 0;
}

/* ================= IOR_OP_POLL support ================= */

static SHORT ior_poll_mask_to_wsa(uint32_t ior_mask)
{
	SHORT ev = 0;
	if (ior_mask & IOR_POLL_IN) {
		ev |= POLLRDNORM | POLLRDBAND;
	}
	if (ior_mask & IOR_POLL_OUT) {
		ev |= POLLWRNORM;
	}
	// ERR/HUP/NVAL are revents-only on Windows and must not be requested.
	return ev;
}

static uint32_t wsa_to_ior_poll_mask(SHORT revents)
{
	uint32_t mask = 0;
	if (revents & (POLLRDNORM | POLLRDBAND)) {
		mask |= IOR_POLL_IN;
	}
	if (revents & POLLWRNORM) {
		mask |= IOR_POLL_OUT;
	}
	if (revents & POLLERR) {
		mask |= IOR_POLL_ERR;
	}
	if (revents & POLLHUP) {
		mask |= IOR_POLL_HUP;
	}
	if (revents & POLLNVAL) {
		mask |= IOR_POLL_NVAL;
	}
	return mask;
}

static void iocp_poller_wake(iocp_poller *p)
{
	char b = 0;
	(void) send(p->wake_tx, &b, 1, 0);
}

static void iocp_poller_drain_wake(iocp_poller *p)
{
	char buf[64];
	while (recv(p->wake_rx, buf, sizeof(buf), 0) > 0) {
	}
}

/* Remove slot i by swapping in the last active entry. */
static void iocp_poller_remove(iocp_poller *p, uint32_t i)
{
	p->active_len--;
	p->active[i] = p->active[p->active_len];
	p->pfds[i + 1] = p->pfds[p->active_len + 1];
}

/* Complete a poll op from the poller thread (active_count slot already held). */
static void iocp_poller_post(ior_ctx_iocp *ctx, ior_iocp_op *op, SHORT revents)
{
	if (revents & POLLNVAL) {
		// Not a socket (or a closed one) - poll works on sockets only.
		post_armed_op(ctx, op, WSAENOTSOCK);
		return;
	}
	op->work_res = (int32_t) wsa_to_ior_poll_mask(revents);
	post_armed_op(ctx, op, ERROR_SUCCESS);
}

static DWORD WINAPI iocp_poller_thread_main(LPVOID arg)
{
	ior_ctx_iocp *ctx = arg;
	iocp_poller *p = &ctx->poller;

	for (;;) {
		// Ingest newly registered ops.
		EnterCriticalSection(&p->lock);
		ior_iocp_op *in = p->incoming;
		p->incoming = NULL;
		LeaveCriticalSection(&p->lock);

		while (in) {
			ior_iocp_op *next = in->next_pending;
			in->next_pending = NULL;
			if (p->active_len == p->active_cap) {
				uint32_t cap = p->active_cap ? p->active_cap * 2 : 16;
				ior_iocp_op **active = realloc(p->active, cap * sizeof(*active));
				WSAPOLLFD *pfds = realloc(p->pfds, (cap + 1) * sizeof(*pfds));
				if (active) {
					p->active = active;
				}
				if (pfds) {
					p->pfds = pfds;
				}
				if (!active || !pfds) {
					post_armed_op(ctx, in, ERROR_NOT_ENOUGH_MEMORY);
					in = next;
					continue;
				}
				p->active_cap = cap;
			}
			p->active[p->active_len] = in;
			p->pfds[p->active_len + 1].fd = (SOCKET) in->fd;
			p->pfds[p->active_len + 1].events = ior_poll_mask_to_wsa(in->poll_mask);
			p->active_len++;
			in = next;
		}

		if (atomic_load(&p->stop)) {
			break;
		}

		// Drop ops whose link timeout fired (flagged by the timer thread).
		for (uint32_t i = 0; i < p->active_len;) {
			ior_iocp_op *op = p->active[i];
			if (atomic_load_explicit(&op->token.cancelled, memory_order_acquire)) {
				iocp_poller_remove(p, i);
				post_armed_op(ctx, op, ERROR_OPERATION_ABORTED);
			} else {
				i++;
			}
		}

		p->pfds[0].fd = p->wake_rx;
		p->pfds[0].events = POLLRDNORM;
		for (uint32_t i = 0; i <= p->active_len; i++) {
			p->pfds[i].revents = 0;
		}

		int n = WSAPoll(p->pfds, p->active_len + 1, -1);
		if (n == SOCKET_ERROR) {
			// No per-socket status to act on; fail everything rather than spin.
			DWORD err = (DWORD) WSAGetLastError();
			while (p->active_len > 0) {
				ior_iocp_op *op = p->active[0];
				iocp_poller_remove(p, 0);
				post_armed_op(ctx, op, err);
			}
			continue;
		}

		if (p->pfds[0].revents) {
			iocp_poller_drain_wake(p);
		}
		for (uint32_t i = 0; i < p->active_len;) {
			SHORT revents = p->pfds[i + 1].revents;
			if (revents) {
				ior_iocp_op *op = p->active[i];
				iocp_poller_remove(p, i);
				iocp_poller_post(ctx, op, revents);
			} else {
				i++;
			}
		}
	}

	// Shutdown: fail everything still pending, including late arrivals.
	EnterCriticalSection(&p->lock);
	ior_iocp_op *in = p->incoming;
	p->incoming = NULL;
	LeaveCriticalSection(&p->lock);
	while (in) {
		ior_iocp_op *next = in->next_pending;
		in->next_pending = NULL;
		post_armed_op(ctx, in, ERROR_OPERATION_ABORTED);
		in = next;
	}
	while (p->active_len > 0) {
		ior_iocp_op *op = p->active[0];
		iocp_poller_remove(p, 0);
		post_armed_op(ctx, op, ERROR_OPERATION_ABORTED);
	}
	return 0;
}

/*
 * One-time (per context) creation of the wakeup socket pair and the poller
 * thread. Assumes WSAStartup has been done by the application (it must have
 * been, to own sockets worth polling).
 */
static int iocp_poller_ensure(ior_ctx_iocp *ctx)
{
	iocp_poller *p = &ctx->poller;

	EnterCriticalSection(&p->lock);
	if (p->thread) {
		LeaveCriticalSection(&p->lock);
		return 0;
	}

	int ret = -ENOMEM;
	SOCKET rx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	SOCKET tx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (rx == INVALID_SOCKET || tx == INVALID_SOCKET) {
		goto fail;
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	int alen = sizeof(addr);
	if (bind(rx, (struct sockaddr *) &addr, sizeof(addr)) != 0
			|| getsockname(rx, (struct sockaddr *) &addr, &alen) != 0
			|| connect(tx, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
		goto fail;
	}
	u_long nonblock = 1;
	if (ioctlsocket(rx, FIONBIO, &nonblock) != 0) {
		goto fail;
	}

	// Pre-size the arrays: the thread may run before the first registration
	// arrives and always needs the wake slot pfds[0].
	p->active_cap = 16;
	p->active = malloc(p->active_cap * sizeof(*p->active));
	p->pfds = malloc((p->active_cap + 1) * sizeof(*p->pfds));
	if (!p->active || !p->pfds) {
		goto fail;
	}

	p->wake_rx = rx;
	p->wake_tx = tx;
	p->thread = CreateThread(NULL, 0, iocp_poller_thread_main, ctx, 0, NULL);
	if (!p->thread) {
		p->wake_rx = INVALID_SOCKET;
		p->wake_tx = INVALID_SOCKET;
		goto fail;
	}

	LeaveCriticalSection(&p->lock);
	return 0;

fail:
	free(p->active);
	free(p->pfds);
	p->active = NULL;
	p->pfds = NULL;
	p->active_cap = 0;
	if (rx != INVALID_SOCKET) {
		closesocket(rx);
	}
	if (tx != INVALID_SOCKET) {
		closesocket(tx);
	}
	LeaveCriticalSection(&p->lock);
	return ret;
}

static int issue_poll(ior_ctx_iocp *ctx, ior_iocp_op *op)
{
	if (iocp_poller_ensure(ctx) < 0) {
		return post_synthetic_completion(ctx, op, ERROR_NOT_ENOUGH_MEMORY, 0);
	}

	atomic_init(&op->token.cancelled, 0);
	op->token.shutdown = &ctx->shutdown;

	// Reserve the active_count slot up front, like issue_work: the poller
	// thread completes the op, so it must post with the slot already held.
	atomic_fetch_add(&ctx->active_count, 1);

	iocp_poller *p = &ctx->poller;
	EnterCriticalSection(&p->lock);
	op->next_pending = p->incoming;
	p->incoming = op;
	LeaveCriticalSection(&p->lock);
	iocp_poller_wake(p);

	return 0;
}

static void op_to_cqe(ior_iocp_op *op)
{
	op->cqe.iocp.user_data = op->user_data;
	op->cqe.iocp.flags = 0;

	if (op->error_code != ERROR_SUCCESS) {
		op->cqe.iocp.res = win_error_to_errno(op->error_code);
	} else if (op->opcode == IOR_OP_WORK || op->opcode == IOR_OP_POLL) {
		// The callback's return value (or ready poll mask), not a byte count.
		op->cqe.iocp.res = op->work_res;
	} else {
		op->cqe.iocp.res = (int32_t) op->bytes_transferred;
	}
}

static ior_iocp_op *cqe_to_op(ior_cqe *cqe)
{
	size_t offset = offsetof(ior_iocp_op, cqe);
	return (ior_iocp_op *) ((char *) cqe - offset);
}

/* ================= Timer support ================= */

static void qpc_freq_init(void)
{
	/*
	 * Thread-safe one-shot initialization of g_qpc_freq.
	 * Uses InterlockedCompareExchange to ensure exactly one thread
	 * calls QueryPerformanceFrequency. The frequency is published with
	 * release semantics; waiters spin on an acquire load so the value is
	 * fully visible before use (correct even on weakly-ordered CPUs).
	 */
	if (InterlockedCompareExchange(&g_qpc_freq_init, 1, 0) == 0) {
		LARGE_INTEGER freq;
		QueryPerformanceFrequency(&freq);
		atomic_store_explicit(&g_qpc_freq, (int64_t) freq.QuadPart, memory_order_release);
	} else {
		// Another thread is initializing or has finished; spin until done.
		while (atomic_load_explicit(&g_qpc_freq, memory_order_acquire) == 0) {
			YieldProcessor();
		}
	}
}

static uint64_t qpc_now_ns(void)
{
	LARGE_INTEGER counter;
	QueryPerformanceCounter(&counter);

	uint64_t c = (uint64_t) counter.QuadPart;
	uint64_t f = (uint64_t) atomic_load_explicit(&g_qpc_freq, memory_order_acquire);

	uint64_t sec = c / f;
	uint64_t rem = c % f;

	return sec * 1000000000ULL + (rem * 1000000000ULL) / f;
}

static uint64_t qpc_deadline_from_timespec(const ior_timespec *ts, uint32_t flags)
{
	uint64_t delta_ns = (uint64_t) ts->tv_sec * 1000000000ULL + (uint64_t) ts->tv_nsec;

	if (flags & IOR_TIMEOUT_ABS) {
		// Absolute deadline: treat the timespec value directly as the deadline.
		// Caller is responsible for using a compatible clock base.
		return delta_ns;
	}

	// Relative: deadline = now + delta
	return qpc_now_ns() + delta_ns;
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

/* Remove a specific op from the heap (O(n) search). Returns true if found. */
static bool timer_heap_remove(timer_mgr *tm, ior_iocp_op *op)
{
	for (uint32_t i = 0; i < tm->heap_len; i++) {
		if (tm->heap[i] != op) {
			continue;
		}
		tm->heap_len--;
		if (i < tm->heap_len) {
			tm->heap[i] = tm->heap[tm->heap_len];
			// Restore heap order from i: try down, then up.
			timer_heap_sift_down(tm, i);
			timer_heap_sift_up(tm, i);
		}
		return true;
	}
	return false;
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

		if (op->guarded) {
			/*
			 * Link timeout fired first: this side won the arbitration (we cleared
			 * timer_armed under the lock, so the completion path will leave the
			 * pair to us). Cancel the in-flight guarded op - its -ECANCELED
			 * completion arrives through the normal IOCP path - and post this
			 * link timeout as -ETIME.
			 *
			 * A guarded work op cannot be cancelled: its callback runs to
			 * completion on the threadpool and posts its real result. Flag its
			 * token instead so the callback can bail out early. The store
			 * happens under timers.lock, which the completion path also takes
			 * to resolve the pair before the op can be reaped and recycled, so
			 * the guarded op is guaranteed alive here.
			 */
			ior_iocp_op *guarded = op->guarded;
			// Work and poll ops have no OVERLAPPED I/O to cancel: flag their
			// token instead (the poller drops a flagged op once woken).
			bool token_cancel
					= guarded->opcode == IOR_OP_WORK || guarded->opcode == IOR_OP_POLL;
			bool is_poll = guarded->opcode == IOR_OP_POLL;
			if (token_cancel) {
				atomic_store_explicit(&guarded->token.cancelled, 1, memory_order_release);
			}
			LeaveCriticalSection(&tm->lock);
			if (!token_cancel) {
				CancelIoEx((HANDLE) guarded->fd, &guarded->overlapped);
			} else if (is_poll) {
				iocp_poller_wake(&ctx->poller);
			}
			post_armed_op(ctx, op, ERROR_TIMEOUT);
			EnterCriticalSection(&tm->lock);
			continue;
		}

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

	uint64_t deadline = qpc_deadline_from_timespec(op->timeout_ts, op->timeout_flags);

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

/*
 * Arm the link timeout guarding an op that has just been issued (and is now
 * in-flight). Reserves an active_count slot, like arm_timer, so post_armed_op
 * balances it on resolution. On a heap-allocation failure the link timeout is
 * completed immediately as -ECANCELED.
 */
static void arm_link_timeout(ior_ctx_iocp *ctx, ior_iocp_op *guarded)
{
	ior_iocp_op *lt = guarded->link_timeout;
	timer_mgr *tm = &ctx->timers;

	uint64_t deadline = lt->timeout_ts
			? qpc_deadline_from_timespec(lt->timeout_ts, lt->timeout_flags)
			: qpc_now_ns();

	EnterCriticalSection(&tm->lock);
	lt->timer_deadline_ns = deadline;
	lt->timer_armed = true;
	int ret = timer_heap_push(tm, lt);
	if (ret == 0) {
		atomic_fetch_add(&ctx->active_count, 1);
		WakeConditionVariable(&tm->cv);
	} else {
		lt->timer_armed = false;
	}
	LeaveCriticalSection(&tm->lock);

	if (ret < 0) {
		(void) post_synthetic_completion(ctx, lt, ERROR_OPERATION_ABORTED, 0);
	}
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

		// Only consider "heads" (not waiting on LINK predecessor).
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
	int ret;
	switch (op->opcode) {
		case IOR_OP_NOP:
			return post_synthetic_completion(ctx, op, ERROR_SUCCESS, 0);

		case IOR_OP_READ:
			ret = issue_read(ctx, op);
			break;

		case IOR_OP_WRITE:
			ret = issue_write(ctx, op);
			break;

		case IOR_OP_SPLICE:
			return post_synthetic_completion(ctx, op, ERROR_NOT_SUPPORTED, 0);

		case IOR_OP_SEND:
			ret = issue_send(ctx, op);
			break;

		case IOR_OP_RECV:
			ret = issue_recv(ctx, op);
			break;

		case IOR_OP_WORK:
			// Falls through to the link-timeout arming below: a guarded work
			// op's deadline is watched by the timer thread while the callback
			// runs on the threadpool.
			ret = issue_work(ctx, op);
			break;

		case IOR_OP_POLL:
			// Like WORK, a guarded poll's deadline is watched by the timer
			// thread, which flags the token and wakes the poller.
			ret = issue_poll(ctx, op);
			break;

		case IOR_OP_TIMER:
			return arm_timer(ctx, op);

		case IOR_OP_LINK_TIMEOUT:
			// A paired link timeout is armed via its guarded op, never issued
			// directly. Reaching here means it was unpaired - treat as a plain
			// timeout so it still completes with -ETIME.
			return arm_timer(ctx, op);

		default:
			return post_synthetic_completion(ctx, op, ERROR_NOT_SUPPORTED, 0);
	}

	// The guarded op is now in flight; arm its link-timeout watchdog.
	if (ret == 0 && op->link_timeout) {
		arm_link_timeout(ctx, op);
	}
	return ret;
}

/* ================= Backend ops ================= */

static int ior_iocp_backend_init(void **backend_ctx, ior_params *params)
{
	if (!backend_ctx || !params) {
		return -EINVAL;
	}

	// Ensure QPC frequency is initialized (thread-safe, one-shot)
	qpc_freq_init();

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

	// Poller bookkeeping; the thread and wakeup sockets are created lazily.
	InitializeCriticalSection(&ctx->poller.lock);
	ctx->poller.wake_tx = INVALID_SOCKET;
	ctx->poller.wake_rx = INVALID_SOCKET;
	atomic_store(&ctx->poller.stop, 0);

	atomic_store(&ctx->shutdown, 0);

	ctx->features = IOR_FEAT_NATIVE_ASYNC | IOR_FEAT_WORK | IOR_FEAT_POLL_ADD;
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

	/*
	 * Let running work callbacks observe teardown through their tokens, then
	 * wait for every submitted callback to finish - queued ones still run
	 * (FALSE = do not cancel pending callbacks), honoring the contract that a
	 * submitted work op's callback always executes. Their completions land in
	 * the IOCP and are reclaimed by the drain loop below.
	 */
	atomic_store(&ctx->shutdown, 1);
	if (ctx->work_pool) {
		CloseThreadpoolCleanupGroupMembers(ctx->work_cleanup, FALSE, NULL);
		CloseThreadpoolCleanupGroup(ctx->work_cleanup);
		DestroyThreadpoolEnvironment(&ctx->work_env);
		CloseThreadpool(ctx->work_pool);
		ctx->work_pool = NULL;
	}

	// Stop timer thread
	atomic_store(&ctx->timers.stop, 1);
	EnterCriticalSection(&ctx->timers.lock);
	WakeConditionVariable(&ctx->timers.cv);
	LeaveCriticalSection(&ctx->timers.lock);

	WaitForSingleObject(ctx->timers.thread, INFINITE);
	CloseHandle(ctx->timers.thread);

	/*
	 * Stop the poller thread (after the timer thread, which may still wake it
	 * for cancelled poll ops). Pending polls are posted as -ECANCELED and
	 * reclaimed by the drain loop below.
	 */
	if (ctx->poller.thread) {
		atomic_store(&ctx->poller.stop, 1);
		iocp_poller_wake(&ctx->poller);
		WaitForSingleObject(ctx->poller.thread, INFINITE);
		CloseHandle(ctx->poller.thread);
		closesocket(ctx->poller.wake_tx);
		closesocket(ctx->poller.wake_rx);
		free(ctx->poller.active);
		free(ctx->poller.pfds);
	}
	DeleteCriticalSection(&ctx->poller.lock);

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

	/*
	 * Drain all in-flight completions from the IOCP.
	 *
	 * active_count tracks ops that have been posted to the IOCP
	 * (via ReadFile/WriteFile/PostQueuedCompletionStatus) but not yet
	 * dequeued by GetQueuedCompletionStatus. We must dequeue them here
	 * or we'll spin forever.
	 */
	while (atomic_load(&ctx->active_count) > 0) {
		DWORD bytes = 0;
		ULONG_PTR key = 0;
		LPOVERLAPPED overlapped = NULL;

		BOOL ok = GetQueuedCompletionStatus(ctx->iocp_handle, &bytes, &key, &overlapped, 100);

		if (!ok && overlapped == NULL) {
			DWORD gle = GetLastError();
			if (gle == WAIT_TIMEOUT || gle == ERROR_TIMEOUT) {
				// Timeout with nothing dequeued; keep trying briefly.
				// Safety valve: if nothing arrives after several rounds,
				// break to avoid hanging forever during teardown.
				continue;
			}
			if (gle == ERROR_ABANDONED_WAIT_0) {
				// IOCP handle was closed (shouldn't happen yet, but be safe)
				break;
			}
			// Unknown error - bail out
			break;
		}

		if (overlapped) {
			ior_iocp_op *op = (ior_iocp_op *) overlapped;
			atomic_fetch_sub(&ctx->active_count, 1);
			free_op(ctx, op);
		}
	}

	// Also drain any ops sitting in the ready queue
	while (!ready_queue_empty(&ctx->ready)) {
		ior_iocp_op *op = ready_queue_pop(&ctx->ready);
		if (op) {
			free_op(ctx, op);
		}
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

		// A link timeout already paired with its guarded op is armed when that
		// op is issued, not submitted as a standalone op. Still count it: its
		// SQE was consumed, and other backends report both entries of the pair.
		if (op->opcode == IOR_OP_LINK_TIMEOUT && op->guarded) {
			submitted++;
			prev = op;
			continue;
		}

		// DRAIN barrier means "wait for all prior completions"
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

		// Pair a guarded op with an immediately following link timeout: the
		// link timeout watchdogs this op rather than chaining after it.
		if (op->sqe_flags & IOR_SQE_IO_LINK && ctx->sq_head != ctx->sq_tail) {
			ior_iocp_op *nxt = ctx->sq_array[ctx->sq_head];
			if (nxt->opcode == IOR_OP_LINK_TIMEOUT && !nxt->guarded) {
				op->link_timeout = nxt;
				nxt->guarded = op;
			}
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
			if (gle == ERROR_ABANDONED_WAIT_0) {
				// IOCP handle was closed while we were waiting
				return -ECANCELED;
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

	/*
	 * Linked-timeout arbitration: if this completed op was guarded by a link
	 * timeout, resolve the pair. Whoever finds the timeout still armed (under
	 * timers.lock) owns posting it. If it is already disarmed, the timer thread
	 * fired first and has handled both sides, so we do nothing here (this op's
	 * own completion is the -ECANCELED produced by that CancelIoEx).
	 */
	if (op->link_timeout) {
		ior_iocp_op *lt = op->link_timeout;
		op->link_timeout = NULL;

		EnterCriticalSection(&ctx->timers.lock);
		bool won = lt->timer_armed;
		if (won) {
			lt->timer_armed = false;
			timer_heap_remove(&ctx->timers, lt);
		}
		LeaveCriticalSection(&ctx->timers.lock);

		if (won) {
			// Guarded op finished before the deadline: cancel the link timeout.
			post_armed_op(ctx, lt, ERROR_OPERATION_ABORTED);
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
		if (ret == -EAGAIN) {
			// A stray NULL completion packet was dequeued (e.g. an external
			// PostQueuedCompletionStatus with NULL overlapped). Under an
			// INFINITE wait this is not a terminal condition - real
			// completions are still pending, so keep waiting.
			continue;
		}
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

	/*
	 * Block until a completion is ready. A stray NULL completion packet (e.g.
	 * an external PostQueuedCompletionStatus with a NULL OVERLAPPED) surfaces as
	 * -EAGAIN from dequeue_one_completion under an INFINITE wait; that is not a
	 * real completion, so we keep waiting rather than returning it.
	 */
	for (;;) {
		if (!ready_queue_empty(&ctx->ready)) {
			ior_iocp_op *op = ready_queue_peek(&ctx->ready);
			*cqe_out = &op->cqe;
			return 0;
		}

		int ret = dequeue_one_completion(ctx, INFINITE);
		if (ret == -EAGAIN) {
			continue;
		}
		if (ret < 0) {
			return ret;
		}
	}
}

static int ior_iocp_backend_wait_cqe_timeout(
		void *backend_ctx, ior_cqe **cqe_out, ior_timespec *timeout)
{
	if (!backend_ctx || !cqe_out) {
		return -EINVAL;
	}

	ior_ctx_iocp *ctx = backend_ctx;

	// Validate the timeout and turn it into an absolute deadline so spurious
	// (stray-packet) wakeups can resume the wait without extending it.
	int has_deadline = 0;
	uint64_t deadline_ns = 0;
	if (timeout) {
		if (timeout->tv_sec < 0 || timeout->tv_nsec < 0 || timeout->tv_nsec >= 1000000000L) {
			return -EINVAL;
		}
		deadline_ns = qpc_now_ns() + (uint64_t) timeout->tv_sec * 1000000000ULL
				+ (uint64_t) timeout->tv_nsec;
		has_deadline = 1;
	}

	for (;;) {
		if (!ready_queue_empty(&ctx->ready)) {
			ior_iocp_op *op = ready_queue_peek(&ctx->ready);
			*cqe_out = &op->cqe;
			return 0;
		}

		// Compute how long to block. If the deadline has already passed we still
		// do one non-blocking poll (timeout_ms = 0) so a completion sitting in
		// the IOCP is not missed, then report -ETIME below.
		DWORD timeout_ms = INFINITE;
		if (has_deadline) {
			uint64_t now_ns = qpc_now_ns();
			if (now_ns >= deadline_ns) {
				timeout_ms = 0;
			} else {
				// Round remaining time up to whole milliseconds, clamped below
				// INFINITE (which doubles as the "no timeout" sentinel).
				uint64_t rem_ms = (deadline_ns - now_ns + 999999ULL) / 1000000ULL;
				timeout_ms = rem_ms >= INFINITE ? (INFINITE - 1) : (DWORD) rem_ms;
			}
		}

		int ret = dequeue_one_completion(ctx, timeout_ms);
		if (ret == 0) {
			continue; // got a completion; loop returns it from the ready queue
		}
		if (ret == -EAGAIN || ret == -ETIMEDOUT) {
			// Nothing ready (stray NULL packet, or the wait elapsed). Give up
			// only once the deadline has passed; otherwise resume waiting.
			if (has_deadline && qpc_now_ns() >= deadline_ns) {
				return -ETIME;
			}
			continue;
		}
		return ret; // genuine error
	}
}

static void ior_iocp_backend_cqe_seen(void *backend_ctx, ior_cqe *cqe)
{
	if (!backend_ctx || !cqe) {
		return;
	}

	ior_ctx_iocp *ctx = backend_ctx;
	ior_iocp_op *op = cqe_to_op(cqe);

	ior_iocp_op *head_op = ready_queue_peek(&ctx->ready);

	if (head_op == op) {
		// Fast path: in-order consumption, matching the common io_uring usage.
		ready_queue_pop(&ctx->ready);
		free_op(ctx, op);
		return;
	}

	/*
	 * Out-of-order cqe_seen. This happens if the caller peeked a batch (via
	 * peek_batch_cqe) and then marked CQEs seen individually rather than using
	 * cq_advance. Rather than abort(), locate the entry in the ready queue and
	 * remove it in place, compacting the ring. This keeps a misusing caller
	 * alive with consistent behaviour across debug and release builds.
	 */
	ready_queue *q = &ctx->ready;
	uint32_t found = UINT32_MAX;
	for (uint32_t i = 0; i < q->count; i++) {
		uint32_t idx = (q->head + i) & q->mask;
		if (q->ops[idx] == op) {
			found = i;
			break;
		}
	}

	if (found == UINT32_MAX) {
		IOR_LOG_ERROR("cqe_seen called for CQE not in ready queue: %p", (void *) op);
		return;
	}

	IOR_LOG_WARN(
			"cqe_seen called out of order (offset %u of %u); removing in place", found, q->count);

	// Shift later entries down by one to fill the gap.
	for (uint32_t i = found; i + 1 < q->count; i++) {
		uint32_t cur = (q->head + i) & q->mask;
		uint32_t nxt = (q->head + i + 1) & q->mask;
		q->ops[cur] = q->ops[nxt];
	}

	q->tail = (q->tail - 1) & q->mask;
	q->count--;

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

	// Drain whatever is already buffered. Bound by ready.count, not just
	// emptiness: this peeks without popping, so the entries stay in the queue
	// (e.g. a completion left behind by a prior wait_cqe). Looping on
	// !ready_queue_empty() would never terminate on the count and would read
	// past the live entries into NULL ring slots.
	while (count < max && count < ctx->ready.count) {
		ior_iocp_op *op = ctx->ready.ops[(ctx->ready.head + count) & ctx->ready.mask];
		cqes[count] = &op->cqe;
		count++;
	}

	unsigned need = max - count;
	for (unsigned i = 0; i < need; i++) {
		int ret = dequeue_one_completion(ctx, 0);
		if (ret < 0) {
			break;
		}
		ior_iocp_op *op = ctx->ready.ops[(ctx->ready.head + count) & ctx->ready.mask];
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

static void ior_iocp_backend_prep_link_timeout(ior_sqe *sqe, ior_timespec *ts, unsigned flags)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_LINK_TIMEOUT;
	op->fd = NULL;
	op->timeout_ts = ts;
	op->timeout_flags = flags;
}

static void ior_iocp_backend_prep_send(
		ior_sqe *sqe, ior_fd_t sockfd, const void *buf, unsigned nbytes, int flags)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_SEND;
	op->fd = sockfd;
	op->buf = (void *) buf;
	op->len = nbytes;
	op->sock_flags = (DWORD) flags;
}

static void ior_iocp_backend_prep_recv(
		ior_sqe *sqe, ior_fd_t sockfd, void *buf, unsigned nbytes, int flags)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_RECV;
	op->fd = sockfd;
	op->buf = buf;
	op->len = nbytes;
	op->sock_flags = (DWORD) flags;
}

static void ior_iocp_backend_prep_poll_add(ior_sqe *sqe, ior_fd_t fd, uint32_t poll_mask)
{
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_POLL;
	op->fd = fd;
	op->poll_mask = poll_mask;
}

static int ior_iocp_backend_prep_work(void *backend_ctx, ior_sqe *sqe, ior_work_fn fn, void *arg)
{
	(void) backend_ctx;
	ior_iocp_op *op = (ior_iocp_op *) sqe;
	memset(&op->overlapped, 0, sizeof(OVERLAPPED));
	op->opcode = IOR_OP_WORK;
	op->fd = NULL;
	op->work_fn = fn;
	op->work_arg = arg;
	return 0;
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
	.prep_link_timeout = ior_iocp_backend_prep_link_timeout,
	.prep_send = ior_iocp_backend_prep_send,
	.prep_recv = ior_iocp_backend_prep_recv,
	.prep_poll_add = ior_iocp_backend_prep_poll_add,
	.prep_work = ior_iocp_backend_prep_work,
	.sqe_set_data = ior_iocp_backend_sqe_set_data,
	.sqe_set_flags = ior_iocp_backend_sqe_set_flags,
	.cqe_get_data = ior_iocp_backend_cqe_get_data,
	.cqe_get_res = ior_iocp_backend_cqe_get_res,
	.cqe_get_flags = ior_iocp_backend_cqe_get_flags,
	.backend_name = ior_iocp_backend_name,
	.get_features = ior_iocp_backend_get_features,
};

#endif /* IOR_HAVE_IOCP */
