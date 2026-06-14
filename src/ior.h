/* SPDX-License-Identifier: BSD-3-Clause */
/**
 * @file ior.h
 * @brief Public API for ior, a cross-platform io_uring-like asynchronous I/O
 *        library.
 *
 * ior exposes a submission/completion queue model inspired by io_uring and maps
 * it onto the best available backend for the platform: io_uring on Linux, a
 * portable thread pool elsewhere, and I/O completion ports on Windows. The API
 * and its semantics are identical across all backends.
 *
 * Typical flow:
 *   1. ior_queue_init() / ior_queue_init_params() to create a context.
 *   2. ior_get_sqe(), then an ior_prep_*() helper to describe an operation.
 *   3. ior_submit() / ior_submit_and_wait() to submit.
 *   4. ior_wait_cqe() / ior_peek_cqe() to reap completions, then ior_cqe_seen().
 *   5. ior_queue_exit() to tear down.
 */
#ifndef IOR_H
#define IOR_H

#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Platform-specific file descriptor type */
#ifdef _WIN32
/*
 * Define WIN32_LEAN_AND_MEAN before windows.h so it does not implicitly
 * include the legacy winsock.h (Winsock 1.1). That header conflicts with
 * winsock2.h, so without this guard any consumer that uses ior.h together
 * with winsock2.h would get a flood of struct/function redefinition errors
 * unless they carefully control include order. With this guard, including
 * ior.h before or after winsock2.h both work.
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
/** Platform descriptor type used by all operations (HANDLE on Windows). */
typedef HANDLE ior_fd_t;
/** Invalid-descriptor sentinel for ::ior_fd_t. */
#define IOR_INVALID_FD INVALID_HANDLE_VALUE
#else
/** Platform descriptor type used by all operations (int on POSIX). */
typedef int ior_fd_t;
/** Invalid-descriptor sentinel for ::ior_fd_t. */
#define IOR_INVALID_FD (-1)
#endif

/**
 * @brief Platform-independent timespec for async I/O operations.
 *
 * Matches the layout of Linux's __kernel_timespec (required by io_uring) and
 * uses 64-bit fields on all platforms.
 */
typedef struct ior_timespec {
	/** Seconds. */
	int64_t tv_sec;
	/** Nanoseconds. */
	long long tv_nsec;
} ior_timespec;

/**
 * @name Operation codes
 * Identify the type of operation an SQE carries; set by the ior_prep_*()
 * helpers. NOP/READ/WRITE/TIMER/SPLICE/SEND/RECV are implemented; the remaining
 * socket opcodes are reserved and not yet wired to prep helpers.
 * @{
 */
/** No-op; completes immediately with result 0. */
#define IOR_OP_NOP 0
/** Read into a buffer (ior_prep_read). */
#define IOR_OP_READ 1
/** Write from a buffer (ior_prep_write). */
#define IOR_OP_WRITE 2
/** Timeout (ior_prep_timeout); completes with -ETIME. */
#define IOR_OP_TIMER 3
/** Move data between descriptors (ior_prep_splice). */
#define IOR_OP_SPLICE 4
// Stage 2:
/** Reserved: accept a connection (not yet implemented). */
#define IOR_OP_ACCEPT 5
/** Reserved: connect a socket (not yet implemented). */
#define IOR_OP_CONNECT 6
/** Reserved: listen on a socket (not yet implemented). */
#define IOR_OP_LISTEN 7
/** Reserved: bind a socket (not yet implemented). */
#define IOR_OP_BIND 8
/** Send on a socket (ior_prep_send). */
#define IOR_OP_SEND 9
/** Receive from a socket (ior_prep_recv). */
#define IOR_OP_RECV 10
/** Timeout that cancels the preceding linked op (ior_prep_link_timeout). */
#define IOR_OP_LINK_TIMEOUT 11
/** @} */

/**
 * @name Setup flags
 * Bits for ior_params::flags. These primarily affect the io_uring backend;
 * other backends ignore flags they do not support.
 * @{
 */
/** Use a kernel submission-polling thread. */
#define IOR_SETUP_SQPOLL (1U << 0)
/** Use busy-polling for I/O completions. */
#define IOR_SETUP_IOPOLL (1U << 1)
/** Defer task work until the next submit. */
#define IOR_SETUP_DEFER (1U << 2)
/** @} */

/**
 * @name Submission queue entry flags
 * Bits for ior_sqe_set_flags().
 * @{
 */
/** fd refers to a registered (fixed) file. */
#define IOR_SQE_FIXED_FILE (1U << 0)
/** Wait for all prior SQEs to complete before this one. */
#define IOR_SQE_IO_DRAIN (1U << 1)
/** Link to the next SQE; it starts only if this one succeeds. */
#define IOR_SQE_IO_LINK (1U << 2)
/** Hint to perform the operation asynchronously. */
#define IOR_SQE_ASYNC (1U << 3)
/** @} */

/** Asynchronous I/O backend implementation. */
typedef enum {
	/** Auto-select the best backend for the platform. */
	IOR_BACKEND_AUTO = 0,
	/** Linux io_uring. */
	IOR_BACKEND_IOURING,
	/** Portable thread-pool fallback. */
	IOR_BACKEND_THREADS,
	/** Windows I/O completion ports. */
	IOR_BACKEND_IOCP,
} ior_backend_type;

/**
 * @name Feature flags
 * Reported in ior_params::features and by ior_get_features().
 * @{
 */
/** Backend performs I/O without a thread pool. */
#define IOR_FEAT_NATIVE_ASYNC (1U << 0)
/** Zero-copy splice is supported. */
#define IOR_FEAT_SPLICE (1U << 1)
/** Registered/fixed files are supported. */
#define IOR_FEAT_FIXED_FILE (1U << 2)
/** Poll-based readiness is supported. */
#define IOR_FEAT_POLL_ADD (1U << 3)
/** Kernel submission polling is supported. */
#define IOR_FEAT_SQPOLL (1U << 4)
/** @} */

/**
 * @brief Sentinel offset meaning "no offset / use the file description's current
 *        position."
 *
 * For read/write this selects read()/write() semantics over the positioned
 * pread()/pwrite() (required for non-seekable fds such as sockets and pipes).
 * For splice it marks an unused in/out offset. Equal to (uint64_t)-1, matching
 * io_uring's convention for an absent offset.
 */
#define IOR_OFF_NONE ((uint64_t) -1)

/* Forward declarations - OPAQUE TYPES */
/** Opaque I/O context: one submission/completion queue pair plus backend state. */
typedef struct ior_ctx ior_ctx;
/** Opaque submission queue entry; fill via ior_prep_*() and ior_sqe_set_*(). */
typedef struct ior_sqe ior_sqe;
/** Opaque completion queue entry; inspect via ior_cqe_get_*(). */
typedef struct ior_cqe ior_cqe;

typedef struct ior_params ior_params;

/** Setup parameters for ior_queue_init_params(). */
struct ior_params {
	/** Submission queue size; 0 uses the `entries` argument to init. */
	uint32_t sq_entries;
	/** Completion queue size; 0 lets the backend choose (typically 2x SQ). */
	uint32_t cq_entries;
	/** IOR_SETUP_* setup flags. */
	uint32_t flags;
	/** CPU to pin the SQPOLL thread to (io_uring + IOR_SETUP_SQPOLL). */
	uint32_t sq_thread_cpu;
	/** SQPOLL idle timeout in ms before the poll thread sleeps. */
	uint32_t sq_thread_idle;
	/** [out] IOR_FEAT_* flags the chosen backend provides. */
	uint32_t features;
	/** Desired backend, or IOR_BACKEND_AUTO. */
	ior_backend_type backend;
};

/* Core API */

/**
 * Create an I/O context with explicit parameters.
 *
 * @param entries  Default submission queue size, used when params->sq_entries is 0.
 * @param ctx_out  [out] Receives the new context on success.
 * @param params   Setup parameters; params->features is filled in on success.
 * @return 0 on success, or a negative errno (-EINVAL for bad arguments, -ENOSYS
 *         if the requested backend is unavailable, -ENOMEM, ...).
 */
int ior_queue_init_params(unsigned entries, ior_ctx **ctx_out, ior_params *params);

/**
 * Create an I/O context with default parameters and the auto-selected backend.
 *
 * @param entries  Submission queue size.
 * @param ctx_out  [out] Receives the new context on success.
 * @return 0 on success, or a negative errno.
 */
int ior_queue_init(unsigned entries, ior_ctx **ctx_out);

/**
 * Destroy an I/O context and release its resources.
 *
 * Waits for any backend worker threads to finish. Safe to call with NULL.
 *
 * @param ctx  Context to destroy (may be NULL).
 */
void ior_queue_exit(ior_ctx *ctx);

/* Submission */

/**
 * Obtain the next free submission queue entry.
 *
 * Describe the operation with an ior_prep_*() helper, optionally attach
 * ior_sqe_set_data()/ior_sqe_set_flags(), then publish it with ior_submit().
 *
 * @param ctx  I/O context.
 * @return A pointer to an SQE, or NULL if the submission queue is full.
 */
ior_sqe *ior_get_sqe(ior_ctx *ctx);

/**
 * Submit all prepared submission queue entries.
 *
 * @param ctx  I/O context.
 * @return The number of entries submitted (>= 0), or a negative errno.
 */
int ior_submit(ior_ctx *ctx);

/**
 * Submit all prepared entries and wait for completions.
 *
 * @param ctx      I/O context.
 * @param wait_nr  Minimum number of completions to wait for (0 = do not wait).
 * @return The number of entries submitted (>= 0), or a negative errno.
 */
int ior_submit_and_wait(ior_ctx *ctx, unsigned wait_nr);

/* Completion
 *
 * All backends honor the same completion-queue contract, modeled on io_uring.
 * A completion (CQE) returned by peek or wait is NOT consumed by those calls:
 * it stays valid and stable - repeated peeks/waits return the same CQE - until
 * it is consumed with ior_cqe_seen or ior_cq_advance.
 */

/**
 * Non-blocking check for a ready completion.
 *
 * Does not consume the completion; a subsequent peek or wait returns the same
 * CQE until it is consumed with ior_cqe_seen() or ior_cq_advance().
 *
 * @param ctx      I/O context.
 * @param cqe_out  On success, set to the completion at the head of the queue.
 * @return 0 if a completion was available, -EAGAIN if none is ready, or
 *         -EINVAL if ctx or cqe_out is NULL.
 */
int ior_peek_cqe(ior_ctx *ctx, ior_cqe **cqe_out);

/**
 * Block until a completion is ready.
 *
 * Waits indefinitely for the next completion. Does not return -EAGAIN
 * spuriously and does not consume the completion (the returned CQE is identical
 * to what ior_peek_cqe() would return).
 *
 * @param ctx      I/O context.
 * @param cqe_out  On success, set to the completion at the head of the queue.
 * @return 0 on success, or a negative errno on failure (e.g. -EINVAL if ctx or
 *         cqe_out is NULL, -EINTR if interrupted).
 */
int ior_wait_cqe(ior_ctx *ctx, ior_cqe **cqe_out);

/**
 * Block until a completion is ready or the timeout elapses.
 *
 * Like ior_wait_cqe() but bounded by @p timeout. Does not consume the
 * completion.
 *
 * @param ctx      I/O context.
 * @param cqe_out  On success, set to the completion at the head of the queue.
 * @param timeout  Maximum time to wait, or NULL to wait indefinitely.
 * @return 0 on success, -ETIME if the timeout elapsed before a completion
 *         arrived, or a negative errno on failure (e.g. -EINVAL for NULL ctx /
 *         cqe_out or an invalid timeout).
 */
int ior_wait_cqe_timeout(ior_ctx *ctx, ior_cqe **cqe_out, ior_timespec *timeout);

/**
 * Consume a single completion.
 *
 * Marks the completion at the head of the queue as seen, advancing the queue by
 * one. Equivalent to ior_cq_advance(ctx, 1). After this call the CQE pointer
 * must not be used.
 *
 * @param ctx  I/O context.
 * @param cqe  The completion previously obtained from peek/wait.
 */
void ior_cqe_seen(ior_ctx *ctx, ior_cqe *cqe);

/**
 * Peek at a batch of ready completions without consuming them.
 *
 * Fills @p cqes with up to @p max completions currently ready. The completions
 * are not consumed; release them afterwards with ior_cq_advance().
 *
 * @param ctx   I/O context.
 * @param cqes  Array receiving pointers to ready completions.
 * @param max   Capacity of @p cqes.
 * @return The number of completions written to @p cqes (0 if none are ready).
 */
unsigned ior_peek_batch_cqe(ior_ctx *ctx, ior_cqe **cqes, unsigned max);

/**
 * Consume @p nr completions from the head of the queue.
 *
 * Typically used to release a batch obtained via ior_peek_batch_cqe().
 *
 * @param ctx  I/O context.
 * @param nr   Number of completions to consume; 0 is a no-op.
 */
void ior_cq_advance(ior_ctx *ctx, unsigned nr);

/* SQE preparation helpers - describe an operation on an entry from ior_get_sqe(). */

/**
 * Prepare a no-op that completes immediately with result 0.
 *
 * @param ctx  I/O context.
 * @param sqe  Entry from ior_get_sqe().
 */
void ior_prep_nop(ior_ctx *ctx, ior_sqe *sqe);

/**
 * Prepare a read into @p buf.
 *
 * @param ctx     I/O context.
 * @param sqe     Entry from ior_get_sqe().
 * @param fd      Source file or socket descriptor.
 * @param buf     Destination buffer.
 * @param nbytes  Maximum number of bytes to read.
 * @param offset  File offset, or IOR_OFF_NONE to read at the current position
 *                (required for non-seekable fds such as sockets and pipes).
 */
void ior_prep_read(
		ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd, void *buf, unsigned nbytes, uint64_t offset);

/**
 * Prepare a write from @p buf.
 *
 * @param ctx     I/O context.
 * @param sqe     Entry from ior_get_sqe().
 * @param fd      Destination file or socket descriptor.
 * @param buf     Source buffer.
 * @param nbytes  Number of bytes to write.
 * @param offset  File offset, or IOR_OFF_NONE to write at the current position
 *                (required for non-seekable fds such as sockets and pipes).
 */
void ior_prep_write(
		ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd, const void *buf, unsigned nbytes, uint64_t offset);

/**
 * Prepare a splice (zero-copy move of data between two descriptors).
 *
 * Requires IOR_FEAT_SPLICE; backends without it emulate the move with a
 * read/write loop.
 *
 * @param ctx      I/O context.
 * @param sqe      Entry from ior_get_sqe().
 * @param fd_in    Source descriptor.
 * @param off_in   Source offset, or IOR_OFF_NONE for the current position.
 * @param fd_out   Destination descriptor.
 * @param off_out  Destination offset, or IOR_OFF_NONE for the current position.
 * @param nbytes   Number of bytes to move.
 * @param flags    Splice flags (SPLICE_F_*).
 */
void ior_prep_splice(ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd_in, uint64_t off_in, ior_fd_t fd_out,
		uint64_t off_out, unsigned nbytes, unsigned flags);

/**
 * Prepare a timeout that completes with -ETIME after @p ts elapses.
 *
 * @param ctx    I/O context.
 * @param sqe    Entry from ior_get_sqe().
 * @param ts     Relative duration to wait.
 * @param count  Number of completions to wait for before the timeout fires
 *               (io_uring semantics; 0 = a pure time-based timeout). Ignored by
 *               backends that do not support it.
 * @param flags  Timeout flags (e.g. absolute time). Ignored where unsupported.
 */
void ior_prep_timeout(ior_ctx *ctx, ior_sqe *sqe, ior_timespec *ts, unsigned count, unsigned flags);

/**
 * Prepare a timeout linked to the preceding operation.
 *
 * Acts as a deadline/watchdog on a single operation. To use it, submit the
 * guarded operation with the IOR_SQE_IO_LINK flag and make this link timeout the
 * immediately following submission entry. Both entries always produce a CQE:
 *   - if @p ts elapses first, the guarded op is cancelled (its CQE has
 *     res == -ECANCELED) and this link timeout completes with res == -ETIME;
 *   - if the guarded op finishes first, it reports its normal result and this
 *     link timeout completes with res == -ECANCELED.
 *
 * On the threads backend, cancellation is effective for read/write/send/recv on
 * pollable descriptors (sockets, pipes); a guarded op on a regular file runs to
 * completion uncancelled.
 *
 * @param ctx    I/O context.
 * @param sqe    Entry from ior_get_sqe(), submitted right after the guarded op.
 * @param ts     Relative duration after which the guarded op is cancelled.
 * @param flags  Reserved; must be 0.
 */
void ior_prep_link_timeout(ior_ctx *ctx, ior_sqe *sqe, ior_timespec *ts, unsigned flags);

/**
 * Prepare a send on a connected socket.
 *
 * @param ctx     I/O context.
 * @param sqe     Entry from ior_get_sqe().
 * @param sockfd  Connected socket descriptor.
 * @param buf     Data to send.
 * @param nbytes  Number of bytes to send.
 * @param flags   Send flags (MSG_*).
 */
void ior_prep_send(
		ior_ctx *ctx, ior_sqe *sqe, ior_fd_t sockfd, const void *buf, unsigned nbytes, int flags);

/**
 * Prepare a receive from a connected socket.
 *
 * @param ctx     I/O context.
 * @param sqe     Entry from ior_get_sqe().
 * @param sockfd  Connected socket descriptor.
 * @param buf     Destination buffer.
 * @param nbytes  Maximum number of bytes to receive.
 * @param flags   Receive flags (MSG_*).
 */
void ior_prep_recv(
		ior_ctx *ctx, ior_sqe *sqe, ior_fd_t sockfd, void *buf, unsigned nbytes, int flags);

/**
 * Attach an opaque user-data pointer to an entry.
 *
 * The same pointer is returned by ior_cqe_get_data() on the operation's
 * completion, letting the caller correlate completions with their requests.
 *
 * @param ctx   I/O context.
 * @param sqe   Entry from ior_get_sqe().
 * @param data  Arbitrary user pointer.
 */
void ior_sqe_set_data(ior_ctx *ctx, ior_sqe *sqe, void *data);

/**
 * Set IOR_SQE_* flags on an entry (e.g. IOR_SQE_IO_LINK, IOR_SQE_IO_DRAIN).
 *
 * @param ctx    I/O context.
 * @param sqe    Entry from ior_get_sqe().
 * @param flags  Bitwise OR of IOR_SQE_* flags.
 */
void ior_sqe_set_flags(ior_ctx *ctx, ior_sqe *sqe, uint8_t flags);

/**
 * Retrieve the user data attached to a completion.
 *
 * @param ctx  I/O context.
 * @param cqe  A completion from peek/wait.
 * @return The user-data pointer set with ior_sqe_set_data() on the originating
 *         submission entry.
 */
void *ior_cqe_get_data(ior_ctx *ctx, ior_cqe *cqe);

/**
 * Retrieve the result of a completed operation.
 *
 * @param ctx  I/O context.
 * @param cqe  A completion from peek/wait.
 * @return A byte count (>= 0) for read/write/send/recv, 0 for a no-op, or a
 *         negative errno on failure (e.g. -ETIME for a timeout).
 */
int32_t ior_cqe_get_res(ior_ctx *ctx, ior_cqe *cqe);

/**
 * Retrieve the operation/backend-specific flags of a completion.
 *
 * @param ctx  I/O context.
 * @param cqe  A completion from peek/wait.
 * @return The completion flags (0 if none apply).
 */
uint32_t ior_cqe_get_flags(ior_ctx *ctx, ior_cqe *cqe);

/* Backend info */

/**
 * Query which backend a context is using.
 *
 * @param ctx  I/O context.
 * @return The backend selected for @p ctx.
 */
ior_backend_type ior_get_backend_type(ior_ctx *ctx);

/**
 * Get the human-readable name of the context's backend.
 *
 * @param ctx  I/O context.
 * @return A static backend name string (e.g. "io_uring", "threads", "iocp").
 */
const char *ior_get_backend_name(ior_ctx *ctx);

/**
 * Query the feature flags supported by the context's backend.
 *
 * @param ctx  I/O context.
 * @return A bitwise OR of the IOR_FEAT_* flags the active backend provides.
 */
uint32_t ior_get_features(ior_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* IOR_H */
