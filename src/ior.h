/* SPDX-License-Identifier: BSD-3-Clause */
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
typedef HANDLE ior_fd_t;
#define IOR_INVALID_FD INVALID_HANDLE_VALUE
#else
typedef int ior_fd_t;
#define IOR_INVALID_FD (-1)
#endif

/**
 * Platform-independent timespec for async I/O operations
 *
 * This structure matches the layout of Linux's __kernel_timespec
 * which is required by io_uring and uses 64-bit fields on all platforms.
 *
 * Fields:
 *   tv_sec:  seconds (64-bit signed)
 *   tv_nsec: nanoseconds (long long for compatibility)
 */
typedef struct ior_timespec {
	int64_t tv_sec;
	long long tv_nsec;
} ior_timespec;

/* Operation codes */
#define IOR_OP_NOP 0
#define IOR_OP_READ 1
#define IOR_OP_WRITE 2
#define IOR_OP_TIMER 3
#define IOR_OP_SPLICE 4
// Stage 2:
#define IOR_OP_ACCEPT 5
#define IOR_OP_CONNECT 6
#define IOR_OP_LISTEN 7
#define IOR_OP_BIND 8
#define IOR_OP_SEND 9
#define IOR_OP_RECV 10

/* Setup flags */
#define IOR_SETUP_SQPOLL (1U << 0)
#define IOR_SETUP_IOPOLL (1U << 1)
#define IOR_SETUP_DEFER (1U << 2)

/* Submission queue entry flags */
#define IOR_SQE_FIXED_FILE (1U << 0)
#define IOR_SQE_IO_DRAIN (1U << 1)
#define IOR_SQE_IO_LINK (1U << 2)
#define IOR_SQE_ASYNC (1U << 3)

/* Backend types */
typedef enum {
	IOR_BACKEND_AUTO = 0,
	IOR_BACKEND_IOURING,
	IOR_BACKEND_THREADS,
	IOR_BACKEND_IOCP,
} ior_backend_type;

/* Feature flags */
#define IOR_FEAT_NATIVE_ASYNC (1U << 0)
#define IOR_FEAT_SPLICE (1U << 1)
#define IOR_FEAT_FIXED_FILE (1U << 2)
#define IOR_FEAT_POLL_ADD (1U << 3)
#define IOR_FEAT_SQPOLL (1U << 4)

/*
 * Sentinel offset meaning "no offset / use the file description's current
 * position." For read/write this selects read()/write() semantics over the
 * positioned pread()/pwrite() (required for non-seekable fds such as sockets
 * and pipes). For splice it marks an unused in/out offset. Equal to
 * (uint64_t)-1, matching io_uring's convention for an absent offset.
 */
#define IOR_OFF_NONE ((uint64_t) -1)

/* Forward declarations - OPAQUE TYPES */
typedef struct ior_ctx ior_ctx;
typedef struct ior_sqe ior_sqe;
typedef struct ior_cqe ior_cqe;

typedef struct ior_params ior_params;

/* Setup parameters */
struct ior_params {
	uint32_t sq_entries;
	uint32_t cq_entries;
	uint32_t flags;
	uint32_t sq_thread_cpu;
	uint32_t sq_thread_idle;
	uint32_t features; // OUT
	ior_backend_type backend;
};

/* Core API */
int ior_queue_init_params(unsigned entries, ior_ctx **ctx_out, ior_params *params);
int ior_queue_init(unsigned entries, ior_ctx **ctx_out);
void ior_queue_exit(ior_ctx *ctx);

/* Submission */
ior_sqe *ior_get_sqe(ior_ctx *ctx);
int ior_submit(ior_ctx *ctx);
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

/* Helper functions - work on opaque types via callbacks */
void ior_prep_nop(ior_ctx *ctx, ior_sqe *sqe);
void ior_prep_read(
		ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd, void *buf, unsigned nbytes, uint64_t offset);
void ior_prep_write(
		ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd, const void *buf, unsigned nbytes, uint64_t offset);
void ior_prep_splice(ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd_in, uint64_t off_in, ior_fd_t fd_out,
		uint64_t off_out, unsigned nbytes, unsigned flags);
void ior_prep_timeout(ior_ctx *ctx, ior_sqe *sqe, ior_timespec *ts, unsigned count, unsigned flags);
void ior_prep_send(
		ior_ctx *ctx, ior_sqe *sqe, ior_fd_t sockfd, const void *buf, unsigned nbytes, int flags);
void ior_prep_recv(
		ior_ctx *ctx, ior_sqe *sqe, ior_fd_t sockfd, void *buf, unsigned nbytes, int flags);

void ior_sqe_set_data(ior_ctx *ctx, ior_sqe *sqe, void *data);
void ior_sqe_set_flags(ior_ctx *ctx, ior_sqe *sqe, uint8_t flags);

void *ior_cqe_get_data(ior_ctx *ctx, ior_cqe *cqe);
int32_t ior_cqe_get_res(ior_ctx *ctx, ior_cqe *cqe);
uint32_t ior_cqe_get_flags(ior_ctx *ctx, ior_cqe *cqe);

/* Backend info */
ior_backend_type ior_get_backend_type(ior_ctx *ctx);
const char *ior_get_backend_name(ior_ctx *ctx);
uint32_t ior_get_features(ior_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* IOR_H */
