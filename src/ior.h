/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef IOR_H
#define IOR_H

#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
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

#define IOR_SPLICE_OFF_NONE ((uint64_t)-1)

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

/* Completion */
int ior_peek_cqe(ior_ctx *ctx, ior_cqe **cqe_out);
int ior_wait_cqe(ior_ctx *ctx, ior_cqe **cqe_out);
int ior_wait_cqe_timeout(ior_ctx *ctx, ior_cqe **cqe_out, ior_timespec *timeout);
void ior_cqe_seen(ior_ctx *ctx, ior_cqe *cqe);
unsigned ior_peek_batch_cqe(ior_ctx *ctx, ior_cqe **cqes, unsigned max);
void ior_cq_advance(ior_ctx *ctx, unsigned nr);

/* Helper functions - work on opaque types via callbacks */
void ior_prep_nop(ior_ctx *ctx, ior_sqe *sqe);
void ior_prep_read(ior_ctx *ctx, ior_sqe *sqe, int fd, void *buf, unsigned nbytes, uint64_t offset);
void ior_prep_write(
		ior_ctx *ctx, ior_sqe *sqe, int fd, const void *buf, unsigned nbytes, uint64_t offset);
void ior_prep_splice(ior_ctx *ctx, ior_sqe *sqe, int fd_in, uint64_t off_in, int fd_out,
		uint64_t off_out, unsigned nbytes, unsigned flags);
void ior_prep_timeout(ior_ctx *ctx, ior_sqe *sqe, ior_timespec *ts, unsigned count, unsigned flags);

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
