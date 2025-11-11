#ifndef IOR_H
#define IOR_H

#include <stdint.h>
#include <time.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

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
#define IOR_SETUP_SQPOLL (1U << 0) // Submission queue polling (native only)
#define IOR_SETUP_IOPOLL (1U << 1) // IO polling (native only)
#define IOR_SETUP_DEFER (1U << 2) // Defer task work

/* Submission queue entry flags */
#define IOR_SQE_FIXED_FILE (1U << 0) // Use fixed file descriptor
#define IOR_SQE_IO_DRAIN (1U << 1) // Issue after previous completions
#define IOR_SQE_IO_LINK (1U << 2) // Link with next sqe
#define IOR_SQE_ASYNC (1U << 3) // Force async execution

/* Backend types */
typedef enum {
	IOR_BACKEND_AUTO = 0,
	IOR_BACKEND_IOURING, // Linux io_uring
	IOR_BACKEND_THREADS, // Thread pool emulation
	IOR_BACKEND_IORING, // Windows IORing (future)
	IOR_BACKEND_IOCP, // Windows IOCP (future)
} ior_backend_type;

/* Feature flags - what backend supports */
#define IOR_FEAT_NATIVE_ASYNC (1U << 0)
#define IOR_FEAT_SPLICE (1U << 1)
#define IOR_FEAT_FIXED_FILE (1U << 2)
#define IOR_FEAT_POLL_ADD (1U << 3)
#define IOR_FEAT_SQPOLL (1U << 4)

/* Forward declarations */
typedef struct ior_ctx ior_ctx;
typedef struct ior_params ior_params;
typedef struct ior_sqe ior_sqe; // Submission Queue Entry
typedef struct ior_cqe ior_cqe; // Completion Queue Entry

/* Setup parameters */
struct ior_params {
	uint32_t sq_entries; // Submission queue size
	uint32_t cq_entries; // Completion queue size (0 = auto)
	uint32_t flags; // Setup flags
	uint32_t sq_thread_cpu; // SQPOLL CPU affinity (native only)
	uint32_t sq_thread_idle; // SQPOLL idle timeout (native only)
	uint32_t features; // OUT: supported features
	ior_backend_type backend; // Preferred backend (IOR_BACKEND_AUTO = auto-detect)
};

/* Submission Queue Entry */
struct ior_sqe {
	uint8_t opcode; // Operation code
	uint8_t flags; // IOR_SQE_* flags
	uint16_t ioprio; // IO priority
	int32_t fd; // File descriptor
	union {
		uint64_t off; // Offset for read/write
		uint64_t addr2; // Secondary address
	};
	union {
		uint64_t addr; // Pointer to buffer (or splice fd_in for splice)
		uint64_t splice_off_in;
	};
	uint32_t len; // Buffer length (or splice fd_out for splice)
	union {
		uint32_t rw_flags; // Read/write flags
		uint32_t fsync_flags;
		uint32_t splice_flags;
		uint32_t timeout_flags;
	};
	uint64_t user_data; // User data passed through
	union {
		uint16_t buf_index; // Buffer ring index (for fixed buffers)
		uint16_t buf_group; // Buffer group ID
	};
	uint16_t personality; // Credentials (if FEAT_PERSONALITY)
	union {
		int32_t splice_fd_in;
		uint32_t file_index;
	};
	uint64_t __pad2[2]; // Future expansion
};

/* Completion Queue Entry */
struct ior_cqe {
	uint64_t user_data; // User data from sqe
	int32_t res; // Result code (bytes transferred or -errno)
	uint32_t flags; // Completion flags
};

/* Core API */

/**
 * Initialize a new ior queue with parameters
 * @param entries Number of submission queue entries
 * @param ctx_out Output pointer for context
 * @param params Queue parameters
 * @return 0 on success, negative error code on failure
 */
int ior_queue_init_params(unsigned entries, ior_ctx **ctx_out, ior_params *params);

/**
 * Initialize a new ior queue with default parameters
 * @param entries Number of submission queue entries
 * @param ctx_out Output pointer for context
 * @return 0 on success, negative error code on failure
 */
int ior_queue_init(unsigned entries, ior_ctx **ctx_out);

/**
 * Destroy an ior queue and free resources
 * @param ctx Queue context
 */
void ior_queue_exit(ior_ctx *ctx);

/* Submission operations */

/**
 * Get a submission queue entry for queuing an operation
 * @param ctx Queue context
 * @return Pointer to SQE, or NULL if queue is full
 */
ior_sqe *ior_get_sqe(ior_ctx *ctx);

/**
 * Submit all queued operations
 * @param ctx Queue context
 * @return Number of operations submitted, or negative error code
 */
int ior_submit(ior_ctx *ctx);

/**
 * Submit operations and wait for completions
 * @param ctx Queue context
 * @param wait_nr Number of completions to wait for
 * @return Number of operations submitted, or negative error code
 */
int ior_submit_and_wait(ior_ctx *ctx, unsigned wait_nr);

/* Completion operations */

/**
 * Peek at completion queue without blocking
 * @param ctx Queue context
 * @param cqe_out Output pointer for completion entry
 * @return 0 if completion available, -EAGAIN if none available
 */
int ior_peek_cqe(ior_ctx *ctx, ior_cqe **cqe_out);

/**
 * Wait for a completion (blocking)
 * @param ctx Queue context
 * @param cqe_out Output pointer for completion entry
 * @return 0 on success, negative error code on failure
 */
int ior_wait_cqe(ior_ctx *ctx, ior_cqe **cqe_out);

/**
 * Wait for a completion with timeout
 * @param ctx Queue context
 * @param cqe_out Output pointer for completion entry
 * @param timeout Timeout specification (NULL = infinite)
 * @return 0 on success, -ETIMEDOUT on timeout, negative error code on failure
 */
int ior_wait_cqe_timeout(ior_ctx *ctx, ior_cqe **cqe_out, struct timespec *timeout);

/**
 * Mark a completion entry as seen/consumed
 * @param ctx Queue context
 * @param cqe Completion entry to mark as seen
 */
void ior_cqe_seen(ior_ctx *ctx, ior_cqe *cqe);

/**
 * Peek at multiple completion entries
 * @param ctx Queue context
 * @param cqes Array of pointers to store completion entries
 * @param max Maximum number of entries to peek
 * @return Number of entries peeked
 */
unsigned ior_peek_batch_cqe(ior_ctx *ctx, ior_cqe **cqes, unsigned max);

/**
 * Advance completion queue head by multiple entries
 * @param ctx Queue context
 * @param nr Number of entries to advance
 */
void ior_cq_advance(ior_ctx *ctx, unsigned nr);

/* Helper functions for common operations */

static inline void ior_prep_nop(ior_sqe *sqe)
{
	sqe->opcode = IOR_OP_NOP;
	sqe->flags = 0;
	sqe->fd = -1;
}

static inline void ior_prep_read(ior_sqe *sqe, int fd, void *buf, unsigned nbytes, uint64_t offset)
{
	sqe->opcode = IOR_OP_READ;
	sqe->flags = 0;
	sqe->ioprio = 0;
	sqe->fd = fd;
	sqe->addr = (uint64_t) (uintptr_t) buf;
	sqe->len = nbytes;
	sqe->off = offset;
}

static inline void ior_prep_write(
		ior_sqe *sqe, int fd, const void *buf, unsigned nbytes, uint64_t offset)
{
	sqe->opcode = IOR_OP_WRITE;
	sqe->flags = 0;
	sqe->ioprio = 0;
	sqe->fd = fd;
	sqe->addr = (uint64_t) (uintptr_t) buf;
	sqe->len = nbytes;
	sqe->off = offset;
}

static inline void ior_prep_splice(ior_sqe *sqe, int fd_in, uint64_t off_in, int fd_out,
		uint64_t off_out, unsigned nbytes, unsigned splice_flags)
{
	sqe->opcode = IOR_OP_SPLICE;
	sqe->flags = 0;
	sqe->ioprio = 0;
	sqe->fd = fd_out;
	sqe->len = nbytes;
	sqe->off = off_out;
	sqe->addr = off_in;
	sqe->splice_fd_in = fd_in;
	sqe->splice_flags = splice_flags;
}

static inline void ior_prep_timeout(
		ior_sqe *sqe, struct timespec *ts, unsigned count, unsigned flags)
{
	sqe->opcode = IOR_OP_TIMER;
	sqe->flags = 0;
	sqe->ioprio = 0;
	sqe->fd = -1;
	sqe->addr = (uint64_t) (uintptr_t) ts;
	sqe->len = 1;
	sqe->off = count;
	sqe->timeout_flags = flags;
}

static inline void ior_sqe_set_data(ior_sqe *sqe, void *data)
{
	sqe->user_data = (uint64_t) (uintptr_t) data;
}

static inline void *ior_cqe_get_data(ior_cqe *cqe)
{
	return (void *) (uintptr_t) cqe->user_data;
}

static inline void ior_sqe_set_flags(ior_sqe *sqe, uint8_t flags)
{
	sqe->flags = flags;
}

/* Backend info */

/**
 * Get the backend type being used
 * @param ctx Queue context
 * @return Backend type
 */
ior_backend_type ior_get_backend_type(ior_ctx *ctx);

/**
 * Get the backend name as a string
 * @param ctx Queue context
 * @return Backend name string
 */
const char *ior_get_backend_name(ior_ctx *ctx);

/**
 * Get supported features bitmask
 * @param ctx Queue context
 * @return Feature flags (IOR_FEAT_*)
 */
uint32_t ior_get_features(ior_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* IOR_H */
