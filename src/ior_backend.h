/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef IOR_BACKEND_H
#define IOR_BACKEND_H

#include "ior.h"
#include "ior_log.h"

/* Backend-specific SQE structures */
#ifdef IOR_HAVE_URING
#include <liburing.h>

typedef struct ior_sqe_uring {
	struct io_uring_sqe sqe;
} ior_sqe_uring;

typedef struct ior_cqe_uring {
	__u64 user_data;
	__s32 res;
	__u32 flags;
	/* Reserve space for IORING_SETUP_CQE32 extension (16 bytes) */
	__u64 big_cqe[2];
} ior_cqe_uring;
#endif

/* Threads backend SQE/CQE */
typedef struct ior_sqe_threads {
	uint8_t opcode;
	uint8_t flags;
	uint16_t ioprio;
	int32_t fd;
	uint64_t off;
	uint64_t addr;
	uint32_t len;
	union {
		uint32_t rw_flags;
		uint32_t splice_flags;
		uint32_t timeout_flags;
	};
	uint64_t user_data;
	union {
		int32_t splice_fd_in;
		uint32_t file_index;
	};
	uint64_t splice_off_in;
	uint64_t __pad[2];
} ior_sqe_threads;

typedef struct ior_cqe_threads {
	uint64_t user_data;
	int32_t res;
	uint32_t flags;
} ior_cqe_threads;

/* IOCP backend SQE/CQE */
#ifdef IOR_HAVE_IOCP
typedef struct ior_sqe_iocp {
	uint8_t opcode;
	uint8_t flags;
	uint16_t ioprio;
	int32_t fd;
	uint64_t off;
	uint64_t addr;
	uint32_t len;
	union {
		uint32_t rw_flags;
		uint32_t timeout_flags;
	};
	uint64_t user_data;
	uint32_t file_index;
	uint64_t __pad[3];
} ior_sqe_iocp;

typedef struct ior_cqe_iocp {
	uint64_t user_data;
	int32_t res;
	uint32_t flags;
} ior_cqe_iocp;
#endif

/* Actual opaque type definitions - unions of all backend types */
struct ior_sqe {
	union {
#ifdef IOR_HAVE_URING
		ior_sqe_uring uring;
#endif
		ior_sqe_threads threads;
#ifdef IOR_HAVE_IOCP
		ior_sqe_iocp iocp;
#endif
	};
};

struct ior_cqe {
	union {
#ifdef IOR_HAVE_URING
		ior_cqe_uring uring;
#endif
		ior_cqe_threads threads;
#ifdef IOR_HAVE_IOCP
		ior_cqe_iocp iocp;
#endif
	};
};

/* Backend operations vtable */
typedef struct ior_backend_ops {
	/* Initialization and cleanup */
	int (*init)(void **backend_ctx, ior_params *params);
	void (*destroy)(void *backend_ctx);

	/* Submission queue operations */
	ior_sqe *(*get_sqe)(void *backend_ctx);
	int (*submit)(void *backend_ctx);
	int (*submit_and_wait)(void *backend_ctx, unsigned wait_nr);

	/* Completion queue operations */
	int (*peek_cqe)(void *backend_ctx, ior_cqe **cqe_out);
	int (*wait_cqe)(void *backend_ctx, ior_cqe **cqe_out);
	int (*wait_cqe_timeout)(void *backend_ctx, ior_cqe **cqe_out, ior_timespec *timeout);
	void (*cqe_seen)(void *backend_ctx, ior_cqe *cqe);
	unsigned (*peek_batch_cqe)(void *backend_ctx, ior_cqe **cqes, unsigned max);
	void (*cq_advance)(void *backend_ctx, unsigned nr);

	/* SQE preparation helpers */
	void (*prep_nop)(ior_sqe *sqe);
	void (*prep_read)(ior_sqe *sqe, int fd, void *buf, unsigned nbytes, uint64_t offset);
	void (*prep_write)(ior_sqe *sqe, int fd, const void *buf, unsigned nbytes, uint64_t offset);
	void (*prep_splice)(ior_sqe *sqe, int fd_in, uint64_t off_in, int fd_out, uint64_t off_out,
			unsigned nbytes, unsigned flags);
	void (*prep_timeout)(ior_sqe *sqe, ior_timespec *ts, unsigned count, unsigned flags);
	void (*sqe_set_data)(ior_sqe *sqe, void *data);
	void (*sqe_set_flags)(ior_sqe *sqe, uint8_t flags);

	/* CQE accessors */
	void *(*cqe_get_data)(ior_cqe *cqe);
	int32_t (*cqe_get_res)(ior_cqe *cqe);
	uint32_t (*cqe_get_flags)(ior_cqe *cqe);

	/* Backend info */
	const char *(*backend_name)(void);
	uint32_t (*get_features)(void *backend_ctx);
} ior_backend_ops;

/* Main context structure */
struct ior_ctx {
	const ior_backend_ops *ops;
	void *backend_ctx;
	ior_backend_type backend;
};

/* Backend registration */
#ifdef IOR_HAVE_URING
extern const ior_backend_ops ior_uring_ops;
#endif

extern const ior_backend_ops ior_threads_ops;

#ifdef IOR_HAVE_IOCP
extern const ior_backend_ops ior_iocp_ops;
#endif

#endif /* IOR_BACKEND_H */
