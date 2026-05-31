# IOR - I/O Ring Library

A cross-platform library providing an io_uring-like API for asynchronous I/O operations.

## Overview

IOR provides a unified, io_uring-compatible API that works across different platforms:

- **Linux**: Native io_uring support (when liburing is available), or thread pool emulation
- **FreeBSD/OpenBSD/macOS**: Thread pool emulation with optimized event notification
- **Windows**: Native IOCP (I/O Completion Ports) backend

The goal is to provide maximum performance on platforms with native async I/O support (like Linux's io_uring), while maintaining portability through efficient thread-based emulation on other platforms.

## Features

### Current (Stage 1)
- Read operations
- Write operations  
- Timer/timeout operations
- Splice operations (Linux)
- Operation chaining with `IOR_SQE_IO_LINK`
- Ordering with `IOR_SQE_IO_DRAIN`
- Thread pool emulation backend
- Linux io_uring backend (with liburing)
- Windows IOCP backend
- eventfd-based notification (Linux/FreeBSD 13+)
- Pipe-based notification fallback

### Planned (Stage 2)
- Accept operations
- Connect operations
- Bind operations
- Listen operations
- Additional io_uring operations

## Building

For detailed build instructions, options, and troubleshooting, see [BUILD.md](BUILD.md).

### Quick Start
```bash
# Clone and build
git clone https://github.com/yourusername/ior.git
cd ior
cmake -B build
cmake --build build

# Run tests
ctest --test-dir build --output-on-failure

# Install
sudo cmake --build build --target install
```

### Requirements

- CMake 3.15+
- C11 compiler (GCC, Clang, MSVC)
- POSIX threads (POSIX platforms)
- **Optional:** liburing (Linux), cmocka (tests)

## Usage

### Basic Example
```c
#include <ior/ior.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

int main() {
    // Initialize queue
    ior_ctx *ctx;
    if (ior_queue_init(32, &ctx) < 0) {
        perror("ior_queue_init");
        return 1;
    }
    
    printf("Using backend: %s\n", ior_get_backend_name(ctx));
    
    // Open file
    int fd = open("test.txt", O_RDONLY);
    if (fd < 0) {
        perror("open");
        ior_queue_exit(ctx);
        return 1;
    }
    
    // Prepare read operation
    char buffer[4096];
    ior_sqe *sqe = ior_get_sqe(ctx);
    if (!sqe) {
        fprintf(stderr, "Failed to get SQE\n");
        close(fd);
        ior_queue_exit(ctx);
        return 1;
    }
    
    ior_prep_read(ctx, sqe, fd, buffer, sizeof(buffer), 0);
    ior_sqe_set_data(ctx, sqe, NULL);
    
    // Submit and wait
    if (ior_submit(ctx) < 0) {
        perror("ior_submit");
        close(fd);
        ior_queue_exit(ctx);
        return 1;
    }
    
    // Wait for completion
    ior_cqe *cqe;
    if (ior_wait_cqe(ctx, &cqe) < 0) {
        perror("ior_wait_cqe");
        close(fd);
        ior_queue_exit(ctx);
        return 1;
    }
    
    int32_t res = ior_cqe_get_res(ctx, cqe);
    if (res < 0) {
        fprintf(stderr, "Read error: %d\n", res);
    } else {
        printf("Read %d bytes\n", res);
    }
    
    ior_cqe_seen(ctx, cqe);
    
    // Cleanup
    close(fd);
    ior_queue_exit(ctx);
    
    return 0;
}
```

> **Windows note:** `ior_fd_t` is a `HANDLE` on Windows, not an `int`. The IOCP
> backend issues overlapped `ReadFile`/`WriteFile`, so handles passed to
> `ior_prep_read`/`ior_prep_write` must be opened with `FILE_FLAG_OVERLAPPED`
> (e.g. via `CreateFile`). A CRT `_open()` descriptor will not work.

### Operation Chaining Example

Chain operations so they execute in order:

```c
// Write followed by read using IO_LINK
ior_sqe *write_sqe = ior_get_sqe(ctx);
ior_prep_write(ctx, write_sqe, fd, data, len, 0);
ior_sqe_set_data(ctx, write_sqe, (void*)1);
ior_sqe_set_flags(ctx, write_sqe, IOR_SQE_IO_LINK);  // Link to next

ior_sqe *read_sqe = ior_get_sqe(ctx);
ior_prep_read(ctx, read_sqe, fd, buffer, len, 0);
ior_sqe_set_data(ctx, read_sqe, (void*)2);

// Submit both - read only executes if write succeeds
ior_submit_and_wait(ctx, 2);

// Process completions in order
for (int i = 0; i < 2; i++) {
    ior_cqe *cqe;
    ior_wait_cqe(ctx, &cqe);
    // ... process ...
    ior_cqe_seen(ctx, cqe);
}
```

### Compile and Link
```bash
# Using pkg-config
gcc example.c $(pkg-config --cflags --libs ior) -o example

# Or manually
gcc example.c -I/usr/local/include -L/usr/local/lib -lior -lpthread -o example
```

## API Overview

### Queue Management
```c
// Initialize with default parameters
int ior_queue_init(unsigned entries, ior_ctx **ctx_out);

// Initialize with custom parameters
int ior_queue_init_params(unsigned entries, ior_ctx **ctx_out, ior_params *params);

// Cleanup and destroy queue
void ior_queue_exit(ior_ctx *ctx);
```

### Submission
```c
// Get a submission queue entry
ior_sqe *ior_get_sqe(ior_ctx *ctx);

// Submit all pending operations
int ior_submit(ior_ctx *ctx);

// Submit and wait for at least wait_nr completions
int ior_submit_and_wait(ior_ctx *ctx, unsigned wait_nr);
```

### Completion
```c
// Check for completion without blocking
int ior_peek_cqe(ior_ctx *ctx, ior_cqe **cqe_out);

// Wait for a completion (blocks)
int ior_wait_cqe(ior_ctx *ctx, ior_cqe **cqe_out);

// Wait with timeout
int ior_wait_cqe_timeout(ior_ctx *ctx, ior_cqe **cqe_out, ior_timespec *timeout);

// Mark completion as consumed (advances completion queue)
void ior_cqe_seen(ior_ctx *ctx, ior_cqe *cqe);

// Batch completion processing
unsigned ior_peek_batch_cqe(ior_ctx *ctx, ior_cqe **cqes, unsigned max);
void ior_cq_advance(ior_ctx *ctx, unsigned nr);
```

### Operation Preparation

All prep functions require the `ctx` parameter:

```c
// No-op operation
void ior_prep_nop(ior_ctx *ctx, ior_sqe *sqe);

// Read operation
void ior_prep_read(ior_ctx *ctx, ior_sqe *sqe, int fd, void *buf, 
                   unsigned nbytes, uint64_t offset);

// Write operation
void ior_prep_write(ior_ctx *ctx, ior_sqe *sqe, int fd, const void *buf,
                    unsigned nbytes, uint64_t offset);

// Timeout operation
void ior_prep_timeout(ior_ctx *ctx, ior_sqe *sqe, ior_timespec *ts,
                      unsigned count, unsigned flags);

// Splice operation (Linux only)
void ior_prep_splice(ior_ctx *ctx, ior_sqe *sqe, int fd_in, uint64_t off_in,
                     int fd_out, uint64_t off_out, unsigned nbytes, unsigned flags);
```

### SQE/CQE Accessors

```c
// Set user data (for identifying completions)
void ior_sqe_set_data(ior_ctx *ctx, ior_sqe *sqe, void *data);

// Set operation flags (IO_LINK, IO_DRAIN, etc.)
void ior_sqe_set_flags(ior_ctx *ctx, ior_sqe *sqe, uint8_t flags);

// Get user data from completion
void *ior_cqe_get_data(ior_ctx *ctx, ior_cqe *cqe);

// Get operation result (bytes transferred or negative errno)
int32_t ior_cqe_get_res(ior_ctx *ctx, ior_cqe *cqe);

// Get completion flags
uint32_t ior_cqe_get_flags(ior_ctx *ctx, ior_cqe *cqe);
```

### Backend Information
```c
// Get backend type
ior_backend_type ior_get_backend_type(ior_ctx *ctx);

// Get backend name as string
const char *ior_get_backend_name(ior_ctx *ctx);

// Get supported features
uint32_t ior_get_features(ior_ctx *ctx);
```

## API Design

### Opaque Types

IOR uses opaque types for `ior_ctx`, `ior_sqe`, and `ior_cqe`. This allows:
- Backend-specific implementations without exposing internals
- Binary compatibility across versions
- Clean separation between interface and implementation

All operations require passing the `ctx` parameter to route to the correct backend.

## Architecture

### Backends

IOR automatically selects the best available backend:

1. **io_uring** (Linux with liburing): Direct wrapper around liburing for maximum performance
2. **IOCP** (Windows): Native Windows I/O Completion Ports
3. **Threads** (all platforms): Thread pool with lock-free ring buffers and efficient event notification

### Thread Backend Design

The thread pool backend uses:
- Lock-free ring buffers for submission and completion queues
- Out-of-order completion support for maximum parallelism
- Operation chaining with `IOR_SQE_IO_LINK` flag
- Ordering guarantees with `IOR_SQE_IO_DRAIN` flag
- eventfd (Linux/FreeBSD 13+) or pipe-based notification
- Dynamic worker thread scaling
- Efficient work distribution and completion posting

### IOCP Backend Design

The Windows IOCP backend maps the io_uring submit/complete model onto an I/O
Completion Port:
- A single completion port receives packets for all operations
- Every operation - real I/O, NOPs, timers, errors, and cancellations - is
  funneled into the port as a completion packet and reaped through one path,
  so completions surface uniformly as CQEs
- Operations Windows has no native equivalent for (NOP, timers) are delivered
  via `PostQueuedCompletionStatus`
- A dedicated timer thread backed by a min-heap services timeout operations
- `IOR_SQE_IO_LINK` and `IOR_SQE_IO_DRAIN` are implemented in software on top
  of the port, matching io_uring ordering semantics
- Operations are drawn from a pre-allocated pool to avoid per-op allocation

> **Note:** The IOCP backend currently supports file I/O. Socket operations
> (accept/connect/send/recv) are part of Stage 2 and not yet wired up; plain
> read/write on a socket handle goes through the file path and is not yet
> recommended for sockets on Windows.

## Performance Considerations

- **Linux with io_uring**: Near-zero overhead wrapper, performance matches native io_uring
- **Windows IOCP**: Native completion-port I/O with a pre-allocated operation pool
- **Thread backend**: Optimized for throughput with batching support and lock-free data structures
- **Batch operations**: Use `ior_peek_batch_cqe()` and `ior_cq_advance()` for better efficiency when processing many completions
- **Operation chaining**: Use `IOR_SQE_IO_LINK` to chain operations without intermediate submissions