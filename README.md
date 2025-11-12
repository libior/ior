# IOR - I/O Ring Library

A cross-platform library providing an io_uring-like API for asynchronous I/O operations.

## Overview

IOR provides a unified, io_uring-compatible API that works across different platforms:

- **Linux**: Native io_uring support (when liburing is available), or thread pool emulation
- **FreeBSD/OpenBSD/macOS**: Thread pool emulation with optimized event notification
- **Windows**: IOCP backend (planned)

The goal is to provide maximum performance on platforms with native async I/O support (like Linux's io_uring), while maintaining portability through efficient thread-based emulation on other platforms.

## Features

### Current (Stage 1)
- Read operations
- Write operations  
- Timer/timeout operations
- Splice operations (Linux)
- Thread pool emulation backend
- Linux io_uring backend (with liburing)
- eventfd-based notification (Linux/FreeBSD 13+)
- Pipe-based notification fallback

### Planned (Stage 2)
- Accept operations
- Connect operations
- Bind operations
- Listen operations
- Windows IOCP backend
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
- POSIX threads
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
    
    ior_prep_read(sqe, fd, buffer, sizeof(buffer), 0);
    ior_sqe_set_data(sqe, NULL);
    
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
    
    if (cqe->res < 0) {
        fprintf(stderr, "Read error: %d\n", cqe->res);
    } else {
        printf("Read %d bytes\n", cqe->res);
    }
    
    ior_cqe_seen(ctx, cqe);
    
    // Cleanup
    close(fd);
    ior_queue_exit(ctx);
    
    return 0;
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
int ior_queue_init(unsigned entries, ior_ctx **ctx_out);
int ior_queue_init_params(unsigned entries, ior_ctx **ctx_out, ior_params *params);
void ior_queue_exit(ior_ctx *ctx);
```

### Submission
```c
ior_sqe *ior_get_sqe(ior_ctx *ctx);
int ior_submit(ior_ctx *ctx);
int ior_submit_and_wait(ior_ctx *ctx, unsigned wait_nr);
```

### Completion
```c
int ior_peek_cqe(ior_ctx *ctx, ior_cqe **cqe_out);
int ior_wait_cqe(ior_ctx *ctx, ior_cqe **cqe_out);
int ior_wait_cqe_timeout(ior_ctx *ctx, ior_cqe **cqe_out, ior_timespec *timeout);
void ior_cqe_seen(ior_ctx *ctx, ior_cqe *cqe);
```

### Helper Functions
```c
void ior_prep_read(ior_sqe *sqe, int fd, void *buf, unsigned nbytes, uint64_t offset);
void ior_prep_write(ior_sqe *sqe, int fd, const void *buf, unsigned nbytes, uint64_t offset);
void ior_prep_timeout(ior_sqe *sqe, ior_timespec *ts, unsigned count, unsigned flags);
void ior_prep_splice(ior_sqe *sqe, int fd_in, uint64_t off_in, int fd_out, uint64_t off_out, unsigned nbytes, unsigned splice_flags);
void ior_sqe_set_data(ior_sqe *sqe, void *data);
void *ior_cqe_get_data(ior_cqe *cqe);
```

## Architecture

### Backends

IOR automatically selects the best available backend:

1. **io_uring** (Linux with liburing): Direct wrapper around liburing for maximum performance
2. **Threads** (all platforms): Thread pool with lock-free ring buffers and efficient event notification
3. **IOCP** (Windows, planned): Native Windows I/O Completion Ports

### Thread Backend Design

The thread pool backend uses:
- Lock-free ring buffers for submission and completion queues
- eventfd (Linux/FreeBSD 13+) or pipe-based notification
- Configurable number of worker threads (defaults to CPU count)
- Efficient work distribution and completion posting

## Performance Considerations

- **Linux with io_uring**: Near-zero overhead wrapper, performance matches native io_uring
- **Thread backend**: Optimized for throughput with batching support
- **Queue sizing**: Larger queues reduce contention but use more memory
- **Batch operations**: Use `ior_peek_batch_cqe()` for better efficiency when processing many completions
