# IOR - I / O Ring Library

A cross-platform library providing an io_uring-like API for asynchronous I/O operations.

## Overview

IOR provides a unified, io_uring-compatible API that works across different platforms:

- **Linux**: Native io_uring support (when liburing is available), or thread pool emulation
- **FreeBSD/OpenBSD/macOS**: Thread pool emulation with optimized event notification
- **Windows**: Native IOCP (I/O Completion Ports) backend

The goal is to provide maximum performance on platforms with native async I/O support (like Linux's io_uring), while maintaining portability through efficient thread-based emulation on other platforms.

## Features

- Read and write operations
- Socket send and receive operations
- Socket accept and connect operations (`ior_prep_accept`,
  `ior_prep_connect`), readiness-driven on the thread pool and through
  AcceptEx/ConnectEx on Windows
- Timer/timeout operations, relative or absolute on the monotonic, boot-time
  or wall clock (`IOR_TIMEOUT_ABS`, `IOR_TIMEOUT_BOOTTIME`,
  `IOR_TIMEOUT_REALTIME`); the timespec is copied at submit on every backend
- Readiness polling (`ior_prep_poll_add`), one-shot or multishot
  (`ior_prep_poll_multishot`): a persistent poll posts one completion per
  readiness edge, flagged `IOR_CQE_F_MORE`, until cancelled -
  `IORING_POLL_ADD_MULTI` on io_uring, an edge-triggered watch (`EPOLLET`,
  `EV_CLEAR`) on the thread pool's poller, the WSAPoll readiness emulation on
  Windows
- Process waits (`ior_prep_waitpid`): `IORING_OP_WAITID` on io_uring (Linux
  6.7, else a pidfd poll), a parked op on the thread pool's poller (pidfd or
  `EVFILT_PROC`), a threadpool wait on the process handle on Windows; what
  nothing can watch (any child, a process group, stop and continue reports)
  is probed from a timer, so no wait holds a thread
- Signal waits (`ior_prep_sigwait`): a signalfd poll on io_uring, a worker
  in `sigtimedwait` on the thread pool, the console control events
  (`SIGINT`, `SIGBREAK`) on Windows
- Async cancellation of submitted operations (`ior_prep_cancel`,
  `ior_prep_cancel_fd`), with io_uring semantics on every backend
- A completion notification descriptor (`ior_notify_fd`) for embedding a
  context in an existing event loop: an eventfd on io_uring and the threads
  backend, a loopback socket on Windows
- Splice operations (native on Linux, emulated elsewhere)
- Operation chaining with `IOR_SQE_IO_LINK`
- Ordering with `IOR_SQE_IO_DRAIN`
- Three backends with a uniform API:
  - Linux io_uring (via liburing)
  - Windows IOCP
  - Portable thread-pool fallback (all other platforms)
- eventfd-based completion notification (Linux/FreeBSD 13+), with a pipe-based fallback

## Building

For detailed build instructions, options, and troubleshooting, see [BUILD.md](BUILD.md).

### Quick Start
```bash
#Clone and build
git clone https://github.com/yourusername/ior.git
cd ior
cmake -B build
cmake --build build

#Run tests
ctest --test-dir build --output-on-failure

#Install
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
#include <ior.h>
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
#Using pkg - config
gcc example.c $(pkg-config --cflags --libs ior) -o example

#Or manually
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
// Get a submission queue entry (NULL if none is available)
ior_sqe *ior_get_sqe(ior_ctx *ctx);

// The same, telling a full submission queue (-ENOSPC: submit) from a full
// completion queue (-EBUSY: reap)
int ior_get_sqe_ex(ior_ctx *ctx, ior_sqe **sqe_out);

// Submit all pending operations, with io_uring semantics on every backend:
// an entry io_uring refuses (e.g. a negative timespec) fails its chain and
// submission stops after it, leaving the rest staged for the next submit.
// Waiting never submits.
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

// Send operation (socket)
void ior_prep_send(ior_ctx *ctx, ior_sqe *sqe, int sockfd, const void *buf,
                   unsigned nbytes, int flags);

// Receive operation (socket)
void ior_prep_recv(ior_ctx *ctx, ior_sqe *sqe, int sockfd, void *buf,
                   unsigned nbytes, int flags);

// Accept a connection: completes with the new socket (a SOCKET cast to
// int32 on Windows), filling addr/addrlen like accept(2); flags are
// IOR_ACCEPT_NONBLOCK / IOR_ACCEPT_CLOEXEC for the accepted socket.
void ior_prep_accept(ior_ctx *ctx, ior_sqe *sqe, int fd, struct sockaddr *addr,
                     socklen_t *addrlen, unsigned flags);

// Connect a socket: completes with 0 or a negative errno.
void ior_prep_connect(ior_ctx *ctx, ior_sqe *sqe, int fd,
                      const struct sockaddr *addr, socklen_t addrlen);

// Timeout operation: ts is a relative duration, or with IOR_TIMEOUT_ABS an
// absolute deadline on the monotonic clock (IOR_TIMEOUT_BOOTTIME and
// IOR_TIMEOUT_REALTIME select the boot-time or wall clock instead). ts is
// read by the submit that takes the entry, so it may live on the stack until
// that submit returns.
void ior_prep_timeout(ior_ctx *ctx, ior_sqe *sqe, ior_timespec *ts,
                      unsigned count, unsigned flags);

// Wait for fd readiness: completes with the ready IOR_POLL_* mask. The
// one-shot form completes once; the multishot form stays armed and posts a
// completion per readiness edge with IOR_CQE_F_MORE in its flags, its last
// one (a cancel's -ECANCELED, an error) without it. Consume readiness fully
// after each completion, as with EPOLLET.
void ior_prep_poll_add(ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd, uint32_t poll_mask);
void ior_prep_poll_multishot(ior_ctx *ctx, ior_sqe *sqe, ior_fd_t fd, uint32_t poll_mask);

// Wait for a process like waitpid(2): completes with its pid, the wait
// status in *status (the exit code on Windows), or -ECHILD. No wait holds a
// thread: a cancel or a link timeout takes it back without reaping, and
// ior_queue_exit() does not wait for the child. -1, a process group and
// WUNTRACED/WCONTINUED are probed every 1-20 ms where the kernel cannot wait
// for them (io_uring before Linux 6.7, the thread pool). Windows takes only
// pid > 0.
int ior_prep_waitpid(ior_ctx *ctx, ior_sqe *sqe, ior_pid_t pid, int *status,
                     int options);

// Wait for a signal of the set like sigwaitinfo(2): completes with its
// number, the details in *info. The signals must be blocked in every
// thread; ior's own threads block everything already. io_uring polls a
// signalfd (cancellable, no thread; -EAGAIN if another wait took the
// signal first), the thread pool holds a worker in sigtimedwait slices
// (a cancel reports -EALREADY, the op then ends -ECANCELED). Windows
// accepts SIGINT and SIGBREAK only, the console control events.
int ior_prep_sigwait(ior_ctx *ctx, ior_sqe *sqe, const ior_sigset_t *set,
                     ior_siginfo_t *info);

// Portable signal sets: sigset_t/siginfo_t on POSIX, a bitmask of CRT
// signal numbers and a {si_signo, si_code} pair on Windows.
int ior_sigemptyset(ior_sigset_t *set);
int ior_sigaddset(ior_sigset_t *set, int signo);
int ior_sigismember(const ior_sigset_t *set, int signo);

// Splice operation (Linux only)
void ior_prep_splice(ior_ctx *ctx, ior_sqe *sqe, int fd_in, uint64_t off_in,
                     int fd_out, uint64_t off_out, unsigned nbytes, unsigned flags);

// Cancel a submitted operation by its user data, or one operation on a
// descriptor (repeat until -ENOENT to cancel all of them). The cancel
// completes with 0 (found and cancelled), -ENOENT (nothing in flight) or
// -EALREADY (running, cannot be interrupted); the target completes with
// -ECANCELED, as do its link timeout and the rest of its link chain.
void ior_prep_cancel(ior_ctx *ctx, ior_sqe *sqe, void *user_data);
void ior_prep_cancel_fd(ior_ctx *ctx, ior_sqe *sqe, int fd);
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

### Completion Notification
```c
// Descriptor readable once completions are posted, like io_uring's
// registered eventfd: wait on it in your own loop, clear it, then reap
// with ior_peek_cqe() until -EAGAIN. Owned by the context.
//
// Clear before reaping, not after: a completion is posted before its
// signal, so clearing afterwards can drain the signal of one that landed
// while you were reaping, leaving it unreaped with the descriptor idle.
// Then reap until the queue is empty - a clear consumes every pending
// signal, so anything left over is not announced again.
ior_fd_t ior_notify_fd(ior_ctx *ctx);
int ior_notify_clear(ior_ctx *ctx);
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

With `IOR_BACKEND_AUTO` the best backend built in is used, unless the
`IOR_BACKEND` environment variable names one (`io_uring`, `threads`, `iocp`);
a name that is unknown or not built in fails init with `-ENOSYS`. On Linux
both backends are built by default and AUTO falls back from io_uring to
threads when io_uring is unusable (old kernel, sysctl, seccomp); an explicit
choice never falls back. See [BUILD.md](BUILD.md).

### Queue Capacity
```c
// Sizes the backend settled on (also written back to ior_params by init)
unsigned ior_sq_entries(ior_ctx *ctx);
unsigned ior_cq_entries(ior_ctx *ctx);

// Entries free right now
unsigned ior_sq_space_left(ior_ctx *ctx);
unsigned ior_cq_space_left(ior_ctx *ctx);
```

Every backend rounds the requested sizes up to a power of two (the thread
and IOCP backends raise the submission queue to at least 32, the thread
backend the completion queue too) and defaults the completion queue to twice
the submission queue. Init writes the sizes used back to `ior_params`, so
reset `sq_entries` and `cq_entries` before reusing the same `ior_params` for
another context, or the first one's sizes carry over. `ior_get_sqe()` refuses an entry for one of two reasons,
which `ior_get_sqe_ex()` tells apart: the submission queue holds
`ior_sq_entries()` entries not yet submitted (`-ENOSPC`, so submit), or no
completion queue slot is free for the operation's completion (`-EBUSY`, so
reap). When a slot counts as taken differs per backend: on io_uring only a
completion posted and not yet reaped takes one, the kernel buffering any
overflow; the thread and IOCP backends never post into a full queue, so a
slot is taken by `ior_get_sqe()` itself and held until the completion is
reaped, plus one per multishot poll edge, which makes `ior_cq_entries()` the
bound on operations in flight there (a completion queue set smaller than the
submission queue limits even a single batch). A caller that counts operations in
flight plus completions unreaped against `ior_cq_entries()` has the same
bound on every backend.

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
- A single readiness poller thread (epoll/kqueue/poll) that parks
  read/write/send/recv on pollable descriptors, so workers never block on a
  socket, non-blocking descriptors never spin on `EAGAIN`, and pending
  operations stay cancellable. A descriptor it cannot ask for a non-blocking
  attempt per call has its mode taken over for the op and restored after
  (see below). It also parks a wait for one child there (a pidfd on Linux,
  `EVFILT_PROC` on kqueue)
- Operation chaining with `IOR_SQE_IO_LINK` flag
- Ordering guarantees with `IOR_SQE_IO_DRAIN` flag
- eventfd (Linux/FreeBSD 13+) or pipe-based notification
- Dynamic worker thread scaling
- Efficient work distribution and completion posting

#### Descriptor blocking mode

A descriptor comes back from ior in the mode it went in. The thread backend
never waits in a worker for a pollable descriptor: an op that would block
parks on the poller instead, which needs a syscall that reports rather than
waits. It gets one in this order:

1. A per-call non-blocking form, where the kernel has one: `MSG_DONTWAIT` for
   `send`/`recv`, and `RWF_NOWAIT` through `preadv2()`/`pwritev2()` for a
   `read`/`write` at the current position on Linux, which sockets, pipes and
   eventfds honour. The descriptor is not touched.
2. Otherwise the descriptor's own mode, taken over for the op: `accept` and
   `connect` everywhere, `read`/`write` at the current position elsewhere than
   Linux or on a descriptor the kernel refuses `RWF_NOWAIT` for (a tty), and
   `send` on macOS, whose `sosend()` ignores `MSG_DONTWAIT`. The first such op
   on a blocking descriptor looks at its flags and switches it (`fcntl` plus
   `ioctl`); ops in flight on the same descriptor share that one switch, and
   the last of them to complete, cancelled or not, restores the mode before
   its completion is posted. A descriptor you keep non-blocking yourself is
   never switched or restored.
3. A regular file needs neither: `RWF_NOWAIT` refusing a buffered write, or
   reporting uncached data, sends the plain syscall to the worker, where it
   runs to completion as on io_uring's worker queue.

Taking the mode over is what lets a worker run a write without waiting.
Readiness alone cannot: `poll()` promises only `SO_SNDLOWAT` bytes of room,
while a blocking write does not return until all of `len` is queued, so a
write larger than the free space would wait however ready the descriptor
looked. As on io_uring, a send or write may therefore complete short; callers
must handle a partial result and submit the remainder. io_uring issues socket
ops non-blocking in the kernel and needs no descriptor change; IOCP uses
overlapped I/O and needs none either.

Two things stay with the caller. While an op of the second kind is in flight,
a synchronous `read()` or `send()` of your own on that descriptor sees
non-blocking mode, as does any other process sharing the open file
description. And the switch is tracked by descriptor number, so close a
descriptor only once its ops have completed (cancel them first): a number
reused meanwhile would be restored in its place, and two numbers for one
open file description (`dup()`) are two switches, restored independently.

If your descriptors are non-blocking already - as they are when you pre-poll
them yourself - pass `IOR_SETUP_FD_NONBLOCK` at setup and the backend skips
the look, the switch and the restore entirely:

```c
ior_params params = { .flags = IOR_SETUP_FD_NONBLOCK };
ior_queue_init_params(256, &ctx, &params);
```

The promise must hold for every descriptor submitted to that context. An
operation on one that does block occupies its worker thread until it
completes, and cannot be cancelled meanwhile.

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
- Operations are drawn from a pre-allocated pool the size of the completion
  queue, held from `ior_get_sqe()` until the completion is reaped, so the
  completion queue also bounds the operations in flight

> **Note:** On the IOCP backend, file I/O uses `ReadFile`/`WriteFile` and socket
> send/receive use `WSASend`/`WSARecv`. For sockets on Windows, prefer
> `ior_prep_send`/`ior_prep_recv` over plain read/write.

## Performance Considerations

- **Linux with io_uring**: Near-zero overhead wrapper, performance matches native io_uring
- **Windows IOCP**: Native completion-port I/O with a pre-allocated operation pool
- **Thread backend**: Optimized for throughput with batching support and lock-free data structures
- **Batch operations**: Use `ior_peek_batch_cqe()` and `ior_cq_advance()` for better efficiency when processing many completions
- **Operation chaining**: Use `IOR_SQE_IO_LINK` to chain operations without intermediate submissions
