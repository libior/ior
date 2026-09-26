cmake_minimum_required(VERSION 3.15)
project(ior VERSION 0.1.0 LANGUAGES C)

# C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Set default build type if not specified.
# Note: for single-config generators (Make, Ninja) this picks the build type
# at configure time. For multi-config generators (Visual Studio, Ninja Multi-Config)
# it is ignored - the build type is chosen at build time via --config.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
	set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING
		"Choose the type of build: Debug Release RelWithDebInfo MinSizeRel" FORCE)
endif()

if(CMAKE_BUILD_TYPE)
	message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
else()
	message(STATUS "Build type: multi-config (set with --config at build time)")
endif()

# Sanitizer options
option(IOR_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(IOR_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(IOR_ENABLE_TSAN "Enable ThreadSanitizer" OFF)

# Compiler flags per build type
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
	# Common warning flags
	set(WARNING_FLAGS
		-Wall
		-Wextra
		-Wpedantic
		-Wno-unused-parameter
	)

	# Debug flags
	set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")

	# Release flags
	set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")

	# Release with debug info
	set(CMAKE_C_FLAGS_RELWITHDEBINFO "-g -O2 -DNDEBUG")

	# Minimum size release
	set(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG")

elseif(CMAKE_C_COMPILER_ID MATCHES "MSVC")
	# MSVC warning flags. /W4 is roughly -Wall -Wextra; /permissive- tightens
	# conformance. We deliberately do NOT use /WX (warnings-as-errors) by default.
	set(WARNING_FLAGS
		/W4
		/permissive-
	)

	# Quiet down some noisy CRT-deprecation warnings for portable POSIX-ish code.
	add_compile_definitions(_CRT_SECURE_NO_WARNINGS)

	# MSVC requires C11 mode plus an experimental flag to enable <stdatomic.h>.
	# /std:c11 is normally implied by CMAKE_C_STANDARD=11, but the atomics header
	# is gated behind /experimental:c11atomics (still required by MSVC 19.44 in
	# VS 2022 17.14 and 19.51 in VS 2026 18.10, under /std:c11, c17 and clatest
	# alike, because locking atomics are not yet complete). Without it,
	# <stdatomic.h> fails to compile. Note: MSVC still defines __STDC_NO_ATOMICS__ even with the
	# flag, so feature detection must compile a test program rather than check that
	# macro (see the atomics check below).
	add_compile_options(/experimental:c11atomics)
endif()

# Helper function to apply sanitizer flags to a target.
function(apply_sanitizers target)
	if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
		if(IOR_ENABLE_ASAN)
			target_compile_options(${target} PRIVATE -fsanitize=address)
			target_link_options(${target} PRIVATE -fsanitize=address)
		endif()

		if(IOR_ENABLE_UBSAN)
			target_compile_options(${target} PRIVATE -fsanitize=undefined)
			target_link_options(${target} PRIVATE -fsanitize=undefined)
		endif()

		if(IOR_ENABLE_TSAN)
			target_compile_options(${target} PRIVATE -fsanitize=thread)
			target_link_options(${target} PRIVATE -fsanitize=thread)
		endif()
	elseif(CMAKE_C_COMPILER_ID MATCHES "MSVC")
		# MSVC supports AddressSanitizer via /fsanitize=address.
		# It does NOT support UBSan or TSan; those options are ignored here.
		if(IOR_ENABLE_ASAN)
			target_compile_options(${target} PRIVATE /fsanitize=address)
			# MSVC ASan is incompatible with the /RTC runtime checks and with
			# incremental linking; CMake's Debug config may set these, so clear
			# RTC on this target and force /Od.
			target_compile_options(${target} PRIVATE /Od)
			# Incremental linking is silently ignored when ASAN metadata is
			# present (warning LNK4300). Disable it explicitly to keep the link
			# output clean.
			target_link_options(${target} PRIVATE /INCREMENTAL:NO)
		endif()
		if(IOR_ENABLE_UBSAN)
			message(WARNING "IOR_ENABLE_UBSAN has no effect with MSVC")
		endif()
		if(IOR_ENABLE_TSAN)
			message(WARNING "IOR_ENABLE_TSAN has no effect with MSVC")
		endif()
	endif()
	# For other compilers, this function does nothing.
endfunction()

# Build options
option(IOR_BUILD_TESTS "Build test programs" ON)
option(IOR_BUILD_BENCH "Build the ior_bench benchmark tool" ON)
option(IOR_WITH_URING "Build the io_uring backend on Linux if liburing 2.2+ is found" ON)
option(IOR_WITH_THREADS "Build the thread backend (on Linux the run-time fallback when io_uring is unusable)" ON)
option(IOR_FORCE_PIPE "Force pipe for thread event notification (testing)" OFF)
option(IOR_FORCE_POLL "Force poll() for the readiness poller even if epoll/kqueue is available (testing)" OFF)
option(IOR_ENABLE_LOG "Enable logging system" OFF)

if(IOR_ENABLE_LOG)
    set(IOR_HAVE_LOG TRUE)
    set(IOR_LOG_LEVEL "2" CACHE STRING
        "Default log level (0=TRACE, 1=DEBUG, 2=INFO, 3=WARN, 4=ERROR)")
    set_property(CACHE IOR_LOG_LEVEL PROPERTY STRINGS "0" "1" "2" "3" "4")

    if(IOR_LOG_LEVEL EQUAL 0)
        set(IOR_LOG_LEVEL_NAME "TRACE")
    elseif(IOR_LOG_LEVEL EQUAL 1)
        set(IOR_LOG_LEVEL_NAME "DEBUG")
    elseif(IOR_LOG_LEVEL EQUAL 2)
        set(IOR_LOG_LEVEL_NAME "INFO")
    elseif(IOR_LOG_LEVEL EQUAL 3)
        set(IOR_LOG_LEVEL_NAME "WARN")
    elseif(IOR_LOG_LEVEL EQUAL 4)
        set(IOR_LOG_LEVEL_NAME "ERROR")
    endif()

    message(STATUS "Logging enabled (level: ${IOR_LOG_LEVEL_NAME})")
else()
    message(STATUS "Logging disabled")
endif()

# Platform detection
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(IOR_PLATFORM_LINUX TRUE)
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    set(IOR_PLATFORM_FREEBSD TRUE)
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
    set(IOR_PLATFORM_OPENBSD TRUE)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(IOR_PLATFORM_MACOS TRUE)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(IOR_PLATFORM_WINDOWS TRUE)
endif()

# Check for C11 atomics (required)
include(CheckIncludeFile)

# On MSVC, <stdatomic.h> only compiles in C11 mode with the experimental flag.
# These configure-time checks (check_include_file / check_c_source_compiles) do
# not see add_compile_options(), so set the flags explicitly for them here.
if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
    set(CMAKE_REQUIRED_FLAGS "/std:c11 /experimental:c11atomics")
endif()

check_include_file("stdatomic.h" HAVE_STDATOMIC_H)
if(NOT HAVE_STDATOMIC_H)
    message(FATAL_ERROR "stdatomic.h not found - C11 atomics are required")
endif()

# Verify atomics actually work
include(CheckCSourceCompiles)

check_c_source_compiles("
    #include <stdatomic.h>
    int main(void) {
        _Atomic int x = 0;
        atomic_store_explicit(&x, 1, memory_order_release);
        int y = atomic_load_explicit(&x, memory_order_acquire);
        return y;
    }
" C11_ATOMICS_WORK)

if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
    unset(CMAKE_REQUIRED_FLAGS)
endif()

if(NOT C11_ATOMICS_WORK)
    message(FATAL_ERROR "C11 atomics don't work - check your compiler")
endif()

message(STATUS "C11 atomics available")

# Check for splice (Linux-specific)
set(IOR_HAVE_SPLICE FALSE)
if(IOR_PLATFORM_LINUX)
    check_c_source_compiles("
        #define _GNU_SOURCE
        #include <fcntl.h>
        #include <unistd.h>
        int main(void) {
            splice(0, NULL, 1, NULL, 0, 0);
            return 0;
        }
    " HAVE_SPLICE)

    if(HAVE_SPLICE)
        set(IOR_HAVE_SPLICE TRUE)
        message(STATUS "splice() available")
    endif()
endif()

# Check for accept4 (Linux, BSD); macOS emulates the flags
set(IOR_HAVE_ACCEPT4 FALSE)
if(NOT IOR_PLATFORM_WINDOWS)
    check_c_source_compiles("
        #define _GNU_SOURCE
        #include <sys/socket.h>
        int main(void) {
            return accept4(0, (struct sockaddr *) 0, (socklen_t *) 0, SOCK_NONBLOCK | SOCK_CLOEXEC) < 0;
        }
    " HAVE_ACCEPT4)
    if(HAVE_ACCEPT4)
        set(IOR_HAVE_ACCEPT4 TRUE)
        message(STATUS "accept4() available")
    endif()
endif()

# Check for preadv2/pwritev2 with RWF_NOWAIT (Linux 4.14+, glibc 2.26+): a
# read or write at the current position on a socket or pipe then reports
# -EAGAIN per call, and the thread backend need not touch the descriptor's
# blocking mode for it
set(IOR_HAVE_PREADV2 FALSE)
if(IOR_PLATFORM_LINUX)
    check_c_source_compiles("
        #define _GNU_SOURCE
        #include <sys/uio.h>
        int main(void) {
            struct iovec iov = { 0, 0 };
            return preadv2(0, &iov, 1, -1, RWF_NOWAIT) < 0 && pwritev2(1, &iov, 1, -1, RWF_NOWAIT) < 0;
        }
    " HAVE_PREADV2)
    if(HAVE_PREADV2)
        set(IOR_HAVE_PREADV2 TRUE)
        message(STATUS "preadv2()/pwritev2() with RWF_NOWAIT available")
    endif()
endif()

# Check for pidfd_open (Linux 5.3+): lets a wait for one child park on the
# poller instead of a worker; without it (or on an older kernel) the worker
# blocks in waitpid()
set(IOR_HAVE_PIDFD_OPEN FALSE)
if(IOR_PLATFORM_LINUX)
    check_c_source_compiles("
        #include <unistd.h>
        #include <sys/syscall.h>
        int main(void) {
            return (int) syscall(SYS_pidfd_open, 1, 0) < 0;
        }
    " HAVE_PIDFD_OPEN)
    if(HAVE_PIDFD_OPEN)
        set(IOR_HAVE_PIDFD_OPEN TRUE)
        message(STATUS "pidfd_open() available")
    endif()
endif()

# Check for sigtimedwait (POSIX.1b; macOS lacks it): lets a worker waiting for
# a signal notice a cancel or teardown between slices; without it the worker
# blocks in sigwait() until a signal of the set arrives
set(IOR_HAVE_SIGTIMEDWAIT FALSE)
if(NOT IOR_PLATFORM_WINDOWS)
    check_c_source_compiles("
        #include <signal.h>
        #include <time.h>
        int main(void) {
            sigset_t set;
            siginfo_t info;
            struct timespec ts = { 0, 0 };
            sigemptyset(&set);
            return sigtimedwait(&set, &info, &ts) < 0;
        }
    " HAVE_SIGTIMEDWAIT)
    if(HAVE_SIGTIMEDWAIT)
        set(IOR_HAVE_SIGTIMEDWAIT TRUE)
        message(STATUS "sigtimedwait() available")
    endif()
endif()

# Check for liburing on Linux
set(IOR_HAVE_URING FALSE)
set(IOR_HAVE_URING_WAITID FALSE)
set(IOR_URING_VERSION "unknown")

if(IOR_PLATFORM_LINUX AND IOR_WITH_URING)
    find_package(PkgConfig)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(LIBURING liburing)
        if(LIBURING_FOUND)
            set(IOR_URING_VERSION ${LIBURING_VERSION})
            message(STATUS "Found liburing: ${LIBURING_VERSION}")

            # Test if liburing actually works
            set(CMAKE_REQUIRED_INCLUDES ${LIBURING_INCLUDE_DIRS})
            set(CMAKE_REQUIRED_LIBRARIES ${LIBURING_LIBRARIES})

            check_c_source_compiles("
                #include <liburing.h>
                int main(void) {
                    struct io_uring ring;
                    struct io_uring_params params = {0};
                    io_uring_queue_init_params(32, &ring, &params);
                    io_uring_queue_exit(&ring);
                    return 0;
                }
            " LIBURING_WORKS)

            if(LIBURING_WORKS)
                message(STATUS "liburing is functional")

                # Work ops (IOR_OP_WORK) and cancel by descriptor
                # (ior_prep_cancel_fd) are mandatory API features; on the
                # io_uring backend they need IORING_OP_MSG_RING and
                # IORING_ASYNC_CANCEL_FD, so liburing 2.2+. The kernel (5.19+)
                # is checked at run time: the backend refuses an older one and
                # IOR_BACKEND_AUTO falls back to the thread backend.
                check_c_source_compiles("
                    #include <liburing.h>
                    int main(void) {
                        struct io_uring_sqe sqe;
                        io_uring_prep_msg_ring(&sqe, 0, 0, 0, 0);
                        io_uring_prep_cancel_fd(&sqe, 0, 0);
                        return IORING_FEAT_CQE_SKIP != 0 ? 0 : 1;
                    }
                " HAVE_URING_MSG_RING)

                if(HAVE_URING_MSG_RING)
                    set(IOR_HAVE_URING TRUE)

                    # IORING_OP_WAITID (kernel 6.7, liburing 2.5): a wait for
                    # any child, a process group or stop and continue reports
                    # without a thread, cancelled without reaping. Used when
                    # the kernel has it; sync cancel (6.0) retires such waits
                    # at teardown.
                    check_c_source_compiles("
                        #include <liburing.h>
                        int main(void) {
                            struct io_uring_sqe sqe;
                            siginfo_t info;
                            struct io_uring_sync_cancel_reg reg;
                            io_uring_prep_waitid(&sqe, P_ALL, 0, &info, WEXITED, 0);
                            (void) reg;
                            return IORING_OP_WAITID != 0 && io_uring_register_sync_cancel != 0 ? 0 : 1;
                        }
                    " HAVE_URING_WAITID)
                    if(HAVE_URING_WAITID)
                        set(IOR_HAVE_URING_WAITID TRUE)
                    endif()
                else()
                    message(STATUS "liburing lacks msg_ring/cancel_fd (needs 2.2+) - io_uring disabled")
                endif()
            else()
                message(WARNING "liburing found but doesn't compile/link properly - disabling")
            endif()

            unset(CMAKE_REQUIRED_INCLUDES)
            unset(CMAKE_REQUIRED_LIBRARIES)
        else()
            message(STATUS "liburing not found via pkg-config")
        endif()
    else()
        message(WARNING "pkg-config not found, cannot detect liburing")
    endif()

    if(NOT IOR_HAVE_URING)
        message(STATUS "io_uring support disabled")
    endif()
endif()

# Check for eventfd (only if we might need threads)
set(IOR_HAVE_EVENTFD FALSE)
if((IOR_PLATFORM_LINUX OR IOR_PLATFORM_FREEBSD) AND NOT IOR_FORCE_PIPE)
    check_c_source_compiles("
        #include <sys/eventfd.h>
        int main(void) {
            int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
            return fd >= 0 ? 0 : 1;
        }
    " HAVE_EVENTFD)

    if(HAVE_EVENTFD)
        if(IOR_PLATFORM_FREEBSD)
            # FreeBSD has eventfd since version 13
            if(CMAKE_SYSTEM_VERSION VERSION_GREATER_EQUAL "13.0")
                set(IOR_HAVE_EVENTFD TRUE)
                message(STATUS "eventfd available (FreeBSD 13+)")
            else()
                message(STATUS "eventfd not available (FreeBSD < 13)")
            endif()
        else()
            set(IOR_HAVE_EVENTFD TRUE)
            message(STATUS "eventfd available")
        endif()
    endif()
endif()

# Check for epoll (readiness poller for the thread backend)
set(IOR_HAVE_EPOLL FALSE)
if(IOR_PLATFORM_LINUX AND NOT IOR_FORCE_POLL)
    check_c_source_compiles("
        #include <sys/epoll.h>
        int main(void) {
            int fd = epoll_create1(EPOLL_CLOEXEC);
            return fd >= 0 ? 0 : 1;
        }
    " HAVE_EPOLL)

    if(HAVE_EPOLL)
        set(IOR_HAVE_EPOLL TRUE)
        message(STATUS "epoll available")
    endif()
endif()

# Check for kqueue (readiness poller on BSD/macOS)
set(IOR_HAVE_KQUEUE FALSE)
if((IOR_PLATFORM_FREEBSD OR IOR_PLATFORM_OPENBSD OR IOR_PLATFORM_MACOS) AND NOT IOR_FORCE_POLL)
    check_c_source_compiles("
        #include <sys/types.h>
        #include <sys/event.h>
        int main(void) {
            int kq = kqueue();
            return kq >= 0 ? 0 : 1;
        }
    " HAVE_KQUEUE)

    if(HAVE_KQUEUE)
        set(IOR_HAVE_KQUEUE TRUE)
        message(STATUS "kqueue available")
    endif()
endif()

# Check for Windows IOCP
set(IOR_HAVE_IOCP FALSE)
if(IOR_PLATFORM_WINDOWS)
    set(IOR_HAVE_IOCP TRUE)
    message(STATUS "Windows IOCP support enabled")
endif()

# Determine if thread backend is needed
set(IOR_HAVE_THREADS FALSE)

# Built unless disabled; elsewhere than Linux it is the only POSIX backend.
if(NOT IOR_PLATFORM_WINDOWS)
    if(IOR_WITH_THREADS OR NOT IOR_PLATFORM_LINUX)
        set(IOR_HAVE_THREADS TRUE)
    elseif(NOT IOR_HAVE_URING)
        message(FATAL_ERROR "IOR_WITH_THREADS=OFF needs the io_uring backend, which is not available")
    endif()
endif()
if(IOR_HAVE_URING AND IOR_HAVE_THREADS)
    message(STATUS "Both backends built; io_uring is the default with the thread backend as the fallback")
endif()

if(IOR_HAVE_THREADS)
    message(STATUS "Thread backend enabled")

    # Thread event notification implementation
    if(IOR_HAVE_EVENTFD)
        message(STATUS "Using eventfd for thread event notification")
    else()
        message(STATUS "Using pipe for thread event notification")
    endif()

    # Readiness poller implementation
    if(IOR_HAVE_EPOLL)
        message(STATUS "Using epoll for the readiness poller")
    elseif(IOR_HAVE_KQUEUE)
        message(STATUS "Using kqueue for the readiness poller")
    else()
        message(STATUS "Using poll for the readiness poller")
    endif()
else()
    message(STATUS "Thread backend disabled (not needed)")
endif()

# Generate config.h
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/config.h
)

# Add subdirectories
add_subdirectory(src)

# Tests
if(IOR_BUILD_TESTS)
    # Check for cmocka
    find_package(cmocka)
    if(cmocka_FOUND)
        enable_testing()
        add_subdirectory(tests)
    else()
        message(WARNING "cmocka not found - tests disabled")
    endif()
endif()

# Benchmark tool (no cmocka dependency; registers its own smoke CTest).
if(IOR_BUILD_BENCH)
    enable_testing()
    add_subdirectory(bench)
endif()

# Installation: the one public header, in include/ior; consumers include
# <ior.h> with that directory on the include path (ior.pc adds it).
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/ior.h
    DESTINATION include/ior
)

# pkg-config file (not meaningful on Windows/MSVC, but harmless to generate).
# A consumer of the static library links io_uring's dependency through
# `pkg-config --static`.
set(IOR_PC_REQUIRES_PRIVATE "")
if(IOR_HAVE_URING)
    set(IOR_PC_REQUIRES_PRIVATE "liburing")
endif()
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/ior.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/ior.pc
    @ONLY
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ior.pc
    DESTINATION lib/pkgconfig
)

# Print configuration summary
message(STATUS "")
message(STATUS "IOR Configuration Summary:")
message(STATUS "  Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "  C Compiler: ${CMAKE_C_COMPILER_ID}")
message(STATUS "")
message(STATUS "Backends:")
if(IOR_HAVE_URING)
    message(STATUS "  io_uring: TRUE (version ${IOR_URING_VERSION})")
else()
    message(STATUS "  io_uring: FALSE")
endif()
message(STATUS "  Threads:  ${IOR_HAVE_THREADS}")
if(IOR_PLATFORM_WINDOWS)
    message(STATUS "  IOCP:     ${IOR_HAVE_IOCP}")
endif()
message(STATUS "")
message(STATUS "Features:")
message(STATUS "  eventfd:     ${IOR_HAVE_EVENTFD}")
message(STATUS "  epoll:       ${IOR_HAVE_EPOLL}")
message(STATUS "  kqueue:      ${IOR_HAVE_KQUEUE}")
message(STATUS "  splice:      ${IOR_HAVE_SPLICE}")
message(STATUS "")
message(STATUS "Build Options:")
message(STATUS "  Tests:         ${IOR_BUILD_TESTS}")
message(STATUS "  With io_uring: ${IOR_WITH_URING}")
message(STATUS "  With threads:  ${IOR_WITH_THREADS}")
message(STATUS "  Force pipe:    ${IOR_FORCE_PIPE}")
message(STATUS "")
