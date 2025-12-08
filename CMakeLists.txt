cmake_minimum_required(VERSION 3.15)
project(ior VERSION 0.1.0 LANGUAGES C)

# C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Set default build type if not specified
if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING
		"Choose the type of build: Debug Release RelWithDebInfo MinSizeRel" FORCE)
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

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

	# Add sanitizers option for debug builds
	option(IOR_ENABLE_ASAN "Enable AddressSanitizer" OFF)
	option(IOR_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
	option(IOR_ENABLE_TSAN "Enable ThreadSanitizer" OFF)
endif()

# Helper function to apply sanitizer flags to a target
# Define unconditionally so it can always be called
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
	endif()
	# For other compilers, this function does nothing
endfunction()

# Build options
option(IOR_BUILD_TESTS "Build test programs" ON)
option(IOR_WITH_URING "Enable io_uring support on Linux (requires liburing)" ON)
option(IOR_FORCE_THREADS "Force thread backend even if io_uring available (testing)" OFF)
option(IOR_FORCE_PIPE "Force pipe for thread event notification (testing)" OFF)
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

check_include_file("stdatomic.h" HAVE_STDATOMIC_H)
if(NOT HAVE_STDATOMIC_H)
    message(FATAL_ERROR "stdatomic.h not found - C11 atomics are required")
endif()

# Verify atomics actually work
include(CheckCSourceCompiles)
check_c_source_compiles("
    #include <stdatomic.h>
    int main() {
        _Atomic int x = 0;
        atomic_store_explicit(&x, 1, memory_order_release);
        int y = atomic_load_explicit(&x, memory_order_acquire);
        return y;
    }
" C11_ATOMICS_WORK)

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
        int main() {
            splice(0, NULL, 1, NULL, 0, 0);
            return 0;
        }
    " HAVE_SPLICE)

    if(HAVE_SPLICE)
        set(IOR_HAVE_SPLICE TRUE)
        message(STATUS "splice() available")
    endif()
endif()

# Check for liburing on Linux
set(IOR_HAVE_URING FALSE)
set(IOR_URING_VERSION "unknown")

if(IOR_PLATFORM_LINUX AND IOR_WITH_URING AND NOT IOR_FORCE_THREADS)
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
                int main() {
                    struct io_uring ring;
                    struct io_uring_params params = {0};
                    io_uring_queue_init_params(32, &ring, &params);
                    io_uring_queue_exit(&ring);
                    return 0;
                }
            " LIBURING_WORKS)

            if(LIBURING_WORKS)
                set(IOR_HAVE_URING TRUE)
                message(STATUS "liburing is functional")
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
        message(STATUS "io_uring support disabled - will use thread backend")
    endif()
elseif(IOR_FORCE_THREADS)
    message(STATUS "Forcing thread backend (IOR_FORCE_THREADS=ON)")
endif()

# Check for eventfd (only if we might need threads)
set(IOR_HAVE_EVENTFD FALSE)
if((IOR_PLATFORM_LINUX OR IOR_PLATFORM_FREEBSD) AND NOT IOR_FORCE_PIPE)
    check_c_source_compiles("
        #include <sys/eventfd.h>
        int main() {
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

# Check for Windows IOCP
set(IOR_HAVE_IOCP FALSE)
if(IOR_PLATFORM_WINDOWS)
    set(IOR_HAVE_IOCP TRUE)
    message(STATUS "Windows IOCP support enabled")
endif()

# Determine if thread backend is needed
set(IOR_HAVE_THREADS FALSE)

if(NOT IOR_PLATFORM_WINDOWS)
    if(NOT IOR_HAVE_URING OR IOR_FORCE_THREADS)
        set(IOR_HAVE_THREADS TRUE)
    endif()
endif()

if(IOR_HAVE_THREADS)
    message(STATUS "Thread backend enabled")

    # Thread event notification implementation
    if(IOR_HAVE_EVENTFD)
        message(STATUS "Using eventfd for thread event notification")
    else()
        message(STATUS "Using pipe for thread event notification")
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

# Installation
install(DIRECTORY include/
    DESTINATION include
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/config.h
    DESTINATION include/ior
)

# pkg-config file
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
message(STATUS "  splice:      ${IOR_HAVE_SPLICE}")
message(STATUS "")
message(STATUS "Build Options:")
message(STATUS "  Tests:         ${IOR_BUILD_TESTS}")
message(STATUS "  Force threads: ${IOR_FORCE_THREADS}")
message(STATUS "  Force pipe:    ${IOR_FORCE_PIPE}")
message(STATUS "")
