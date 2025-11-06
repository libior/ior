cmake_minimum_required(VERSION 3.15)
project(ior VERSION 0.1.0 LANGUAGES C)

# C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build options
option(IOR_BUILD_TESTS "Build test programs" ON)
option(IOR_WITH_URING "Enable io_uring support on Linux (requires liburing)" ON)
option(IOR_FORCE_PIPE "Force pipe for thread event notification (testing)" OFF)

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

# Check for liburing on Linux
set(IOR_HAVE_URING FALSE)
if(IOR_PLATFORM_LINUX AND IOR_WITH_URING)
    find_package(PkgConfig)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(LIBURING liburing)
        if(LIBURING_FOUND)
            set(IOR_HAVE_URING TRUE)
            message(STATUS "Found liburing: ${LIBURING_VERSION}")
        else()
            message(STATUS "liburing not found via pkg-config, trying manual search")
            # Try manual find
            find_path(LIBURING_INCLUDE_DIR liburing.h)
            find_library(LIBURING_LIBRARY uring)
            if(LIBURING_INCLUDE_DIR AND LIBURING_LIBRARY)
                set(IOR_HAVE_URING TRUE)
                set(LIBURING_INCLUDE_DIRS ${LIBURING_INCLUDE_DIR})
                set(LIBURING_LIBRARIES ${LIBURING_LIBRARY})
                message(STATUS "Found liburing manually")
            else()
                message(WARNING "liburing requested but not found - io_uring support disabled")
            endif()
        endif()
    else()
        message(WARNING "pkg-config not found, cannot detect liburing")
    endif()
endif()

# Check for eventfd
set(IOR_HAVE_EVENTFD FALSE)
if((IOR_PLATFORM_LINUX OR IOR_PLATFORM_FREEBSD) AND NOT IOR_FORCE_PIPE)
    include(CheckSymbolExists)
    check_symbol_exists(eventfd "sys/eventfd.h" HAVE_EVENTFD_HEADER)
    if(HAVE_EVENTFD_HEADER)
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

# Thread event notification implementation
if(IOR_HAVE_EVENTFD)
    message(STATUS "Using eventfd for thread event notification")
else()
    message(STATUS "Using pipe for thread event notification")
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
message(STATUS "  io_uring: ${IOR_HAVE_URING}")
message(STATUS "  Threads:  TRUE")
if(IOR_PLATFORM_WINDOWS)
    message(STATUS "  IOCP:     ${IOR_HAVE_IOCP}")
endif()
message(STATUS "")
message(STATUS "Features:")
message(STATUS "  eventfd:  ${IOR_HAVE_EVENTFD}")
message(STATUS "")
message(STATUS "Build Options:")
message(STATUS "  Tests:    ${IOR_BUILD_TESTS}")
message(STATUS "")
