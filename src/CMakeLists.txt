# Source files - common
set(IOR_SOURCES
    ior.c
)

# Backend selection based on platform and availability
set(IOR_BACKEND_SOURCES)

# Linux io_uring backend
if(IOR_HAVE_URING)
    list(APPEND IOR_BACKEND_SOURCES
        ior_uring.c
    )
endif()

# Thread pool backend (all platforms)
list(APPEND IOR_BACKEND_SOURCES
    ior_threads.c
    ior_threads_ring.c
    ior_threads_pool.c
    ior_threads_event_common.c
)

# Thread event implementation
if(IOR_HAVE_EVENTFD)
    list(APPEND IOR_BACKEND_SOURCES
        ior_threads_event_eventfd.c
    )
else()
    list(APPEND IOR_BACKEND_SOURCES
        ior_threads_event_pipe.c
    )
endif()

# Windows IOCP backend
if(IOR_HAVE_IOCP)
    list(APPEND IOR_BACKEND_SOURCES
        ior_iocp.c
    )
endif()

# Create library
add_library(ior ${IOR_SOURCES} ${IOR_BACKEND_SOURCES})

# Include directories
target_include_directories(ior
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_BINARY_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Compiler flags
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
	target_compile_options(ior PRIVATE
		-Wall
		-Wextra
		-Wpedantic
		-Wno-unused-parameter
	)

	# Sanitizers
	if(IOR_ENABLE_ASAN)
		target_compile_options(ior PRIVATE -fsanitize=address)
		target_link_options(ior PRIVATE -fsanitize=address)
	endif()

	if(IOR_ENABLE_UBSAN)
		target_compile_options(ior PRIVATE -fsanitize=undefined)
		target_link_options(ior PRIVATE -fsanitize=undefined)
	endif()

	if(IOR_ENABLE_TSAN)
		target_compile_options(ior PRIVATE -fsanitize=thread)
		target_link_options(ior PRIVATE -fsanitize=thread)
	endif()
endif()

# Link libraries
if(IOR_HAVE_URING)
    target_include_directories(ior PRIVATE ${LIBURING_INCLUDE_DIRS})
    target_link_libraries(ior PRIVATE ${LIBURING_LIBRARIES})
endif()

# Platform-specific libraries
if(NOT IOR_PLATFORM_WINDOWS)
    target_link_libraries(ior PRIVATE pthread)
else()
    # Windows needs different libs
    target_link_libraries(ior PRIVATE ws2_32)
endif()

# Compiler flags
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(ior PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wno-unused-parameter
    )
endif()

# Installation
install(TARGETS ior
    EXPORT ior-targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)
