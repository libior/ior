# Test utilities
add_library(test_utils STATIC
    test_utils.c
)
target_include_directories(test_utils PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_utils PUBLIC ior cmocka::cmocka)

# Test executables
set(TESTS
    test_basic
    test_read_write
    test_timeout
    test_ring
    test_event
)

# Add test for splice only on Linux
if(IOR_PLATFORM_LINUX)
    list(APPEND TESTS test_splice)
endif()

foreach(test ${TESTS})
    add_executable(${test} ${test}.c)
    target_link_libraries(${test} PRIVATE test_utils ior cmocka::cmocka)
    
    # Add to CTest
    add_test(NAME ${test} COMMAND ${test})
    
    # Set timeout for tests
    set_tests_properties(${test} PROPERTIES TIMEOUT 30)
endforeach()

# Thread backend tests (always compiled)
add_executable(test_threads_backend test_threads_backend.c)
target_link_libraries(test_threads_backend PRIVATE test_utils ior cmocka::cmocka)
add_test(NAME test_threads_backend COMMAND test_threads_backend)
set_tests_properties(test_threads_backend PROPERTIES TIMEOUT 30)

# io_uring backend tests (only if available)
if(IOR_HAVE_URING)
    add_executable(test_uring_backend test_uring_backend.c)
    target_link_libraries(test_uring_backend PRIVATE test_utils ior cmocka::cmocka)
    add_test(NAME test_uring_backend COMMAND test_uring_backend)
    set_tests_properties(test_uring_backend PROPERTIES TIMEOUT 30)
endif()
