# ior_bench - benchmark / load tool for the ior library.

# Portable sources; the OS primitives live in one platform leaf compiled per OS.
set(BENCH_SOURCES
    ior_bench.c
    bench_metrics.c
    bench_trace.c
    scenario_socket.c
    scenario_file.c
    scenario_mixed.c
    scenario_work.c
)

if(WIN32)
    list(APPEND BENCH_SOURCES bench_platform_win.c)
else()
    list(APPEND BENCH_SOURCES bench_platform_posix.c)
endif()

add_executable(ior_bench ${BENCH_SOURCES})

target_include_directories(ior_bench PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}
)
target_link_libraries(ior_bench PRIVATE ior)

# Optional in-memory tracing for debugging hangs/anomalies (see bench_trace.h).
# Off by default so it adds zero overhead to normal benchmark runs.
option(IOR_BENCH_TRACE "Enable ior_bench in-memory tracing" OFF)
if(IOR_BENCH_TRACE)
    target_compile_definitions(ior_bench PRIVATE BENCH_TRACE=1)
endif()

if(WIN32)
    target_link_libraries(ior_bench PRIVATE ws2_32)
endif()

apply_sanitizers(ior_bench)

# Correctness-gated smoke run wired into CTest/CI. It exits non-zero on any
# correctness violation under load; throughput/latency are printed but not gated
# (machine-dependent). Generous timeout so it survives slow sanitizer builds.
if(IOR_BUILD_TESTS)
    add_test(NAME bench_smoke COMMAND ior_bench --smoke)
    set_tests_properties(bench_smoke PROPERTIES TIMEOUT 180)
endif()
