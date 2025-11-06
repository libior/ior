/* SPDX-License-Identifier: BSD-3-Clause */
#include "test_utils.h"

// Test forcing threads backend
static void test_threads_backend(void **state) {
    (void)state;
    
    ior_ctx *ctx;
    ior_params params = {
        .sq_entries = 32,
        .cq_entries = 64,
        .flags = 0,
        .backend = IOR_BACKEND_THREADS,  // Force threads
    };
    
    int ret = ior_queue_init_params(32, &ctx, &params);
    assert_return_code(ret, 0);
    
    // Verify it's using threads backend
    assert_int_equal(ior_get_backend_type(ctx), IOR_BACKEND_THREADS);
    assert_string_equal(ior_get_backend_name(ctx), "threads");
    
    ior_queue_exit(ctx);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_threads_backend),
    };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}
