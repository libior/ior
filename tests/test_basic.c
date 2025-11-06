/* SPDX-License-Identifier: BSD-3-Clause */
#include "test_utils.h"

// Test initialization and cleanup
static void test_init_and_exit(void **state) {
    (void)state;
    
    ior_ctx *ctx;
    int ret = ior_queue_init(32, &ctx);
    
    assert_return_code(ret, 0);
    assert_non_null(ctx);
    
    // Check backend was selected
    ior_backend_type backend = ior_get_backend_type(ctx);
    assert_true(backend != IOR_BACKEND_AUTO);
    
    const char *backend_name = ior_get_backend_name(ctx);
    assert_non_null(backend_name);
    
    printf("Using backend: %s\n", backend_name);
    
    ior_queue_exit(ctx);
}

// Test initialization with parameters
static void test_init_with_params(void **state) {
    (void)state;
    
    ior_ctx *ctx;
    ior_params params = {
        .sq_entries = 64,
        .cq_entries = 128,
        .flags = 0,
        .backend = IOR_BACKEND_AUTO,
    };
    
    int ret = ior_queue_init_params(64, &ctx, &params);
    
    assert_return_code(ret, 0);
    assert_non_null(ctx);
    
    printf("Features: 0x%x\n", params.features);
    
    ior_queue_exit(ctx);
}

// Test getting SQE
static void test_get_sqe(void **state) {
    test_state *ts = (test_state *)*state;
    
    ior_sqe *sqe = ior_get_sqe(ts->ctx);
    assert_non_null(sqe);
    
    // Fill in a NOP operation
    ior_prep_nop(sqe);
    assert_int_equal(sqe->opcode, IOR_OP_NOP);
    
    // Submit
    int ret = ior_submit(ts->ctx);
    assert_true(ret > 0);
}

// Test NOP operation
static void test_nop_operation(void **state) {
    test_state *ts = (test_state *)*state;
    
    // Queue NOP
    ior_sqe *sqe = ior_get_sqe(ts->ctx);
    assert_non_null(sqe);
    
    ior_prep_nop(sqe);
    ior_sqe_set_data(sqe, (void *)0x1234);
    
    // Submit and wait
    int ret = ior_submit_and_wait(ts->ctx, 1);
    assert_true(ret >= 0);
    
    // Get completion
    ior_cqe *cqe;
    ret = ior_wait_cqe(ts->ctx, &cqe);
    assert_return_code(ret, 0);
    assert_non_null(cqe);
    
    // Check result
    assert_int_equal(cqe->res, 0);
    assert_ptr_equal(ior_cqe_get_data(cqe), (void *)0x1234);
    
    ior_cqe_seen(ts->ctx, cqe);
}

// Test peek CQE
static void test_peek_cqe(void **state) {
    test_state *ts = (test_state *)*state;
    
    // Queue NOP
    ior_sqe *sqe = ior_get_sqe(ts->ctx);
    assert_non_null(sqe);
    ior_prep_nop(sqe);
    
    // Submit
    int ret = ior_submit(ts->ctx);
    assert_true(ret > 0);
    
    // Peek should return -EAGAIN initially (operation may not be done yet)
    // So we wait first
    ior_cqe *cqe;
    ret = ior_wait_cqe(ts->ctx, &cqe);
    assert_return_code(ret, 0);
    
    // Now peek should work without consuming
    ior_cqe *cqe2;
    ret = ior_peek_cqe(ts->ctx, &cqe2);
    assert_return_code(ret, 0);
    assert_ptr_equal(cqe, cqe2);
    
    // Consume it
    ior_cqe_seen(ts->ctx, cqe);
    
    // Now peek should fail
    ret = ior_peek_cqe(ts->ctx, &cqe2);
    assert_int_equal(ret, -EAGAIN);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_init_and_exit),
        cmocka_unit_test(test_init_with_params),
        cmocka_unit_test_setup_teardown(test_get_sqe, setup_ior_ctx, teardown_ior_ctx),
        cmocka_unit_test_setup_teardown(test_nop_operation, setup_ior_ctx, teardown_ior_ctx),
        cmocka_unit_test_setup_teardown(test_peek_cqe, setup_ior_ctx, teardown_ior_ctx),
    };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}
