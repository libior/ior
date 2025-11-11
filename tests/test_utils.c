/* SPDX-License-Identifier: BSD-3-Clause */
#include "test_utils.h"

int setup_ior_ctx(void **state) {
    test_state *ts = calloc(1, sizeof(test_state));
    assert_non_null(ts);
    
    int ret = ior_queue_init(32, &ts->ctx);
    assert_return_code(ret, 0);
    assert_non_null(ts->ctx);
    
    *state = ts;
    return 0;
}

int teardown_ior_ctx(void **state) {
    test_state *ts = (test_state *)*state;
    
    if (ts) {
        if (ts->ctx) {
            ior_queue_exit(ts->ctx);
        }
        free(ts);
    }
    
    return 0;
}

int setup_temp_file(void **state) {
    setup_ior_ctx(state);
    
    test_state *ts = (test_state *)*state;
    
    const char *content = "Hello, World!\nThis is a test file.\n";
    ts->temp_file = create_temp_file(content, strlen(content));
    assert_non_null(ts->temp_file);
    
    ts->test_fd = open(ts->temp_file, O_RDWR);
    assert_true(ts->test_fd >= 0);
    
    return 0;
}

int teardown_temp_file(void **state) {
    test_state *ts = (test_state *)*state;
    
    if (ts) {
        if (ts->test_fd >= 0) {
            close(ts->test_fd);
        }
        if (ts->temp_file) {
            remove_temp_file(ts->temp_file);
            free(ts->temp_file);
        }
    }
    
    return teardown_ior_ctx(state);
}

char *create_temp_file(const char *content, size_t len) {
    char template[] = "/tmp/ior_test_XXXXXX";
    int fd = mkstemp(template);
    if (fd < 0) {
        return NULL;
    }
    
    if (content && len > 0) {
        ssize_t written = write(fd, content, len);
        if (written != (ssize_t)len) {
            close(fd);
            unlink(template);
            return NULL;
        }
    }
    
    close(fd);
    return strdup(template);
}

void remove_temp_file(const char *path) {
    if (path) {
        unlink(path);
    }
}
