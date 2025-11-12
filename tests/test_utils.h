/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <cmocka.h>
#include "config.h"
#include "../src/ior.h"

// Test fixture structure
typedef struct test_state {
	ior_ctx *ctx;
	int test_fd;
	char *temp_file;
} test_state;

// Setup/teardown helpers
int setup_ior_ctx(void **state);
int teardown_ior_ctx(void **state);
int setup_temp_file(void **state);
int teardown_temp_file(void **state);

// Utility functions
char *create_temp_file(const char *content, size_t len);
void remove_temp_file(const char *path);

#endif /* TEST_UTILS_H */
