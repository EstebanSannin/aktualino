/* Minimal host test helpers: CHECK/CHECK_EQ etc. main() returns tests_failed. */
#pragma once
#include <stdio.h>
#include <string.h>

static int g_tests_run = 0;
static int g_tests_failed = 0;

#define CHECK(cond) do {                                                      \
    g_tests_run++;                                                            \
    if (!(cond)) {                                                            \
        g_tests_failed++;                                                     \
        printf("  FAIL %s:%d  CHECK(%s)\n", __FILE__, __LINE__, #cond);       \
    }                                                                         \
} while (0)

#define CHECK_MSG(cond, ...) do {                                             \
    g_tests_run++;                                                            \
    if (!(cond)) {                                                            \
        g_tests_failed++;                                                     \
        printf("  FAIL %s:%d  ", __FILE__, __LINE__);                         \
        printf(__VA_ARGS__);                                                  \
        printf("\n");                                                         \
    }                                                                         \
} while (0)

#define CHECK_STREQ(a, b) do {                                                \
    g_tests_run++;                                                            \
    if (strcmp((a), (b)) != 0) {                                             \
        g_tests_failed++;                                                     \
        printf("  FAIL %s:%d  \"%s\" != \"%s\"\n", __FILE__, __LINE__, (a), (b)); \
    }                                                                         \
} while (0)

#define TEST_SUMMARY(name) do {                                               \
    printf("[%s] %d checks, %d failed\n", (name),                             \
           g_tests_run, g_tests_failed);                                      \
    return g_tests_failed ? 1 : 0;                                            \
} while (0)
