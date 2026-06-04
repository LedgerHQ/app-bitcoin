#pragma once

/**
 * Header-only helpers for the data-driven unit tests that load their vectors
 * from a TOML file (via the vendored tomlc17 parser).
 *
 * These run from each test's main() before cmocka_run_group_tests_name(), so
 * there is no active test (and no setjmp buffer) for cmocka's fail() / assert_*
 * macros to unwind to. On malformed input they abort() the process instead,
 * which gives a deterministic, non-zero exit.
 *
 * All helpers are static inline so the header can be included from multiple
 * translation units without violating the one-definition rule; unused ones are
 * dropped without warning.
 */

#include <limits.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tomlc17.h"

/* Copy a required string field from a TOML table into a fixed-size buffer.
 * Aborts the process if the field is missing or doesn't fit. */
static inline void copy_required_string(toml_datum_t table,
                                        const char *key,
                                        char *dst,
                                        size_t dst_size) {
    toml_datum_t d = toml_get(table, key);
    if (d.type != TOML_STRING) {
        fprintf(stderr, "missing or non-string field: %s\n", key);
        abort();
    }
    if ((size_t) d.u.str.len >= dst_size) {
        fprintf(stderr, "field %s too long (%d >= %zu)\n", key, d.u.str.len, dst_size);
        abort();
    }
    memcpy(dst, d.u.str.ptr, (size_t) d.u.str.len);
    dst[d.u.str.len] = '\0';
}

/* Copy an optional string field; returns true if it was present. Aborts only
 * if the field is present but doesn't fit. */
static inline bool copy_optional_string(toml_datum_t table,
                                        const char *key,
                                        char *dst,
                                        size_t dst_size) {
    toml_datum_t d = toml_get(table, key);
    if (d.type != TOML_STRING) {
        return false;
    }
    if ((size_t) d.u.str.len >= dst_size) {
        fprintf(stderr, "field %s too long (%d >= %zu)\n", key, d.u.str.len, dst_size);
        abort();
    }
    memcpy(dst, d.u.str.ptr, (size_t) d.u.str.len);
    dst[d.u.str.len] = '\0';
    return true;
}

/* Copy a required non-negative integer field. Aborts if missing, non-integer,
 * negative, or larger than UINT_MAX. */
static inline unsigned int copy_required_uint(toml_datum_t table, const char *key) {
    toml_datum_t d = toml_get(table, key);
    if (d.type != TOML_INT64) {
        fprintf(stderr, "missing or non-integer field: %s\n", key);
        abort();
    }
    if (d.u.int64 < 0) {
        fprintf(stderr, "negative integer in field: %s\n", key);
        abort();
    }
    if (d.u.int64 > UINT_MAX) {
        fprintf(stderr, "integer in field %s too large\n", key);
        abort();
    }
    return (unsigned int) d.u.int64;
}
