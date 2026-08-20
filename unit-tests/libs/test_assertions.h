#pragma once

/**
 * Shared cmocka assertions. Include after <cmocka.h>.
 */

#include <stddef.h>
#include <stdint.h>

/** Fails unless every byte of `buf` is zero. */
static inline void assert_cleared(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        assert_int_equal(buf[i], 0);
    }
}
