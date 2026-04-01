#pragma once

/**
 * Mock implementation of the Ledger SDK cx_hash / cx_sha256 functions,
 * backed by the reference SHA-256 library (sha-256.c from amosnier/sha-2).
 *
 * Provides:
 *  - cx_sha256_init
 *  - cx_hash_no_throw  (update / finalize)
 *  - cx_hash_sha256    (one-shot)
 *  - cx_sha256_hash_iovec
 *
 * The function prototypes are already declared in the mock SDK headers
 * (lcx_hash.h / lcx_sha256.h). This header just needs to be included
 * in the mock .c file; test files should include the SDK headers via
 * cx.h or directly.
 */

#include <stdint.h>
#include <stddef.h>

#include "os.h"
#include "cx.h"
