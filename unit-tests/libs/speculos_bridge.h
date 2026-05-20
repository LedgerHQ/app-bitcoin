/**
 * Speculos bridge for host-side unit tests.
 *
 * This header declares the (small) bridge layer that lets the application
 * code link against the C implementation of the Ledger BOLOS syscalls
 * provided by speculos (https://github.com/LedgerHQ/speculos), so that
 * code under test can be exercised without needing a device or an
 * ARM emulator.
 *
 * It is NOT a replacement for the SDK headers: it just provides the
 * forwarders/wrappers that bind the SDK symbol names expected by the
 * application code to the speculos primitives (`sys_cx_*`, `spec_cx_*`).
 *
 * Including this header from a test is optional: the bridge is linked
 * at the symbol level.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

/* Re-export the SDK's cx_err_t error codes (CX_OK, CX_INTERNAL_ERROR,
 * ...) so tests can use the symbolic names instead of magic numbers
 * when asserting against return values from speculos-backed code. */
#include "cx_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initialise OpenSSL RNG with a deterministic seed so test runs are
 * reproducible. Call once from main() before exercising code under test. */
void speculos_bridge_init(void);

#ifdef __cplusplus
}
#endif
