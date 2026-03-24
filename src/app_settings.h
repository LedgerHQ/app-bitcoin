#pragma once

#include <stdbool.h>
#include <stdint.h>

/**
 * Application settings stored in NVRAM (persistent across reboots, reset on app/OS update).
 */
typedef struct {
    // If true, non-standard sighash types (SIGHASH_NONE, SIGHASH_SINGLE,
    // SIGHASH_ANYONECANPAY|*) are allowed with a warning during signing.
    // If false (default), these sighash types are rejected with
    // SW_SECURITY_STATUS_NOT_SATISFIED.
    uint8_t allow_nondefault_sighash;
} app_settings_t;

#ifndef SKIP_FOR_CMOCKA

#include "os.h"

extern const app_settings_t N_app_settings_real;
#define N_app_settings (*(const volatile app_settings_t *) PIC(&N_app_settings_real))

/**
 * Returns true if non-standard sighash types are allowed (user opted in through settings).
 */
static inline bool app_settings_get_allow_nondefault_sighash(void) {
    return N_app_settings.allow_nondefault_sighash != 0;
}

/**
 * Sets whether non-standard sighash types are allowed.
 */
static inline void app_settings_set_allow_nondefault_sighash(bool allow) {
    uint8_t val = allow ? 1 : 0;
    nvm_write((void *) &N_app_settings.allow_nondefault_sighash, &val, sizeof(val));
}

#else /* SKIP_FOR_CMOCKA - unit test stubs */

extern uint8_t mock_allow_nondefault_sighash;

static inline bool app_settings_get_allow_nondefault_sighash(void) {
    return mock_allow_nondefault_sighash != 0;
}

static inline void app_settings_set_allow_nondefault_sighash(bool allow) {
    mock_allow_nondefault_sighash = allow ? 1 : 0;
}

#endif /* SKIP_FOR_CMOCKA */
