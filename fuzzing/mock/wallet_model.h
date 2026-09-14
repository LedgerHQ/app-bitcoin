#pragma once

#include <stddef.h>
#include <stdint.h>

#include "mock_dispatcher.h"

/* Match the app, do not mirror a smaller bound: MAX_N_KEYS_IN_WALLET_POLICY is 15
 * and a serialized header allows 252, so a builder capped at 6 could never test the
 * limit. The descriptor cap is deliberately above the app's
 * MAX_DESCRIPTOR_TEMPLATE_LENGTH_V2 (512) so the over-length rejection is reachable. */
#define WM_MAX_KEYS 16
#define WM_MAX_DESCRIPTOR_LEN 600

typedef struct {
    uint8_t version;
    char name[72];   /* app allows MAX_WALLET_NAME_LENGTH = 64 */
    uint8_t name_len;

    char descriptor[WM_MAX_DESCRIPTOR_LEN];
    size_t descriptor_len;

    int n_keys;
    uint32_t purposes[WM_MAX_KEYS];

    /* V1 inlines the descriptor, so this must hold the longest one plus the header
     * (version, name, two varints, two 32-byte roots). */
    uint8_t wallet_policy[WM_MAX_DESCRIPTOR_LEN + 256];
    size_t wallet_policy_len;

    uint8_t wallet_id[32];
    uint8_t wallet_hmac[32];

    uint8_t keys_info_root[32];

    uint8_t apdu[WM_MAX_DESCRIPTOR_LEN + 512];
    size_t apdu_len;
} wallet_scenario_t;

int wm_build_scenario(wallet_scenario_t *sc,
                      mock_dispatcher_t *host,
                      const uint8_t *entropy,
                      size_t entropy_len,
                      const uint8_t *slot_data,
                      size_t slot_data_len);

int wm_build_get_address_apdu(wallet_scenario_t *sc,
                              const uint8_t *slot_data,
                              size_t slot_data_len);
