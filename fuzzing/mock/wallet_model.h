#pragma once

#include <stddef.h>
#include <stdint.h>

#include "semantic_host.h"

#define WM_MAX_KEYS 6
#define WM_MAX_DESCRIPTOR_LEN 128

typedef struct {
    uint8_t version;
    char name[17];
    uint8_t name_len;

    char descriptor[WM_MAX_DESCRIPTOR_LEN];
    size_t descriptor_len;

    int n_keys;
    uint32_t purposes[WM_MAX_KEYS];
    int has_wildcard;

    uint8_t wallet_policy[256];
    size_t wallet_policy_len;

    uint8_t wallet_id[32];
    uint8_t wallet_hmac[32];

    uint8_t keys_info_root[32];

    uint8_t apdu[512];
    size_t apdu_len;
} wallet_scenario_t;

int wm_build_scenario(wallet_scenario_t *sc,
                      semantic_host_t *host,
                      const uint8_t *entropy,
                      size_t entropy_len,
                      const uint8_t *slot_data,
                      size_t slot_data_len);

int wm_build_get_address_apdu(wallet_scenario_t *sc,
                              const uint8_t *slot_data,
                              size_t slot_data_len);
