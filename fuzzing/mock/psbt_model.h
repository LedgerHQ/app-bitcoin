#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "semantic_host.h"

#define PM_MAX_INPUTS   8
#define PM_MAX_OUTPUTS  8

typedef struct {
    uint8_t prev_txid[32];
    uint32_t output_index;
    uint32_t sequence;
    uint64_t amount;
    uint8_t scriptpubkey[34];
    size_t scriptpubkey_len;
    uint32_t bip32_change;
    uint32_t bip32_addr_index;
    int use_non_witness_utxo;
    uint8_t rawtx[256];
    size_t rawtx_len;
    uint8_t sighash_type;
    int has_redeem_script;
    uint8_t redeem_script[128];
    size_t redeem_script_len;
    int has_witness_script;
    uint8_t witness_script[256];
    size_t witness_script_len;
} pm_input_t;

typedef struct {
    uint64_t amount;
    uint8_t scriptpubkey[34];
    size_t scriptpubkey_len;
    bool is_change;
    uint32_t bip32_addr_index;
} pm_output_t;

typedef struct {
    uint32_t tx_version;
    uint32_t locktime;
    int n_inputs;
    int n_outputs;
    uint8_t sign_mode;  /* 0=default, 1=registered, 2=rawtx, 3=musig-r1, 4=musig-r2 */
    pm_input_t inputs[PM_MAX_INPUTS];
    pm_output_t outputs[PM_MAX_OUTPUTS];

    uint8_t wallet_policy[512];
    size_t wallet_policy_len;

    uint8_t wallet_id[32];
    uint8_t wallet_hmac[32];

    uint8_t global_root_keys[32];
    uint8_t global_root_values[32];
    uint8_t inputs_root[32];
    uint8_t outputs_root[32];

    uint8_t apdu[512];
    size_t apdu_len;
} psbt_scenario_t;

extern int pm_force_sign_mode;

int pm_build_scenario(psbt_scenario_t *sc,
                      semantic_host_t *host,
                      const uint8_t *entropy,
                      size_t entropy_len,
                      const uint8_t *slot_data,
                      size_t slot_data_len);

size_t pm_build_apdu(const psbt_scenario_t *sc, uint8_t *buf, size_t max);

int pm_derive_mock_xpub(void);
int pm_encode_xpub(char *out, size_t out_len);
int pm_encode_xpub_for_purpose(uint32_t purpose, char *out, size_t out_len);
