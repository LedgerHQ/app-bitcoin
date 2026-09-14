#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mock_dispatcher.h"

#define PM_MAX_INPUTS   3
#define PM_MAX_OUTPUTS  3

/* Cursor over the harness input. The scenario carries it so every map drawn during
 * one build continues where the last stopped -- the tail is one stream, not a set of
 * fixed-offset slots. */
typedef struct {
    const uint8_t *p;
    size_t len;
    size_t off;
} pm_tape_t;

typedef struct {
    pm_tape_t tape;
    uint32_t tx_version;
    uint32_t locktime;
    int n_inputs;
    int n_outputs;
    uint8_t sign_mode;  /* 0=default, 1=registered, 2=rawtx, 3=musig-r1, 4=musig-r2 */

    uint8_t wallet_policy[512];
    size_t wallet_policy_len;

    uint8_t wallet_id[32];
    uint8_t wallet_hmac[32];

    /* Counts the APDU declares, which the tape may set independently of how many
     * input/output maps were actually committed to the trees. */
    int declared_inputs;
    int declared_outputs;

    /* The scriptPubKey this wallet policy derives for (change 0, index 0), or
     * length 0 if it could not be derived. See pm_bind_wallet_spk(). */
    uint8_t wallet_spk[34];
    size_t wallet_spk_len;

    /* The compressed pubkey the policy's first key expression derives at
     * (change 0, index 0), and the PSBT_IN_BIP32_DERIVATION value that names it:
     * master fingerprint followed by the full derivation path. */
    uint8_t wallet_pubkey[33];
    size_t wallet_pubkey_len;
    uint8_t wallet_deriv[4 + 5 * 4];
    size_t wallet_deriv_len;

    uint8_t global_root_keys[32];
    uint8_t global_root_values[32];
    uint8_t inputs_root[32];
    uint8_t outputs_root[32];

    uint8_t apdu[512];
    size_t apdu_len;
} psbt_scenario_t;

extern int pm_force_sign_mode;

int pm_build_scenario(psbt_scenario_t *sc,
                      mock_dispatcher_t *host,
                      const uint8_t *entropy,
                      size_t entropy_len,
                      const uint8_t *slot_data,
                      size_t slot_data_len);

size_t pm_build_apdu(const psbt_scenario_t *sc, uint8_t *buf, size_t max);

int pm_derive_mock_xpub(void);
