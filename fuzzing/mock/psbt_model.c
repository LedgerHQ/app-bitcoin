#include "psbt_model.h"
#include "fuzz_sha256.h"
#include "fuzz_varint.h"
#include "mocks.h"

#include "base58.h"
#include "bip32.h"
#include "psbt.h"
#include "varint.h"
#include "wallet.h"
#include "write.h"
#include "constants.h"
#include "crypto.h"
#include "musig.h"

#include <string.h>
#include <stdio.h>

/*
 * Fault-knob-driven builder faults.  btc_fault_kind (from the last 4 bytes
 * of the fuzz tail) selects the fault; btc_fault_target picks the affected
 * input/output; btc_fault_param[0..1] carry per-kind parameters.
 *
 * Pre-tree faults modify scenario fields before the Merkle tree is built
 * so the faulted values propagate consistently through all preimages.
 * Post-wallet faults corrupt sealed wallet state (HMAC) to stress the
 * crypto verification gates.
 */
static void pm_apply_pre_tree_fault(psbt_scenario_t *sc) {
    int target_in = (sc->n_inputs > 0) ?
        (int)(btc_fault_target % sc->n_inputs) : -1;
    int target_out = (sc->n_outputs > 0) ?
        (int)(btc_fault_target % sc->n_outputs) : -1;

    switch (btc_fault_kind) {
        case BTC_FAULT_SIGHASH_OVR:
            if (target_in >= 0) {
                uint8_t sh = btc_fault_param[0];
                if (sh == 0) sh = 0x42;
                sc->inputs[target_in].sighash_type = sh;
            }
            break;
        case BTC_FAULT_AMOUNT_XOR:
            if (target_in >= 0) {
                sc->inputs[target_in].amount ^=
                    ((uint64_t)btc_fault_param[0] << 32) | btc_fault_param[1];
            }
            break;
        case BTC_FAULT_SEQ_LOCK:
            if (target_in >= 0) {
                sc->inputs[target_in].sequence = 0xFFFFFFFFUL;
                sc->locktime = 500000;
            }
            break;
        case BTC_FAULT_OUTPUT_AMT:
            if (target_out >= 0) {
                sc->outputs[target_out].amount = 0xFFFFFFFFFFULL;
            }
            break;
        default:
            break;
    }
}

static void pm_apply_post_wallet_fault(psbt_scenario_t *sc) {
    if (btc_fault_kind == BTC_FAULT_WRONG_HMAC) {
        for (int i = 0; i < 32; i++)
            sc->wallet_hmac[i] ^= btc_fault_param[0] | 0x01;
    }
}

static serialized_extended_pubkey_t g_derived_xpub;
static bool g_xpub_derived = false;

int pm_derive_mock_xpub(void) {
    if (g_xpub_derived) return 0;
    uint32_t path[] = {0x80000000UL | 84, 0x80000000UL | (uint32_t)BIP44_COIN_TYPE, 0x80000000UL};
    cx_err_t err = get_extended_pubkey_at_path(path, 3, BIP32_PUBKEY_VERSION, &g_derived_xpub);
    if (err != CX_OK) return -1;
    g_xpub_derived = true;
    return 0;
}

static int encode_xpub_internal(const serialized_extended_pubkey_t *xpub, char *out, size_t out_len) {
    serialized_extended_pubkey_check_t check;
    memcpy(&check.serialized_extended_pubkey, xpub, sizeof(check.serialized_extended_pubkey));
    crypto_get_checksum((uint8_t *)&check.serialized_extended_pubkey,
                        sizeof(check.serialized_extended_pubkey),
                        check.checksum);
    return base58_encode((uint8_t *)&check, sizeof(check), out, out_len);
}

int pm_encode_xpub(char *out, size_t out_len) {
    if (pm_derive_mock_xpub() < 0) return -1;
    return encode_xpub_internal(&g_derived_xpub, out, out_len);
}

int pm_encode_xpub_for_purpose(uint32_t purpose, char *out, size_t out_len) {
    serialized_extended_pubkey_t xpub;
    uint32_t path[] = {0x80000000UL | purpose, 0x80000000UL | (uint32_t)BIP44_COIN_TYPE, 0x80000000UL};
    cx_err_t err = get_extended_pubkey_at_path(path, 3, BIP32_PUBKEY_VERSION, &xpub);
    if (err != CX_OK) return -1;
    return encode_xpub_internal(&xpub, out, out_len);
}

static cx_err_t pm_derive_child_xpub(uint32_t purpose,
                                      uint32_t account,
                                      uint32_t change,
                                      uint32_t addr_index,
                                      serialized_extended_pubkey_t *out) {
    uint32_t path[] = {
        0x80000000UL | purpose,
        0x80000000UL | (uint32_t)BIP44_COIN_TYPE,
        0x80000000UL | account,
        change,
        addr_index,
    };
    return get_extended_pubkey_at_path(path, 5, BIP32_PUBKEY_VERSION, out);
}

typedef struct {
    const char *descriptor;
    int n_keys;
    uint32_t purpose;
    uint8_t script_type;  /* 0=P2WPKH, 1=P2TR, 2=P2WSH, 3=P2SH-P2WPKH */
    int musig_n_keys;     /* keys inside musig() placeholder; 0 for non-musig */
} pm_descriptor_t;

/* SIGN_PSBT descriptor catalog.  Indices 0..PM_MUSIG_DESC_START-1 are
 * non-musig; indices >= PM_MUSIG_DESC_START are musig variants and are
 * only selected when sign_mode is 3 (musig round 1) or 4 (round 2).
 * See wallet_model.c TEMPLATES[] for the registration/address catalog. */
static const pm_descriptor_t PM_DESCRIPTORS[] = {
    /* 0 */ {"wpkh(@0)",                        1, 84, 0, 0},
    /* 1 */ {"tr(@0)",                          1, 86, 1, 0},
    /* 2 */ {"wsh(multi(2,@0,@1))",             2, 48, 2, 0},
    /* 3 */ {"sh(wpkh(@0))",                    1, 49, 3, 0},
    /* 4 */ {"wsh(sortedmulti(2,@0,@1))",       2, 48, 2, 0},
    /* 5 */ {"tr(@0,pk(@1))",                   2, 86, 1, 0},
    /* 6 */ {"wsh(and_v(v:pk(@0),pk(@1)))",     2, 48, 2, 0},
    /* 7 */ {"wsh(or_b(pk(@0),s:pk(@1)))",      2, 48, 2, 0},
    /* 8  musig keypath only           */ {"tr(musig(@0,@1)/**)",            2, 86, 1, 2},
    /* 9  musig keypath + script leaf  */ {"tr(musig(@0,@1)/**,pk(@2/**))",  3, 86, 1, 2},
    /* 10 musig 3-of-3 keypath         */ {"tr(musig(@0,@1,@2)/**)",         3, 86, 1, 3},
};

#define PM_MUSIG_DESC_START 8

#define PM_N_DESCRIPTORS (sizeof(PM_DESCRIPTORS) / sizeof(PM_DESCRIPTORS[0]))

static int g_pm_desc_idx = 0;

enum {
    PM_SIGN_MODE_DEFAULT = 0,
    PM_SIGN_MODE_REGISTERED = 1,
    PM_SIGN_MODE_RAWTX = 2,
    PM_SIGN_MODE_MUSIG_R1 = 3,
    PM_SIGN_MODE_MUSIG_R2 = 4,
};

enum {
    PM_SLOT0_TX_VERSION_OFF = 52,
    PM_SLOT0_LOCKTIME_OFF = 56,
    PM_SLOT0_N_INPUTS_OFF = 60,
    PM_SLOT0_N_OUTPUTS_OFF = 61,
    PM_SLOT0_SUBTYPE_OFF = 62,
    PM_SLOT0_DESCRIPTOR_OFF = 63,
};

#define PM_DESC_WSH_SORTEDMULTI 4

enum {
    PM_INPUT_SLOT_PREV_TXID_OFF = 0,
    PM_INPUT_SLOT_OUTPUT_INDEX_OFF = 32,
    PM_INPUT_SLOT_AMOUNT_OFF = 33,
    PM_INPUT_SLOT_SEQUENCE_OFF = 41,
    PM_INPUT_SLOT_SIGHASH_OFF = 45,
    PM_INPUT_SLOT_CHANGE_OFF = 46,
    PM_INPUT_SLOT_ADDR_INDEX_OFF = 47,
    PM_INPUT_SLOT_RAWTX_N_OUTS_OFF = 50,
    PM_INPUT_SLOT_RAWTX_VERSION_OFF = 51,
    PM_INPUT_SLOT_RAWTX_LOCKTIME_OFF = 55,
};

enum {
    PM_OUTPUT_SLOT_AMOUNT_OFF = 0,
    PM_OUTPUT_SLOT_ADDR_INDEX_OFF = 8,
    PM_OUTPUT_SLOT_SCRIPT_HINT_A_OFF = 10,
    PM_OUTPUT_SLOT_CHANGE_A_OFF = 11,
    PM_OUTPUT_SLOT_SCRIPT_HINT_B_OFF = 12,
    PM_OUTPUT_SLOT_CHANGE_B_OFF = 13,
};

static int build_multisig_witness_script(uint32_t change, uint32_t addr_index,
                                          uint8_t *ws_out, size_t *ws_len_out) {
    uint32_t purpose = PM_DESCRIPTORS[g_pm_desc_idx].purpose;
    int nk = PM_DESCRIPTORS[g_pm_desc_idx].n_keys;
    if (nk < 2) nk = 2;
    if (nk > 3) nk = 3;

    static serialized_extended_pubkey_t kc[3];
    for (int k = 0; k < nk; k++) {
        if (CX_OK != pm_derive_child_xpub(purpose, (uint32_t) k, change, addr_index, &kc[k]))
            return -1;
    }

    /* sortedmulti(): lex-order the pubkeys to match the BIP-67 convention. */
    if (g_pm_desc_idx == PM_DESC_WSH_SORTEDMULTI && nk >= 2) {
        for (int i = 0; i < nk - 1; i++)
            for (int j = i + 1; j < nk; j++)
                if (memcmp(kc[i].compressed_pubkey, kc[j].compressed_pubkey, 33) > 0) {
                    serialized_extended_pubkey_t tmp = kc[i];
                    kc[i] = kc[j];
                    kc[j] = tmp;
                }
    }

    uint8_t *ws = ws_out;
    *ws++ = 0x50 + nk;
    for (int k = 0; k < nk; k++) {
        *ws++ = 0x21;
        memcpy(ws, kc[k].compressed_pubkey, 33);
        ws += 33;
    }
    *ws++ = 0x50 + nk;
    *ws++ = 0xAE;
    *ws_len_out = (size_t) (ws - ws_out);
    return 0;
}

/* script_type == 4 is OP_RETURN; change / addr_index are ignored. */
static void build_scriptpubkey_for_type(uint8_t script_type,
                                         uint32_t change,
                                         uint32_t addr_index,
                                         uint8_t *out,
                                         size_t *out_len) {
    uint32_t purpose = PM_DESCRIPTORS[g_pm_desc_idx].purpose;

    switch (script_type) {
        case 0: {
            static serialized_extended_pubkey_t child;
            if (CX_OK != pm_derive_child_xpub(purpose, 0, change, addr_index, &child)) {
                *out_len = 0;
                return;
            }
            uint8_t h160[20];
            crypto_hash160(child.compressed_pubkey, 33, h160);
            out[0] = 0x00;
            out[1] = 0x14;
            memcpy(out + 2, h160, 20);
            *out_len = 22;
            break;
        }
        case 1: {
            static serialized_extended_pubkey_t child;
            if (CX_OK != pm_derive_child_xpub(purpose, 0, change, addr_index, &child)) {
                *out_len = 0;
                return;
            }
            out[0] = 0x51;
            out[1] = 0x20;
            uint8_t parity;
            crypto_tr_tweak_pubkey(child.compressed_pubkey + 1,
                                   (uint8_t[]) {},
                                   0,
                                   &parity,
                                   out + 2);
            *out_len = 34;
            break;
        }
        case 2: {
            uint8_t ws[256];
            size_t ws_len = 0;
            if (build_multisig_witness_script(change, addr_index, ws, &ws_len) < 0 ||
                ws_len == 0) {
                *out_len = 0;
                return;
            }
            uint8_t ws_hash[32];
            fuzz_sha256(ws, ws_len, ws_hash);
            out[0] = 0x00;
            out[1] = 0x20;
            memcpy(out + 2, ws_hash, 32);
            *out_len = 34;
            break;
        }
        case 3: {
            static serialized_extended_pubkey_t child;
            if (CX_OK != pm_derive_child_xpub(purpose, 0, change, addr_index, &child)) {
                *out_len = 0;
                return;
            }
            uint8_t h160[20];
            crypto_hash160(child.compressed_pubkey, 33, h160);
            uint8_t rs[22];
            rs[0] = 0x00;
            rs[1] = 0x14;
            memcpy(rs + 2, h160, 20);
            uint8_t rs_h160[20];
            crypto_hash160(rs, 22, rs_h160);
            out[0] = 0xA9;
            out[1] = 0x14;
            memcpy(out + 2, rs_h160, 20);
            out[22] = 0x87;
            *out_len = 23;
            break;
        }
        case 4: {
            if (pm_derive_mock_xpub() < 0) {
                *out_len = 0;
                return;
            }
            uint8_t h[32];
            fuzz_sha256(g_derived_xpub.compressed_pubkey, 33, h);
            out[0] = 0x6A;
            out[1] = 0x14;
            memcpy(out + 2, h, 20);
            *out_len = 22;
            break;
        }
        default:
            *out_len = 0;
            break;
    }
}

static void build_wpkh_scriptpubkey(uint32_t change, uint32_t addr_index,
                                     uint8_t *out, size_t *out_len) {
    build_scriptpubkey_for_type(PM_DESCRIPTORS[g_pm_desc_idx].script_type,
                                change, addr_index, out, out_len);
}

/* Build a minimal raw transaction whose shape is still tail-driven enough to
 * stress the rawtx parser: caller selects version, locktime, number of
 * outputs, and the funded output index. The transaction remains coherent so
 * the recomputed txid matches the PSBT fields. Layout:
 *   version(4) | vin_count(varint) | vin | vout_count(varint) | vout | locktime(4)
 */
static size_t build_rawtx_for_prevout(uint64_t amount,
                                      const uint8_t *spk, size_t spk_len,
                                      uint32_t output_index,
                                      uint8_t n_outs_hint,
                                      uint32_t version,
                                      uint32_t locktime,
                                      uint8_t *rawtx, size_t max_len,
                                      uint8_t txid_out[32]) {
    uint8_t *p = rawtx;
    uint8_t *end = rawtx + max_len;

    if (max_len < 80) return 0;

    fuzz_write_u32_le(p, version);      p += 4;
    *p++ = 0x01;
    memset(p, 0, 32);                    p += 32;
    fuzz_write_u32_le(p, 0);            p += 4;
    *p++ = 0x00;
    fuzz_write_u32_le(p, 0xFFFFFFFFUL); p += 4;

    int n_outs = 1 + (n_outs_hint & 0x07);
    if (n_outs < 1) n_outs = 1;
    if (n_outs > 8) n_outs = 8;
    output_index %= (uint32_t) n_outs;
    p += fuzz_write_varint(p, (uint64_t) n_outs);

    for (int i = 0; i < n_outs; i++) {
        if (p + 8 + 1 + spk_len + 4 > end) return 0;
        if (i == (int) output_index) {
            fuzz_write_u64_le(p, amount); p += 8;
            p += fuzz_write_varint(p, spk_len);
            memcpy(p, spk, spk_len); p += spk_len;
        } else {
            fuzz_write_u64_le(p, 0); p += 8;
            *p++ = 0x00;
        }
    }

    fuzz_write_u32_le(p, locktime); p += 4;

    size_t tx_len = (size_t) (p - rawtx);

    uint8_t hash1[32];
    fuzz_sha256(rawtx, tx_len, hash1);
    fuzz_sha256(hash1, 32, txid_out);

    return tx_len;
}

static int add_merkleized_map(semantic_host_t *host,
                              const uint8_t *keys[], const size_t *key_lens,
                              const uint8_t *values[], const size_t *value_lens,
                              int n_entries,
                              uint8_t root_keys[32], uint8_t root_values[32]) {
    int kt = sh_tree_init(host);
    int vt = sh_tree_init(host);
    if (kt < 0 || vt < 0) return -1;

    for (int i = 0; i < n_entries; i++) {
        sh_tree_add_leaf(host, kt, keys[i], key_lens[i]);
        sh_tree_add_leaf(host, vt, values[i], value_lens[i]);
    }
    sh_tree_finalize(host, kt);
    sh_tree_finalize(host, vt);
    memcpy(root_keys, host->trees[kt].root, 32);
    memcpy(root_values, host->trees[vt].root, 32);
    return 0;
}

static int add_map_commitment_preimage(semantic_host_t *host,
                                       int n_keys,
                                       const uint8_t keys_root[32],
                                       const uint8_t values_root[32]) {
    uint8_t commit[1 + 32 + 32];
    commit[0] = (uint8_t)n_keys;
    memcpy(commit + 1, keys_root, 32);
    memcpy(commit + 33, values_root, 32);

    uint8_t preimage[1 + sizeof(commit)];
    preimage[0] = 0x00;
    memcpy(preimage + 1, commit, sizeof(commit));
    sh_add_preimage(host, preimage, 1 + sizeof(commit));
    return 0;
}

static int build_global_map(psbt_scenario_t *sc, semantic_host_t *host) {
    uint8_t key_version[1] = {PSBT_GLOBAL_TX_VERSION};
    uint8_t val_version[4];
    fuzz_write_u32_le(val_version, sc->tx_version);

    uint8_t key_locktime[1] = {PSBT_GLOBAL_FALLBACK_LOCKTIME};
    uint8_t val_locktime[4];
    fuzz_write_u32_le(val_locktime, sc->locktime);

    const uint8_t *keys[] = {key_version, key_locktime};
    const size_t key_lens[] = {1, 1};
    const uint8_t *vals[] = {val_version, val_locktime};
    const size_t val_lens[] = {4, 4};

    return add_merkleized_map(host, keys, key_lens, vals, val_lens, 2,
                              sc->global_root_keys, sc->global_root_values);
}

static int is_taproot_descriptor(void) {
    return PM_DESCRIPTORS[g_pm_desc_idx].script_type == 1;
}

static int is_musig_descriptor(void) {
    return g_pm_desc_idx >= PM_MUSIG_DESC_START;
}

static int g_musig_round2 = 0;  /* set when sign_mode == 4 (musig round 2). */

/* Referenced by zero-symbols.txt and fuzz_globals.zon so Absolution keeps
 * a zero-cost slot for it; no runtime use. */
int pm_force_sign_mode = 0;

static void build_input_script_bundle(pm_input_t *inp,
                                      uint32_t change,
                                      uint32_t addr_index) {
    uint8_t script_type = PM_DESCRIPTORS[g_pm_desc_idx].script_type;

    inp->has_redeem_script = 0;
    inp->redeem_script_len = 0;
    inp->has_witness_script = 0;
    inp->witness_script_len = 0;

    switch (script_type) {
        case 2: {
            if (build_multisig_witness_script(change, addr_index,
                                              inp->witness_script,
                                              &inp->witness_script_len) < 0) {
                inp->scriptpubkey_len = 0;
                return;
            }
            inp->has_witness_script = 1;

            uint8_t ws_hash[32];
            fuzz_sha256(inp->witness_script, inp->witness_script_len, ws_hash);
            inp->scriptpubkey[0] = 0x00;
            inp->scriptpubkey[1] = 0x20;
            memcpy(inp->scriptpubkey + 2, ws_hash, 32);
            inp->scriptpubkey_len = 34;
            break;
        }
        case 3: {
            uint32_t purpose = PM_DESCRIPTORS[g_pm_desc_idx].purpose;
            static serialized_extended_pubkey_t child;
            if (CX_OK != pm_derive_child_xpub(purpose, 0, change, addr_index, &child)) {
                inp->scriptpubkey_len = 0;
                return;
            }
            uint8_t h160[20];
            crypto_hash160(child.compressed_pubkey, 33, h160);
            inp->redeem_script[0] = 0x00;
            inp->redeem_script[1] = 0x14;
            memcpy(inp->redeem_script + 2, h160, 20);
            inp->redeem_script_len = 22;
            inp->has_redeem_script = 1;

            uint8_t rs_h160[20];
            crypto_hash160(inp->redeem_script, 22, rs_h160);
            inp->scriptpubkey[0] = 0xA9;
            inp->scriptpubkey[1] = 0x14;
            memcpy(inp->scriptpubkey + 2, rs_h160, 20);
            inp->scriptpubkey[22] = 0x87;
            inp->scriptpubkey_len = 23;
            break;
        }
        default:
            build_scriptpubkey_for_type(script_type, change, addr_index,
                                        inp->scriptpubkey, &inp->scriptpubkey_len);
            break;
    }
}

/* For KEY_EXPRESSION_MUSIG, sign_psbt.c sets psbt_root_key_derivation_length
 * to 0, so the TAP_BIP32_DERIVATION value must carry the aggregate pubkey's
 * fingerprint followed by [change, address_index] only.  Results are cached
 * per descriptor index. */
#define PM_MAX_MUSIG_KEYS 5

static int pm_compute_musig_aggregate(uint8_t agg_compressed[static 33],
                                      uint32_t *fingerprint_out) {
    static int cached_desc_idx = -1;
    static uint8_t cached_agg[33];
    static uint32_t cached_fpr;

    if (cached_desc_idx == g_pm_desc_idx) {
        memcpy(agg_compressed, cached_agg, 33);
        *fingerprint_out = cached_fpr;
        return 0;
    }

    const pm_descriptor_t *desc = &PM_DESCRIPTORS[g_pm_desc_idx];
    int n_musig = desc->musig_n_keys;
    if (n_musig < 2 || n_musig > PM_MAX_MUSIG_KEYS) return -1;

    plain_pk_t keys[PM_MAX_MUSIG_KEYS];
    for (int k = 0; k < n_musig; k++) {
        static serialized_extended_pubkey_t key_xpub;
        uint32_t path[] = {
            0x80000000UL | desc->purpose,
            0x80000000UL | (uint32_t)BIP44_COIN_TYPE,
            0x80000000UL | (uint32_t)k
        };
        cx_err_t err = get_extended_pubkey_at_path(path, 3, BIP32_PUBKEY_VERSION, &key_xpub);
        if (err != CX_OK) return -1;
        memcpy(keys[k], key_xpub.compressed_pubkey, 33);
    }

    qsort(keys, n_musig, sizeof(plain_pk_t), compare_plain_pk);

    musig_keyagg_context_t ctx;
    if (0 > musig_key_agg(keys, n_musig, &ctx)) return -1;

    agg_compressed[0] = (ctx.Q.y[31] % 2 == 0) ? 2 : 3;
    memcpy(agg_compressed + 1, ctx.Q.x, 32);
    *fingerprint_out = crypto_get_key_fingerprint(agg_compressed);

    memcpy(cached_agg, agg_compressed, 33);
    cached_fpr = *fingerprint_out;
    cached_desc_idx = g_pm_desc_idx;

    return 0;
}

typedef struct {
    const uint8_t *keys[16];
    size_t key_lens[16];
    const uint8_t *vals[16];
    size_t val_lens[16];
    int n_entries;
} pm_merkle_map_t;

static void pm_map_reset(pm_merkle_map_t *map) {
    map->n_entries = 0;
}

static int pm_map_add(pm_merkle_map_t *map,
                      const uint8_t *key,
                      size_t key_len,
                      const uint8_t *val,
                      size_t val_len) {
    size_t max_entries = sizeof(map->keys) / sizeof(map->keys[0]);
    int idx = map->n_entries;

    if ((size_t) idx >= max_entries) {
        return -1;
    }

    map->keys[idx] = key;
    map->key_lens[idx] = key_len;
    map->vals[idx] = val;
    map->val_lens[idx] = val_len;
    map->n_entries++;
    return 0;
}

static int pm_map_finalize(semantic_host_t *host,
                           pm_merkle_map_t *map,
                           uint8_t keys_root[32],
                           uint8_t values_root[32]) {
    return add_merkleized_map(host,
                              map->keys,
                              map->key_lens,
                              map->vals,
                              map->val_lens,
                              map->n_entries,
                              keys_root,
                              values_root);
}

static int build_input_map(psbt_scenario_t *sc,
                           semantic_host_t *host,
                           int input_idx,
                           uint8_t keys_root[32],
                           uint8_t values_root[32],
                           int *n_entries_out) {
    pm_input_t *inp = &sc->inputs[input_idx];
    uint32_t purpose = PM_DESCRIPTORS[g_pm_desc_idx].purpose;
    pm_merkle_map_t map;

    pm_map_reset(&map);

    static serialized_extended_pubkey_t inp_child;
    if (CX_OK != pm_derive_child_xpub(purpose, 0,
                                       inp->bip32_change, inp->bip32_addr_index,
                                       &inp_child)) {
        return -1;
    }

    uint8_t val_bip32[4 + 5 * 4];
    memset(val_bip32, 0, 4);
    fuzz_write_u32_le(val_bip32 + 4,  0x80000000UL | purpose);
    fuzz_write_u32_le(val_bip32 + 8,  0x80000000UL | (uint32_t)BIP44_COIN_TYPE);
    fuzz_write_u32_le(val_bip32 + 12, 0x80000000UL);
    fuzz_write_u32_le(val_bip32 + 16, inp->bip32_change);
    fuzz_write_u32_le(val_bip32 + 20, inp->bip32_addr_index);
    size_t val_bip32_len = 24;

    uint8_t key_bip32[34];
    key_bip32[0] = PSBT_IN_BIP32_DERIVATION;
    memcpy(key_bip32 + 1, inp_child.compressed_pubkey, 33);

    uint8_t key_tap_bip32[34];
    key_tap_bip32[0] = PSBT_IN_TAP_BIP32_DERIVATION;
    memcpy(key_tap_bip32 + 1, inp_child.compressed_pubkey + 1, 32);
    /* TAP_BIP32 value: num_hashes(varint=0) then the plain BIP32 value. */
    uint8_t val_tap_bip32[1 + 4 + 5 * 4];
    val_tap_bip32[0] = 0x00;
    memcpy(val_tap_bip32 + 1, val_bip32, val_bip32_len);
    size_t val_tap_bip32_len = 1 + val_bip32_len;

    uint8_t key_prevtxid[1] = {PSBT_IN_PREVIOUS_TXID};
    uint8_t key_outidx[1] = {PSBT_IN_OUTPUT_INDEX};
    uint8_t val_outidx[4];
    fuzz_write_u32_le(val_outidx, inp->output_index);

    uint8_t key_seq[1] = {PSBT_IN_SEQUENCE};
    uint8_t val_seq[4];
    fuzz_write_u32_le(val_seq, inp->sequence);

    uint8_t key_sighash[1] = {PSBT_IN_SIGHASH_TYPE};
    uint8_t val_sighash[4];
    fuzz_write_u32_le(val_sighash, (uint32_t) inp->sighash_type);

    uint8_t key_tap_ikey[1] = {PSBT_IN_TAP_INTERNAL_KEY};
    uint8_t val_tap_ikey[32];
    memcpy(val_tap_ikey, inp_child.compressed_pubkey + 1, 32);

    /* MUSIG2_PUB_NONCE key = 0x1B | participant_pk(33) | aggregate_pk(33),
     * value = 66-byte pubnonce (two compressed group elements). */
    uint8_t key_musig_nonce[1 + 33 + 33];
    key_musig_nonce[0] = PSBT_IN_MUSIG2_PUB_NONCE;
    memcpy(key_musig_nonce + 1, inp_child.compressed_pubkey, 33);
    memcpy(key_musig_nonce + 34, inp_child.compressed_pubkey, 33);
    size_t key_musig_nonce_len = 1 + 33 + 33;
    uint8_t val_musig_nonce[66];
    memset(val_musig_nonce, 0x02, 66);
    memcpy(val_musig_nonce + 1, inp_child.compressed_pubkey + 1, 32);
    memcpy(val_musig_nonce + 34, inp_child.compressed_pubkey + 1, 32);

    if (is_musig_descriptor()) {
        static uint8_t musig_agg[33];
        uint32_t musig_fpr;
        if (0 == pm_compute_musig_aggregate(musig_agg, &musig_fpr)) {
            memcpy(key_tap_bip32 + 1, musig_agg + 1, 32);
            val_tap_bip32[0] = 0x00;
            write_u32_be(val_tap_bip32 + 1, 0, musig_fpr);
            fuzz_write_u32_le(val_tap_bip32 + 5, inp->bip32_change);
            fuzz_write_u32_le(val_tap_bip32 + 9, inp->bip32_addr_index);
            val_tap_bip32_len = 13;

            memcpy(val_tap_ikey, musig_agg + 1, 32);

            static serialized_extended_pubkey_t part_root;
            uint32_t part_path[] = {
                0x80000000UL | purpose,
                0x80000000UL | (uint32_t) BIP44_COIN_TYPE,
                0x80000000UL
            };
            if (CX_OK == get_extended_pubkey_at_path(part_path, 3,
                                                      BIP32_PUBKEY_VERSION, &part_root)) {
                memcpy(key_musig_nonce + 1, part_root.compressed_pubkey, 33);
            }
            memcpy(key_musig_nonce + 34, musig_agg, 33);
        }
    }

    /* Keys MUST be inserted in lexicographic order to match
     * check_merkle_tree_sorted() in the app.  Canonical order:
     * UTXO 0x00/0x01, SIGHASH 0x03, REDEEM 0x04, WITNESS 0x05,
     * BIP32 0x06+pk, PREV_TXID 0x0E, OUT_IDX 0x0F, SEQ 0x10,
     * TAP_BIP32 0x16+pk, TAP_INTERNAL_KEY 0x17, MUSIG2_PUB_NONCE 0x1B+... */
    static uint8_t utxo_key_byte;
    static uint8_t val_witness_utxo[8 + 1 + 34];

    if (inp->use_non_witness_utxo && inp->rawtx_len > 0) {
        utxo_key_byte = PSBT_IN_NON_WITNESS_UTXO;
        if (pm_map_add(&map, &utxo_key_byte, 1, inp->rawtx, inp->rawtx_len) < 0) {
            return -1;
        }
    } else {
        utxo_key_byte = PSBT_IN_WITNESS_UTXO;
        fuzz_write_u64_le(val_witness_utxo, inp->amount);
        val_witness_utxo[8] = (uint8_t)inp->scriptpubkey_len;
        memcpy(val_witness_utxo + 9, inp->scriptpubkey, inp->scriptpubkey_len);
        size_t val_wu_len = 9 + inp->scriptpubkey_len;

        if (pm_map_add(&map, &utxo_key_byte, 1, val_witness_utxo, val_wu_len) < 0) {
            return -1;
        }
    }

    if (inp->sighash_type != 0x00) {
        if (pm_map_add(&map, key_sighash, 1, val_sighash, 4) < 0) {
            return -1;
        }
    }

    static uint8_t key_redeem[1];
    if (inp->has_redeem_script && inp->redeem_script_len > 0) {
        key_redeem[0] = PSBT_IN_REDEEM_SCRIPT;
        if (pm_map_add(&map,
                       key_redeem,
                       1,
                       inp->redeem_script,
                       inp->redeem_script_len) < 0) {
            return -1;
        }
    }

    static uint8_t key_witness[1];
    if (inp->has_witness_script && inp->witness_script_len > 0) {
        key_witness[0] = PSBT_IN_WITNESS_SCRIPT;
        if (pm_map_add(&map,
                       key_witness,
                       1,
                       inp->witness_script,
                       inp->witness_script_len) < 0) {
            return -1;
        }
    }

    if (pm_map_add(&map, key_bip32, 34, val_bip32, val_bip32_len) < 0) {
        return -1;
    }

    if (pm_map_add(&map, key_prevtxid, 1, inp->prev_txid, 32) < 0) {
        return -1;
    }

    if (pm_map_add(&map, key_outidx, 1, val_outidx, 4) < 0) {
        return -1;
    }

    if (pm_map_add(&map, key_seq, 1, val_seq, 4) < 0) {
        return -1;
    }

    if (is_taproot_descriptor()) {
        if (pm_map_add(&map, key_tap_bip32, 33, val_tap_bip32, val_tap_bip32_len) < 0) {
            return -1;
        }
    }

    if (is_musig_descriptor()) {
        if (pm_map_add(&map, key_tap_ikey, 1, val_tap_ikey, 32) < 0) {
            return -1;
        }

        if (g_musig_round2) {
            if (pm_map_add(&map,
                           key_musig_nonce,
                           key_musig_nonce_len,
                           val_musig_nonce,
                           66) < 0) {
                return -1;
            }
        }
    }

    *n_entries_out = map.n_entries;
    return pm_map_finalize(host, &map, keys_root, values_root);
}

static int build_output_map(psbt_scenario_t *sc,
                            semantic_host_t *host,
                            int output_idx,
                            uint8_t keys_root[32],
                            uint8_t values_root[32],
                            int *n_entries_out) {
    pm_output_t *outp = &sc->outputs[output_idx];
    uint32_t purpose = PM_DESCRIPTORS[g_pm_desc_idx].purpose;
    uint32_t out_change = outp->is_change ? 1U : 0U;
    pm_merkle_map_t map;

    pm_map_reset(&map);

    static serialized_extended_pubkey_t out_child;
    if (CX_OK != pm_derive_child_xpub(purpose, 0,
                                       out_change, outp->bip32_addr_index,
                                       &out_child)) {
        return -1;
    }

    uint8_t val_bip32[4 + 5 * 4];
    memset(val_bip32, 0, 4);
    fuzz_write_u32_le(val_bip32 + 4,  0x80000000UL | purpose);
    fuzz_write_u32_le(val_bip32 + 8,  0x80000000UL | (uint32_t)BIP44_COIN_TYPE);
    fuzz_write_u32_le(val_bip32 + 12, 0x80000000UL);
    fuzz_write_u32_le(val_bip32 + 16, out_change);
    fuzz_write_u32_le(val_bip32 + 20, outp->bip32_addr_index);
    size_t val_bip32_len = 24;

    uint8_t key_bip32[34];
    key_bip32[0] = PSBT_OUT_BIP32_DERIVATION;
    memcpy(key_bip32 + 1, out_child.compressed_pubkey, 33);

    uint8_t key_tap_bip32[34];
    key_tap_bip32[0] = PSBT_OUT_TAP_BIP32_DERIVATION;
    memcpy(key_tap_bip32 + 1, out_child.compressed_pubkey + 1, 32);
    uint8_t val_tap_bip32[1 + 4 + 5 * 4];
    val_tap_bip32[0] = 0x00;
    memcpy(val_tap_bip32 + 1, val_bip32, val_bip32_len);
    size_t val_tap_bip32_len = 1 + val_bip32_len;

    if (is_musig_descriptor()) {
        static uint8_t musig_agg[33];
        uint32_t musig_fpr;
        if (0 == pm_compute_musig_aggregate(musig_agg, &musig_fpr)) {
            memcpy(key_tap_bip32 + 1, musig_agg + 1, 32);
            val_tap_bip32[0] = 0x00;
            write_u32_be(val_tap_bip32 + 1, 0, musig_fpr);
            fuzz_write_u32_le(val_tap_bip32 + 5, out_change);
            fuzz_write_u32_le(val_tap_bip32 + 9, outp->bip32_addr_index);
            val_tap_bip32_len = 13;
        }
    }

    uint8_t key_amount[1] = {PSBT_OUT_AMOUNT};
    uint8_t val_amount[8];
    fuzz_write_u64_le(val_amount, outp->amount);

    uint8_t key_script[1] = {PSBT_OUT_SCRIPT};

    /* Sorted key order: BIP32=0x02+pk, AMOUNT=0x03, SCRIPT=0x04,
     * TAP_BIP32=0x07+pk.  Must match check_merkle_tree_sorted(). */
    if (pm_map_add(&map, key_bip32, 34, val_bip32, val_bip32_len) < 0) {
        return -1;
    }

    if (pm_map_add(&map, key_amount, 1, val_amount, 8) < 0) {
        return -1;
    }

    if (pm_map_add(&map, key_script, 1, outp->scriptpubkey, outp->scriptpubkey_len) < 0) {
        return -1;
    }

    if (is_taproot_descriptor()) {
        if (pm_map_add(&map, key_tap_bip32, 33, val_tap_bip32, val_tap_bip32_len) < 0) {
            return -1;
        }
    }

    *n_entries_out = map.n_entries;
    return pm_map_finalize(host, &map, keys_root, values_root);
}

static int build_wallet_policy(psbt_scenario_t *sc, semantic_host_t *host) {
    const pm_descriptor_t *desc = &PM_DESCRIPTORS[g_pm_desc_idx];
    const char *descriptor = desc->descriptor;
    size_t desc_len = strlen(descriptor);

    // V2 stores sha256(descriptor) in place of the inline template and
    // requires the key_info to omit the "/**" wildcard suffix.  Force V2
    // whenever V1's syntax cannot represent the descriptor (inline "/**"
    // wildcard, multi-key registered sign, or musig round 1).
    int has_inline_wildcard = (strstr(descriptor, "/**") != NULL);
    int use_v2 = has_inline_wildcard ||
                 (sc->sign_mode == 1 && desc->n_keys > 1) ||
                 (sc->sign_mode == 3);

    int ki_tree = sh_tree_init(host);
    if (ki_tree < 0) return -1;

    for (int k = 0; k < desc->n_keys; k++) {
        /* Vary the account so each @N resolves to a distinct xpub; static
         * buffers survive the longjmp inside the crypto mock. */
        uint32_t account = (uint32_t) k;
        static serialized_extended_pubkey_t key_xpub;
        uint32_t path[] = {
            0x80000000UL | desc->purpose,
            0x80000000UL | (uint32_t)BIP44_COIN_TYPE,
            0x80000000UL | account
        };
        cx_err_t err = get_extended_pubkey_at_path(path, 3, BIP32_PUBKEY_VERSION, &key_xpub);
        if (err != CX_OK) return -1;

        static char xpub_str[MAX_SERIALIZED_PUBKEY_LENGTH + 1];
        int xpub_len = encode_xpub_internal(&key_xpub, xpub_str, sizeof(xpub_str) - 1);
        if (xpub_len < 0) return -1;
        xpub_str[xpub_len] = '\0';

        char key_info[256];
        int ki_len;
        if (use_v2) {
            ki_len = snprintf(key_info, sizeof(key_info),
                              "[00000000/%u'/%d'/%u']%s",
                              (unsigned)desc->purpose, BIP44_COIN_TYPE, (unsigned)account,
                              xpub_str);
        } else {
            ki_len = snprintf(key_info, sizeof(key_info),
                              "[00000000/%u'/%d'/%u']%s/**",
                              (unsigned)desc->purpose, BIP44_COIN_TYPE, (unsigned)account,
                              xpub_str);
        }
        if (ki_len < 0) return -1;

        sh_tree_add_leaf(host, ki_tree, (const uint8_t *)key_info, (size_t)ki_len);
    }
    sh_tree_finalize(host, ki_tree);

    uint8_t *p = sc->wallet_policy;

    if (use_v2) {
        /* V2: version | name_len | name | desc_len(varint) |
         *     sha256(descriptor)(32) | n_keys(varint) | keys_root(32). */
        static const char wallet_name[] = "mywallet";
        uint8_t name_len = (uint8_t) strlen(wallet_name);

        *p++ = WALLET_POLICY_VERSION_V2;
        *p++ = name_len;
        memcpy(p, wallet_name, name_len);
        p += name_len;
        p += fuzz_write_varint(p, desc_len);
        fuzz_sha256((const uint8_t *) descriptor, desc_len, p);
        p += 32;
        p += fuzz_write_varint(p, (uint64_t) desc->n_keys);
        memcpy(p, host->trees[ki_tree].root, 32);
        p += 32;
        sc->wallet_policy_len = (size_t) (p - sc->wallet_policy);

        sh_add_preimage(host, (const uint8_t *) descriptor, desc_len);
    } else {
        /* V1: version | name_len | desc_len(varint) | descriptor |
         *     n_keys(varint) | keys_root(32).  Registered mode gets a
         *     non-empty name; default/standard mode keeps name_len = 0. */
        static const char reg_name[] = "mywallet";
        uint8_t name_len = (sc->sign_mode == 1) ? (uint8_t) strlen(reg_name) : 0;

        *p++ = WALLET_POLICY_VERSION_V1;
        *p++ = name_len;
        if (name_len > 0) {
            memcpy(p, reg_name, name_len);
            p += name_len;
        }
        p += fuzz_write_varint(p, desc_len);
        memcpy(p, descriptor, desc_len);
        p += desc_len;
        p += fuzz_write_varint(p, (uint64_t) desc->n_keys);
        memcpy(p, host->trees[ki_tree].root, 32);
        p += 32;
        sc->wallet_policy_len = (size_t) (p - sc->wallet_policy);
    }

    fuzz_sha256(sc->wallet_policy, sc->wallet_policy_len, sc->wallet_id);

    sh_add_preimage(host, sc->wallet_policy, sc->wallet_policy_len);

    if (!compute_wallet_hmac(sc->wallet_id, sc->wallet_hmac)) {
        memset(sc->wallet_hmac, 0, 32);
    }

    return 0;
}

static const uint8_t pm_zero_slot[FUZZ_TAIL_SLOT_SIZE] = {0};

static inline const uint8_t *pm_slot(const uint8_t *slot_data, size_t slot_data_len, int idx) {
    size_t off = (size_t) idx * FUZZ_TAIL_SLOT_SIZE;
    if (slot_data && off + FUZZ_TAIL_SLOT_SIZE <= slot_data_len)
        return slot_data + off;
    return pm_zero_slot;
}

static uint8_t pm_decode_subtype_slot(const uint8_t *entropy,
                                      size_t entropy_len,
                                      const uint8_t *slot0) {
    uint8_t entropy_subtype = (entropy_len > 2) ? entropy[2] : 0;
    return (uint8_t) ((slot0[PM_SLOT0_SUBTYPE_OFF] + entropy_subtype) & 0x0F);
}

static uint8_t pm_pick_sign_mode(uint8_t subtype_slot) {
    if (subtype_slot < 6) {
        return PM_SIGN_MODE_DEFAULT;
    }
    if (subtype_slot < 10) {
        return PM_SIGN_MODE_REGISTERED;
    }
    if (subtype_slot < 14) {
        return PM_SIGN_MODE_RAWTX;
    }
    if (subtype_slot == 14) {
        return PM_SIGN_MODE_MUSIG_R1;
    }
    return PM_SIGN_MODE_MUSIG_R2;
}

static void pm_select_descriptor(uint8_t sign_mode, uint8_t desc_seed) {
    if (sign_mode == PM_SIGN_MODE_MUSIG_R1 ||
        sign_mode == PM_SIGN_MODE_MUSIG_R2) {
        g_pm_desc_idx = PM_MUSIG_DESC_START +
                        (desc_seed % (PM_N_DESCRIPTORS - PM_MUSIG_DESC_START));
    } else {
        g_pm_desc_idx = desc_seed % PM_MUSIG_DESC_START;
    }

    g_musig_round2 = (sign_mode == PM_SIGN_MODE_MUSIG_R2) ? 1 : 0;
}

static void pm_decode_global_controls(psbt_scenario_t *sc, const uint8_t *slot0) {
    sc->n_inputs = 1 + (slot0[PM_SLOT0_N_INPUTS_OFF] % PM_MAX_INPUTS);
    sc->n_outputs = 1 + (slot0[PM_SLOT0_N_OUTPUTS_OFF] % PM_MAX_OUTPUTS);
    if (sc->n_inputs > PM_MAX_INPUTS) sc->n_inputs = PM_MAX_INPUTS;
    if (sc->n_outputs > PM_MAX_OUTPUTS) sc->n_outputs = PM_MAX_OUTPUTS;

    sc->tx_version = fuzz_read_u32_le(slot0 + PM_SLOT0_TX_VERSION_OFF);
    sc->locktime = fuzz_read_u32_le(slot0 + PM_SLOT0_LOCKTIME_OFF);
}

static uint8_t pm_rawtx_output_count(const uint8_t *slot) {
    return 1 + (slot[PM_INPUT_SLOT_RAWTX_N_OUTS_OFF] & 0x07);
}

static void pm_decode_input_slot(pm_input_t *inp, const uint8_t *slot) {
    inp->output_index = (uint32_t) slot[PM_INPUT_SLOT_OUTPUT_INDEX_OFF];
    inp->amount = fuzz_read_u64_le(slot + PM_INPUT_SLOT_AMOUNT_OFF);
    inp->sequence = fuzz_read_u32_le(slot + PM_INPUT_SLOT_SEQUENCE_OFF);
    inp->sighash_type = slot[PM_INPUT_SLOT_SIGHASH_OFF];
    inp->bip32_change = slot[PM_INPUT_SLOT_CHANGE_OFF] & 1U;
    inp->bip32_addr_index =
        (uint32_t) fuzz_read_u16_le(slot + PM_INPUT_SLOT_ADDR_INDEX_OFF);
    build_input_script_bundle(inp, inp->bip32_change, inp->bip32_addr_index);
}

static void pm_build_inputs(psbt_scenario_t *sc,
                            const uint8_t *slot_data,
                            size_t slot_data_len,
                            int use_rawtx_mode) {
    for (int i = 0; i < sc->n_inputs; i++) {
        pm_input_t *inp = &sc->inputs[i];
        const uint8_t *slot = pm_slot(slot_data, slot_data_len, i);
        uint8_t rawtx_n_outs = pm_rawtx_output_count(slot);

        pm_decode_input_slot(inp, slot);

        if (use_rawtx_mode && inp->scriptpubkey_len > 0) {
            inp->output_index %= rawtx_n_outs;
            inp->rawtx_len = build_rawtx_for_prevout(
                inp->amount, inp->scriptpubkey, inp->scriptpubkey_len,
                inp->output_index, rawtx_n_outs,
                fuzz_read_u32_le(slot + PM_INPUT_SLOT_RAWTX_VERSION_OFF),
                fuzz_read_u32_le(slot + PM_INPUT_SLOT_RAWTX_LOCKTIME_OFF),
                inp->rawtx, sizeof(inp->rawtx),
                inp->prev_txid);
            inp->use_non_witness_utxo = (inp->rawtx_len > 0) ? 1 : 0;
        } else {
            memcpy(inp->prev_txid, slot + PM_INPUT_SLOT_PREV_TXID_OFF, 32);
            inp->use_non_witness_utxo = 0;
            inp->rawtx_len = 0;
        }
    }

}

static uint8_t pm_output_script_selector(const uint8_t *slot) {
    return (uint8_t) ((slot[PM_OUTPUT_SLOT_SCRIPT_HINT_A_OFF] +
                       slot[PM_OUTPUT_SLOT_SCRIPT_HINT_B_OFF]) % 6);
}

static void pm_decode_output_slot(pm_output_t *outp,
                                  const uint8_t *slot,
                                  int force_change) {
    uint8_t script_sel = pm_output_script_selector(slot);
    uint32_t out_change;

    outp->amount = fuzz_read_u64_le(slot + PM_OUTPUT_SLOT_AMOUNT_OFF);
    outp->bip32_addr_index = fuzz_read_u32_le(slot + PM_OUTPUT_SLOT_ADDR_INDEX_OFF);
    outp->is_change = (slot[PM_OUTPUT_SLOT_CHANGE_A_OFF] & 1) ||
                      (slot[PM_OUTPUT_SLOT_CHANGE_B_OFF] & 1) ||
                      force_change;

    out_change = outp->is_change ? 1U : 0U;
    if (!outp->is_change && script_sel == 4) {
        outp->amount = 0;
        build_scriptpubkey_for_type(4, 0, 0, outp->scriptpubkey,
                                    &outp->scriptpubkey_len);
    } else if (!outp->is_change && script_sel < 4) {
        build_scriptpubkey_for_type(script_sel, 0, outp->bip32_addr_index,
                                    outp->scriptpubkey, &outp->scriptpubkey_len);
    } else {
        build_wpkh_scriptpubkey(out_change, outp->bip32_addr_index,
                                outp->scriptpubkey, &outp->scriptpubkey_len);
    }
}

static void pm_build_outputs(psbt_scenario_t *sc,
                             const uint8_t *slot_data,
                             size_t slot_data_len) {
    for (int i = 0; i < sc->n_outputs; i++) {
        pm_output_t *outp = &sc->outputs[i];
        int slot_idx = sc->n_inputs + i;
        const uint8_t *slot = pm_slot(slot_data, slot_data_len, slot_idx);

        pm_decode_output_slot(outp, slot, i == sc->n_outputs - 1);
    }
}

static int pm_build_inputs_tree(psbt_scenario_t *sc, semantic_host_t *host) {
    int inputs_tree = sh_tree_init(host);
    if (inputs_tree < 0) return -1;

    for (int i = 0; i < sc->n_inputs; i++) {
        uint8_t kr[32], vr[32];
        uint8_t commit[65];
        int n_entries;

        if (build_input_map(sc, host, i, kr, vr, &n_entries) < 0) return -1;

        commit[0] = (uint8_t) n_entries;
        memcpy(commit + 1, kr, 32);
        memcpy(commit + 33, vr, 32);
        sh_tree_add_leaf(host, inputs_tree, commit, sizeof(commit));
        add_map_commitment_preimage(host, (int) commit[0], kr, vr);
    }

    sh_tree_finalize(host, inputs_tree);
    memcpy(sc->inputs_root, host->trees[inputs_tree].root, 32);
    return 0;
}

static int pm_build_outputs_tree(psbt_scenario_t *sc, semantic_host_t *host) {
    int outputs_tree = sh_tree_init(host);
    if (outputs_tree < 0) return -1;

    for (int i = 0; i < sc->n_outputs; i++) {
        uint8_t kr[32], vr[32];
        uint8_t commit[65];
        int n_entries;

        if (build_output_map(sc, host, i, kr, vr, &n_entries) < 0) return -1;

        commit[0] = (uint8_t) n_entries;
        memcpy(commit + 1, kr, 32);
        memcpy(commit + 33, vr, 32);
        sh_tree_add_leaf(host, outputs_tree, commit, sizeof(commit));
        add_map_commitment_preimage(host, (int) commit[0], kr, vr);
    }

    sh_tree_finalize(host, outputs_tree);
    memcpy(sc->outputs_root, host->trees[outputs_tree].root, 32);
    return 0;
}

int pm_build_scenario(psbt_scenario_t *sc,
                      semantic_host_t *host,
                      const uint8_t *entropy,
                      size_t entropy_len,
                      const uint8_t *slot_data,
                      size_t slot_data_len) {
    memset(sc, 0, sizeof(*sc));
    sh_reset(host);

    uint8_t e0 = (entropy_len > 0) ? entropy[0] : 0;
    const uint8_t *s0 = pm_slot(slot_data, slot_data_len, 0);

    /* SIGN_PSBT subtype distribution, selected from slot0[62] (with the
     * historical prefix nibble mixed in for corpus compatibility):
     *   slots  0..5  (6/16, 37.5%)  default
     *   slots  6..9  (4/16, 25.0%)  registered
     *   slots 10..13 (4/16, 25.0%)  rawtx
     *   slot 14      (1/16,  6.25%) musig round 1 (internal sign_mode 3)
     *   slot 15      (1/16,  6.25%) musig round 2 (internal sign_mode 4) */
    uint8_t subtype_slot = pm_decode_subtype_slot(entropy, entropy_len, s0);
    uint8_t desc_seed = s0[PM_SLOT0_DESCRIPTOR_OFF] ^ e0;
    int use_rawtx_mode;

    sc->sign_mode = pm_pick_sign_mode(subtype_slot);
    pm_select_descriptor(sc->sign_mode, desc_seed);
    pm_decode_global_controls(sc, s0);

    use_rawtx_mode = (sc->sign_mode == PM_SIGN_MODE_RAWTX);

    /* Input fields read from dense 64-byte tail slots.
     * Byte map per FUZZ_TAIL_SLOT_SIZE-byte input slot:
     *   [0..31]  prev_txid       (32 bytes, raw)
     *   [32]     output_index    (full byte, unclamped)
     *   [33..40] amount          (uint64 LE, full range)
     *   [41..44] sequence        (uint32 LE, fuzz-driven)
     *   [45]     sighash_type    (raw byte, any value)
     *   [46]     bip32_change    (bit 0)
     *   [47..48] bip32_addr_index (uint16 LE, unclamped)
     *   [50]     rawtx vout-count hint (hybrid)
     *   [51..54] rawtx version   (uint32 LE)
     *   [55..58] rawtx locktime  (uint32 LE)
     */
    pm_build_inputs(sc, slot_data, slot_data_len, use_rawtx_mode);

    /* Output fields — dense 64-byte tail slots.
     *   [0..7]  amount            (uint64 LE, full range)
     *   [8..11] bip32_addr_index  (uint32 LE)
     *   [10]/[12] script hints    (mixed to widen non-change script families)
     *   [11]/[13] is_change       (bit 0, fuzz-driven)
     */
    pm_build_outputs(sc, slot_data, slot_data_len);

    /* Pre-tree contradiction must run before the wallet policy and input/
     * output maps are built so the faulted fields propagate through every
     * preimage the continuation handler streams back. */
    pm_apply_pre_tree_fault(sc);

    if (build_wallet_policy(sc, host) < 0) return -1;
    if (build_global_map(sc, host) < 0) return -1;
    if (pm_build_inputs_tree(sc, host) < 0) return -1;
    if (pm_build_outputs_tree(sc, host) < 0) return -1;

    host->active = true;

    pm_apply_post_wallet_fault(sc);

    sc->apdu_len = pm_build_apdu(sc, sc->apdu, sizeof(sc->apdu));
    return 0;
}

size_t pm_build_apdu(const psbt_scenario_t *sc, uint8_t *buf, size_t max) {
    uint8_t *p = buf;
    uint8_t *end = buf + max;

    p += fuzz_write_varint(p, 2);
    if (p + 64 > end) return 0;
    memcpy(p, sc->global_root_keys, 32); p += 32;
    memcpy(p, sc->global_root_values, 32); p += 32;

    p += fuzz_write_varint(p, (uint64_t)sc->n_inputs);
    if (p + 32 > end) return 0;
    memcpy(p, sc->inputs_root, 32); p += 32;

    p += fuzz_write_varint(p, (uint64_t)sc->n_outputs);
    if (p + 32 > end) return 0;
    memcpy(p, sc->outputs_root, 32); p += 32;

    if (p + 64 > end) return 0;
    memcpy(p, sc->wallet_id, 32); p += 32;
    memcpy(p, sc->wallet_hmac, 32); p += 32;

    return (size_t)(p - buf);
}
