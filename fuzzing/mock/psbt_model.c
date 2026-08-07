#include "psbt_model.h"

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
#include "policy.h"  /* compute_wallet_hmac */

#include <string.h>
#include <stdio.h>

// Tail fault knobs select targeted corruption: pre-tree faults change scenario
// fields before the Merkle tree is built (so preimages stay consistent);
// post-wallet faults corrupt sealed wallet state (HMAC).
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

typedef struct {
    const char *descriptor;
    int n_keys;
    uint32_t purpose;
    uint8_t script_type;  /* 0=P2WPKH, 1=P2TR, 2=P2WSH, 3=P2SH-P2WPKH */
    int musig_n_keys;     /* keys inside musig() placeholder; 0 for non-musig */
} pm_descriptor_t;

// SIGN_PSBT descriptors: indices < PM_MUSIG_DESC_START are non-MuSig; the rest
// are MuSig-only (sign_mode 3/4).
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
    /* 40..51 had no reader in any builder; two of them now carry the declared
     * input/output counts, which must be independent of how many maps get built. */
    PM_SLOT0_DECL_INPUTS_OFF = 40,
    PM_SLOT0_DECL_OUTPUTS_OFF = 41,
    PM_SLOT0_TX_VERSION_OFF = 52,
    PM_SLOT0_LOCKTIME_OFF = 56,
    PM_SLOT0_N_INPUTS_OFF = 60,
    PM_SLOT0_N_OUTPUTS_OFF = 61,
    PM_SLOT0_SUBTYPE_OFF = 62,
    PM_SLOT0_DESCRIPTOR_OFF = 63,
};

#define PM_DESC_WSH_SORTEDMULTI 4

/* script_type == 4 is OP_RETURN; change / addr_index are ignored. */
// Build a coherent tail-driven prevout transaction so the recomputed txid
// matches the PSBT fields.
// Layout: version(4) | vin_count | vin | vout_count | vout | locktime(4)
static int add_merkleized_map(mock_dispatcher_t *host,
                              const uint8_t *keys[], const size_t *key_lens,
                              const uint8_t *values[], const size_t *value_lens,
                              int n_entries,
                              uint8_t root_keys[32], uint8_t root_values[32]) {
    int kt = mock_dispatcher_tree_begin(host);
    int vt = mock_dispatcher_tree_begin(host);
    if (kt < 0 || vt < 0) return -1;

    for (int i = 0; i < n_entries; i++) {
        /* A dropped leaf makes the root commit to fewer leaves than the APDU
         * declares, so the app's proof request for the missing index is refused
         * mid-conversation with no signal. Fail the scenario instead, as
         * message_model and wallet_model already do. */
        if (mock_dispatcher_tree_add_leaf(host, kt, keys[i], key_lens[i]) < 0 ||
            mock_dispatcher_tree_add_leaf(host, vt, values[i], value_lens[i]) < 0) {
            return -1;
        }
    }
    mock_dispatcher_tree_end(host, kt, NULL);
    mock_dispatcher_tree_end(host, vt, NULL);
    memcpy(root_keys, host->trees[kt].root, 32);
    memcpy(root_values, host->trees[vt].root, 32);
    return 0;
}

static int add_map_commitment_preimage(mock_dispatcher_t *host,
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
    mock_dispatcher_add_preimage(host, preimage, 1 + sizeof(commit));
    return 0;
}

static int build_global_map(psbt_scenario_t *sc, mock_dispatcher_t *host) {
    uint8_t key_version[1] = {PSBT_GLOBAL_TX_VERSION};
    uint8_t val_version[4];
    U4LE_ENCODE(val_version, 0, sc->tx_version);

    uint8_t key_locktime[1] = {PSBT_GLOBAL_FALLBACK_LOCKTIME};
    uint8_t val_locktime[4];
    U4LE_ENCODE(val_locktime, 0, sc->locktime);

    const uint8_t *keys[] = {key_version, key_locktime};
    const size_t key_lens[] = {1, 1};
    const uint8_t *vals[] = {val_version, val_locktime};
    const size_t val_lens[] = {4, 4};

    return add_merkleized_map(host, keys, key_lens, vals, val_lens, 2,
                              sc->global_root_keys, sc->global_root_values);
}


/* Referenced by zero-symbols.txt and fuzz_globals.zon so Absolution keeps
 * a zero-cost slot for it; no runtime use. */

// MuSig TAP_BIP32 carries the aggregate fingerprint + [change, index] only;
// cached per descriptor index.

typedef struct {
    const uint8_t *keys[16];
    size_t key_lens[16];
    const uint8_t *vals[16];
    size_t val_lens[16];
    int n_entries;
} pm_merkle_map_t;

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

static int pm_map_finalize(mock_dispatcher_t *host,
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

static int build_wallet_policy(psbt_scenario_t *sc, mock_dispatcher_t *host) {
    const pm_descriptor_t *desc = &PM_DESCRIPTORS[g_pm_desc_idx];
    const char *descriptor = desc->descriptor;
    size_t desc_len = strlen(descriptor);

    // Use V2 when V1 cannot represent the descriptor (inline "/**", multi-key
    // registered signing, or MuSig round 1).
    int has_inline_wildcard = (strstr(descriptor, "/**") != NULL);
    int use_v2 = has_inline_wildcard ||
                 (sc->sign_mode == 1 && desc->n_keys > 1) ||
                 (sc->sign_mode == 3);

    int ki_tree = mock_dispatcher_tree_begin(host);
    if (ki_tree < 0) return -1;

    for (int k = 0; k < desc->n_keys; k++) {
        // Vary account per @N for distinct xpubs; static survives the longjmp.
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

        mock_dispatcher_tree_add_leaf(host, ki_tree, (const uint8_t *)key_info, (size_t)ki_len);
    }
    mock_dispatcher_tree_end(host, ki_tree, NULL);

    uint8_t *p = sc->wallet_policy;

    if (use_v2) {
        // V2: version | name_len | name | desc_len | sha256(desc) | n_keys | keys_root.
        static const char wallet_name[] = "mywallet";
        uint8_t name_len = (uint8_t) strlen(wallet_name);

        *p++ = WALLET_POLICY_VERSION_V2;
        *p++ = name_len;
        memcpy(p, wallet_name, name_len);
        p += name_len;
        p += fuzz_write_varint(p, desc_len);
        cx_hash_sha256((const uint8_t *) descriptor, desc_len, p, 32);
        p += 32;
        p += fuzz_write_varint(p, (uint64_t) desc->n_keys);
        memcpy(p, host->trees[ki_tree].root, 32);
        p += 32;
        sc->wallet_policy_len = (size_t) (p - sc->wallet_policy);

        mock_dispatcher_add_preimage(host, (const uint8_t *) descriptor, desc_len);
    } else {
        // V1: version | name_len | desc_len | descriptor | n_keys | keys_root.
        // Registered mode (sign_mode 1) gets a name; otherwise name_len = 0.
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

    cx_hash_sha256(sc->wallet_policy, sc->wallet_policy_len, sc->wallet_id, 32);

    mock_dispatcher_add_preimage(host, sc->wallet_policy, sc->wallet_policy_len);

    if (!compute_wallet_hmac(sc->wallet_id, sc->wallet_hmac)) {
        memset(sc->wallet_hmac, 0, 32);
    }

    /* Derive the scriptPubKey this policy owns, so an input can be made internal.
     *
     * preprocess_inputs.c:363 aborts the whole command when every input is external,
     * and is_in_out_internal() calls an input internal only when its scriptPubKey
     * equals what the policy derives for some (change, address_index). That value is a
     * hash of a pubkey derived from the wallet's own xpub: the fuzzer cannot reach it
     * by mutation any more than it can reach a prevout txid.
     *
     * Same class of obligation as the key sort and the txid binding -- a real host
     * signing with this wallet always has matching scriptPubKeys. Everything about
     * which keys exist, their lengths and their contents still comes from the tape.
     *
     * Driven through the unit-test mock's own dispatcher context, which answers the
     * client commands in C. mock_dispatcher_reset() (called at the top of
     * pm_build_scenario) has already pointed g_active_mock at this host. */
    sc->wallet_spk_len = 0;
    {
        dispatcher_context_t *dc = mock_dispatcher_get_dc(host);
        buffer_t policy_buf = buffer_create(sc->wallet_policy, sc->wallet_policy_len);
        policy_map_wallet_header_t header;
        uint8_t descriptor_out[MAX_DESCRIPTOR_TEMPLATE_LENGTH];
        union {
            uint8_t bytes[MAX_WALLET_POLICY_BYTES];
            policy_node_t parsed;
        } policy_map;

        if (0 <= read_and_parse_wallet_policy(dc, &policy_buf, &header, descriptor_out,
                                              policy_map.bytes, sizeof(policy_map.bytes))) {
            uint8_t spk[34];
            int spk_len = get_wallet_script(
                dc, &policy_map.parsed,
                &(wallet_derivation_info_t) {.wallet_version = header.version,
                                             .keys_merkle_root = header.keys_info_merkle_root,
                                             .n_keys = header.n_keys,
                                             .change = 0,
                                             .address_index = 0},
                spk);
            if (spk_len > 0 && (size_t) spk_len <= sizeof(sc->wallet_spk)) {
                memcpy(sc->wallet_spk, spk, (size_t) spk_len);
                sc->wallet_spk_len = (size_t) spk_len;
            }

            /* And the key expression the policy's first key names at (0, 0).
             *
             * process_in_outs.c:110 returns "external" before the scriptPubKey is even
             * compared unless in_out_info->key_expression_found is set, and that is set
             * only by a PSBT_IN_BIP32_DERIVATION entry whose 33-byte pubkey the policy
             * derives, under the master fingerprint and path its key_info declares.
             * Both bindings are needed; the scriptPubKey alone leaves every input
             * external.
             *
             * build_wallet_policy writes key_info as "[00000000/purpose'/coin'/account']",
             * so the fingerprint is 00000000 and the path continues .../0/0. */
            static serialized_extended_pubkey_t leaf;
            uint32_t leaf_path[5] = {
                0x80000000UL | desc->purpose,
                0x80000000UL | (uint32_t) BIP44_COIN_TYPE,
                0x80000000UL,   /* account 0, matching key 0's key_info */
                0,              /* change */
                0,              /* address index */
            };
            if (CX_OK == get_extended_pubkey_at_path(leaf_path, 5, BIP32_PUBKEY_VERSION,
                                                     &leaf)) {
                memcpy(sc->wallet_pubkey, leaf.compressed_pubkey, 33);
                sc->wallet_pubkey_len = 33;

                uint8_t *d = sc->wallet_deriv;
                memset(d, 0, 4);                    /* master fingerprint 00000000 */
                for (size_t i = 0; i < 5; i++) {
                    U4LE_ENCODE(d + 4 + i * 4, 0, leaf_path[i]);
                }
                sc->wallet_deriv_len = 4 + 5 * 4;
            }
        }
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

}

static void pm_decode_global_controls(psbt_scenario_t *sc, const uint8_t *slot0) {
    /* How many maps get built, bounded because each one costs trees from the
     * per-scenario MOCK_MAX_TREES budget and tape from a finite supply. */
    sc->n_inputs = 1 + (slot0[PM_SLOT0_N_INPUTS_OFF] % PM_MAX_INPUTS);
    sc->n_outputs = 1 + (slot0[PM_SLOT0_N_OUTPUTS_OFF] % PM_MAX_OUTPUTS);

    /* What the APDU *declares*, which is a separate question. Serializing the number
     * actually built made the app's declared-count handling unreachable by
     * construction: sign_psbt reads these counts from the APDU and then asks the host
     * for that many leaves, so a count larger than the tree exercises the
     * out-of-range leaf request, and a smaller one leaves committed leaves unread.
     * Bounding the built count is a harness resource limit; bounding the declared
     * count would mirror a bound the app checks itself. */
    sc->declared_inputs = ((slot0[PM_SLOT0_N_INPUTS_OFF] & 0xF0u) == 0xF0u)
                              ? (int) slot0[PM_SLOT0_DECL_INPUTS_OFF]
                              : sc->n_inputs;
    sc->declared_outputs = ((slot0[PM_SLOT0_N_OUTPUTS_OFF] & 0xF0u) == 0xF0u)
                               ? (int) slot0[PM_SLOT0_DECL_OUTPUTS_OFF]
                               : sc->n_outputs;
    if (sc->n_inputs > PM_MAX_INPUTS) sc->n_inputs = PM_MAX_INPUTS;
    if (sc->n_outputs > PM_MAX_OUTPUTS) sc->n_outputs = PM_MAX_OUTPUTS;

    sc->tx_version = U4LE(slot0 + PM_SLOT0_TX_VERSION_OFF, 0);
    sc->locktime = U4LE(slot0 + PM_SLOT0_LOCKTIME_OFF, 0);
}

/* ─── Content from the tape (pm_tape_t lives in the header) ─────────── */

static uint8_t pm_tape_u8(pm_tape_t *t) {
    return (t->off < t->len) ? t->p[t->off++] : 0;
}

/* Sized so a whole scenario's demand fits the tape the harness actually supplies.
 *
 * Supply is slot_data_len - FUZZ_TAIL_SLOT_SIZE = 1988 bytes. Demand is
 * (1 global + n_inputs + n_outputs) maps, each costing 1 + E[n] * (3 + E[klen] +
 * E[vlen]) bytes. These values put demand at ~1000 bytes, 2x inside the supply.
 *
 * Fewer inputs and outputs, but funded ones: one input map carrying real key bytes
 * reaches preprocess_inputs, txhashes and psbt_parse_rawtx; five that zero-fill
 * reach none of them. */
#define PM_TAPE_MAP_MAX    12   /* entries per map the tape may request */
#define PM_TAPE_KV_MAX    128   /* ceiling for a key or value */
#define PM_TAPE_VAL_SHORT  40   /* the common case; covers 32B hashes and 33B pubkeys */

/* Read one PSBT map off the tape: an entry count, then per entry a key length, the
 * key bytes, a value length and the value bytes.
 *
 * Nothing is constrained. A key may be any length including zero, a value any
 * length, keys may repeat, and the count may exceed anything a real PSBT carries.
 * Key lengths are biased short because a PSBT key type is one byte -- that is a
 * shape prior, not a value constraint, and it is what lets libFuzzer's coverage
 * feedback find the key types that matter instead of guessing them uniformly.
 */
static int pm_map_from_tape(pm_tape_t *t, mock_dispatcher_t *host,
                            uint8_t kr[32], uint8_t vr[32], int *n_entries,
                            const psbt_scenario_t *sc) {
    static uint8_t kb[PM_TAPE_MAP_MAX][PM_TAPE_KV_MAX];
    static uint8_t vb[PM_TAPE_MAP_MAX][PM_TAPE_KV_MAX];
    pm_merkle_map_t map;
    memset(&map, 0, sizeof(map));

    size_t n = 1 + (size_t) (pm_tape_u8(t) % PM_TAPE_MAP_MAX);
    for (size_t i = 0; i < n; i++) {
        size_t kl = 1 + (size_t) (pm_tape_u8(t) % 4u);            /* short keys */
        /* 0x0F, not 0: see the exhaustion rule above *n_entries below. A tape that
         * has run out yields zeros, so testing == 0 here made every unfunded entry
         * take the rare long-key branch and land on kl = 0. */
        if ((pm_tape_u8(t) & 0x0Fu) == 0x0Fu) {
            kl = (size_t) (pm_tape_u8(t) % PM_TAPE_KV_MAX);        /* sometimes long, or 0 */
        }
        /* Values short by default with a long tail. Most PSBT values are a few bytes
         * -- an index, an amount, a 33-byte pubkey -- but PSBT_IN_NON_WITNESS_UTXO
         * carries a whole serialized transaction, so the tail has to reach ~100 bytes
         * for psbt_parse_rawtx to have anything to parse. Drawing uniformly over the
         * ceiling would cost 3x the tape for the same reach. */
        size_t vl = (size_t) (pm_tape_u8(t) % PM_TAPE_VAL_SHORT);
        if ((pm_tape_u8(t) & 0x07u) == 0x07u) {
            vl = (size_t) (pm_tape_u8(t) % PM_TAPE_KV_MAX);
        }
        for (size_t j = 0; j < kl; j++) kb[i][j] = pm_tape_u8(t);
        for (size_t j = 0; j < vl; j++) vb[i][j] = pm_tape_u8(t);
        if (pm_map_add(&map, kb[i], kl, vb[i], vl) < 0) break;
    }

    /* Sort by key, strictly, and drop equal keys.
     *
     * This is a commitment obligation, not content authoring: the app runs
     * check_merkle_tree_sorted() on every merkleized map it opens
     * (get_merkleized_map.c:41) and rejects any pair where
     * compare_byte_arrays(prev, cur) >= 0 -- so duplicates fail too. A map that is
     * not strictly ascending is rejected at leaf 2, before a single value is
     * fetched, which makes the whole tape unreadable rather than malformed.
     * Ordering a fuzz-chosen multiset decides no value; the keys, their lengths,
     * their contents and their number all still come from the tape.
     *
     * Insertion sort: n <= 16 here. */
    for (int i = 1; i < map.n_entries; i++) {
        for (int j = i; j > 0; j--) {
            size_t la = map.key_lens[j - 1], lb = map.key_lens[j];
            size_t m = la < lb ? la : lb;
            int c = m ? memcmp(map.keys[j - 1], map.keys[j], m) : 0;
            if (c < 0 || (c == 0 && la < lb)) break;
            const uint8_t *tk = map.keys[j - 1]; size_t tkl = map.key_lens[j - 1];
            const uint8_t *tv = map.vals[j - 1]; size_t tvl = map.val_lens[j - 1];
            map.keys[j - 1] = map.keys[j];       map.key_lens[j - 1] = map.key_lens[j];
            map.vals[j - 1] = map.vals[j];       map.val_lens[j - 1] = map.val_lens[j];
            map.keys[j] = tk;                    map.key_lens[j] = tkl;
            map.vals[j] = tv;                    map.val_lens[j] = tvl;
        }
    }
    int w = 0;
    for (int i = 0; i < map.n_entries; i++) {
        if (w > 0 && map.key_lens[w - 1] == map.key_lens[i] &&
            (map.key_lens[i] == 0 ||
             memcmp(map.keys[w - 1], map.keys[i], map.key_lens[i]) == 0)) {
            continue;   /* equal to its predecessor; the app rejects those */
        }
        map.keys[w] = map.keys[i];     map.key_lens[w] = map.key_lens[i];
        map.vals[w] = map.vals[i];     map.val_lens[w] = map.val_lens[i];
        w++;
    }
    map.n_entries = w;

    /* Bind PSBT_IN_PREVIOUS_TXID to the transaction PSBT_IN_NON_WITNESS_UTXO carries,
     * most of the time.
     *
     * amount_from_psbt.c:73 rejects an input whose PSBT_IN_PREVIOUS_TXID does not
     * equal the double-SHA256 of its PSBT_IN_NON_WITNESS_UTXO. No mutation can
     * produce that equality: it would mean guessing a 32-byte hash of bytes the
     * fuzzer also chose. So everything past that line -- the rest of
     * amount_from_psbt, and txhashes.c through sign_psbt.c:111 -- is unreachable at
     * any campaign length without the host discharging the binding. That is the same
     * class of obligation as the key sort above: a cryptographic commitment the host
     * must satisfy for the conversation to continue, not a value the harness chose.
     *
     * Deliberately not always. One time in sixteen the txid is left exactly as the
     * tape wrote it, so the mismatch rejection stays reachable as well. */
    if ((pm_tape_u8(t) & 0x0Fu) != 0x0Fu) {
        const uint8_t *rawtx = NULL;
        size_t rawtx_len = 0;
        uint8_t *txid = NULL;
        for (int i = 0; i < map.n_entries; i++) {
            if (map.key_lens[i] != 1) continue;
            if (map.keys[i][0] == PSBT_IN_NON_WITNESS_UTXO) {
                rawtx = map.vals[i];
                rawtx_len = map.val_lens[i];
            } else if (map.keys[i][0] == PSBT_IN_PREVIOUS_TXID && map.val_lens[i] == 32) {
                txid = (uint8_t *) map.vals[i];   /* points into vb[], writable */
            }
        }
        if (rawtx != NULL && txid != NULL && rawtx_len > 0) {
            uint8_t h[32];
            cx_hash_sha256(rawtx, rawtx_len, h, sizeof(h));
            cx_hash_sha256(h, sizeof(h), txid, 32);
        }

        /* Name the wallet's own key expression, so key_expression_found gets set. */
        if (sc != NULL && sc->wallet_pubkey_len > 0 && sc->wallet_deriv_len > 0) {
            for (int i = 0; i < map.n_entries; i++) {
                if (map.key_lens[i] != 1 + sc->wallet_pubkey_len) continue;
                if (map.keys[i][0] != PSBT_IN_BIP32_DERIVATION) continue;
                uint8_t *k = (uint8_t *) map.keys[i];   /* points into kb[], writable */
                uint8_t *v = (uint8_t *) map.vals[i];
                memcpy(k + 1, sc->wallet_pubkey, sc->wallet_pubkey_len);
                memcpy(v, sc->wallet_deriv, sc->wallet_deriv_len);
                map.val_lens[i] = sc->wallet_deriv_len;
                break;
            }
        }

        /* And make the witness utxo claim the wallet's own scriptPubKey, so
         * is_in_out_internal() can call the input internal. A witness utxo is
         * amount(8) | varint script_len | script; the amount and the tape's choice of
         * total length are left alone, only the script is replaced. */
        if (sc != NULL && sc->wallet_spk_len > 0) {
            for (int i = 0; i < map.n_entries; i++) {
                if (map.key_lens[i] != 1 || map.keys[i][0] != PSBT_IN_WITNESS_UTXO) continue;
                if (map.val_lens[i] < 8 + 1 + sc->wallet_spk_len) continue;
                uint8_t *v = (uint8_t *) map.vals[i];   /* points into vb[], writable */
                v[8] = (uint8_t) sc->wallet_spk_len;
                memcpy(v + 9, sc->wallet_spk, sc->wallet_spk_len);
                map.val_lens[i] = 8 + 1 + sc->wallet_spk_len;
                break;
            }
        }
    }

    /* Declared count from its own tape byte, so it can still disagree with the
     * leaves actually served -- the one disagreement a merkleized map allows.
     *
     * THE EXHAUSTION RULE, which every tape predicate in this tree must obey: reads
     * past the end of the tape yield 0, so a predicate written as `== 0` fires on
     * *every* unfunded read -- which would make an unfunded map declare itself empty.
     *
     * Testing 0x0F keeps the same 1-in-16 rate for the interesting disagreement
     * while making the degenerate case the benign one. */
    *n_entries = ((pm_tape_u8(t) & 0x0Fu) == 0x0Fu) ? (int) pm_tape_u8(t) : map.n_entries;
    return pm_map_finalize(host, &map, kr, vr);
}

static int pm_build_inputs_tree(psbt_scenario_t *sc, mock_dispatcher_t *host) {
    int inputs_tree = mock_dispatcher_tree_begin(host);
    if (inputs_tree < 0) return -1;

    for (int i = 0; i < sc->n_inputs; i++) {
        uint8_t kr[32], vr[32];
        uint8_t commit[65];
        int n_entries;

        if (pm_map_from_tape(&sc->tape, host, kr, vr, &n_entries, sc) < 0) return -1;

        commit[0] = (uint8_t) n_entries;
        memcpy(commit + 1, kr, 32);
        memcpy(commit + 33, vr, 32);
        if (mock_dispatcher_tree_add_leaf(host, inputs_tree, commit, sizeof(commit)) < 0)
            return -1;
        add_map_commitment_preimage(host, (int) commit[0], kr, vr);
    }

    mock_dispatcher_tree_end(host, inputs_tree, NULL);
    memcpy(sc->inputs_root, host->trees[inputs_tree].root, 32);
    return 0;
}

static int pm_build_outputs_tree(psbt_scenario_t *sc, mock_dispatcher_t *host) {
    int outputs_tree = mock_dispatcher_tree_begin(host);
    if (outputs_tree < 0) return -1;

    for (int i = 0; i < sc->n_outputs; i++) {
        uint8_t kr[32], vr[32];
        uint8_t commit[65];
        int n_entries;

        if (pm_map_from_tape(&sc->tape, host, kr, vr, &n_entries, sc) < 0) return -1;

        commit[0] = (uint8_t) n_entries;
        memcpy(commit + 1, kr, 32);
        memcpy(commit + 33, vr, 32);
        if (mock_dispatcher_tree_add_leaf(host, outputs_tree, commit, sizeof(commit)) < 0)
            return -1;
        add_map_commitment_preimage(host, (int) commit[0], kr, vr);
    }

    mock_dispatcher_tree_end(host, outputs_tree, NULL);
    memcpy(sc->outputs_root, host->trees[outputs_tree].root, 32);
    return 0;
}

int pm_build_scenario(psbt_scenario_t *sc,
                      mock_dispatcher_t *host,
                      const uint8_t *entropy,
                      size_t entropy_len,
                      const uint8_t *slot_data,
                      size_t slot_data_len) {
    /* Wire the mock's dispatcher_context_t the first time through.
     *
     * The fuzz path answers client commands with mock_dispatcher_handle_ccmd(), which
     * needs none of the dc callbacks, but build_wallet_policy() calls the app's own
     * get_wallet_script() through this dc, which goes through dc->add_to_response.
     * Testing the pointer rather than a static flag keeps it out of the invariant: a
     * sampled `already initialised` on the first iteration is a null-pointer call.
     *
     * Init before reset, never after: init zeroes the whole struct, which would
     * discard the trees and preimages a scenario has already registered. */
    if (host->dc.add_to_response == NULL) {
        mock_dispatcher_init(host);
    }
    memset(sc, 0, sizeof(*sc));
    mock_dispatcher_reset(host);

    /* The whole tail is one stream. Slot 0 stays reserved for the scenario controls
     * the harness reads directly; map content starts after it. */
    sc->tape.p = slot_data ? slot_data + FUZZ_TAIL_SLOT_SIZE : NULL;
    sc->tape.len = (slot_data_len > FUZZ_TAIL_SLOT_SIZE) ? slot_data_len - FUZZ_TAIL_SLOT_SIZE : 0;
    sc->tape.off = 0;

    uint8_t e0 = (entropy_len > 0) ? entropy[0] : 0;
    const uint8_t *s0 = pm_slot(slot_data, slot_data_len, 0);

    // SIGN_PSBT subtype from slot0[62]: 0..5 default, 6..9 registered,
    // 10..13 rawtx, 14 MuSig R1 (sign_mode 3), 15 MuSig R2 (sign_mode 4).
    uint8_t subtype_slot = pm_decode_subtype_slot(entropy, entropy_len, s0);
    uint8_t desc_seed = s0[PM_SLOT0_DESCRIPTOR_OFF] ^ e0;

    sc->sign_mode = pm_pick_sign_mode(subtype_slot);
    pm_select_descriptor(sc->sign_mode, desc_seed);
    pm_decode_global_controls(sc, s0);


    // Inputs and outputs read dense 64-byte tail slots at the PM_*_SLOT_*_OFF
    // offsets defined above.

    // Apply pre-tree faults before building wallet/maps so every streamed
    // preimage reflects them.

    if (build_wallet_policy(sc, host) < 0) return -1;
    if (build_global_map(sc, host) < 0) return -1;
    if (pm_build_inputs_tree(sc, host) < 0) return -1;
    if (pm_build_outputs_tree(sc, host) < 0) return -1;



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

    p += fuzz_write_varint(p, (uint64_t) sc->declared_inputs);
    if (p + 32 > end) return 0;
    memcpy(p, sc->inputs_root, 32); p += 32;

    p += fuzz_write_varint(p, (uint64_t) sc->declared_outputs);
    if (p + 32 > end) return 0;
    memcpy(p, sc->outputs_root, 32); p += 32;

    if (p + 64 > end) return 0;
    memcpy(p, sc->wallet_id, 32); p += 32;
    memcpy(p, sc->wallet_hmac, 32); p += 32;

    return (size_t)(p - buf);
}
