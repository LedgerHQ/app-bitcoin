#include "wallet_model.h"
#include "psbt_model.h"
#include "fuzz_sha256.h"
#include "fuzz_varint.h"
#include "mocks.h"

#include "base58.h"
#include "bip32.h"
#include "wallet.h"
#include "write.h"
#include "constants.h"
#include "crypto.h"

#include <string.h>
#include <stdio.h>

static void wm_inject_typed_fault(wallet_scenario_t *sc,
                                  const uint8_t *slot_data,
                                  size_t slot_data_len);

typedef struct {
    const char *descriptor;
    int n_keys;
    uint32_t purposes[WM_MAX_KEYS];
} descriptor_template_t;

// Descriptor catalog.  Row indices are referenced by generate-seed-corpus.py
// and by the disruption tests, so ordering is append-only.  See README.md
// "Descriptor templates" for the coverage-target grouping and the reason
// some rows require the V2 key-expression wildcard suffix ("@N/**").
static const descriptor_template_t TEMPLATES[] = {
    /*  0 */ {"wpkh(@0)",                               1, {84, 0, 0, 0, 0, 0}},
    /*  1 */ {"pkh(@0)",                                1, {44, 0, 0, 0, 0, 0}},
    /*  2 */ {"sh(wpkh(@0))",                           1, {49, 0, 0, 0, 0, 0}},
    /*  3 */ {"tr(@0)",                                 1, {86, 0, 0, 0, 0, 0}},
    /*  4 */ {"wsh(multi(2,@0,@1))",                    2, {48, 48, 0, 0, 0, 0}},
    /*  5 */ {"wsh(sortedmulti(2,@0,@1))",              2, {48, 48, 0, 0, 0, 0}},
    /*  6 */ {"tr(@0,pk(@1))",                          2, {86, 86, 0, 0, 0, 0}},
    /*  7 */ {"sh(multi(2,@0,@1))",                     2, {45, 45, 0, 0, 0, 0}},
    /*  8 */ {"wsh(and_v(v:pk(@0),pk(@1)))",            2, {48, 48, 0, 0, 0, 0}},
    /*  9 */ {"wsh(or_b(pk(@0),s:pk(@1)))",             2, {48, 48, 0, 0, 0, 0}},
    /* 10 */ {"wsh(or_i(pk(@0),pk(@1)))",               2, {48, 48, 0, 0, 0, 0}},
    /* 11 */ {"wsh(andor(pk(@0),pk(@1),pk(@2)))",       3, {48, 48, 48, 0, 0, 0}},
    /* 12 */ {"tr(@0,multi_a(2,@1,@2))",                3, {86, 86, 86, 0, 0, 0}},
    /* 13 */ {"tr(@0,sortedmulti_a(2,@1,@2))",          3, {86, 86, 86, 0, 0, 0}},
    /* 14 */ {"tr(@0,{pk(@1),pk(@2)})",                 3, {86, 86, 86, 0, 0, 0}},
    /* 15 */ {"wsh(thresh(2,pk(@0),s:pk(@1),s:pk(@2)))",3, {48, 48, 48, 0, 0, 0}},
    /* 16 */ {"wsh(and_v(v:older(10),pk(@0)))",         1, {48, 0, 0, 0, 0, 0}},
    /* 17 */ {"wsh(and_v(v:after(100),pk(@0)))",        1, {48, 0, 0, 0, 0, 0}},
    /* 18 */ {"wsh(and_v(v:sha256(e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855),pk(@0/**)))",
              1, {48, 0, 0, 0, 0, 0}},
    /* 19 */ {"wsh(andor(pk(@0),older(10),pk(@1)))",    2, {48, 48, 0, 0, 0, 0}},
    /* 20 */ {"wsh(and_b(pk(@0),a:pk(@1)))",            2, {48, 48, 0, 0, 0, 0}},
    /* 21 */ {"wsh(or_d(pk(@0/**),and_v(v:pkh(@1/**),older(1000))))",
              2, {48, 48, 0, 0, 0, 0}},
    /* 22 */ {"wsh(t:or_c(pk(@0),v:pkh(@1)))",          2, {48, 48, 0, 0, 0, 0}},
    /* 23 */ {"wsh(and_v(v:pk(@0),dv:older(1008)))",    1, {48, 0, 0, 0, 0, 0}},
    /* 24 */ {"wsh(and_v(v:pk(@0/**),or_i(j:pk(@1/**),pkh(@2/**))))",
              3, {48, 48, 48, 0, 0, 0}},
    /* 25 */ {"wsh(or_i(and_v(v:pk(@0),pk(@1)),pk(@2)))",
              3, {48, 48, 48, 0, 0, 0}},
    /* 26 */ {"wsh(and_n(pk(@0/**),and_v(v:pk(@1/**),older(144))))",
              2, {48, 48, 0, 0, 0, 0}},
    /* 27 */ {"wsh(and_v(v:pk(@0),u:older(42)))",       1, {48, 0, 0, 0, 0, 0}},
    /* 28 */ {"wsh(and_v(v:pk(@0),l:older(42)))",       1, {48, 0, 0, 0, 0, 0}},
    /* 29 */ {"wsh(or_d(pk(@0),and_n(pk(@1),older(10))))",
              2, {48, 48, 0, 0, 0, 0}},
    /* 30 */ {"wsh(c:pk_k(@0))",                        1, {48, 0, 0, 0, 0, 0}},
    /* 31 */ {"wsh(c:pk_h(@0))",                        1, {48, 0, 0, 0, 0, 0}},
    /* 32 */ {"wsh(or_i(pk(@0),0))",                    1, {48, 0, 0, 0, 0, 0}},
    /* 33 */ {"wsh(or_i(1,pk(@0)))",                    1, {48, 0, 0, 0, 0, 0}},
    /* 34 */ {"wsh(and_v(v:pk(@0),n:older(42)))",       1, {48, 0, 0, 0, 0, 0}},
    /* 35 */ {"wsh(j:pk(@0))",                          1, {48, 0, 0, 0, 0, 0}},
    /* 36 */ {"wsh(n:pk(@0))",                          1, {48, 0, 0, 0, 0, 0}},
    /* 37 */ {"wsh(l:pk(@0))",                          1, {48, 0, 0, 0, 0, 0}},
    /* 38 */ {"wsh(u:pk(@0))",                          1, {48, 0, 0, 0, 0, 0}},
    /* 39 */ {"wsh(and_v(v:pk(@0/**),hash160(cafebabecafebabecafebabecafebabecafebabe)))",
              1, {48, 0, 0, 0, 0, 0}},
    /* 40 */ {"wsh(and_v(v:pk(@0/**),ripemd160(deadbeefdeadbeefdeadbeefdeadbeefdeadbeef)))",
              1, {48, 0, 0, 0, 0, 0}},
    /* 41 */ {"wsh(and_v(v:pk(@0/**),hash256(1111111111111111111111111111111111111111111111111111111111111111)))",
              1, {48, 0, 0, 0, 0, 0}},
    /* 42 */ {"sh(wsh(multi(2,@0,@1)))",                2, {48, 48, 0, 0, 0, 0}},
    /* 43 */ {"sh(wsh(sortedmulti(2,@0,@1)))",          2, {48, 48, 0, 0, 0, 0}},
    /* 44 */ {"wsh(pk(@0/<0;1>/*))",                    1, {48, 0, 0, 0, 0, 0}},
    /* 45 */ {"tr(@0/<0;1>/*)",                         1, {86, 0, 0, 0, 0, 0}},
    /* 46 */ {"wsh(or_b(pk(@0),s:c:pk_k(@1)))",         2, {48, 48, 0, 0, 0, 0}},
    /* 47 */ {"wsh(thresh(3,pk(@0),s:pk(@1),s:pk(@2)))",3, {48, 48, 48, 0, 0, 0}},
    /* 48 */ {"wsh(and_b(1,s:pk(@0)))",                 1, {48, 0, 0, 0, 0, 0}},
    /* 49 */ {"wsh(and_v(v:pkh(@0),after(2500000000)))",1, {48, 0, 0, 0, 0, 0}},
    /* 50 */ {"wsh(and_v(v:pk(@0/<0;1>/*),pk(@0/<1;2>/*)))",
              1, {48, 0, 0, 0, 0, 0}},
    /* 51 */ {"wsh(and_v(v:pk(@0/<0;1>/*),pk(@0/<2;3>/*)))",
              1, {48, 0, 0, 0, 0, 0}},
    /* 52 */ {"tr(musig(@0,@1)/**)",                    2, {86, 86, 0, 0, 0, 0}},
    /* 53 */ {"tr(musig(@0,@1,@2)/**)",                 3, {86, 86, 86, 0, 0, 0}},
    /* 54 */ {"tr(musig(@0,@1)/**,pk(@2/**))",          3, {86, 86, 86, 0, 0, 0}},
    /* 55 */ {"tr(@0/**,pk(musig(@1,@2)/**))",          3, {86, 86, 86, 0, 0, 0}},
};

#define N_TEMPLATES (sizeof(TEMPLATES) / sizeof(TEMPLATES[0]))

static int build_key_info(int key_idx, uint32_t purpose, int version,
                          char *out, size_t out_len) {
    /* Vary the account component per key so each @N resolves to a distinct
     * xpub (avoids the "Repeated pubkey in wallet policy" rejection).
     * Static buffers so values survive longjmp inside the crypto mock. */
    static serialized_extended_pubkey_t key_xpub;
    uint32_t account = (uint32_t) key_idx;
    uint32_t path[] = {
        0x80000000UL | purpose,
        0x80000000UL | (uint32_t) BIP44_COIN_TYPE,
        0x80000000UL | account
    };
    cx_err_t err = get_extended_pubkey_at_path(path, 3, BIP32_PUBKEY_VERSION, &key_xpub);
    if (err != CX_OK) return -1;

    static serialized_extended_pubkey_check_t check;
    memcpy(&check.serialized_extended_pubkey, &key_xpub, sizeof(key_xpub));
    crypto_get_checksum((uint8_t *) &check.serialized_extended_pubkey,
                        sizeof(check.serialized_extended_pubkey),
                        check.checksum);

    static char xpub_str[120];
    int xpub_len = base58_encode((uint8_t *) &check, sizeof(check), xpub_str, sizeof(xpub_str) - 1);
    if (xpub_len < 0) return -1;
    xpub_str[xpub_len] = '\0';

    const char *suffix = (version == WALLET_POLICY_VERSION_V1) ? "/**" : "";

    return snprintf(out, out_len,
                    "[00000000/%u'/%d'/%u']%s%s",
                    (unsigned) purpose, BIP44_COIN_TYPE, (unsigned) account,
                    xpub_str, suffix);
}

/*
 * slot0[18] ^ entropy[3] flag byte layout used by wm_build_scenario:
 *   bit 0  V1 vs V2 serialization
 *   bit 1  empty name vs "mywallet"
 *   bit 2  corrupt one key_info (error path coverage)
 *   bit 3  use fuzz-driven wallet name from slot_data[0]
 */
static const uint8_t wm_zero_slot[FUZZ_TAIL_SLOT_SIZE] = {0};

enum {
    WM_SLOT_NAME_LEN_OFF = 1,
    WM_SLOT_NAME_DATA_OFF = 2,
    WM_SLOT_TEMPLATE_SEED_OFF = 16,
    WM_SLOT_FLAGS_OFF = 18,
    WM_SLOT_CORRUPT_KEY_OFF = 19,
    WM_SLOT_DISPLAY_OFF = 32,
    WM_SLOT_IS_CHANGE_OFF = 33,
    WM_SLOT_ADDRESS_INDEX_OFF = 34,
    WM_SLOT_USE_REGISTERED_OFF = 38,
    WM_SLOT_FLIP_HMAC_OFF = 39,
};

enum {
    WM_FAULT_SLOT_IDX = 1,
    WM_FAULT_KIND_OFF = 10,
};

static inline const uint8_t *wm_slot(const uint8_t *slot_data, size_t slot_data_len, int idx) {
    size_t off = (size_t) idx * FUZZ_TAIL_SLOT_SIZE;
    if (slot_data && off + FUZZ_TAIL_SLOT_SIZE <= slot_data_len)
        return slot_data + off;
    return wm_zero_slot;
}

static int wm_slot_count(size_t slot_data_len) {
    if (slot_data_len < FUZZ_TAIL_SLOT_SIZE) {
        return 0;
    }
    return (int) (slot_data_len / FUZZ_TAIL_SLOT_SIZE);
}

static int wm_select_template_index(const uint8_t *entropy,
                                    size_t entropy_len,
                                    const uint8_t *slot0,
                                    int n_slots) {
    int template_seed = (entropy_len > 2) ? entropy[2] : 0;
    if (n_slots > 0) {
        template_seed ^= (int) fuzz_read_u16_le(slot0 + WM_SLOT_TEMPLATE_SEED_OFF);
    }
    return template_seed % N_TEMPLATES;
}

static uint8_t wm_read_flags(const uint8_t *entropy,
                             size_t entropy_len,
                             const uint8_t *slot0) {
    return ((entropy_len > 3) ? entropy[3] : 0) ^ slot0[WM_SLOT_FLAGS_OFF];
}

static void wm_load_name(wallet_scenario_t *sc,
                         uint8_t flags,
                         const uint8_t *slot0,
                         int n_slots) {
    if (flags & 8 && n_slots > 0) {
        size_t raw_len = slot0[WM_SLOT_NAME_LEN_OFF];
        if (raw_len == 0) raw_len = 1;
        if (raw_len > 16) raw_len = 16;
        sc->name_len = (uint8_t) raw_len;
        memcpy(sc->name, slot0 + WM_SLOT_NAME_DATA_OFF, sc->name_len);
        return;
    }

    if (flags & 2) {
        const char *name = "mywallet";
        sc->name_len = (uint8_t) strlen(name);
        memcpy(sc->name, name, sc->name_len);
        return;
    }

    {
        const char *name = "w";
        sc->name_len = (uint8_t) strlen(name);
        memcpy(sc->name, name, sc->name_len);
    }
}

static void wm_mutate_descriptor(wallet_scenario_t *sc,
                                 const uint8_t *slot_data,
                                 size_t slot_data_len,
                                 int n_slots) {
    if (n_slots > 1) {
        const uint8_t *s1 = wm_slot(slot_data, slot_data_len, 1);
        if (s1[0] < 38 && sc->descriptor_len > 2) {
            size_t n_mutations = 1 + (s1[1] % 3);
            for (size_t mi = 0; mi < n_mutations; mi++) {
                size_t pos = s1[2 + mi] % sc->descriptor_len;
                sc->descriptor[pos] = (char) s1[5 + mi];
            }
        }
    }
}

static int wm_corrupt_key_index(const wallet_scenario_t *sc,
                                uint8_t flags,
                                const uint8_t *slot0) {
    if ((flags & 4) == 0) {
        return -1;
    }
    return (int) (slot0[WM_SLOT_CORRUPT_KEY_OFF] % sc->n_keys);
}

int wm_build_scenario(wallet_scenario_t *sc,
                      semantic_host_t *host,
                      const uint8_t *entropy,
                      size_t entropy_len,
                      const uint8_t *slot_data,
                      size_t slot_data_len) {
    memset(sc, 0, sizeof(*sc));
    sh_reset(host);

    const uint8_t *s0 = wm_slot(slot_data, slot_data_len, 0);
    int n_slots = wm_slot_count(slot_data_len);
    int template_idx = wm_select_template_index(entropy, entropy_len, s0, n_slots);
    const descriptor_template_t *tmpl = &TEMPLATES[template_idx];
    uint8_t flags = wm_read_flags(entropy, entropy_len, s0);
    sc->version = (flags & 1) ? WALLET_POLICY_VERSION_V2 : WALLET_POLICY_VERSION_V1;

    if (sc->version == WALLET_POLICY_VERSION_V1 &&
        strlen(tmpl->descriptor) > MAX_DESCRIPTOR_TEMPLATE_LENGTH_V1) {
        sc->version = WALLET_POLICY_VERSION_V2;
    }

    wm_load_name(sc, flags, s0, n_slots);

    sc->descriptor_len = strlen(tmpl->descriptor);
    memcpy(sc->descriptor, tmpl->descriptor, sc->descriptor_len);
    sc->n_keys = tmpl->n_keys;
    for (int i = 0; i < sc->n_keys; i++)
        sc->purposes[i] = tmpl->purposes[i];
    sc->has_wildcard = (sc->version == WALLET_POLICY_VERSION_V1) ? 1 : 0;

    /* ~15% near-valid descriptor mutation: a few random byte rewrites that
     * stress the policy parser's error handling without destroying framing. */
    wm_mutate_descriptor(sc, slot_data, slot_data_len, n_slots);

    int ki_tree = sh_tree_init(host);
    if (ki_tree < 0) return -1;

    int corrupt_key = wm_corrupt_key_index(sc, flags, s0);

    for (int i = 0; i < sc->n_keys; i++) {
        char key_info[256];
        int ki_len;

        if (i == corrupt_key) {
            ki_len = snprintf(key_info, sizeof(key_info), "INVALID_KEY_INFO_%d", i);
        } else {
            ki_len = build_key_info(i, sc->purposes[i], sc->version,
                                    key_info, sizeof(key_info));
        }
        if (ki_len < 0) return -1;
        sh_tree_add_leaf(host, ki_tree, (const uint8_t *) key_info, (size_t) ki_len);
    }
    sh_tree_finalize(host, ki_tree);
    memcpy(sc->keys_info_root, host->trees[ki_tree].root, 32);

    uint8_t *p = sc->wallet_policy;
    *p++ = sc->version;
    *p++ = sc->name_len;
    memcpy(p, sc->name, sc->name_len);
    p += sc->name_len;

    if (sc->version == WALLET_POLICY_VERSION_V1) {
        p += fuzz_write_varint(p, sc->descriptor_len);
        memcpy(p, sc->descriptor, sc->descriptor_len);
        p += sc->descriptor_len;
    } else {
        p += fuzz_write_varint(p, sc->descriptor_len);
        uint8_t desc_sha[32];
        fuzz_sha256((const uint8_t *) sc->descriptor, sc->descriptor_len, desc_sha);
        memcpy(p, desc_sha, 32);
        p += 32;

        sh_add_preimage(host, (const uint8_t *) sc->descriptor, sc->descriptor_len);
    }

    p += fuzz_write_varint(p, (uint64_t) sc->n_keys);
    memcpy(p, sc->keys_info_root, 32);
    p += 32;
    sc->wallet_policy_len = (size_t) (p - sc->wallet_policy);

    fuzz_sha256(sc->wallet_policy, sc->wallet_policy_len, sc->wallet_id);

    sh_add_preimage(host, sc->wallet_policy, sc->wallet_policy_len);

    if (!compute_wallet_hmac(sc->wallet_id, sc->wallet_hmac)) {
        memset(sc->wallet_hmac, 0, 32);
    }

    host->active = true;

    wm_inject_typed_fault(sc, slot_data, slot_data_len);

    uint8_t *ap = sc->apdu;
    uint8_t *ap_end = sc->apdu + sizeof(sc->apdu);

    ap += fuzz_write_varint(ap, sc->wallet_policy_len);
    if (ap + sc->wallet_policy_len > ap_end) return -1;
    memcpy(ap, sc->wallet_policy, sc->wallet_policy_len);
    ap += sc->wallet_policy_len;

    sc->apdu_len = (size_t) (ap - sc->apdu);
    return 0;
}

int wm_build_get_address_apdu(wallet_scenario_t *sc,
                              const uint8_t *slot_data,
                              size_t slot_data_len) {
    uint8_t *ap = sc->apdu;
    uint8_t *ap_end = sc->apdu + sizeof(sc->apdu);
    const uint8_t *s0 = wm_slot(slot_data, slot_data_len, 0);

    if (ap + 1 + 32 + 32 + 1 + 4 > ap_end) return -1;

    uint8_t display = s0[WM_SLOT_DISPLAY_OFF] & 1;
    uint8_t is_change = s0[WM_SLOT_IS_CHANGE_OFF] & 1;
    uint32_t address_index = fuzz_read_u32_le(s0 + WM_SLOT_ADDRESS_INDEX_OFF);
    int use_registered = (s0[WM_SLOT_USE_REGISTERED_OFF] & 1) != 0;

    *ap++ = display;

    memcpy(ap, sc->wallet_id, 32);
    ap += 32;

    if (use_registered) {
        memcpy(ap, sc->wallet_hmac, 32);
    } else {
        memset(ap, 0, 32);
    }

    if (s0[WM_SLOT_FLIP_HMAC_OFF] & 1) {
        for (int i = 0; i < 32; i++)
            ap[i] ^= 0xFF;
    }
    ap += 32;

    *ap++ = is_change;
    ap[0] = (uint8_t) ((address_index >> 24) & 0xFF);
    ap[1] = (uint8_t) ((address_index >> 16) & 0xFF);
    ap[2] = (uint8_t) ((address_index >> 8) & 0xFF);
    ap[3] = (uint8_t) (address_index & 0xFF);
    ap += 4;

    sc->apdu_len = (size_t) (ap - sc->apdu);
    return 0;
}

/*
 * ~25% per-iteration fault rate applied after the canonical wallet is built
 * (so the app sees a targeted contradiction rather than a random malformed
 * descriptor). slot1[10] carries both the gate and the fault kind.
 */
static void wm_inject_typed_fault(wallet_scenario_t *sc,
                                  const uint8_t *slot_data,
                                  size_t slot_data_len) {
    const uint8_t *s1 = wm_slot(slot_data, slot_data_len, WM_FAULT_SLOT_IDX);
    uint8_t fault_byte = s1[WM_FAULT_KIND_OFF];
    if (fault_byte >= 64) return;

    switch (fault_byte % 4) {
        case 0:
            for (int i = 0; i < 32; i++) sc->wallet_hmac[i] ^= 0xBB;
            break;
        case 1:
            if (sc->descriptor_len > 5) sc->descriptor_len = 3;
            break;
        case 2:
            sc->version = (sc->version == WALLET_POLICY_VERSION_V1) ?
                WALLET_POLICY_VERSION_V2 : WALLET_POLICY_VERSION_V1;
            break;
        case 3:
            sc->name_len = 0;
            break;
    }
}
