/* Wallet-policy scenarios for the fuzz harness.
 *
 * This file has exactly two jobs, and keeping them apart is the whole design:
 *
 *   content  -- the descriptor text, key count, name, version and key material.
 *               Every byte of it comes from the fuzz input, through wm_tape_t.
 *               Nothing here decides a value.
 *
 *   commitment -- serialize the policy, hash it, build the key-info Merkle tree,
 *               register the preimages the app will ask for. This is the only part
 *               that must be correct, because a commitment the host cannot answer
 *               ends the APDU before any app logic runs.
 *
 * There is no fault injector: corrupting a scalar before the Merkle trees are built
 * leaves every declared length, leaf count, proof and root self-consistent.
 * libFuzzer's own mutators serve that role, because the tape *is* the wire content.
 */

#include "wallet_model.h"
#include "fuzz_varint.h"
#include "mocks.h"

#include "base58.h"
#include "bip32.h"
#include "policy.h"  /* compute_wallet_hmac */
#include "wallet.h"
#include "write.h"
#include "constants.h"
#include "crypto.h"

#include <string.h>
#include <stdio.h>

/* ─── Layer 1: the tape ────────────────────────────────────────────────────
 *
 * A cursor over the harness input. Reads past the end return 0 rather than
 * failing, so a short input degrades to a simple descriptor instead of no
 * descriptor at all. This is the only source of values in the file.
 */
typedef struct {
    const uint8_t *p;
    size_t len;
    size_t off;
} wm_tape_t;

static uint8_t tape_u8(wm_tape_t *t) {
    return (t->off < t->len) ? t->p[t->off++] : 0;
}

static uint16_t tape_u16(wm_tape_t *t) {
    uint16_t hi = tape_u8(t);
    return (uint16_t) ((hi << 8) | tape_u8(t));
}

static uint32_t tape_u32(wm_tape_t *t) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        v = (v << 8) | tape_u8(t);
    }
    return v;
}

/* ─── Layer 2: content from the tape ───────────────────────────────────────── */

/* Bounded output buffer. On overflow len goes past cap and stays there, so callers
 * test wm_ok() once at the end instead of checking every append. */
typedef struct {
    char *buf;
    size_t cap;
    size_t len;
    int max_key;   /* highest @N emitted, so n_keys is derived rather than declared */
} wm_out_t;

static int wm_ok(const wm_out_t *o) { return o->len <= o->cap; }

static void wm_put(wm_out_t *o, const char *s, size_t n) {
    if (o->len + n > o->cap) { o->len = o->cap + 1; return; }
    memcpy(o->buf + o->len, s, n);
    o->len += n;
}

static void wm_putc(wm_out_t *o, char c) { wm_put(o, &c, 1); }
static void wm_puts(wm_out_t *o, const char *s) { wm_put(o, s, strlen(s)); }

static void wm_put_dec(wm_out_t *o, uint32_t v) {
    char tmp[12];
    int n = snprintf(tmp, sizeof(tmp), "%u", (unsigned) v);
    if (n > 0) wm_put(o, tmp, (size_t) n);
}

/* ─── The grammar, as data ──────────────────────────────────────────────────
 *
 * One expander walks a production string and substitutes from the tape. Making the
 * productions data rather than a switch per rule is what keeps this small: adding a
 * fragment is one table row, not a case block.
 *
 *   K  a key expression        S  a nested script (recurses)
 *   M  a multi-family token    D  decimal from one byte
 *   T  decimal from two bytes  U  decimal from four bytes
 *   H  32 hex-encoded bytes    *  repeat the preceding production, comma-separated
 *
 * Every count, index, depth and threshold above comes off the tape, which is the
 * whole point: the shapes that matter are the ones no fixed table contained.
 */
static const char *const WM_FRAGS[] = {
    "pk(K)", "pkh(K)", "M(D,K*)", "thresh(T,S*)",
    "and_v(v:S,S)", "or_d(S,S)", "older(U)", "sha256(H)",
};
static const char *const WM_MULTI[] = {"multi", "multi_a", "sortedmulti", "sortedmulti_a"};
static const char *const WM_CTX[] = {
    "wsh(S)", "sh(wsh(S))", "wpkh(K)", "pkh(K)", "tr(K)", "tr(K,S)",
};

/* @N, optionally with a BIP-389 suffix carrying two full 31-bit fields. The
 * catalogue only ever emitted <0;1>, <1;2> and <2;3>; those fields are what a
 * stride-desynchronised consumer reads as a type tag and a relative pointer. */
static void wm_key(wm_tape_t *t, wm_out_t *o) {
    size_t n = ((tape_u8(t) & 3u) == 3u) ? 2 + (size_t) (tape_u8(t) % 7u) : 0;
    if (n) wm_puts(o, "musig(");
    for (size_t i = 0; i <= n && wm_ok(o); i++) {
        if (i) wm_putc(o, ',');
        uint8_t k = (uint8_t) (tape_u8(t) % WM_MAX_KEYS);
        wm_putc(o, '@');
        wm_put_dec(o, k);
        if (k > o->max_key) o->max_key = k;
        if (!n) break;
    }
    if (n) wm_putc(o, ')');
    switch (tape_u8(t) % 3u) {
        case 0: wm_puts(o, "/**"); break;
        case 1:
            wm_puts(o, "/<");
            wm_put_dec(o, tape_u32(t) & 0x7FFFFFFFu);
            wm_putc(o, ';');
            wm_put_dec(o, tape_u32(t) & 0x7FFFFFFFu);
            wm_puts(o, ">/*");
            break;
        default: break;
    }
}

static void wm_expand(wm_tape_t *t, wm_out_t *o, const char *tpl, int budget);

/* A script is an optional wrapper run then a fragment. The app's wrapper loop is
 * flat and uncapped -- MAX_PARSE_SCRIPT_RECURSION_DEPTH does not count wrappers --
 * so depth is a value the fuzzer must own. The catalogue's maximum was 2. */
static void wm_script(wm_tape_t *t, wm_out_t *o, int budget) {
    if (budget <= 0 || !wm_ok(o)) {
        wm_puts(o, "pk(@0/**)");   /* always-legal bottom, so a short tape still balances */
        return;
    }
    size_t n_wrap = (size_t) (tape_u8(t) % 64u);
    if (n_wrap) {
        char w = "acdjlnstuv"[tape_u8(t) % 10u];
        /* Not `n_wrap--` in the condition: on the last iteration that evaluates 0,
         * exits correctly, and then wraps n_wrap to SIZE_MAX -- an unsigned overflow
         * UBSan reports on every descriptor with a wrapper run. */
        while (n_wrap > 0 && wm_ok(o)) {
            wm_putc(o, w);
            n_wrap--;
        }
        wm_putc(o, ':');
    }
    wm_expand(t, o, WM_FRAGS[tape_u8(t) % 8u], budget);
}

static void wm_one(wm_tape_t *t, wm_out_t *o, char c, int budget) {
    switch (c) {
        case 'K': wm_key(t, o); break;
        case 'S': wm_script(t, o, budget - 1); break;
        case 'M': wm_puts(o, WM_MULTI[tape_u8(t) % 4u]); break;
        case 'D': wm_put_dec(o, tape_u8(t)); break;
        case 'T': wm_put_dec(o, tape_u16(t)); break;
        case 'U': wm_put_dec(o, tape_u32(t)); break;
        case 'H':
            for (int i = 0; i < 32 && wm_ok(o); i++) {
                char hx[3];
                snprintf(hx, sizeof(hx), "%02x", tape_u8(t));
                wm_put(o, hx, 2);
            }
            break;
        default: wm_putc(o, c); break;
    }
}

static void wm_expand(wm_tape_t *t, wm_out_t *o, const char *tpl, int budget) {
    for (const char *c = tpl; *c && wm_ok(o); c++) {
        if (c[1] == '*') {
            size_t n = 1 + (size_t) (tape_u8(t) % 20u);
            for (size_t i = 0; i < n && wm_ok(o); i++) {
                if (i) wm_putc(o, ',');
                wm_one(t, o, *c, budget);
            }
            c++;   /* consume the '*' */
        } else {
            wm_one(t, o, *c, budget);
        }
    }
}

static size_t wm_emit_descriptor(wm_tape_t *t, char *buf, size_t cap, int *n_keys_out) {
    wm_out_t o = {.buf = buf, .cap = cap - 1, .len = 0, .max_key = 0};
    wm_expand(t, &o, WM_CTX[tape_u8(t) % 6u], 4);
    if (!wm_ok(&o)) return 0;
    buf[o.len] = '\0';
    int n = o.max_key + 1;
    *n_keys_out = (n > WM_MAX_KEYS) ? WM_MAX_KEYS : n;
    return o.len;
}

/* ─── The floor: key info the app can parse ────────────────────────────────
 *
 * parse_policy_map_key_info checks length 111/112, base58 decoding and the
 * checksum -- it does not check curve membership -- but a leaf that fails those
 * ends the conversation, so the shape stays real. The tape still chooses how many
 * keys there are and may replace any one of them with arbitrary bytes.
 */
static int build_key_info(int key_idx, uint32_t purpose, int version,
                          char *out, size_t out_len) {
    // Vary account per @N for distinct xpubs; static so it survives the
    // crypto-mock longjmp.
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

/* GET_WALLET_ADDRESS fields live in slot 0 at fixed offsets so that a mutation to
 * one does not disturb another. Everything else now comes off the tape. */
static const uint8_t wm_zero_slot[FUZZ_TAIL_SLOT_SIZE] = {0};

enum {
    WM_ADDR_DISPLAY_OFF = 32,
    WM_ADDR_IS_CHANGE_OFF = 33,
    WM_ADDR_INDEX_OFF = 34,
    WM_ADDR_USE_REGISTERED_OFF = 38,
    WM_ADDR_FLIP_HMAC_OFF = 39,
};

static inline const uint8_t *wm_slot(const uint8_t *slot_data, size_t slot_data_len, int idx) {
    size_t off = (size_t) idx * FUZZ_TAIL_SLOT_SIZE;
    if (slot_data && off + FUZZ_TAIL_SLOT_SIZE <= slot_data_len)
        return slot_data + off;
    return wm_zero_slot;
}

/* ─── Layer 3: the commitment keeper ──────────────────────────────────────── */

int wm_build_scenario(wallet_scenario_t *sc,
                      mock_dispatcher_t *host,
                      const uint8_t *entropy,
                      size_t entropy_len,
                      const uint8_t *slot_data,
                      size_t slot_data_len) {
    mock_dispatcher_reset(host);

    /* The tape starts after slot 0, which GET_WALLET_ADDRESS reserves for its own
     * fields; everything from slot 1 on is descriptor content. */
    wm_tape_t tape = {
        .p = slot_data ? slot_data + FUZZ_TAIL_SLOT_SIZE : NULL,
        .len = (slot_data_len > FUZZ_TAIL_SLOT_SIZE) ? slot_data_len - FUZZ_TAIL_SLOT_SIZE : 0,
        .off = 0,
    };

    uint8_t ctl = (entropy_len > 3) ? entropy[3] : 0;

    int n_keys = 1;
    sc->descriptor_len = wm_emit_descriptor(&tape, sc->descriptor,
                                           sizeof(sc->descriptor), &n_keys);
    if (sc->descriptor_len == 0) {
        return -1;
    }
    sc->n_keys = n_keys;

    /* Version from the tape. V1 cannot express a descriptor longer than
     * MAX_DESCRIPTOR_TEMPLATE_LENGTH_V1 or an inline wildcard, so a long one is forced
     * to V2 -- otherwise the app rejects it before the parser does anything. */
    sc->version = (ctl & 1u) ? WALLET_POLICY_VERSION_V2 : WALLET_POLICY_VERSION_V1;
    if (sc->version == WALLET_POLICY_VERSION_V1 &&
        (sc->descriptor_len > MAX_DESCRIPTOR_TEMPLATE_LENGTH_V1 ||
         strstr(sc->descriptor, "/**") != NULL)) {
        sc->version = WALLET_POLICY_VERSION_V2;
    }

    /* Name: length straight from the tape, including 0. Zero matters -- the
     * zero-HMAC branch in get_wallet_address requires name_len == 0, and the old
     * builder clamped it to at least 1, so that branch always died. */
    size_t name_len = (size_t) (tape_u8(&tape) % (sizeof(sc->name) - 1));
    sc->name_len = (uint8_t) name_len;
    for (size_t i = 0; i < name_len; i++) {
        sc->name[i] = (char) tape_u8(&tape);
    }

    /* A full 32-bit derivation index per key, not a pick from a table: the purpose
     * lands in key_info and in the derivation path, so the path parser needs boundary
     * and multi-digit indices too. One of the six standard BIP numbers three times in
     * four, so the standard-policy paths stay reachable. */
    for (int i = 0; i < sc->n_keys; i++) {
        static const uint32_t PURPOSES[] = {84, 44, 49, 86, 48, 45};
        sc->purposes[i] = ((tape_u8(&tape) & 3u) == 3u)
                              ? tape_u32(&tape)
                              : PURPOSES[tape_u8(&tape) % 6u];
    }

    /* Key-info leaves. One key in eight is replaced by arbitrary tape bytes, so the
     * key-info parser sees more than one malformed shape. */
    int ki_tree = mock_dispatcher_tree_begin(host);
    if (ki_tree < 0) return -1;

    for (int i = 0; i < sc->n_keys; i++) {
        char key_info[256];
        int ki_len;

        if ((tape_u8(&tape) & 0x07u) == 0x07u) {
            size_t n = (size_t) (tape_u8(&tape) % 120u);
            for (size_t j = 0; j < n; j++) {
                key_info[j] = (char) tape_u8(&tape);
            }
            ki_len = (int) n;
        } else {
            ki_len = build_key_info(i, sc->purposes[i], sc->version,
                                    key_info, sizeof(key_info));
        }
        if (ki_len < 0) return -1;
        if (mock_dispatcher_tree_add_leaf(host, ki_tree,
                                          (const uint8_t *) key_info,
                                          (size_t) ki_len) < 0) {
            return -1;
        }
    }
    mock_dispatcher_tree_end(host, ki_tree, sc->keys_info_root);

    /* Bound every write into wallet_policy[] before making it. */
    uint8_t *const wp_end = sc->wallet_policy + sizeof(sc->wallet_policy);
    if (2 + sc->name_len + 9 + 32 + 9 + 32 + sc->descriptor_len > sizeof(sc->wallet_policy)) {
        return -1;
    }

    uint8_t *p = sc->wallet_policy;
    *p++ = sc->version;
    *p++ = sc->name_len;
    memcpy(p, sc->name, sc->name_len);
    p += sc->name_len;

    /* The declared length is emitted from the tape, so it can disagree with the
     * descriptor actually served. The app checks exactly that
     * (policy.c: "Descriptor template length mismatch"), a branch the old builder
     * could never reach because one variable drove both. */
    uint64_t declared_len = sc->descriptor_len;
    if ((tape_u8(&tape) & 0x0Fu) == 0x0Fu) {
        declared_len = tape_u16(&tape);
    }

    if (sc->version == WALLET_POLICY_VERSION_V1) {
        p += fuzz_write_varint(p, declared_len);
        memcpy(p, sc->descriptor, sc->descriptor_len);
        p += sc->descriptor_len;
    } else {
        p += fuzz_write_varint(p, declared_len);
        uint8_t desc_sha[32];
        cx_hash_sha256((const uint8_t *) sc->descriptor, sc->descriptor_len, desc_sha, 32);
        memcpy(p, desc_sha, 32);
        p += 32;

        mock_dispatcher_add_preimage(host, (const uint8_t *) sc->descriptor,
                                     sc->descriptor_len);
    }

    /* Same for the key count: declared independently of the leaves served. */
    uint64_t declared_keys = (uint64_t) sc->n_keys;
    if ((tape_u8(&tape) & 0x0Fu) == 0x0Fu) {
        declared_keys = tape_u8(&tape);
    }
    p += fuzz_write_varint(p, declared_keys);
    memcpy(p, sc->keys_info_root, 32);
    p += 32;
    if (p > wp_end) {
        return -1;
    }
    sc->wallet_policy_len = (size_t) (p - sc->wallet_policy);

    cx_hash_sha256(sc->wallet_policy, sc->wallet_policy_len, sc->wallet_id, 32);
    mock_dispatcher_add_preimage(host, sc->wallet_policy, sc->wallet_policy_len);

    if (!compute_wallet_hmac(sc->wallet_id, sc->wallet_hmac)) {
        memset(sc->wallet_hmac, 0, 32);
    }

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

    /* Passed through unmasked. The old builder masked both to &1, which made
     * get_wallet_address's "is_change != 0 && is_change != 1" rejection dead code. */
    uint8_t display = s0[WM_ADDR_DISPLAY_OFF];
    uint8_t is_change = s0[WM_ADDR_IS_CHANGE_OFF];
    uint32_t address_index = U4LE(s0 + WM_ADDR_INDEX_OFF, 0);
    int use_registered = (s0[WM_ADDR_USE_REGISTERED_OFF] & 1) != 0;

    *ap++ = display;

    memcpy(ap, sc->wallet_id, 32);
    ap += 32;

    if (use_registered) {
        memcpy(ap, sc->wallet_hmac, 32);
    } else {
        memset(ap, 0, 32);
    }

    if (s0[WM_ADDR_FLIP_HMAC_OFF] & 1) {
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
