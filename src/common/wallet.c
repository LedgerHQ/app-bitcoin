#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "wallet.h"

/* SDK headers */
#include "base58.h"
#include "bip32.h"
#include "buffer.h"

/* Local headers */
#include "buffer_ext.h"
#include "debug.h"
#include "script.h"
#include "segwit_addr.h"
#include "sw.h"

#include "../crypto.h"

typedef struct {
    PolicyNodeType type;
    const char *name;
} token_descriptor_t;

static const token_descriptor_t KNOWN_TOKENS[] = {
    {.type = TOKEN_SH, .name = "sh"},
    {.type = TOKEN_WSH, .name = "wsh"},
    {.type = TOKEN_PKH, .name = "pkh"},
    {.type = TOKEN_WPKH, .name = "wpkh"},
    {.type = TOKEN_MULTI, .name = "multi"},
    {.type = TOKEN_MULTI_A, .name = "multi_a"},
    {.type = TOKEN_SORTEDMULTI, .name = "sortedmulti"},
    {.type = TOKEN_SORTEDMULTI_A, .name = "sortedmulti_a"},
    {.type = TOKEN_TR, .name = "tr"},

    // miniscript tokens (except wrappers)
    {.type = TOKEN_0, .name = "0"},
    {.type = TOKEN_1, .name = "1"},
    {.type = TOKEN_PK, .name = "pk"},
    {.type = TOKEN_PK_K, .name = "pk_k"},
    {.type = TOKEN_PK_H, .name = "pk_h"},
    {.type = TOKEN_OLDER, .name = "older"},
    {.type = TOKEN_AFTER, .name = "after"},
    {.type = TOKEN_SHA256, .name = "sha256"},
    {.type = TOKEN_HASH256, .name = "hash256"},
    {.type = TOKEN_RIPEMD160, .name = "ripemd160"},
    {.type = TOKEN_HASH160, .name = "hash160"},
    {.type = TOKEN_ANDOR, .name = "andor"},
    {.type = TOKEN_AND_V, .name = "and_v"},
    {.type = TOKEN_AND_B, .name = "and_b"},
    {.type = TOKEN_AND_N, .name = "and_n"},
    {.type = TOKEN_OR_B, .name = "or_b"},
    {.type = TOKEN_OR_C, .name = "or_c"},
    {.type = TOKEN_OR_D, .name = "or_d"},
    {.type = TOKEN_OR_I, .name = "or_i"},
    {.type = TOKEN_THRESH, .name = "thresh"},
};

// lookup table for characters that represent a valid miniscript wrapper fragment
const bool is_valid_miniscript_wrapper[] = {
    1,  // "a"
    0,  // "b"
    1,  // "c"
    1,  // "d"
    0,  // "e"
    0,  // "f"
    0,  // "g"
    0,  // "h"
    0,  // "i"
    1,  // "j"
    0,  // "k"
    1,  // "l"
    0,  // "m"
    1,  // "n"
    0,  // "o"
    0,  // "p"
    0,  // "q"
    0,  // "r"
    1,  // "s"
    1,  // "t"
    1,  // "u"
    1,  // "v"
    0,  // "w"
    0,  // "x"
    0,  // "y"
    0,  // "z"
};

/**
 * Length of the longest token in the policy wallet descriptor language (not including the
 * terminating \0 byte).
 */
#define MAX_TOKEN_LENGTH (sizeof("sortedmulti_a") - 1)

int read_wallet_policy_header(buffer_t *buffer, policy_map_wallet_header_t *header) {
    if (!buffer_read_u8(buffer, &header->version)) {
        return WITH_ERROR(-1, "Invalid wallet policy header");
    }

    if (header->version != WALLET_POLICY_VERSION_V1 &&
        header->version != WALLET_POLICY_VERSION_V2) {
        return WITH_ERROR(-1, "Invalid wallet policy header");
    }

    if (!buffer_read_u8(buffer, &header->name_len)) {
        return WITH_ERROR(-1, "Invalid wallet policy header");
    }

    if (header->name_len > MAX_WALLET_NAME_LENGTH) {
        return WITH_ERROR(-1, "Invalid wallet policy header");
    }

    if (!buffer_read_bytes(buffer, (uint8_t *) header->name, header->name_len)) {
        return WITH_ERROR(-1, "Invalid wallet policy header");
    }
    header->name[header->name_len] = '\0';

    uint64_t descriptor_template_len;
    if (!buffer_read_varint(buffer, &descriptor_template_len)) {
        return WITH_ERROR(-1, "Invalid wallet policy header");
    }

    if (header->version == WALLET_POLICY_VERSION_V1) {
        if (descriptor_template_len > MAX_DESCRIPTOR_TEMPLATE_LENGTH_V1) {
            return WITH_ERROR(-1, "Invalid wallet policy header: descriptor template too long");
        }
        if (!buffer_read_bytes(buffer,
                               (uint8_t *) header->descriptor_template,
                               descriptor_template_len)) {
            return WITH_ERROR(-1, "Invalid wallet policy header");
        }
    } else {  // WALLET_POLICY_VERSION_V2
        if (descriptor_template_len > MAX_DESCRIPTOR_TEMPLATE_LENGTH_V2) {
            return WITH_ERROR(-1, "Invalid wallet policy header: descriptor template too long");
        }

        if (!buffer_read_bytes(buffer, (uint8_t *) header->descriptor_template_sha256, 32)) {
            return WITH_ERROR(-1, "Invalid wallet policy header");
        }
    }

    header->descriptor_template_len = (uint16_t) descriptor_template_len;

    uint64_t n_keys;
    if (!buffer_read_varint(buffer, &n_keys) || n_keys > 252) {
        return WITH_ERROR(-1, "Invalid wallet policy header");
    }
    header->n_keys = (uint16_t) n_keys;

    if (!buffer_read_bytes(buffer, (uint8_t *) header->keys_info_merkle_root, 32)) {
        return WITH_ERROR(-1, "Invalid wallet policy header");
    }

    return 0;
}

static bool is_digit(char c) {
    return '0' <= c && c <= '9';
}

static bool is_alpha(char c) {
    return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z');
}

static bool is_alphanumeric(char c) {
    return is_alpha(c) || is_digit(c);
}

static bool is_lowercase_hex(char c) {
    return is_digit(c) || ('a' <= c && c <= 'f');
}

static uint8_t lowercase_hex_to_int(char c) {
    return (uint8_t) (is_digit(c) ? c - '0' : c - 'a' + 10);
}

static bool consume_character(buffer_t *in_buf, char expected) {
    char c;
    if (!buffer_peek(in_buf, (uint8_t *) &c) || c != expected) {
        return false;
    }
    buffer_seek_cur(in_buf, 1);
    return true;
}

static bool consume_characters(buffer_t *in_buf, const char *expected, size_t len) {
    char c;
    for (size_t i = 0; i < len; i++) {
        if (!buffer_peek_n(in_buf, i, (uint8_t *) &c) || c != expected[i]) {
            return false;
        }
    }
    buffer_seek_cur(in_buf, len);
    return true;
}

/**
 * Read up to out_len characters from buffer, until either:
 * - the buffer is exhausted
 * - out_len characters are read
 * - the next character is _not_ in [a-zAZ0-9_]
 */
static size_t read_token(buffer_t *buffer, char *out, size_t out_len) {
    size_t word_len = 0;
    char c;
    while (word_len < out_len && buffer_peek(buffer, (uint8_t *) &c) &&
           (is_alphanumeric(c) || c == '_')) {
        out[word_len++] = c;
        buffer_seek_cur(buffer, 1);
    }
    return word_len;
}

/**
 * Read the next word from buffer (or up to MAX_TOKEN_LENGTH characters), and
 * returns the index of this word in KNOWN_TOKENS if found; TOKEN_INVALID otherwise.
 */
static PolicyNodeType parse_token(buffer_t *buffer) {
    char word[MAX_TOKEN_LENGTH + 1];

    size_t word_len = read_token(buffer, word, MAX_TOKEN_LENGTH);
    word[word_len] = '\0';

    for (unsigned int i = 0; i < sizeof(KNOWN_TOKENS) / sizeof(KNOWN_TOKENS[0]); i++) {
        if (strncmp((const char *) PIC(KNOWN_TOKENS[i].name), word, MAX_TOKEN_LENGTH) == 0) {
            return ((const token_descriptor_t *) PIC(&KNOWN_TOKENS[i]))->type;
        }
    }
    return TOKEN_INVALID;
}

/**
 * Parses an unsigned decimal number from buffer, stopping when either the buffer ends, the next
 * character is not a number, or the number is already too big. Leading zeros are not allowed.
 * Returns a valid 0 on success, -1 on failure.
 * The read number is saved into *out on success.
 */
static int parse_unsigned_decimal(buffer_t *buffer, uint32_t *out) {
    uint8_t c;
    uint32_t result = 0;
    int digits_read = 0;
    while (buffer_peek(buffer, &c) && is_digit(c)) {
        ++digits_read;
        uint8_t next_digit = c - '0';

        if (digits_read == 2 && result == 0) {
            // if the first digit was a 0, then it should be the only digit
            return -1;
        }

        if (result > (UINT32_MAX - next_digit) / 10) {
            return -1;
        }

        result = 10 * result + next_digit;

        buffer_seek_cur(buffer, 1);
    }
    if (digits_read == 0) {
        return -1;
    }

    *out = result;

    return 0;
}

/**
 * Reads exactly 2*n lowercase hecadecimal characters, storing them in exactly n bytes in `out` (1
 * byte every two hex characters); returns -1 if any character is not hexadecimal, or if less than
 * 2*n characters can be read.
 */
static int buffer_read_hex_hash(buffer_t *buffer, uint8_t *out, size_t n) {
    if (!buffer_can_read(buffer, 2 * n)) {
        return -1;
    }

    for (unsigned int i = 0; i < n; i++) {
        uint8_t c1, c2;
        buffer_read_u8(buffer, &c1);
        buffer_read_u8(buffer, &c2);

        if (!is_lowercase_hex(c1) || !is_lowercase_hex(c2)) {
            return -1;
        }

        out[i] = 16 * lowercase_hex_to_int((char) c1) + lowercase_hex_to_int((char) c2);
    }
    return 0;
}

// Reads a derivation step expressed in decimal, with the symbol ' to mark if hardened (h is not
// supported) Returns 0 on success, -1 on error.
static int buffer_read_derivation_step(buffer_t *buffer, uint32_t *out) {
    uint32_t der_step;
    if (parse_unsigned_decimal(buffer, &der_step) == -1 || der_step >= BIP32_FIRST_HARDENED_CHILD) {
        PRINTF("Failed reading derivation step\n");
        return -1;
    }

    *out = der_step;

    // Check if hardened
    if (consume_character(buffer, '\'')) {
        *out |= BIP32_FIRST_HARDENED_CHILD;
    }
    return 0;
}

int parse_policy_map_key_info(buffer_t *buffer, policy_map_key_info_t *out, int version) {
    if (version != WALLET_POLICY_VERSION_V1 && version != WALLET_POLICY_VERSION_V2) {
        return WITH_ERROR(-1, "Invalid version");
    }

    memset(out, 0, sizeof(policy_map_key_info_t));

    if (consume_character(buffer, '[')) {
        out->has_key_origin = 1;

        if (!buffer_can_read(buffer, 9)) {  // at least 8 bytes + (closing parenthesis or '\')
            return -1;
        }
        for (int i = 0; i < 4; i++) {
            char num[2];
            buffer_read_bytes(buffer, (uint8_t *) num, 2);
            if (!is_lowercase_hex(num[0]) || !is_lowercase_hex(num[1])) {
                return -1;
            }
            out->master_key_fingerprint[i] =
                16 * lowercase_hex_to_int(num[0]) + lowercase_hex_to_int(num[1]);
        }

        // read all the given derivation steps
        out->master_key_derivation_len = 0;
        while (consume_character(buffer, '/')) {
            if (out->master_key_derivation_len >= MAX_BIP388_XPUB_DERIVATION_STEPS) {
                return WITH_ERROR(-1, "Too many derivation steps");
            }

            if (buffer_read_derivation_step(
                    buffer,
                    &out->master_key_derivation[out->master_key_derivation_len]) == -1) {
                return -1;
            };

            ++out->master_key_derivation_len;
        }

        // the next character must be ']'
        if (!consume_character(buffer, ']')) {
            return WITH_ERROR(-1, "Expected ']'");
        }
    }

    // consume the rest of the buffer into the pubkey, except possibly the final "/**"
    unsigned int ext_pubkey_len = 0;
    char ext_pubkey_str[MAX_SERIALIZED_PUBKEY_LENGTH + 1];
    uint8_t c;
    while (ext_pubkey_len < MAX_SERIALIZED_PUBKEY_LENGTH && buffer_peek(buffer, &c) &&
           is_alphanumeric(c)) {
        ext_pubkey_str[ext_pubkey_len] = c;
        ++ext_pubkey_len;
        buffer_seek_cur(buffer, 1);
    }
    ext_pubkey_str[ext_pubkey_len] = '\0';

    if (ext_pubkey_len < 111 || ext_pubkey_len > 112) {
        // loose sanity check; pubkeys in bitcoin can be 111 or 112 characters long
        return WITH_ERROR(-1, "Invalid extended pubkey length");
    }

    serialized_extended_pubkey_check_t ext_pubkey_check;
    if (base58_decode(ext_pubkey_str,
                      ext_pubkey_len,
                      (uint8_t *) &ext_pubkey_check,
                      sizeof(ext_pubkey_check)) < 0) {
        return WITH_ERROR(-1, "Error decoding serialized extended pubkey");
    }

    // verify checksum
    uint8_t checksum[4];
    crypto_get_checksum((uint8_t *) &ext_pubkey_check.serialized_extended_pubkey,
                        sizeof(ext_pubkey_check.serialized_extended_pubkey),
                        checksum);

    if (memcmp(&ext_pubkey_check.checksum, checksum, sizeof(checksum)) != 0) {
        return WITH_ERROR(-1, "Wrong extended pubkey checksum");
    }

    out->ext_pubkey = ext_pubkey_check.serialized_extended_pubkey;

    // either the string terminates now, or it has a final "/**" suffix for the wildcard.
    if (!buffer_can_read(buffer, 1)) {
        // no wildcard; this is an error in V1
        if (version == WALLET_POLICY_VERSION_V1) {
            return WITH_ERROR(
                -1,
                "Invalid key expression; keys in V1 wallet policies must end with /**.");
        }

        return 0;
    }

    // in V2, key expressions terminate with the key (no wildcards)
    if (version == WALLET_POLICY_VERSION_V2) {
        return WITH_ERROR(-1, "Invalid key expression; must terminate after the key/xpub");
    }

    out->has_wildcard = 1;

    // Only the final "/**" suffix should be left
    uint8_t wildcard[3];
    // Make sure that the buffer is indeed exhausted
    if (!buffer_read_bytes(buffer, wildcard, 3)  // should be able to read 3 characters
        || buffer_can_read(buffer, 1)            // but nothing more
        || wildcard[0] != '/'                    // suffix should be exactly "/**"
        || wildcard[1] != '*' || wildcard[2] != '*') {
        return -1;
    }

    return 0;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcomment"
// The compiler doesn't like /** inside a block comment, so we disable this warning temporarily.

/**
 * Parses a key expression, in one of the following forms:
 * - Single key index:
 *   - @IDX/**
 *   - @IDX/<M;N>/*
 * - MuSig2 aggregate key (only if allow_musig is true):
 *   - musig(@IDX,@IDX,...,@IDX)/**
 *   - musig(@IDX,@IDX,...,@IDX)/<M;N>/*
 * where IDX is a key index.
 */
#pragma GCC diagnostic pop
static int parse_keyexpr(buffer_t *in_buf,
                         int version,
                         policy_node_keyexpr_t *out,
                         bool allow_musig,
                         buffer_t *out_buf,
                         uint16_t *keyexpr_index) {
    char c;
    if (!buffer_read_u8(in_buf, (uint8_t *) &c)) {
        return WITH_ERROR(-1, "Expected key expression");
    }

    if (c == '@') {
        out->type = KEY_EXPRESSION_NORMAL;

        uint32_t k;
        if (parse_unsigned_decimal(in_buf, &k) == -1 || k > INT16_MAX) {
            return WITH_ERROR(-1, "The key index in a placeholder must be at most 32767");
        }

        out->k.key_index = (int16_t) k;
    } else if (c == 'm') {
        // parse a musig(key1,...,keyn) expression, where each key is a key expression
        if (!consume_characters(in_buf, "usig(", 5)) {
            return WITH_ERROR(-1, "Expected musig key expression");
        }

        if (!allow_musig) {
            return WITH_ERROR(-1, "musig is only allowed in taproot");
        }

        out->type = KEY_EXPRESSION_MUSIG;

        if (version != WALLET_POLICY_VERSION_V2) {
            return WITH_ERROR(-1, "musig key expressions are only supported with version number 2");
        }

        uint16_t keys[MAX_PUBKEYS_PER_MUSIG];
        int n_musig_keys = 0;

        // parse comma-separated list of @NUM
        while (true) {
            if (!buffer_read_u8(in_buf, (uint8_t *) &c) || c != '@') {
                return WITH_ERROR(-1, "Expected key placeholder starting with '@'");
            }

            uint32_t k;
            if (parse_unsigned_decimal(in_buf, &k) == -1 || k > INT16_MAX) {
                return WITH_ERROR(-1, "The key index in a placeholder must be at most 32767");
            }

            if (n_musig_keys >= MAX_PUBKEYS_PER_MUSIG) {
                return WITH_ERROR(-1, "Too many keys in musig");
            }

            keys[n_musig_keys] = (uint16_t) k;
            ++n_musig_keys;

            // the next character must be "," if there are more keys, or ')' otherwise
            if (!buffer_read_u8(in_buf, (uint8_t *) &c)) {
                return WITH_ERROR(-1, "Expression terminated prematurely");
            }

            if (c == ')') {
                break;
            } else if (c != ',') {
                return WITH_ERROR(-1, "Invalid character in musig; expected ',' or ')'");
            }
        }

        if (n_musig_keys < 2) {
            return WITH_ERROR(-1, "musig must have at least 2 key indexes");
        }

        // sanity check; the loop above should never exit with too many keys
        LEDGER_ASSERT(n_musig_keys <= MAX_PUBKEYS_PER_MUSIG, "Too many keys in musig");

        // allocate musig structures

        musig_aggr_key_info_t *musig_info =
            (musig_aggr_key_info_t *) buffer_alloc(out_buf, sizeof(musig_aggr_key_info_t), true);

        if (musig_info == NULL) {
            return WITH_ERROR(-1, "Out of memory");
        }

        uint16_t *key_indexes =
            (uint16_t *) buffer_alloc(out_buf, sizeof(uint16_t) * n_musig_keys, true);
        if (key_indexes == NULL) {
            return WITH_ERROR(-1, "Out of memory");
        }
        memcpy(key_indexes, keys, sizeof(uint16_t) * n_musig_keys);

        musig_info->n = n_musig_keys;
        i_uint16(&musig_info->key_indexes, key_indexes);

        i_musig_aggr_key_info(&out->m.musig_info, musig_info);
    } else {
        return WITH_ERROR(-1, "Expected key expression starting with '@', or musig");
    }

    if (version == WALLET_POLICY_VERSION_V1) {
        // default values for compatibility with the new code
        out->num_first = 0;
        out->num_second = 1;
    } else if (version == WALLET_POLICY_VERSION_V2) {
        // the key expression must be followed by / and **, or /<0;1>/*
        uint8_t next_character;
        if (!consume_character(in_buf, '/')           // the next character is "/"
            || !buffer_peek(in_buf, &next_character)  // we must be able to read the next character
            || !(next_character == '*' || next_character == '<')  // and it must be '*' or '<'
        ) {
            return WITH_ERROR(-1, "Expected /** or /<M;N>/* in key expression");
        }

        if (next_character == '*') {
            if (!consume_characters(in_buf, "**", 2)) {
                return WITH_ERROR(-1, "Expected /** or /<M;N>/* in key expression");
            }
            out->num_first = 0;
            out->num_second = 1;
        } else if (next_character == '<') {
            buffer_seek_cur(in_buf, 1);  // skip "<"
            if (parse_unsigned_decimal(in_buf, &out->num_first) == -1 ||
                out->num_first > 0x80000000u) {
                return WITH_ERROR(
                    -1,
                    "Expected /** or /<M;N>/* in key expression, with unhardened M and N");
            }

            if (!consume_character(in_buf, ';')) {
                return WITH_ERROR(-1, "Expected /** or /<M;N>/* in key expression");
            }

            if (parse_unsigned_decimal(in_buf, &out->num_second) == -1 ||
                out->num_second > 0x80000000u) {
                return WITH_ERROR(
                    -1,
                    "Expected /** or /<M;N>/* in key expression, with unhardened M and N");
            }

            if (out->num_first == out->num_second) {
                return WITH_ERROR(-1, "M and N must be different in <M;N>/*");
            }

            if (!consume_characters(in_buf, ">/*", 3)) {
                return WITH_ERROR(-1, "Expected /** or /<M;N>/* in key expression");
            }
        }
    } else {
        return WITH_ERROR(-1, "Invalid version number");
    }

    out->keyexpr_index = *keyexpr_index;
    ++(*keyexpr_index);
    return 0;
}

#define CONTEXT_WITHIN_SH  1  // parsing a direct child of SH
#define CONTEXT_WITHIN_WSH 2  // parsing a direct child of WSH
#define CONTEXT_WITHIN_TR  4  // parsing a child of TR (direct or not)

// The remaining bits of the context flags count the THRESH nodes that contain the script being
// parsed. Each of them costs about 600 bytes of stack while the extended info of the policy is
// computed (see compute_thresh_ops), therefore their nesting is limited by MAX_THRESH_NESTING;
// policies with thresh expressions with more nesting seem unlikely to be used in practice.
#define CONTEXT_THRESH_NESTING_UNIT   8
#define CONTEXT_THRESH_NESTING(flags) ((flags) / CONTEXT_THRESH_NESTING_UNIT)

// forward declaration
static int parse_script(buffer_t *in_buf,
                        buffer_t *out_buf,
                        int version,
                        size_t depth,
                        unsigned int context_flags);

static int parse_child_scripts(buffer_t *in_buf,
                               buffer_t *out_buf,
                               size_t depth,
                               rptr_policy_node_t child_scripts[],
                               int n_children,
                               int version,
                               unsigned int context_flags) {
    // the internal scripts are recursively parsed (if successful) in the current location
    // of the output buffer

    for (int child_index = 0; child_index < n_children; child_index++) {
        buffer_alloc(out_buf, 0, true);  // ensure alignment of current pointer
        i_policy_node(&child_scripts[child_index], buffer_get_cur(out_buf));

        if (0 > parse_script(in_buf, out_buf, version, depth + 1, context_flags)) {
            // failed while parsing internal script
            return -1;
        }

        // the next character must be a comma (except after the last child)
        if (child_index <= n_children - 2 && !consume_character(in_buf, ',')) {
            return WITH_ERROR(-1, "Expected ','");
        }
    }
    return 0;
}

// forward-declaration, since it's used in parse_script
static int parse_tree(buffer_t *in_buf, buffer_t *out_buf, int version, size_t depth);

/**
 * Parses a SCRIPT expression from the in_buf buffer, allocating the nodes and variables in out_buf.
 * The initial pointer in out_buf will contain the root node of the SCRIPT.
 */
static int parse_script(buffer_t *in_buf,
                        buffer_t *out_buf,
                        int version,
                        size_t depth,
                        unsigned int context_flags) {
    if (depth > MAX_PARSE_SCRIPT_RECURSION_DEPTH) {
        return WITH_ERROR(-1, "Script is too deeply nested");
    }

    int n_wrappers = 0;

    // Keep track of how many key expressions have been created while parsing
    // This allows to know the counter even in recursive calls
    static uint16_t key_expression_count = 0;

    if (depth == 0) {
        // reset the counter on function entry, but not in recursive calls
        key_expression_count = 0;
    }

    policy_node_t *outermost_node = (policy_node_t *) buffer_get_cur(out_buf);
    policy_node_with_script_t *inner_wrapper = NULL;  // pointer to the inner wrapper, if any

    // miniscript-related parsing only within top-level WSH, or within tr
    bool parse_as_miniscript =
        ((context_flags & CONTEXT_WITHIN_WSH) != 0 && (context_flags & CONTEXT_WITHIN_SH) == 0) ||
        (context_flags & CONTEXT_WITHIN_TR) != 0;

    if (parse_as_miniscript) {
        // look ahead to finds out if the buffer starts with alphanumeric digits that could be
        // wrappers, followed by a colon
        char c;
        bool can_read;
        while (true) {
            can_read = buffer_peek_n(in_buf, n_wrappers, (uint8_t *) &c);
            if (can_read && 'a' <= c && c <= 'z' && is_valid_miniscript_wrapper[c - 'a']) {
                ++n_wrappers;
            } else {
                break;
            }
        }

        if (can_read && c == ':') {
            // The wrappers are parsed in this same stack frame, but each of them creates a node
            // containing the following one; therefore, they must be charged to the recursion
            // budget explicitly. Otherwise, a short chain of wrappers that type-checks for any
            // length (for example "nnn...n:pk(@0/**)") would produce an arbitrarily deep policy,
            // exhausting the stack in the functions that walk it recursively.
            if (depth + (size_t) n_wrappers > MAX_PARSE_SCRIPT_RECURSION_DEPTH) {
                return WITH_ERROR(-1, "Script is too deeply nested");
            }

            // parse wrappers
            for (int i = 0; i < n_wrappers; i++) {
                policy_node_with_script_t *node =
                    (policy_node_with_script_t *) buffer_alloc(out_buf,
                                                               sizeof(policy_node_with_script_t),
                                                               true);
                if (node == NULL) {
                    return WITH_ERROR(-1, "Out of memory");
                }
                buffer_read_u8(in_buf, (uint8_t *) &c);
                switch (c) {
                    case 'a':
                        node->base.type = TOKEN_A;
                        break;
                    case 's':
                        node->base.type = TOKEN_S;
                        break;
                    case 'c':
                        node->base.type = TOKEN_C;
                        break;
                    case 't':
                        node->base.type = TOKEN_T;
                        break;
                    case 'd':
                        node->base.type = TOKEN_D;
                        break;
                    case 'v':
                        node->base.type = TOKEN_V;
                        break;
                    case 'j':
                        node->base.type = TOKEN_J;
                        break;
                    case 'n':
                        node->base.type = TOKEN_N;
                        break;
                    case 'l':
                        node->base.type = TOKEN_L;
                        break;
                    case 'u':
                        node->base.type = TOKEN_U;
                        break;
                    default:
                        PRINTF("Unexpected wrapper: %c\n", c);
                        return -1;
                }

                if (inner_wrapper != NULL) {
                    i_policy_node(&inner_wrapper->script, node);
                }
                inner_wrapper = node;
            }
            buffer_seek_cur(in_buf, 1);  // skip ":"

            // the wrapped script is nested n_wrappers levels below the current one
            depth += n_wrappers;
        } else {
            n_wrappers = 0;  // it was not a wrapper
        }
    }

    // We read the token, we'll do different parsing based on what token we find
    PolicyNodeType token = parse_token(in_buf);
    if (token == TOKEN_INVALID) {
        PRINTF("Failed to parse token");
        return -1;
    }

    if (context_flags & CONTEXT_WITHIN_SH) {
        // whitelist of allowed tokens within sh; in particular, no miniscript
        switch (token) {
            case TOKEN_PK:
            case TOKEN_PKH:
            case TOKEN_MULTI:
            case TOKEN_SORTEDMULTI:
            case TOKEN_WPKH:
            case TOKEN_WSH:
                break;
            default:
                return WITH_ERROR(-1, "Token not allowed within sh");
        }
    }

    if ((context_flags & CONTEXT_WITHIN_SH) != 0 && (context_flags & CONTEXT_WITHIN_WSH) != 0 &&
        depth == 2) {
        // whitelist of allowed tokens within sh(wsh()); only few simple wallet types are supported
        switch (token) {
            case TOKEN_PK:
            case TOKEN_PKH:
            case TOKEN_MULTI:
            case TOKEN_SORTEDMULTI:
                break;
            default:
                return WITH_ERROR(-1, "Token not allowed within sh(wsh())");
        }
    }

    // all tokens but '0' and '1' have opening and closing parentheses
    bool has_parentheses = token != TOKEN_0 && token != TOKEN_1;

    if (has_parentheses) {
        // Opening '('
        if (!consume_character(in_buf, '(')) {
            return WITH_ERROR(-1, "Expected '('");
        }
    }
    policy_node_t *parsed_node;

    switch (token) {
        case TOKEN_0:
        case TOKEN_1: {
            policy_node_constant_t *node =
                (policy_node_constant_t *) buffer_alloc(out_buf,
                                                        sizeof(policy_node_constant_t),
                                                        true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }

            parsed_node = (policy_node_t *) node;

            node->base.type = token;
            if (token == TOKEN_0) {
                node->base.flags.is_miniscript = 1;
                node->base.flags.miniscript_type = MINISCRIPT_TYPE_B;
                node->base.flags.miniscript_mod_z = 1;
                node->base.flags.miniscript_mod_o = 0;
                node->base.flags.miniscript_mod_n = 0;
                node->base.flags.miniscript_mod_d = 1;
                node->base.flags.miniscript_mod_u = 1;
            } else {
                node->base.flags.is_miniscript = 1;
                node->base.flags.miniscript_type = MINISCRIPT_TYPE_B;
                node->base.flags.miniscript_mod_z = 1;
                node->base.flags.miniscript_mod_o = 0;
                node->base.flags.miniscript_mod_n = 0;
                node->base.flags.miniscript_mod_d = 0;
                node->base.flags.miniscript_mod_u = 1;
            }

            break;
        }
        case TOKEN_SH:
        case TOKEN_WSH: {
            if (token == TOKEN_SH) {
                if (depth != 0) {
                    return WITH_ERROR(-1, "sh can only be a top-level function");
                }
            } else if (token == TOKEN_WSH) {
                if (depth != 0 && ((context_flags & CONTEXT_WITHIN_SH) == 0)) {
                    return WITH_ERROR(-1, "wsh can only be top-level or inside sh");
                }
            }

            policy_node_with_script_t *node =
                (policy_node_with_script_t *) buffer_alloc(out_buf,
                                                           sizeof(policy_node_with_script_t),
                                                           true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            parsed_node = (policy_node_t *) node;

            node->base.type = token;

            node->base.flags.is_miniscript = 0;

            unsigned int inner_context_flags = context_flags;
            inner_context_flags |= (token == TOKEN_SH) ? CONTEXT_WITHIN_SH : CONTEXT_WITHIN_WSH;

            // the internal script is recursively parsed (if successful) in the current location
            // of the output buffer
            buffer_alloc(out_buf, 0, true);  // ensure alignment of current pointer
            i_policy_node(&node->script, buffer_get_cur(out_buf));

            if (0 > parse_script(in_buf, out_buf, version, depth + 1, inner_context_flags)) {
                // failed while parsing internal script
                return -1;
            }

            break;
        }
        case TOKEN_SHA256:
        case TOKEN_HASH256: {
            policy_node_with_hash_256_t *node =
                (policy_node_with_hash_256_t *) buffer_alloc(out_buf,
                                                             sizeof(policy_node_with_hash_256_t),
                                                             true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            parsed_node = (policy_node_t *) node;

            if (0 > buffer_read_hex_hash(in_buf, node->h, 32)) {
                return WITH_ERROR(-1, "Failed to parse 32-byte hash image");
            }

            node->base.type = token;
            node->base.flags.is_miniscript = 1;
            node->base.flags.miniscript_type = MINISCRIPT_TYPE_B;
            node->base.flags.miniscript_mod_z = 0;
            node->base.flags.miniscript_mod_o = 1;
            node->base.flags.miniscript_mod_n = 1;
            node->base.flags.miniscript_mod_d = 1;
            node->base.flags.miniscript_mod_u = 1;
            break;
        }

        case TOKEN_RIPEMD160:
        case TOKEN_HASH160: {
            policy_node_with_hash_160_t *node =
                (policy_node_with_hash_160_t *) buffer_alloc(out_buf,
                                                             sizeof(policy_node_with_hash_160_t),
                                                             true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            parsed_node = (policy_node_t *) node;

            if (0 > buffer_read_hex_hash(in_buf, node->h, 20)) {
                return WITH_ERROR(-1, "Failed to parse 20-byte hash image");
            }

            node->base.type = token;
            node->base.flags.is_miniscript = 1;
            node->base.flags.miniscript_type = MINISCRIPT_TYPE_B;
            node->base.flags.miniscript_mod_z = 0;
            node->base.flags.miniscript_mod_o = 1;
            node->base.flags.miniscript_mod_n = 1;
            node->base.flags.miniscript_mod_d = 1;
            node->base.flags.miniscript_mod_u = 1;
            break;
        }

        case TOKEN_ANDOR: {
            policy_node_with_script3_t *node =
                (policy_node_with_script3_t *) buffer_alloc(out_buf,
                                                            sizeof(policy_node_with_script3_t),
                                                            true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            parsed_node = (policy_node_t *) node;

            node->base.type = token;

            if (0 > parse_child_scripts(in_buf,
                                        out_buf,
                                        depth,
                                        node->scripts,
                                        3,
                                        version,
                                        context_flags)) {
                return -1;
            }

            for (int i = 0; i < 3; i++) {
                if (!r_policy_node(&node->scripts[i])->flags.is_miniscript) {
                    return WITH_ERROR(-1, "children of andor must be miniscript");
                }
            }

            // andor(X, Y, Z)
            // X is Bdu; Y and Z are both B, K, or V

            const policy_node_t *X = r_policy_node(&node->scripts[0]);
            const policy_node_t *Y = r_policy_node(&node->scripts[1]);
            const policy_node_t *Z = r_policy_node(&node->scripts[2]);

            if (X->flags.miniscript_type != MINISCRIPT_TYPE_B || !X->flags.miniscript_mod_d ||
                !X->flags.miniscript_mod_u) {
                return WITH_ERROR(-1, "invalid type");
            }

            if (Y->flags.miniscript_type != Z->flags.miniscript_type) {
                return WITH_ERROR(-1, "invalid type");
            }

            if (Y->flags.miniscript_type == MINISCRIPT_TYPE_W) {  // must be one of the other three
                return WITH_ERROR(-1, "invalid type");
            }

            // clang-format off
            node->base.flags.is_miniscript = 1;
            node->base.flags.miniscript_type = Y->flags.miniscript_type;
            node->base.flags.miniscript_mod_z =
                X->flags.miniscript_mod_z & Y->flags.miniscript_mod_z & Z->flags.miniscript_mod_z;
            node->base.flags.miniscript_mod_o =
                (X->flags.miniscript_mod_z & Y->flags.miniscript_mod_o & Z->flags.miniscript_mod_o)
                |
                (X->flags.miniscript_mod_o & Y->flags.miniscript_mod_z & Z->flags.miniscript_mod_z);
            node->base.flags.miniscript_mod_n = 0;
            node->base.flags.miniscript_mod_d = Z->flags.miniscript_mod_d;
            node->base.flags.miniscript_mod_u = Y->flags.miniscript_mod_u & Z->flags.miniscript_mod_u;
            // clang-format on

            break;
        }
        case TOKEN_AND_V: {
            policy_node_with_script2_t *node =
                (policy_node_with_script2_t *) buffer_alloc(out_buf,
                                                            sizeof(policy_node_with_script2_t),
                                                            true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            parsed_node = (policy_node_t *) node;

            node->base.type = token;

            if (0 > parse_child_scripts(in_buf,
                                        out_buf,
                                        depth,
                                        node->scripts,
                                        2,
                                        version,
                                        context_flags)) {
                return -1;
            }

            if (!r_policy_node(&node->scripts[0])->flags.is_miniscript ||
                !r_policy_node(&node->scripts[1])->flags.is_miniscript) {
                return WITH_ERROR(-1, "children of and_v must be miniscript");
            }

            const policy_node_t *X = r_policy_node(&node->scripts[0]);
            const policy_node_t *Y = r_policy_node(&node->scripts[1]);

            // and_v(X,Y)
            // X is V; Y is B, K, or V

            if (X->flags.miniscript_type != MINISCRIPT_TYPE_V) {
                return WITH_ERROR(-1, "invalid type");
            }

            if (Y->flags.miniscript_type == MINISCRIPT_TYPE_W) {  // must be one of the other three
                return WITH_ERROR(-1, "invalid type");
            }

            // clang-format off
            node->base.flags.is_miniscript = 1;
            node->base.flags.miniscript_type = Y->flags.miniscript_type;
            node->base.flags.miniscript_mod_z = X->flags.miniscript_mod_z & Y->flags.miniscript_mod_z;
            node->base.flags.miniscript_mod_o =
                (X->flags.miniscript_mod_z & Y->flags.miniscript_mod_o)
                |
                (X->flags.miniscript_mod_o & Y->flags.miniscript_mod_z);
            node->base.flags.miniscript_mod_n =
                X->flags.miniscript_mod_n
                |
                (X->flags.miniscript_mod_z & Y->flags.miniscript_mod_n);
            node->base.flags.miniscript_mod_d = 0;
            node->base.flags.miniscript_mod_u = Y->flags.miniscript_mod_u;
            // clang-format on

            break;
        }
        case TOKEN_AND_B: {
            policy_node_with_script2_t *node =
                (policy_node_with_script2_t *) buffer_alloc(out_buf,
                                                            sizeof(policy_node_with_script2_t),
                                                            true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            parsed_node = (policy_node_t *) node;

            node->base.type = token;

            if (0 > parse_child_scripts(in_buf,
                                        out_buf,
                                        depth,
                                        node->scripts,
                                        2,
                                        version,
                                        context_flags)) {
                return -1;
            }

            if (!r_policy_node(&node->scripts[0])->flags.is_miniscript ||
                !r_policy_node(&node->scripts[1])->flags.is_miniscript) {
                return WITH_ERROR(-1, "children of and_b must be miniscript");
            }

            const policy_node_t *X = r_policy_node(&node->scripts[0]);
            const policy_node_t *Y = r_policy_node(&node->scripts[1]);

            // and_b(X,Y)
            // X is B; Y is W

            if (X->flags.miniscript_type != MINISCRIPT_TYPE_B ||
                Y->flags.miniscript_type != MINISCRIPT_TYPE_W) {
                return WITH_ERROR(-1, "invalid type");
            }

            // clang-format off
            node->base.flags.is_miniscript = 1;
            node->base.flags.miniscript_type = MINISCRIPT_TYPE_B;
            node->base.flags.miniscript_mod_z = X->flags.miniscript_mod_z & Y->flags.miniscript_mod_z;
            node->base.flags.miniscript_mod_o =
                (X->flags.miniscript_mod_z & Y->flags.miniscript_mod_o)
                |
                (X->flags.miniscript_mod_o & Y->flags.miniscript_mod_z);
            node->base.flags.miniscript_mod_n =
                X->flags.miniscript_mod_n
                |
                (X->flags.miniscript_mod_z & Y->flags.miniscript_mod_n);
            node->base.flags.miniscript_mod_d = X->flags.miniscript_mod_d & Y->flags.miniscript_mod_d;
            node->base.flags.miniscript_mod_u = 1;
            // clang-format on

            break;
        }
        case TOKEN_AND_N: {
            policy_node_with_script2_t *node =
                (policy_node_with_script2_t *) buffer_alloc(out_buf,
                                                            sizeof(policy_node_with_script2_t),
                                                            true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            parsed_node = (policy_node_t *) node;

            node->base.type = token;

            if (0 > parse_child_scripts(in_buf,
                                        out_buf,
                                        depth,
                                        node->scripts,
                                        2,
                                        version,
                                        context_flags)) {
                return -1;
            }

            if (!r_policy_node(&node->scripts[0])->flags.is_miniscript ||
                !r_policy_node(&node->scripts[1])->flags.is_miniscript) {
                return WITH_ERROR(-1, "children of and_n must be miniscript");
            }

            // and_n(X, Y) is equivalent to andor(X, Y, 0)
            // X is Bdu; Y is B

            const policy_node_t *X = r_policy_node(&node->scripts[0]);
            const policy_node_t *Y = r_policy_node(&node->scripts[1]);

            if (X->flags.miniscript_type != MINISCRIPT_TYPE_B || !X->flags.miniscript_mod_d ||
                !X->flags.miniscript_mod_u) {
                return WITH_ERROR(-1, "invalid type");
            }

            if (Y->flags.miniscript_type != MINISCRIPT_TYPE_B) {
                return WITH_ERROR(-1, "invalid type");
            }

            // clang-format off
            node->base.flags.is_miniscript = 1;
            node->base.flags.miniscript_type = MINISCRIPT_TYPE_B;
            node->base.flags.miniscript_mod_z =
                X->flags.miniscript_mod_z & Y->flags.miniscript_mod_z;
            node->base.flags.miniscript_mod_o = X->flags.miniscript_mod_o & Y->flags.miniscript_mod_z;
            node->base.flags.miniscript_mod_n = 0;
            node->base.flags.miniscript_mod_d = 1;
            node->base.flags.miniscript_mod_u = Y->flags.miniscript_mod_u;
            // clang-format on

            break;
        }
        case TOKEN_OR_B: {
            policy_node_with_script2_t *node =
                (policy_node_with_script2_t *) buffer_alloc(out_buf,
                                                            sizeof(policy_node_with_script2_t),
                                                            true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            parsed_node = (policy_node_t *) node;

            node->base.type = token;

            if (0 > parse_child_scripts(in_buf,
                                        out_buf,
                                        depth,
                                        node->scripts,
                                        2,
                                        version,
                                        context_flags)) {
                return -1;
            }

            if (!r_policy_node(&node->scripts[0])->flags.is_miniscript ||
                !r_policy_node(&node->scripts[1])->flags.is_miniscript) {
                return WITH_ERROR(-1, "children of or_b must be miniscript");
            }

            // or_b(X, Z)
            // X is Bd; Z is Wd

            const policy_node_t *X = r_policy_node(&node->scripts[0]);
            const policy_node_t *Z = r_policy_node(&node->scripts[1]);

            if (X->flags.miniscript_type != MINISCRIPT_TYPE_B || !X->flags.miniscript_mod_d) {
                return WITH_ERROR(-1, "invalid type");
            }

            if (Z->flags.miniscript_type != MINISCRIPT_TYPE_W || !Z->flags.miniscript_mod_d) {
                return WITH_ERROR(-1, "invalid type");
            }

            // clang-format off
            node->base.flags.is_miniscript = 1;
            node->base.flags.miniscript_type = MINISCRIPT_TYPE_B;
            node->base.flags.miniscript_mod_z = X->flags.miniscript_mod_z & Z->flags.miniscript_mod_z;
            node->base.flags.miniscript_mod_o =
                (X->flags.miniscript_mod_z & Z->flags.miniscript_mod_o)
                |
                (X->flags.miniscript_mod_o & Z->flags.miniscript_mod_z);
            node->base.flags.miniscript_mod_n = 0;
            node->base.flags.miniscript_mod_d = 1;
            node->base.flags.miniscript_mod_u = 1;
            // clang-format on

            break;
        }
        case TOKEN_OR_C: {
            policy_node_with_script2_t *node =
                (policy_node_with_script2_t *) buffer_alloc(out_buf,
                                                            sizeof(policy_node_with_script2_t),
                                                            true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            parsed_node = (policy_node_t *) node;

            node->base.type = token;

            if (0 > parse_child_scripts(in_buf,
                                        out_buf,
                                        depth,
                                        node->scripts,
                                        2,
                                        version,
                                        context_flags)) {
                return -1;
            }

            if (!r_policy_node(&node->scripts[0])->flags.is_miniscript ||
                !r_policy_node(&node->scripts[1])->flags.is_miniscript) {
                return WITH_ERROR(-1, "children of or_c must be miniscript");
            }

            // or_c(X, Z)
            // X is Bdu; Z is V

            const policy_node_t *X = r_policy_node(&node->scripts[0]);
            const policy_node_t *Z = r_policy_node(&node->scripts[1]);

            if (X->flags.miniscript_type != MINISCRIPT_TYPE_B || !X->flags.miniscript_mod_d ||
                !X->flags.miniscript_mod_u) {
                return WITH_ERROR(-1, "invalid type");
            }

            if (Z->flags.miniscript_type != MINISCRIPT_TYPE_V) {
                return WITH_ERROR(-1, "invalid type");
            }

            // clang-format off
            node->base.flags.is_miniscript = 1;
            node->base.flags.miniscript_type = MINISCRIPT_TYPE_V;
            node->base.flags.miniscript_mod_z = X->flags.miniscript_mod_z & Z->flags.miniscript_mod_z;
            node->base.flags.miniscript_mod_o = X->flags.miniscript_mod_o & Z->flags.miniscript_mod_z;
            node->base.flags.miniscript_mod_n = 0;
            node->base.flags.miniscript_mod_d = 0;
            node->base.flags.miniscript_mod_u = 0;
            // clang-format on

            break;
        }
        case TOKEN_OR_D: {
            policy_node_with_script2_t *node =
                (policy_node_with_script2_t *) buffer_alloc(out_buf,
                                                            sizeof(policy_node_with_script2_t),
                                                            true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            parsed_node = (policy_node_t *) node;

            node->base.type = token;

            if (0 > parse_child_scripts(in_buf,
                                        out_buf,
                                        depth,
                                        node->scripts,
                                        2,
                                        version,
                                        context_flags)) {
                return -1;
            }

            if (!r_policy_node(&node->scripts[0])->flags.is_miniscript ||
                !r_policy_node(&node->scripts[1])->flags.is_miniscript) {
                return WITH_ERROR(-1, "children of or_d must be miniscript");
            }

            // or_d(X, Z)
            // X is Bdu; Z is B

            const policy_node_t *X = r_policy_node(&node->scripts[0]);
            const policy_node_t *Z = r_policy_node(&node->scripts[1]);

            if (X->flags.miniscript_type != MINISCRIPT_TYPE_B || !X->flags.miniscript_mod_d ||
                !X->flags.miniscript_mod_u) {
                return WITH_ERROR(-1, "invalid type");
            }

            if (Z->flags.miniscript_type != MINISCRIPT_TYPE_B) {
                return WITH_ERROR(-1, "invalid type");
            }

            // clang-format off
            node->base.flags.is_miniscript = 1;
            node->base.flags.miniscript_type = MINISCRIPT_TYPE_B;
            node->base.flags.miniscript_mod_z = X->flags.miniscript_mod_z & Z->flags.miniscript_mod_z;
            node->base.flags.miniscript_mod_o = X->flags.miniscript_mod_o & Z->flags.miniscript_mod_z;
            node->base.flags.miniscript_mod_n = 0;
            node->base.flags.miniscript_mod_d = Z->flags.miniscript_mod_d;
            node->base.flags.miniscript_mod_u = Z->flags.miniscript_mod_u;
            // clang-format on

            break;
        }
        case TOKEN_OR_I: {
            policy_node_with_script2_t *node =
                (policy_node_with_script2_t *) buffer_alloc(out_buf,
                                                            sizeof(policy_node_with_script2_t),
                                                            true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            parsed_node = (policy_node_t *) node;

            node->base.type = token;

            if (0 > parse_child_scripts(in_buf,
                                        out_buf,
                                        depth,
                                        node->scripts,
                                        2,
                                        version,
                                        context_flags)) {
                return -1;
            }

            if (!r_policy_node(&node->scripts[0])->flags.is_miniscript ||
                !r_policy_node(&node->scripts[1])->flags.is_miniscript) {
                return WITH_ERROR(-1, "children of or_i must be miniscript");
            }

            // or_i(X, Z)
            // both are B, K, or V

            const policy_node_t *X = r_policy_node(&node->scripts[0]);
            const policy_node_t *Z = r_policy_node(&node->scripts[1]);

            if (X->flags.miniscript_type == MINISCRIPT_TYPE_W) {
                return WITH_ERROR(-1, "invalid type");  // must be B, K or V
            }

            if (X->flags.miniscript_type != Z->flags.miniscript_type) {
                return WITH_ERROR(-1, "invalid type");  // children must be the same type
            }

            // clang-format off
            node->base.flags.is_miniscript = 1;
            node->base.flags.miniscript_type = X->flags.miniscript_type;
            node->base.flags.miniscript_mod_z = 0;
            node->base.flags.miniscript_mod_o = X->flags.miniscript_mod_z & Z->flags.miniscript_mod_z;
            node->base.flags.miniscript_mod_n = 0;
            node->base.flags.miniscript_mod_d = X->flags.miniscript_mod_d | Z->flags.miniscript_mod_d;
            node->base.flags.miniscript_mod_u = X->flags.miniscript_mod_u & Z->flags.miniscript_mod_u;
            // clang-format on

            break;
        }
        case TOKEN_THRESH: {
            if (CONTEXT_THRESH_NESTING(context_flags) >= MAX_THRESH_NESTING) {
                return WITH_ERROR(-1, "Too many nested thresh expressions");
            }
            // the children of this node (and all their descendants) are within one more thresh
            unsigned int inner_context_flags = context_flags + CONTEXT_THRESH_NESTING_UNIT;

            policy_node_thresh_t *node =
                (policy_node_thresh_t *) buffer_alloc(out_buf, sizeof(policy_node_thresh_t), true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            parsed_node = (policy_node_t *) node;
            node->base.type = token;

            // the internal scripts are recursively parsed (if successful) in the current location
            // of the output buffer

            uint32_t k;
            if (parse_unsigned_decimal(in_buf, &k) == -1 || k > INT16_MAX) {
                return WITH_ERROR(-1, "Error parsing threshold");
            }
            node->k = (int16_t) k;

            // the next character must be a comma
            if (!consume_character(in_buf, ',')) {
                return WITH_ERROR(-1, "Expected a comma");
            }

            if (node->k < 1) {
                return WITH_ERROR(-1, "Threshold must be at least 1");
            }

            node->n = 0;
            policy_node_scriptlist_t *scriptlist =
                buffer_alloc(out_buf, sizeof(policy_node_scriptlist_t), true);
            if (scriptlist == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            i_policy_node_scriptlist(&node->scriptlist, scriptlist);

            policy_node_scriptlist_t *cur = scriptlist;

            i_policy_node_scriptlist(&cur->next, NULL);

            int count_z = 0;
            int count_o = 0;
            while (true) {
                ++node->n;
                // parse a script into cur->script
                buffer_alloc(out_buf, 0, true);  // ensure alignment of current pointer
                i_policy_node(&cur->script, buffer_get_cur(out_buf));
                if (0 > parse_script(in_buf, out_buf, version, depth + 1, inner_context_flags)) {
                    // failed while parsing internal script
                    return -1;
                }

                if (!r_policy_node(&cur->script)->flags.is_miniscript) {
                    return WITH_ERROR(-1, "children of thresh must be miniscript");
                }

                if (node->n == 1) {
                    // the first child's type must be B
                    if (r_policy_node(&cur->script)->flags.miniscript_type != MINISCRIPT_TYPE_B) {
                        return WITH_ERROR(-1, "the first children of thresh must be of type B");
                    }
                } else {
                    // every other child's type must be W
                    if (r_policy_node(&cur->script)->flags.miniscript_type != MINISCRIPT_TYPE_W) {
                        return WITH_ERROR(
                            -1,
                            "each child of thresh (except the first) must be of type W");
                    }
                }

                // all children must have properties du
                if (!r_policy_node(&cur->script)->flags.miniscript_mod_d ||
                    !r_policy_node(&cur->script)->flags.miniscript_mod_u) {
                    return WITH_ERROR(-1, "each child of thresh must have properties d and u");
                }

                if (r_policy_node(&cur->script)->flags.miniscript_mod_z) {
                    ++count_z;
                }
                if (r_policy_node(&cur->script)->flags.miniscript_mod_o) {
                    ++count_o;
                }

                // peek, if next character is ',', consume it and exit
                if (consume_character(in_buf, ',')) {
                    policy_node_scriptlist_t *next =
                        (policy_node_scriptlist_t *) buffer_alloc(out_buf,
                                                                  sizeof(policy_node_scriptlist_t),
                                                                  true);
                    if (next == NULL) {
                        return WITH_ERROR(-1, "Out of memory");
                    }

                    i_policy_node_scriptlist(&cur->next, next);

                    cur = next;
                    i_policy_node_scriptlist(&cur->next, NULL);
                } else {
                    // no more scripts to parse
                    break;
                }
            }

            if (node->k > node->n) {
                return WITH_ERROR(-1, "thresh: k exceeds n");
            }

            // thresh(k, X1, ..., Xn)
            // X1 is Bdu; others are Wdu

            // clang-format off
            node->base.flags.is_miniscript = 1;
            node->base.flags.miniscript_type = MINISCRIPT_TYPE_B;
            node->base.flags.miniscript_mod_z = (count_z == node->n) ? 1 : 0;
            node->base.flags.miniscript_mod_o = (count_z == node->n - 1 && count_o == 1) ? 1 : 0;
            node->base.flags.miniscript_mod_n = 0;
            node->base.flags.miniscript_mod_d = 1;
            node->base.flags.miniscript_mod_u = 1;
            // clang-format on

            break;
        }
        case TOKEN_PK:
        case TOKEN_PKH:
        case TOKEN_PK_K:
        case TOKEN_PK_H:
        case TOKEN_WPKH: {
            policy_node_with_key_t *node =
                (policy_node_with_key_t *) buffer_alloc(out_buf,
                                                        sizeof(policy_node_with_key_t),
                                                        true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }

            policy_node_keyexpr_t *key_expr =
                buffer_alloc(out_buf, sizeof(policy_node_keyexpr_t), true);

            if (key_expr == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            i_policy_node_keyexpr(&node->key, key_expr);

            if (token == TOKEN_WPKH) {
                if (depth > 0 && ((context_flags & CONTEXT_WITHIN_SH) == 0)) {
                    return WITH_ERROR(-1, "wpkh can only be top-level or inside sh");
                }
            }

            parsed_node = (policy_node_t *) node;

            node->base.type = token;

            bool is_taproot = (context_flags & CONTEXT_WITHIN_TR) != 0;
            if (0 > parse_keyexpr(in_buf,
                                  version,
                                  key_expr,
                                  is_taproot,  // musig is only allowed in taproot
                                  out_buf,
                                  &key_expression_count)) {
                return WITH_ERROR(-1, "Couldn't parse key expression");
            }

            if (token == TOKEN_WPKH) {
                // not valid in miniscript
                node->base.flags.is_miniscript = 0;
            } else {
                switch (token) {
                    case TOKEN_PK:  // pk(key) == c:pk_k(key)
                        node->base.flags.is_miniscript = 1;
                        node->base.flags.miniscript_type = MINISCRIPT_TYPE_B;
                        node->base.flags.miniscript_mod_z = 0;
                        node->base.flags.miniscript_mod_o = 1;
                        node->base.flags.miniscript_mod_n = 1;
                        node->base.flags.miniscript_mod_d = 1;
                        node->base.flags.miniscript_mod_u = 1;
                        break;
                    case TOKEN_PKH:  // pkh(key) == c:pk_h(key)
                        node->base.flags.is_miniscript = 1;
                        node->base.flags.miniscript_type = MINISCRIPT_TYPE_B;
                        node->base.flags.miniscript_mod_z = 0;
                        node->base.flags.miniscript_mod_o = 0;
                        node->base.flags.miniscript_mod_n = 1;
                        node->base.flags.miniscript_mod_d = 1;
                        node->base.flags.miniscript_mod_u = 1;
                        break;
                    case TOKEN_PK_K:
                        node->base.flags.is_miniscript = 1;
                        node->base.flags.miniscript_type = MINISCRIPT_TYPE_K;
                        node->base.flags.miniscript_mod_z = 0;
                        node->base.flags.miniscript_mod_o = 1;
                        node->base.flags.miniscript_mod_n = 1;
                        node->base.flags.miniscript_mod_d = 1;
                        node->base.flags.miniscript_mod_u = 1;
                        break;
                    case TOKEN_PK_H:
                        node->base.flags.is_miniscript = 1;
                        node->base.flags.miniscript_type = MINISCRIPT_TYPE_K;
                        node->base.flags.miniscript_mod_z = 0;
                        node->base.flags.miniscript_mod_o = 0;
                        node->base.flags.miniscript_mod_n = 1;
                        node->base.flags.miniscript_mod_d = 1;
                        node->base.flags.miniscript_mod_u = 1;
                        break;
                    default:
                        return WITH_ERROR(-1, "unreachable code reached");
                }
            }

            break;
        }
        case TOKEN_TR: {  // supporting only xpubs
            if (depth > 1) {
                return WITH_ERROR(-1, "tr can only be top-level");
            }

            policy_node_tr_t *node =
                (policy_node_tr_t *) buffer_alloc(out_buf, sizeof(policy_node_tr_t), true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }

            policy_node_keyexpr_t *key_expr =
                buffer_alloc(out_buf, sizeof(policy_node_keyexpr_t), true);
            if (key_expr == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            i_policy_node_keyexpr(&node->key, key_expr);

            // the taproot internal key can be a musig
            if (0 >
                parse_keyexpr(in_buf, version, key_expr, true, out_buf, &key_expression_count)) {
                return WITH_ERROR(-1, "Couldn't parse key expression");
            }

            uint8_t c;
            if (!buffer_peek(in_buf, &c)) {
                return WITH_ERROR(-1, "buffer exhausted too early while parsing tr");
            }
            if (c == ',') {
                // Parse a TREE node
                buffer_seek_cur(in_buf, 1);  // skip ','

                buffer_alloc(out_buf, 0, true);  // ensure alignment of current pointer
                policy_node_tree_t *tree = (policy_node_tree_t *) buffer_get_cur(out_buf);
                if (0 > parse_tree(in_buf, out_buf, version, depth + 1)) {
                    return WITH_ERROR(-1, "Failed to parse TREE expression");
                }
                i_policy_node_tree(&node->tree, tree);
            } else {
                // no TREE, only tr(KP)
                if (c != ')') {
                    return WITH_ERROR(-1, "Failed to parse tr");
                }
                i_policy_node_tree(&node->tree, NULL);
            }

            parsed_node = (policy_node_t *) node;

            node->base.type = token;

            node->base.flags.is_miniscript = 0;

            break;
        }
        case TOKEN_OLDER:
        case TOKEN_AFTER: {
            policy_node_with_uint32_t *node =
                (policy_node_with_uint32_t *) buffer_alloc(out_buf,
                                                           sizeof(policy_node_with_uint32_t),
                                                           true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            parsed_node = (policy_node_t *) node;
            node->base.type = token;

            if (parse_unsigned_decimal(in_buf, &node->n) == -1) {
                return WITH_ERROR(-1, "Error parsing number");
            }

            if (node->n < 1 || node->n >= (1u << 31)) {
                return WITH_ERROR(-1, "n must satisfy 1 <= n < 2^31 in older/after");
            }

            node->base.flags.is_miniscript = 1;
            node->base.flags.miniscript_type = MINISCRIPT_TYPE_B;
            node->base.flags.miniscript_mod_z = 1;
            node->base.flags.miniscript_mod_o = 0;
            node->base.flags.miniscript_mod_n = 0;
            node->base.flags.miniscript_mod_d = 0;
            node->base.flags.miniscript_mod_u = 0;

            break;
        }
        case TOKEN_MULTI:
        case TOKEN_MULTI_A:
        case TOKEN_SORTEDMULTI:
        case TOKEN_SORTEDMULTI_A: {
            policy_node_multisig_t *node =
                (policy_node_multisig_t *) buffer_alloc(out_buf,
                                                        sizeof(policy_node_multisig_t),
                                                        true);

            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }

            bool is_taproot = (context_flags & CONTEXT_WITHIN_TR) != 0;
            if (is_taproot) {
                if (token != TOKEN_MULTI_A && token != TOKEN_SORTEDMULTI_A) {
                    return WITH_ERROR(
                        -1,
                        "multi and sortedmulti can only be used in legacy or segwit scripts");
                }
            } else {  // legacy or segwit scripts
                if (token != TOKEN_MULTI && token != TOKEN_SORTEDMULTI) {
                    return WITH_ERROR(
                        -1,
                        "multi_a and sortedmulti_a can only be used in taproot scripts");
                }
            }

            if (token == TOKEN_SORTEDMULTI) {
                size_t n_sh_wrappers = 0;
                if (context_flags & CONTEXT_WITHIN_SH) ++n_sh_wrappers;
                if (context_flags & CONTEXT_WITHIN_WSH) ++n_sh_wrappers;

                // sortedmulti can only be used bare, or directly under sh(), wsh()
                if (depth != n_sh_wrappers) {
                    return WITH_ERROR(-1,
                                      "sortedmulti can only be bare, or directly under sh or wsh");
                }
            }

            parsed_node = (policy_node_t *) node;
            node->base.type = token;

            uint32_t k;
            if (parse_unsigned_decimal(in_buf, &k) == -1 || k > INT16_MAX) {
                return WITH_ERROR(-1, "Error parsing threshold");
            }
            node->k = (int16_t) k;

            // We allocate the array of key indices at the current position in the output buffer
            // (on success).
            // Note: this is incompatible with musig keys, therefore we don't currently support
            // musig nested inside multi_a or sortedmulti_a.
            buffer_alloc(out_buf, 0, true);  // ensure alignment of current pointer
            i_policy_node_keyexpr(&node->keys, buffer_get_cur(out_buf));

            node->n = 0;
            while (true) {
                uint8_t c;
                // If the next character is a ')', we exit and leave it in the buffer
                if (buffer_peek(in_buf, &c) && c == ')') {
                    break;
                }

                // otherwise, there must be a comma
                if (!consume_character(in_buf, ',')) {
                    return WITH_ERROR(-1, "Expected ','");
                }

                policy_node_keyexpr_t *key_expr = (policy_node_keyexpr_t *) buffer_alloc(
                    out_buf,
                    sizeof(policy_node_keyexpr_t),
                    true);  // we align this pointer, as there's padding in an array of
                            // structures
                if (key_expr == NULL) {
                    return WITH_ERROR(-1, "Out of memory");
                }

                if (0 >
                    parse_keyexpr(
                        in_buf,
                        version,
                        key_expr,
                        false,  // musig is not currently supported in keys of multisig fragments
                        out_buf,
                        &key_expression_count)) {
                    return WITH_ERROR(-1, "Error parsing key expression");
                }

                ++node->n;
            }

            // check integrity of k and n
            if (!(1 <= node->k && node->k <= node->n && node->n <= MAX_PUBKEYS_PER_MULTISIG)) {
                return WITH_ERROR(-1, "Invalid k and/or n");
            }

            if (token == TOKEN_SORTEDMULTI || token == TOKEN_SORTEDMULTI_A) {
                node->base.flags.is_miniscript = 0;
            } else if (token == TOKEN_MULTI) {
                node->base.flags.is_miniscript = 1;
                node->base.flags.miniscript_type = MINISCRIPT_TYPE_B;
                node->base.flags.miniscript_mod_z = 0;
                node->base.flags.miniscript_mod_o = 0;
                node->base.flags.miniscript_mod_n = 1;
                node->base.flags.miniscript_mod_d = 1;
                node->base.flags.miniscript_mod_u = 1;
            } else if (token == TOKEN_MULTI_A) {
                node->base.flags.is_miniscript = 1;
                node->base.flags.miniscript_type = MINISCRIPT_TYPE_B;
                node->base.flags.miniscript_mod_z = 0;
                node->base.flags.miniscript_mod_o = 0;
                node->base.flags.miniscript_mod_n = 0;
                node->base.flags.miniscript_mod_d = 1;
                node->base.flags.miniscript_mod_u = 1;
            }

            break;
        }
        default:
            PRINTF("Unknown token: %d\n", token);
            return -1;
    }

    if (has_parentheses) {
        if (!consume_character(in_buf, ')')) {
            return WITH_ERROR(-1, "Expected ')'");
        }
    }

    if (depth == 0 && buffer_can_read(in_buf, 1)) {
        return WITH_ERROR(-1, "Input buffer too long");
    }

    // if there was one or more wrappers, the script of the most internal node must point
    // to the parsed node
    if (inner_wrapper != NULL) {
        i_policy_node(&inner_wrapper->script, parsed_node);
    }

    // Validate and compute the flags (miniscript type and modifiers) for all the wrapper, if any
    // We start from the most internal wrapper.
    // Remark: This loop has quadratic complexity as we process a linked list in reverse order, but
    // it does not matter as it is always a short list.

    for (int i = n_wrappers - 1; i >= 0; i--) {
        // find the actual node by traversing the list
        policy_node_with_script_t *node = (policy_node_with_script_t *) outermost_node;
        for (int j = 0; j < i; j++) {
            node = (policy_node_with_script_t *) r_policy_node(&node->script);
        }

        if (!r_policy_node(&node->script)->flags.is_miniscript) {
            return WITH_ERROR(-1, "wrappers can only be applied to miniscript");
        }

        const policy_node_t *X = r_policy_node(&node->script);

        uint8_t X_type = X->flags.miniscript_type;

        uint8_t X_z = X->flags.miniscript_mod_z;
        uint8_t X_o = X->flags.miniscript_mod_o;
        uint8_t X_n = X->flags.miniscript_mod_n;
        uint8_t X_d = X->flags.miniscript_mod_d;
        uint8_t X_u = X->flags.miniscript_mod_u;

        switch (node->base.type) {
            case TOKEN_A:
                if (X_type != MINISCRIPT_TYPE_B) {
                    return WITH_ERROR(-1, "'a' wrapper requires a B type child");
                }

                node->base.flags.is_miniscript = 1;
                node->base.flags.miniscript_type = MINISCRIPT_TYPE_W;
                node->base.flags.miniscript_mod_z = 0;
                node->base.flags.miniscript_mod_o = 0;
                node->base.flags.miniscript_mod_n = 0;
                node->base.flags.miniscript_mod_d = X_d;
                node->base.flags.miniscript_mod_u = X_u;
                break;
            case TOKEN_S:
                if (X_type != MINISCRIPT_TYPE_B || !X_o) {
                    return WITH_ERROR(-1, "'s' wrapper requires a Bu type child");
                }

                node->base.flags.is_miniscript = 1;
                node->base.flags.miniscript_type = MINISCRIPT_TYPE_W;
                node->base.flags.miniscript_mod_z = 0;
                node->base.flags.miniscript_mod_o = 0;
                node->base.flags.miniscript_mod_n = 0;
                node->base.flags.miniscript_mod_d = X_d;
                node->base.flags.miniscript_mod_u = X_u;
                break;
            case TOKEN_C:
                if (X_type != MINISCRIPT_TYPE_K) {
                    return WITH_ERROR(-1, "'c' wrapper requires a K type child");
                }

                node->base.flags.is_miniscript = 1;
                node->base.flags.miniscript_type = MINISCRIPT_TYPE_B;
                node->base.flags.miniscript_mod_z = 0;
                node->base.flags.miniscript_mod_o = X_o;
                node->base.flags.miniscript_mod_n = X_n;
                node->base.flags.miniscript_mod_d = X_d;
                node->base.flags.miniscript_mod_u = 1;
                break;
            case TOKEN_T:
                // t:X == and_v(X,1)

                if (X_type != MINISCRIPT_TYPE_V) {
                    return WITH_ERROR(-1, "'t' wrapper requires a V type child");
                }

                node->base.flags.is_miniscript = 1;
                node->base.flags.miniscript_type = MINISCRIPT_TYPE_B;
                node->base.flags.miniscript_mod_z = X_z;
                node->base.flags.miniscript_mod_o = X_o;
                node->base.flags.miniscript_mod_n = X_n;
                node->base.flags.miniscript_mod_d = 0;
                node->base.flags.miniscript_mod_u = 1;
                break;
            case TOKEN_D:
                if (X_type != MINISCRIPT_TYPE_V || !X_z) {
                    return WITH_ERROR(-1, "'d' wrapper requires a Vz type child");
                }

                node->base.flags.is_miniscript = 1;
                node->base.flags.miniscript_type = MINISCRIPT_TYPE_B;
                node->base.flags.miniscript_mod_z = 0;
                node->base.flags.miniscript_mod_o = 1;
                node->base.flags.miniscript_mod_n = 1;
                node->base.flags.miniscript_mod_d = 1;
                node->base.flags.miniscript_mod_u = (context_flags & CONTEXT_WITHIN_TR) ? 1 : 0;
                break;
            case TOKEN_V:
                if (X_type != MINISCRIPT_TYPE_B) {
                    return WITH_ERROR(-1, "'v' wrapper requires a B type child");
                }

                node->base.flags.is_miniscript = 1;
                node->base.flags.miniscript_type = MINISCRIPT_TYPE_V;
                node->base.flags.miniscript_mod_z = X_z;
                node->base.flags.miniscript_mod_o = X_o;
                node->base.flags.miniscript_mod_n = X_n;
                node->base.flags.miniscript_mod_d = 0;
                node->base.flags.miniscript_mod_u = 0;
                break;
            case TOKEN_J:
                if (X_type != MINISCRIPT_TYPE_B || !X_n) {
                    return WITH_ERROR(-1, "'j' wrapper requires a Bn type child");
                }

                node->base.flags.is_miniscript = 1;
                node->base.flags.miniscript_type = MINISCRIPT_TYPE_B;
                node->base.flags.miniscript_mod_z = 0;
                node->base.flags.miniscript_mod_o = X_o;
                node->base.flags.miniscript_mod_n = 1;
                node->base.flags.miniscript_mod_d = 1;
                node->base.flags.miniscript_mod_u = X_u;
                break;
            case TOKEN_N:
                if (X_type != MINISCRIPT_TYPE_B) {
                    return WITH_ERROR(-1, "'n' wrapper requires a B type child");
                }

                node->base.flags.is_miniscript = 1;
                node->base.flags.miniscript_type = MINISCRIPT_TYPE_B;
                node->base.flags.miniscript_mod_z = X_z;
                node->base.flags.miniscript_mod_o = X_o;
                node->base.flags.miniscript_mod_n = X_n;
                node->base.flags.miniscript_mod_d = X_d;
                node->base.flags.miniscript_mod_u = 1;
                break;
            case TOKEN_L:
                // l:X == or_i(0,X)

                if (X_type != MINISCRIPT_TYPE_B) {
                    return WITH_ERROR(-1, "'l' wrapper requires a B type child");
                }

                node->base.flags.is_miniscript = 1;
                node->base.flags.miniscript_type = MINISCRIPT_TYPE_B;
                node->base.flags.miniscript_mod_z = 0;
                node->base.flags.miniscript_mod_o = X_z;
                node->base.flags.miniscript_mod_n = 0;
                node->base.flags.miniscript_mod_d = 1;
                node->base.flags.miniscript_mod_u = X_u;
                break;
            case TOKEN_U:
                // u:X == or_i(X,0)

                if (X_type != MINISCRIPT_TYPE_B) {
                    return WITH_ERROR(-1, "'u' wrapper requires a B type child");
                }

                node->base.flags.is_miniscript = 1;
                node->base.flags.miniscript_type = MINISCRIPT_TYPE_B;
                node->base.flags.miniscript_mod_z = 0;
                node->base.flags.miniscript_mod_o = X_z;
                node->base.flags.miniscript_mod_n = 0;
                node->base.flags.miniscript_mod_d = 1;
                node->base.flags.miniscript_mod_u = X_u;
                break;
            default:
                return WITH_ERROR(-1, "unreachable code reached");
        }
    }

    return 0;
}

// Parses a TREE expression inside tr()
// `depth` here refers to the depth inside the policy, therefore it starts at 1 for the taptree
static int parse_tree(buffer_t *in_buf, buffer_t *out_buf, int version, size_t depth) {
    // out_buf must be aligned before calling this function

    if (depth > MAX_TAPTREE_POLICY_DEPTH) {
        return WITH_ERROR(-1, "Taptree policy depth limit exceeded");
    }

    if (!buffer_is_cur_aligned(out_buf)) {
        return WITH_ERROR(-1, "out_buf not aligned");
    }

    policy_node_tree_t *tree_node =
        (policy_node_tree_t *) buffer_alloc(out_buf, sizeof(policy_node_tree_t), true);

    if (tree_node == NULL) {
        return WITH_ERROR(-1, "Out of memory");
    }

    uint8_t c;

    // the first character must be a '{'
    if (!buffer_peek(in_buf, &c)) {
        return WITH_ERROR(-1, "buffer ended too early");
    }

    if (c != '{') {
        // parse a SCRIPT
        tree_node->is_leaf = true;

        buffer_alloc(out_buf, 0, true);  // ensure alignment of current pointer
        i_policy_node(&tree_node->script, buffer_get_cur(out_buf));
        if (0 > parse_script(in_buf, out_buf, version, depth + 1, CONTEXT_WITHIN_TR)) {
            return -1;
        }
    } else {
        // parse a {TREE,TREE}
        tree_node->is_leaf = false;
        buffer_seek_cur(in_buf, 1);  // skip '{'

        // parse first TREE expression
        buffer_alloc(out_buf, 0, true);  // ensure alignment of current pointer
        i_policy_node_tree(&tree_node->left_tree, buffer_get_cur(out_buf));
        if (0 > parse_tree(in_buf, out_buf, version, depth + 1)) {
            return -1;
        }

        // the next character must be a comma
        if (!consume_character(in_buf, ',')) {
            return WITH_ERROR(-1, "Expected a comma");
        }

        // parse the second TREE expression
        buffer_alloc(out_buf, 0, true);  // ensure alignment of current pointer
        i_policy_node_tree(&tree_node->right_tree, buffer_get_cur(out_buf));
        if (0 > parse_tree(in_buf, out_buf, version, depth + 1)) {
            return -1;
        }

        // the next character must be a '}'
        if (!consume_character(in_buf, '}')) {
            return WITH_ERROR(-1, "Expected a '}'");
        }
    }

    return 0;
}

int parse_descriptor_template(buffer_t *in_buf, void *out, size_t out_len, int version) {
    if ((unsigned long) out % 4 != 0) {
        return WITH_ERROR(-1, "Unaligned pointer");
    }

    if (version != WALLET_POLICY_VERSION_V1 && version != WALLET_POLICY_VERSION_V2) {
        return WITH_ERROR(-1, "Unsupported wallet policy version");
    }

    buffer_t out_buf = buffer_create(out, out_len);

    int result = parse_script(in_buf, &out_buf, version, 0, 0);
    if (result < 0) {
        return result;
    }

    // the offset of the buffer is the size of the parsed descriptor template
    return (int) out_buf.offset;
}

int get_policy_segwit_version(const policy_node_t *policy) {
    if (policy->type == TOKEN_TR) {
        return 1;
    } else if (policy->type == TOKEN_SH) {
        const policy_node_t *inner =
            r_policy_node(&((const policy_node_with_script_t *) policy)->script);
        if (inner->type == TOKEN_WPKH || inner->type == TOKEN_WSH) {
            return 0;  // wrapped segwit
        } else {
            return -1;  // legacy
        }
    } else if (policy->type == TOKEN_WPKH || policy->type == TOKEN_WSH) {
        return 0;  // native segwit
    } else {
        return -1;  // legacy
    }
}

/**
 * Convenience function that returns a + b, except:
 * - returns -1 if any of a and b is negative
 * - returns INT16_MAX if the sum of a and b is bigger than INT16_MAX = 32767.
 * Used to combine satisfaction/dissatisfaction for miniscript.
 */
static int16_t sumcheck(int16_t a, int16_t b) {
    if (a < 0 || b < 0)
        return -1;
    else if ((uint32_t) a + (uint32_t) b > INT16_MAX)
        return INT16_MAX;
    else
        return a + b;
}

/**
 * Convenience function that whichever of a and b is not negative; if both are positive, returns the
 * largest. If both are negative, returns either of the two. Used to combine
 * satisfaction/dissatisfaction for miniscript.
 */
static int16_t maxcheck(int16_t a, int16_t b) {
    if (a < 0)
        return b;
    else
        return a > b ? a : b;
}

// The two functions below are kept out of line on purpose: their arrays would otherwise be part of
// the stack frame of compute_miniscript_policy_ext_info(), which is recursive, and would therefore
// be reserved once per level of the policy even for the nodes that are not thresh. As they are,
// they only use stack while a thresh node is being processed, and the nesting of thresh nodes is
// limited to MAX_THRESH_NESTING while parsing.
__attribute__((noinline)) static int compute_thresh_ops(const policy_node_thresh_t *node,
                                                        miniscript_ops_t *out,
                                                        MiniscriptContext ctx) {
    uint16_t sats[MAX_N_IN_THRESH + 1 + 1] = {0};
    uint16_t next_sats[MAX_N_IN_THRESH + 1 + 1] = {0};  // it temporarily uses an extra element

    if (node->n > MAX_N_IN_THRESH) return -1;

    policy_node_scriptlist_t *cur = r_policy_node_scriptlist(&node->scriptlist);

    out->count = 0;

    sats[0] = 0;
    int sats_size = 1;

    while (cur != NULL) {
        policy_node_ext_info_t t;
        if (0 > compute_miniscript_policy_ext_info(r_policy_node(&cur->script), &t, ctx)) return -1;

        out->count += t.ops.count + 1;

        next_sats[0] = sumcheck(sats[0], t.ops.dsat);
        for (int j = 1; j < sats_size; j++) {
            next_sats[j] =
                maxcheck(sumcheck(sats[j], t.ops.dsat), sumcheck(sats[j - 1], t.ops.sat));
        }
        next_sats[sats_size] = sumcheck(sats[sats_size - 1], t.ops.sat);

        ++sats_size;
        memmove(sats, next_sats, sats_size * sizeof(sats[0]));

        cur = r_policy_node_scriptlist(&cur->next);
    }

    out->sat = sats[node->k];
    out->dsat = sats[0];
    return 0;
}

__attribute__((noinline)) static int compute_thresh_stacksize(const policy_node_thresh_t *node,
                                                              miniscript_stacksize_t *out,
                                                              MiniscriptContext ctx) {
    uint16_t sats[MAX_N_IN_THRESH + 1 + 1] = {0};
    uint16_t next_sats[MAX_N_IN_THRESH + 1 + 1] = {0};  // it temporarily uses an extra element

    if (node->n > MAX_N_IN_THRESH) return -1;

    policy_node_scriptlist_t *cur = r_policy_node_scriptlist(&node->scriptlist);

    sats[0] = 0;
    int sats_size = 1;

    while (cur != NULL) {
        policy_node_ext_info_t t;
        if (0 > compute_miniscript_policy_ext_info(r_policy_node(&cur->script), &t, ctx)) return -1;

        next_sats[0] = sumcheck(sats[0], t.ss.dsat);
        for (int j = 1; j < sats_size; j++) {
            next_sats[j] = maxcheck(sumcheck(sats[j], t.ss.dsat), sumcheck(sats[j - 1], t.ss.sat));
        }
        next_sats[sats_size] = sumcheck(sats[sats_size - 1], t.ss.sat);

        ++sats_size;
        memmove(sats, next_sats, sats_size * sizeof(sats[0]));

        cur = r_policy_node_scriptlist(&cur->next);
    }

    out->sat = sats[node->k];
    out->dsat = sats[0];
    return 0;
}

int compute_miniscript_policy_ext_info(const policy_node_t *policy_node,
                                       policy_node_ext_info_t *out,
                                       MiniscriptContext ctx) {
    if (!policy_node->flags.is_miniscript) {
        return WITH_ERROR(-1, "Not miniscript");
    }

    if (ctx != MINISCRIPT_CONTEXT_P2WSH && ctx != MINISCRIPT_CONTEXT_TAPSCRIPT) {
        return WITH_ERROR(-1, "Unknown miniscript context");
    }

    memset(out, 0, sizeof(policy_node_ext_info_t));

    // set flags that are 1 in most cases (they will be zeroed when appropriate)
    out->m = 1;
    out->k = 1;
    out->x = 1;

    switch (policy_node->type) {
        case TOKEN_0:
            out->s = 1;
            out->e = 1;

            out->script_size = 1;

            out->ops = (miniscript_ops_t) {0, -1, 0};
            out->ss = (miniscript_stacksize_t) {-1, 0};

            return 0;
        case TOKEN_1:
            out->f = 1;

            out->script_size = 1;

            out->ops = (miniscript_ops_t) {0, 0, -1};
            out->ss = (miniscript_stacksize_t) {0, -1};

            return 0;
        case TOKEN_PK_K:
            out->s = 1;
            out->e = 1;

            out->script_size = (ctx == MINISCRIPT_CONTEXT_TAPSCRIPT ? 33 : 34);

            out->ops = (miniscript_ops_t) {0, 0, 0};
            out->ss = (miniscript_stacksize_t) {1, 1};

            return 0;
        case TOKEN_PK_H:
            out->s = 1;
            out->e = 1;

            out->script_size = 3 + 21;

            out->ops = (miniscript_ops_t) {3, 0, 0};
            out->ss = (miniscript_stacksize_t) {2, 2};

            return 0;
        case TOKEN_PK:  // pk(key) = c:pk_k(key)
            out->s = 1;
            out->e = 1;

            out->x = 0;

            out->script_size = (ctx == MINISCRIPT_CONTEXT_TAPSCRIPT ? 34 : 35);

            out->ops = (miniscript_ops_t) {1, 0, 0};
            out->ss = (miniscript_stacksize_t) {1, 1};

            return 0;
        case TOKEN_PKH:  // pkh(key) = c:pk_h(key)
            out->s = 1;
            out->e = 1;

            out->x = 0;

            out->script_size = 3 + 21 + 1;

            out->ops = (miniscript_ops_t) {4, 0, 0};
            out->ss = (miniscript_stacksize_t) {2, 2};

            return 0;
        case TOKEN_MULTI: {
            const policy_node_multisig_t *node = (const policy_node_multisig_t *) policy_node;

            out->s = 1;
            out->e = 1;

            out->x = 0;

            out->script_size = (uint16_t) (1 + get_push_script_size(node->k) +
                                           get_push_script_size(node->n) + 34 * node->n);

            out->ops = (miniscript_ops_t) {1, node->n, node->n};
            out->ss = (miniscript_stacksize_t) {node->k + 1, node->k + 1};

            return 0;
        }
        case TOKEN_MULTI_A: {
            const policy_node_multisig_t *node = (const policy_node_multisig_t *) policy_node;

            out->s = 1;
            out->e = 1;

            out->x = 0;

            out->script_size = (uint16_t) (1 + get_push_script_size(node->k) + 34 * node->n);

            out->ops = (miniscript_ops_t) {node->n + 1, 0, 0};
            out->ss = (miniscript_stacksize_t) {node->n, node->n};

            return 0;
        }
        case TOKEN_OLDER: {
            const policy_node_with_uint32_t *node = (const policy_node_with_uint32_t *) policy_node;

            out->f = 1;

            if (node->n & SEQUENCE_LOCKTIME_TYPE_FLAG) {
                out->g = 1;
            } else {
                out->h = 1;
            }

            out->script_size = (uint16_t) (1 + get_push_script_size(node->n));

            out->ops = (miniscript_ops_t) {1, 0, -1};
            out->ss = (miniscript_stacksize_t) {0, -1};

            return 0;
        }
        case TOKEN_AFTER: {
            const policy_node_with_uint32_t *node = (const policy_node_with_uint32_t *) policy_node;

            out->f = 1;

            if (node->n >= LOCKTIME_THRESHOLD) {
                out->i = 1;
            } else {
                out->j = 1;
            }

            out->script_size = (uint16_t) (1 + get_push_script_size(node->n));

            out->ops = (miniscript_ops_t) {1, 0, -1};
            out->ss = (miniscript_stacksize_t) {0, -1};

            return 0;
        }
        case TOKEN_SHA256:
        case TOKEN_HASH256:
            out->x = 0;

            out->script_size = 4 + 2 + 33;

            out->ops = (miniscript_ops_t) {4, 0, -1};
            out->ss = (miniscript_stacksize_t) {1, -1};

            return 0;
        case TOKEN_RIPEMD160:
        case TOKEN_HASH160:
            out->x = 0;

            out->script_size = 4 + 2 + 21;

            out->ops = (miniscript_ops_t) {4, 0, -1};
            out->ss = (miniscript_stacksize_t) {1, -1};

            return 0;
        case TOKEN_ANDOR: {
            const policy_node_with_script3_t *node =
                (const policy_node_with_script3_t *) policy_node;
            policy_node_ext_info_t x;
            policy_node_ext_info_t y;
            policy_node_ext_info_t z;

            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->scripts[0]), &x, ctx))
                return -1;
            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->scripts[1]), &y, ctx))
                return -1;
            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->scripts[2]), &z, ctx))
                return -1;

            out->s = z.s & (x.s | y.s);
            out->f = z.f & (x.s | y.f);
            out->e = z.e & (x.s | y.f);

            out->m = x.m & y.m & z.m & x.e & (x.s | y.s | z.s);

            out->g = x.g | y.g | z.g;
            out->h = x.h | y.h | z.h;
            out->i = x.i | y.i | z.i;
            out->j = x.j | y.j | z.j;

            if (!(x.k & y.k & z.k) || (x.g & y.h) || (x.h & y.g) || (x.i & y.j) || (x.j & y.i)) {
                out->k = 0;
            }

            out->script_size = 3 + x.script_size + y.script_size + z.script_size;

            out->ops = (miniscript_ops_t) {
                3 + x.ops.count + y.ops.count + z.ops.count,
                maxcheck(sumcheck(y.ops.sat, x.ops.sat), sumcheck(y.ops.dsat, z.ops.sat)),
                sumcheck(x.ops.dsat, z.ops.dsat)};
            out->ss = (miniscript_stacksize_t) {
                maxcheck(sumcheck(x.ss.sat, y.ss.sat), sumcheck(x.ss.dsat, z.ss.sat)),
                sumcheck(x.ss.dsat, z.ss.dsat)};

            return 0;
        }
        case TOKEN_AND_V: {
            const policy_node_with_script2_t *node =
                (const policy_node_with_script2_t *) policy_node;
            policy_node_ext_info_t x;
            policy_node_ext_info_t y;

            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->scripts[0]), &x, ctx))
                return -1;
            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->scripts[1]), &y, ctx))
                return -1;

            out->s = x.s | y.s;
            out->f = x.s | y.f;

            out->m = x.m & y.m;

            out->g = x.g | y.g;
            out->h = x.h | y.h;
            out->i = x.i | y.i;
            out->j = x.j | y.j;

            if (!(x.k & y.k) || (x.g & y.h) || (x.h & y.g) || (x.i & y.j) || (x.j & y.i)) {
                out->k = 0;
            }

            out->x = y.x;

            out->script_size = x.script_size + y.script_size;

            out->ops =
                (miniscript_ops_t) {x.ops.count + y.ops.count, sumcheck(x.ops.sat, y.ops.sat), -1};
            out->ss = (miniscript_stacksize_t) {sumcheck(x.ss.sat, y.ss.sat), -1};
            return 0;
        }
        case TOKEN_AND_B: {
            const policy_node_with_script2_t *node =
                (const policy_node_with_script2_t *) policy_node;
            policy_node_ext_info_t x;
            policy_node_ext_info_t y;

            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->scripts[0]), &x, ctx))
                return -1;
            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->scripts[1]), &y, ctx))
                return -1;

            out->s = x.s | y.s;
            out->f = (x.f & y.f) | (x.s & x.f) | (y.s & y.f);
            out->e = x.e & y.e & x.s & y.s;

            out->m = x.m & y.m;

            out->g = x.g | y.g;
            out->h = x.h | y.h;
            out->i = x.i | y.i;
            out->j = x.j | y.j;

            if (!(x.k & y.k) || (x.g & y.h) || (x.h & y.g) || (x.i & y.j) || (x.j & y.i)) {
                out->k = 0;
            }

            out->script_size = 1 + x.script_size + y.script_size;

            out->ops = (miniscript_ops_t) {1 + x.ops.count + y.ops.count,
                                           sumcheck(x.ops.sat, y.ops.sat),
                                           sumcheck(x.ops.dsat, y.ops.dsat)};
            out->ss = (miniscript_stacksize_t) {sumcheck(x.ss.sat, y.ss.sat),
                                                sumcheck(x.ss.dsat, y.ss.dsat)};

            return 0;
        }
        case TOKEN_AND_N: {  // == andor(X,Y,0)
            const policy_node_with_script2_t *node =
                (const policy_node_with_script2_t *) policy_node;
            policy_node_ext_info_t x;
            policy_node_ext_info_t y;

            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->scripts[0]), &x, ctx))
                return -1;
            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->scripts[1]), &y, ctx))
                return -1;

            out->s = x.s | y.s;
            out->e = x.s | y.f;

            out->m = x.m & y.m & x.e & (x.s | y.s);

            out->g = x.g | y.g;
            out->h = x.h | y.h;
            out->i = x.i | y.i;
            out->j = x.j | y.j;

            if (!(x.k & y.k) || (x.g & y.h) || (x.h & y.g) || (x.i & y.j) || (x.j & y.i)) {
                out->k = 0;
            }

            out->script_size = 4 + x.script_size + y.script_size;

            out->ops = (miniscript_ops_t) {3 + x.ops.count + y.ops.count,
                                           maxcheck(sumcheck(y.ops.sat, x.ops.sat), y.ops.dsat),
                                           x.ops.dsat};
            out->ss = (miniscript_stacksize_t) {sumcheck(x.ss.sat, y.ss.sat), x.ss.dsat};
            return 0;
        }
        case TOKEN_OR_B: {
            const policy_node_with_script2_t *node =
                (const policy_node_with_script2_t *) policy_node;
            policy_node_ext_info_t x;
            policy_node_ext_info_t z;

            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->scripts[0]), &x, ctx))
                return -1;
            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->scripts[1]), &z, ctx))
                return -1;

            out->s = x.s & z.s;
            out->e = 1;

            out->m = x.m & z.m & x.e & z.e & (x.s | z.s);

            out->g = x.g | z.g;
            out->h = x.h | z.h;
            out->i = x.i | z.i;
            out->j = x.j | z.j;

            out->k = x.k & z.k;

            out->script_size = 1 + x.script_size + z.script_size;

            out->ops = (miniscript_ops_t) {
                1 + x.ops.count + z.ops.count,
                maxcheck(sumcheck(x.ops.sat, z.ops.dsat), sumcheck(z.ops.sat, x.ops.dsat)),
                sumcheck(x.ops.dsat, z.ops.dsat)};
            out->ss = (miniscript_stacksize_t) {
                maxcheck(sumcheck(x.ss.dsat, z.ss.sat), sumcheck(x.ss.sat, z.ss.dsat)),
                sumcheck(x.ss.dsat, z.ss.dsat)};
            return 0;
        }
        case TOKEN_OR_C: {
            const policy_node_with_script2_t *node =
                (const policy_node_with_script2_t *) policy_node;
            policy_node_ext_info_t x;
            policy_node_ext_info_t z;

            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->scripts[0]), &x, ctx))
                return -1;
            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->scripts[1]), &z, ctx))
                return -1;

            out->s = x.s & z.s;
            out->f = 1;

            out->m = x.m & z.m & x.e & (x.s | z.s);

            out->g = x.g | z.g;
            out->h = x.h | z.h;
            out->i = x.i | z.i;
            out->j = x.j | z.j;

            out->k = x.k & z.k;

            out->script_size = 2 + x.script_size + z.script_size;

            out->ops = (miniscript_ops_t) {2 + x.ops.count + z.ops.count,
                                           maxcheck(x.ops.sat, sumcheck(z.ops.sat, x.ops.dsat)),
                                           -1};
            out->ss =
                (miniscript_stacksize_t) {maxcheck(x.ss.sat, sumcheck(x.ss.dsat, z.ss.sat)), -1};
            return 0;
        }
        case TOKEN_OR_D: {
            const policy_node_with_script2_t *node =
                (const policy_node_with_script2_t *) policy_node;
            policy_node_ext_info_t x;
            policy_node_ext_info_t z;

            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->scripts[0]), &x, ctx))
                return -1;
            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->scripts[1]), &z, ctx))
                return -1;

            out->s = x.s & z.s;
            out->f = z.f;
            out->e = z.e;

            out->m = x.m & z.m & x.e & (x.s | z.s);

            out->g = x.g | z.g;
            out->h = x.h | z.h;
            out->i = x.i | z.i;
            out->j = x.j | z.j;

            out->k = x.k & z.k;

            out->script_size = 3 + x.script_size + z.script_size;

            out->ops = (miniscript_ops_t) {3 + x.ops.count + z.ops.count,
                                           maxcheck(x.ops.sat, sumcheck(z.ops.sat, x.ops.dsat)),
                                           sumcheck(x.ops.dsat, z.ops.dsat)};
            out->ss = (miniscript_stacksize_t) {maxcheck(x.ss.sat, sumcheck(x.ss.dsat, z.ss.sat)),
                                                sumcheck(x.ss.dsat, z.ss.dsat)};
            return 0;
        }
        case TOKEN_OR_I: {
            const policy_node_with_script2_t *node =
                (const policy_node_with_script2_t *) policy_node;
            policy_node_ext_info_t x;
            policy_node_ext_info_t z;

            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->scripts[0]), &x, ctx))
                return -1;
            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->scripts[1]), &z, ctx))
                return -1;

            out->s = x.s & z.s;
            out->f = x.f & z.f;
            out->e = (x.e & z.f) | (z.e & x.f);

            out->m = x.m & z.m & (x.s | z.s);

            out->g = x.g | z.g;
            out->h = x.h | z.h;
            out->i = x.i | z.i;
            out->j = x.j | z.j;

            out->k = x.k & z.k;

            out->script_size = 3 + x.script_size + z.script_size;

            out->ops = (miniscript_ops_t) {3 + x.ops.count + z.ops.count,
                                           maxcheck(x.ops.sat, z.ops.sat),
                                           maxcheck(x.ops.dsat, z.ops.dsat)};
            out->ss =
                (miniscript_stacksize_t) {maxcheck(sumcheck(x.ss.sat, 1), sumcheck(z.ss.sat, 1)),
                                          maxcheck(sumcheck(x.ss.dsat, 1), sumcheck(z.ss.dsat, 1))};

            return 0;
        }
        case TOKEN_THRESH: {
            const policy_node_thresh_t *node = (const policy_node_thresh_t *) policy_node;

            policy_node_scriptlist_t *cur = r_policy_node_scriptlist(&node->scriptlist);

            int count_s = 0;
            int count_e = 0;
            int count_m = 0;
            size_t children_scriptsize = 0;
            size_t n_children = 0;
            while (cur != NULL) {
                ++n_children;

                policy_node_ext_info_t t;
                if (0 > compute_miniscript_policy_ext_info(r_policy_node(&cur->script), &t, ctx))
                    return -1;

                if (t.e) {
                    ++count_e;
                }
                if (t.s) {
                    ++count_s;
                }
                if (t.m) {
                    ++count_m;
                }
                cur = r_policy_node_scriptlist(&cur->next);

                out->g |= t.g;
                out->h |= t.h;
                out->i |= t.i;
                out->j |= t.j;

                out->k &= t.k;  // if any child doesn't have k, thresh doesn't have k

                // if any two children have mixed timelocks, thresh doesn't have k
                if (node->k >= 2 &&
                    ((t.g & out->h) || (t.h & out->g) || (t.i & out->j) || (t.j & out->i))) {
                    out->k = 0;
                }

                children_scriptsize += t.script_size;
            }

            int count_not_s = node->n - count_s;

            out->s = count_not_s <= node->k - 1 ? 1 : 0;
            out->e = count_s == node->n ? 1 : 0;

            out->m = (count_e == node->n && count_m == node->n && count_not_s <= node->k) ? 1 : 0;

            out->x = 0;

            out->script_size = children_scriptsize + n_children + get_push_script_size(node->k);

            if (0 > compute_thresh_ops(node, &out->ops, ctx)) return -1;
            if (0 > compute_thresh_stacksize(node, &out->ss, ctx)) return -1;

            return 0;
        }
        case TOKEN_A: {
            const policy_node_with_script_t *node = (const policy_node_with_script_t *) policy_node;
            policy_node_ext_info_t x;

            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->script), &x, ctx))
                return -1;

            out->s = x.s;
            out->f = x.f;
            out->e = x.e;

            out->m = x.m;

            out->g = x.g;
            out->h = x.h;
            out->i = x.i;
            out->j = x.j;
            out->k = x.k;

            out->script_size = x.script_size + 2;

            out->ops = (miniscript_ops_t) {2 + x.ops.count, x.ops.sat, x.ops.dsat};
            out->ss = x.ss;

            return 0;
        }
        case TOKEN_S:
        case TOKEN_N: {
            const policy_node_with_script_t *node = (const policy_node_with_script_t *) policy_node;
            policy_node_ext_info_t x;

            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->script), &x, ctx))
                return -1;

            out->s = x.s;
            out->f = x.f;
            out->e = x.e;

            out->m = x.m;

            out->g = x.g;
            out->h = x.h;
            out->i = x.i;
            out->j = x.j;
            out->k = x.k;

            if (policy_node->type == TOKEN_S) out->x = x.x;

            out->script_size = x.script_size + 1;

            out->ops = (miniscript_ops_t) {1 + x.ops.count, x.ops.sat, x.ops.dsat};
            out->ss = x.ss;

            return 0;
        }
        case TOKEN_C: {
            const policy_node_with_script_t *node = (const policy_node_with_script_t *) policy_node;
            policy_node_ext_info_t x;

            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->script), &x, ctx))
                return -1;

            out->s = 1;
            out->f = x.f;
            out->e = x.e;

            out->m = x.m;

            out->g = x.g;
            out->h = x.h;
            out->i = x.i;
            out->j = x.j;
            out->k = x.k;

            out->x = x.x;

            out->script_size = x.script_size + 1;

            out->x = 0;

            out->ops = (miniscript_ops_t) {1 + x.ops.count, x.ops.sat, x.ops.dsat};
            out->ss = x.ss;

            return 0;
        }
        case TOKEN_D: {
            const policy_node_with_script_t *node = (const policy_node_with_script_t *) policy_node;
            policy_node_ext_info_t x;

            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->script), &x, ctx))
                return -1;

            out->s = x.s;
            out->e = 1;

            out->m = x.m;

            out->g = x.g;
            out->h = x.h;
            out->i = x.i;
            out->j = x.j;
            out->k = x.k;

            out->script_size = x.script_size + 3;

            out->ops = (miniscript_ops_t) {3 + x.ops.count, x.ops.sat, 0};
            out->ss = (miniscript_stacksize_t) {sumcheck(1, x.ss.sat), 1};

            return 0;
        }
        case TOKEN_T: {  // and_v(X,1)
            const policy_node_with_script_t *node = (const policy_node_with_script_t *) policy_node;
            policy_node_ext_info_t x;

            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->script), &x, ctx))
                return -1;

            out->s = x.s;
            out->f = 1;

            out->m = x.m;

            out->g = x.g;
            out->h = x.h;
            out->i = x.i;
            out->j = x.j;
            out->k = x.k;

            out->script_size = x.script_size + 1;

            out->ops = (miniscript_ops_t) {x.ops.count, x.ops.sat, -1};

            out->ss = (miniscript_stacksize_t) {x.ss.sat, -1};

            return 0;
        }
        case TOKEN_V: {
            const policy_node_with_script_t *node = (const policy_node_with_script_t *) policy_node;
            policy_node_ext_info_t x;

            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->script), &x, ctx))
                return -1;

            out->s = x.s;
            out->f = 1;

            out->m = x.m;

            out->g = x.g;
            out->h = x.h;
            out->i = x.i;
            out->j = x.j;
            out->k = x.k;

            out->script_size = x.script_size + x.x;

            out->ops = (miniscript_ops_t) {x.ops.count + x.x, x.ops.sat, -1};
            out->ss = (miniscript_stacksize_t) {x.ss.sat, -1};

            return 0;
        }
        case TOKEN_J: {
            const policy_node_with_script_t *node = (const policy_node_with_script_t *) policy_node;
            policy_node_ext_info_t x;

            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->script), &x, ctx))
                return -1;

            out->s = x.s;
            out->e = x.f;

            out->m = x.m;

            out->g = x.g;
            out->h = x.h;
            out->i = x.i;
            out->j = x.j;
            out->k = x.k;

            out->script_size = x.script_size + 4;

            out->ops = (miniscript_ops_t) {4 + x.ops.count, x.ops.sat, 0};
            out->ss = (miniscript_stacksize_t) {x.ss.sat, 1};

            return 0;
        }
        case TOKEN_L:    // or_i(0,X)
        case TOKEN_U: {  // or_i(X,0)
            const policy_node_with_script_t *node = (const policy_node_with_script_t *) policy_node;
            policy_node_ext_info_t x;

            if (0 > compute_miniscript_policy_ext_info(r_policy_node(&node->script), &x, ctx))
                return -1;

            out->s = x.s;
            out->f = 0;
            out->e = x.f;

            out->m = x.m;

            out->g = x.g;
            out->h = x.h;
            out->i = x.i;
            out->j = x.j;
            out->k = x.k;

            out->script_size = x.script_size + 4;

            out->ops = (miniscript_ops_t) {3 + x.ops.count, x.ops.sat, x.ops.dsat};
            out->ss = (miniscript_stacksize_t) {sumcheck(x.ss.sat, 1),
                                                maxcheck(1, sumcheck(x.ss.dsat, 1))};

            return 0;
        }
        case TOKEN_SORTEDMULTI:
        case TOKEN_SORTEDMULTI_A:
        case TOKEN_WPKH:
        case TOKEN_SH:
        case TOKEN_WSH:
        case TOKEN_TR:
            PRINTF("Not miniscript: %d\n", policy_node->type);
            return -1;
        default:
            PRINTF("%s, %d\n", __FILE__, __LINE__);
            PRINTF("Unknown token: %d\n", policy_node->type);
            return -1;
    }
}

static int traverse_policy_node_tree(const policy_node_tree_t *tree,
                                     policy_node_callback_t callback,
                                     void *callback_state) {
    if (tree->is_leaf) {
        return traverse_policy_dfs(r_policy_node(&tree->script), callback, callback_state);
    } else {
        int ret = traverse_policy_node_tree(r_policy_node_tree(&tree->left_tree),
                                            callback,
                                            callback_state);
        if (ret < 0) return ret;
        return traverse_policy_node_tree(r_policy_node_tree(&tree->right_tree),
                                         callback,
                                         callback_state);
    }
}

int traverse_policy_dfs(const policy_node_t *policy_node,
                        policy_node_callback_t callback,
                        void *callback_state) {
    if (callback == NULL) {
        return -1;
    }

    // Visit the current node first (pre-order)
    int ret = callback(policy_node, callback_state);
    if (ret < 0) return ret;

    switch (policy_node->type) {
        // Leaf nodes with no child scripts
        case TOKEN_0:
        case TOKEN_1:
        case TOKEN_PK_K:
        case TOKEN_PK_H:
        case TOKEN_PK:
        case TOKEN_PKH:
        case TOKEN_WPKH:
        case TOKEN_OLDER:
        case TOKEN_AFTER:
        case TOKEN_SHA256:
        case TOKEN_HASH256:
        case TOKEN_RIPEMD160:
        case TOKEN_HASH160:
        case TOKEN_MULTI:
        case TOKEN_MULTI_A:
        case TOKEN_SORTEDMULTI:
        case TOKEN_SORTEDMULTI_A:
            return 0;

        // Nodes with a single child script (including miniscript wrappers)
        case TOKEN_SH:
        case TOKEN_WSH:
        case TOKEN_A:
        case TOKEN_S:
        case TOKEN_C:
        case TOKEN_T:
        case TOKEN_D:
        case TOKEN_V:
        case TOKEN_J:
        case TOKEN_N:
        case TOKEN_L:
        case TOKEN_U: {
            const policy_node_with_script_t *node = (const policy_node_with_script_t *) policy_node;
            return traverse_policy_dfs(r_policy_node(&node->script), callback, callback_state);
        }

        // Nodes with exactly two child scripts
        case TOKEN_AND_V:
        case TOKEN_AND_B:
        case TOKEN_AND_N:
        case TOKEN_OR_B:
        case TOKEN_OR_C:
        case TOKEN_OR_D:
        case TOKEN_OR_I: {
            const policy_node_with_script2_t *node =
                (const policy_node_with_script2_t *) policy_node;
            ret = traverse_policy_dfs(r_policy_node(&node->scripts[0]), callback, callback_state);
            if (ret < 0) return ret;
            return traverse_policy_dfs(r_policy_node(&node->scripts[1]), callback, callback_state);
        }

        // Nodes with exactly three child scripts
        case TOKEN_ANDOR: {
            const policy_node_with_script3_t *node =
                (const policy_node_with_script3_t *) policy_node;
            ret = traverse_policy_dfs(r_policy_node(&node->scripts[0]), callback, callback_state);
            if (ret < 0) return ret;
            ret = traverse_policy_dfs(r_policy_node(&node->scripts[1]), callback, callback_state);
            if (ret < 0) return ret;
            return traverse_policy_dfs(r_policy_node(&node->scripts[2]), callback, callback_state);
        }

        // Nodes with a linked list of child scripts
        case TOKEN_THRESH: {
            const policy_node_thresh_t *node = (const policy_node_thresh_t *) policy_node;
            policy_node_scriptlist_t *cur = r_policy_node_scriptlist(&node->scriptlist);
            while (cur != NULL) {
                ret = traverse_policy_dfs(r_policy_node(&cur->script), callback, callback_state);
                if (ret < 0) return ret;
                cur = r_policy_node_scriptlist(&cur->next);
            }
            return 0;
        }

        // tr nodes with a keypath and (possibly) a taptree
        case TOKEN_TR: {
            const policy_node_tr_t *node = (const policy_node_tr_t *) policy_node;
            if (!isnull_policy_node_tree(&node->tree)) {
                return traverse_policy_node_tree(r_policy_node_tree(&node->tree),
                                                 callback,
                                                 callback_state);
            }
            return 0;
        }
        case TOKEN_INVALID:
        default:
            PRINTF("traverse_policy_dfs: unexpected token %d\n", policy_node->type);
            return -1;
    }
}

void get_policy_wallet_id(policy_map_wallet_header_t *wallet_header, uint8_t out[static 32]) {
    cx_sha256_t wallet_hash_context;
    cx_sha256_init(&wallet_hash_context);

    crypto_hash_update_u8(&wallet_hash_context.header, wallet_header->version);
    crypto_hash_update_u8(&wallet_hash_context.header, wallet_header->name_len);
    crypto_hash_update(&wallet_hash_context.header, wallet_header->name, wallet_header->name_len);

    crypto_hash_update_varint(&wallet_hash_context.header, wallet_header->descriptor_template_len);

    if (wallet_header->version == WALLET_POLICY_VERSION_V1) {
        crypto_hash_update(&wallet_hash_context.header,
                           wallet_header->descriptor_template,
                           wallet_header->descriptor_template_len);
    } else {  // WALLET_POLICY_VERSION_V2
        crypto_hash_update(&wallet_hash_context.header,
                           wallet_header->descriptor_template_sha256,
                           32);
    }

    crypto_hash_update_varint(&wallet_hash_context.header, wallet_header->n_keys);

    crypto_hash_update(&wallet_hash_context.header, wallet_header->keys_info_merkle_root, 32);

    crypto_hash_digest(&wallet_hash_context.header, out, 32);
}
