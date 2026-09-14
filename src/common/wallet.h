#pragma once

#include <assert.h>
#include <stdint.h>

/* SDK headers */
#include "bip32.h"
#include "buffer.h"

/* Local headers */
#include "constants.h"
#include "crypto.h"

#include "os.h"
#include "cx.h"

// The maximum number of keys supported for CHECKMULTISIG{VERIFY}
// bitcoin-core supports up to 20, but we limit to 16 as bigger pushes require special handling.
#define MAX_PUBKEYS_PER_MULTISIG 16

// The maximum number of keys supported in a musig() key expression
// It is basically unlimited in theory, but we need to set a practical limit.
// The implementation of MuSig2 requires quite a few large arrays (for example, the pubnonces are
// 66 bytes each, and there is one for each cosigner), therefore we keep this quite small.
// Increasing this might require optimizing the memory management in the MuSig2 implementation.
#define MAX_PUBKEYS_PER_MUSIG 5

#define WALLET_POLICY_VERSION_V1 1  // the legacy version of the first release
#define WALLET_POLICY_VERSION_V2 2  // the current full version

// The string describing a pubkey can contain:
// - (optional) the key origin info, which we limit to 46 bytes (2 + 8 + 8*12 = 106 bytes)
// - the xpub itself (up to 113 characters)
// - optional, the "/**" suffix.
// Therefore, the total length of the key info string is at most 162 bytes.
#define MAX_POLICY_KEY_INFO_LEN_V1 (106 + MAX_SERIALIZED_PUBKEY_LENGTH + 3)

// In V1, there is no "/**" suffix, as that is no longer part of the key
#define MAX_POLICY_KEY_INFO_LEN_V2 (106 + MAX_SERIALIZED_PUBKEY_LENGTH)

#define MAX_POLICY_KEY_INFO_LEN MAX(MAX_POLICY_KEY_INFO_LEN_V1, MAX_POLICY_KEY_INFO_LEN_V2)

// longest supported policy in V1 is "sh(wsh(sortedmulti(5,@0,@1,@2,@3,@4)))", 38 bytes
#define MAX_DESCRIPTOR_TEMPLATE_LENGTH_V1 40

// Maximum number of keys supported for a wallet policy. It is a technical limit to
// bound the total memory occupation of a wallet policy, and could be increased if necessary.
#define MAX_N_KEYS_IN_WALLET_POLICY 15

// This amount should be enough for many useful policies
// We do not expect these limits to be reached in practice any time soon, but they can
// be further increased if necessary.
#define MAX_DESCRIPTOR_TEMPLATE_LENGTH_V2 512

// Memory reserved for the abstract syntax tree of a parsed wallet policy.
// We declare the size based on the size of pointers (which is 4 on the real device),
// so that it doesn't need to be changed when compiling for unit tests.
#ifdef TARGET_NANOX
// The Nano X has considerably less RAM than the other devices, therefore we keep the budget
// smaller - which might reject some very large policies.
#define MAX_WALLET_POLICY_BYTES 1024
#else
#define MAX_WALLET_POLICY_BYTES (384 * sizeof(void *))  // 1536 on the real devices
#endif

#define MAX_DESCRIPTOR_TEMPLATE_LENGTH \
    MAX(MAX_DESCRIPTOR_TEMPLATE_LENGTH_V1, MAX_DESCRIPTOR_TEMPLATE_LENGTH_V2)

// As parse_script is recursive, we set a maximum reasonable recursion depth in order to avoid the
// risk of stack exhaustion.
// This depth is unlikely to be hit in practice.
// Miniscript wrappers are counted as well: while they are not parsed recursively, they still
// increase the depth of the parsed policy, which affects other recursive walkers.
#define MAX_PARSE_SCRIPT_RECURSION_DEPTH 16

// Maximum supported nesting of thresh operators
#define MAX_THRESH_NESTING 4

// Maximum supported value for n in a thresh miniscript operator (technical limitation).
// It also bounds the stack used while analyzing a policy: the arrays of compute_thresh_ops() and
// compute_thresh_stacksize() are proportional to it, and up to MAX_THRESH_NESTING of them are
// alive at the same time due to recursion, therefore this ends up eating a substantial amount of
// memory.
// This limit is extremely unlikely to be hit in practice.
#define MAX_N_IN_THRESH 24

// at most 140 bytes
// wallet type (1 byte)
// name length (1 byte)
// name (max MAX_WALLET_NAME_LENGTH bytes)
// policy length (1 byte)
// policy (max MAX_DESCRIPTOR_TEMPLATE_LENGTH bytes)
// n_keys (1 byte)
// keys_merkle_root (32 bytes)
#define MAX_WALLET_POLICY_SERIALIZED_LENGTH_V1 \
    (1 + 1 + MAX_WALLET_NAME_LENGTH + 1 + MAX_DESCRIPTOR_TEMPLATE_LENGTH_V1 + 1 + 32)

// at most 148 bytes
// wallet type (1 byte)
// name length (1 byte)
// name (max MAX_WALLET_NAME_LENGTH bytes)
// policy length (varint, up to 9 bytes)
// policy hash 32
// n_keys (varint, up to 9 bytes)
// keys_merkle_root (32 bytes)
#define MAX_WALLET_POLICY_SERIALIZED_LENGTH_V2 (1 + 1 + MAX_WALLET_NAME_LENGTH + 9 + 32 + 9 + 32)

#define MAX_WALLET_POLICY_SERIALIZED_LENGTH \
    MAX(MAX_WALLET_POLICY_SERIALIZED_LENGTH_V1, MAX_WALLET_POLICY_SERIALIZED_LENGTH_V2)

// maximum depth of a taproot tree that we support
// (here depth 1 means only the root of the taptree)
#define MAX_TAPTREE_POLICY_DEPTH 9

typedef struct {
    uint32_t master_key_derivation[MAX_BIP388_XPUB_DERIVATION_STEPS];
    uint8_t master_key_fingerprint[4];
    uint8_t master_key_derivation_len;
    uint8_t has_key_origin;
    uint8_t has_wildcard;  // true iff the keys ends with the wildcard (/ followed by **)
    serialized_extended_pubkey_t ext_pubkey;
} policy_map_key_info_t;

typedef struct {
    uint8_t version;  // supported values: WALLET_POLICY_VERSION_V1 and WALLET_POLICY_VERSION_V2
    uint8_t name_len;
    uint16_t descriptor_template_len;
    char name[MAX_WALLET_NAME_LENGTH + 1];
    union {
        char descriptor_template[MAX_DESCRIPTOR_TEMPLATE_LENGTH_V1];  // used in V1
        uint8_t descriptor_template_sha256[32];                       // used in V2
    };
    size_t n_keys;
    uint8_t keys_info_merkle_root[32];  // root of the Merkle tree of the keys information
} policy_map_wallet_header_t;

typedef enum {
    TOKEN_SH,
    TOKEN_WSH,
    TOKEN_PK,
    TOKEN_PKH,
    TOKEN_WPKH,
    // TOKEN_COMBO     // disabled, does not mix well with the script policy language
    TOKEN_MULTI,
    TOKEN_MULTI_A,
    TOKEN_SORTEDMULTI,
    TOKEN_SORTEDMULTI_A,
    TOKEN_TR,
    // TOKEN_ADDR,     // unsupported
    // TOKEN_RAW,      // unsupported

    /* miniscript tokens */

    TOKEN_0,
    TOKEN_1,
    TOKEN_PK_K,
    TOKEN_PK_H,
    TOKEN_OLDER,
    TOKEN_AFTER,
    TOKEN_SHA256,
    TOKEN_HASH256,
    TOKEN_RIPEMD160,
    TOKEN_HASH160,
    TOKEN_ANDOR,
    TOKEN_AND_V,
    TOKEN_AND_B,
    TOKEN_AND_N,
    TOKEN_OR_B,
    TOKEN_OR_C,
    TOKEN_OR_D,
    TOKEN_OR_I,
    TOKEN_THRESH,
    // wrappers
    TOKEN_A,
    TOKEN_S,
    TOKEN_C,
    TOKEN_T,
    TOKEN_D,
    TOKEN_V,
    TOKEN_J,
    TOKEN_N,
    TOKEN_L,
    TOKEN_U,

    TOKEN_INVALID = -1  // used to mark invalid tokens
} PolicyNodeType;

typedef enum {
    MINISCRIPT_CONTEXT_P2WSH,
    MINISCRIPT_CONTEXT_TAPSCRIPT,
} MiniscriptContext;

// miniscript basic types
#define MINISCRIPT_TYPE_B 0
#define MINISCRIPT_TYPE_V 1
#define MINISCRIPT_TYPE_K 2
#define MINISCRIPT_TYPE_W 3

// The structures below make up the abstract syntax tree of a wallet policy. They are all
// bump-allocated inside a single buffer by parse_descriptor_template(), and they refer to each
// other with plain pointers into that same buffer; therefore, the tree is only valid as long as
// the buffer it was parsed into is alive, and it cannot be moved elsewhere.
// The sizes in the comments below are the ones for the 32-bit devices.

// 8 bytes
typedef struct policy_node_s {
    PolicyNodeType type;
    struct {
        unsigned int is_miniscript : 1;
        unsigned int miniscript_type : 2;  // B, C, K or W
        unsigned int miniscript_mod_z : 1;
        unsigned int miniscript_mod_o : 1;
        unsigned int miniscript_mod_n : 1;
        unsigned int miniscript_mod_d : 1;
        unsigned int miniscript_mod_u : 1;
    } flags;  // 4 bytes
} policy_node_t;

typedef struct miniscript_ops_s {
    uint16_t count;  // non-push opcodes
    int16_t sat;     // number of keys in possibly executed OP_CHECKMULTISIG(VERIFY)s to satisfy (-1
                     // for "invalid")
    int16_t dsat;    // number of keys in possibly executed OP_CHECKMULTISIG(VERIFY)s to dissatisfy
                     // (-1 for "invalid")
} miniscript_ops_t;

typedef struct miniscript_stacksize_s {
    int16_t sat;   // Maximum stack size to satisfy
    int16_t dsat;  // Maximum stack size to dissatisfy
} miniscript_stacksize_t;

typedef struct policy_node_ext_info_s {
    miniscript_ops_t ops;
    miniscript_stacksize_t ss;
    uint16_t script_size;

    unsigned int s : 1;  // has a signature

    unsigned int f : 1;  // forced
    unsigned int e : 1;

    unsigned int m : 1;  // non-malleable property

    // flags related to timelocks
    unsigned int g : 1;  // older: contains relative time timelock   (csv_time)
    unsigned int h : 1;  // older: contains relative height timelock (csv_height)
    unsigned int i : 1;  // after: contains time timelock   (cltv_time)
    unsigned int j : 1;  // after: contains height timelock (cltv_height)
    unsigned int k : 1;  // does not contain a combination of height and time locks

    unsigned int x : 1;  // the last opcode is not EQUAL, CHECKSIG, or CHECKMULTISIG
} policy_node_ext_info_t;

// 8 bytes
typedef struct {
    uint16_t n;             // number of key indexes
    uint16_t *key_indexes;  // pointer to an array of exactly n key indexes
} musig_aggr_key_info_t;

typedef enum {
    KEY_EXPRESSION_NORMAL = 0,  // a key expression with a single key expression
    KEY_EXPRESSION_MUSIG = 1    // a key expression containing a musig()
} KeyExpressionType;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcomment"
// The compiler doesn't like /** inside a block comment, so we disable this warning temporarily.

/** Structure representing a key expression.
 * In V1, it's the index of a key in the key information array, which includes the final /** step.
 * In V2, it's the index of a key in the key information array, plus the two numbers a, b in the
 * /<NUM_a;NUM_b>/* derivation steps; here, the xpubs in the key information array don't have extra
 * derivation steps.
 */
#pragma GCC diagnostic pop

// 20 bytes
typedef struct {
    // the following fields are only used in V2
    uint32_t num_first;   // NUM_a of /<NUM_a,NUM_b>/*
    uint32_t num_second;  // NUM_b of /<NUM_a,NUM_b>/*

    KeyExpressionType type;
    union {
        // type == 0
        struct {
            uint16_t key_index;  // index of the key (common between V1 and V2)
        } k;
        // type == 1
        struct {
            musig_aggr_key_info_t *musig_info;  // only used in V2
        } m;
    };
    uint16_t
        keyexpr_index;  // index of the key expression in the descriptor template, in parsing order
} policy_node_keyexpr_t;

// 8 bytes
typedef struct {
    struct policy_node_s base;
} policy_node_constant_t;

// 12 bytes
typedef struct {
    struct policy_node_s base;
    policy_node_t *script;
} policy_node_with_script_t;

// 16 bytes
typedef struct {
    struct policy_node_s base;
    policy_node_t *scripts[2];
} policy_node_with_script2_t;

// 20 bytes
typedef struct {
    struct policy_node_s base;
    policy_node_t *scripts[3];
} policy_node_with_script3_t;

// generic type with pointer for up to 3 (but constant) number of child scripts
typedef policy_node_with_script3_t policy_node_with_scripts_t;

// 12 bytes
typedef struct {
    struct policy_node_s base;
    policy_node_keyexpr_t *key;
} policy_node_with_key_t;

// 12 bytes
typedef struct {
    struct policy_node_s base;
    uint32_t n;
} policy_node_with_uint32_t;

// 16 bytes
typedef struct {
    struct policy_node_s base;    // type is TOKEN_MULTI or TOKEN_SORTEDMULTI
    uint16_t k;                   // threshold
    uint16_t n;                   // number of keys
    policy_node_keyexpr_t *keys;  // pointer to array of exactly n key expressions
} policy_node_multisig_t;

// 8 bytes
typedef struct policy_node_scriptlist_s {
    struct policy_node_scriptlist_s *next;
    policy_node_t *script;
} policy_node_scriptlist_t;

// 16 bytes, (+ 8 bytes for every script)
typedef struct {
    struct policy_node_s base;             // type is TOKEN_THRESH
    uint16_t k;                            // threshold
    uint16_t n;                            // number of child scripts
    policy_node_scriptlist_t *scriptlist;  // pointer to a linked list of exactly n child scripts
} policy_node_thresh_t;

typedef struct {
    struct policy_node_s base;  // type is TOKEN_SHA160 or TOKEN_HASH160
    uint8_t h[20];
} policy_node_with_hash_160_t;

typedef struct {
    struct policy_node_s base;  // type is TOKEN_SHA256 or TOKEN_HASH256
    uint8_t h[32];
} policy_node_with_hash_256_t;

// a TREE is either a script, or a {TREE,TREE}
// 12 bytes
typedef struct policy_node_tree_s {
    bool is_leaf;  // if this is a leaf, then it contains a pointer to a SCRIPT;
                   // otherwise, it contains two pointers to TREE expressions.
    union {
        policy_node_t *script;  // pointer to a policy_node_with_script_t
        struct {
            struct policy_node_tree_s *left_tree;
            struct policy_node_tree_s *right_tree;
        };
    };
} policy_node_tree_t;

// 16 bytes
typedef struct {
    struct policy_node_s base;
    policy_node_keyexpr_t *key;
    policy_node_tree_t *tree;  // NULL if tr(KP)
} policy_node_tr_t;

/**
 * Parses the string in the `buffer` as a serialized policy map into `header`
 *
 * @param buffer the pointer to the buffer_t to parse
 * @param header the pointer to a `policy_map_wallet_header_t` structure
 * @return a negative number on failure, 0 on success.
 */
int read_wallet_policy_header(buffer_t *buffer, policy_map_wallet_header_t *header);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcomment"
// The compiler doesn't like /** inside a block comment, so we disable this warning temporarily.

/**
 * Parses a string representing the key information for a policy map wallet.
 * The string is compatible with the output descriptor format, except that the pubkey must _not_
 * have derivation steps (the key origin info, if present, does have derivation steps from the
 * master key fingerprint). The serialized base58check-encoded pubkey is _not_ validated.
 *
 * For WALLET_POLICY_VERSION_V1, the final suffix /** must be present and is part of the key
 * information. For WALLET_POLICY_VERSION_V2, parsing stops at the xpub.

 * Example (V1):
 * "[d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/**"
 * Example (V2):
 * "[d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
 */
int parse_policy_map_key_info(buffer_t *buffer, policy_map_key_info_t *out, int version);

#pragma GCC diagnostic pop

/**
 * Parses `in_buf` as a wallet policy descriptor template, constructing the abstract syntax tree in
 * the buffer `out` of size `out_len`.
 *
 * When parsing descriptors containing miniscript, this fails if the miniscript is not correct,
 * as defined by the miniscript type system.
 * This does NOT check non-malleability of the miniscript.
 * @param in_buf the buffer containing the policy map to parse
 * @param out the pointer to the output buffer, which must be 4-byte aligned
 * @param out_len the length of the output buffer
 * @param version either WALLET_POLICY_VERSION_V1 or WALLET_POLICY_VERSION_V2
 * @return The memory size of the parsed descriptor template (that is, the number of bytes consumed
 * in the output buffer) on success; -1 in case of parsing error, if the output buffer is unaligned,
 * or if the output buffer is too small.
 */
int parse_descriptor_template(buffer_t *in_buf, void *out, size_t out_len, int version);

/**
 * Given a valid policy that the bitcoin app is able to sign, returns the segwit version.
 * The result is undefined for a node that is not a valid root of a wallet policy that the bitcoin
 * app is able to sign.
 *
 * @param policy the root node of the wallet policy
 * @return -1 if it's a legacy policy, 0 if it is a policy for SegwitV0 (possibly nested), 1 for
 * SegwitV1 (taproot).
 */
int get_policy_segwit_version(const policy_node_t *policy);

/**
 * Computes additional properties of the given miniscript, to detect malleability and other security
 * properties to assess if the miniscript is sane.
 * The stack size limits are only valid for miniscript within wsh.
 *
 * @param policy_node a pointer to a miniscript policy node
 * @param out pointer to the output policy_node_ext_info_t
 * @param ctx either MINISCRIPT_CONTEXT_P2WSH or MINISCRIPT_CONTEXT_TAPSCRIPT
 * @return a negative number on error; 0 on success.
 */
int compute_miniscript_policy_ext_info(const policy_node_t *policy_node,
                                       policy_node_ext_info_t *out,
                                       MiniscriptContext ctx);

/**
 * Callback type for traverse_policy_dfs.
 * Called for each node in depth-first (pre-order) traversal.
 *
 * @param node pointer to the current policy node
 * @param callback_state opaque pointer passed through from the caller
 * @return 0 on success; a negative number to abort traversal with an error.
 */
typedef int (*policy_node_callback_t)(const policy_node_t *node, void *callback_state);

/**
 * Recursively traverses a descriptor template tree in depth-first (pre-order) order, calling
 * the callback for each node.
 * Traversal stops early if the callback returns a negative value.
 *
 * @param policy_node pointer to the root of the subtree to traverse
 * @param callback function called for each node
 * @param callback_state opaque pointer forwarded to the callback
 * @return 0 on success; a negative number on error (from callback or unexpected node type).
 */
int traverse_policy_dfs(const policy_node_t *policy_node,
                        policy_node_callback_t callback,
                        void *callback_state);

/**
 * Computes the id of the policy map wallet (commitment to header + policy map + keys_info), as per
 * specifications.
 *
 * @param wallet_header
 * @param out a pointer to a 32-byte array for the output
 */
void get_policy_wallet_id(policy_map_wallet_header_t *wallet_header, uint8_t out[static 32]);
