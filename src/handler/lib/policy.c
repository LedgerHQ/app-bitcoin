#include <stdlib.h>

#include "policy.h"

/* SDK headers */
#include "base58.h"
#include "ledger_assert.h"
#include "read.h"

/* Local headers */
#include "bitvector.h"
#include "crypto.h"
#include "debug.h"
#include "get_merkle_leaf_element.h"
#include "get_preimage.h"
#include "musig.h"
#include "script.h"
#include "segwit_addr.h"
#include "wallet.h"

#define MAX_POLICY_DEPTH 10

// The last opcode must be processed as a VERIFY flag
#define PROCESSOR_FLAG_V 1

/**
 * The label used to derive the symmetric key used to register/verify wallet policies on device.
 */
#define WALLET_SLIP0021_LABEL "\0LEDGER-Wallet policy"
#define WALLET_SLIP0021_LABEL_LEN \
    (sizeof(WALLET_SLIP0021_LABEL) - 1)  // sizeof counts the terminating 0

typedef struct {
    const policy_node_t *policy_node;

    // bytes written to output
    uint16_t length;
    // used to identify the stage of execution for nodes that require multiple rounds
    uint8_t step;

    uint8_t flags;
} policy_parser_node_state_t;

typedef struct {
    dispatcher_context_t *dispatcher_context;
    const wallet_derivation_info_t *wdi;
    bool is_taproot;

    policy_parser_node_state_t nodes[MAX_POLICY_DEPTH];  // stack of nodes being processed
    int node_stack_eos;  // index of node being processed within nodes; will be set -1 at the end of
                         // processing

    cx_hash_t *hash_context;
    uint8_t hash[32];  // when a node is popped, the hash is computed here
} policy_parser_state_t;

// comparator for pointers to arrays of equal length
static int cmp_arrays(const void *a, const void *b, size_t length) {
    const uint8_t *key_a = (const uint8_t *) a;
    const uint8_t *key_b = (const uint8_t *) b;
    for (size_t i = 0; i < length; i++) {
        int diff = key_a[i] - key_b[i];
        if (diff != 0) {
            return diff;
        }
    }
    return 0;
}

typedef int (*policy_parser_processor_t)(policy_parser_state_t *state, const void *arg);

typedef enum {
    CMD_CODE_OP,       // data is a byte to emit (usually an opcode)
    CMD_CODE_OP_V,     // data is an opcode, but transform according to 'v' if necessary
    CMD_CODE_PUSH_PK,  // push the compressed pubkey indicated by the current policy_node_with_key_t
    CMD_CODE_PUSH_PKH,         // push the hash160 of the compressed pubkey indicated by the current
                               // policy_node_with_key_t
    CMD_CODE_PUSH_UINT32,      // push the integer in the current policy_node_with_uint32_t
    CMD_CODE_PUSH_HASH20,      // push a 20 bytes hash in the current policy_node_with_hash_160_t
    CMD_CODE_PUSH_HASH32,      // push a 32 bytes hash in the current policy_node_with_hash_256_t
    CMD_CODE_PROCESS_CHILD,    // process the i-th script of a policy_node_with_scripts_t,
                               // where i is indicated by the command data
    CMD_CODE_PROCESS_CHILD_V,  // like the previous, but it propagates the v flag to the child
    CMD_CODE_PROCESS_CHILD_VV,  // like the previous, but it activates the v flag in the child

    CMD_CODE_END  // last step, should terminate here
} generic_processor_command_code_e;

typedef struct {
    uint8_t code;
    uint8_t data;
} generic_processor_command_t;

// Whitelistes for allowed fragments when processing inner scripts expressions
static const uint8_t fragment_whitelist_sh[] = {TOKEN_WPKH, TOKEN_MULTI, TOKEN_SORTEDMULTI};
static const uint8_t fragment_whitelist_sh_wsh[] = {TOKEN_MULTI, TOKEN_SORTEDMULTI};
static const uint8_t fragment_whitelist_wsh[] = {
    /* tokens for scripts on segwit */
    TOKEN_0,
    TOKEN_1,
    TOKEN_PK,
    TOKEN_PKH,
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
    TOKEN_MULTI,
    TOKEN_OR_B,
    TOKEN_OR_C,
    TOKEN_OR_D,
    TOKEN_OR_I,
    TOKEN_SORTEDMULTI,
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
    TOKEN_U};
static const uint8_t fragment_whitelist_tapscript[] = {
    /* tokens for scripts in taptrees */
    TOKEN_0,
    TOKEN_1,
    TOKEN_PK,
    TOKEN_PKH,
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
    TOKEN_MULTI_A,
    TOKEN_OR_B,
    TOKEN_OR_C,
    TOKEN_OR_D,
    TOKEN_OR_I,
    TOKEN_SORTEDMULTI_A,
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
    TOKEN_U};

static const generic_processor_command_t commands_0[] = {{CMD_CODE_OP_V, OP_0}, {CMD_CODE_END, 0}};
static const generic_processor_command_t commands_1[] = {{CMD_CODE_OP_V, OP_1}, {CMD_CODE_END, 0}};
static const generic_processor_command_t commands_pk_k[] = {{CMD_CODE_PUSH_PK, 0},
                                                            {CMD_CODE_END, 0}};
static const generic_processor_command_t commands_pk_h[] = {{CMD_CODE_OP, OP_DUP},
                                                            {CMD_CODE_OP, OP_HASH160},
                                                            {CMD_CODE_PUSH_PKH, 0},
                                                            {CMD_CODE_OP, OP_EQUALVERIFY},
                                                            {CMD_CODE_END, 0}};
static const generic_processor_command_t commands_pk[] = {{CMD_CODE_PUSH_PK, 0},
                                                          {CMD_CODE_OP_V, OP_CHECKSIG},
                                                          {CMD_CODE_END, 0}};
static const generic_processor_command_t commands_older[] = {{CMD_CODE_PUSH_UINT32, 0},
                                                             {CMD_CODE_OP_V, OP_CSV},
                                                             {CMD_CODE_END, 0}};
static const generic_processor_command_t commands_after[] = {{CMD_CODE_PUSH_UINT32, 0},
                                                             {CMD_CODE_OP_V, OP_CLTV},
                                                             {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_sha256[] = {{CMD_CODE_OP, OP_SIZE},
                                                              {CMD_CODE_OP, 1},   // 1-byte push
                                                              {CMD_CODE_OP, 32},  // pushed value
                                                              {CMD_CODE_OP, OP_EQUALVERIFY},
                                                              {CMD_CODE_OP, OP_SHA256},
                                                              {CMD_CODE_PUSH_HASH32, 0},
                                                              {CMD_CODE_OP_V, OP_EQUAL},
                                                              {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_hash256[] = {{CMD_CODE_OP, OP_SIZE},
                                                               {CMD_CODE_OP, 1},   // 1-byte push
                                                               {CMD_CODE_OP, 32},  // pushed value
                                                               {CMD_CODE_OP, OP_EQUALVERIFY},
                                                               {CMD_CODE_OP, OP_HASH256},
                                                               {CMD_CODE_PUSH_HASH32, 0},
                                                               {CMD_CODE_OP_V, OP_EQUAL},
                                                               {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_ripemd160[] = {{CMD_CODE_OP, OP_SIZE},
                                                                 {CMD_CODE_OP, 1},   // 1-byte push
                                                                 {CMD_CODE_OP, 32},  // pushed value
                                                                 {CMD_CODE_OP, OP_EQUALVERIFY},
                                                                 {CMD_CODE_OP, OP_RIPEMD160},
                                                                 {CMD_CODE_PUSH_HASH20, 0},
                                                                 {CMD_CODE_OP_V, OP_EQUAL},
                                                                 {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_hash160[] = {{CMD_CODE_OP, OP_SIZE},
                                                               {CMD_CODE_OP, 1},   // 1-byte push
                                                               {CMD_CODE_OP, 32},  // pushed value
                                                               {CMD_CODE_OP, OP_EQUALVERIFY},
                                                               {CMD_CODE_OP, OP_HASH160},
                                                               {CMD_CODE_PUSH_HASH20, 0},
                                                               {CMD_CODE_OP_V, OP_EQUAL},
                                                               {CMD_CODE_END, 0}};

// andor(X,Y,X) ==> [X] NOTIF [Z] ELSE [Y] ENDIF
static const generic_processor_command_t commands_andor[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                             {CMD_CODE_OP, OP_NOTIF},
                                                             {CMD_CODE_PROCESS_CHILD, 2},
                                                             {CMD_CODE_OP, OP_ELSE},
                                                             {CMD_CODE_PROCESS_CHILD, 1},
                                                             {CMD_CODE_OP_V, OP_ENDIF},
                                                             {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_and_v[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                             {CMD_CODE_PROCESS_CHILD_V, 1},
                                                             {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_and_b[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                             {CMD_CODE_PROCESS_CHILD, 1},
                                                             {CMD_CODE_OP_V, OP_BOOLAND},
                                                             {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_and_n[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                             {CMD_CODE_OP, OP_NOTIF},
                                                             {CMD_CODE_OP, OP_0},
                                                             {CMD_CODE_OP, OP_ELSE},
                                                             {CMD_CODE_PROCESS_CHILD, 1},
                                                             {CMD_CODE_OP_V, OP_ENDIF},
                                                             {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_or_b[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                            {CMD_CODE_PROCESS_CHILD, 1},
                                                            {CMD_CODE_OP_V, OP_BOOLOR},
                                                            {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_or_c[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                            {CMD_CODE_OP, OP_NOTIF},
                                                            {CMD_CODE_PROCESS_CHILD, 1},
                                                            {CMD_CODE_OP_V, OP_ENDIF},
                                                            {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_or_d[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                            {CMD_CODE_OP, OP_IFDUP},
                                                            {CMD_CODE_OP, OP_NOTIF},
                                                            {CMD_CODE_PROCESS_CHILD, 1},
                                                            {CMD_CODE_OP_V, OP_ENDIF},
                                                            {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_or_i[] = {{CMD_CODE_OP, OP_IF},
                                                            {CMD_CODE_PROCESS_CHILD, 0},
                                                            {CMD_CODE_OP, OP_ELSE},
                                                            {CMD_CODE_PROCESS_CHILD, 1},
                                                            {CMD_CODE_OP_V, OP_ENDIF},
                                                            {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_a[] = {{CMD_CODE_OP, OP_TOALTSTACK},
                                                         {CMD_CODE_PROCESS_CHILD, 0},
                                                         {CMD_CODE_OP, OP_FROMALTSTACK},
                                                         {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_s[] = {{CMD_CODE_OP, OP_SWAP},
                                                         {CMD_CODE_PROCESS_CHILD, 0},
                                                         {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_c[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                         {CMD_CODE_OP_V, OP_CHECKSIG},
                                                         {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_t[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                         {CMD_CODE_OP_V, OP_1},
                                                         {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_d[] = {{CMD_CODE_OP, OP_DUP},
                                                         {CMD_CODE_OP, OP_IF},
                                                         {CMD_CODE_PROCESS_CHILD, 0},
                                                         {CMD_CODE_OP_V, OP_ENDIF},
                                                         {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_v[] = {{CMD_CODE_PROCESS_CHILD_VV, 0},
                                                         {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_j[] = {{CMD_CODE_OP, OP_SIZE},
                                                         {CMD_CODE_OP, OP_0NOTEQUAL},
                                                         {CMD_CODE_OP, OP_IF},
                                                         {CMD_CODE_PROCESS_CHILD, 0},
                                                         {CMD_CODE_OP_V, OP_ENDIF},
                                                         {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_n[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                         {CMD_CODE_OP_V, OP_0NOTEQUAL},
                                                         {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_l[] = {{CMD_CODE_OP, OP_IF},
                                                         {CMD_CODE_OP, OP_0},
                                                         {CMD_CODE_OP, OP_ELSE},
                                                         {CMD_CODE_PROCESS_CHILD, 0},
                                                         {CMD_CODE_OP_V, OP_ENDIF},
                                                         {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_u[] = {{CMD_CODE_OP, OP_IF},
                                                         {CMD_CODE_PROCESS_CHILD, 0},
                                                         {CMD_CODE_OP, OP_ELSE},
                                                         {CMD_CODE_OP, OP_0},
                                                         {CMD_CODE_OP_V, OP_ENDIF},
                                                         {CMD_CODE_END, 0}};

int read_and_parse_wallet_policy(
    dispatcher_context_t *dispatcher_context,
    buffer_t *buf,
    policy_map_wallet_header_t *wallet_header,
    uint8_t policy_map_descriptor_template[static MAX_DESCRIPTOR_TEMPLATE_LENGTH],
    uint8_t *policy_map_bytes,
    size_t policy_map_bytes_len) {
    if ((read_wallet_policy_header(buf, wallet_header)) < 0) {
        return WITH_ERROR(-1, "Failed reading wallet policy header");
    }

    if (wallet_header->version == WALLET_POLICY_VERSION_V1) {
        memcpy(policy_map_descriptor_template,
               wallet_header->descriptor_template,
               wallet_header->descriptor_template_len);
    } else {
        // if V2, stream and parse descriptor template from client first
        int descriptor_template_len = call_get_preimage(dispatcher_context,
                                                        wallet_header->descriptor_template_sha256,
                                                        policy_map_descriptor_template,
                                                        MAX_DESCRIPTOR_TEMPLATE_LENGTH);
        if (descriptor_template_len < 0) {
            return WITH_ERROR(-1, "Failed getting wallet policy descriptor template");
        }
        if ((size_t) descriptor_template_len != wallet_header->descriptor_template_len) {
            return WITH_ERROR(-1, "Descriptor template length mismatch");
        }
    }

    buffer_t policy_map_buffer =
        buffer_create(policy_map_descriptor_template, wallet_header->descriptor_template_len);

    int desc_temp_len = parse_descriptor_template(&policy_map_buffer,
                                                  policy_map_bytes,
                                                  policy_map_bytes_len,
                                                  wallet_header->version);
    if (desc_temp_len < 0) {
        return WITH_ERROR(-1, "Failed parsing descriptor template");
    }
    return desc_temp_len;
}

/**
 * Pushes a node onto the stack. Returns 0 on success, -1 if the stack is exhausted.
 */
__attribute__((warn_unused_result)) static int state_stack_push(policy_parser_state_t *state,
                                                                const policy_node_t *policy_node,
                                                                uint8_t flags) {
    ++state->node_stack_eos;

    if (state->node_stack_eos >= MAX_POLICY_DEPTH) {
        return WITH_ERROR(-1, "Reached maximum policy depth");
    }

    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];
    node->policy_node = policy_node;
    node->length = 0;
    node->step = 0;
    node->flags = flags;

    return 0;
}

/**
 * Pops a node from the stack.
 * Returns the emitted length on success, -1 on error.
 */
__attribute__((warn_unused_result)) static int state_stack_pop(policy_parser_state_t *state) {
    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];

    if (state->node_stack_eos <= -1) {
        return WITH_ERROR(-1, "Stack underflow");
    }

    --state->node_stack_eos;

    if (state->node_stack_eos >= 0) {
        state->nodes[state->node_stack_eos].length += node->length;
    }
    return node->length;
}

__attribute__((warn_unused_result)) static inline int
execute_processor(policy_parser_state_t *state, policy_parser_processor_t proc, const void *arg) {
    int ret = proc(state, arg);

    // if the processor is done, pop the stack
    if (ret > 0) {
        return state_stack_pop(state);
    }

    return ret;
}

// p2pkh                     ==> legacy address (start with 1 on mainnet, m or n on testnet)
// p2sh (also nested segwit) ==> legacy script  (start with 3 on mainnet, 2 on testnet)
// p2wpkh or p2wsh           ==> bech32         (start with bc1 on mainnet, tb1 on testnet)

// convenience function, split from get_derived_pubkey only to improve stack usage
// returns -1 on error, 0 if the returned key info has no wildcard (**), 1 if it has the wildcard
__attribute__((noinline, warn_unused_result)) int get_extended_pubkey_from_client(
    dispatcher_context_t *dispatcher_context,
    const wallet_derivation_info_t *wdi,
    int key_index,
    serialized_extended_pubkey_t *out) {
    PRINT_STACK_POINTER();

    policy_map_key_info_t key_info;

    {
        char key_info_str[MAX_POLICY_KEY_INFO_LEN];

        int key_info_len = call_get_merkle_leaf_element(dispatcher_context,
                                                        wdi->keys_merkle_root,
                                                        wdi->n_keys,
                                                        key_index,
                                                        (uint8_t *) key_info_str,
                                                        sizeof(key_info_str));
        if (key_info_len < 0) {
            return -1;
        }

        // Make a sub-buffer for the pubkey info
        buffer_t key_info_buffer = buffer_create(key_info_str, key_info_len);

        if (parse_policy_map_key_info(&key_info_buffer, &key_info, wdi->wallet_version) == -1) {
            return -1;
        }
    }
    *out = key_info.ext_pubkey;

    return key_info.has_wildcard ? 1 : 0;
}

__attribute__((warn_unused_result)) static int get_derived_pubkey(
    dispatcher_context_t *dispatcher_context,
    const wallet_derivation_info_t *wdi,
    const policy_node_keyexpr_t *key_expr,
    uint8_t out[static 33]) {
    PRINT_STACK_POINTER();

    serialized_extended_pubkey_t ext_pubkey;

    if (key_expr->type == KEY_EXPRESSION_NORMAL) {
        if (0 > get_extended_pubkey_from_client(dispatcher_context,
                                                wdi,
                                                key_expr->k.key_index,
                                                &ext_pubkey)) {
            return -1;
        }
    } else if (key_expr->type == KEY_EXPRESSION_MUSIG) {
        const musig_aggr_key_info_t *musig_info = r_musig_aggr_key_info(&key_expr->m.musig_info);
        const uint16_t *key_indexes = r_uint16(&musig_info->key_indexes);
        plain_pk_t keys[MAX_PUBKEYS_PER_MUSIG];
        for (int i = 0; i < musig_info->n; i++) {
            // we use ext_pubkey as a temporary variable; will overwrite later
            if (0 > get_extended_pubkey_from_client(dispatcher_context,
                                                    wdi,
                                                    key_indexes[i],
                                                    &ext_pubkey)) {
                return -1;
            }
            memcpy(keys[i], ext_pubkey.compressed_pubkey, sizeof(ext_pubkey.compressed_pubkey));
        }

        // sort the keys in ascending order
        qsort(keys, musig_info->n, sizeof(plain_pk_t), compare_plain_pk);

        musig_keyagg_context_t musig_ctx;
        if (0 > musig_key_agg(keys, musig_info->n, &musig_ctx)) {
            return -1;
        }

        // compute the aggregated extended pubkey
        memset(&ext_pubkey, 0, sizeof(ext_pubkey));
        write_u32_be(ext_pubkey.version, 0, BIP32_PUBKEY_VERSION);

        ext_pubkey.compressed_pubkey[0] = (musig_ctx.Q.y[31] % 2 == 0) ? 2 : 3;
        memcpy(&ext_pubkey.compressed_pubkey[1], musig_ctx.Q.x, sizeof(musig_ctx.Q.x));
        memcpy(&ext_pubkey.chain_code, BIP_328_CHAINCODE, sizeof(BIP_328_CHAINCODE));
    } else {
        LEDGER_ASSERT(false, "Unreachable code");
    }

    // we derive the /<change>/<address_index> child of this pubkey
    // we reuse the same memory of ext_pubkey
    if (0 > derive_first_step_for_pubkey(&ext_pubkey,
                                         key_expr,
                                         wdi->sign_psbt_cache,
                                         wdi->change,
                                         &ext_pubkey)) {
        return -1;
    }
    if (0 > bip32_CKDpub(&ext_pubkey, wdi->address_index, &ext_pubkey, NULL)) {
        return -1;
    }

    memcpy(out, ext_pubkey.compressed_pubkey, 33);

    return 0;
}

static void update_output(policy_parser_state_t *state, const uint8_t *data, size_t data_len) {
    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];
    node->length += data_len;
    if (state->hash_context != NULL) {
        crypto_hash_update(state->hash_context, data, data_len);
    }
}

static inline void update_output_u8(policy_parser_state_t *state, uint8_t data) {
    update_output(state, &data, 1);
}

// outputs the minimal push opcode for an unsigned 32bit integer
static void update_output_push_u32(policy_parser_state_t *state, uint32_t n) {
    if (n == 0) {
        update_output_u8(state, OP_0);
    } else if (n <= 16) {
        update_output_u8(state, 0x50 + (uint8_t) n);
    } else {
        uint8_t n_le[4];
        write_u32_le(n_le, 0, n);
        uint8_t byte_size;
        if (n <= 0x7f)
            byte_size = 1;
        else if (n <= 0x7fff)
            byte_size = 2;
        else if (n <= 0x7fffff)
            byte_size = 3;
        else if (n <= 0x7fffffff)
            byte_size = 4;
        else
            byte_size = 5;  // no 32-bit number needs more than 5 bytes

        update_output_u8(state, byte_size);
        if (byte_size < 5) {
            update_output(state, n_le, byte_size);
        } else {
            // Since numbers are signed little endian, unsigned numbers bigger than 0x7FFFFFFF
            // need an extra 0x00 byte.
            update_output(state, n_le, 4);
            update_output_u8(state, 0);
        }
    }
}

static void update_output_op_v(policy_parser_state_t *state, uint8_t op) {
    const policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];
    if (node->flags & PROCESSOR_FLAG_V) {
        if (op == OP_CHECKSIG || op == OP_CHECKMULTISIG || op == OP_NUMEQUAL || op == OP_EQUAL) {
            // the _VERIFY versions of the opcodes are all 1 larger
            update_output_u8(state, op + 1);
        } else {
            update_output_u8(state, op);
            update_output_u8(state, OP_VERIFY);
        }
    } else {
        update_output_u8(state, op);
    }
}

__attribute__((warn_unused_result)) static int process_generic_node(policy_parser_state_t *state,
                                                                    const void *arg) {
    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];

    const generic_processor_command_t *commands = (const generic_processor_command_t *) arg;

    size_t n_commands = 0;
    while (commands[n_commands].code != CMD_CODE_END) ++n_commands;

    if (node->step > n_commands) {
        return WITH_ERROR(-1, "Inconsistent state");
    } else if (node->step == n_commands) {
        return 1;
    } else {
        uint8_t cmd_code = commands[node->step].code;
        uint8_t cmd_data = commands[node->step].data;

        switch (cmd_code) {
            case CMD_CODE_OP: {
                update_output_u8(state, cmd_data);
                break;
            }
            case CMD_CODE_OP_V: {
                update_output_op_v(state, cmd_data);
                break;
            }
            case CMD_CODE_PUSH_PK: {
                const policy_node_with_key_t *policy =
                    (const policy_node_with_key_t *) node->policy_node;
                uint8_t compressed_pubkey[33];
                if (-1 == get_derived_pubkey(state->dispatcher_context,
                                             state->wdi,
                                             r_policy_node_keyexpr(&policy->key),
                                             compressed_pubkey)) {
                    return -1;
                }

                if (!state->is_taproot) {
                    update_output_u8(state, 33);  // PUSH 33 bytes
                    update_output(state, compressed_pubkey, 33);
                } else {
                    // x-only pubkey if within taproot
                    update_output_u8(state, 32);  // PUSH 32 bytes
                    update_output(state, compressed_pubkey + 1, 32);
                }
                break;
            }
            case CMD_CODE_PUSH_PKH: {
                const policy_node_with_key_t *policy =
                    (const policy_node_with_key_t *) node->policy_node;
                uint8_t compressed_pubkey[33];
                if (-1 == get_derived_pubkey(state->dispatcher_context,
                                             state->wdi,
                                             r_policy_node_keyexpr(&policy->key),
                                             compressed_pubkey)) {
                    return -1;
                }
                if (!state->is_taproot) {
                    crypto_hash160(compressed_pubkey, 33, compressed_pubkey);  // reuse memory
                } else {
                    // x-only pubkey if within taproot
                    crypto_hash160(compressed_pubkey + 1, 32, compressed_pubkey);  // reuse memory
                }

                update_output_u8(state, 20);  // PUSH 20 bytes
                update_output(state, compressed_pubkey, 20);
                break;
            }
            case CMD_CODE_PUSH_UINT32: {
                const policy_node_with_uint32_t *policy =
                    (const policy_node_with_uint32_t *) node->policy_node;
                update_output_push_u32(state, policy->n);
                break;
            }
            case CMD_CODE_PUSH_HASH20: {
                const policy_node_with_hash_160_t *policy =
                    (const policy_node_with_hash_160_t *) node->policy_node;
                update_output_u8(state, 20);
                update_output(state, policy->h, 20);
                break;
            }
            case CMD_CODE_PUSH_HASH32: {
                const policy_node_with_hash_256_t *policy =
                    (const policy_node_with_hash_256_t *) node->policy_node;
                update_output_u8(state, 32);
                update_output(state, policy->h, 32);
                break;
            }
            case CMD_CODE_PROCESS_CHILD: {
                const policy_node_with_scripts_t *policy =
                    (const policy_node_with_scripts_t *) node->policy_node;
                if (0 > state_stack_push(state, r_policy_node(&policy->scripts[cmd_data]), 0)) {
                    return -1;
                }
                break;
            }
            case CMD_CODE_PROCESS_CHILD_V: {
                const policy_node_with_scripts_t *policy =
                    (const policy_node_with_scripts_t *) node->policy_node;
                if (0 > state_stack_push(state,
                                         r_policy_node(&policy->scripts[cmd_data]),
                                         node->flags)) {
                    return -1;
                }
                break;
            }
            case CMD_CODE_PROCESS_CHILD_VV: {
                const policy_node_with_scripts_t *policy =
                    (const policy_node_with_scripts_t *) node->policy_node;
                if (0 > state_stack_push(state,
                                         r_policy_node(&policy->scripts[cmd_data]),
                                         node->flags | PROCESSOR_FLAG_V)) {
                    return -1;
                }
                break;
            }
            default:
                PRINTF("Unexpected command code: %d\n", cmd_code);
                return -1;
        }
        ++node->step;
        return 0;
    }
}

__attribute__((warn_unused_result)) static int process_pkh_wpkh_node(policy_parser_state_t *state,
                                                                     const void *arg) {
    UNUSED(arg);

    PRINT_STACK_POINTER();

    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];

    if (node->step != 0) {
        return -1;
    }

    policy_node_with_key_t *policy = (policy_node_with_key_t *) node->policy_node;

    uint8_t compressed_pubkey[33];

    if (-1 == get_derived_pubkey(state->dispatcher_context,
                                 state->wdi,
                                 r_policy_node_keyexpr(&policy->key),
                                 compressed_pubkey)) {
        return -1;
    } else if (policy->base.type == TOKEN_PKH) {
        update_output_u8(state, OP_DUP);
        update_output_u8(state, OP_HASH160);

        update_output_u8(state, 20);  // PUSH 20 bytes

        if (!state->is_taproot) {
            crypto_hash160(compressed_pubkey, 33, compressed_pubkey);  // reuse memory
        } else {
            // x-only pubkey if within taproot
            crypto_hash160(compressed_pubkey + 1, 32, compressed_pubkey);  // reuse memory
        }
        update_output(state, compressed_pubkey, 20);

        update_output_u8(state, OP_EQUALVERIFY);
        update_output_op_v(state, OP_CHECKSIG);
    } else {  // policy->base.type == TOKEN_WPKH
        if (state->is_taproot) {
            PRINTF("wpkh is invalid within taproot context");
            return -1;
        }

        update_output_u8(state, OP_0);

        update_output_u8(state, 20);  // PUSH 20 bytes

        crypto_hash160(compressed_pubkey, 33, compressed_pubkey);  // reuse memory
        update_output(state, compressed_pubkey, 20);
    }

    return 1;
}

__attribute__((warn_unused_result)) static int process_thresh_node(policy_parser_state_t *state,
                                                                   const void *arg) {
    UNUSED(arg);

    PRINT_STACK_POINTER();

    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];
    const policy_node_thresh_t *policy = (const policy_node_thresh_t *) node->policy_node;

    // [X1] [X2] ADD ... [Xn] ADD <k> EQUAL

    /*
      It's a bit unnatural to encode thresh in a way that is compatible with our
      stack-based encoder, as every "step" that needs to recur on a child Script
      must emit the child script as its last thing. The natural way of splitting
      this would be:

      [X1]   /   [X2] ADD   /   [X3] ADD   /   ...   /   [Xn] ADD   /   <k> EQUAL

      Instead, we have to split it as follows:

      [X1]   /   [X2]   /   ADD [X3]   /   ...   /   ADD [Xn]   /   ADD <k> EQUAL

      But this is incorrect if n == 1, because the correct encoding is just

      [X1] <k> EQUAL

      Therefore, the case n == 1 needs to be handled separately to avoid the extra ADD.
    */

    // n+1 steps
    // at step i, for 0 <= i < n, we produce [Xi] if i <= 1, or ADD [Xi] otherwise
    // at step n, we produce <k> EQUAL if n == 1, or ADD <k> EQUAL otherwise

    if (node->step < policy->n) {
        // find the current child node
        policy_node_scriptlist_t *cur = r_policy_node_scriptlist(&policy->scriptlist);
        LEDGER_ASSERT(cur != NULL, "This should never happen");
        for (size_t i = 0; i < node->step; i++) {
            cur = r_policy_node_scriptlist(&cur->next);
            LEDGER_ASSERT(cur != NULL, "This should never happen");
        }

        // process child node
        if (node->step > 1) {
            update_output_u8(state, OP_ADD);
        }

        if (-1 == state_stack_push(state, r_policy_node(&cur->script), 0)) {
            return -1;
        }
        ++node->step;
        return 0;
    } else {
        // final step
        if (policy->n >= 2) {
            // no OP_ADD if n == 1, per comment above
            update_output_u8(state, OP_ADD);
        }
        update_output_push_u32(state, policy->k);
        update_output_op_v(state, OP_EQUAL);
        return 1;
    }
}

__attribute__((warn_unused_result)) static int process_multi_sortedmulti_node(
    policy_parser_state_t *state,
    const void *arg) {
    UNUSED(arg);

    PRINT_STACK_POINTER();

    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];
    const policy_node_multisig_t *policy = (const policy_node_multisig_t *) node->policy_node;

    if (policy->n > 16) {
        return WITH_ERROR(-1, "Implemented only for n <= 16");
    }

    // k {pubkey_1} ... {pubkey_n} n OP_CHECKMULTISIG

    update_output_u8(state, 0x50 + policy->k);  // OP_k

    // bitvector of used keys (only relevant for sorting keys in SORTEDMULTI)
    uint8_t used[BITVECTOR_REAL_SIZE(MAX_PUBKEYS_PER_MULTISIG)];
    memset(used, 0, sizeof(used));

    for (int i = 0; i < policy->n; i++) {
        uint8_t compressed_pubkey[33];

        if (policy->base.type == TOKEN_MULTI) {
            if (-1 == get_derived_pubkey(state->dispatcher_context,
                                         state->wdi,
                                         &r_policy_node_keyexpr(&policy->keys)[i],
                                         compressed_pubkey)) {
                return -1;
            }
        } else {
            // sortedmulti is problematic, especially for very large wallets: we don't have enough
            // memory on Nano S to keep all the keys in memory. Therefore, we use a slow method: at
            // each iteration, find the lexicographically smallest key that was not already used
            // (basically, like in insertion sort). This means quadratic communication with the
            // client, and a quadratic number of pubkey derivations as well, which are quite slow.
            // Performance might become an issue for very large multisig wallets, but this allows us
            // to remove any limitation on the supported number of pubkeys, and to keep the code
            // simple.
            // Should speed be reported as an issue in practice, sorting could be done in-memory for
            // non-Nano S devices, instead (requiring 33*MAX_PUBKEYS_PER_MULTISIG > 500 bytes more
            // memory).

            int smallest_pubkey_index = -1;
            memset(compressed_pubkey, 0xFF, sizeof(compressed_pubkey));  // init to largest value

            for (int j = 0; j < policy->n; j++) {
                if (!bitvector_get(used, j)) {
                    uint8_t cur_pubkey[33];
                    if (-1 == get_derived_pubkey(state->dispatcher_context,
                                                 state->wdi,
                                                 &r_policy_node_keyexpr(&policy->keys)[j],
                                                 cur_pubkey)) {
                        return -1;
                    }

                    if (cmp_arrays(compressed_pubkey, cur_pubkey, 33) > 0) {
                        memcpy(compressed_pubkey, cur_pubkey, 33);
                        smallest_pubkey_index = j;
                    }
                }
            }
            bitvector_set(used, smallest_pubkey_index, true);  // mark the key as used
        }

        // push <i-th pubkey> (33 = 0x21 bytes)
        update_output_u8(state, 0x21);
        update_output(state, compressed_pubkey, 33);
    }

    update_output_u8(state, 0x50 + policy->n);    // OP_n
    update_output_op_v(state, OP_CHECKMULTISIG);  // OP_CHECKMULTISIG

    return 1;
}

__attribute__((warn_unused_result)) static int process_multi_a_sortedmulti_a_node(
    policy_parser_state_t *state,
    const void *arg) {
    UNUSED(arg);

    PRINT_STACK_POINTER();

    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];
    const policy_node_multisig_t *policy = (const policy_node_multisig_t *) node->policy_node;

    if (policy->k > 16) {
        return WITH_ERROR(-1, "Implemented only for k <= 16");
    }

    // <pk_1> OP_CHECKSIG <pk_2> OP_CHECKSIGADD ... <pk_n> OP_CHECKSIGADD <k> OP_NUMEQUAL

    // bitvector of used keys (only relevant for sorting keys in SORTEDMULTI)
    uint8_t used[BITVECTOR_REAL_SIZE(MAX_PUBKEYS_PER_MULTISIG)];
    memset(used, 0, sizeof(used));

    for (int i = 0; i < policy->n; i++) {
        uint8_t compressed_pubkey[33];

        if (policy->base.type == TOKEN_MULTI_A) {
            if (-1 == get_derived_pubkey(state->dispatcher_context,
                                         state->wdi,
                                         &r_policy_node_keyexpr(&policy->keys)[i],
                                         compressed_pubkey)) {
                return -1;
            }
        } else {
            // Inefficient O(n^2) sorting; check process_multi_sortedmulti_node for the motivation.

            int smallest_pubkey_index = -1;
            memset(compressed_pubkey, 0xFF, sizeof(compressed_pubkey));  // init to largest value

            for (int j = 0; j < policy->n; j++) {
                if (!bitvector_get(used, j)) {
                    uint8_t cur_pubkey[33];
                    if (-1 == get_derived_pubkey(state->dispatcher_context,
                                                 state->wdi,
                                                 &r_policy_node_keyexpr(&policy->keys)[j],
                                                 cur_pubkey)) {
                        return -1;
                    }

                    // x-only pubkeys must be compared ignoring the first byte
                    if (cmp_arrays(compressed_pubkey + 1, cur_pubkey + 1, 32) > 0) {
                        memcpy(compressed_pubkey, cur_pubkey, 33);
                        smallest_pubkey_index = j;
                    }
                }
            }
            bitvector_set(used, smallest_pubkey_index, true);  // mark the key as used
        }

        // push <i-th pubkey> as x-only key (32 = 0x20 bytes)
        update_output_u8(state, 0x20);
        update_output(state, compressed_pubkey + 1, 32);

        if (i == 0) {
            update_output_u8(state, OP_CHECKSIG);
        } else {
            update_output_u8(state, OP_CHECKSIGADD);
        }
    }

    update_output_u8(state, 0x50 + policy->k);  // <k>
    update_output_op_v(state, OP_NUMEQUAL);     // OP_NUMEQUAL

    return 1;
}

__attribute__((warn_unused_result, noinline)) static int compute_tapleaf_hash(
    dispatcher_context_t *dispatcher_context,
    const wallet_derivation_info_t *wdi,
    const policy_node_t *script_policy,
    uint8_t out[static 32]) {
    cx_sha256_t hash_context;
    crypto_tr_tapleaf_hash_init(&hash_context);

    // we compute the tapscript once just to compute its length
    // this avoids having to store the script in memory
    int tapscript_len = get_wallet_internal_script_hash(dispatcher_context,
                                                        script_policy,
                                                        wdi,
                                                        WRAPPED_SCRIPT_TYPE_TAPSCRIPT,
                                                        NULL);

    if (tapscript_len < 0) {
        return WITH_ERROR(-1, "Failed to compute tapleaf script");
    }

    crypto_hash_update_u8(&hash_context.header, 0xC0);
    crypto_hash_update_varint(&hash_context.header, tapscript_len);

    if (0 > get_wallet_internal_script_hash(dispatcher_context,
                                            script_policy,
                                            wdi,
                                            WRAPPED_SCRIPT_TYPE_TAPSCRIPT,
                                            &hash_context.header)) {
        return WITH_ERROR(-1, "Failed to compute tapscript hash");  // should never happen!
    }

    crypto_hash_digest(&hash_context.header, out, 32);
    return 0;
}

// Separated from compute_taptree_hash to optimize its stack usage
__attribute__((warn_unused_result, noinline)) static int compute_and_combine_taptree_child_hashes(
    dispatcher_context_t *dc,
    const wallet_derivation_info_t *wdi,
    const policy_node_tree_t *tree,
    uint8_t out[static 32]) {
    uint8_t left_h[32], right_h[32];
    if (0 > compute_taptree_hash(dc, wdi, r_policy_node_tree(&tree->left_tree), left_h)) return -1;
    if (0 > compute_taptree_hash(dc, wdi, r_policy_node_tree(&tree->right_tree), right_h))
        return -1;
    crypto_tr_combine_taptree_hashes(left_h, right_h, out);
    return 0;
}

// See taproot_tree_helper in BIP-0341
__attribute__((noinline)) int compute_taptree_hash(dispatcher_context_t *dc,
                                                   const wallet_derivation_info_t *wdi,
                                                   const policy_node_tree_t *tree,
                                                   uint8_t out[static 32]) {
    if (tree->is_leaf)
        return compute_tapleaf_hash(dc, wdi, r_policy_node(&tree->script), out);
    else
        return compute_and_combine_taptree_child_hashes(dc, wdi, tree, out);
}

#pragma GCC diagnostic push
// make sure that the compiler gives an error if any PolicyNodeType is missed
#pragma GCC diagnostic error "-Wswitch-enum"

int get_wallet_script(dispatcher_context_t *dispatcher_context,
                      const policy_node_t *policy,
                      const wallet_derivation_info_t *wdi,
                      uint8_t out[static 34]) {
    int script_type = -1;

    cx_sha256_t hash_context;
    cx_sha256_init(&hash_context);

    if (policy->type == TOKEN_PKH) {
        uint8_t compressed_pubkey[33];
        policy_node_with_key_t *pkh_policy = (policy_node_with_key_t *) policy;
        if (0 > get_derived_pubkey(dispatcher_context,
                                   wdi,
                                   r_policy_node_keyexpr(&pkh_policy->key),
                                   compressed_pubkey)) {
            return -1;
        }
        out[0] = OP_DUP;
        out[1] = OP_HASH160;

        out[2] = 20;  // PUSH 20 bytes

        crypto_hash160(compressed_pubkey, 33, out + 3);

        out[23] = OP_EQUALVERIFY;
        out[24] = OP_CHECKSIG;
        return 25;
    } else if (policy->type == TOKEN_WPKH) {
        uint8_t compressed_pubkey[33];
        policy_node_with_key_t *wpkh_policy = (policy_node_with_key_t *) policy;
        if (0 > get_derived_pubkey(dispatcher_context,
                                   wdi,
                                   r_policy_node_keyexpr(&wpkh_policy->key),
                                   compressed_pubkey)) {
            return -1;
        }
        out[0] = OP_0;
        out[1] = 20;  // PUSH 20 bytes

        crypto_hash160(compressed_pubkey, 33, out + 2);

        return 22;
    } else if (policy->type == TOKEN_SH || policy->type == TOKEN_WSH) {
        const policy_node_t *core_policy;
        if (policy->type == TOKEN_SH) {
            const policy_node_t *child =
                r_policy_node(&((const policy_node_with_script_t *) policy)->script);
            if (child->type == TOKEN_WSH) {
                script_type = WRAPPED_SCRIPT_TYPE_SH_WSH;
                core_policy = r_policy_node(&((const policy_node_with_script_t *) child)->script);
            } else {
                script_type = WRAPPED_SCRIPT_TYPE_SH;
                core_policy = child;
            }
        } else {  // if (policy->type == TOKEN_WSH
            script_type = WRAPPED_SCRIPT_TYPE_WSH;
            core_policy = r_policy_node(&((const policy_node_with_script_t *) policy)->script);
        }

        if (0 > get_wallet_internal_script_hash(dispatcher_context,
                                                core_policy,
                                                wdi,
                                                script_type,
                                                &hash_context.header)) {
            return -1;
        }

        uint8_t script_hash[32];
        crypto_hash_digest(&hash_context.header, script_hash, 32);

        switch (script_type) {
            case WRAPPED_SCRIPT_TYPE_SH:
            case WRAPPED_SCRIPT_TYPE_SH_WSH: {
                if (script_type == WRAPPED_SCRIPT_TYPE_SH_WSH) {
                    cx_sha256_init(&hash_context);
                    crypto_hash_update_u8(&hash_context.header, OP_0);

                    crypto_hash_update_u8(&hash_context.header, 32);  // PUSH 32 bytes
                    crypto_hash_update(&hash_context.header, script_hash, 32);

                    crypto_hash_digest(&hash_context.header, script_hash, 32);
                }

                out[0] = OP_HASH160;
                out[1] = 20;  // PUSH 20 bytes

                crypto_ripemd160(script_hash, 32, out + 2);

                out[22] = OP_EQUAL;
                return 1 + 1 + 20 + 1;
            }
            case WRAPPED_SCRIPT_TYPE_WSH: {
                out[0] = OP_0;
                out[1] = 32;  // PUSH 32 bytes

                memcpy(out + 2, script_hash, 32);

                return 1 + 1 + 32;
            }
            default: {
                // This should never happen!
                return -1;
            }
        }
    } else if (policy->type == TOKEN_TR) {
        policy_node_tr_t *tr_policy = (policy_node_tr_t *) policy;

        uint8_t compressed_pubkey[33];

        if (0 > get_derived_pubkey(dispatcher_context,
                                   wdi,
                                   r_policy_node_keyexpr(&tr_policy->key),
                                   compressed_pubkey)) {
            return -1;
        }

        out[0] = OP_1;
        out[1] = 32;  // PUSH 32 bytes

        // uint8_t h[32];
        uint8_t *h = out + 2;  // hack: reuse the output array to save memory

        int h_length = 0;
        if (!isnull_policy_node_tree(&tr_policy->tree)) {
            if (0 > compute_taptree_hash(dispatcher_context,
                                         wdi,
                                         r_policy_node_tree(&tr_policy->tree),
                                         h)) {
                return -1;
            }
            h_length = 32;
        }

        uint8_t parity;
        crypto_tr_tweak_pubkey(compressed_pubkey + 1, h, h_length, &parity, out + 2);

        return 34;
    }

    PRINTF("Invalid or unsupported top-level script\n");
    return -1;
}

__attribute__((noinline)) int get_wallet_internal_script_hash(
    dispatcher_context_t *dispatcher_context,
    const policy_node_t *policy,
    const wallet_derivation_info_t *wdi,
    internal_script_type_e script_type,
    cx_hash_t *hash_context) {
    const uint8_t *whitelist;
    size_t whitelist_len;
    switch (script_type) {
        case WRAPPED_SCRIPT_TYPE_SH:
            whitelist = fragment_whitelist_sh;
            whitelist_len = sizeof(fragment_whitelist_sh);
            break;
        case WRAPPED_SCRIPT_TYPE_SH_WSH:
            whitelist = fragment_whitelist_sh_wsh;
            whitelist_len = sizeof(fragment_whitelist_sh_wsh);
            break;
        case WRAPPED_SCRIPT_TYPE_WSH:
            whitelist = fragment_whitelist_wsh;
            whitelist_len = sizeof(fragment_whitelist_wsh);
            break;
        case WRAPPED_SCRIPT_TYPE_TAPSCRIPT:
            whitelist = fragment_whitelist_tapscript;
            whitelist_len = sizeof(fragment_whitelist_tapscript);
            break;
        default:
            PRINTF("Unexpected script_type: %d\n", script_type);
            return -1;
    }

    policy_parser_state_t state = {.dispatcher_context = dispatcher_context,
                                   .wdi = wdi,
                                   .is_taproot = (script_type == WRAPPED_SCRIPT_TYPE_TAPSCRIPT),
                                   .node_stack_eos = 0,
                                   .hash_context = hash_context};

    state.nodes[0] =
        (policy_parser_node_state_t){.length = 0, .flags = 0, .step = 0, .policy_node = policy};

    int ret;
    do {
        const policy_parser_node_state_t *node = &state.nodes[state.node_stack_eos];

        if (node->policy_node == NULL) {
            PRINTF("Unexpected uninitialized policy_node\n");
            return -1;
        }

        bool is_whitelisted = false;
        for (size_t i = 0; i < whitelist_len; i++) {
            if (node->policy_node->type == whitelist[i]) {
                is_whitelisted = true;
                break;
            }
        }

        if (!is_whitelisted) {
            PRINTF("Fragment %d not allowed in script type %d\n",
                   node->policy_node->type,
                   script_type);
            return -1;
        }

        switch (node->policy_node->type) {
            case TOKEN_0:
                ret = execute_processor(&state, process_generic_node, commands_0);
                break;
            case TOKEN_1:
                ret = execute_processor(&state, process_generic_node, commands_1);
                break;
            case TOKEN_PK_K:
                ret = execute_processor(&state, process_generic_node, commands_pk_k);
                break;
            case TOKEN_PK_H:
                ret = execute_processor(&state, process_generic_node, commands_pk_h);
                break;
            case TOKEN_PK:
                ret = execute_processor(&state, process_generic_node, commands_pk);
                break;
            case TOKEN_PKH:
            case TOKEN_WPKH:
                ret = execute_processor(&state, process_pkh_wpkh_node, NULL);
                break;
            case TOKEN_OLDER:
                ret = execute_processor(&state, process_generic_node, commands_older);
                break;
            case TOKEN_AFTER:
                ret = execute_processor(&state, process_generic_node, commands_after);
                break;

            case TOKEN_SHA256:
                ret = execute_processor(&state, process_generic_node, commands_sha256);
                break;
            case TOKEN_HASH256:
                ret = execute_processor(&state, process_generic_node, commands_hash256);
                break;
            case TOKEN_RIPEMD160:
                ret = execute_processor(&state, process_generic_node, commands_ripemd160);
                break;
            case TOKEN_HASH160:
                ret = execute_processor(&state, process_generic_node, commands_hash160);
                break;

            case TOKEN_ANDOR:
                ret = execute_processor(&state, process_generic_node, commands_andor);
                break;
            case TOKEN_AND_V:
                ret = execute_processor(&state, process_generic_node, commands_and_v);
                break;
            case TOKEN_AND_B:
                ret = execute_processor(&state, process_generic_node, commands_and_b);
                break;
            case TOKEN_AND_N:
                ret = execute_processor(&state, process_generic_node, commands_and_n);
                break;

            case TOKEN_OR_B:
                ret = execute_processor(&state, process_generic_node, commands_or_b);
                break;
            case TOKEN_OR_C:
                ret = execute_processor(&state, process_generic_node, commands_or_c);
                break;
            case TOKEN_OR_D:
                ret = execute_processor(&state, process_generic_node, commands_or_d);
                break;
            case TOKEN_OR_I:
                ret = execute_processor(&state, process_generic_node, commands_or_i);
                break;

            case TOKEN_THRESH:
                ret = execute_processor(&state, process_thresh_node, NULL);
                break;

            case TOKEN_MULTI:
            case TOKEN_SORTEDMULTI:
                ret = execute_processor(&state, process_multi_sortedmulti_node, NULL);
                break;
            case TOKEN_MULTI_A:
            case TOKEN_SORTEDMULTI_A:
                ret = execute_processor(&state, process_multi_a_sortedmulti_a_node, NULL);
                break;
            case TOKEN_A:
                ret = execute_processor(&state, process_generic_node, commands_a);
                break;
            case TOKEN_S:
                ret = execute_processor(&state, process_generic_node, commands_s);
                break;
            case TOKEN_C:
                ret = execute_processor(&state, process_generic_node, commands_c);
                break;
            case TOKEN_T:
                ret = execute_processor(&state, process_generic_node, commands_t);
                break;
            case TOKEN_D:
                ret = execute_processor(&state, process_generic_node, commands_d);
                break;
            case TOKEN_V:
                ret = execute_processor(&state, process_generic_node, commands_v);
                break;
            case TOKEN_J:
                ret = execute_processor(&state, process_generic_node, commands_j);
                break;
            case TOKEN_N:
                ret = execute_processor(&state, process_generic_node, commands_n);
                break;
            case TOKEN_L:
                ret = execute_processor(&state, process_generic_node, commands_l);
                break;
            case TOKEN_U:
                ret = execute_processor(&state, process_generic_node, commands_u);
                break;
            case TOKEN_TR:
            case TOKEN_SH:
            case TOKEN_WSH:
                PRINTF("Unexpected token type: %d\n", node->policy_node->type);
                return -1;

            case TOKEN_INVALID:
            default:
                PRINTF("Unknown token type: %d\n", node->policy_node->type);
                return -1;
        }
    } while (ret >= 0 && state.node_stack_eos >= 0);

    if (ret < 0) {
        return WITH_ERROR(ret, "Processor failed");
    }

    return ret;
}

#pragma GCC diagnostic pop

// For a standard descriptor template, return the corresponding BIP44 purpose
// Otherwise, returns -1.
static int get_bip44_purpose(const policy_node_t *descriptor_template) {
    const policy_node_keyexpr_t *kp = NULL;
    int purpose = -1;
    switch (descriptor_template->type) {
        case TOKEN_PKH:
            kp =
                r_policy_node_keyexpr(&((const policy_node_with_key_t *) descriptor_template)->key);
            purpose = 44;  // legacy
            break;
        case TOKEN_WPKH:
            kp =
                r_policy_node_keyexpr(&((const policy_node_with_key_t *) descriptor_template)->key);
            purpose = 84;  // native segwit
            break;
        case TOKEN_SH: {
            const policy_node_t *inner =
                r_policy_node(&((const policy_node_with_script_t *) descriptor_template)->script);
            if (inner->type != TOKEN_WPKH) {
                return -1;
            }

            kp = r_policy_node_keyexpr(&((const policy_node_with_key_t *) inner)->key);
            purpose = 49;  // nested segwit
            break;
        }
        case TOKEN_TR: {
            const policy_node_tr_t *tr = (const policy_node_tr_t *) descriptor_template;
            if (!isnull_policy_node_tree(&tr->tree)) {
                return -1;
            }

            kp = r_policy_node_keyexpr(&((const policy_node_tr_t *) descriptor_template)->key);
            purpose = 86;  // standard single-key P2TR
            break;
        }
        default:
            return -1;
    }

    if (kp->type != KEY_EXPRESSION_NORMAL) {
        // any key expression that is not a plain xpub is not BIP-44 compliant
        return -1;
    }

    if (kp->k.key_index != 0 || kp->num_first != 0 || kp->num_second != 1) {
        return -1;
    }

    return purpose;
}

bool is_wallet_policy_standard(dispatcher_context_t *dispatcher_context,
                               const policy_map_wallet_header_t *wallet_policy_header,
                               const policy_node_t *descriptor_template) {
    // Based on the address type, we set the expected bip44 purpose
    int bip44_purpose = get_bip44_purpose(descriptor_template);
    if (bip44_purpose < 0) {
        PRINTF("Non-standard policy, and no hmac provided\n");
        return false;
    }

    if (wallet_policy_header->n_keys != 1) {
        PRINTF("Standard wallets must have exactly 1 key\n");
        return false;
    }

    // we check if the key is indeed internal
    uint32_t master_key_fingerprint = crypto_get_master_key_fingerprint();

    uint8_t key_info_str[MAX_POLICY_KEY_INFO_LEN];
    int key_info_len = call_get_merkle_leaf_element(dispatcher_context,
                                                    wallet_policy_header->keys_info_merkle_root,
                                                    wallet_policy_header->n_keys,
                                                    0,  // only one key
                                                    key_info_str,
                                                    sizeof(key_info_str));
    if (key_info_len < 0) {
        return false;
    }

    // Make a sub-buffer for the pubkey info
    buffer_t key_info_buffer = buffer_create(key_info_str, key_info_len);

    policy_map_key_info_t key_info;
    if (0 > parse_policy_map_key_info(&key_info_buffer, &key_info, wallet_policy_header->version)) {
        return false;
    }

    if (!key_info.has_key_origin) {
        return false;
    }

    if (read_u32_be(key_info.master_key_fingerprint, 0) != master_key_fingerprint) {
        return false;
    }

    // generate pubkey and check if it matches
    serialized_extended_pubkey_t derived_pubkey;
    if (CX_OK != get_extended_pubkey_at_path(key_info.master_key_derivation,
                                             key_info.master_key_derivation_len,
                                             BIP32_PUBKEY_VERSION,
                                             &derived_pubkey)) {
        PRINTF("Failed to derive pubkey\n");
        return false;
    }

    if (memcmp(&key_info.ext_pubkey, &derived_pubkey, sizeof(derived_pubkey)) != 0) {
        return false;
    }

    // check if derivation path of the key is indeed standard

    // per BIP-0044, derivation must be
    // m / purpose' / coin_type' / account'

    const uint32_t H = BIP32_FIRST_HARDENED_CHILD;
    if (key_info.master_key_derivation_len != 3 ||
        key_info.master_key_derivation[0] != H + bip44_purpose ||
        key_info.master_key_derivation[1] != H + BIP44_COIN_TYPE ||
        key_info.master_key_derivation[2] < H ||
        key_info.master_key_derivation[2] > H + MAX_BIP44_ACCOUNT_RECOMMENDED) {
        return false;
    }

    return true;
}

bool compute_wallet_hmac(const uint8_t wallet_id[static 32], uint8_t wallet_hmac[static 32]) {
    uint8_t key[32];

    bool result = false;

    if (!crypto_derive_symmetric_key(WALLET_SLIP0021_LABEL, WALLET_SLIP0021_LABEL_LEN, key)) {
        goto end;
    }

    cx_hmac_sha256(key, sizeof(key), wallet_id, 32, wallet_hmac, 32);

    result = true;

end:
    explicit_bzero(key, sizeof(key));

    return result;
}

bool check_wallet_hmac(const uint8_t wallet_id[static 32], const uint8_t wallet_hmac[static 32]) {
    uint8_t key[32];
    uint8_t correct_hmac[32];

    bool result = false;

    if (!crypto_derive_symmetric_key(WALLET_SLIP0021_LABEL, WALLET_SLIP0021_LABEL_LEN, key)) {
        goto end;
    }

    cx_hmac_sha256(key, sizeof(key), wallet_id, 32, correct_hmac, 32);

    // It is important to use a constant-time function to compare the hmac,
    // to avoid timing-attack that could be exploited to extract it.
    result = os_secure_memcmp((void *) wallet_hmac, (void *) correct_hmac, 32) == 0;

end:
    explicit_bzero(key, sizeof(key));
    explicit_bzero(correct_hmac, sizeof(correct_hmac));

    return result;
}

#pragma GCC diagnostic push
// make sure that the compiler gives an error if any PolicyNodeType is missed
#pragma GCC diagnostic error "-Wswitch-enum"

static int get_keyexpr_by_index_in_tree(const policy_node_tree_t *tree,
                                        unsigned int i,
                                        const policy_node_t **out_tapleaf_ptr,
                                        policy_node_keyexpr_t **out_keyexpr) {
    if (tree->is_leaf) {
        int ret = get_keyexpr_by_index(r_policy_node(&tree->script), i, NULL, out_keyexpr);
        if (ret >= 0 && out_tapleaf_ptr != NULL && i < (unsigned) ret) {
            *out_tapleaf_ptr = r_policy_node(&tree->script);
        }
        return ret;
    } else {
        int ret1 = get_keyexpr_by_index_in_tree(r_policy_node_tree(&tree->left_tree),
                                                i,
                                                out_tapleaf_ptr,
                                                out_keyexpr);
        if (ret1 < 0) return -1;

        bool found = i < (unsigned int) ret1;

        int ret2 = get_keyexpr_by_index_in_tree(r_policy_node_tree(&tree->right_tree),
                                                found ? 0 : i - ret1,
                                                found ? NULL : out_tapleaf_ptr,
                                                found ? NULL : out_keyexpr);
        if (ret2 < 0) return -1;

        return ret1 + ret2;
    }
}

int get_keyexpr_by_index(const policy_node_t *policy,
                         unsigned int i,
                         const policy_node_t **out_tapleaf_ptr,
                         policy_node_keyexpr_t **out_keyexpr) {
    // make sure that out_keyexpr is a valid pointer, if the output is not needed
    policy_node_keyexpr_t *tmp;
    if (out_keyexpr == NULL) {
        out_keyexpr = &tmp;
    }

    switch (policy->type) {
        // terminal nodes with absolutely no keys
        case TOKEN_0:
        case TOKEN_1:
        case TOKEN_OLDER:
        case TOKEN_AFTER:
        case TOKEN_SHA256:
        case TOKEN_HASH256:
        case TOKEN_RIPEMD160:
        case TOKEN_HASH160:
            return 0;

        // terminal nodes with exactly 1 key
        case TOKEN_PK_K:
        case TOKEN_PK_H:
        case TOKEN_PK:
        case TOKEN_PKH:
        case TOKEN_WPKH: {
            if (i == 0) {
                policy_node_with_key_t *wpkh = (policy_node_with_key_t *) policy;
                *out_keyexpr = r_policy_node_keyexpr(&wpkh->key);
            }
            return 1;
        }
        case TOKEN_TR: {
            policy_node_tr_t *tr = (policy_node_tr_t *) policy;
            if (i == 0) {
                *out_keyexpr = r_policy_node_keyexpr(&tr->key);
            }
            if (!isnull_policy_node_tree(&tr->tree)) {
                int ret_tree = get_keyexpr_by_index_in_tree(
                    r_policy_node_tree(&tr->tree),
                    i == 0 ? 0 : i - 1,
                    i == 0 ? NULL : out_tapleaf_ptr,
                    i == 0 ? NULL : out_keyexpr);  // if i == 0, we already found it; so we
                                                   // recur with out_keyexpr set to NULL
                if (ret_tree < 0) {
                    return -1;
                }
                return 1 + ret_tree;
            } else {
                return 1;
            }
        }

        // terminal nodes with multiple keys
        case TOKEN_MULTI:
        case TOKEN_MULTI_A:
        case TOKEN_SORTEDMULTI:
        case TOKEN_SORTEDMULTI_A: {
            const policy_node_multisig_t *node = (const policy_node_multisig_t *) policy;

            if (i < (unsigned int) node->n) {
                policy_node_keyexpr_t *key_expressions = r_policy_node_keyexpr(&node->keys);
                *out_keyexpr = &key_expressions[i];
            }

            return node->n;
        }

        // nodes with a single child script (including miniscript wrappers)
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
            return get_keyexpr_by_index(
                r_policy_node(&((const policy_node_with_script_t *) policy)->script),
                i,
                out_tapleaf_ptr,
                out_keyexpr);
        }

        // nodes with exactly two child scripts
        case TOKEN_AND_V:
        case TOKEN_AND_B:
        case TOKEN_AND_N:
        case TOKEN_OR_B:
        case TOKEN_OR_C:
        case TOKEN_OR_D:
        case TOKEN_OR_I: {
            const policy_node_with_script2_t *node = (const policy_node_with_script2_t *) policy;
            int ret1 = get_keyexpr_by_index(r_policy_node(&node->scripts[0]),
                                            i,
                                            out_tapleaf_ptr,
                                            out_keyexpr);
            if (ret1 < 0) return -1;

            bool found = i < (unsigned int) ret1;
            int ret2 = get_keyexpr_by_index(r_policy_node(&node->scripts[1]),
                                            found ? 0 : i - ret1,
                                            found ? NULL : out_tapleaf_ptr,
                                            found ? NULL : out_keyexpr);
            if (ret2 < 0) return -1;

            return ret1 + ret2;
        }

        // nodes with exactly three child scripts
        case TOKEN_ANDOR: {
            const policy_node_with_script3_t *node = (const policy_node_with_script3_t *) policy;
            int ret1 = get_keyexpr_by_index(r_policy_node(&node->scripts[0]),
                                            i,
                                            out_tapleaf_ptr,
                                            out_keyexpr);
            if (ret1 < 0) return -1;

            bool found = i < (unsigned int) ret1;
            int ret2 = get_keyexpr_by_index(r_policy_node(&node->scripts[1]),
                                            found ? 0 : i - ret1,
                                            found ? NULL : out_tapleaf_ptr,
                                            found ? NULL : out_keyexpr);
            if (ret2 < 0) return -1;

            found = i < (unsigned int) (ret1 + ret2);
            int ret3 = get_keyexpr_by_index(r_policy_node(&node->scripts[2]),
                                            found ? 0 : i - ret1 - ret2,
                                            found ? NULL : out_tapleaf_ptr,
                                            found ? NULL : out_keyexpr);
            if (ret3 < 0) return -1;
            return ret1 + ret2 + ret3;
        }

        // nodes with multiple child scripts
        case TOKEN_THRESH: {
            const policy_node_thresh_t *node = (const policy_node_thresh_t *) policy;
            bool found;
            int ret = 0;
            policy_node_scriptlist_t *cur_child = r_policy_node_scriptlist(&node->scriptlist);
            for (int script_idx = 0; script_idx < node->n; script_idx++) {
                LEDGER_ASSERT(cur_child != NULL, "The script must have exactly n child scripts");

                found = i < (unsigned int) ret;
                int ret_partial = get_keyexpr_by_index(r_policy_node(&cur_child->script),
                                                       found ? 0 : i - ret,
                                                       found ? NULL : out_tapleaf_ptr,
                                                       found ? NULL : out_keyexpr);
                if (ret_partial < 0) return -1;

                ret += ret_partial;
                cur_child = r_policy_node_scriptlist(&cur_child->next);
            }
            return ret;
        }

        case TOKEN_INVALID:
        default:
            PRINTF("Unknown token type: %d\n", policy->type);
            return -1;
    }

    // unreachable
    assert(0);
    return -1;
}

int count_distinct_keys_info(const policy_node_t *policy) {
    int ret = -1;
    policy_node_keyexpr_t *key_expression_ptr;
    int n_key_expressions = get_keyexpr_by_index(policy, 0, NULL, NULL);
    if (n_key_expressions < 0) {
        return -1;
    }

    for (int cur = 0; cur < n_key_expressions; ++cur) {
        if (0 > get_keyexpr_by_index(policy, cur, NULL, &key_expression_ptr)) {
            return -1;
        }
        if (key_expression_ptr->type == KEY_EXPRESSION_NORMAL) {
            ret = MAX(ret, key_expression_ptr->k.key_index + 1);
        } else if (key_expression_ptr->type == KEY_EXPRESSION_MUSIG) {
            const musig_aggr_key_info_t *musig_info =
                r_musig_aggr_key_info(&key_expression_ptr->m.musig_info);
            const uint16_t *key_indexes = r_uint16(&musig_info->key_indexes);
            for (int i = 0; i < musig_info->n; i++) {
                ret = MAX(ret, key_indexes[i] + 1);
            }
        } else {
            LEDGER_ASSERT(false, "Unknown key expression type");
        }
    }
    return ret;
}

// Utility function to extract and decode the i-th xpub from the keys information vector
static int get_pubkey_from_merkle_tree(dispatcher_context_t *dispatcher_context,
                                       int wallet_version,
                                       const uint8_t keys_merkle_root[static 32],
                                       uint32_t n_keys,
                                       uint32_t index,
                                       serialized_extended_pubkey_t *out) {
    char key_info_str[MAX_POLICY_KEY_INFO_LEN];
    int key_info_len = call_get_merkle_leaf_element(dispatcher_context,
                                                    keys_merkle_root,
                                                    n_keys,
                                                    index,
                                                    (uint8_t *) key_info_str,
                                                    sizeof(key_info_str));
    if (key_info_len < 0) {
        return WITH_ERROR(-1, "Failed to retrieve key info");
    }

    // Make a sub-buffer for the pubkey info
    buffer_t key_info_buffer = buffer_create(key_info_str, key_info_len);

    policy_map_key_info_t key_info;
    if (parse_policy_map_key_info(&key_info_buffer, &key_info, wallet_version) == -1) {
        return WITH_ERROR(-1, "Failed to parse key information");
    }
    *out = key_info.ext_pubkey;
    return 0;
}

static int is_miniscript_sane(const policy_node_t *script, MiniscriptContext context) {
    if (context != MINISCRIPT_CONTEXT_P2WSH && context != MINISCRIPT_CONTEXT_TAPSCRIPT) {
        return WITH_ERROR(-1, "Unknown miniscript context");
    }
    if (!script->flags.is_miniscript) {
        return WITH_ERROR(-1, "This function can only be called for miniscript");
    }

    // Top level node in miniscript must be type B
    if (script->flags.miniscript_type != MINISCRIPT_TYPE_B) {
        return WITH_ERROR(-1, "Top level miniscript node must be of type B");
    }

    // check miniscript sanity conditions
    policy_node_ext_info_t ext_info;
    if (0 > compute_miniscript_policy_ext_info(script, &ext_info, context)) {
        return WITH_ERROR(-1, "Error analyzing miniscript policy");
    }

    // Check that non-malleability can be guaranteed
    if (!ext_info.m) {
        return WITH_ERROR(-1, "Miniscript cannot always be satisfied non-malleably");
    }

    // Check that a signature is always required to satisfy the miniscript
    if (!ext_info.s) {
        return WITH_ERROR(-1, "Miniscript does not always require a signature");
    }

    // Check that there is no time-lock mix
    if (!ext_info.k) {
        return WITH_ERROR(-1, "Miniscript with time-lock mix");
    }

    // Note: the following limits could be relaxed for taproot miniscript; however, that
    // would mean that tapscripts could run into the maximum stack size limits during
    // execution, which we didn't implement explicit checks against.
    // Therefore, we rather apply the conservative limit for segwit even to tapscripts.
    // We don't expect these limits to be reached in real-world policies.

    // Check the maximum stack size to satisfy the policy
    if (ext_info.ss.sat == -1 || (uint32_t) ext_info.ss.sat > MAX_STANDARD_P2WSH_STACK_ITEMS) {
        return WITH_ERROR(-1, "Miniscript exceeds maximum standard stack size");
    }

    if (ext_info.ops.sat == -1) {
        // Should never happen for non-malleable scripts
        return WITH_ERROR(-1, "Invalid maximum ops computations");
    }

    // Check ops limit
    if ((uint32_t) ext_info.ops.count + (uint32_t) ext_info.ops.sat > MAX_OPS_PER_SCRIPT) {
        return WITH_ERROR(-1, "Miniscript exceeds maximum ops");
    }

    // Check the script size
    if (ext_info.script_size > MAX_STANDARD_P2WSH_SCRIPT_SIZE) {
        return WITH_ERROR(-1, "Miniscript exceeds maximum script size");
    }
    return 0;
}

static int is_taptree_miniscript_sane(const policy_node_tree_t *taptree) {
    // Recurse until leaves are found, then check sanity if they contain miniscript.
    // No check is performed on leaves not containing miniscript.
    if (taptree->is_leaf) {
        const policy_node_t *script = r_policy_node(&taptree->script);
        if (script->flags.is_miniscript &&  // only check for miniscript leaves
            0 > is_miniscript_sane(script, MINISCRIPT_CONTEXT_TAPSCRIPT)) {
            return -1;
        }
    } else {
        if (0 > is_taptree_miniscript_sane(r_policy_node_tree(&taptree->left_tree))) {
            return -1;
        }
        if (0 > is_taptree_miniscript_sane(r_policy_node_tree(&taptree->right_tree))) {
            return -1;
        }
    }

    return 0;
}

static int compare_uint16(const void *a, const void *b) {
    uint16_t num1 = *(const uint16_t *) a;
    uint16_t num2 = *(const uint16_t *) b;

    return (num1 > num2) - (num1 < num2);
}

static bool are_key_placeholders_identical(const policy_node_keyexpr_t *kp1,
                                           const policy_node_keyexpr_t *kp2) {
    if (kp1->type != kp2->type) {
        return false;
    }
    if (kp1->type == KEY_EXPRESSION_NORMAL && kp2->type == KEY_EXPRESSION_NORMAL) {
        return kp1->k.key_index == kp2->k.key_index;
    } else if (kp1->type == KEY_EXPRESSION_MUSIG && kp2->type == KEY_EXPRESSION_MUSIG) {
        const musig_aggr_key_info_t *musig_info_i = r_musig_aggr_key_info(&kp1->m.musig_info);
        const uint16_t *key_indexes_i = r_uint16(&musig_info_i->key_indexes);
        const musig_aggr_key_info_t *musig_info_j = r_musig_aggr_key_info(&kp2->m.musig_info);
        const uint16_t *key_indexes_j = r_uint16(&musig_info_j->key_indexes);

        // two musig key expressions have identical placeholders if and only if they have
        // exactly the same set of key indexes

        if (musig_info_i->n != musig_info_j->n) {
            return false;  // cannot be the same set if the size is different
        }

        uint16_t key_indexes_i_sorted[MAX_PUBKEYS_PER_MUSIG];
        uint16_t key_indexes_j_sorted[MAX_PUBKEYS_PER_MUSIG];
        memcpy(key_indexes_i_sorted, key_indexes_i, musig_info_i->n * sizeof(uint16_t));
        memcpy(key_indexes_j_sorted, key_indexes_j, musig_info_j->n * sizeof(uint16_t));

        // sort the arrays
        qsort(key_indexes_i_sorted, musig_info_i->n, sizeof(uint16_t), compare_uint16);
        qsort(key_indexes_j_sorted, musig_info_j->n, sizeof(uint16_t), compare_uint16);

        if (memcmp(key_indexes_i_sorted,
                   key_indexes_j_sorted,
                   musig_info_i->n * sizeof(uint16_t)) != 0) {
            return false;  // different set of keys
        }
        return true;
    } else {
        LEDGER_ASSERT(false, "Unknown key expression type");
        return false;
    }
    LEDGER_ASSERT(false, "Unreachable code");
}

/**
 * Callback for traverse_policy_dfs that rejects older(n) nodes with an argument that is not
 * safe, as it sets bits with no consensus meaning (see comment in is_policy_sane() below).
 */
static int check_older_node_cb(const policy_node_t *node, void *callback_state) {
    (void) callback_state;
    if (node->type == TOKEN_OLDER) {
        const policy_node_with_uint32_t *older = (const policy_node_with_uint32_t *) node;
        uint32_t n = older->n & ~SEQUENCE_LOCKTIME_TYPE_FLAG;
        if (n < 1 || n > 65535) {
            return -1;
        }
    }
    return 0;
}

int is_policy_sane(dispatcher_context_t *dispatcher_context,
                   const policy_node_t *policy,
                   int wallet_version,
                   const uint8_t keys_merkle_root[static 32],
                   uint32_t n_keys) {
    if (policy->type == TOKEN_WSH) {
        const policy_node_t *inner =
            r_policy_node(&((const policy_node_with_script_t *) policy)->script);
        if (inner->flags.is_miniscript) {
            if (0 > is_miniscript_sane(inner, MINISCRIPT_CONTEXT_P2WSH)) {
                return -1;
            }
        }
    } else if (policy->type == TOKEN_TR) {
        // if there is a taptree, we check the sanity of every miniscript leaf
        const policy_node_tr_t *tr = (const policy_node_tr_t *) policy;
        const policy_node_tree_t *taptree = r_policy_node_tree(&tr->tree);
        if (taptree != NULL && 0 > is_taptree_miniscript_sane(taptree)) {
            return -1;
        }
    }

    // check that all the xpubs are different
    for (unsigned int i = 0; i < n_keys - 1; i++) {  // no point in running this for the last key
        serialized_extended_pubkey_t pubkey_i;
        if (0 > get_pubkey_from_merkle_tree(dispatcher_context,
                                            wallet_version,
                                            keys_merkle_root,
                                            n_keys,
                                            i,
                                            &pubkey_i)) {
            return -1;
        }

        for (unsigned int j = i + 1; j < n_keys; j++) {
            serialized_extended_pubkey_t pubkey_j;
            if (0 > get_pubkey_from_merkle_tree(dispatcher_context,
                                                wallet_version,
                                                keys_merkle_root,
                                                n_keys,
                                                j,
                                                &pubkey_j)) {
                return -1;
            }

            // We reject if any two xpubs have the same pubkey
            // Conservatively, we only compare the compressed pubkey, rather than the whole xpub:
            // there is no good reason for allowing two different xpubs with the same pubkey.
            if (memcmp(pubkey_i.compressed_pubkey,
                       pubkey_j.compressed_pubkey,
                       sizeof(pubkey_i.compressed_pubkey)) == 0) {
#ifndef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
                // duplicated pubkey
                return WITH_ERROR(-1, "Repeated pubkey in wallet policy");
#else
                // The fuzzing crypto mock (cx_ecpoint_export in the SDK) returns a
                // constant pubkey for every BIP-32 derivation, so this check would
                // otherwise reject every multi-key wallet policy and starve the
                // downstream are_key_placeholders_identical / older()-range checks
                // from coverage. Allow the collision under fuzz so those paths run.
#endif
            }
        }
    }

    // check that all the key expressions for the same xpub do indeed have different
    // derivations
    int n_key_expressions = get_keyexpr_by_index(policy, 0, NULL, NULL);
    if (n_key_expressions < 0) {
        return WITH_ERROR(-1, "Unexpected error while counting key expressions");
    }

    // for each MuSig key expression, checks that the key indices are all distinct
    for (int i = 0; i < n_key_expressions; i++) {
        policy_node_keyexpr_t *kp_i;
        if (0 > get_keyexpr_by_index(policy, i, NULL, &kp_i)) {
            return WITH_ERROR(-1, "Unexpected error retrieving key expressions from the policy");
        }
        if (kp_i->type == KEY_EXPRESSION_MUSIG) {
            const musig_aggr_key_info_t *musig_info_i = r_musig_aggr_key_info(&kp_i->m.musig_info);
            const uint16_t *key_indexes_i = r_uint16(&musig_info_i->key_indexes);

            uint16_t key_indexes_i_sorted[MAX_PUBKEYS_PER_MUSIG];
            memcpy(key_indexes_i_sorted, key_indexes_i, musig_info_i->n * sizeof(uint16_t));

            // sort the arrays
            qsort(key_indexes_i_sorted, musig_info_i->n, sizeof(uint16_t), compare_uint16);

            for (int j = 0; j < musig_info_i->n - 1; j++) {
                if (key_indexes_i_sorted[j] == key_indexes_i_sorted[j + 1]) {
                    return WITH_ERROR(-1, "Repeated key in musig key expression");
                }
            }
        }
    }

    // The following loop is computationally very inefficient, but more efficient solutions likely
    // require a substantial amount of RAM and/or more complex code.
    // As it's unlikely that the number of keys in a wallet policy will be large enough for this to,
    // matther, we rather keep the code as simple as possible.
    for (int i = 0; i < n_key_expressions - 1;
         i++) {  // no point in running this for the last key expression
        policy_node_keyexpr_t *kp_i;
        if (0 > get_keyexpr_by_index(policy, i, NULL, &kp_i)) {
            return WITH_ERROR(-1, "Unexpected error retrieving key expressions from the policy");
        }
        for (int j = i + 1; j < n_key_expressions; j++) {
            policy_node_keyexpr_t *kp_j;
            if (0 > get_keyexpr_by_index(policy, j, NULL, &kp_j)) {
                return WITH_ERROR(-1,
                                  "Unexpected error retrieving key expressions from the policy");
            }

            // There is nothing to check for two placeholders that are not identical.
            // If they are identical, we make sure that the derivations are disjoint, as per
            // BIP-388. Note that this means that we do not enforce that _all_ the keys in different
            // musig placeholders are disjoint, as long as they are not exactly the same set of
            // keys. Similarly, a key used in a normal placeholder could also be part of the set of
            // keys in a musig placeholder.
            if (are_key_placeholders_identical(kp_i, kp_j)) {
                if (kp_i->k.key_index == kp_j->k.key_index) {
                    if (kp_i->num_first == kp_j->num_first || kp_i->num_first == kp_j->num_second ||
                        kp_i->num_second == kp_j->num_first ||
                        kp_i->num_second == kp_j->num_second) {
                        return WITH_ERROR(
                            -1,
                            "Key expressions with repeated derivations in miniscript");
                    }
                }
            }
        }
    }

    // For relative timelocks with `older(n)`, bits 16 to 21 and 23 to 31 have no consensus meaning
    // per BIP-68/BIP-112. Therefore, for example, `older(65536)` is equivalent to `older(0)`, which
    // could be dangerous as the user might expect that a timelock is enforced. For relative
    // timelocks, we reject any value outside the following safe ranges:
    // - between 1 and 65535 (inclusive), if bit 22 is cleared (block-based timelock)
    // - between 1 + 2^22 = 4194305 and 65535 + 2^22 = 4259839 (inclusive), if bit 22 is set
    // (time-based timelock)
    //
    // Bit 22 is SEQUENCE_LOCKTIME_TYPE_FLAG in BIP-68.
    // Note that bit 31 (SEQUENCE_LOCKTIME_DISABLE_FLAG) is implicitly excluded, as the argument n
    // of older(n) is guaranteed to be strictly less than 2^31 per miniscript rules, which are
    // enforced in the policy parser.
    //
    // See also: https://github.com/bitcoin/bitcoin/pull/33135
    if (0 > traverse_policy_dfs(policy, check_older_node_cb, NULL)) {
        return WITH_ERROR(-1, "older() argument out of valid range");
    }

    return 0;
}

#pragma GCC diagnostic pop
