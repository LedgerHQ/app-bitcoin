#pragma once

/* Local headers */
#include "dispatcher.h"
#include "sign_psbt_cache.h"
#include "wallet.h"

/**
 * Parses a serialized wallet policy, saving the wallet header, the policy map descriptor and the
 * policy descriptor. Then, it parses the descriptor into the Abstract Syntax Tree into the
 * policy_map_bytes array.
 *
 * It returns -1 if any error occurs.
 *
 * @param dispatcher_context Pointer to the dispatcher content
 * @param buf Pointer to the buffer from which the serialized policy is read from
 * @param wallet_header Pointer to policy_map_wallet_header_t that will receive the policy map
 * header
 * @param policy_map_descriptor_template Pointer to a buffer of MAX_DESCRIPTOR_TEMPLATE_LENGTH bytes
 * that will contain the descriptor template as a string
 * @param policy_map_bytes Pointer to an array of bytes that will be used for the parsed abstract
 * syntax tree
 * @param policy_map_bytes_len Length of policy_map_bytes in bytes.
 * @return The memory size of the parsed descriptor template on success, a negative number in case
 * of error.
 */
// TODO: we should distinguish actual errors from just "policy too big to fit in memory"
__attribute__((warn_unused_result)) int read_and_parse_wallet_policy(
    dispatcher_context_t *dispatcher_context,
    buffer_t *buf,
    policy_map_wallet_header_t *wallet_header,
    uint8_t policy_map_descriptor[static MAX_DESCRIPTOR_TEMPLATE_LENGTH],
    uint8_t *policy_map_bytes,
    size_t policy_map_bytes_len);

typedef enum {
    WRAPPED_SCRIPT_TYPE_SH,
    WRAPPED_SCRIPT_TYPE_WSH,
    WRAPPED_SCRIPT_TYPE_SH_WSH,
    WRAPPED_SCRIPT_TYPE_TAPSCRIPT
} internal_script_type_e;

// Bundles together some parameters relative to a call to
// get_wallet_script or get_wallet_internal_script_hash
typedef struct {
    int wallet_version;  // The wallet policy version, either WALLET_POLICY_VERSION_V1 or
                         // WALLET_POLICY_VERSION_V2
    const uint8_t
        *keys_merkle_root;  // The Merkle root of the tree of key information in the policy
    uint32_t n_keys;        // The number of key information elements in the policy
    size_t address_index;   // The address index to use in the derivation
    bool change;            // whether a change address or a receive address is derived
    sign_psbt_cache_t
        *sign_psbt_cache;  // If not NULL, the cache for key derivations used during signing
} wallet_derivation_info_t;

/**
 * Requests and parses the serialized extended public key from the client.
 *
 * @param[in] dispatcher_context Pointer to the dispatcher content
 * @param[in] wdi Pointer to a `wallet_derivation_info_t` struct with the details of the
 * necessary details of the wallet policy. The change/addr_index pairs are not
 * @param[in] key_index Index of the pubkey in the vector of keys of the wallet policy.
 * @param[out] out Pointer to a `serialized_extended_pubkey_t` that will contain the requested
 * extended pubkey.
 *
 * @return -1 on error, 0 if the returned key info has no wildcard (**), 1 if it has the wildcard.
 */
__attribute__((warn_unused_result)) int get_extended_pubkey_from_client(
    dispatcher_context_t *dispatcher_context,
    const wallet_derivation_info_t *wdi,
    int key_index,
    serialized_extended_pubkey_t *out);

/**
 * Computes the hash of a taptree, to be used as tweak for the internal key per BIP-0341;
 * The returned hash is the second value in the tuple returned by taproot_tree_helper in
 * BIP-0341, assuming leaf_version 0xC0.
 *
 * @param[in] dispatcher_context
 *   Pointer to the dispatcher context
 * @param[in] wdi
 *   Pointer to a wallet_derivation_info_t structure containing multiple other parameters
 * @param[in] tree
 *   Pointer to the root of the taptree
 * @param[out] out
 *   A buffer of 32 bytes to receive the output
 *
 * @return 0 on success, a negative number on failure.
 */
__attribute__((warn_unused_result)) int compute_taptree_hash(
    dispatcher_context_t *dispatcher_context,
    const wallet_derivation_info_t *wdi,
    const policy_node_tree_t *tree,
    uint8_t out[static 32]);

/**
 * Computes the script corresponding to a wallet policy, for a certain change and address index.
 *
 * @param[in] dispatcher_context
 *   Pointer to the dispatcher context
 * @param[in] policy
 *   Pointer to the root node of the policy
 * @param[in] wdi
 *   Pointer to a wallet_derivation_info_t structure containing multiple other parameters
 * @param[out] out
 *   A buffer of at least 34 bytes to contain the script. The actual length of the output might be
 * smaller.
 *
 * @return The length of the output on success; -1 in case of error.
 *
 */
__attribute__((warn_unused_result)) int get_wallet_script(dispatcher_context_t *dispatcher_context,
                                                          const policy_node_t *policy,
                                                          const wallet_derivation_info_t *wdi,
                                                          uint8_t out[static 34]);

/**
 * Computes the script corresponding to a wallet policy, for a certain change and address index.
 *
 * @param[in] dispatcher_context
 *   Pointer to the dispatcher context
 * @param[in] policy
 *   Pointer to the root node of the policy
 * @param[in] wdi
 *   Pointer to a wallet_derivation_info_t structure containing multiple other parameters
 * @param[out] hash_context
 *   A pointer to an already initialized hash context that will be updated with the bytes from the
 * produced script. If NULL, it is ignored.
 *
 * @return the length of the script on success; a negative number in case of error.
 *
 */
__attribute__((warn_unused_result)) int get_wallet_internal_script_hash(
    dispatcher_context_t *dispatcher_context,
    const policy_node_t *policy,
    const wallet_derivation_info_t *wdi,
    internal_script_type_e script_type,
    cx_hash_t *hash_context);

/**
 * Returns the address type constant corresponding to a standard policy type.
 *
 * @param[in] policy
 *   Pointer to the root node of the policy
 *
 * @return One of, ADDRESS_TYPE_LEGACY, ADDRESS_TYPE_WIT, ADDRESS_TYPE_SH_WIT, ADDRESS_TYPE_TR if
 * the policy pattern is one of the expected types; -1 otherwise.
 */
int get_policy_address_type(const policy_node_t *policy);

/**
 * Returns true if the descriptor template is a standard one.
 * Standard wallet policies are single-signature policies as per the following standards:
 *  - BIP-44 (legacy, P2PKH)
 *  - BIP-84 (native segwit, P2WPKH)
 *  - BIP-49 (wrapped segwit, P2SH-P2WPKH)
 *  - BIP-86 (standard single key P2TR)
 * with the standard derivations for the key placeholders, and unhardened steps for the
 * change / address_index steps (using 0 for non-change, 1 for change addresses).
 *
 * @param[in] dispatcher_context
 *   Pointer to the dispatcher context
 * @param[in] wallet_policy_header
 *   Pointer the wallet policy header
 * @param[in] descriptor_template
 *   Pointer to the root node of the policy
 *
 * @return true if the descriptor_template is not standard; false if not, or in case of error.
 */
__attribute__((warn_unused_result)) bool is_wallet_policy_standard(
    dispatcher_context_t *dispatcher_context,
    const policy_map_wallet_header_t *wallet_policy_header,
    const policy_node_t *descriptor_template);

/**
 * Computes and returns the wallet_hmac, using the symmetric key derived
 * with the WALLET_SLIP0021_LABEL label according to SLIP-0021.
 *
 * @param[in] wallet_id
 *   Pointer to the a 32-bytes array containing the 32-byte wallet policy id.
 * @param[out] wallet_hmac
 *   Pointer to the a 32-bytes array containing the wallet policy registration hmac.
 * @return true if the given hmac is valid, false otherwise.
 */
bool compute_wallet_hmac(const uint8_t wallet_id[static 32], uint8_t wallet_hmac[static 32]);

/**
 * Verifies if the wallet_hmac is correct for the given wallet_id, using the symmetric key derived
 * with the WALLET_SLIP0021_LABEL label according to SLIP-0021.
 *
 * @param[in] wallet_id
 *   Pointer to the a 32-bytes array containing the 32-byte wallet policy id.
 * @param[in] wallet_hmac
 *   Pointer to the a 32-bytes array containing the expected wallet policy registration hmac.
 * @return true if the given hmac is valid, false otherwise.
 */
bool check_wallet_hmac(const uint8_t wallet_id[static 32], const uint8_t wallet_hmac[static 32]);

/**
 * Copies the i-th key expression (indexing from 0) of the given policy into `out_keyexpr` (if not
 * null).
 *
 * @param[in] policy
 *   Pointer to the root node of the policy
 * @param[in] i
 *   Index of the wanted key expression. Ignored if out_keyexpr is NULL.
 * @param[out] out_tapleaf_ptr
 *   If not NULL, and if the i-th key expression is in a tapleaf of the policy, receives the pointer
 * to the tapleaf's script.
 * @param[out] out_keyexpr
 *   If not NULL, it is a pointer that will receive a pointer to the i-th key expression of the
 * policy.
 * @return the number of key expressions in the policy on success; -1 in case of error.
 */
__attribute__((warn_unused_result)) int get_keyexpr_by_index(const policy_node_t *policy,
                                                             unsigned int i,
                                                             const policy_node_t **out_tapleaf_ptr,
                                                             policy_node_keyexpr_t **out_keyexpr);

/**
 * Determines whether two key expressions refer to the same key, independently of the derivation
 * steps. Normal key expressions are identical iff they share the same key index; musig key
 * expressions are identical iff they aggregate exactly the same (unordered) set of key indexes.
 *
 * @param[in] kp1
 *   Pointer to the first key expression.
 * @param[in] kp2
 *   Pointer to the second key expression.
 * @return true if the two key expressions refer to the same key, false otherwise.
 */
bool are_key_placeholders_identical(const policy_node_keyexpr_t *kp1,
                                    const policy_node_keyexpr_t *kp2);

/**
 * Determines the expected number of unique keys in the provided policy's key information.
 * The function calculates this by finding the maximum key index from key expressions and increments
 * it by 1. For instance, if the maximum key index found in the key expressions is `n`, then the
 * result would be `n + 1`.
 *
 * @param[in] policy
 *   Pointer to the root node of the policy
 * @return the expected number of items in the keys information vector; -1 in case of error.
 */
__attribute__((warn_unused_result)) int count_distinct_keys_info(const policy_node_t *policy);

/**
 * Checks if a wallet policy is sane, verifying that pubkeys are never repeated and (if miniscript)
 * that the miniscript is "sane".
 * @param[in] dispatcher_context
 *   Pointer to the dispatcher context
 * @param[in] policy
 *   Pointer to the root node of the policy
 * @param[in] wallet_version
 *   The version of the wallet policy (since it affects the format of keys in the vector of keys)
 * @param[in] keys_merkle_root
 *   The root of the Merkle tree of the vector of keys information in the wallet policy
 * @param[in] n_keys
 *   The number of keys in the vector of keys
 * @return 0 on success; -1 in case of error.
 */
__attribute__((warn_unused_result)) int is_policy_sane(dispatcher_context_t *dispatcher_context,
                                                       const policy_node_t *policy,
                                                       int wallet_version,
                                                       const uint8_t keys_merkle_root[static 32],
                                                       uint32_t n_keys);
