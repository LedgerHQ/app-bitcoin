/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2025 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>
#include <string.h>

/* SDK headers */
#include "bip32.h"
#include "cx.h"
#include "os.h"
#include "read.h"
#include "write.h"

/* Local headers */
#include "client_commands.h"
#include "commands.h"
#include "constants.h"
#include "crypto.h"
#include "dispatcher.h"
#include "display.h"
#include "error_codes.h"
#include "get_merkle_leaf_element.h"
#include "get_preimage.h"
#include "handlers.h"
#include "menu.h"
#include "merkle.h"
#include "policy.h"
#include "sw.h"
#include "wallet.h"
#include "common/cleartext.h"

static bool is_policy_acceptable(const policy_node_t *policy);
static bool is_policy_name_acceptable(const char *name, size_t name_len);

static const uint8_t BIP0341_NUMS_PUBKEY[] = {0x02, 0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
                                              0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07,
                                              0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf,
                                              0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0};

/**
 * Fetches and validates the keys of the wallet policy, asks the user to confirm the registration,
 * and sends the response.
 *
 * This is a separate (and explicitly not inlined) function because of its large buffers: they
 * would otherwise be part of the stack frame of handler_register_wallet() while the descriptor
 * template is parsed and validated, and those steps recurse over the parsed policy.
 */
__attribute__((noinline)) static void confirm_and_register_wallet(
    dispatcher_context_t *dc,
    const policy_map_wallet_header_t *wallet_header,
    const uint8_t *policy_map_descriptor,
    const policy_node_t *policy,
    const uint8_t wallet_id[static 32]) {
    size_t n_internal_keys = 0;

    uint32_t master_key_fingerprint = crypto_get_master_key_fingerprint();

    char keys_info[MAX_N_KEYS_IN_WALLET_POLICY][MAX_POLICY_KEY_INFO_LEN + 1];
    key_type_e keys_type[MAX_N_KEYS_IN_WALLET_POLICY];
    memset(keys_type, 0, sizeof(keys_type));

    for (size_t cosigner_index = 0; cosigner_index < wallet_header->n_keys; cosigner_index++) {
        /**
         * Receives and parses the next pubkey info.
         * Asks the user to validate the pubkey info.
         */

        int key_info_len = call_get_merkle_leaf_element(dc,
                                                        wallet_header->keys_info_merkle_root,
                                                        wallet_header->n_keys,
                                                        cosigner_index,
                                                        (uint8_t *) keys_info[cosigner_index],
                                                        MAX_POLICY_KEY_INFO_LEN);

        if (key_info_len < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        keys_info[cosigner_index][key_info_len] = 0;

        // Make a sub-buffer for the pubkey info
        buffer_t key_info_buffer = buffer_create(keys_info[cosigner_index], key_info_len);

        policy_map_key_info_t key_info;
        if (parse_policy_map_key_info(&key_info_buffer, &key_info, wallet_header->version) == -1) {
            PRINTF("Incorrect policy map.\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        if (read_u32_be(key_info.ext_pubkey.version, 0) != BIP32_PUBKEY_VERSION) {
            PRINTF("Invalid pubkey version. Wrong network?\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        // Reject invalid pubkeys (not on the curve)
        uint8_t uncompressed_pubkey[65];
        if (0 > crypto_get_uncompressed_pubkey(key_info.ext_pubkey.compressed_pubkey,
                                               uncompressed_pubkey)) {
            PRINTF("The pubkey is not a valid point of the curve\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        // We refuse to register wallets without key origin information, or whose keys don't end
        // with the wildcard ('/**'). The key origin information is necessary when signing to
        // identify which one is our key. Using addresses without a wildcard could potentially be
        // supported, but disabled for now (question to address: can only _some_ of the keys have a
        // wildcard?).

        if (memcmp(key_info.ext_pubkey.compressed_pubkey,
                   BIP0341_NUMS_PUBKEY,
                   sizeof(BIP0341_NUMS_PUBKEY)) == 0) {
            // this public key is known to be unspendable
            keys_type[cosigner_index] = PUBKEY_TYPE_UNSPENDABLE;
        } else {
            keys_type[cosigner_index] = PUBKEY_TYPE_EXTERNAL;

            // if there is key origin information and the fingerprint matches, we make sure it's not
            // a false positive (it could be wrong info, or a collision).
            if (key_info.has_key_origin &&
                read_u32_be(key_info.master_key_fingerprint, 0) == master_key_fingerprint) {
                // we verify that we can actually generate the same pubkey
                serialized_extended_pubkey_t pubkey_derived;
                uint16_t sw =
                    cx_err_to_sw(get_extended_pubkey_at_path(key_info.master_key_derivation,
                                                             key_info.master_key_derivation_len,
                                                             BIP32_PUBKEY_VERSION,
                                                             &pubkey_derived));
                if (SW_OK != sw) {
                    SEND_SW(dc, sw);
                    return;
                }

                if (memcmp(&key_info.ext_pubkey, &pubkey_derived, sizeof(pubkey_derived)) == 0) {
                    keys_type[cosigner_index] = PUBKEY_TYPE_INTERNAL;
                    ++n_internal_keys;
                }
            }
        }
    }

    if (n_internal_keys < 1) {
        // Unclear if there is any use case for registering policies with no internal keys.
        // We disallow that, might reconsider in future versions if needed.
        PRINTF("Wallet policy with no internal keys\n");
        SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_REGISTER_WALLET_POLICY_HAS_NO_INTERNAL_KEY);
        return;
    } else if (n_internal_keys != 1 && wallet_header->version == WALLET_POLICY_VERSION_V1) {
        // for legacy policies, we keep the restriction to exactly 1 internal key
        PRINTF("V1 policies must have exactly 1 internal key\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // Try to compute the cleartext spending-path lines. If the descriptor
    // doesn't classify (DC_OTHER), has non-canonical derivations, or its
    // confusion score exceeds the threshold, the cleartext block is skipped
    // and the UX falls back to the existing raw-descriptor-template screen.
    char cleartext_lines[CT_MAX_LINES][CT_MAX_LINE_LEN + 1];
    size_t n_cleartext_lines = 0;
    bool has_cleartext = false;
    descriptor_class_e cleartext_class = DC_OTHER;

    if (cleartext_confusion_score(policy) <= CLEARTEXT_MAX_CONFUSION_SCORE) {
        int rc = cleartext_encode(policy,
                                  NULL,
                                  cleartext_lines,
                                  &n_cleartext_lines,
                                  &has_cleartext,
                                  &cleartext_class);
        if (rc <= 0 || !has_cleartext) {
            // Either the descriptor doesn't classify (rc == 0), an internal
            // error occurred (rc == -1), or at least one part of the
            // descriptor lacks a cleartext rendering — in all cases keep
            // the current behaviour (raw descriptor template only).
            n_cleartext_lines = 0;
        }
    }

    // For multisig policies (all coalesced into DC_MULTISIG),
    // the cleartext "Any K of <keys> must sign" captures the spending policy
    // with little risk of ambiguity. Therefore, it is safe to hide the
    // raw descriptor template, simplifying the UX.
    const char *descriptor_to_show = (const char *) policy_map_descriptor;
    if (has_cleartext && n_cleartext_lines > 0 && cleartext_class == DC_MULTISIG) {
        descriptor_to_show = NULL;
    }

    // show wallet policy
    if (!ui_display_register_wallet_policy(dc,
                                           wallet_header,
                                           descriptor_to_show,
                                           &cleartext_lines,
                                           n_cleartext_lines,
                                           &keys_info,
                                           &keys_type)) {
        SEND_SW(dc, SW_DENY);
        return;
    }

    struct {
        uint8_t wallet_id[32];
        uint8_t hmac[32];
    } response;

    memcpy(response.wallet_id, wallet_id, 32);

    if (!compute_wallet_hmac(wallet_id, response.hmac)) {
        SEND_SW(dc, SW_BAD_STATE);  // this should never fail
        return;
    }

    SEND_RESPONSE(dc, &response, sizeof(response), SW_OK);
}

/**
 * Validates the input, initializes the hash context and starts accumulating the wallet header in
 * it.
 */
void handler_register_wallet(dispatcher_context_t *dc, uint8_t protocol_version) {
    UNUSED(protocol_version);

    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    policy_map_wallet_header_t wallet_header;

    uint8_t wallet_id[32];
    union {
        uint8_t bytes[MAX_WALLET_POLICY_BYTES];
        policy_node_t parsed;
    } policy_map;

    uint64_t serialized_policy_map_len;
    if (!buffer_read_varint(&dc->read_buffer, &serialized_policy_map_len)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    uint8_t policy_map_descriptor[MAX_DESCRIPTOR_TEMPLATE_LENGTH + 1];
    if (0 > read_and_parse_wallet_policy(dc,
                                         &dc->read_buffer,
                                         &wallet_header,
                                         policy_map_descriptor,
                                         policy_map.bytes,
                                         sizeof(policy_map.bytes))) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }
    policy_map_descriptor[wallet_header.descriptor_template_len] = '\0';

    if (wallet_header.n_keys > MAX_N_KEYS_IN_WALLET_POLICY) {
        PRINTF("At most %d key expressions are supported in a wallet policy.\n",
               MAX_N_KEYS_IN_WALLET_POLICY);
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return;
    }

    if (count_distinct_keys_info(&policy_map.parsed, wallet_header.n_keys) !=
        (int) wallet_header.n_keys) {
        PRINTF("The number of keys in descriptor template doesn't match the provided keys\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // Compute the wallet id (sha256 of the serialization)
    get_policy_wallet_id(&wallet_header, wallet_id);

    // Verify that the name is acceptable
    if (!is_policy_name_acceptable(wallet_header.name, wallet_header.name_len)) {
        PRINTF("Policy name is not acceptable\n");
        SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_REGISTER_WALLET_UNACCEPTABLE_POLICY_NAME);
        return;
    }

    // check if policy is acceptable
    if (!is_policy_acceptable(&policy_map.parsed)) {
        PRINTF("Policy is not acceptable\n");

        SEND_SW(dc, SW_NOT_SUPPORTED);
        return;
    }

    // make sure that the policy is sane (especially if it contains miniscript)
    if (0 > is_policy_sane(dc,
                           &policy_map.parsed,
                           wallet_header.version,
                           wallet_header.keys_info_merkle_root,
                           wallet_header.n_keys)) {
        PRINTF("Policy is not sane\n");

        SEND_SW_EC(dc, SW_NOT_SUPPORTED, EC_REGISTER_WALLET_POLICY_NOT_SANE);
        return;
    }

    confirm_and_register_wallet(dc,
                                &wallet_header,
                                policy_map_descriptor,
                                &policy_map.parsed,
                                wallet_id);
}

static bool is_policy_acceptable(const policy_node_t *policy) {
    return policy->type == TOKEN_PKH || policy->type == TOKEN_WPKH || policy->type == TOKEN_SH ||
           policy->type == TOKEN_WSH || policy->type == TOKEN_TR;
}

static bool is_policy_name_acceptable(const char *name, size_t name_len) {
    // between 1 and MAX_WALLET_NAME_LENGTH characters
    if (name_len == 0 || name_len > MAX_WALLET_NAME_LENGTH) return false;

    // first and last characters must not be whitespace
    if (name[0] == ' ' || name[name_len - 1] == ' ') return false;

    // only allow ascii characters in the range from 0x20 to 0x7E (inclusive)
    for (unsigned int i = 0; i < name_len; i++)
        if (name[i] < 0x20 || name[i] > 0x7E) return false;

    return true;
}
