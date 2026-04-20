/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2024 Ledger SAS.
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

#include "os.h"
#include "cx.h"

#include "../boilerplate/dispatcher.h"
#include "../boilerplate/sw.h"
#include "../common/bip32.h"
#include "../common/merkle.h"
#include "../common/read.h"
#include "../common/wallet.h"
#include "../common/write.h"

#include "../commands.h"
#include "../constants.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/menu.h"

#include "lib/get_merkle_leaf_element.h"
#include "lib/get_preimage.h"
#include "lib/policy.h"

#include "client_commands.h"

#include "handlers.h"

static bool is_policy_acceptable(const policy_node_t *policy);
static bool is_policy_name_acceptable(const char *name, size_t name_len);

static const uint8_t BIP0341_NUMS_PUBKEY[] = {0x02, 0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
                                              0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07,
                                              0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf,
                                              0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0};

/**
 * Validates the input, initializes the hash context and starts accumulating the wallet header in
 * it.
 */
void handler_register_wallet(dispatcher_context_t *dc, uint8_t protocol_version) {
    (void) protocol_version;

    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    policy_map_wallet_header_t wallet_header;

    uint8_t wallet_id[32];
    union {
        uint8_t bytes[MAX_WALLET_POLICY_BYTES];
        policy_node_t parsed;
    } policy_map;

    size_t n_internal_keys = 0;

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

    if (count_distinct_keys_info(&policy_map.parsed) != (int) wallet_header.n_keys) {
        PRINTF("Number of keys in descriptor template doesn't provided keys\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // Compute the wallet id (sha256 of the serialization)
    get_policy_wallet_id(&wallet_header, wallet_id);

    // Verify that the name is acceptable
    if (!is_policy_name_acceptable(wallet_header.name, wallet_header.name_len)) {
        PRINTF("Policy name is not acceptable\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
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

        SEND_SW(dc, SW_NOT_SUPPORTED);
        return;
    }

    if (!ui_display_register_wallet(dc, &wallet_header, (char *) policy_map_descriptor)) {
        SEND_SW(dc, SW_DENY);
        ui_post_processing_confirm_wallet_registration(dc, false);
        return;
    }

    uint32_t master_key_fingerprint = crypto_get_master_key_fingerprint();

    for (size_t cosigner_index = 0; cosigner_index < wallet_header.n_keys; cosigner_index++) {
        /**
         * Receives and parses the next pubkey info.
         * Asks the user to validate the pubkey info.
         */

        uint8_t next_pubkey_info[MAX_POLICY_KEY_INFO_LEN + 1];
        int pubkey_info_len = call_get_merkle_leaf_element(dc,
                                                           wallet_header.keys_info_merkle_root,
                                                           wallet_header.n_keys,
                                                           cosigner_index,
                                                           next_pubkey_info,
                                                           MAX_POLICY_KEY_INFO_LEN);

        if (pubkey_info_len < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            ui_post_processing_confirm_wallet_registration(dc, false);
            return;
        }

        next_pubkey_info[pubkey_info_len] = 0;

        // Make a sub-buffer for the pubkey info
        buffer_t key_info_buffer = buffer_create(next_pubkey_info, pubkey_info_len);

        policy_map_key_info_t key_info;
        if (parse_policy_map_key_info(&key_info_buffer, &key_info, wallet_header.version) == -1) {
            PRINTF("Incorrect policy map.\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            ui_post_processing_confirm_wallet_registration(dc, false);
            return;
        }

        if (read_u32_be(key_info.ext_pubkey.version, 0) != BIP32_PUBKEY_VERSION) {
            PRINTF("Invalid pubkey version. Wrong network?\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        // We refuse to register wallets without key origin information, or whose keys don't end
        // with the wildcard ('/**'). The key origin information is necessary when signing to
        // identify which one is our key. Using addresses without a wildcard could potentially be
        // supported, but disabled for now (question to address: can only _some_ of the keys have a
        // wildcard?).

        key_type_e key_type;

        if (memcmp(key_info.ext_pubkey.compressed_pubkey,
                   BIP0341_NUMS_PUBKEY,
                   sizeof(BIP0341_NUMS_PUBKEY)) == 0) {
            // this public key is known to be unspendable
            key_type = PUBKEY_TYPE_UNSPENDABLE;
        } else {
            key_type = PUBKEY_TYPE_EXTERNAL;

            // if there is key origin information and the fingerprint matches, we make sure it's not
            // a false positive (it could be wrong info, or a collision).
            if (key_info.has_key_origin &&
                read_u32_be(key_info.master_key_fingerprint, 0) == master_key_fingerprint) {
                // we verify that we can actually generate the same pubkey
                serialized_extended_pubkey_t pubkey_derived;
                int serialized_pubkey_len =
                    get_extended_pubkey_at_path(key_info.master_key_derivation,
                                                key_info.master_key_derivation_len,
                                                BIP32_PUBKEY_VERSION,
                                                &pubkey_derived);
                if (serialized_pubkey_len == -1) {
                    SEND_SW(dc, SW_BAD_STATE);
                    ui_post_processing_confirm_wallet_registration(dc, false);
                    return;
                }

                if (memcmp(&key_info.ext_pubkey, &pubkey_derived, sizeof(pubkey_derived)) == 0) {
                    key_type = PUBKEY_TYPE_INTERNAL;
                    ++n_internal_keys;
                }
            }
        }

        if (!ui_display_policy_map_cosigner_pubkey(dc,
                                                   (char *) next_pubkey_info,
                                                   cosigner_index,  // 1-indexed for the UI
                                                   wallet_header.n_keys,
                                                   key_type)) {
            SEND_SW(dc, SW_DENY);
            return;
        }
    }

    if (n_internal_keys < 1) {
        // Unclear if there is any use case for registering policies with no internal keys.
        // We disallow that, might reconsider in future versions if needed.
        PRINTF("Wallet policy with no internal keys\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        ui_post_processing_confirm_wallet_registration(dc, false);
        return;
    } else if (n_internal_keys != 1 && wallet_header.version == WALLET_POLICY_VERSION_V1) {
        // for legacy policies, we keep the restriction to exactly 1 internal key
        PRINTF("V1 policies must have exactly 1 internal key\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        ui_post_processing_confirm_wallet_registration(dc, false);
        return;
    }

    struct {
        uint8_t wallet_id[32];
        uint8_t hmac[32];
    } response;

    memcpy(response.wallet_id, wallet_id, sizeof(wallet_id));

    // TODO: we might want to add external info to be committed with the signature (e.g.: app
    // version).
    //       This would allow newer versions of the app to invalidate an old signature if desired,
    //       for example if a vulnerability is discovered in the registration flow of a previous
    //       app. The response would be changed to:
    //         <wallet_id> <metadata_len> <metadata> <hmac>
    //       And the signature would be on the concatenation of the wallet id and the metadata.
    //       The client must persist the metadata, together with the signature.

    if (!compute_wallet_hmac(wallet_id, response.hmac)) {
        SEND_SW(dc, SW_BAD_STATE);  // this should never fail
        return;
    }

    SEND_RESPONSE(dc, &response, sizeof(response), SW_OK);
    ui_post_processing_confirm_wallet_registration(dc, true);
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