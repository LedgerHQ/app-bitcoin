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

/* SDK headers */
#include "base58.h"
#include "bip32.h"
#include "buffer.h"
#include "read.h"
#include "swap.h"

/* Local headers */
#include "client_commands.h"
#include "commands.h"
#include "constants.h"
#include "crypto.h"
#include "display.h"
#include "error_codes.h"
#include "get_merkle_leaf_element.h"
#include "get_preimage.h"
#include "handle_swap_sign_transaction.h"
#include "handlers.h"
#include "io_ext.h"
#include "menu.h"
#include "merkle.h"
#include "policy.h"
#include "script.h"
#include "segwit_addr.h"
#include "sw.h"
#include "wallet.h"

void handler_get_wallet_address(dispatcher_context_t *dc, uint8_t protocol_version) {
    UNUSED(protocol_version);

    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    uint8_t display_address;

    uint32_t address_index;
    uint8_t is_change;

    uint8_t wallet_id[32];
    uint8_t wallet_hmac[32];

    bool is_wallet_default;  // whether the wallet policy can be used without being registered

    policy_map_wallet_header_t wallet_header;

    union {
        uint8_t bytes[MAX_WALLET_POLICY_BYTES];
        policy_node_t parsed;
    } wallet_policy_map;

    if (!buffer_read_u8(&dc->read_buffer, &display_address) ||
        !buffer_read_bytes(&dc->read_buffer, wallet_id, 32) ||
        !buffer_read_bytes(&dc->read_buffer, wallet_hmac, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    // change
    if (!buffer_read_u8(&dc->read_buffer, &is_change)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }
    if (is_change != 0 && is_change != 1) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // address index
    if (!buffer_read_u32(&dc->read_buffer, &address_index, BE)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }
    if (address_index >= BIP32_FIRST_HARDENED_CHILD) {
        SEND_SW(dc, SW_INCORRECT_DATA);  // it must be unhardened
        return;
    }

    {
        uint8_t serialized_wallet_policy[MAX_WALLET_POLICY_SERIALIZED_LENGTH];

        // Fetch the serialized wallet policy from the client
        int serialized_wallet_policy_len = call_get_preimage(dc,
                                                             wallet_id,
                                                             serialized_wallet_policy,
                                                             sizeof(serialized_wallet_policy));
        if (serialized_wallet_policy_len < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        buffer_t serialized_wallet_policy_buf =
            buffer_create(serialized_wallet_policy, serialized_wallet_policy_len);

        uint8_t policy_map_descriptor[MAX_DESCRIPTOR_TEMPLATE_LENGTH];
        if (0 > read_and_parse_wallet_policy(dc,
                                             &serialized_wallet_policy_buf,
                                             &wallet_header,
                                             policy_map_descriptor,
                                             wallet_policy_map.bytes,
                                             sizeof(wallet_policy_map.bytes))) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
    }

    if (is_array_all_zeros(wallet_hmac, sizeof(wallet_hmac))) {
        // No hmac, verify that the policy is indeed a default one

        if (!is_wallet_policy_standard(dc, &wallet_header, &wallet_policy_map.parsed)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        if (wallet_header.name_len != 0) {
            PRINTF("Name must be zero-length for a standard wallet policy\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        if (address_index > MAX_BIP44_ADDRESS_INDEX_RECOMMENDED) {
            PRINTF("Address index is too large\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        is_wallet_default = true;
    } else {
        // Verify hmac

        if (!check_wallet_hmac(wallet_id, wallet_hmac)) {
            PRINTF("Incorrect hmac\n");
            SEND_SW(dc, SW_SIGNATURE_FAIL);
            return;
        }

        is_wallet_default = false;
    }

#ifdef HAVE_SWAP
    // Swap feature: check that the wallet policy is a default one
    if (G_called_from_swap && !is_wallet_default) {
        PRINTF("Must be a default wallet policy for swap feature\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_METHOD_NONDEFAULT_POLICY);
        finalize_exchange_sign_transaction(false);
    }
#endif /* HAVE_SWAP */

    {
        uint8_t computed_wallet_id[32];
        // Compute the wallet id (sha256 of the serialization)
        get_policy_wallet_id(&wallet_header, computed_wallet_id);

        if (memcmp(wallet_id, computed_wallet_id, sizeof(wallet_id)) != 0) {
            PRINTF("Mismatching wallet policy id\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
    }

    {
        uint8_t script[MAX_PREVOUT_SCRIPTPUBKEY_LEN];

        int script_len = get_wallet_script(
            dc,
            &wallet_policy_map.parsed,
            &(wallet_derivation_info_t) {.wallet_version = wallet_header.version,
                                         .keys_merkle_root = wallet_header.keys_info_merkle_root,
                                         .n_keys = wallet_header.n_keys,
                                         .change = is_change,
                                         .address_index = address_index},
            script);
        if (script_len < 0) {
            PRINTF("Couldn't produce wallet script\n");
            SEND_SW(dc, SW_BAD_STATE);  // unexpected
            return;
        }

        int address_len;
        char address[MAX_ADDRESS_LENGTH_STR + 1];  // null-terminated string

        address_len = get_script_address(script, script_len, address, sizeof(address));

        if (address_len < 0) {
            PRINTF("Could not produce address\n");
            SEND_SW(dc, SW_BAD_STATE);  // unexpected
            return;
        }

        if (display_address != 0) {
            if (!ui_display_wallet_address(dc,
                                           is_wallet_default ? NULL : wallet_header.name,
                                           address)) {
                SEND_SW(dc, SW_DENY);
                return;
            }
        }

        SEND_RESPONSE(dc, address, address_len, SW_OK);
    }
}
