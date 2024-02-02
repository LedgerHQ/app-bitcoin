/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
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
#include <stdbool.h>

#include "buffer.h"
#include "io.h"
#include "ledger_assert.h"

#include "dispatcher.h"
#include "apdu_constants.h"

int apdu_dispatcher(const command_t *cmd) {
    LEDGER_ASSERT(cmd != NULL, "NULL cmd");

    if (cmd->cla != CLA) {
        return io_send_sw(SW_CLA_NOT_SUPPORTED);
    }

    buffer_t buf = {0};

    switch (cmd->ins) {
        case INS_GET_WALLET_PUBLIC_KEY:
            PRINTF("Get wallet public key\n");
            if (!cmd->data) {
                return io_send_sw(SW_INCORRECT_LENGTH);
            }
            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_get_wallet_public_key(&buf, cmd->p1, cmd->p2);

        case INS_GET_TRUSTED_INPUT:
            PRINTF("Get trusted input\n");
            if (!cmd->data) {
                return io_send_sw(SW_INCORRECT_LENGTH);
            }

            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_get_trusted_input(&buf, cmd->p1, cmd->p2);

        case INS_HASH_INPUT_START:
            PRINTF("Hash input start\n");
            if (!cmd->data) {
                return io_send_sw(SW_INCORRECT_LENGTH);
            }

            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_hash_input_start(&buf, cmd->p1, cmd->p2);

        case INS_HASH_SIGN:
            PRINTF("Hash sign\n");
            if (!cmd->data) {
                return io_send_sw(SW_INCORRECT_LENGTH);
            }

            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_hash_sign(&buf, cmd->p1, cmd->p2);

        case INS_HASH_INPUT_FINALIZE_FULL:
            PRINTF("Hash input finalize full\n");
            if (!cmd->data) {
                return io_send_sw(SW_INCORRECT_LENGTH);
            }

            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_hash_input_finalize_full(&buf, cmd->p1, cmd->p2);

        case INS_SIGN_MESSAGE:
            PRINTF("Sign message\n");
            if (!cmd->data) {
                return io_send_sw(SW_INCORRECT_LENGTH);
            }

            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_sign_message(&buf, cmd->p1, cmd->p2);

        case INS_GET_FIRMWARE_VERSION:
            PRINTF("Get firmware version\n");

            return handler_get_firmware_version();
            
        case INS_GET_COIN_VER:
            PRINTF("Get coin version\n");

            return handler_get_coin_version();

        default:
            PRINTF("Instruction not supported\n");
            return io_send_sw(SW_INS_NOT_SUPPORTED);
    }
}
