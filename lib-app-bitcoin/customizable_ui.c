/*******************************************************************************
*   Ledger App - Bitcoin Wallet
*   (c) 2016-2019 Ledger
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
********************************************************************************/
#include "customizable_ui.h"
#include "customizable_helpers.h"
#include "helpers.h"
#include "context.h"
#include "display_variables.h"
#include "segwit_addr.h"
#include "cashaddr.h"
#include "be_operations.h"
#include "display_utils.h"
#include "read.h"


WEAK void get_address_from_output_script(unsigned char* script, int script_size, char* out, int out_size) {
    if (output_script_is_op_return(script)) {
        strncpy(out, "OP_RETURN", out_size);
        return;
    }
    if ((COIN_KIND == COIN_KIND_HYDRA) &&
        output_script_is_op_create(script, script_size)) {
        strncpy(out, "OP_CREATE", out_size);
        return;
    }
    if ((COIN_KIND == COIN_KIND_HYDRA) &&
        output_script_is_op_call(script, script_size)) {
        strncpy(out, "OP_CALL", out_size);
        return;
    }
    if (output_script_is_native_witness(script)) {
        if (COIN_NATIVE_SEGWIT_PREFIX) {
            segwit_addr_encode(
                out, (char *)PIC(COIN_NATIVE_SEGWIT_PREFIX), 0,
                script + OUTPUT_SCRIPT_NATIVE_WITNESS_PROGRAM_OFFSET,
                script[OUTPUT_SCRIPT_NATIVE_WITNESS_PROGRAM_OFFSET - 1]);
        }
        return;
    }
    unsigned char versionSize;
    unsigned char address[22];
    unsigned short textSize;
    int addressOffset = 3;
    unsigned short version = COIN_P2SH_VERSION;

    if (output_script_is_regular(script)) {
        addressOffset = 4;
        version = COIN_P2PKH_VERSION;
    }

    if (version > 255) {
        versionSize = 2;
        address[0] = (version >> 8);
        address[1] = version;
    } else {
        versionSize = 1;
        address[0] = version;
    }
    memmove(address + versionSize, script + addressOffset, 20);

    // Prepare address
    if (context.usingCashAddr) {
        cashaddr_encode(
            address + versionSize, 20, (uint8_t *)out, out_size,
            (version == COIN_P2SH_VERSION
                    ? CASHADDR_P2SH
                    : CASHADDR_P2PKH));
    } else {
        textSize = public_key_to_encoded_base58(
            address, 20 + versionSize, (unsigned char *)out,
            out_size, version, 1);
        out[textSize] = '\0';
    }
}

WEAK uint8_t prepare_fees(void) {
    if (context.transactionContext.relaxed) {
        memmove(vars.tmp.feesAmount, "UNKNOWN", 7);
        vars.tmp.feesAmount[7] = '\0';
    } else {
        unsigned char fees[8];
        unsigned char borrow;

        borrow = transaction_amount_sub_be(
                fees, context.transactionContext.transactionAmount,
                context.totalOutputAmount);
        if (borrow && COIN_KIND == COIN_KIND_KOMODO) {
            memmove(vars.tmp.feesAmount, "REWARD", 6);
            vars.tmp.feesAmount[6] = '\0';
        }
        else {
            if (borrow) {
                PRINTF("Error : Fees not consistent");
                goto error;
            }
        format_sats_amount(COIN_COINID_SHORT,
                (uint64_t)read_u64_be(fees, 0), // Cast prevents weird compilo bug
                vars.tmp.feesAmount);
        }
    }
    return 1;
error:
    return 0;
}
