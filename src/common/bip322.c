/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2026 Ledger SAS.
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

#include <string.h>

#include "bip322.h"

/* SDK headers */
#include "write.h"

/* Local headers */
#include "crypto.h"

// The BIP-340 tag used for the message hash, as defined by BIP-322.
static const uint8_t BIP0322_MSG_TAG[] = {'B', 'I', 'P', '0', '3', '2', '2', '-', 's', 'i', 'g',
                                          'n', 'e', 'd', '-', 'm', 'e', 's', 's', 'a', 'g', 'e'};

void bip322_message_hash_init(cx_sha256_t *hash_context) {
    crypto_tr_tagged_hash_init(hash_context, BIP0322_MSG_TAG, sizeof(BIP0322_MSG_TAG));
}

int bip322_serialize_to_spend(const uint8_t message_hash[static 32],
                              const uint8_t *challenge_script,
                              size_t challenge_script_len,
                              uint8_t out[static BIP322_TO_SPEND_MAX_LEN]) {
    if (challenge_script_len > MAX_PREVOUT_SCRIPTPUBKEY_LEN) {
        return -1;
    }

    size_t offset = 0;
    write_u32_le(out, offset, 0);  // nVersion = 0
    offset += 4;
    out[offset++] = 0x01;         // 1 input
    memset(out + offset, 0, 32);  // prevout hash = null
    offset += 32;
    write_u32_le(out, offset, 0xFFFFFFFF);  // prevout index
    offset += 4;
    out[offset++] = 34;    // scriptSig length
    out[offset++] = 0x00;  // OP_0
    out[offset++] = 0x20;  // push of 32 bytes
    memcpy(out + offset, message_hash, 32);
    offset += 32;
    write_u32_le(out, offset, 0);  // nSequence = 0
    offset += 4;
    out[offset++] = 0x01;        // 1 output
    memset(out + offset, 0, 8);  // value = 0
    offset += 8;
    // the compact size of the script length is a single byte for lengths below 0xFD
    _Static_assert(MAX_PREVOUT_SCRIPTPUBKEY_LEN < 0xFD,
                   "the challenge script length must be serializable as a single byte");
    out[offset++] = (uint8_t) challenge_script_len;
    memcpy(out + offset, challenge_script, challenge_script_len);
    offset += challenge_script_len;
    write_u32_le(out, offset, 0);  // nLockTime = 0
    offset += 4;

    return (int) offset;
}

int bip322_compute_to_spend_txid(const uint8_t message_hash[static 32],
                                 const uint8_t *challenge_script,
                                 size_t challenge_script_len,
                                 uint8_t out_txid[static 32]) {
    uint8_t to_spend[BIP322_TO_SPEND_MAX_LEN];

    int len =
        bip322_serialize_to_spend(message_hash, challenge_script, challenge_script_len, to_spend);
    if (len < 0) {
        return -1;
    }

    cx_hash_sha256(to_spend, len, out_txid, 32);
    cx_hash_sha256(out_txid, 32, out_txid, 32);
    return 0;
}
