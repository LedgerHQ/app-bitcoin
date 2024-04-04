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

#include "io.h"
#include "write.h"

#include "apdu_constants.h"
#include "context.h"

WEAK unsigned short handler_get_coin_version(void) {
  uint8_t offset = 0;
  size_t string_size;

  write_u16_be(G_io_apdu_buffer, offset, COIN_P2PKH_VERSION);
  offset += 2;

  write_u16_be(G_io_apdu_buffer, offset, COIN_P2SH_VERSION);
  offset += 2;

  G_io_apdu_buffer[offset++] = COIN_FAMILY;

  string_size = strlen(COIN_COINID);
  G_io_apdu_buffer[offset++] = string_size;
  memmove(G_io_apdu_buffer + offset, COIN_COINID, string_size);
  offset += string_size;

  string_size = strlen(COIN_COINID_SHORT);
  G_io_apdu_buffer[offset++] = string_size;
  memmove(G_io_apdu_buffer + offset, COIN_COINID_SHORT, string_size);
  offset += string_size;

  context.outLength = offset;

  return io_send_response_pointer(G_io_apdu_buffer, offset, SW_OK);
}
