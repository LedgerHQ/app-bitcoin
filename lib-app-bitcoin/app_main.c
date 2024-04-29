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
#include "swap.h"

#include "apdu_constants.h"
#include "context.h"
#include "dispatcher.h"
#include "ui.h"

void app_main(void) {
  // Structured APDU command
  command_t cmd;

  io_init();

  if (!G_called_from_swap) {
    ui_idle_flow();
  }

  context_init();

  for (;;) {
    // Length of APDU command received in G_io_apdu_buffer
    int input_len = 0;

    // Receive command bytes in G_io_apdu_buffer
    if ((input_len = io_recv_command()) < 0) {
      PRINTF("=> io_recv_command failure\n");
      return;
    }

    // Parse APDU command from G_io_apdu_buffer
    if (!apdu_parser(&cmd, G_io_apdu_buffer, input_len)) {
      PRINTF("=> /!\\ BAD LENGTH: %.*H\n", input_len, G_io_apdu_buffer);
      io_send_sw(SW_INCORRECT_LENGTH);
      continue;
    }

    PRINTF(
        "=> CLA=%02X | INS=%02X | P1=%02X | P2=%02X | Lc=%02X | CData=%.*H\n",
        cmd.cla, cmd.ins, cmd.p1, cmd.p2, cmd.lc, cmd.lc, cmd.data);

    context.outLength = 0;

    // Dispatch structured APDU command to handler
    if (apdu_dispatcher(&cmd) < 0) {
      PRINTF("=> apdu_dispatcher failure\n");
      return;
    }
  }
}
