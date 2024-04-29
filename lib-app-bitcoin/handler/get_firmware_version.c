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

#include "apdu_constants.h"
#include "context.h"

#define FEATURES_SELF_SCREEN_BUTTONS 0x02
#define FEATURES_NFC 0x08
#define FEATURES_BLE 0x10

#define MODE_SETUP 0x01
#define MODE_OPERATION 0x02

#define FEATURES (FEATURES_NFC | FEATURES_BLE | FEATURES_SELF_SCREEN_BUTTONS)
#define MODE (MODE_SETUP | MODE_OPERATION)

#define ARCH_ID 0x30

#define TCS_LOADER_PATCH_VERSION 0

/*
 * Function: handler_get_firmware_version
 * ---------------------------------------
 * Retrieves the firmware version information.
 *
 * Returns:
 *   - -1 if the operation is unsuccessful.
 */
WEAK unsigned short handler_get_firmware_version() {

  G_io_apdu_buffer[0] = FEATURES;
  G_io_apdu_buffer[1] = ARCH_ID;
  G_io_apdu_buffer[2] = MAJOR_VERSION;
  G_io_apdu_buffer[3] = MINOR_VERSION;
  G_io_apdu_buffer[4] = PATCH_VERSION;
  G_io_apdu_buffer[5] = 1;
  G_io_apdu_buffer[6] = TCS_LOADER_PATCH_VERSION;
  G_io_apdu_buffer[7] = MODE;

  context.outLength = 0x08;

  return io_send_response_pointer(G_io_apdu_buffer, 0x08, SW_OK);
}
