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

/* Local headers */
#include "client_commands.h"
#include "constants.h"
#include "dispatcher.h"
#include "handlers.h"
#include "sw.h"

void handler_register_wallet(dispatcher_context_t *dc, uint8_t protocol_version) {
    UNUSED(protocol_version);

    // not supported in derived apps
    SEND_SW(dc, SW_NOT_SUPPORTED);
    return;
}
