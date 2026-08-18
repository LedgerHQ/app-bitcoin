#include "mocks.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern bool ___src_ui_display_c_g_ux_flow_ended;
extern bool ___src_ui_display_c_g_ux_flow_response;

/* Framework idiom: fuzz_mock_<area>_<failure-condition>, 0 = happy path --
 * matching fuzz_mock_nbgl_reject in the SDK's NBGL mock. */
uint8_t fuzz_mock_ui_reject;

void io_seproxyhal_io_heartbeat(void) {
    ___src_ui_display_c_g_ux_flow_ended = true;
    ___src_ui_display_c_g_ux_flow_response = (fuzz_mock_ui_reject == 0);
}

uint8_t psbt_entropy[PSBT_ENTROPY_SIZE];

