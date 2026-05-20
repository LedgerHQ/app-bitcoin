#include "mocks.h"
#include "semantic_host.h"
#include "fuzz_continuation_host.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef PRINTF
#undef PRINTF
#endif
int PRINTF(const char *format, ...) {
    (void) format;
    return 0;
}

void os_explicit_zero_BSS_segment(void) {
    /* No-op: zeroing BSS would erase the Absolution prefix state. */
}

void __attribute__((noreturn)) app_exit(void) {
    _Exit(0);
}

extern bool ___src_ui_display_c_g_ux_flow_ended;
extern bool ___src_ui_display_c_g_ux_flow_response;

bool fuzz_ui_approve;

void io_seproxyhal_io_heartbeat(void) {
    ___src_ui_display_c_g_ux_flow_ended = true;
    ___src_ui_display_c_g_ux_flow_response = fuzz_ui_approve;
}

uint8_t psbt_entropy[PSBT_ENTROPY_SIZE];

unsigned char mock_continuation_data[MOCK_CONTINUATION_SLOTS][MOCK_CONTINUATION_PAYLOAD_SIZE];

const uint8_t *fuzz_tail_ptr = NULL;
size_t fuzz_tail_len = 0;

/* mock_continuation_data is zeroed by zero-symbols.txt; builders now read
 * slot data from fuzz_tail_ptr (see FUZZ_TAIL_SLOT_* in mocks.h).
 * get_fuzz_for_round() is retained for ABI compatibility but returns
 * zeroed data (the semantic host handles all continuation replies). */
uint8_t *get_fuzz_for_round(int round) {
    return mock_continuation_data[round % MOCK_CONTINUATION_SLOTS];
}
