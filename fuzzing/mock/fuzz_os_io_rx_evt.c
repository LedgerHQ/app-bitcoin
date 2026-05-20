#include "fuzz_continuation_host.h"
#include <string.h>
#include <stdbool.h>

extern unsigned char G_io_tx_buffer[];
extern uint16_t G_output_len;

fuzz_continuation_host_t *fuzz_continuation_host = NULL;
int fuzz_continuation_idx = 0;

#define FUZZ_CCMD_PAYLOAD_MAX  250
#define FUZZ_CCMD_ENVELOPE_HDR   6

int os_io_rx_evt(unsigned char *buffer, unsigned short buffer_max_length,
                 unsigned int *timeout_ms, bool check_se_event) {
    uint8_t payload[FUZZ_CCMD_PAYLOAD_MAX];
    size_t payload_len = 0;
    size_t total_len;

    (void) timeout_ms;
    (void) check_se_event;

    if (fuzz_continuation_idx >= FUZZ_MAX_CONTINUATIONS) {
        buffer[0] = 0x10;
        buffer[1] = 0x00;
        return 2;
    }

    if (!fuzz_continuation_host || !fuzz_continuation_host->active) {
        buffer[0] = 0x10;
        buffer[1] = 0x00;
        return 2;
    }

    size_t tx_len = (size_t) G_output_len;
    if (tx_len > 260) tx_len = 260;

    payload_len = sizeof(payload);
    int rc = fuzz_continuation_host->handle_ccmd(
        fuzz_continuation_host->ctx,
        G_io_tx_buffer, tx_len,
        payload, &payload_len);

    fuzz_continuation_idx++;

    if (rc < 0 || payload_len > FUZZ_CCMD_PAYLOAD_MAX) {
        buffer[0] = 0x10;
        buffer[1] = 0x00;
        return 2;
    }

    total_len = FUZZ_CCMD_ENVELOPE_HDR + payload_len;
    if (total_len > buffer_max_length) {
        payload_len = buffer_max_length - FUZZ_CCMD_ENVELOPE_HDR;
        total_len = buffer_max_length;
    }

    buffer[0] = 0x10;
    buffer[1] = 0xF8;
    buffer[2] = 0x01;
    buffer[3] = 0x00;
    buffer[4] = 0x00;
    buffer[5] = (uint8_t) payload_len;
    if (payload_len > 0)
        memcpy(&buffer[6], payload, payload_len);

    return (int) total_len;
}
