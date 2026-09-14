#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FUZZ_MAX_CONTINUATIONS 512

// Continuation-host hook: os_io_rx_evt()'s mock dispatches app data requests
// here and wraps the reply in the SDK envelope.
typedef struct {
    // Receives the raw request and fills response (in: capacity, out: length);
    // returns 0 on success, negative to terminate.
    int (*handle_ccmd)(void *ctx,
                       const uint8_t *request, size_t request_len,
                       uint8_t *response, size_t *response_len);
    void *ctx;
    bool  active;
} fuzz_continuation_host_t;

extern fuzz_continuation_host_t *fuzz_continuation_host;

/* Reset to 0 per input by the harness; incremented per round by os_io_rx_evt mock. */
extern int fuzz_continuation_idx;
