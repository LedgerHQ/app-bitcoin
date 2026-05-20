#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FUZZ_MAX_CONTINUATIONS 512

/*
 * Continuation-host interface for Ledger app fuzz harnesses.  Apps that
 * use continuation protocols (handler calls os_io_rx_evt() to request
 * more data) set fuzz_continuation_host before dispatch; the framework's
 * os_io_rx_evt mock dispatches to it and wraps the reply in the standard
 * envelope.  See $BOLOS_SDK/fuzzing/docs/APP_CONTRACT.md.
 */
typedef struct {
    /*
     *   ctx          opaque app context (e.g. semantic_host_t *)
     *   request      raw continuation bytes from G_io_tx_buffer
     *   response     buffer to fill (in: capacity, out: length)
     * Returns 0 on success, negative on error (terminate response).
     */
    int (*handle_ccmd)(void *ctx,
                       const uint8_t *request, size_t request_len,
                       uint8_t *response, size_t *response_len);
    void *ctx;
    bool  active;
} fuzz_continuation_host_t;

extern fuzz_continuation_host_t *fuzz_continuation_host;

/* Reset to 0 per input by the harness; incremented per round by os_io_rx_evt mock. */
extern int fuzz_continuation_idx;
