#pragma once

#include <stddef.h>
#include <stdint.h>

#include "mock_dispatcher.h"

#define MSG_MAX_CHUNKS 32
#define MSG_CHUNK_SIZE 64

typedef struct {
    uint8_t bip32_path[8 * 4];
    size_t bip32_path_served;   /* components actually written, may be < the
                                 * length the APDU declares */
    uint8_t bip32_path_len;

    uint64_t message_length;
    int n_chunks;
    uint8_t chunks[MSG_MAX_CHUNKS][MSG_CHUNK_SIZE];
    /* Per-chunk length, independent of message_length. Deriving one from the other is
     * what made the app's non-final-chunk length check unreachable. */
    size_t chunk_lens[MSG_MAX_CHUNKS];

    uint8_t merkle_root[32];

    uint8_t apdu[256];
    size_t apdu_len;
} msg_scenario_t;

int mm_build_scenario(msg_scenario_t *sc,
                      mock_dispatcher_t *host,
                      const uint8_t *entropy,
                      size_t entropy_len,
                      const uint8_t *slot_data,
                      size_t slot_data_len);
