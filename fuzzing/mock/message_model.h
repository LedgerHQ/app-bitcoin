#pragma once

#include <stddef.h>
#include <stdint.h>

#include "semantic_host.h"

#define MSG_MAX_CHUNKS 32
#define MSG_CHUNK_SIZE 64

typedef struct {
    uint8_t bip32_path[8 * 4];
    uint8_t bip32_path_len;

    uint64_t message_length;
    int n_chunks;
    uint8_t chunks[MSG_MAX_CHUNKS][MSG_CHUNK_SIZE];
    size_t last_chunk_len;

    uint8_t merkle_root[32];

    uint8_t apdu[256];
    size_t apdu_len;
} msg_scenario_t;

int mm_build_scenario(msg_scenario_t *sc,
                      semantic_host_t *host,
                      const uint8_t *entropy,
                      size_t entropy_len,
                      const uint8_t *slot_data,
                      size_t slot_data_len);
