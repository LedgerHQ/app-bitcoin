#include "message_model.h"
#include "fuzz_sha256.h"
#include "fuzz_varint.h"
#include "mocks.h"

#include "write.h"

#include <string.h>

static const uint8_t mm_zero_slot[FUZZ_TAIL_SLOT_SIZE] = {0};

enum {
    MM_SLOT_PATH_BITS_OFF = 0,
    MM_SLOT_CHANGE_OFF = 1,
    MM_SLOT_ADDR_INDEX_OFF = 2,
    MM_SLOT_MESSAGE_LEN_OFF = 6,
    MM_SLOT_PRINTABLE_OFF = 8,
};

static inline const uint8_t *mm_slot(const uint8_t *slot_data, size_t slot_data_len, int idx) {
    size_t off = (size_t) idx * FUZZ_TAIL_SLOT_SIZE;
    if (slot_data && off + FUZZ_TAIL_SLOT_SIZE <= slot_data_len)
        return slot_data + off;
    return mm_zero_slot;
}

static uint32_t mm_pick_purpose(const uint8_t *entropy,
                                size_t entropy_len,
                                const uint8_t *slot0) {
    static const uint32_t PURPOSE_MAP[4] = {84, 44, 49, 86};
    uint8_t path_bits =
        slot0[MM_SLOT_PATH_BITS_OFF] ^ ((entropy_len > 10) ? entropy[10] : 0);
    return PURPOSE_MAP[path_bits & 3];
}

static uint8_t mm_path_bits(const uint8_t *entropy,
                            size_t entropy_len,
                            const uint8_t *slot0) {
    return slot0[MM_SLOT_PATH_BITS_OFF] ^ ((entropy_len > 10) ? entropy[10] : 0);
}

static uint16_t mm_message_length(const uint8_t *slot0) {
    uint16_t raw_len = fuzz_read_u16_le(slot0 + MM_SLOT_MESSAGE_LEN_OFF);
    if (raw_len == 0) raw_len = 1;
    if (raw_len > MSG_MAX_CHUNKS * MSG_CHUNK_SIZE) {
        raw_len = MSG_MAX_CHUNKS * MSG_CHUNK_SIZE;
    }
    return raw_len;
}

static size_t mm_chunk_len_for_index(const msg_scenario_t *sc, int idx) {
    if (idx == sc->n_chunks - 1) {
        size_t remainder = (size_t) (sc->message_length % MSG_CHUNK_SIZE);
        if (remainder != 0) {
            return remainder;
        }
    }
    return MSG_CHUNK_SIZE;
}

static void mm_fill_chunk(msg_scenario_t *sc,
                          int idx,
                          const uint8_t *slot,
                          int printable_mode) {
    size_t chunk_len = mm_chunk_len_for_index(sc, idx);
    sc->last_chunk_len = chunk_len;

    if (printable_mode) {
        for (size_t j = 0; j < chunk_len; j++) {
            sc->chunks[idx][j] =
                0x20 + (slot[j % FUZZ_TAIL_SLOT_SIZE] % (0x7E - 0x20 + 1));
        }
        return;
    }

    memcpy(sc->chunks[idx], slot,
           chunk_len > FUZZ_TAIL_SLOT_SIZE ? FUZZ_TAIL_SLOT_SIZE : chunk_len);
}

int mm_build_scenario(msg_scenario_t *sc,
                      semantic_host_t *host,
                      const uint8_t *entropy,
                      size_t entropy_len,
                      const uint8_t *slot_data,
                      size_t slot_data_len) {
    memset(sc, 0, sizeof(*sc));
    sh_reset(host);

    const uint8_t *s0 = mm_slot(slot_data, slot_data_len, 0);
    uint8_t path_bits = mm_path_bits(entropy, entropy_len, s0);
    uint32_t purpose = mm_pick_purpose(entropy, entropy_len, s0);

    sc->bip32_path_len = 3;
    write_u32_be(sc->bip32_path, 0, 0x80000000UL | purpose);
    write_u32_be(sc->bip32_path, 4, 0x80000001UL);
    write_u32_be(sc->bip32_path, 8, 0x80000000UL);

    if (path_bits & 4) {
        uint8_t change = s0[MM_SLOT_CHANGE_OFF] & 1;
        uint32_t addr_idx = fuzz_read_u32_le(s0 + MM_SLOT_ADDR_INDEX_OFF);
        write_u32_be(sc->bip32_path, 12, (uint32_t) change);
        write_u32_be(sc->bip32_path, 16, addr_idx);
        sc->bip32_path_len = 5;
    }

    /* Message length is tail-driven and capped only by the builder's chunk
     * storage. This keeps the first chunk as a combined payload/control
     * surface instead of hiding the length in the prefix. */
    uint16_t raw_len = mm_message_length(s0);
    sc->n_chunks = (int) ((raw_len + MSG_CHUNK_SIZE - 1) / MSG_CHUNK_SIZE);
    if (sc->n_chunks > MSG_MAX_CHUNKS) sc->n_chunks = MSG_MAX_CHUNKS;
    sc->message_length = (uint64_t) sc->n_chunks * MSG_CHUNK_SIZE;
    if (sc->message_length > raw_len) sc->message_length = raw_len;

    int printable_mode = ((s0[MM_SLOT_PRINTABLE_OFF] & 1) == 0);

    for (int i = 0; i < sc->n_chunks; i++) {
        const uint8_t *slot = mm_slot(slot_data, slot_data_len, i);
        mm_fill_chunk(sc, i, slot, printable_mode);
    }

    int tree_idx = sh_tree_init(host);
    if (tree_idx < 0) return -1;

    for (int i = 0; i < sc->n_chunks; i++) {
        size_t chunk_len = mm_chunk_len_for_index(sc, i);
        sh_tree_add_leaf(host, tree_idx, sc->chunks[i], chunk_len);
    }
    sh_tree_finalize(host, tree_idx);
    memcpy(sc->merkle_root, host->trees[tree_idx].root, 32);

    host->active = true;

    uint8_t *p = sc->apdu;
    uint8_t *end = sc->apdu + sizeof(sc->apdu);

    *p++ = sc->bip32_path_len;
    if (p + sc->bip32_path_len * 4 > end) return -1;
    memcpy(p, sc->bip32_path, sc->bip32_path_len * 4);
    p += sc->bip32_path_len * 4;

    p += fuzz_write_varint(p, sc->message_length);

    if (p + 32 > end) return -1;
    memcpy(p, sc->merkle_root, 32);
    p += 32;

    sc->apdu_len = (size_t) (p - sc->apdu);
    return 0;
}
