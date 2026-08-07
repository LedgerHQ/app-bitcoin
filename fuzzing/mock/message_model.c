/* SIGN_MESSAGE scenarios.
 *
 * Two roles, kept apart:
 *
 *   content    -- path length and every path component, the declared message
 *                 length, the chunk count and each chunk's length and bytes. All of
 *                 it comes off the tape. Nothing here decides a value.
 *   commitment -- build the chunk Merkle tree and serialize the APDU, so the host
 *                 can answer for whatever was committed.
 *
 */

#include "message_model.h"
#include "fuzz_varint.h"
#include "mocks.h"

#include "write.h"

#include <string.h>

/* Cursor over the harness input; reads past the end yield 0, so a short input
 * degrades to a small message rather than to no message. */
typedef struct {
    const uint8_t *p;
    size_t len;
    size_t off;
} mm_tape_t;

static uint8_t mm_u8(mm_tape_t *t) {
    return (t->off < t->len) ? t->p[t->off++] : 0;
}

static uint32_t mm_u32(mm_tape_t *t) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        v = (v << 8) | mm_u8(t);
    }
    return v;
}

int mm_build_scenario(msg_scenario_t *sc,
                      mock_dispatcher_t *host,
                      const uint8_t *entropy,
                      size_t entropy_len,
                      const uint8_t *slot_data,
                      size_t slot_data_len) {
    (void) entropy;
    (void) entropy_len;

    memset(sc, 0, sizeof(*sc));
    mock_dispatcher_reset(host);

    /* Slot 0 is reserved scenario-control space in all three builders, so the tape
     * starts after it here too. */
    mm_tape_t tape = {
        .p = slot_data ? slot_data + FUZZ_TAIL_SLOT_SIZE : NULL,
        .len = (slot_data_len > FUZZ_TAIL_SLOT_SIZE) ? slot_data_len - FUZZ_TAIL_SLOT_SIZE : 0,
        .off = 0,
    };

    size_t max_steps = sizeof(sc->bip32_path) / 4;
    size_t served = (size_t) (mm_u8(&tape) % (max_steps + 1));
    for (size_t i = 0; i < served; i++) {
        write_u32_be(sc->bip32_path, i * 4, mm_u32(&tape));
    }
    /* The declared length is its own tape byte, not the number of components served,
     * so it can outrun them: that reaches both sign_message.c:57's
     * MAX_BIP32_PATH_STEPS rejection and the truncation cases. Honest seven times in
     * eight, so the happy path stays reachable. */
    sc->bip32_path_len = ((mm_u8(&tape) & 0x07u) == 0x07u)
                             ? mm_u8(&tape)
                             : (uint8_t) served;
    sc->bip32_path_served = served;

    /* Chunk count and each chunk's length are independent of the declared message
     * length below, which is the whole point: they are allowed to disagree. */
    sc->n_chunks = (int) (mm_u8(&tape) % (MSG_MAX_CHUNKS + 1));
    size_t bytes_served = 0;
    for (int i = 0; i < sc->n_chunks; i++) {
        size_t chunk_len = (size_t) (mm_u8(&tape) % (MSG_CHUNK_SIZE + 1));
        for (size_t j = 0; j < chunk_len; j++) {
            sc->chunks[i][j] = mm_u8(&tape);   /* raw bytes, no printable filter */
        }
        sc->chunk_lens[i] = chunk_len;
        bytes_served += chunk_len;
    }

    /* Declared length: usually what was actually served, so the happy path stays
     * reachable, but sometimes an unrelated 32-bit value so the length checks and
     * the chunk-count arithmetic in sign_message.c see a mismatch. */
    sc->message_length = ((mm_u8(&tape) & 0x07u) == 0x07u) ? mm_u32(&tape) : (uint64_t) bytes_served;

    int tree_idx = mock_dispatcher_tree_begin(host);
    if (tree_idx < 0) return -1;
    for (int i = 0; i < sc->n_chunks; i++) {
        if (mock_dispatcher_tree_add_leaf(host, tree_idx, sc->chunks[i],
                                         sc->chunk_lens[i]) < 0) {
            return -1;
        }
    }
    mock_dispatcher_tree_end(host, tree_idx, sc->merkle_root);

    uint8_t *p = sc->apdu;
    uint8_t *end = sc->apdu + sizeof(sc->apdu);

    /* Declare the tape's length, serialize the components actually written. When they
     * disagree the app reads a payload shorter than its own header claims, which is
     * the truncation case sign_message.c has to survive. Copying declared*4 would run
     * off sc->bip32_path, which holds only 8 components. */
    *p++ = sc->bip32_path_len;
    if (p + sc->bip32_path_served * 4 + 9 + 32 > end) return -1;
    memcpy(p, sc->bip32_path, sc->bip32_path_served * 4);
    p += sc->bip32_path_served * 4;

    p += fuzz_write_varint(p, sc->message_length);

    memcpy(p, sc->merkle_root, 32);
    p += 32;

    sc->apdu_len = (size_t) (p - sc->apdu);
    return 0;
}
