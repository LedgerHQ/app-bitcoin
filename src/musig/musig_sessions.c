#include <string.h>

#include "musig_sessions.h"

/* SDK headers */
#include "cx.h"

/* Local headers */
#include "crypto.h"

// A session in the persistent storage.
// Only a prefix of the psbt_session_id is stored, so that each session fits in 64 bytes. This is
// harmless: collisions remain nearly impossible, and anyway a collision on the ID only causes a
// session to be deleted, and the following round 2 to fail.
#define STORED_ID_PREFIX_LEN 28

typedef struct {
    uint8_t id_prefix[STORED_ID_PREFIX_LEN];
    // Incremented for each stored session, in order to evict the oldest session when the storage is
    // full. It is never 0 for a stored session; it would take 2^32 sessions to overflow.
    uint32_t counter;
    uint8_t rand_root[32];
} musig_stored_session_t;

_Static_assert(sizeof(musig_stored_session_t) == 64, "A stored session must take 64 bytes");

typedef struct {
    // Aligning by 4 is necessary due to platform limitations.
    // Aligning by 64 further guarantees that each session occupies exactly
    // a single NVRAM page, minimizing the number of writes.
    __attribute__((aligned(64))) musig_stored_session_t sessions[MAX_N_MUSIG_SESSIONS];
} musig_persistent_storage_t;

const musig_persistent_storage_t N_musig_storage_real;
#define N_musig_storage (*(const volatile musig_persistent_storage_t *) PIC(&N_musig_storage_real))

static bool is_slot_free(int i) {
    return is_array_all_zeros((uint8_t *) &N_musig_storage.sessions[i],
                              sizeof(musig_stored_session_t));
}

static bool musigsession_pop(const uint8_t psbt_session_id[static 32], musig_psbt_session_t *out) {
    for (int i = 0; i < MAX_N_MUSIG_SESSIONS; i++) {
        if (is_slot_free(i)) {
            continue;
        }
        if (memcmp(psbt_session_id,
                   (const void *) N_musig_storage.sessions[i].id_prefix,
                   STORED_ID_PREFIX_LEN) == 0) {
            if (out != NULL) {
                memcpy(out->_id, psbt_session_id, sizeof(out->_id));
                memcpy(out->_rand_root,
                       (const void *) N_musig_storage.sessions[i].rand_root,
                       sizeof(out->_rand_root));
            }
            uint8_t zeros[sizeof(musig_stored_session_t)] = {0};
            nvm_write((void *) &N_musig_storage.sessions[i],
                      (void *) zeros,
                      sizeof(musig_stored_session_t));

            return true;
        }
    }
    return false;
}

__attribute__((warn_unused_result)) static bool musigsession_init_randomness(
    musig_psbt_session_t *session) {
    // it is extremely important that the randomness is initialized with a cryptographically strong
    // random number generator
    if (cx_get_random_bytes(session->_rand_root, sizeof(session->_rand_root)) != CX_OK) {
        explicit_bzero(session->_rand_root, sizeof(session->_rand_root));
        return false;
    }
    return true;
}

static void musigsession_store(const uint8_t psbt_session_id[static 32],
                               const musig_psbt_session_t *session) {
    // make sure that no session with the same id exists; delete it otherwise
    musigsession_pop(psbt_session_id, NULL);

    // Use a free slot if any; otherwise, evict the oldest session (the one with the smallest
    // counter). The new session gets a counter larger than all the stored ones.
    int free_slot = -1;
    int oldest_slot = -1;
    uint32_t max_counter = 0;
    for (int i = 0; i < MAX_N_MUSIG_SESSIONS; i++) {
        if (is_slot_free(i)) {
            if (free_slot < 0) {
                free_slot = i;
            }
            continue;
        }
        uint32_t counter = N_musig_storage.sessions[i].counter;
        if (oldest_slot < 0 || counter < N_musig_storage.sessions[oldest_slot].counter) {
            oldest_slot = i;
        }
        if (counter > max_counter) {
            max_counter = counter;
        }
    }
    int chosen = free_slot >= 0 ? free_slot : oldest_slot;

    musig_stored_session_t stored_session;
    memcpy(stored_session.id_prefix, psbt_session_id, sizeof(stored_session.id_prefix));
    stored_session.counter = max_counter + 1;
    memcpy(stored_session.rand_root, session->_rand_root, sizeof(stored_session.rand_root));

    // replace the chosen slot
    nvm_write((void *) &N_musig_storage.sessions[chosen],
              (void *) &stored_session,
              sizeof(musig_stored_session_t));

    explicit_bzero(&stored_session, sizeof(stored_session));
}

void compute_rand_i_j(const musig_psbt_session_t *psbt_session,
                      int i,
                      int j,
                      uint8_t out[static 32]) {
    // It is extremely important that different choices of the root of randomness, i and j always
    // produce a different result in out.
    // Failure would be catastrophic as it would cause nonce reuse, which in MuSig2 allows attackers
    // to recover the private key.

    cx_sha256_t hash_context;
    cx_sha256_init(&hash_context);
    crypto_hash_update(&hash_context.header, psbt_session->_rand_root, CX_SHA256_SIZE);
    crypto_hash_update_u32(&hash_context.header, (uint32_t) i);
    crypto_hash_update_u32(&hash_context.header, (uint32_t) j);
    crypto_hash_digest(&hash_context.header, out, 32);

    // avoid leaving sensitive randomness traces in memory
    explicit_bzero(&hash_context, sizeof(hash_context));
}

void musigsession_initialize_signing_state(musig_signing_state_t *musig_signing_state) {
    memset(musig_signing_state, 0, sizeof(musig_signing_state_t));
}

const musig_psbt_session_t *musigsession_round1_initialize(
    uint8_t psbt_session_id[static 32],
    musig_signing_state_t *musig_signing_state) {
    // if an existing session for psbt_session_id exists, delete it
    if (musigsession_pop(psbt_session_id, NULL)) {
        // We wouldn't expect this: probably the client sent the same psbt for
        // round 1 twice, without adding the pubnonces to the psbt after the first round.
        // We delete the old session and start a fresh one, but we print a
        // warning if in debug mode.
        PRINTF("Session with the same id already existing\n");
    }

    if (memcmp(musig_signing_state->_round1._id, psbt_session_id, 32) != 0) {
        // first input/placeholder pair using this session: initialize the session
        if (!musigsession_init_randomness(&musig_signing_state->_round1)) {
            PRINTF("Failed to initialize randomness for MuSig2 session\n");
            return NULL;
        }
        // only copy the id if there was no failure
        memcpy(musig_signing_state->_round1._id, psbt_session_id, 32);
    }

    return &musig_signing_state->_round1;
}

const musig_psbt_session_t *musigsession_round2_initialize(
    uint8_t psbt_session_id[static 32],
    musig_signing_state_t *musig_signing_state) {
    if (memcmp(musig_signing_state->_round2._id, psbt_session_id, 32) != 0) {
        // get and delete the musig session from permanent storage
        if (!musigsession_pop(psbt_session_id, &musig_signing_state->_round2)) {
            // The PSBT contains a partial nonce, but we do not have the corresponding psbt
            // session in storage. Either it was deleted, or the pubnonces were not real. Either
            // way, we cannot continue.
            PRINTF("Missing MuSig2 session\n");
            return NULL;
        }
    }

    return &musig_signing_state->_round2;
}

void musigsession_commit(musig_signing_state_t *musig_signing_state) {
    // If round 1 was not executed, then there is nothing to store.
    // This assumes that musigsession_initialize_signing_state zeroes the id, therefore the field is
    // zeroed out if and only if it wasn't used.
    if (!is_array_all_zeros(musig_signing_state->_round1._id,
                            sizeof(musig_signing_state->_round1._id))) {
        musigsession_store(musig_signing_state->_round1._id, &musig_signing_state->_round1);
    }

    // The signing flow is over: leave no secret behind
    explicit_bzero(musig_signing_state, sizeof(musig_signing_state_t));
}
