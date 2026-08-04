
#pragma once

#include <stdint.h>
#include <string.h>

/* SDK headers */
#include "bip32.h"
#include "cx.h"
#include "os.h"
#include "varint.h"
#include "write.h"

/* Local headers */
#include "constants.h"

/**
 * A serialized extended pubkey according to BIP32 specifications.
 * All the fields are represented as fixed-length arrays serialized in big-endian.
 */
typedef struct serialized_extended_pubkey_s {
    uint8_t version[4];
    uint8_t depth;
    uint8_t parent_fingerprint[4];
    uint8_t child_number[4];
    uint8_t chain_code[32];
    uint8_t compressed_pubkey[33];
} serialized_extended_pubkey_t;

typedef struct {
    serialized_extended_pubkey_t serialized_extended_pubkey;
    uint8_t checksum[4];
} serialized_extended_pubkey_check_t;

/**
 * Checks if the provided buffer is fully zeroed.
 *
 * It guarantees that the running time is constant for all the buffers of the same length,
 * as a protection against timing attacks.
 * However, it DOES leak the length of the buffer.
 *
 * @param[in] buffer       Pointer to the array.
 * @param[in] buffer_len   The number of bytes in the array.
 *
 * @return true if the buffer is entirely zeroed, false otherwise.
 */
static inline bool is_array_all_zeros(const uint8_t buffer[], size_t buffer_len) {
    uint8_t acc = 0;
    for (size_t i = 0; i < buffer_len; i++) {
        acc |= buffer[i];
    }
    return acc == 0;
}

/**
 * Generates the child extended public key, from a parent extended public key and non-hardened
 * index.
 *
 * @param[in]  parent
 *   Pointer to the extended serialized pubkey of the parent.
 * @param[in] index
 *   Index of the child to derive. It MUST be not hardened, that is, strictly less than 0x80000000.
 * @param[out] child
 *   Pointer to the output struct for the child's serialized pubkey. It can equal parent, which in
 * that case is overwritten.
 * @param[out] tweak
 *   If not NULL, pointer to a 32-byte array that will receive the 32-byte tweak used during the
 * child key derivation.
 *
 * @return 0 if success, a negative number on failure.
 *
 */
int bip32_CKDpub(const serialized_extended_pubkey_t *parent,
                 uint32_t index,
                 serialized_extended_pubkey_t *child,
                 uint8_t *tweak);

/**
 * Convenience wrapper for cx_hash_no_throw to add some data to an initialized hash context.
 *
 * @param[in] hash_context
 *   The context of the hash, which must already be initialized.
 * @param[in] in
 *   Pointer to the data to be added to the hash computation.
 * @param[in] in_len
 *   Size of the passed data.
 *
 * @return the return value of cx_hash_no_throw.
 */
static inline int crypto_hash_update(cx_hash_t *hash_context, const void *in, size_t in_len) {
    return cx_hash_no_throw(hash_context, 0, in, in_len, NULL, 0);
}

/**
 * Convenience wrapper for cx_hash_no_throw to compute the final hash, without adding any extra data
 * to the hash context.
 *
 * @param[in] hash_context
 *   The context of the hash, which must already be initialized.
 * @param[in] out
 *   Pointer to the output buffer for the result.
 * @param[in] out_len
 *   Size of output buffer, which must be large enough to contain the result.
 *
 * @return the return value of cx_hash_no_throw.
 */
static inline int crypto_hash_digest(cx_hash_t *hash_context, uint8_t *out, size_t out_len) {
    return cx_hash_no_throw(hash_context, CX_LAST, NULL, 0, out, out_len);
}

/**
 * Convenience wrapper for crypto_hash_update, updating a hash with an uint8_t.
 *
 * @param[in] hash_context
 *  The context of the hash, which must already be initialized.
 * @param[in] data
 *  The uint8_t to be added to the hash.
 *
 * @return the return value of cx_hash.
 */
static inline int crypto_hash_update_u8(cx_hash_t *hash_context, uint8_t data) {
    return crypto_hash_update(hash_context, &data, 1);
}

/**
 * Convenience wrapper for crypto_hash_update, updating a hash with an uint16_t,
 * encoded in big-endian.
 *
 * @param[in] hash_context
 *  The context of the hash, which must already be initialized.
 * @param[in] data
 *  The uint16_t to be added to the hash.
 *
 * @return the return value of cx_hash.
 */
static inline int crypto_hash_update_u16(cx_hash_t *hash_context, uint16_t data) {
    uint8_t buf[2];
    write_u16_be(buf, 0, data);
    return crypto_hash_update(hash_context, &buf, sizeof(buf));
}

/**
 * Convenience wrapper for crypto_hash_update, updating a hash with an uint64_t, serialized as a
 * variable length integer in bitcoin's format.
 *
 * @param[in] hash_context
 *  The context of the hash, which must already be initialized.
 * @param[in] data
 *  The uint64_t to be added to the hash as a bitcoin-style varint.
 *
 * @return the return value of cx_hash.
 */
static inline int crypto_hash_update_varint(cx_hash_t *hash_context, uint64_t data) {
    uint8_t buf[9];
    int len = varint_write(buf, 0, data);
    return crypto_hash_update(hash_context, &buf, len);
}

/**
 * Convenience wrapper for crypto_hash_update, updating a hash with an uint32_t,
 * encoded in big-endian.
 *
 * @param[in] hash_context
 *  The context of the hash, which must already be initialized.
 * @param[in] data
 *  The uint32_t to be added to the hash.
 *
 * @return the return value of cx_hash.
 */
static inline int crypto_hash_update_u32(cx_hash_t *hash_context, uint32_t data) {
    uint8_t buf[4];
    write_u32_be(buf, 0, data);
    return crypto_hash_update(hash_context, &buf, sizeof(buf));
}

/**
 * Computes RIPEMD160(in).
 *
 * @param[in] in
 *   Pointer to input data.
 * @param[in] inlen
 *   Length of input data.
 * @param[out] out
 *   Pointer to the 160-bit (20 bytes) output array.
 */
void crypto_ripemd160(const uint8_t *in, uint16_t inlen, uint8_t out[static 20]);

/**
 * Computes RIPEMD160(SHA256(in)).
 *
 * @param[in] in
 *   Pointer to input data.
 * @param[in] inlen
 *   Length of input data.
 * @param[out] out
 *   Pointer to the 160-bit (20 bytes) output array.
 */
void crypto_hash160(const uint8_t *in, uint16_t inlen, uint8_t out[static 20]);

/**
 * Computes the 33-bytes compressed public key from the uncompressed 65-bytes public key.
 *
 * @param[in] uncompressed_key
 *   Pointer to the uncompressed public key. The first byte must be 0x04, followed by 64 bytes
 * public key data.
 * @param[out] out
 *   Pointer to the output array, that must be 33 bytes long. The first byte of the output will be
 * 0x02 or 0x03. It is allowed to have out == uncompressed_key, and in that case the computation
 * will be done in-place. Otherwise, the input and output arrays MUST be non-overlapping.
 *
 * @return 0 on success, a negative number on failure.
 */
int crypto_get_compressed_pubkey(const uint8_t uncompressed_key[static 65], uint8_t out[static 33]);

/**
 * Computes the 65-bytes uncompressed public key from the compressed 33-bytes public key.
 *
 * @param[in] compressed_key
 *   Pointer to the compressed public key. The first byte must be 0x02 or 0x03, followed by 32
 * bytes.
 * @param[out] out
 *   Pointer to the output array, that must be 65 bytes long. The first byte of the output will be
 * 0x04. It is allowed to have out == compressed_key, and in that case the computation will be done
 * in-place. Otherwise, the input and output arrays MUST be non-overlapping.
 *
 * @return 0 on success, a negative number on failure.
 */
int crypto_get_uncompressed_pubkey(const uint8_t compressed_key[static 33], uint8_t out[static 65]);

/**
 * Computes the checksum as the first 4 bytes of the double sha256 hash of the input data.
 *
 * @param[in] in
 *   Pointer to the input data.
 * @param[in] in_len
 *   Length of the input data.
 * @param[out] out
 *   Pointer to the output buffer, which must contain at least 4 bytes.
 *
 */
void crypto_get_checksum(const uint8_t *in, uint16_t in_len, uint8_t out[static 4]);

/**
 * Gets the compressed pubkey and (optionally) the chain code at the given derivation path.
 *
 * @param[in]  bip32_path
 *   Pointer to 32-bit integer input buffer.
 * @param[in]  bip32_path_len
 *   Number of derivation steps.
 * @param[out]  pubkey
 *   A pointer to a 33-bytes buffer that will receive the compressed public key.
 * @param[out]  chaincode
 *   Either NULL, or a pointer to a 32-bytes buffer that will receive the chain code.
 *
 * @return true on success, false in case of error.
 */
cx_err_t crypto_get_compressed_pubkey_at_path(const uint32_t bip32_path[],
                                              uint8_t bip32_path_len,
                                              uint8_t pubkey[static 33],
                                              uint8_t chain_code[]);

/**
 * Computes the fingerprint of a compressed key as per BIP32; that is, the first 4 bytes of the
 * HASH160 of the given compressed pubkey, interpreted as a big-endian 32-bit unsigned integer.
 *
 * @param[in]  pub_key
 *   Pointer to 32-bit integer input buffer.
 *
 * @return the fingerprint of pub_key.
 */
uint32_t crypto_get_key_fingerprint(const uint8_t pub_key[static 33]);

/**
 * Computes the fingerprint of the master key as per BIP32.
 *
 * @return the fingerprint of the master key.
 */
uint32_t crypto_get_master_key_fingerprint();

/**
 * Computes extended pubkey at a given path, serialized as per BIP32.
 *
 * @param[in]  bip32_path
 *   Pointer to 32-bit array of BIP-32 derivation steps.
 * @param[in]  bip32_path_len
 *   Number of steps in the BIP32 derivation.
 * @param[in]  bip32_pubkey_version
 *   Version prefix to use for the pubkey.
 * @param[out] out_pubkey
 *   A pointer to a serialized_extended_pubkey_t.
 *
 * @return 0 on success, or -1 on error.
 */
cx_err_t get_extended_pubkey_at_path(const uint32_t bip32_path[],
                                     uint8_t bip32_path_len,
                                     uint32_t bip32_pubkey_version,
                                     serialized_extended_pubkey_t *out_pubkey);

/**
 * Derives the level-1 symmetric key at the given label using SLIP-0021.
 *
 * @param[in]  label
 *   Pointer to the label. The first byte of the label must be 0x00 to comply with SLIP-0021.
 * @param[in]  label_len
 *   Length of the label. It must be at most 32 bytes.
 * @param[out] key
 *   Pointer to a 32-byte output buffer that will contain the generated key.
 */
bool crypto_derive_symmetric_key(const char *label, size_t label_len, uint8_t key[static 32]);

/**
 * Encodes a 20-bytes hash in base58 with checksum, after prepending a version prefix.
 * If version < 256, it is prepended as 1 byte.
 * If 256 <= version < 65536, it is prepended in big-endian as 2 bytes.
 * Otherwise, it is prepended in big-endian as 4 bytes.
 *
 * @param[in]  in
 *   Pointer to the 20-bytes hash to encode.
 * @param[in]  version
 *   The 1-byte, 2-byte or 4-byte version prefix.
 * @param[out]  out
 *   The pointer to the output array.
 * @param[in]  out_len
 *   The length of the output array.
 *
 * @return the length of the encoded output on success, -1 on failure (that is, if the output
 *   would be longer than out_len).
 */
int base58_encode_address(const uint8_t in[20], uint32_t version, char *out, size_t out_len);

/**
 * Signs a SHA-256 hash using the ECDSA with deterministic nonce according to RFC6979; the signing
 * private key is the one derived at the given BIP-32 path. The signature is returned in the
 * conventional DER encoding.
 *
 * @param[in]  bip32_path
 *   Pointer to 32-bit array of BIP-32 derivation steps.
 * @param[in]  bip32_path_len
 *   Number of steps in the BIP32 derivation.
 * @param[in]  hash
 *   Pointer to a 32-byte SHA-256 hash digest.
 * @param[out]  pubkey
 *   Either NULL, or a pointer to a 33-bytes array that will receive the compressed pubkey
 * corresponding to the private key used for signing.
 * @param[out]  out
 *   The pointer to the output array to contain the signature, that must be of length
 * `MAX_DER_SIG_LEN`.
 * @param[out]  info
 *   Pointer to contain the `info` variable returned by `cx_ecdsa_sign`, or `NULL` if not needed.
 *
 * @return the length of the signature on success, or -1 in case of error.
 */
int crypto_ecdsa_sign_sha256_hash_with_key(const uint32_t bip32_path[],
                                           uint8_t bip32_path_len,
                                           const uint8_t hash[static 32],
                                           uint8_t *pubkey,
                                           uint8_t out[static MAX_DER_SIG_LEN],
                                           uint32_t *info);

// Constants defined in BIP-0341
extern const uint8_t BIP0341_taptweak_tag[8];
extern const uint8_t BIP0341_tapbranch_tag[9];
extern const uint8_t BIP0341_tapleaf_tag[7];

/**
 * Initializes the "tagged" SHA256 hash with the given tag, as defined by BIP-0340.
 *
 * @param[out]  hash_context
 *   Pointer to a sha256 hash context.
 * @param[in]  tag
 *   Pointer to an array containing the tag of the tagged hash.
 * @param[in]  tag_len
 *   Length of the tag.
 */
void crypto_tr_tagged_hash_init(cx_sha256_t *hash_context, const uint8_t *tag, uint16_t tag_len);

/**
 * Implementation of the lift_x procedure as defined by BIP-0340.
 *
 * @param[in]  x
 *   Pointer to a 32-byte array.
 * @param[out]  out
 *   Pointer to an array that will received the output as an uncompressed 65-bytes pubkey.
 *
 * @return 0 on success, -1 if x is not the x-coordinate of a point on the curve. On failure, the
 *   content of `out` is unspecified and must not be used.
 */
int crypto_tr_lift_x(const uint8_t x[static 32], uint8_t out[static 65]);

/**
 * A tagged hash as defined in BIP-0340.
 *
 * @param[in]  tag
 *   Pointer to an array containing the tag of the tagged hash.
 * @param[in]  tag_len
 *   Length of the tag.
 * @param[in]  data
 *   Pointer to an array of data.
 * @param[in]  data_len
 *   Length of the array pointed by `data`.
 * @param[in]  data2
 *   If NULL, ignored. If not null, a pointer to an array of data; the tagged hash for the
 * concatenation of `data` and `data2` is computed.
 * @param[in]  data2_len
 *   If `data2` is NULL, ignored. Otherwise, the length the array pointed by `data2`.
 * @param[out]  out
 *   Pointer to a 32-byte array that will receive the result.
 */
void crypto_tr_tagged_hash(const uint8_t *tag,
                           uint16_t tag_len,
                           const uint8_t *data,
                           uint16_t data_len,
                           const uint8_t *data2,
                           uint16_t data2_len,
                           uint8_t out[static CX_SHA256_SIZE]);

/**
 * Initializes the "tagged" SHA256 hash with tag "TapLeaf", used for tapscript leaves.
 *
 * @param[out]  hash_context
 *   Pointer to a sha256 hash context.
 */
void crypto_tr_tapleaf_hash_init(cx_sha256_t *hash_context);

/**
 * Computes the tagged hash with tagged hash of a tapbranch, given the hashes for the children.
 *
 * @param[in]  left_h
 *   The hash of the left tapbranch/tapleaf.
 * @param[in]  right_h
 *   The hash of the right tapbranch/tapleaf.
 * @param[out]  out
 *   The combined hash for the tapbranch.
 */
void crypto_tr_combine_taptree_hashes(const uint8_t left_h[static 32],
                                      const uint8_t right_h[static 32],
                                      uint8_t out[static 32]);

/**
 * Computes the tweaked public key from a BIP340 public key array.
 * Implementation of taproot_tweak_pubkey of BIP341 with `h` set to the empty byte string.
 *
 * @param[in]  pubkey
 *   Pointer to the 32-byte to be used as public key.
 * @param[in]  h
 *   Pointer to the tweaking data.
 * @param[in]  h_len
 *   Length of `h`.
 * @param[out]  y_parity
 *   Pointer to a variable that will be set to 0/1 according to the parity of th y-coordinate of the
 * final tweaked pubkey.
 * @param[out]  out
 *  Pointer to the a 32-byte array that will contain the x coordinate of the tweaked key.
 *
 * @return 0 on success, or -1 in case of error.
 */
int crypto_tr_tweak_pubkey(const uint8_t pubkey[static 32],
                           const uint8_t *h,
                           size_t h_len,
                           uint8_t *y_parity,
                           uint8_t out[static 32]);

/**
 * Computes the tweaked secret key from a BIP340 secret key.
 * Implementation of taproot_tweak_seckey of BIP341 with `h` set to the empty byte string.
 *
 * @param[in] seckey
 *   Pointer to the 32-byte containing the secret key.
 * @param[out]  h
 *   Pointer to the tweaking data.
 * @param[out]  h_len
 *   Length of `h`.
 * @param[out]  out
 *  Pointer to the a 32-byte array that will contain the tweaked secret key.
 *
 * @return 0 on success, or -1 in case of error.
 */
int crypto_tr_tweak_seckey(const uint8_t seckey[static 32],
                           const uint8_t *h,
                           size_t h_len,
                           uint8_t out[static 32]);

/**
 * Converts cx_err_t to 2-bytes SW and prints out debug information.
 *
 * @param[in] error
 *  Cryptographic error code
 *
 * @return SW (SW_OK on success, other value on error).
 */
uint16_t cx_err_to_sw(cx_err_t error);
