/**
 * Tiny base58check helper for BIP32 serialized extended pubkeys, used
 * by unit tests so test vectors can be expressed as their on-the-wire
 * xpub string (e.g. "xpub661MyMwAqRbc...") rather than as 78-byte
 * hex blobs.
 *
 * Both mainnet (xpub/ypub/zpub) and testnet (tpub/upub/vpub) version
 * prefixes are accepted: the four version bytes are returned verbatim
 * in the decoded struct.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto.h" /* serialized_extended_pubkey_t */

/* Longest possible base58check encoding of a 78-byte payload + 4-byte
 * checksum. 82 bytes of binary fits in 112 base58 characters. */
#define XPUB_BASE58_MAX_LEN 112

/**
 * Decodes a base58check-encoded BIP32 extended pubkey.
 *
 * @param[in]  str   NUL-terminated base58check string.
 * @param[out] out   Filled with the 78 decoded bytes on success.
 *
 * @return true on success (decoded length is exactly 82 bytes and the
 *   embedded 4-byte double-SHA256 checksum matches); false otherwise.
 */
bool xpub_from_base58(const char *str, serialized_extended_pubkey_t *out);

/**
 * Encodes a BIP32 extended pubkey as a base58check string.
 *
 * @param[in]  in       The 78-byte struct to encode.
 * @param[out] out      Output buffer for the NUL-terminated string.
 * @param[in]  out_len  Capacity of @p out, in bytes (must be at least
 *                      XPUB_BASE58_MAX_LEN + 1).
 *
 * @return Length of the encoded string (excluding NUL), or -1 on error.
 */
int xpub_to_base58(const serialized_extended_pubkey_t *in, char *out,
                   size_t out_len);
