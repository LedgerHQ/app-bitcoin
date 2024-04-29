#include "filesystem_tx.h"
#include "ledger_assert.h"
#include "read.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "./display_utils.h"

// Division and modulus operators over uint64_t causes the inclusion of the
// __udivmoddi4 and other library functions that occupy more than 400 bytes.
// Since performance is not critical and division by 10 is sufficient, we avoid
// it with a binary search instead.
static uint64_t div10(uint64_t n) {
  if (n < 10)
    return 0; // special case needed to make sure that n - 10 is safe

  // Since low, mid and high are always <= UINT64_MAX / 10, there is no risk of
  // overflow
  uint64_t low = 0;
  uint64_t high = UINT64_MAX / 10;

  while (true) {
    uint64_t mid = (low + high) / 2;

    // the result equals mid if and only if mid * 10 <= n < mid * 10 + 10
    // care is taken to make sure overflows and underflows are impossible
    if (mid * 10 > n - 10 && n >= mid * 10) {
      return mid;
    } else if (n < mid * 10) {
      high = mid - 1;
    } else /* n >= 10 * mid + 10 */ {
      low = mid + 1;
    }
  }
}

static uint64_t div100000000(uint64_t n) {
  uint64_t res = n;
  for (int i = 0; i < 8; i++)
    res = div10(res);
  return res;
}

static size_t n_digits(uint64_t number) {
  size_t count = 0;
  do {
    count++;

    // HACK: avoid __udivmoddi4
    // number /= 10;

    number = div10(number);
  } while (number != 0);
  return count;
}

void format_sats_amount(const char *coin_name, uint64_t amount,
                        char out[static MAX_AMOUNT_LENGTH + 1]) {
  size_t coin_name_len = strlen(coin_name);
  strncpy(out, coin_name, MAX_AMOUNT_LENGTH + 1);
  out[coin_name_len] = ' ';

  char *amount_str = out + coin_name_len + 1;

  // HACK: avoid __udivmoddi4
  // uint64_t integral_part = amount / 100000000;
  // uint32_t fractional_part = (uint32_t) (amount % 100000000);
  uint64_t integral_part = div100000000(amount);
  uint32_t fractional_part = (uint32_t)(amount - integral_part * 100000000);

  // format the integral part, starting from the least significant digit
  size_t integral_part_digit_count = n_digits(integral_part);
  for (unsigned int i = 0; i < integral_part_digit_count; i++) {
    // HACK: avoid __udivmoddi4
    // amount_str[integral_part_digit_count - 1 - i] = '0' + (integral_part %
    // 10); integral_part /= 10;

    uint64_t tmp_quotient = div10(integral_part);
    char tmp_remainder = (char)(integral_part - 10 * tmp_quotient);
    amount_str[integral_part_digit_count - 1 - i] = '0' + tmp_remainder;
    integral_part = tmp_quotient;
  }

  if (fractional_part == 0) {
    amount_str[integral_part_digit_count] = '\0';
  } else {
    // format the fractional part (exactly 8 digits, possibly with trailing
    // zeros)
    amount_str[integral_part_digit_count] = '.';
    char *fract_part_str = amount_str + integral_part_digit_count + 1;
    snprintf(fract_part_str, 8 + 1, "%08u", fractional_part);

    // drop trailing zeros
    for (int i = 7; i > 0 && fract_part_str[i] == '0'; i--) {
      fract_part_str[i] = '\0';
    }
  }
}

unsigned char format_path(const unsigned char *bip32Path, char *out,
                          unsigned char max_out_len) {

  unsigned char bip32PathLength;
  unsigned char i, offset;
  unsigned int current_level;
  bool hardened;

  bip32PathLength = bip32Path[0];

  LEDGER_ASSERT(bip32PathLength <= MAX_BIP32_PATH, "Wrong path len: %d",
                bip32PathLength);

  bip32Path++;
  out[0] = ' ';
  offset = 1;
  for (i = 0; i < bip32PathLength; i++) {
    current_level = read_u32_be(bip32Path, 0);
    hardened = (bool)(current_level & 0x80000000);
    if (hardened) {
      // remove hardening flag
      current_level ^= 0x80000000;
    }
    bip32Path += 4;
    snprintf(out + offset, max_out_len - offset, "%u", current_level);
    offset = strnlen(out, max_out_len);
    LEDGER_ASSERT(offset < max_out_len - 2, "OVERFLOW");
    if (hardened)
      out[offset++] = '\'';

    out[offset++] = '/';
    out[offset] = '\0';
  }
  // remove last '/'
  out[offset - 1] = '\0';

  return offset - 1;
}
