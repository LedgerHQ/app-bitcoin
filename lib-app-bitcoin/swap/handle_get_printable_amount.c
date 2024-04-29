#include "read.h"

#include "display_utils.h"
#include "handle_get_printable_amount.h"

void swap_handle_get_printable_amount(
    get_printable_amount_parameters_t *params) {
  params->printable_amount[0] = 0;
  if (params->amount_length > 8) {
    PRINTF("Amount is too big");
    return;
  }
  unsigned char amount[8];
  memset(amount, 0, 8);
  memcpy(amount + (8 - params->amount_length), params->amount,
         params->amount_length);

  format_sats_amount(
      COIN_COINID_SHORT,
      (uint64_t)(read_u64_be(amount, 0)), // Cast prevents weird compilo bug
      params->printable_amount);
  return;
}