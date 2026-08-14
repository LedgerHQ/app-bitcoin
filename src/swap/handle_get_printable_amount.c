#ifdef HAVE_SWAP

#include <string.h>

/* SDK headers */
#include "read.h"
#include "swap_lib_calls.h"

/* Local headers */
#include "display_utils.h"

#define MAX_NON_PRINTABLE_AMOUNT_LEN 8

void swap_handle_get_printable_amount(get_printable_amount_parameters_t *params) {
    params->printable_amount[0] = 0;
    if (params->amount_length > MAX_NON_PRINTABLE_AMOUNT_LEN) {
        PRINTF("Amount is too big");
        return;
    }
    unsigned char amount[MAX_NON_PRINTABLE_AMOUNT_LEN] = {0};
    /* Amount + ' ' + ticker */
    memcpy(amount + (MAX_NON_PRINTABLE_AMOUNT_LEN - params->amount_length),
           params->amount,
           params->amount_length);

    format_sats_amount(COIN_COINID_SHORT,
                       (uint64_t) (read_u64_be(amount, 0)),  // Cast prevents weird compilo bug
                       params->printable_amount);
}

#endif /* HAVE_SWAP */
