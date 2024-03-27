#include "handle_get_printable_amount.h"
#include "bcd.h"
#include <string.h>

void swap_handle_get_printable_amount(get_printable_amount_parameters_t* params) {
    params->printable_amount[0] = 0;
    if (params->amount_length > 8) {
        PRINTF("Amount is too big");
        return;
    }
    unsigned char amount[8];
    memset(amount, 0, 8);
    memcpy(amount + (8 - params->amount_length), params->amount, params->amount_length);
    unsigned char coin_name_length = strlen(COIN_COINID_SHORT);
    memmove(params->printable_amount, COIN_COINID_SHORT, coin_name_length);
    params->printable_amount[coin_name_length] = ' ';
    int res_length = convert_hex_amount_to_displayable_no_globals(amount, COIN_FLAGS, (uint8_t *)params->printable_amount + coin_name_length + 1);
    params->printable_amount[res_length + coin_name_length + 1] = '\0';

    return;
}