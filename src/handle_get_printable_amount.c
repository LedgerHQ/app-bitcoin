#include "handle_get_printable_amount.h"
#include "btchip_bcd.h"
#include <string.h>

int handle_get_printable_amount( get_printable_amount_parameters_t* params) {
    params->printable_amount[0] = 0;
    if (params->amount_length > 8) {
        PRINTF("Amount is too big");
        return 0;
    }
    unsigned char amount[8];
    os_memset(amount, 0, 8);
    os_memcpy(amount + (8 - params->amount_length), params->amount, params->amount_length);
    unsigned char coin_name_length = strlen(COIN_COINID_SHORT);
    os_memmove(params->printable_amount, COIN_COINID_SHORT, coin_name_length);
    params->printable_amount[coin_name_length] = ' ';
    int res_length = btchip_convert_hex_amount_to_displayable_no_globals(amount, 0, (uint8_t *)params->printable_amount + coin_name_length + 1);
    params->printable_amount[res_length + coin_name_length + 1] = '\0';

    return 1;
}