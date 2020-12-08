#include "handle_get_printable_amount.h"
#include "btchip_bcd.h"
#include <string.h>

int handle_get_printable_amount( get_printable_amount_parameters_t* params, btchip_altcoin_config_t *config) {
    params->printable_amount[0] = 0;
    if (params->amount_length > 8) {
        PRINTF("Amount is too big");
        return 0;
    }
    unsigned char amount[8];
    os_memset(amount, 0, 8);
    os_memcpy(amount + (8 - params->amount_length), params->amount, params->amount_length);
    unsigned char coin_name_length = strlen(config->name_short);
    os_memmove(params->printable_amount, config->name_short, coin_name_length);
    params->printable_amount[coin_name_length] = ' ';
    int res_length = btchip_convert_hex_amount_to_displayable_no_globals(amount, config->flags, (uint8_t *)params->printable_amount + coin_name_length + 1);
    params->printable_amount[res_length + coin_name_length + 1] = '\0';

    return 1;
}