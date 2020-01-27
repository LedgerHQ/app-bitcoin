#include "handle_check_address.h"
#include "os.h"
#include "btchip_helpers.h"

void handle_check_address(check_address_parameters_t* params) {
    PRINTF("Insied handle_check_address\n");
    params->result = 0;
    if (params->address_to_check == 0) {
        PRINTF("Address to check == 0\n");
        return;
    }
    PRINTF("Address format = %d\n", params->address_parameters[0]);
    PRINTF("Path = %.*H\n", params->address_parameters_length, params->address_parameters);
    
    G_io_apdu_buffer[67 + G_io_apdu_buffer[66]] = 0;
    if (os_memcmp(G_io_apdu_buffer + 67, params->address_to_check, G_io_apdu_buffer[66]) == 0)
        params->result = 1;
}