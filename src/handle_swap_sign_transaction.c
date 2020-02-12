#include "handle_swap_sign_transaction.h"
#include "btchip_public_ram_variables.h"
#include "btchip_context.h"
#include "usbd_core.h"

void handle_swap_sign_transaction(create_transaction_parameters_t* get_printable_amount_params, btchip_altcoin_config_t *config) {
    G_coin_config = config;
    btchip_context_init();
    PRINTF("I am back from btchip_context_init\n");
    USB_power(0);
    USB_power(1);
    PRINTF("USB power ON/OFF\n");
#ifdef TARGET_NANOX
    // grab the current plane mode setting
    G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
#endif // TARGET_NANOX
#ifdef HAVE_BLE
    BLE_power(0, NULL);
    BLE_power(1, "Nano X");
#endif // HAVE_BLE
    app_main();
}