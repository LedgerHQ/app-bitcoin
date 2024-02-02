#include "handle_swap_sign_transaction.h"
#include "os_io_seproxyhal.h"
#include "display_variables.h"
#include "context.h"
#include "usbd_core.h"
#include "ux.h"

#ifdef HAVE_NBGL
#include "nbgl_use_case.h"
#endif

#include "swap.h"

// Save the BSS address where we will write the return value when finished
static uint8_t *G_swap_sign_return_value_address;

bool swap_copy_transaction_parameters(create_transaction_parameters_t* params) {
    PRINTF("Inside swap_copy_transaction_parameters\n");

    // Ensure no extraid
    if (params->destination_address_extra_id == NULL) {
        PRINTF("destination_address_extra_id expected\n");
        return false;
    } else if (params->destination_address_extra_id[0] != '\0') {
        PRINTF("destination_address_extra_id expected empty, not '%s'\n",
               params->destination_address_extra_id);
        return false;
    }

    // We need this "trick" as the input data position can overlap with app globals
    // and also because we want to memset the whole bss segment as it is not done
    // when an app is called as a lib.
    // This is necessary as many part of the code expect bss variables to
    // initialized at 0.
    swap_data_t swap_validated;
    memset(&swap_validated, 0, sizeof(swap_validated));

    // Save recipient
    strlcpy(swap_validated.destination_address,
            params->destination_address, 
            sizeof(swap_validated.destination_address));
    if (swap_validated.destination_address[sizeof(swap_validated.destination_address) - 1] != '\0') {
        return false;
    }

    // store amount as big endian in 8 bytes, so the passed data should be alligned to right
    // input {0xEE, 0x00, 0xFF} should be stored like {0x00, 0x00, 0x00, 0x00, 0x00, 0xEE, 0x00, 0xFF}
    memcpy(swap_validated.amount + 8 - params->amount_length, params->amount, params->amount_length);
    memcpy(swap_validated.fees + 8 - params->fee_amount_length, params->fee_amount, params->fee_amount_length);

    // Save amount and fees
//    swap_str_to_u64(params->amount, params->amount_length, &swap_validated.amount);
//    swap_str_to_u64(params->fee_amount, params->fee_amount_length, &swap_validated.fees);
//
    swap_validated.initialized = true;

    // Full reset the global variables
    os_explicit_zero_BSS_segment();

    // Keep the address at which we'll reply the signing status
    G_swap_sign_return_value_address = &params->result;


    // Copy from stack back to global data segment
    memcpy(&vars.swap_data, &swap_validated, sizeof(swap_validated));
    swap_validated.initialized = true;
    return true;
}

void __attribute__((noreturn)) swap_finalize_exchange_sign_transaction(bool is_success) {
    *G_swap_sign_return_value_address = is_success;
    os_lib_end();
}
