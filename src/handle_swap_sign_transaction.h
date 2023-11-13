#ifndef _HANDLE_SWAP_SIGN_TRANSACTION_H_
#define _HANDLE_SWAP_SIGN_TRANSACTION_H_

#include "swap_lib_calls.h"
#include "btchip_context.h"

bool copy_transaction_parameters(create_transaction_parameters_t* sign_transaction_params);

void handle_swap_sign_transaction(btchip_altcoin_config_t *config);

void __attribute__((noreturn)) finalize_exchange_sign_transaction(bool is_success);

#endif // _HANDLE_SWAP_SIGN_TRANSACTION_H_
