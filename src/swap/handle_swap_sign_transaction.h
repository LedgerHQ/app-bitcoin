#ifndef _HANDLE_SWAP_SIGN_TRANSACTION_H_
#define _HANDLE_SWAP_SIGN_TRANSACTION_H_

#include "swap_lib_calls.h"
#include "context.h"

bool swap_copy_transaction_parameters(create_transaction_parameters_t* sign_transaction_params);

void swap_handle_swap_sign_transaction(void);

void __attribute__((noreturn)) swap_finalize_exchange_sign_transaction(bool is_success);

#endif // _HANDLE_SWAP_SIGN_TRANSACTION_H_
