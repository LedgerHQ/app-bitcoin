#pragma once

#ifdef HAVE_SWAP

#include <stdbool.h>

void __attribute__((noreturn)) finalize_exchange_sign_transaction(bool is_success);

#endif /* HAVE_SWAP */
