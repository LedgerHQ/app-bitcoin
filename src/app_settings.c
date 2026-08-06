#include "app_settings.h"

#ifndef SKIP_FOR_CMOCKA
// NVRAM storage for app settings. Initialized to all zeros by default.
// Reset on application or OS update.
const app_settings_t N_app_settings_real;
#else
uint8_t mock_allow_nondefault_sighash = 0;
#endif
