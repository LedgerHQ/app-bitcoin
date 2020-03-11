#ifndef __HEADLESS_STORAGE_H__

#define __HEADLESS_STORAGE_H__

#include "btchip_internal.h"

#define N_storage (*(volatile internalStorage_t*) PIC(&N_storage_real))

typedef struct internalStorage_t {
  uint8_t initialized;
  uint8_t headless;
  cx_ecfp_public_key_t headlessValidationKey;
} internalStorage_t;

extern const internalStorage_t N_storage_real;

#endif

