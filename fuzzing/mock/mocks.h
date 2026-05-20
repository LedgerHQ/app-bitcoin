#pragma once

#include "cx_errors.h"
#include "ox_ec.h"
#include "os_task.h"
#include <string.h>
#include <setjmp.h>
#include "exceptions.h"
#include <stdio.h>
#include <stdint.h>

#include "fuzz_defs.h"

extern try_context_t fuzz_exit_jump_ctx;

/* mock_continuation_data is zeroed via zero-symbols.txt; builders read
 * slot data from fuzz_tail_ptr instead (see FUZZ_TAIL_SLOT_*). */
#define MOCK_CONTINUATION_SLOTS         16
#define MOCK_CONTINUATION_PAYLOAD_SIZE  200
extern unsigned char mock_continuation_data[MOCK_CONTINUATION_SLOTS][MOCK_CONTINUATION_PAYLOAD_SIZE];

#define FUZZ_TAIL_SLOT_SIZE  64
#define FUZZ_TAIL_N_SLOTS    16
#define FUZZ_TAIL_FAULT_SIZE 4

#define PSBT_ENTROPY_SIZE               16
extern uint8_t psbt_entropy[PSBT_ENTROPY_SIZE];

#define FUZZ_CTRL_SIZE                  PSBT_ENTROPY_SIZE
#define fuzz_ctrl                       psbt_entropy

extern const uint8_t *fuzz_tail_ptr;
extern size_t fuzz_tail_len;

/*
 * Fault knobs: the last 4 bytes of the fuzz tail control fault injection.
 * Slot data occupies tail[0..N_SLOTS*SLOT_SIZE-1]; the fault region is
 * tail[len-4..len-1].  Seeds set fault_kind=0 (clean); libFuzzer discovers
 * that flipping the last 4 bytes activates different fault paths.
 *
 *   fault[0] & 0x07  = kind (see BTC_FAULT_* below)
 *   fault[1]         = target index (round for cont faults, input for builder)
 *   fault[2..3]      = per-kind parameters
 */
#define BTC_FAULT_CLEAN           0
#define BTC_FAULT_WRONG_HMAC      1
#define BTC_FAULT_SIGHASH_OVR     2
#define BTC_FAULT_AMOUNT_XOR      3
#define BTC_FAULT_SEQ_LOCK        4
#define BTC_FAULT_OUTPUT_AMT      5
#define BTC_FAULT_CONT_TRUNCATE   6
#define BTC_FAULT_CONT_FLIP       7

extern uint8_t btc_fault_kind;
extern uint8_t btc_fault_target;
extern uint8_t btc_fault_param[2];

uint8_t *get_fuzz_for_round(int round);
