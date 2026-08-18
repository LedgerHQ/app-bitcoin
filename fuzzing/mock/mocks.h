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


#define FUZZ_TAIL_SLOT_SIZE  64
/* 32, matching the 2048-byte slot region the manifest sizes tail_budget on.
 * At 16 the mutator could only address tail bytes [0,1024) while all three tapes
 * read well past that, so half the tail was reachable by no app operator. */
#define FUZZ_TAIL_N_SLOTS    32
#define FUZZ_TAIL_FAULT_SIZE 4

#define PSBT_ENTROPY_SIZE               16
extern uint8_t psbt_entropy[PSBT_ENTROPY_SIZE];


/* Fault knobs (last 4 tail bytes): fault[0]&0x07 = kind (BTC_FAULT_*),
 * fault[1] = target index, fault[2..3] = per-kind parameters. */
/* Only faults that corrupt a host reply *after* its commitment was computed belong
 * here. Mutating a scenario field before the Merkle trees are built leaves every
 * length, leaf count, proof and root self-consistent, which malforms nothing. */
#define BTC_FAULT_CLEAN           0
#define BTC_FAULT_CONT_TRUNCATE   6
#define BTC_FAULT_CONT_FLIP       7

extern uint8_t btc_fault_kind;
extern uint8_t btc_fault_target;
extern uint8_t btc_fault_param[2];
