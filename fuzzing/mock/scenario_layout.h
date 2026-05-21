#pragma once

/*
 * Single source of truth for the Absolution input prefix layout shared
 * between the C harness (fuzz_dispatcher.c, mocks.c) and the Python seed
 * generator (generate-seed-corpus.py).
 *
 * Offsets are relative to the start of the generated Absolution prefix
 * (the byte stream consumed by sample_invariant(), not raw in-memory
 * globals order).  The Python generator parses this file with a simple
 * #define regex; see the `mock/scenario_layout.h` section in
 * $BOLOS_SDK/fuzzing/docs/APP_CONTRACT.md.
 */

/* Current generated prefix size — updated after Absolution rebuild.
 * mock_continuation_data is zeroed; builders read from the fuzz tail. */
#define SCEN_PREFIX_SIZE                469

/*
 * psbt_entropy: the 16-byte framework control header.
 * SCEN_CTRL_OFF / SCEN_CTRL_LEN (auto-updated by the pipeline with
 * --ctrl-name psbt_entropy) must always match SCEN_ENTROPY_OFF / LEN.
 */
#define SCEN_ENTROPY_OFF                121
#define SCEN_ENTROPY_LEN                16
#define SCEN_CTRL_OFF                   121
#define SCEN_CTRL_LEN                   16

/* Absolution-driven global offsets (auto-updated by update-scenario-layout.py). */
#define SCEN_G_SWAP_OFF                 3
#define SCEN_UI_APPROVE_OFF             141
#define SCEN_G_CALLED_FROM_SWAP_OFF     1

/* Tail-based slot layout (fuzz_tail_ptr).  Dense 64-byte builder slots
 * start at offset 0.  The last 4 bytes of the tail carry fault knobs. */
#define SCEN_TAIL_SLOT_SIZE             64
#define SCEN_TAIL_N_SLOTS               16
#define SCEN_TAIL_FAULT_SIZE            4
