# Bitcoin Fuzzing

This app integrates the fuzzing framework shipped with `ledger-secure-sdk`.
It uses the SDK's framework-driven entry
(`fuzz_harness_entry`) for APDU routing — the Bitcoin-specific pieces are
per-lane weighted `fuzz_commands[]` maps (via the SDK's
`FUZZ_PICK_COMMAND_RAW` / `FUZZ_PICK_COMMAND_STRUCTURED` override hooks),
app-side `fuzz_app_reset` / `fuzz_app_dispatch` callbacks, and a
continuation-host model required because several handlers pull extra data
through `os_io_rx_evt()`.

## Run it

See the [SDK Fuzzing Framework documentation](https://ledgerhq.github.io/ledger-secure-sdk/)
for full campaign and coverage instructions. Quick start from the dev container:

```bash
export BOLOS_SDK=/opt/flex-secure-sdk
"$BOLOS_SDK"/fuzzing/scripts/app-campaign.sh --app-dir "$(pwd)" bitcoin-run
```

- **`bitcoin-run`** is the campaign name (optional); outputs go to
  `.fuzz-artifacts/bitcoin-run/` under the app root. Omit for a UTC timestamp.
- Defaults: **`FUZZ_TIME=90`**, **`WORKERS=min(2, nproc)`**.
- To carry a prior run's corpus forward, promote it with
  `corpus.py promote <run>/targets/fuzz_app/corpus fuzzing/base-corpus.zip`; it
  then loads on every later run and its `.compat-key` is checked against the build.

The promoted seed corpus at `fuzzing/base-corpus.zip` (with its
`fuzzing/base-corpus.compat-key` sidecar) is folded into the bootstrap corpus
automatically by `app-campaign.sh` when it is compatible. Set
**`BASE_CORPUS_ZIP=`** to skip it if the checked-in corpus is stale for your
layout.

## Single harness

Bitcoin builds one fuzzing harness configuration. Two small fuzz-only repairs
are gated behind `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`: a wallet-policy
repeated-pubkey bypass (the crypto mock returns a constant pubkey) and a relaxed
cross-chain swap output-count check (so the OP_RETURN parser stays reachable).
UI confirmations are auto-approved separately via the app's own
`HAVE_AUTOAPPROVE_FOR_PERF_TESTS` flag (`display.c`).
MuSig signing runs against the SDK crypto mock, so its consistency checks reject
the mocked values early; descriptor parsing is still fully exercised.

## What the harness actually does

The input still has the normal shape:

```text
[ Absolution prefix | tail ]
```

The tail begins with the framework's 4 control bytes (lane, command, `P1`,
`P2`), followed by Bitcoin's own 16-byte header — the builder entropy
`psbt_entropy`, declared to the framework as `FUZZ_APP_HEADER_LEN` and copied
out of the input in `fuzz_entry()`. The APDU payload starts after it, so
`fuzz_tail_ptr[0]` is a stable base for the builders.

Bitcoin overrides only the raw-lane command picker, so each lane draws from its
own weighted map (see `harness/fuzz_dispatcher.c`):

```
#define FUZZ_PICK_COMMAND_RAW(data, size) \
    (&btc_raw_commands[(data)[1] % btc_raw_n_commands])
```

The structured lane keeps the framework default over `fuzz_commands[]`.
`fuzz_app_dispatch()` calls `fuzz_use_structured_lane()` to decide whether to
synthesise a structured payload — the framework sets the lane before
`fuzz_app_reset()` runs, so the app tracks nothing itself.

The prefix owns app state; the input owns routing and almost all structured
builder content:

- `G_swap_state` is driven directly by Absolution (domain-constrained).
- Continuation replies are served by the semantic host from the scenario
  built for the current iteration (not prefix-driven).
- Control byte 0 decides raw vs structured lane, byte 1 picks the command slot.
- `psbt_entropy[2]` co-selects the `SIGN_PSBT` subtype and the wallet
  descriptor template; in both cases it is combined with a payload slot (below),
  so header and payload share the choice.
- The tail's dense slots carry the values the builders materialize into APDUs:
  PSBT amounts / sequences / locktime / tx version / counts, wallet template
  and address controls, message length / path bits, and the fault knobs.
- `fuzz_mock_ui_reject`, `fuzz_mock_nbgl_reject` are Absolution-driven control
  globals (see `invariants/domain-overrides.txt`).

### Tail layout

Dense 64-byte builder slots occupy `fuzz_tail[0..N_SLOTS*64-1]`.
The last 4 bytes of the tail carry fault knobs:

| Offset (from end) | Field | Description |
|---:|---|---|
| `-4` | `fault[0] & 0x07` | Fault kind (see `BTC_FAULT_*` in `mocks.h`) |
| `-3` | `fault[1]` | Target index (round for cont faults, input for builder) |
| `-2` | `fault[2]` | Parameter 0 |
| `-1` | `fault[3]` | Parameter 1 |

| Kind | Name | Effect | Site |
|---:|---|---|---|
| 0 | `CLEAN` | No fault (default for seeds) | — |
| 1 | `WRONG_HMAC` | Corrupt wallet HMAC after tree sealed | `psbt_model.c` |
| 2 | `SIGHASH_OVR` | Override sighash on target input | `psbt_model.c` |
| 3 | `AMOUNT_XOR` | XOR target input amount | `psbt_model.c` |
| 4 | `SEQ_LOCK` | Set conflicting sequence/locktime | `psbt_model.c` |
| 5 | `OUTPUT_AMT` | Set output amount to 0xFFFFFFFFFF | `psbt_model.c` |
| 6 | `CONT_TRUNCATE` | Truncate targeted continuation reply | `fuzz_dispatcher.c` |
| 7 | `CONT_FLIP` | Flip bytes in targeted continuation reply | `fuzz_dispatcher.c` |

Seeds set `fault[0]=0` (clean).  libFuzzer discovers that mutating the
last 4 bytes activates different fault paths.

### Field-aware custom mutator

For structured inputs, ~30% of mutations apply a domain-aware operation
(boundary amounts, special sequences/sighash, slot swap/zero, fault knob
mutation) on top of the generic split mutator.

## Raw vs structured lanes

The framework decides the lane from the input's first byte against
`FUZZ_STRUCTURED_LANE_THRESHOLD`.  Bitcoin then draws from a lane-specific
weighted command map so the fuzzer stops wasting iterations on commands
that are dead-on-arrival in the wrong lane.

### Raw lane (`btc_raw_commands[]`, 4 slots)

Commands that make sense with arbitrary `data[]` bytes as the APDU:

| Slots | Command | Share |
|---:|---|---:|
| 3 | `GET_EXTENDED_PUBKEY` | 75% |
| 1 | `GET_MASTER_FINGERPRINT` | 25% |

### Structured lane (`fuzz_commands[]`, 16 slots)

Commands that need continuation traffic or semantic construction.  Payload
bytes are synthesised by `fuzz_app_dispatch` from the restored state + builder
entropy.  `SIGN_PSBT` carries the bulk of the budget; its internal subtype
(default / registered / rawtx / musig round 1 & 2) is decoded from
`(slot0[62] + psbt_entropy[2]) & 0x0F`.

| Slots | Command | Share |
|---:|---|---:|
| 8 | `SIGN_PSBT` | 50% |
| 2 | `REGISTER_WALLET` | 12.5% |
| 2 | `GET_WALLET_ADDRESS` | 12.5% |
| 2 | `SIGN_MESSAGE` | 12.5% |
| 1 | `FUZZ_INS_SWAP_CHECK` (0xF1) | 6.25% |
| 1 | `FUZZ_INS_SWAP_HELPERS` (0xF2) | 6.25% |

### SIGN_PSBT subtype map (`(slot0[62] + psbt_entropy[2]) & 0x0F`, 16 slots)

| Slots | Subtype | Share |
|---:|---|---:|
| 6 | default | 37.5% |
| 4 | registered | 25% |
| 4 | rawtx | 25% |
| 1 | musig round 1 | 6.25% |
| 1 | musig round 2 | 6.25% |

Decoded by `pm_decode_subtype_slot()` (`mock/psbt_model.c`); the tail slot and
the prefix byte both have per-iteration leverage over which PSBT scenario the
builder emits.

## Descriptor templates

`mock/wallet_model.c` holds a descriptor catalog selected per iteration from
`psbt_entropy[2] ^ slot0[template-seed]`.  Row order is append-only because
`generate-seed-corpus.py` and disruption tests reference rows by index.
Every row uses the V2 key-expression suffix (`@N/**`) when needed; the
builder auto-promotes V1 → V2 when the descriptor exceeds the V1 length
cap.

| Rows | Group | Purpose |
|---:|---|---|
|  0-3 | Single-key simple | `wpkh` / `pkh` / `sh(wpkh)` / `tr` — canonical address paths |
|  4-7 | Multisig | `wsh(multi)`, `wsh(sortedmulti)`, `tr(A,pk(B))`, `sh(multi)` |
|  8-18 | Miniscript fragments | `and_v`, `or_b`, `or_i`, `andor`, `multi_a`, `sortedmulti_a`, `thresh`, `older`/`after`, hash-preimage locks |
| 19-28 | Wrapper-focused | `or_d`, `and_b`, `t:`, `dv:`, `and_n`, `u:`, `l:` on nested fragments |
| 29-41 | Token-focused | `c:pk_k`, `c:pk_h`, `0`/`1` branches, `n:`/`j:`/`l:`/`u:` on bare `pk`, `hash160`/`ripemd160`/`hash256` |
| 42-51 | Mixed / multipath | `sh(wsh(...))` combos, `<a;b>/*` multipath descriptors |
| 52-55 | MuSig | `musig(a,b)`, `musig(a,b,c)`, MuSig + tapscript combinations |

Per-key derivation path is `[00000000/<purpose>'/<BIP44_COIN_TYPE>'/<keyidx>']` with
the purpose drawn from the template's `purposes[]` array, so each `@N`
resolves to a distinct xpub.

## Continuation host flow

Several handlers (`sign_psbt`, `register_wallet`, `sign_message`, …) pull
extra bytes through `os_io_rx_evt()` mid-dispatch. The fuzz harness owns a
single-host chain that serves those rounds off the pre-built semantic
state:

```
handler → os_io_rx_evt (mock/fuzz_os_io_rx_evt.c)
        → fuzz_continuation_host->handle_ccmd
        → btc_handle_ccmd (harness/fuzz_dispatcher.c)
        → mock_dispatcher_handle_ccmd (unit-tests/libs/mock_dispatcher.c)
        → wraps reply in the 6-byte SEPH envelope → returned to handler
```

Steps:

1. `fuzz_app_reset` zeros `fuzz_continuation_idx` and deactivates the host
   so raw-lane iterations never feed continuation replies.
2. Structured-lane builders call `btc_activate_host()` after populating
   `g_btc_host` with the preimages and Merkle trees the scenario needs.
   That host is the app's own unit-test `mock_dispatcher`, not a second
   implementation: same four client commands, the same Merkle code from
   `src/common/merkle.c`, and the same `cx_hash_sha256`.
3. Each `os_io_rx_evt` tick increments `fuzz_continuation_idx`. When the
   running round matches `btc_fault_target` and `btc_fault_kind` is
   `CONT_TRUNCATE` or `CONT_FLIP`, `btc_handle_ccmd` mutates that one
   reply (see the fault knob table above). All other rounds return the
   protocol-correct reply.
4. After `FUZZ_MAX_CONTINUATIONS` rounds the mock returns the canonical
   empty frame, which causes the handler to bail out cleanly instead of
   spinning forever on a buggy builder.

The SDK fuzzing documentation (<https://ledgerhq.github.io/ledger-secure-sdk/>)
covers the shared harness and generated-file contract. The continuation-host
specifics used by Bitcoin are documented in this README and the local mock
sources.

## Files

| Path | Purpose |
|---|---|
| `fuzz-manifest.toml` | Coverage list, dictionary, seed strategy |
| `CMakeLists.txt` | Build config for the single fuzz harness |
| `harness/fuzz_dispatcher.c` | `fuzz_commands[]` table, `fuzz_app_reset/dispatch`, synthetic-INS routes, tail-driven chaos window |
| `unit-tests/libs/mock_dispatcher.c` | Continuation-host replies for Merkle and preimage traffic (shared with the unit tests) |
| `mock/psbt_model.c` | Structured `SIGN_PSBT` scenarios, early/late faults, tail-driven chaos budget |
| `mock/wallet_model.c` | Structured wallet registration and address scenarios |
| `mock/message_model.c` | Structured `SIGN_MESSAGE` scenarios |
| `mock/fuzz_continuation_host.h` / `mock/fuzz_os_io_rx_evt.c` | Continuation host interface + SEPH envelope mock |
| `mock/fuzz_varint.h` | Shared varint + little-endian fixed-size writers |
| `invariants/zero-symbols.txt` | Globals removed from the prefix |
| `invariants/domain-overrides.txt` | Valid enum and state domains |

## Getting started

Minimal onboarding checklist for editing the harness. Each item points at
the single source of truth; avoid duplicating that information across
files.

1. **Add a new APDU command** — register it in
   `harness/fuzz_dispatcher.c`: extend `fuzz_commands[]` (structured lane)
   or `btc_raw_commands[]` (raw lane), then add a `command_descriptor_t`
   entry in `FUZZ_COMMAND_DESCRIPTORS` and a dedicated `build_*_payload`
   plus a case in `build_structured_payload()`. Keep synthetic INS values
   above `0xF0` so they never collide with app INSes.
2. **Add a new PSBT builder fault** — extend the `BTC_FAULT_*`
   definitions in `mock/mocks.h`, then add the apply branch to
   `pm_apply_pre_tree_fault` (if it must propagate through Merkle
   preimages) or `pm_apply_post_wallet_fault` (if it only lives
   in the APDU header). Every kind must be target-visible in bytes the
   app actually consumes.
3. **Add a new descriptor template** — append one row to the `TEMPLATES`
   array in `mock/wallet_model.c` (ordering is append-only). Pick the
   right group (see the table above) and fill in the correct `n_keys` /
   `purposes[]` so `build_key_info` derives distinct xpubs.
4. **Adjust structured mutation pressure** — tune `btc_field_aware_tweak`
   in `harness/fuzz_dispatcher.c` and keep the README's slot/fault tables
   in sync when you add new targeted operations.
5. **Adjust fuzz-only repairs** — keep repairs gated with
   `#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` and document any new one in
   the source site that applies it.
6. **Promote corpus inputs** — re-promote after any change that alters the
   Absolution prefix layout (new globals, SDK version bump, harness version
   bump) or after significant harness changes that open new code paths.
   Run a campaign, then pack the merged corpus with
   `$BOLOS_SDK/fuzzing/scripts/corpus.py promote <corpus-dir>
   fuzzing/base-corpus.zip`. The zip and its `.compat-key` sidecar are
   auto-loaded by `app-campaign.sh` when compatible with the current build.
7. **Change tracked coverage files** — edit
   `fuzz-manifest.toml`'s `[coverage].key_files` array; the campaign
   script re-runs `llvm-cov show` against that list.
8. **Add / remove an Absolution-driven global** — declare it in `mock/mocks.h`
   and constrain it in `invariants/zero-symbols.txt` or
   `invariants/domain-overrides.txt`. There is no layout to update: the
   campaign rediscovers the prefix and passes its size to the build, and
   nothing in the app knows where a global sits inside it.
