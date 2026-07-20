# Bitcoin app playground

A small, dev-only playground for exercising the Ledger Bitcoin app's APDU
commands against speculos or a real device. Each command maps to one APDU
so you can watch the corresponding UX flow on the device screen.

Two front-ends:

- **CLI** ([cli.py](cli.py)) — single-shot subcommands, scriptable. Takes a
  fully-resolved wallet policy via inline `--template` / `--key` / `--name`
  flags; no preset concept.
- **TUI** ([gui.py](gui.py)) — Textual-based, tabbed UI; one tab per
  command. Adds *presets* on top: picking a preset prefills the tab's
  fields (and, for wallet policies, eagerly resolves device-derived xpubs).
  Streams the same stdout/stderr the CLI would print into an output panel.

## Setup

All commands assume you're at the repo root (`app-bitcoin/`).

```bash
# 1. Create and activate a Python virtualenv (Python >= 3.8).
python3 -m venv .venv
source .venv/bin/activate

# 2. Install the ledger_bitcoin client library (editable install).
pip install -e ./bitcoin_client

# 3. Install the playground's extra dependencies.
pip install -r dev-tools/playground/requirements.txt
```

If you also plan to use the speculos emulator, install it too:

```bash
pip install speculos
```

## Running speculos (optional, for emulator use)

In a separate terminal:

```bash
speculos build/nanos2/bin/app.elf
```

(replace `nanos2` with the device target you have an SDK build for).

## Running the TUI

```bash
python dev-tools/playground/gui.py
```

The TUI has one tab per command (`get-fingerprint`, `get-xpub`,
`register-wallet`, `get-address`, `sign-psbt`, `sign-message`). At
startup it probes speculos first, then a USB device; pass `--target
speculos` or `--target hid` to skip the probe. The Output panel at the
bottom streams stdout/stderr from each command in real time — so what
you see is exactly what the CLI would have printed.

### Presets

Most tabs (`get-xpub`, `register-wallet`, `get-address`, `sign-psbt`) have
a **Preset** combobox at the top. Picking a preset prefills the remaining
fields:

- **`get-xpub`** presets are common BIP-32 paths
  (`bip44-account0`, …, `bip86-account0`, `multisig-account0`, and one
  `deepest-allowed` at the maximum derivation depth the app accepts).

- **`register-wallet`** / **`get-address`** / **`sign-psbt`** presets carry
  a full wallet policy — descriptor template, wallet name, and one
  `KeySpec` per `@N`. On selection the TUI eagerly queries the device to
  resolve every internal key into a `[fpr/origin]xpub` line; external
  cosigners are derived locally from one of the fixed mnemonics in
  `EXTERNAL_MNEMONICS`. The resulting policy is written into the editable
  fields so you can review or tweak it before pressing Run.

- The `sign-psbt` tab also exposes **scenario presets** (e.g.
  `huge-fee-wpkh`, `external-inputs-net-receive`): same wallet-policy form,
  plus a way to shape the auto-generated fake PSBT into an interesting state
  before signing. Two mechanisms:
  - a declarative **`PsbtSpec`** (preferred, used by both presets above) —
    describes the inputs and outputs as data, including *external* inputs the
    wallet can't sign and the exact fee; the spec defines its own input/output
    set, so the "Generated inputs/outputs" fields are ignored;
  - a **`psbt_mutator`** escape hatch — a Python callable `(psbt) -> psbt`
    that tweaks the generated PSBT, for the rare tweak a spec can't express
    (no preset currently needs it).
  When a preset carries both, the spec builds the PSBT and the mutator tweaks
  it. Both only run when the PSBT textarea is empty; if you paste a fixture
  they're ignored.

Pick `(no preset)` to keep editing the fields by hand.

### Sign-PSBT input

A single textarea: leave empty to generate a fake PSBT (uses the
Inputs/Outputs fields); paste a base64 PSBT (auto-detected by the `cHNidP`
prefix); or type a file path to load from disk.

### Keyboard / mouse

- `Ctrl+L` clears the log; `Ctrl+R` reconnects; `Ctrl+Q` quits.
- Right-click on any text field pastes from the OS clipboard (requires one
  of `xclip` / `xsel` / `wl-paste` / `pbpaste`). On most terminals
  `Shift+Right-Click` also works via the terminal's own paste path.

## Running the CLI

The CLI has no preset concept. Wallet-policy subcommands take a
fully-resolved policy via inline flags:

```bash
# Simple commands (no wallet policy).
python dev-tools/playground/cli.py get-fingerprint
python dev-tools/playground/cli.py get-xpub "m/86'/1'/0'" --display
python dev-tools/playground/cli.py sign-message "m/44'/1'/0'/0/0" "hi"

# Standard single-sig (no --name => standard policy, no registration).
python dev-tools/playground/cli.py get-address \
    --template "tr(@0/**)" \
    --key "[f5acc2fd/86'/1'/0']tpub..." \
    --display

# Non-standard policy: --name is required for register-wallet and triggers
# HMAC caching for subsequent get-address / sign-psbt calls.
python dev-tools/playground/cli.py register-wallet \
    --name "Joint account" \
    --template "wsh(or_d(pk(@0/**),pkh(@1/**)))" \
    --key "[f5acc2fd/48'/1'/0'/2']tpub..." \
    --key "[d34db33f/48'/1'/0'/2']tpub..."

# Same flags on sign-psbt; defaults to a generated fake PSBT.
python dev-tools/playground/cli.py sign-psbt \
    --name "Joint account" \
    --template "wsh(or_d(pk(@0/**),pkh(@1/**)))" \
    --key "[f5acc2fd/48'/1'/0'/2']tpub..." \
    --key "[d34db33f/48'/1'/0'/2']tpub..."

# Pre-build a fake PSBT (no device interaction).
python dev-tools/playground/cli.py make-psbt \
    --template "tr(@0/**)" \
    --key "[f5acc2fd/86'/1'/0']tpub..." \
    --inputs 2 --outputs 4 -o /tmp/fake.psbt
```

For MuSig2 (`tr(musig(@0,@1)/**)`), `sign-psbt` stops after round 1 by
default. Pass `--external-xpriv <xpriv>` once per non-device cosigner to
drive round 2 end-to-end.

To talk to a real USB-connected device instead of speculos, pass
`--target hid`:

```bash
python dev-tools/playground/cli.py --target hid get-fingerprint
```

## How to add a preset (TUI only)

Edit [presets.py](presets.py) and append to the relevant list:

- `XPUB_PRESETS`: an `XpubPreset(name, path, description)` for a new
  derivation path.
- `POLICY_PRESETS`: a `PolicyPreset(name, description, wallet_name,
  template, keys=[KeySpec(...), ...])` for a new wallet policy. Use
  `wallet_name=""` for standard single-sig (no registration); any
  non-empty string makes it a registrable policy.
- `SIGN_PSBT_SCENARIO_PRESETS`: a `PolicyPreset` that shapes the
  auto-generated fake PSBT with a declarative `psbt_spec=PsbtSpec(...)`
  describing the inputs (`PsbtInputSpec(amount, external=...)`), the outputs
  (`PsbtOutputSpec(amount=..., is_change=...)`), and the exact `fee`. Leave one
  output's `amount` unset to make it absorb the remainder. Keep at least one
  internal (non-`external`) input so the device has something to sign. For the
  rare tweak a spec can't express, `psbt_mutator=(psbt) -> psbt` is available
  as an escape hatch (applied on top of the spec).

`KeySpec(path, external_index=None)` means the key is sourced from the
device at `path`; pass an `external_index` (`0`, `1`, or `2`) to use one
of the pinned mnemonics in `EXTERNAL_MNEMONICS`. External cosigners give
the playground a true co-custody policy without requiring a second
device, and the HMAC cache (`$TMPDIR/btcapp-playground/wallets.json`)
stays valid across runs because the policy id is reproducible.
