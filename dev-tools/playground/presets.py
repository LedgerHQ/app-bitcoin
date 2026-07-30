"""TUI-only presets for the Bitcoin app playground.

A preset prefills the form fields of one TUI tab. Selecting a preset never
involves the device unless the preset includes a device-derived key, in
which case the TUI eagerly queries the device to resolve the
`[fpr/path]xpub` before populating the keys textarea — so the user always
sees the concrete policy they're about to send.

Two flavors:

- `XpubPreset` — a BIP-32 path. Fills the path field on the get-xpub tab.

- `PolicyPreset` — a complete wallet policy (descriptor template + per-`@N`
  `KeySpec`). Fills the wallet-name / template / keys fields on the
  register-wallet / get-address / sign-psbt tabs. For sign-psbt only, the
  fake PSBT to sign can be shaped in two ways: a declarative `PsbtSpec`
  (preferred — describes inputs/outputs, including external inputs, as data)
  or a `psbt_mutator` escape hatch (a callable that tweaks the generated
  PSBT). When both are set, the spec builds it and the mutator tweaks it.

The CLI does not use presets: it accepts a fully-resolved policy via
inline `--template` / `--key` / `--name` flags.
"""

import json
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from bitcoin_client.ledger_bitcoin import Chain  # noqa: E402
from bitcoin_client.ledger_bitcoin.psbt import PSBT  # noqa: E402


REPO_ROOT: Path = _REPO_ROOT


# Fixed test mnemonics used to derive external-cosigner xpubs. Pinning the
# mnemonics keeps each policy id stable across runs, which keeps the
# registration HMAC cache valid.
EXTERNAL_MNEMONICS: List[str] = [
    "all all all all all all all all all all all all",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "legal winner thank year wave sausage worth useful legal winner thank yellow",
]


@dataclass(frozen=True)
class KeySpec:
    """How to source one `@N` key when resolving a policy preset against the device."""
    path: str
    external_index: Optional[int] = None  # None = device; else EXTERNAL_MNEMONICS[index]

    @property
    def is_external(self) -> bool:
        return self.external_index is not None


def _external_master(chain: Chain, index: int):
    """Build a `python-bip32` master key from EXTERNAL_MNEMONICS[index]."""
    from bip32 import BIP32
    from mnemonic import Mnemonic

    if not (0 <= index < len(EXTERNAL_MNEMONICS)):
        raise ValueError(
            f"external_index {index} out of range; "
            f"{len(EXTERNAL_MNEMONICS)} mnemonics available"
        )

    seed = Mnemonic("english").to_seed(EXTERNAL_MNEMONICS[index])
    network = "main" if chain == Chain.MAIN else "test"
    return BIP32.from_seed(seed, network=network)


def external_key_info(chain: Chain, index: int, path: str) -> str:
    """Build a BIP-388 key-info string `[fpr/path]xpub` for the external
    cosigner at `index`, derived from EXTERNAL_MNEMONICS[index]."""
    from bitcoin_client.ledger_bitcoin.common import hash160

    master = _external_master(chain, index)
    master_fpr = hash160(master.pubkey)[:4].hex()
    xpub = master.get_xpub_from_path(path)

    origin = path.lstrip("m").lstrip("/")
    return f"[{master_fpr}/{origin}]{xpub}" if origin else xpub


def external_xpriv(chain: Chain, index: int, path: str) -> str:
    """Returns the base58-serialized xpriv at `path` derived from
    EXTERNAL_MNEMONICS[index]. Used by the musig2 cosigner to participate
    in both rounds of the protocol with its own private key."""
    return _external_master(chain, index).get_xpriv_from_path(path)


# ----- get-xpub presets ------------------------------------------------------

@dataclass(frozen=True)
class XpubPreset:
    name: str
    path: str
    description: str = ""


XPUB_PRESETS: List[XpubPreset] = [
    XpubPreset("bip44-account0", "m/44'/1'/0'", "BIP-44 legacy (P2PKH), first account"),
    XpubPreset("bip49-account0", "m/49'/1'/0'", "BIP-49 wrapped segwit (P2SH-P2WPKH), first account"),
    XpubPreset("bip84-account0", "m/84'/1'/0'", "BIP-84 native segwit (P2WPKH), first account"),
    XpubPreset("bip86-account0", "m/86'/1'/0'", "BIP-86 taproot (P2TR), first account"),
    XpubPreset("multisig-account0", "m/48'/1'/0'/2'", "BIP-48 multisig (native segwit), first account"),
    # The Bitcoin app caps explicit derivation depth at 8 steps (m/.../.../.../.../.../.../.../...).
    XpubPreset(
        "deepest-allowed",
        "m/48'/1'/0'/2'/0/0/0/0",
        "Maximum derivation depth the app accepts (8 steps)",
    ),
]


# ----- declarative sign-psbt shapes -----------------------------------------

# SIGHASH flag bytes. The low bits pick the base type; ANYONECANPAY (0x80) is a
# modifier OR-ed on top (e.g. SIGHASH_ALL | SIGHASH_ANYONECANPAY == 0x81). The
# app rejects a bare 0x80 and SIGHASH_DEFAULT (0x00) on segwitv0, so always OR
# ANYONECANPAY with a base type. Signing a non-default sighash also needs the
# device's "non-standard sighash" setting enabled.
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80


@dataclass(frozen=True)
class PsbtInputSpec:
    """One input of a `PsbtSpec`."""
    amount: int
    external: bool = False        # True => a foreign input the wallet can't sign
    sighash: Optional[int] = None  # None => default; else a SIGHASH_* byte (PSBT_IN_SIGHASH_TYPE)


@dataclass(frozen=True)
class PsbtOutputSpec:
    """One output of a `PsbtSpec`. `amount=None` marks the single "remainder"
    output that absorbs whatever value is left after the explicit outputs and
    the fee — set it on the change output to produce a net receive."""
    amount: Optional[int] = None
    is_change: bool = False  # True => wallet change (internal)


@dataclass(frozen=True)
class PsbtSpec:
    """A declarative description of the fake PSBT a sign-psbt preset wants.

    Turned into a `test_utils.txmaker.createPsbt` call by `build_psbt_from_spec`.
    Prefer this over a `psbt_mutator` for anything that is really about the
    *shape* of the transaction (which inputs are external, the amounts, which
    output is change). Keep at least one internal input so the device signs.

    `fee` is the exact fee in satoshis. Because a transaction must balance
    (inputs = outputs + fee), you control the fee by leaving one output's
    `amount` unset (the "remainder"): it becomes `total_in - explicit - fee`.
    So a large `fee` with a small remainder gives a high-fee transaction, and a
    small `fee` with a change remainder gives a net receive. If every output has
    an explicit amount there is no free variable, so `fee` must equal
    `total_in - sum(outputs)` exactly (else it's a mistake and we raise).

    All of that assumes the transaction is complete, which holds only as long as
    every input commits to all the amounts — i.e. uses SIGHASH_DEFAULT or
    SIGHASH_ALL (or omits the field). If there are other sighash flags, every
    output must set `amount` explicitly, and `fee` is ignored.
    """
    inputs: List[PsbtInputSpec]
    outputs: List[PsbtOutputSpec]
    fee: int = 1000


def build_psbt_from_spec(policy, spec: PsbtSpec) -> PSBT:
    """Build a fake PSBT for `policy` matching `spec`, via the shared factory.

    At most one output may leave `amount` unset ("remainder"): it receives
    `total_in - sum(explicit outputs) - spec.fee`. All other amounts are taken
    verbatim. `spec.fee` is always honored — via the remainder if there is one,
    otherwise as a checked invariant against `total_in - sum(outputs)`. A
    per-input `sighash` is copied onto the built PSBT input.

    Exception: if any input sets a `sighash` that doesn't commit to all the
    amounts, the transaction is not required to balance (see `PsbtSpec`), so every
    output must set `amount`, and `spec.fee` is neither used nor checked — outputs
    may exceed the inputs.
    """
    # local imports (heavy module)
    from test_utils.txmaker import createPsbt, sighash_commits_to_all_amounts

    input_amounts = [i.amount for i in spec.inputs]
    input_is_external = [i.external for i in spec.inputs]
    input_sighashes = [i.sighash for i in spec.inputs]
    total_in = sum(input_amounts)

    # SIGHASH_DEFAULT / SIGHASH_ALL still fix every amount, so they keep the
    # ordinary balanced treatment, exactly like an unset sighash.
    unbalanced = not all(
        sighash_commits_to_all_amounts(sighash) for sighash in input_sighashes
    )

    remainder_indices = [n for n, o in enumerate(spec.outputs) if o.amount is None]
    if len(remainder_indices) > 1:
        raise ValueError("at most one output may omit `amount` (the remainder)")
    explicit_total = sum(o.amount for o in spec.outputs if o.amount is not None)

    if unbalanced:
        if spec.fee != 0:
            raise ValueError("fee must be 0 (or omitted) when a sighash doesn't commit to all amounts")

        # No fee to spread around: such a sighash leaves the transaction open, so
        # there is nothing for a remainder output to absorb.
        if remainder_indices:
            raise ValueError(
                "every output must set `amount` when an input sets a `sighash` "
                "that doesn't commit to all the amounts: such a transaction need "
                "not balance, so there is no fee for a remainder output to absorb"
            )
        output_amounts = [o.amount for o in spec.outputs]
    elif remainder_indices:
        remainder = total_in - explicit_total - spec.fee
        if remainder < 0:
            raise ValueError(
                f"remainder is negative: inputs ({total_in}) too small for "
                f"explicit outputs ({explicit_total}) + fee ({spec.fee})"
            )
        output_amounts = [
            remainder if o.amount is None else o.amount for o in spec.outputs
        ]
    else:
        # No free variable: the fee is fully determined by inputs - outputs, so
        # the declared fee must match (guards against a silently-ignored fee).
        implied_fee = total_in - explicit_total
        if implied_fee < 0:
            raise ValueError(
                f"outputs ({explicit_total}) exceed inputs ({total_in})"
            )
        if spec.fee != implied_fee:
            raise ValueError(
                f"fee={spec.fee} disagrees with inputs - outputs ({implied_fee}); "
                f"leave one output's amount unset (the remainder) to let the fee "
                f"take effect, or set fee={implied_fee}"
            )
        output_amounts = [o.amount for o in spec.outputs]
    output_is_change = [o.is_change for o in spec.outputs]

    return createPsbt(
        policy, input_amounts, output_amounts, output_is_change, input_is_external,
        input_sighashes,
    )


# ----- wallet-policy presets -------------------------------------------------

@dataclass
class PolicyPreset:
    name: str
    description: str
    wallet_name: str               # WalletPolicy.name; "" => standard, no registration
    template: str
    keys: List[KeySpec]
    # sign-psbt only; both are ignored on the register-wallet / get-address tabs.
    # `psbt_spec` declaratively describes the fake PSBT to generate (preferred).
    # `psbt_mutator` is an escape hatch that tweaks the generated PSBT after the
    # fact; when both are set, the spec builds it and the mutator tweaks it.
    psbt_spec: Optional[PsbtSpec] = None
    psbt_mutator: Optional[Callable[[PSBT], PSBT]] = None

    @property
    def needs_registration(self) -> bool:
        return self.wallet_name != ""


POLICY_PRESETS: List[PolicyPreset] = [
    # --- standard singlesig (no registration) -------------------------------
    PolicyPreset(
        name="pkh-singlesig",
        description="BIP-44 legacy single-sig (P2PKH)",
        wallet_name="",
        template="pkh(@0/**)",
        keys=[KeySpec("m/44'/1'/0'")],
    ),
    PolicyPreset(
        name="sh-wpkh-singlesig",
        description="BIP-49 wrapped-segwit single-sig (P2SH-P2WPKH)",
        wallet_name="",
        template="sh(wpkh(@0/**))",
        keys=[KeySpec("m/49'/1'/0'")],
    ),
    PolicyPreset(
        name="wpkh-singlesig",
        description="BIP-84 native-segwit single-sig (P2WPKH)",
        wallet_name="",
        template="wpkh(@0/**)",
        keys=[KeySpec("m/84'/1'/0'")],
    ),
    PolicyPreset(
        name="tr-singlesig",
        description="BIP-86 taproot single-sig (P2TR)",
        wallet_name="",
        template="tr(@0/**)",
        keys=[KeySpec("m/86'/1'/0'")],
    ),

    # --- multisig (1 device + 1 external) -----------------------------------
    PolicyPreset(
        name="multisig-2of2-wsh",
        description="2-of-2 native-segwit sortedmulti (1 device + 1 external cosigner)",
        wallet_name="Test multisig",
        template="wsh(sortedmulti(2,@0/**,@1/**))",
        keys=[
            KeySpec("m/48'/1'/0'/2'"),                          # device
            KeySpec("m/48'/1'/0'/2'", external_index=0),        # external
        ],
    ),

    # --- miniscript ---------------------------------------------------------
    PolicyPreset(
        name="miniscript-or",
        description="Miniscript: device OR external — wsh(or_d(pk(@0/**),pkh(@1/**)))",
        wallet_name="Joint account",
        template="wsh(or_d(pk(@0/**),pkh(@1/**)))",
        keys=[
            KeySpec("m/48'/1'/0'/2'"),
            KeySpec("m/48'/1'/0'/2'", external_index=0),
        ],
    ),
    PolicyPreset(
        name="miniscript-2fa-with-fallback",
        description=(
            "Miniscript 2FA with timelock fallback: device AND "
            "(external OR after 12960 blocks)"
        ),
        wallet_name="2FA with fallback",
        template="wsh(and_v(v:pk(@0/**),or_d(pk(@1/**),older(12960))))",
        keys=[
            KeySpec("m/48'/1'/0'/2'"),
            KeySpec("m/48'/1'/0'/2'", external_index=0),
        ],
    ),

    PolicyPreset(
        name="tr-miniscript-3key",
        description=(
            "Taproot miniscript: internal keypath"
            " + external single-key"
            " + external timelocked single-sig"
        ),
        wallet_name="TR miniscript 3key",
        template="tr(@0/**,{pk(@1/**),and_v(v:pk(@2/<0;1>/*),older(52560))})",
        keys=[
            KeySpec("m/86'/1'/0'"),                    # device: key-path spend
            KeySpec("m/86'/1'/0'", external_index=0),  # ext1: immediate script-path
            KeySpec("m/86'/1'/0'", external_index=1),  # ext2: timelock script-path
        ],
    ),


    # --- musig2 -------------------------------------------------------------
    PolicyPreset(
        name="musig2-keypath",
        description="MuSig2 at the taproot key-path with 2 aggregated keys (1 device + 1 external)",
        wallet_name="Musig 2 my ears",
        template="tr(musig(@0,@1)/**)",
        keys=[
            KeySpec("m/48'/1'/0'/2'"),
            KeySpec("m/48'/1'/0'/2'", external_index=0),
        ],
    ),
]


# ----- sign-psbt scenario presets -------------------------------------------

# These reuse simple wallet policies but shape the generated fake PSBT (via a
# declarative `psbt_spec`) to put the device in an interesting state. The
# `psbt_mutator` escape hatch on `PolicyPreset` is available for tweaks a spec
# can't express, but no preset currently needs it.
SIGN_PSBT_SCENARIO_PRESETS: List[PolicyPreset] = [
    PolicyPreset(
        name="huge-fee-wpkh",
        description="wpkh single-sig paying almost the entire input as fee — should trigger the high-fee warning",
        wallet_name="",
        template="wpkh(@0/**)",
        keys=[KeySpec("m/84'/1'/0'")],
        psbt_spec=PsbtSpec(
            inputs=[PsbtInputSpec(100_000_000)],
            # The remainder recipient gets total_in - fee = 1000 (dust); the
            # ~1 BTC fee dwarfs it -> high-fee warning.
            outputs=[PsbtOutputSpec()],
            fee=99_999_000,
        ),
    ),
    PolicyPreset(
        name="external-inputs-net-send",
        description=(
            "tr single-sig with a large external input, most value sent out — "
            "external-inputs warning + net-send display"
        ),
        wallet_name="",
        template="tr(@0/**)",
        keys=[KeySpec("m/86'/1'/0'")],
        psbt_spec=PsbtSpec(
            inputs=[
                PsbtInputSpec(100_000_000),                 # internal (the wallet signs this)
                PsbtInputSpec(300_000_000, external=True),  # external (foreign, unsigned)
            ],
            outputs=[
                PsbtOutputSpec(),                             # recipient absorbs the rest
                # change < internal inputs (100M) => net send
                PsbtOutputSpec(amount=50_000_000, is_change=True),
            ],
        ),
    ),
    PolicyPreset(
        name="external-inputs-net-receive",
        description=(
            "tr single-sig with a large external input routed to change — "
            "external-inputs warning + net-receive display"
        ),
        wallet_name="",
        template="tr(@0/**)",
        keys=[KeySpec("m/86'/1'/0'")],
        psbt_spec=PsbtSpec(
            inputs=[
                PsbtInputSpec(100_000_000),                 # internal (the wallet signs this)
                PsbtInputSpec(300_000_000, external=True),  # external (foreign, unsigned)
            ],
            outputs=[
                PsbtOutputSpec(amount=10_000),   # small recipient
                PsbtOutputSpec(is_change=True),  # change absorbs the rest => net receive
            ],
        ),
    ),

    # --- non-default sighash types (need the device's non-standard-sighash setting) ---
    PolicyPreset(
        name="sighash-anyonecanpay",
        description=(
            "wpkh single-sig, every input with ALL | ANYONECANPAY"
        ),
        wallet_name="",
        template="wpkh(@0/**)",
        keys=[KeySpec("m/84'/1'/0'")],
        psbt_spec=PsbtSpec(
            inputs=[
                PsbtInputSpec(100_000_000, sighash=SIGHASH_ALL | SIGHASH_ANYONECANPAY),
                PsbtInputSpec(50_000_000, sighash=SIGHASH_ALL | SIGHASH_ANYONECANPAY),
            ],
            outputs=[
                PsbtOutputSpec(amount=120_000_000),              # recipient
                PsbtOutputSpec(amount=80_999_000, is_change=True),  # change
            ],
        ),
    ),
    PolicyPreset(
        name="sighash-none",
        description=("wpkh single-sig, every input with NONE (0x02)"),
        wallet_name="",
        template="wpkh(@0/**)",
        keys=[KeySpec("m/84'/1'/0'")],
        psbt_spec=PsbtSpec(
            inputs=[
                PsbtInputSpec(100_000_000, sighash=SIGHASH_NONE),
                PsbtInputSpec(50_000_000, sighash=SIGHASH_NONE),
            ],
            outputs=[
                PsbtOutputSpec(amount=120_000_000),              # recipient
                PsbtOutputSpec(amount=80_999_000, is_change=True),  # change
            ],
        ),
    ),
    PolicyPreset(
        name="sighash-single-anyonecanpay-1in1out",
        description=("wpkh single-sig, 1-in-1-out, SINGLE|ANYONECANPAY"),
        wallet_name="",
        template="wpkh(@0/**)",
        keys=[KeySpec("m/84'/1'/0'")],
        psbt_spec=PsbtSpec(
            inputs=[
                PsbtInputSpec(100_000_000, sighash=SIGHASH_SINGLE | SIGHASH_ANYONECANPAY),
            ],
            outputs=[
                PsbtOutputSpec(amount=120_000_000, is_change=True),
            ],
        ),
    ),
]


def sign_psbt_presets() -> List[PolicyPreset]:
    """Presets shown on the sign-psbt tab: every wallet-policy preset plus the
    scenario presets."""
    return list(POLICY_PRESETS) + list(SIGN_PSBT_SCENARIO_PRESETS)


# ----- registration cache ---------------------------------------------------

_CACHE_DIR = Path(tempfile.gettempdir()) / "btcapp-playground"
_CACHE_FILE = _CACHE_DIR / "wallets.json"


def _load_cache() -> dict:
    if not _CACHE_FILE.exists():
        return {}
    try:
        return json.loads(_CACHE_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(data: dict) -> None:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    _CACHE_FILE.write_text(json.dumps(data, indent=2))


def _cache_key(master_fpr_hex: str, wallet_id_hex: str) -> str:
    return f"{master_fpr_hex}:{wallet_id_hex}"


def cached_registration(master_fpr_hex: str, wallet_id: bytes) -> Optional[bytes]:
    """Look up a cached HMAC for `(master_fpr, wallet_id)`.

    The cache is keyed on the wallet id (a hash of the policy itself), so it
    is automatically invalidated whenever the user changes a template/key —
    no preset name needed.
    """
    entry = _load_cache().get(_cache_key(master_fpr_hex, wallet_id.hex()))
    if not entry:
        return None
    try:
        return bytes.fromhex(entry["hmac"])
    except (KeyError, ValueError):
        return None


def store_registration(
    master_fpr_hex: str, wallet_id: bytes, wallet_hmac: bytes
) -> None:
    data = _load_cache()
    data[_cache_key(master_fpr_hex, wallet_id.hex())] = {
        "hmac": wallet_hmac.hex(),
    }
    _save_cache(data)


def cache_file_path() -> Path:
    return _CACHE_FILE
