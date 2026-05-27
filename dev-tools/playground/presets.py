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
  register-wallet / get-address / sign-psbt tabs. For sign-psbt only, an
  optional `psbt_mutator` is applied to the generated fake PSBT just
  before signing — used for scenario presets like "huge-fee".

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


# ----- wallet-policy presets -------------------------------------------------

@dataclass
class PolicyPreset:
    name: str
    description: str
    wallet_name: str               # WalletPolicy.name; "" => standard, no registration
    template: str
    keys: List[KeySpec]
    # sign-psbt only: optional mutator applied to the generated fake PSBT.
    # Ignored on the register-wallet and get-address tabs.
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


# ----- sign-psbt PSBT mutators ----------------------------------------------

def _huge_fee_mutator(psbt: PSBT) -> PSBT:
    """Reduce every output value to dust so that almost the entire input
    value becomes fee — exercises the device's high-fee warning UX."""
    DUST = 1000
    for vout in psbt.tx.vout:
        vout.nValue = DUST
    return psbt


def _zero_outputs_mutator(psbt: PSBT) -> PSBT:
    """Set every output value to zero — exercises the device's zero-amount
    handling and (via the resulting massive fee) the high-fee warning."""
    for vout in psbt.tx.vout:
        vout.nValue = 0
    return psbt


# Sign-psbt-only scenario presets. These reuse simple wallet policies but
# mutate the generated fake PSBT to put the device in an interesting state.
SIGN_PSBT_SCENARIO_PRESETS: List[PolicyPreset] = [
    PolicyPreset(
        name="huge-fee-wpkh",
        description="wpkh single-sig with all outputs forced to dust — should trigger the high-fee warning",
        wallet_name="",
        template="wpkh(@0/**)",
        keys=[KeySpec("m/84'/1'/0'")],
        psbt_mutator=_huge_fee_mutator,
    ),
]


def sign_psbt_presets() -> List[PolicyPreset]:
    """Presets shown on the sign-psbt tab: every wallet-policy preset (no
    mutator) plus the scenario presets (with mutators)."""
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
