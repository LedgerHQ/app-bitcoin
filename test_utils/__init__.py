import re
import sys
import os

import hashlib
from typing import Literal, Union

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from mnemonic import Mnemonic
from bip32 import BIP32

from ledger_bitcoin.wallet import WalletPolicy, WalletType

from .slip21 import Slip21Node

mnemo = Mnemonic("english")

DEFAULT_SPECULOS_MNEMONIC = "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"

WALLET_POLICY_SLIP21_LABEL = b"LEDGER-Wallet policy"


default_settings = {
    # mnemonic to use when running speculos
    "mnemonic": DEFAULT_SPECULOS_MNEMONIC,
    # path of the automation file to use for speculos if used, or None
    "automation_file": None
}


def test_settings(s: dict):
    """Decorator that adds the given settings to the "test_settings" field of a test function."""
    def decorator(func):
        if not hasattr(func, 'test_settings'):
            func.test_settings = default_settings.copy()
        func.test_settings.update(s)
        return func
    return decorator


def has_automation(filename: str):
    """Adds the automation_file setting to use `filename` as the Speculos automation file."""
    return test_settings({"automation_file": filename})


def mnemonic(mnemo: str):
    """Adds the `mnemonic` setting to the test settings."""
    return test_settings({"mnemonic": mnemo})


def ripemd160(x: bytes) -> bytes:
    try:
        h = hashlib.new("ripemd160")
        h.update(x)
        return h.digest()
    except BaseException:
        # ripemd160 is not always present in hashlib.
        # Fallback to custom implementation if missing.
        from . import ripemd
        return ripemd.ripemd160(x)


def sha256(s: bytes) -> bytes:
    return hashlib.new('sha256', s).digest()


def hash160(s: bytes) -> bytes:
    return ripemd160(sha256(s))


def hash256(s: bytes) -> bytes:
    return sha256(sha256(s))


class SpeculosGlobals:
    def __init__(self, mnemonic: str, network: str = "test"):
        if network not in ["main", "test"]:
            raise ValueError(f"Invalid network: {network}")

        self.mnemonic = mnemonic
        self.seed = mnemo.to_seed(mnemonic)
        bip32 = BIP32.from_seed(self.seed, network)
        self.master_extended_privkey = bip32.get_xpriv()
        self.master_extended_pubkey = bip32.get_xpub()
        self.master_key_fingerprint = hash160(bip32.pubkey)[0:4]
        self.master_compressed_pubkey = bip32.pubkey.hex()
        slip21_root = Slip21Node.from_seed(self.seed)
        self.wallet_registration_key = slip21_root.derive_child(
            WALLET_POLICY_SLIP21_LABEL).key


def get_internal_xpub(seed: str, path: str) -> str:
    bip32 = BIP32.from_seed(seed, network="test")
    return bip32.get_xpub_from_path(f"m/{path}") if path else bip32.get_xpub_from_path("m")


def count_internal_key_placeholders(seed: str, network: Union[Literal['main'], Literal['test']], wallet_policy: WalletPolicy, *, only_musig=False) -> int:
    """Count how many of the key placeholders in wallet_policy are indeed internal.
    musig() placeholders are counted as many times as there are internal keys in them."""

    bip32 = BIP32.from_seed(seed, network)
    master_key_fingerprint = hash160(bip32.pubkey)[0:4]

    is_key_internal = []
    for key_index, key_info in enumerate(wallet_policy.keys_info):
        is_this_key_internal = False
        if "]" in key_info:
            key_orig_end_pos = key_info.index("]")
            fpr = key_info[1:9]
            path = key_info[10:key_orig_end_pos]
            xpub = key_info[key_orig_end_pos + 1:]

            # support for V1 policies, where the key info contains additional derivation steps
            if "/" in xpub:
                xpub = xpub[:xpub.index("/")]  # truncate any additional steps

            if fpr == master_key_fingerprint.hex():
                computed_xpub = get_internal_xpub(seed, path)
                if computed_xpub == xpub:
                    is_this_key_internal = True
        is_key_internal.append(is_this_key_internal)

    # enumerate all the key placeholders
    # for simplicity, we look for all the following patterns using regular expressions:
    # - Simple keys: @<key_index>/  (always with additional derivations, hence the final '/')
    # - Musig expressions: musig(@k1, @k2, ...)

    count = 0

    if not only_musig:
        simple_key_placeholders = re.findall(
            r'@(\d+)/', wallet_policy.descriptor_template)
        # for each match, count it if the corresponding key is internal
        for key_index in simple_key_placeholders:
            if is_key_internal[int(key_index)]:
                count += 1

    if wallet_policy.version != WalletType.WALLET_POLICY_V1:  # no musig in V1 policies
        musig_key_placeholders = re.findall(
            r'musig\(([^)]*)\)', wallet_policy.descriptor_template)
        for musig_expr in musig_key_placeholders:
            musig_keys_indices = [int(k[1:]) for k in musig_expr.split(",")]
            # We count each musig placeholder as many times are there are internal keys in it
            count += sum(int(is_key_internal[k]) for k in musig_keys_indices)

    return count
