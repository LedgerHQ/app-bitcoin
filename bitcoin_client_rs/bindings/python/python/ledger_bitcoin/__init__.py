"""Ledger Nano Bitcoin app client"""

from importlib.metadata import version as _version

from .client import (Client, NewClient, createClient, UnsupportedAppVersionError, PartialSignature,
                     MusigPubNonce, MusigPartialSignature, SignPsbtYieldedObject,
                     UnknownSignPsbtYieldedObject)
from .common import AddressType, Chain
from .transport import TransportClient
from .wallet import WalletPolicy, MultisigWallet, WalletType

# the version of the package is the one of the Rust crate it is built from (Cargo.toml)
__version__ = _version("ledger_bitcoin")

__all__ = [
    "Client",
    "NewClient",
    "TransportClient",
    "PartialSignature",
    "MusigPubNonce",
    "MusigPartialSignature",
    "SignPsbtYieldedObject",
    "UnknownSignPsbtYieldedObject",
    "UnsupportedAppVersionError",
    "createClient",
    "Chain",
    "AddressType",
    "WalletPolicy",
    "MultisigWallet",
    "WalletType"
]
