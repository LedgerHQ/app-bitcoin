import re
from enum import IntEnum
from typing import List, Optional

from . import _native
from .common import AddressType


class WalletType(IntEnum):
    WALLET_POLICY_V1 = 1
    WALLET_POLICY_V2 = 2


class WalletPolicy:
    """
    A wallet policy (BIP-388): a descriptor template whose key placeholders `@i` refer to the
    key information strings in `keys_info`.

    For version V2, the wallet is serialized as follows:
       - 1 byte   : wallet version
       - 1 byte   : length of the wallet name (max 64)
       - (var)    : wallet name (ASCII string)
       - (varint) : length of the descriptor template
       - 32-bytes : sha256 hash of the descriptor template
       - (varint) : number of keys (not larger than 252)
       - 32-bytes : root of the Merkle tree of all the keys information.
    """

    def __init__(self, name: str, descriptor_template: str, keys_info: List[str], version: WalletType = WalletType.WALLET_POLICY_V2):
        if version not in (WalletType.WALLET_POLICY_V1, WalletType.WALLET_POLICY_V2):
            raise ValueError("Invalid wallet policy version")

        self.name = name
        self.version = WalletType(version)
        self.descriptor_template = descriptor_template
        self.keys_info = keys_info

    @property
    def n_keys(self) -> int:
        return len(self.keys_info)

    def _native_args(self) -> tuple:
        return (self.name, self.descriptor_template, list(self.keys_info), int(self.version))

    def serialize(self) -> bytes:
        """The serialization of the policy, as the device commits to it."""
        return _native.wallet_policy_serialize(*self._native_args())

    @property
    def id(self) -> bytes:
        """The wallet id: the SHA-256 hash of the serialization."""
        return _native.wallet_policy_id(*self._native_args())

    def get_descriptor(self, change: Optional[bool]) -> str:
        """
        Generates a descriptor string based on the wallet's descriptor template and keys.

        Args:
            change (bool | None): Indicates whether the descriptor is for a change address.
                                  - If None, returns the BIP-389 multipath address for both the receive and change address.
                                  - If True, the descriptor is for a change address.
                                  - If False, the descriptor is for a non-change address.

        Returns:
            str: The generated descriptor.
        """

        desc = self.descriptor_template
        for i in reversed(range(self.n_keys)):
            key = self.keys_info[i]
            desc = desc.replace(f"@{i}", key)

        # in V1, /** is part of the key; in V2, it's part of the policy map. This handles either
        if change is not None:
            desc = desc.replace("/**", f"/{1 if change else 0}/*")
        else:
            desc = desc.replace("/**", "/<0;1>/*")

        if self.version == WalletType.WALLET_POLICY_V2:
            # V2, the /<M;N> syntax is supported. Replace with M if not change, or with N if change
            if change is not None:
                desc = re.sub(r"/<(\d+);(\d+)>", "/\\2" if change else "/\\1", desc)

        return desc


class MultisigWallet(WalletPolicy):
    """A multisig wallet policy, in legacy, native segwit or nested segwit form."""

    def __init__(self, name: str, address_type: AddressType, threshold: int, keys_info: List[str], sorted: bool = True, version: WalletType = WalletType.WALLET_POLICY_V2) -> None:
        n_keys = len(keys_info)

        if not (1 <= threshold <= n_keys <= 16):
            raise ValueError("Invalid threshold or number of keys")

        multisig_op = "sortedmulti" if sorted else "multi"

        if (address_type == AddressType.LEGACY):
            policy_prefix = f"sh({multisig_op}("
            policy_suffix = "))"
        elif address_type == AddressType.WIT:
            policy_prefix = f"wsh({multisig_op}("
            policy_suffix = "))"
        elif address_type == AddressType.SH_WIT:
            policy_prefix = f"sh(wsh({multisig_op}("
            policy_suffix = ")))"
        else:
            raise ValueError(f"Unexpected address type: {address_type}")

        key_placeholder_suffix = "/**" if version == WalletType.WALLET_POLICY_V2 else ""

        descriptor_template = "".join([
            policy_prefix,
            str(threshold) + ",",
            ",".join("@" + str(k) + key_placeholder_suffix for k in range(n_keys)),
            policy_suffix
        ])

        super().__init__(name, descriptor_template, keys_info, version)

        self.threshold = threshold
