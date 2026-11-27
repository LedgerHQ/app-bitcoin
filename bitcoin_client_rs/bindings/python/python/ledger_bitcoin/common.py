from enum import Enum
from typing import Union


# from bitcoin-core/HWI
class Chain(Enum):
    """
    The blockchain network to use
    """
    MAIN = 0  #: Bitcoin Main network
    TEST = 1  #: Bitcoin Test network
    REGTEST = 2  #: Bitcoin Core Regression Test network
    SIGNET = 3  #: Bitcoin Signet

    def __str__(self) -> str:
        return self.name.lower()

    def __repr__(self) -> str:
        return str(self)

    @staticmethod
    def argparse(s: str) -> Union['Chain', str]:
        try:
            return Chain[s.upper()]
        except KeyError:
            return s


# from bitcoin-core/HWI
class AddressType(Enum):
    """
    The type of address to use
    """
    LEGACY = 1  #: Legacy address type. P2PKH for single sig, P2SH for scripts.
    WIT = 2    #: Native segwit v0 address type. P2WPKH for single sig, P2WPSH for scripts.
    SH_WIT = 3  #: Nested segwit v0 address type. P2SH-P2WPKH for single sig, P2SH-P2WPSH for scripts.
    TAP = 4    #: Segwit v1 Taproot address type. P2TR always.

    def __str__(self) -> str:
        return self.name.lower()

    def __repr__(self) -> str:
        return str(self)

    @staticmethod
    def argparse(s: str) -> Union['AddressType', str]:
        try:
            return AddressType[s.upper()]
        except KeyError:
            return s
