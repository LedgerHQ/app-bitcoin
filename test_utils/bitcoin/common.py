from io import BytesIO
from typing import List, Optional, Literal
from enum import Enum
from typing import Union

import hashlib

UINT64_MAX: int = 18446744073709551615
UINT32_MAX: int = 4294967295
UINT16_MAX: int = 65535


# from bitcoin-core/HWI
class Chain(Enum):
    """
    The blockchain network to use
    """
    MAIN = 0 #: Bitcoin Main network
    TEST = 1 #: Bitcoin Test network
    REGTEST = 2 #: Bitcoin Core Regression Test network
    SIGNET = 3 #: Bitcoin Signet

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
    LEGACY = 1 #: Legacy address type. P2PKH for single sig, P2SH for scripts.
    WIT = 2    #: Native segwit v0 address type. P2WPKH for single sig, P2WPSH for scripts.
    SH_WIT = 3 #: Nested segwit v0 address type. P2SH-P2WPKH for single sig, P2SH-P2WPSH for scripts.
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

def bip32_path_from_string(path: str) -> List[bytes]:
    splitted_path: List[str] = path.split("/")

    if not splitted_path:
        raise Exception(f"BIP32 path format error: '{path}'")

    if "m" in splitted_path and splitted_path[0] == "m":
        splitted_path = splitted_path[1:]

    return [int(p).to_bytes(4, byteorder="big") if "'" not in p
            else (0x80000000 | int(p[:-1])).to_bytes(4, byteorder="big")
            for p in splitted_path]


def write_varint(n: int) -> bytes:
    if n <= 0xFC:
        return n.to_bytes(1, byteorder="little")

    if n <= UINT16_MAX:
        return b"\xFD" + n.to_bytes(2, byteorder="little")

    if n <= UINT32_MAX:
        return b"\xFE" + n.to_bytes(4, byteorder="little")

    if n <= UINT64_MAX:
        return b"\xFF" + n.to_bytes(8, byteorder="little")

    raise ValueError(f"Can't write to varint: '{n}'!")


def read_varint(buf: BytesIO,
                prefix: Optional[bytes] = None) -> int:
    b: bytes = prefix if prefix else buf.read(1)

    if not b:
        raise ValueError(f"Can't read prefix: '{b}'!")

    n: int = {b"\xfd": 2, b"\xfe": 4, b"\xff": 8}.get(b, 1)  # default to 1

    b = buf.read(n) if n > 1 else b

    if len(b) != n:
        raise ValueError("Can't read varint!")

    return int.from_bytes(b, byteorder="little")


def read_uint(buf: BytesIO,
              bit_len: int,
              byteorder: Literal['big', 'little'] = 'little') -> int:
    size: int = bit_len // 8
    b: bytes = buf.read(size)

    if len(b) < size:
        raise ValueError(f"Can't read u{bit_len} in buffer!")

    return int.from_bytes(b, byteorder)


def serialize_str(value: str) -> bytes:
    return len(value.encode()).to_bytes(1, byteorder="big") + value.encode()


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


class ByteStreamParser:
    def __init__(self, input: bytes):
        self.stream = BytesIO(input)

    def assert_empty(self) -> bytes:
        if self.stream.read(1) != b'':
            raise ValueError("Byte stream was expected to be empty")

    def read_bytes(self, n: int) -> bytes:
        result = self.stream.read(n)
        if len(result) < n:
            raise ValueError("Byte stream exhausted")
        return result

    def read_uint(self, n: int, byteorder: Literal['big', 'little'] = "big") -> int:
        return int.from_bytes(self.read_bytes(n), byteorder)

    def read_varint(self) -> int:
        prefix = self.read_uint(1)

        if prefix == 253:
            return self.read_uint(2, 'little')
        elif prefix == 254:
            return self.read_uint(4, 'little')
        elif prefix == 255:
            return self.read_uint(8, 'little')
        else:
            return prefix
