from io import BytesIO
from sys import version_info
from dataclasses import dataclass
assert version_info.major >= 3, "Python 3 required!"
if version_info.minor >= 8:
    # pylint: disable=no-name-in-module
    from typing import NewType, Optional, cast, Literal
elif version_info.minor <= 6:   # TypedDict & Literal not yet standard in 3.6
    from typing import NewType, Optional, cast
    from typing_extensions import Literal

# Types of the transaction fields, used to check fields lengths
u8 = NewType("u8", int)  # 1-byte int
u16 = NewType("u16", int)  # 2-byte int
u32 = NewType("u32", int)  # 4-byte int
u64 = NewType("u64", int)  # 8-byte int
i64 = NewType("i64", int)  # 8-byte int, signed
varint = NewType("varint", int)       # 1-9 bytes
byte = NewType("byte", bytes)         # 1 byte
bytes2 = NewType("bytes2", bytes)     # 2 bytes
bytes4 = NewType("bytes4", bytes)     # 4 bytes
bytes8 = NewType("bytes8", bytes)     # 8 bytes
bytes16 = NewType("bytes16", bytes)   # 16 bytes
bytes32 = NewType("bytes32", bytes)   # 32 bytes
bytes64 = NewType("bytes64", bytes)   # 64 bytes
txtype = NewType("txtype", int)
byteorder = NewType("byteorder", Literal['big', 'little'])


# Types for the supported kinds of transactions. Extend as needed.
class TxType:
    Btc: txtype = 0
    Segwit: txtype = 1
    Bch: txtype = 2
    Zcash: txtype = 3
    ZcashSapling: txtype = 4


class TxHashMode:
    """Hash modes for the BTC app. Encoded on 5 bits:

    ```
    | 0 | 0 | 0 | i | i | i | s | t |
    ```

    With:

    - t: 0 = Hash an untrusted input / 1 = Hash a trusted input
    - s: 0 = Hash input w/o its script / 1 = Hash input with its script
    - iii: Input origin
        - 000 (0): Legacy BTC tx
        - 010 (2): Segwit BTC tx
        - 011 (3): Zcash tx (for tx version >=2 and < 4)
        - 100 (4): Zcash Sapling tx (for tx version >= 4)
        - 101 (5): BCH (Bitcoin Cash) tx (not supported in tests for now?)
    """
    Untrusted: int = 0b00000000
    Trusted: int = 0b00000001
    NoScript: int = 0b00000000
    WithScript: int = 0b00000010

    LegacyBtc: int = (0x00 << 2)
    SegwitBtc: int = (0x02 << 2)
    Zcash: int = (0x03 << 2)
    ZcashSapling: int = (0x04 << 2)
    BitcoinCash: int = (0x05 << 2)

    def __init__(self, hash_mode: int):
        self._hash_mode = hash_mode

    @property
    def is_trusted_input_hash(self) -> bool:
        return self._hash_mode & self.Trusted == self.Trusted

    @property
    def is_hash_with_script(self) -> bool:
        return self._hash_mode & self.WithScript == self.WithScript

    @property
    def is_hash_no_script(self):
        return not self.is_hash_with_script

    @property
    def is_btc_input_hash(self) -> bool:
        return self._hash_mode & 0x1C == 0x00

    @property
    def is_segwit_input_hash(self) -> bool:
        return self._hash_mode & self.SegwitBtc == self.SegwitBtc

    @property
    def is_zcash_input_hash(self) -> bool:
        return self._hash_mode & self.Zcash == self.Zcash

    @property
    def is_sapling_input_hash(self) -> bool:
        return self._hash_mode & self.ZcashSapling == self.ZcashSapling

    @property
    def is_bcash_input_hash(self) -> bool:
        return self._hash_mode & self.BitcoinCash == self.BitcoinCash

    @property
    def is_zcash_or_sapling_input_hash(self) -> bool:
        return self.is_zcash_input_hash or self.is_sapling_input_hash

    @property
    def is_segwit_zcash_or_sapling_input_hash(self) -> bool:
        return self.is_segwit_input_hash or self.is_zcash_or_sapling_input_hash

    @property
    def is_btc_or_bcash_input_hash(self) -> bool:
        return self.is_btc_input_hash or self.is_bcash_input_hash

    @property
    def is_relaxed_input_hash(self) -> bool:
        return not (self.is_trusted_input_hash or self.is_segwit_input_hash or
                    self.is_zcash_input_hash or self.is_sapling_input_hash or
                    self.is_bcash_input_hash)


# Definitions useful for type hints and lengths handling
# Store an integer value and its byte representation, while allowing type checking
class TxInt:
    pass


@dataclass
class TxInt1(TxInt):
    val: u8
    buf: byte


@dataclass
class TxInt2(TxInt):
    val: u16
    buf: bytes2


@dataclass
class TxInt4(TxInt):
    val: u32
    buf: bytes4


@dataclass
class TxInt8(TxInt):
    val: u64
    buf: bytes8


@dataclass
class TxVarInt(TxInt):
    val: varint
    buf: bytes

    @classmethod
    def to_bytes(cls, value: Optional[int], endianness: str = 'big'):
        int_value: int = value if value is not None else cls.val if cls.val is not None else 0
        if int_value < 0xfd:
            return int_value.to_bytes(1, endianness)
        if int_value <= 0xffff:
            bval = int_value.to_bytes(2, endianness)
            return b'\xfd' + bval if endianness == 'big' else bval + b'\xfd'
        if int_value <= 0xffffffff:
            bval = int_value.to_bytes(4, endianness)
            return b'\xff' + bval if endianness == 'big' else bval + b'\xfd'
        raise ValueError(f"Value {int_value} too big to be encoded as a varint")

    @staticmethod
    def from_raw(buf: BytesIO,
                 prefix: Optional[bytes] = None,
                 endianness: byteorder = 'big'):
        """Returns the size encoded as a varint in the next 1 to 9 bytes of buf."""
        b: bytes = prefix if prefix else buf.read(1)
        n: int = {b"\xfd": 2, b"\xfe": 4, b"\xff": 8}.get(b, 1)  # default to 1
        b = buf.read(n) if n > 1 else b

        if len(b) != n:
            raise ValueError("Can't read varint!")
        return TxVarInt(
            val=cast(varint, int.from_bytes(b, endianness)),
            buf=b)


# Dictionaries holding special values introduced by BTC protocol evolution or
# BTC-derivative currencies
@dataclass
class TxExtension:
    """
    Base dictionaries holding the extension values that can be added to the base
    raw transaction by BTC protocol evolution or by BTC-derivative currencies
    Common base class, do not use except as a base class or in a type comparison.
    """
    pass


@dataclass
class TxHeader:
    ext: TxExtension


@dataclass
class TxFooter:
    ext: TxExtension
