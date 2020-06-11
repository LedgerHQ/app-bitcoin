from io import BytesIO
from typing import Optional, List, NewType, Union, Literal, cast

try:
    from typing import TypedDict  # >=3.8
except ImportError:
    from mypy_extensions import TypedDict  # <=3.7

# Types of the transaction fields, used to check fields lengths
u8 = NewType("u8", int)  # 1 byte
u16 = NewType("u16", int)  # 2 bytes
u32 = NewType("u32", int)  # 4 bytes
u64 = NewType("u64", int)  # 8 bytes
i64 = NewType("i64", int)  # 8 bytes
varint = NewType("varint", int)  # 1-9 bytes
bytes32 = NewType("bytes32", type(bytes(32)))  # 32 bytes
bytes64 = NewType("bytes32", type(bytes(64)))  # 64 bytes
txtype = NewType("txtype", int)


# Types for the supported kinds of transactions. Extend as needed.
class TxType:
    btc: txtype = 0
    segwit: txtype = 1
    zcash: txtype = 2


# Dictionaries holding special values introduced by BTC protocol evolution or
# BTC-derivative currencies
class SpecialFields(TypedDict):
    """
    Base dictionaries holding the special values that can be added to the base raw
    transaction by BTC protocol evolution or by BTC-derivative currencies
    Common base class, do not use except as a base class or in a type comparison.
    """
    pass


class SpecialSegwit(SpecialFields):
    """
    Stores the Marker & Flag bytes of a segwit-enabled Bitcoin transaction
    """
    marker: u8
    flag: u8


class SpecialZcashHeader(SpecialFields):
    """
    Stores the transaction fields secific to Zcash added to the header of the BTC raw tx
    """
    overwintered_flag: bool
    version_group_id: u32


class SpecialZcashFooter(SpecialFields):
    """
    Stores the transaction fields secific to Zcash appended to the end of the raw BTC tx
    """
    expiry_height: u32
    # All remaining Zcash-specific fields (value_balance, shielded_spend, shielded_output,
    # join_split, binding_sig) are hashed as a single bloc by the BTC app so we don't need to
    # to differentiate each field
    extra_data: bytes


# BTC transaction description dictionaries
class TxHeader(TypedDict):
    """
    Raw transaction header fields
    """
    version: u32
    special: SpecialFields


class TxFooter(SpecialFields):
    special: SpecialFields


class TxInput(TypedDict):
    prev_tx_hash: bytes
    prev_tx_out_index: u32
    script_len: varint
    script: bytes
    sequence_no: u32


class TxOutput(TypedDict):
    value: u64
    script_len: varint
    script: bytes


class Tx(TypedDict):
    """
    Helper class that eases the parsing of a raw unsigned Bitcoin, Bitcoin segwit or Zcash transaction.
    """
    type: txtype
    header: TxHeader
    input_count: varint
    inputs: List[TxInput]
    output_count: varint
    outputs: List[TxOutput]
    lock_time: u32
    footer: Optional[TxFooter]


class TxParse:
    """
    Bitcoin and Bitcoin-derived raw transaction parser.

    Usage:

        - Parse the raw tx into a Python TypedDict object:
            ``parsed_tx = TxParse.from_raw(raw_btc_tx)``
    """

    @classmethod
    def from_raw(cls,
                 raw_tx: Union[bytes, str],
                 endianness: Literal['big', 'little'] = 'little') -> Tx:
        """
        Returns a TX object with members initialized from the parsing of the rawTx parameter

        :param raw_tx: The raw transaction to parse. Supported transactions types are:
            Bitcoin, Bitcoin Segwit, Zcash

        :param endianness: The endianness of values in the raw tx among 'little' or 'big'.
            Defaults to 'little' (i.e. BTC & derivatives).

        :return: A Tx class (of type TypedDict) with all members initialized.
        :raise ValueError: If the transaction is malformed or is of an unsupported type.
        """

        # Internal utilities
        def _read_varint(buf: BytesIO,
                         prefix: Optional[bytes] = None,
                         bytes_order: Literal['big', 'little'] = 'little') -> varint:
            """Returns the size encoded as a varint in the next 1 to 9 bytes of buf."""
            b: bytes = prefix if prefix else buf.read(1)
            n: int = {b"\xfd": 2, b"\xfe": 4, b"\xff": 8}.get(b, 1)  # default to 1
            b = buf.read(n) if n > 1 else b

            if len(b) != n:
                raise ValueError("Can't read varint!")
            return cast(varint, int.from_bytes(b, bytes_order))

        def _read_bytes(buf: BytesIO, size: int) -> bytes:
            """Returns the next 'size' bytes read from 'buf'."""
            b: bytes = buf.read(size)

            if len(b) < size:
                raise ValueError(f"Cant read {size} bytes in buffer!")
            return b

        def _read_uint(buf: BytesIO,
                       bytes_len: int,
                       bytes_order: Literal['big', 'little'] = 'little') -> int:
            """Returns the arbitrary-length integer value encoded in the next 'bytes_len' bytes of 'buf'."""
            b: bytes = buf.read(bytes_len)
            if len(b) < bytes_len:
                raise ValueError(f"Can't read next u{bytes_len * 8} from raw tx!")
            return int.from_bytes(b, bytes_order)

        def _read_u8(buf: BytesIO) -> u8:
            """Returns the next byte in 'buf'."""
            return cast(u8, _read_bytes(buf, 1))

        def _read_u16(buf: BytesIO, bytes_order: Literal['big', 'little'] = 'little') -> u16:
            """Returns the integer value encoded in the next 2 bytes of 'buf'."""
            return cast(u16, _read_uint(buf, 2, bytes_order))

        def _read_u32(buf: BytesIO, bytes_order: Literal['big', 'little'] = 'little') -> u32:
            """Returns the integer value encoded in the next 4 bytes of 'buf'."""
            return cast(u32, _read_uint(buf, 4, bytes_order))

        def _read_u64(buf: BytesIO, bytes_order: Literal['big', 'little'] = 'little') -> u64:
            """Returns the integer value encoded in the next 8 bytes of 'buf'.
            """
            return cast(u64, _read_uint(buf, 8, bytes_order))

        def _parse_inputs(buf: BytesIO, in_count: int) -> List[TxInput]:
            """Returns a list of TxInputs containing the raw tx's input fields."""
            _inputs: List[TxInput] = []
            for _ in range(in_count):
                prev_tx_hash: bytes = _read_bytes(buf, 32)
                prev_tx_out_index: u32 = _read_u32(buf)
                in_script_len: varint = _read_varint(buf)
                in_script: bytes = _read_bytes(buf, in_script_len)
                sequence_no: u32 = _read_u32(buf)
                _inputs.append(
                    TxInput(
                        prev_tx_hash=prev_tx_hash,
                        prev_tx_out_index=prev_tx_out_index,
                        script_len=in_script_len,
                        script=in_script,
                        sequence_no=sequence_no))
            return _inputs

        def _parse_outputs(buf: BytesIO, out_count: int) -> List[TxOutput]:
            """Returns a list of TxOutputs containing the raw tx's output fields."""
            _outputs: List[TxOutput] = []
            for _ in range(out_count):
                value: u64 = _read_u64(buf)
                out_script_len: varint = _read_varint(buf)
                out_script: bytes = _read_bytes(buf, out_script_len)
                _outputs.append(
                    TxOutput(
                        value=value,
                        script_len=out_script_len,
                        script=out_script))
            return _outputs

        def _tx_type(buf: BytesIO) -> txtype:
            """Test if special bytes are present, marking the BTC tx as either a segwit tx or
            a tx for a Bitcoin-derived currency (e.g. Zcash)"""
            typ: txtype = TxType.btc
            stream_pos: int = buf.tell()
            buf.seek(0)

            byte0: Optional[u8] = _read_u8(buf)
            byte1: Optional[u8] = _read_u8(buf)
            if byte0 == b"\x00" and byte1 == b'\x01':
                # Either segwit tx or legacy coinbase tx =>if coinbase, byte1 is the output count (1 byte)
                buf.seek(8)
                buf.seek(_read_u8(buf) + 4)  # If a coinbase tx, stream pointer is at the end of the stream now
                if buf.read(1):
                    typ = TxType.segwit
            elif byte0 == b'\0x85' and byte1 == b'\x20':  # 1st two bytes of zcash special bytes
                bytes2_3: Optional[u16] = _read_u16(buf, 'big')
                if bytes2_3 == b'\x2f89':
                    typ = TxType.zcash

            buf.seek(stream_pos)
            return typ

        #
        # Transaction parsing code starts here
        #
        io_buf: BytesIO = BytesIO(bytes.fromhex(raw_tx)) if type(raw_tx) == str else BytesIO(raw_tx)
        version: u32 = _read_u32(io_buf, endianness)
        tx_type: txtype = _tx_type(io_buf)

        marker: Optional[u8] = None
        flag: Optional[u8] = None
        version_group_id: Optional[u32] = None
        overwintered_flag: bool = False
        expiry_height: Optional[u32] = None
        extra_data: Optional[bytes] = None

        if tx_type == TxType.segwit:
            marker = _read_u8(io_buf)
            flag = _read_u8(io_buf)
        elif tx_type == TxType.zcash:
            version_group_id = _read_u32(io_buf, endianness)
            overwintered_flag = True if version_group_id & 0x80000000 else False

        input_count: varint = _read_varint(io_buf)
        inputs: List[TxInput] = _parse_inputs(io_buf, input_count)
        output_count: varint = _read_varint(io_buf)
        outputs: List[TxOutput] = _parse_outputs(io_buf, output_count)
        lock_time: u32 = _read_u32(io_buf)

        if tx_type == TxType.zcash:
            expiry_height: Optional[u32] = _read_u32(io_buf)
            extra_data: Optional[bytes] = _read_bytes(io_buf, -1)  # read up to EOF

        return Tx(
            type=tx_type,
            header=TxHeader(
                version=version,
                special=SpecialSegwit(
                    marker=marker,
                    flag=flag) if tx_type == TxType.segwit
                else SpecialZcashHeader(
                    overwintered_flag=overwintered_flag,
                    version_group_id=version_group_id) if tx_type == TxType.zcash
                else None
            ),
            input_count=input_count,
            inputs=inputs,
            output_count=output_count,
            outputs=outputs,
            lock_time=lock_time,
            footer=TxFooter(
                special=SpecialZcashFooter(
                    expiry_height=expiry_height,
                    extra_data=extra_data) if tx_type == TxType.zcash
                else None
            )
        )
