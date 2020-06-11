from .txtypes import *
from io import BytesIO, SEEK_CUR, SEEK_END
from copy import deepcopy
from dataclasses import dataclass
from typing import Optional, List, Union, cast, Any, Tuple  # >= 3.6
from hashlib import sha256


@dataclass
class SegwitExtHeader(TxExtension):
    """Stores the Marker & Flag bytes of a segwit-enabled Bitcoin transaction"""
    marker: u8
    flag: u8


@dataclass
class SegwitExtFooter(TxExtension):
    """Stores the witness data of a Segwit-enabled Bitcoin transaction"""
    class WitnessData:
        class Sig:
            r: bytes
            s: bytes
        sig: Sig
        other: bytes
    witness_count: varint
    witness_len: varint
    witness: List[WitnessData]


@dataclass
class ZcashExtHeader(TxExtension):
    """Stores the transaction fields secific to Zcash added to the header of the BTC raw tx"""
    overwintered_flag: bool
    version_group_id: TxInt4


@dataclass
class ZcashExtFooter(TxExtension):
    """Stores the transaction fields secific to Zcash appended to the end of the raw BTC tx"""
    expiry_height: TxInt4
    value_balance: TxInt8
    shielded_spend_count: TxVarInt      # Number of SpendDescription
    shielded_spend: bytes               # 384 bytes per SpendDescription
    shielded_output_count: TxVarInt     # Number of OutputDescription
    shielded_output: bytes              # 648 bytes per OutputDescription
    join_split_count: TxVarInt          # Number of JoinSplit desc
    join_split: bytes                   # 1698 bytes if tx version >= 4 else 1802 bytes if 2 <= version < 4
    join_split_pubkey: bytes32
    join_split_sig: bytes64
    binding_sig: bytes32


# BTC transaction description dictionaries
@dataclass
class TxInput:
    prev_tx_hash: bytes32
    prev_tx_out_index: TxInt4
    script_len: TxVarInt
    script: bytes
    sequence_nb: TxInt4


@dataclass
class TxOutput:
    value: TxInt8
    script_len: TxVarInt
    script: bytes


@dataclass
class Tx:
    """
    Helper class that eases the parsing of a raw unsigned Bitcoin, Bitcoin segwit or Zcash transaction.
    """
    type: txtype
    hash: Optional[str]
    version: TxInt4
    header: Optional[TxHeader]
    input_count: TxVarInt
    inputs: List[TxInput]
    output_count: TxVarInt
    outputs: List[TxOutput]
    lock_time: TxInt4
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
                 endianness: lbstr = 'little') -> Tx:
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
        def _hash(tx: Union[Tx, bytes], show_hashed_items: bool = False) -> str:
            """Double SHA-256 hash a raw tx or a parsed tx. """
            def _recursive_hash_obj(obj: Any,
                                    hasher: Any,
                                    ignored_fields: Union[List, Tuple],
                                    path: list,
                                    show_path: bool = False) -> None:
                """Recursive hashing of all significant items of a composite object.
                This inner function is written in a way could be made to an independent one,
                able to hash the content of any composite dataclass or dict object."""
                if obj is not None and type(obj) is not bytes:
                    # Each items in a list of objects must be parsed entirely
                    if type(obj) is list:
                        for i, item in enumerate(obj):
                            path.append(str(i+1))   # Display the item rank in the list
                            _recursive_hash_obj(item, hasher, ignored_fields, path, show_path)
                            path.pop()
                    else:
                        # Recursively descend into object
                        attrs = list(obj.__dict__.items())
                        for key, value in attrs:
                            # Ignore fields that shan't be hashed
                            if key not in ignored_fields and value is not None and \
                                    type(value) not in (SegwitExtHeader, SegwitExtFooter):
                                tmp = path[:]
                                tmp.append(key)
                                _recursive_hash_obj(getattr(obj, key), hasher, ignored_fields, tmp, show_path)
                else:
                    # Terminal byte object, add it to the hash
                    if show_path:
                        print(f"Adding to hash: {'/'.join(path)} = {cast(bytes, obj).hex()}")
                    hasher.update(cast(bytes, obj))

            h1, h2 = (sha256(), sha256())
            if type(tx) is bytes:
                # Raw tx => hash everything in one go. /!\ Should not be used with a Segwit tx,
                # use a parsed tx object instead for the hash to be correctly computed.
                h1.update(tx)
            elif tx.type == TxType.Segwit:
                # Parsed tx => Recursively hash the items in the tx, ignoring the ones that should not
                # be included in the hash, among which the Segwit marker, flag & witnesses. Change "show_path"
                # argument to True to display the data that is being hashed.
                _recursive_hash_obj(obj=tx, hasher=h1, ignored_fields=('type', 'hash', 'val'),
                                    path=[], show_path=show_hashed_items)
            h2.update(h1.digest())
            tx_hash: str = h2.hexdigest()
            print(f"=> Computed tx hash = {tx_hash}\n")
            return tx_hash

        def _read_varint(buf: BytesIO,
                         prefix: Optional[bytes] = None,
                         bytes_order: lbstr = 'little') -> TxVarInt:
            """Returns the size encoded as a varint in the next 1 to 9 bytes of buf."""
            return TxVarInt.from_raw(buf, prefix, bytes_order)

        def _read_bytes(buf: BytesIO, size: int) -> bytes:
            """Returns the next 'size' bytes read from 'buf'."""
            b: bytes = buf.read(size)

            if len(b) < size:
                raise IOError(f"Cant read {size} bytes in buffer!")
            return b

        def _read_uint(buf: BytesIO,
                       bytes_len: int,
                       bytes_order: lbstr = 'little') -> int:
            """Returns the arbitrary-length integer value encoded in the next 'bytes_len' bytes of 'buf'."""
            b: bytes = buf.read(bytes_len)
            if len(b) < bytes_len:
                raise ValueError(f"Can't read next u{bytes_len * 8} from raw tx!")
            return int.from_bytes(b, bytes_order)

        def _read_u8(buf: BytesIO) -> u8:
            """Returns the next byte in 'buf'."""
            return cast(u8, _read_uint(buf, 1))

        def _read_u16(buf: BytesIO, bytes_order: lbstr = 'little') -> u16:
            """Returns the integer value encoded in the next 2 bytes of 'buf'."""
            return cast(u16, _read_uint(buf, 2, bytes_order))

        def _read_u32(buf: BytesIO, bytes_order: lbstr = 'little') -> u32:
            """Returns the integer value encoded in the next 4 bytes of 'buf'."""
            return cast(u32, _read_uint(buf, 4, bytes_order))

        def _read_tx_int(buf: BytesIO, count: int, bytes_order: lbstr) -> (int, bytes):
            tmp: bytes = _read_bytes(buf, count)
            return int.from_bytes(tmp, bytes_order), deepcopy(tmp)

        def _parse_inputs(buf: BytesIO,
                          in_count: int,
                          bytes_order: lbstr = 'little') -> List[TxInput]:
            """Returns a list of TxInputs containing the raw tx's input fields."""
            _inputs: List[TxInput] = []
            for _ in range(in_count):
                prev_tx_hash: bytes32 = cast(bytes32, _read_bytes(buf, 32))

                int_val, bytes_val = _read_tx_int(buf, 4, bytes_order)
                prev_tx_out_index: TxInt4 = TxInt4(
                    val=cast(u32, int_val),
                    buf=cast(bytes4, bytes_val)
                )
                # TODO: if present, for non-segwit tx, parse into a signatures (r, s, pubkey) object?
                in_script_len: TxVarInt = _read_varint(buf)
                in_script: bytes = _read_bytes(buf, in_script_len.val)

                int_val, bytes_val = _read_tx_int(buf, 4, bytes_order)
                sequence_nb: TxInt4 = TxInt4(
                    val=cast(u32, int_val),
                    buf=cast(bytes4, bytes_val)
                )
                _inputs.append(
                    TxInput(
                        prev_tx_hash=prev_tx_hash,
                        prev_tx_out_index=prev_tx_out_index,
                        script_len=in_script_len,
                        script=in_script,
                        sequence_nb=sequence_nb))
            return _inputs

        def _parse_outputs(buf: BytesIO,
                           out_count: int,
                           bytes_order: lbstr = 'little') -> List[TxOutput]:
            """Returns a list of TxOutputs containing the raw tx's output fields."""
            _outputs: List[TxOutput] = []
            for _ in range(out_count):
                int_val, bytes_val = _read_tx_int(buf, 8, bytes_order)
                value: TxInt8 = TxInt8(
                    val=cast(u64, int_val),
                    buf=cast(bytes8, bytes_val)
                )
                out_script_len: TxVarInt = _read_varint(buf)
                out_script: bytes = _read_bytes(buf, out_script_len.val)
                _outputs.append(
                    TxOutput(
                        value=value,
                        script_len=out_script_len,
                        script=out_script))
            return _outputs

        def _parse_zcash_footer(buf: BytesIO, bytes_order: lbstr = 'little') -> Optional[ZcashExtFooter]:
            expiry_height: Optional[TxInt4] = None
            value_balance: Optional[TxInt8] = None
            shielded_spend_count: Optional[TxVarInt] = None
            shielded_spend: Optional[bytes] = None
            shielded_output_count: Optional[TxVarInt] = None
            shielded_output: Optional[bytes] = None
            join_split_count: Optional[TxVarInt] = None
            join_split: Optional[bytes] = None
            join_split_pubkey: Optional[bytes32] = None
            join_split_sig: Optional[bytes64] = None
            binding_sig: Optional[bytes32] = None

            if version.val >= 3:
                ival, bval = _read_tx_int(buf, 4, bytes_order)
                expiry_height = TxInt4(val=cast(u32, ival), buf=cast(bytes4, bval))
            if version.val >= 4:
                ival, bval = _read_tx_int(buf, 8, bytes_order)
                value_balance = TxInt8(val=cast(u64, ival), buf=cast(bytes8, bval))
                shielded_spend_count = _read_varint(buf, bytes_order=bytes_order)
                shielded_spend = _read_bytes(buf, 384 * shielded_spend_count.val) \
                    if shielded_spend_count.val > 0 else None
                shielded_output_count = _read_varint(buf, bytes_order=bytes_order)
                shielded_output = _read_bytes(buf, 948 * shielded_output_count.val) \
                    if shielded_output_count.val > 0 else None
            if version.val >= 2:
                join_split_count = _read_varint(buf, bytes_order=bytes_order)
                join_split = _read_bytes(buf, (1698 if version.val >= 4 else 1802) * shielded_output_count.val) \
                             if join_split_count.val > 0 else None
            if version.val >= 2 and join_split_count.val > 0:
                join_split_pubkey = cast(bytes32, _read_bytes(buf, 32))
                join_split_sig = cast(bytes64, _read_bytes(buf, 64))
            if version.val >= 4 and shielded_spend_count.val + shielded_output_count.val > 0:
                binding_sig = cast(bytes32, _read_bytes(buf, 32))

            return ZcashExtFooter(
                expiry_height=expiry_height,
                value_balance=value_balance,
                shielded_spend_count=shielded_spend_count,
                shielded_spend=shielded_spend,
                shielded_output_count=shielded_output_count,
                shielded_output=shielded_output,
                join_split_count=join_split_count,
                join_split=join_split,
                join_split_pubkey=join_split_pubkey,
                join_split_sig=join_split_sig,
                binding_sig=binding_sig)

        def _tx_type(buf: BytesIO) -> txtype:
            """Test if special bytes are present, marking the BTC tx as either a segwit tx or
            a tx for a Bitcoin-derived currency (e.g. Zcash)"""
            typ: txtype = TxType.Btc
            stream_pos: int = buf.tell()
            buf.seek(4)   # Reset stream position to right afer tx version

            byte0: Optional[u8] = _read_u8(buf)
            byte1: Optional[u8] = _read_u8(buf)

            if (byte0, byte1) == (0x00, 0x01):
                # Either segwit tx or legacy coinbase tx =>if coinbase, byte1 is the output count (1 output)
                buf.seek(8, SEEK_CUR)                       # If coinbase tx, skip coinbase output value
                coinb_num_bytes_to_end = _read_u8(buf) + 4  # Compute theoretical remaining bytes to end of tx
                pos_cur = buf.tell()
                pos_end = buf.seek(0, SEEK_END)
                if pos_end - pos_cur != coinb_num_bytes_to_end:
                    typ = TxType.Segwit
            elif (byte0, byte1) == (0x70, 0x82):  # 1st two bytes of pre-Sapling (OVW) versionGroupId little endian
                bytes2_3: Optional[u16] = _read_u16(buf, 'big')
                if bytes2_3 == 0xc403:
                    typ = TxType.Zcash
            elif (byte0, byte1) == (0x85, 0x20):  # 1st two bytes of Sapling versionGroupId, little endian
                bytes2_3: Optional[u16] = _read_u16(buf, 'big')
                if bytes2_3 == 0x2f89:
                    typ = TxType.ZcashSapling

            buf.seek(stream_pos)
            return typ

        #
        # Transaction parsing code starts here
        #
        raw_tx_bytes: bytes = bytes.fromhex(raw_tx) if type(raw_tx) == str else raw_tx
        io_buf: BytesIO = BytesIO(raw_tx_bytes)
        ivers, bvers = _read_tx_int(io_buf, 4, endianness)
        version: TxInt4 = TxInt4(
            val=cast(u32, ivers & ~0x80000000),     # Remove overwinter flag is present
            buf=cast(bytes4, bvers)
        )
        tx_type: txtype = _tx_type(io_buf)

        marker: Optional[u8] = None
        flag: Optional[u8] = None
        version_group_id: Optional[TxInt4] = None
        overwintered_flag: bool = False

        if tx_type == TxType.Segwit:
            marker = _read_u8(io_buf)
            flag = _read_u8(io_buf)
        elif tx_type in (TxType.Zcash, TxType.ZcashSapling):
            ival, bval = _read_tx_int(io_buf, 4, endianness)
            version_group_id = TxInt4(
                val=cast(u32, ival),
                buf=cast(bytes4, bval)
            )
            overwintered_flag = True if ivers & 0x80000000 else False

        input_count: TxVarInt = _read_varint(io_buf)
        inputs: List[TxInput] = _parse_inputs(io_buf, input_count.val)
        output_count: TxVarInt = _read_varint(io_buf)
        outputs: List[TxOutput] = _parse_outputs(io_buf, output_count.val)
        if tx_type == TxType.Segwit:
            # TODO: If present read witnesses & parse into a signatures (r, s, pubkey) object
            io_buf.seek(-4, SEEK_END)    # For now, skip all witnesses to access locktime
        ival, bval = _read_tx_int(io_buf, 4, endianness)
        lock_time: TxInt4 = TxInt4(
            val=cast(u32, ival),
            buf=cast(bytes4, bval)
        )

        zcash_footer: Optional[ZcashExtFooter] = None
        if tx_type in (TxType.Zcash, TxType.ZcashSapling):
            zcash_footer: ZcashExtFooter = _parse_zcash_footer(io_buf, endianness)

        parsed_tx = Tx(
            type=tx_type,
            hash=None,      # Will be set just before returning
            version=version,
            header=TxHeader(
                ext=SegwitExtHeader(
                    marker=marker,
                    flag=flag) if tx_type == TxType.Segwit
                else ZcashExtHeader(
                    overwintered_flag=overwintered_flag,
                    version_group_id=version_group_id) if tx_type in (TxType.Zcash, TxType.ZcashSapling)
                else None
            ),
            input_count=input_count,
            inputs=inputs,
            output_count=output_count,
            outputs=outputs,
            lock_time=lock_time,
            footer=TxFooter(
                ext=zcash_footer if tx_type in (TxType.Zcash, TxType.ZcashSapling) else None
            )
        )
        parsed_tx.hash = _hash(parsed_tx) if parsed_tx.type == TxType.Segwit else _hash(raw_tx_bytes)
        return parsed_tx
