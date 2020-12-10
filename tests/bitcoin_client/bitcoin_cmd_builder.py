import enum
import logging
import struct
from typing import Optional, List, Tuple, Iterator, Union, cast

from bitcoin_client.hwi.serialization import CTransaction, ser_compact_size
from bitcoin_client.utils import chunkify, MAX_APDU_LEN
from bitcoin_client.bitcoin_utils import bip32_path_from_string


class InsType(enum.IntEnum):
    """Instruction commands supported."""

    GET_RANDOM = 0xC0
    GET_FIRMWARE_VERSION = 0xC4
    GET_COIN_VERSION = 0x16
    GET_WALLET_PUBLIC_KEY = 0x40
    GET_TRUSTED_INPUT = 0x42
    UNTRUSTED_HASH_TRANSACTION_INPUT_START = 0x44
    UNTRUSTED_HASH_TRANSACTION_INPUT_FINALIZE = 0x4A
    UNTRUSTED_HASH_SIGN = 0x48


class AddrType(enum.IntEnum):
    """Type of Bitcoin address."""

    Legacy = 0x00
    P2SH_P2WPKH = 0x01
    BECH32 = 0x02


class BitcoinCommandBuilder:
    """APDU command builder for the Bitcoin application.

    Parameters
    ----------
    debug : bool
        Whether you want to see logging or not.

    Attributes
    ----------
    debug : bool
        Whether you want to see logging or not.

    """

    CLA: int = 0xE0

    def __init__(self, debug: bool = False):
        """Init constructor."""
        self.debug = debug

    def serialize(self,
                  cla: int,
                  ins: Union[int, enum.IntEnum],
                  p1: int = 0,
                  p2: int = 0,
                  cdata: bytes = b"") -> bytes:
        """Serialize the whole APDU command (header + cdata).

        Parameters
        ----------
        cla : int
            Instruction class: CLA (1 byte)
        ins : Union[int, IntEnum]
            Instruction code: INS (1 byte)
        p1 : int
            Instruction parameter 1: P1 (1 byte).
        p2 : int
            Instruction parameter 2: P2 (1 byte).
        cdata : bytes
            Bytes of command data.

        Returns
        -------
        bytes
            Bytes of a complete APDU command.

        """
        ins = cast(int, ins.value) if isinstance(ins, enum.IntEnum) else cast(int, ins)

        header: bytes = struct.pack("BBBBB",
                                    cla,
                                    ins,
                                    p1,
                                    p2,
                                    len(cdata))  # add Lc to APDU header

        if self.debug:
            logging.info("header: %s", header.hex())
            logging.info("cdata:  %s", cdata.hex())

        return header + cdata

    def get_random(self, n: int = 248) -> bytes:
        """Command builder for GET_RANDOM.

        Parameters
        ----------
        n : int
            Number of bytes (1 <= n <= 248).

        Returns
        -------
        bytes
            APDU command for GET_RANDOM.

        """
        return self.serialize(cla=self.CLA,
                              ins=InsType.GET_RANDOM,
                              p1=0x00,
                              p2=0x00,
                              cdata=b"\x00" * n)

    def get_firmware_version(self) -> bytes:
        """Command builder for GET_FIRMWARE_VERSION.

        Returns
        -------
        bytes
            APDU command for GET_FIMWARE_VERSION.

        """
        ins: InsType = InsType.GET_FIRMWARE_VERSION
        p1: int = 0x00
        p2: int = 0x00

        return self.serialize(cla=self.CLA, ins=ins, p1=p1, p2=p2, cdata=b"")

    def get_coin_version(self) -> bytes:
        """Command builder for GET_COIN_VERSION.

        Returns
        -------
        bytes
            APDU command for GET_COIN_VERSION.

        """
        ins: InsType = InsType.GET_COIN_VERSION
        p1: int = 0x00
        p2: int = 0x00

        return self.serialize(cla=self.CLA, ins=ins, p1=p1, p2=p2, cdata=b"")

    def get_public_key(self,
                       addr_type: AddrType,
                       bip32_path: str,
                       display: bool = False) -> bytes:
        """Command builder for GET_WALLET_PUBLIC_KEY.

        Parameters
        ----------
        addr_type : AddrType
            The type of address expected in the response. Could be Legacy (0x00),
            P2SH-P2WPKH (0x01) or BECH32 encoded P2WPKH (0x02).
        bip32_path : str
            String representation of BIP32 path (e.g. "m/44'/0'/0'/0" or "44'/0'/0'/0").
        display : bool
            Whether you want to display address and ask confirmation on the device.

        Returns
        -------
        bytes
            APDU command for GET_WALLET_PUBLIC_KEY.

        """
        ins: InsType = InsType.GET_WALLET_PUBLIC_KEY
        # P1:
        # - 0x00, do not display the address
        # - 0x01, display the address
        # - 0x02, display the validation token (unused here)
        p1: int = 0x01 if display else 0x00
        # P2: type of Bitcoin address in the reponse
        p2: int = addr_type.value

        path: List[bytes] = bip32_path_from_string(bip32_path)

        cdata: bytes = b"".join([
            len(path).to_bytes(1, byteorder="big"),
            *path
        ])

        return self.serialize(cla=self.CLA, ins=ins, p1=p1, p2=p2, cdata=cdata)

    def get_trusted_input(self,
                          utxo: CTransaction,
                          output_index: int) -> Iterator[bytes]:
        """Command builder for GET_TRUSTED_INPUT.

        Parameters
        ----------
        utxo: CTransaction
            Unspent Transaction Output (UTXO) serialized.
        output_index: int
            Output index owned in the UTXO.

        Yields
        ------
        bytes
            APDU command chunk for GET_TRUSTED_INPUT.

        """
        ins: InsType = InsType.GET_TRUSTED_INPUT
        # P1:
        # - 0x00, first transaction data chunk
        # - 0x80, other transaction data chunk
        p1: int
        p2: int = 0x00

        cdata: bytes = (output_index.to_bytes(4, byteorder="big") +
                        utxo.serialize_without_witness())

        for i, (is_last, chunk) in enumerate(chunkify(cdata, MAX_APDU_LEN)):
            p1 = 0x00 if i == 0 else 0x80
            if is_last:
                yield self.serialize(cla=self.CLA,
                                     ins=ins,
                                     p1=p1,
                                     p2=p2,
                                     cdata=chunk)
                return
            yield self.serialize(cla=self.CLA,
                                 ins=ins,
                                 p1=p1,
                                 p2=p2,
                                 cdata=chunk)

    def untrusted_hash_tx_input_start(self,
                                      tx: CTransaction,
                                      inputs: List[Tuple[CTransaction, bytes]],
                                      input_index: int,
                                      script: bytes,
                                      is_new_transaction: bool
                                      ) -> Iterator[bytes]:
        """Command builder for UNTRUSTED_HASH_TRANSACTION_INPUT_START.

        Parameters
        ----------
        tx: CTransaction
            Serialized Bitcoin transaction to sign.
        inputs: List[Tuple[CTransaction, bytes]]
            List of inputs with pair of UTXO and trusted input.
        input_index: int
            Index of the input to process.
        script : bytes
            The scriptSig to add at `input_index`.
        is_new_transaction: bool
            First time sending this input.

        Yields
        -------
        bytes
            APDU command chunk for UNTRUSTED_HASH_TRANSACTION_INPUT_START.

        """
        ins: InsType = InsType.UNTRUSTED_HASH_TRANSACTION_INPUT_START
        # P1:
        # - 0x00, first transaction data chunk
        # - 0x80, other transaction data chunk
        p1: int = 0x00
        # P2:
        # - 0x80, new transaction
        # - 0x02, new transaction with segwit input
        p2: int = 0x02 if is_new_transaction else 0x80

        cdata: bytes = (tx.nVersion.to_bytes(4, byteorder="little") +
                        ser_compact_size(len(inputs)))

        yield self.serialize(cla=self.CLA,
                             ins=ins,
                             p1=p1,
                             p2=p2,
                             cdata=cdata)

        p1 = 0x80
        for i, (_, trusted_input) in enumerate(inputs):
            script_sig: bytes = script if i == input_index else b""
            cdata = b"".join([
                b"\x01",  # 0x01 for trusted input, 0x02 for witness, 0x00 otherwise
                len(trusted_input).to_bytes(1, byteorder="big"),
                trusted_input,
                ser_compact_size(len(script_sig))
            ])

            yield self.serialize(cla=self.CLA,
                                 ins=ins,
                                 p1=p1,
                                 p2=p2,
                                 cdata=cdata)

            yield self.serialize(cla=self.CLA,
                                 ins=ins,
                                 p1=p1,
                                 p2=p2,
                                 cdata=(script_sig +
                                        0xfffffffd.to_bytes(4, byteorder="little")))

    def untrusted_hash_tx_input_finalize(self,
                                         tx: CTransaction,
                                         change_path: Optional[str]
                                         ) -> Iterator[bytes]:
        """Command builder for UNTRUSTED_HASH_TRANSACTION_INPUT_FINALIZE.

        Parameters
        ----------
        tx: CTransaction
            Transaction to sign.
        change_path: Optional[str]
            BIP32 path for the change.

        Yields
        -------
        bytes
            APDU command chunk for UNTRUSTED_HASH_TRANSACTION_INPUT_FINALIZE.

        """
        ins: InsType = InsType.UNTRUSTED_HASH_TRANSACTION_INPUT_FINALIZE
        # P1:
        # - 0x00, more input chunk to be sent
        # - 0x80, last chunk to be sent
        # - 0xFF, BIP32 path for the change address
        p1: int
        p2: int = 0x00

        p1 = 0xFF
        if change_path:
            bip32_change_path: List[bytes] = bip32_path_from_string(change_path)
            cdata: bytes = b"".join([
                len(bip32_change_path).to_bytes(1, byteorder="big"),
                *bip32_change_path
            ])
            yield self.serialize(cla=self.CLA, ins=ins, p1=p1, p2=p2, cdata=cdata)
        else:
            yield self.serialize(cla=self.CLA, ins=ins, p1=p1, p2=p2, cdata=b"\x00")

        vout_num = len(tx.vout)
        p1 = 0x00
        yield self.serialize(cla=self.CLA,
                             ins=ins,
                             p1=p1,
                             p2=p2,
                             cdata=ser_compact_size(vout_num))

        for i, ctxout in enumerate(tx.vout):
            p1 = 0x00 if i < vout_num - 1 else 0x80
            yield self.serialize(cla=self.CLA,
                                 ins=ins,
                                 p1=p1,
                                 p2=p2,
                                 cdata=ctxout.serialize())

    def untrusted_hash_sign(self,
                            sign_path: str,
                            lock_time: int = 0,
                            sig_hash: int = 1) -> bytes:
        """Command builder for UNTRUSTED_HASH_SIGN.

        Parameters
        ----------
        sign_path : str
            BIP32 path to be used to sign.
        lock_time : int
            Block height or timestamp when transaction is final.
        sig_hash : int
            Either SIGHASH_ALL (0x01), SIGHASH_NONE (0x02) or SIGHASH_SINGLE (0x03).
            Only SIGHASH_ALL (0x01) is supported.

        Returns
        -------
        bytes
            APDU command for UNTRUSTED_HASH_SIGN.

        """
        ins: InsType = InsType.UNTRUSTED_HASH_SIGN
        p1: int = 0x00
        p2: int = 0x00

        bip32_path: List[bytes] = bip32_path_from_string(sign_path)
        cdata: bytes = b"".join([
            len(bip32_path).to_bytes(1, byteorder="big"),
            *bip32_path,
            b"\00",  # unused (Reserved for Future Use)
            lock_time.to_bytes(4, byteorder="big"),  # /!\ big instead of little
            sig_hash.to_bytes(1, byteorder="big")
        ])

        return self.serialize(cla=self.CLA, ins=ins, p1=p1, p2=p2, cdata=cdata)
