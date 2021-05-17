import struct
from typing import Tuple, List, Optional

from ledgercomm import Transport

from bitcoin_client.hwi.serialization import CTransaction, hash256
from bitcoin_client.exception.device_exception import DeviceException
from bitcoin_client.bitcoin_cmd_builder import AddrType, InsType, BitcoinCommandBuilder


class BitcoinBaseCommand:
    """Bitcoin Base Command.

    Send APDU command to device and get APDU response.

    Parameters
    ----------
    transport : Transport
        Transport interface to the device.
    debug : bool
        Whether you want to see logging or not.

    Attributes
    ----------
    transport : Transport
        Transport interface to send APDUs.
    builder : BitcoinCommandBuilder
        Command builder to construct APDUs.

    """

    def __init__(self, transport: Transport, debug: bool = False) -> None:
        """Init constructor."""
        self.transport = transport
        self.builder = BitcoinCommandBuilder(debug=debug)

    def get_random(self, n: int = 5) -> bytes:
        """Get `n` bytes random value.

        Parameters
        ----------
        n : int
            Number of bytes (5 <= n <= 248).

        Returns
        -------
        bytes
            Random bytes of length `n` from the device.

        """
        sw, response = self.transport.exchange_raw(
            self.builder.get_random(n=n)
        )

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=InsType.GET_RANDOM)

        return response

    def get_firmware_version(self) -> Tuple[int, int, int]:
        """Get the version of the application.

        Returns
        -------
        Tuple[int, int, int]
            (MAJOR, MINOR, PATCH) version of the application.

        """
        sw, response = self.transport.exchange_raw(
            self.builder.get_firmware_version()
        )

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=InsType.GET_FIRMWARE_VERSION)

        # response = flag (1) [unused] ||
        #            architecture id (1) [unused] ||
        #            major version of the application (1) ||
        #            minor version of the application (1) ||
        #            patch version of the application (1) ||
        #            loader id major version (1) [unused] ||
        #            loader id minor version (1) [unused] ||
        #            mode (1) [unused]
        _, _, major, minor, patch, _, _, _ = struct.unpack(
            "BBBBBBBB",
            response
        )  # type: int, int, int, int, int, int, int, int

        return major, minor, patch

    def get_coin_version(self) -> Tuple[int, int, int, str, str]:
        """Get coin information depending on Bitcoin app fork.

        Returns
        -------
        Tuple[int, int, int, str, str]
            A tuple (p2pkh_pref, p2sh_prefix, coin_family, coin_name, coin_ticker).

        """
        sw, response = self.transport.exchange_raw(
            self.builder.get_coin_version()
        )  # type: int, bytes

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=InsType.GET_COIN_VERSION)

        # response = p2pkh_prefix (2) || p2sh_prefix (2) || coin_family (1) ||
        #            len(coin_name) (1) || coin_name (var) ||
        #            len(coin_ticker) (1) || coin_ticker (var)
        offset: int = 0
        p2pkh_prefix: int = int.from_bytes(response[offset:offset + 2], byteorder="big")
        offset += 2
        p2sh_prefix: int = int.from_bytes(response[offset:offset + 2], byteorder="big")
        offset += 2
        coin_family: int = response[offset]
        offset += 1
        coin_name_len: int = response[offset]
        offset += 1
        coin_name: str = response[offset:offset + coin_name_len].decode("ascii")
        offset += coin_name_len
        coin_ticker_len: int = response[offset]
        offset += 1
        coin_ticker: str = response[offset:offset + coin_ticker_len].decode("ascii")
        offset += coin_ticker_len

        assert len(response) == offset

        return p2pkh_prefix, p2sh_prefix, coin_family, coin_name, coin_ticker

    def get_public_key(self,
                       addr_type: AddrType,
                       bip32_path: str,
                       display: bool = False) -> Tuple[bytes, str, bytes]:
        """Get public key given address type and BIP32 path.

        Parameters
        ----------
        addr_type : AddrType
            Type of address. Could be AddrType.Legacy, AddrType.P2SH_P2WPKH,
            AddrType.BECH32.
        bip32_path : str
            BIP32 path of the public key you want.
        display : bool
            Whether you want to display address and ask confirmation on the device.

        Returns
        -------

        """
        sw, response = self.transport.exchange_raw(
            self.builder.get_public_key(addr_type=addr_type,
                                        bip32_path=bip32_path,
                                        display=display)
        )  # type: int, bytes

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=InsType.GET_WALLET_PUBLIC_KEY)

        # response = len(pub_key) (1) || pub_key (var) ||
        #            len(addr) (1) || addr (var) || bip32_chain_code (32)
        offset: int = 0
        pub_key_len: int = response[offset]
        offset += 1
        pub_key: bytes = response[offset:offset + pub_key_len]
        offset += pub_key_len
        addr_len: int = response[offset]
        offset += 1
        addr: str = response[offset:offset + addr_len].decode("ascii")
        offset += addr_len
        bip32_chain_code: bytes = response[offset:offset + 32]
        offset += 32

        assert len(response) == offset

        return pub_key, addr, bip32_chain_code

    def get_trusted_input(self,
                          utxo: CTransaction,
                          output_index: int) -> bytes:
        """Get trusted input given UTXO and output index.

        Parameters
        ----------
        utxo : CTransaction
            Serialized Bitcoin transaction to extract UTXO.
        output_index : int
            Index of the UTXO to build the trusted input.

        Returns
        -------
        bytes
            Serialized trusted input.

        """
        sw: int
        response: bytes = b""

        for chunk in self.builder.get_trusted_input(utxo, output_index):
            self.transport.send_raw(chunk)
            sw, response = self.transport.recv()  # type: int, bytes

            if sw != 0x9000:
                raise DeviceException(error_code=sw, ins=InsType.GET_TRUSTED_INPUT)

        # response = 0x32 (1) || 0x00 (1) || random (2) || prev_txid (32) ||
        #            output_index (4) || amount (8) || HMAC (8)
        assert len(response) == 56

        offset: int = 0
        magic_trusted_input: int = response[offset]
        assert magic_trusted_input == 0x32
        offset += 1
        zero: int = response[offset]
        assert zero == 0x00
        offset += 1
        _: bytes = response[offset:offset + 2]  # random
        offset += 2
        prev_txid: bytes = response[offset:offset + 32]
        assert prev_txid == hash256(utxo.serialize_without_witness())
        offset += 32
        out_index: int = int.from_bytes(response[offset:offset + 4],
                                        byteorder="little")
        assert out_index == output_index
        offset += 4
        amount: int = int.from_bytes(response[offset:offset + 8],
                                     byteorder="little")
        assert amount == utxo.vout[output_index].nValue
        offset += 8
        _: bytes = response[offset:offset + 8]  # HMAC
        offset += 8

        assert offset == len(response)

        return response

    def untrusted_hash_tx_input_start(self,
                                      tx: CTransaction,
                                      inputs: List[Tuple[CTransaction, bytes]],
                                      input_index: int,
                                      script: bytes,
                                      is_new_transaction: bool) -> None:
        """Send trusted inputs to build the new transaction.

        Parameters
        ----------
        tx : CTransaction
            Serialized Bitcoin transaction to sign.
        inputs : List[Tuple[CTransaction, bytes]]
            List of inputs with pair of UTXO and trusted input.
        input_index : int
            Index of the input to process.
        script : bytes
            The scriptSig to add at `input_index`.
        is_new_transaction: bool
            First time sending this input.

        Returns
        -------
        None

        """
        sw: int

        for chunk in self.builder.untrusted_hash_tx_input_start(tx=tx,
                                                                inputs=inputs,
                                                                input_index=input_index,
                                                                script=script,
                                                                is_new_transaction=is_new_transaction):
            self.transport.send_raw(chunk)
            sw, _ = self.transport.recv()  # type: int, bytes

            if sw != 0x9000:
                raise DeviceException(
                    error_code=sw,
                    ins=InsType.UNTRUSTED_HASH_TRANSACTION_INPUT_START
                )

    def untrusted_hash_tx_input_finalize(self,
                                         tx: CTransaction,
                                         change_path: Optional[str]) -> bytes:
        """Send transaction outputs to finalize the new transaciton.

        Parameters
        ----------
        tx: CTransaction
            Transaction to sign.
        change_path: Optional[str]
            BIP32 path for the change.

        Returns
        -------
        bytes
            Two bytes Reserved for Future Use (RFU) and transaction validation flag.
            Unused, always 0x00 and 0x00.


        """
        sw: int
        response: bytes = b""

        for chunk in self.builder.untrusted_hash_tx_input_finalize(tx=tx,
                                                                   change_path=change_path):
            self.transport.send_raw(chunk)
            sw, response = self.transport.recv()

            if sw != 0x9000:
                raise DeviceException(
                    error_code=sw,
                    ins=InsType.UNTRUSTED_HASH_TRANSACTION_INPUT_FINALIZE
                )
        # response = RFU (1) || User validation flag (1)
        return response

    def untrusted_hash_sign(self,
                            sign_path: str,
                            lock_time: int = 0,
                            sig_hash: int = 1) -> Tuple[int, bytes]:
        """Sign input just sent using `sign_path`.

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
        Tuple[int, bytes]
            A pair (v, der_sig) with:
            - v: 0x01 if y-coordinate of R is odd, 0x00 otherwise.
            - der_sig: DER encoded Bitcoin ECDSA signature (with SIGHASH).

        """
        sw, response = self.transport.exchange_raw(
            self.builder.untrusted_hash_sign(sign_path, lock_time, sig_hash)
        )  # type: int, bytes

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=InsType.UNTRUSTED_HASH_SIGN)

        return (1, b"\x30" + response[1:]) if response[0] & 0x01 else (0, response)
