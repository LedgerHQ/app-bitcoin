from dataclasses import dataclass
from typing import Optional, List, Any
import hashlib
import base58
from ledgerblue.commException import CommException
from .deviceappproxy.deviceappproxy import DeviceAppProxy


class NID:
    MAINNET = bytes.fromhex("00")
    TESTNET = bytes.fromhex("6f")


class CONSENSUS_BRANCH_ID:
    OVERWINTER = bytes.fromhex("5ba81b19")
    SAPLING = bytes.fromhex("76b809bb")
    ZCLASSIC = bytes.fromhex("930b540d")
    ZCASH = bytes.fromhex("2BB40E60")


@dataclass(init=False, repr=False)
class BtcPublicKey:
    def __init__(self, apdu_response: bytes, network_id: NID = NID.TESTNET) -> None:
        self.nid: NID = network_id
        self.pubkey_len: int = apdu_response[0]
        self.pubkey: bytes = apdu_response[1:1 + self.pubkey_len]
        self.pubkey_comp: bytes = (3 if self.pubkey[0] % 2 else 2).to_bytes(1, 'big') \
                                  + self.pubkey[1:self.pubkey_len >> 1]    # -1 not necessary w/ >>
        self.pubkey_comp_len: int = len(self.pubkey_comp)
        self.address_len: int = apdu_response[1 + self.pubkey_len]
        self.address: str = apdu_response[1 + self.pubkey_len + 1:1 + self.pubkey_len + 1 + self.address_len].decode()
        self.chaincode: bytes = apdu_response[1 + self.pubkey_len + 1 + self.address_len:]
        self.pubkey_hash: bytes = base58.b58decode(self.address)
        self.pubkey_hash_len: int = len(self.pubkey_hash)
        self.pubkey_hash = self.pubkey_hash[1:-4]   # remove network id & hash checksum
        self.pubkey_hash_len = len(self.pubkey_hash)

    def __repr__(self) -> str:
        return f"    PublicKey ({self.pubkey_len} bytes) = {self.pubkey.hex()}\n"\
               f"    PublicKey (compressed, {self.pubkey_comp_len} bytes) = {self.pubkey_comp.hex()}\n"\
               f"    PublicKey hash ({self.pubkey_hash_len} bytes) = {self.pubkey_hash.hex()}\n"\
               f"    Base58 address = {self.address}\n"\
               f"    Chain code ({len(self.chaincode)} bytes) = {self.chaincode.hex()}\n"


class BaseTestBtc:
    """
    Base class for tests of BTC app, contains data validators.
    """
    @staticmethod
    def check_trusted_input(trusted_input: bytes,
                            out_index: bytes,
                            out_amount: bytes,
                            out_hash: Optional[bytes] = None) -> None:
        print(f"    Magic marker = {trusted_input[:2].hex()}")
        print(f"    2-byte nonce = {trusted_input[2:4].hex()}")
        print(f"    Transaction hash (txid) = {trusted_input[4:36].hex()}")
        print(f"    Prevout index = {trusted_input[36:40].hex()}")
        print(f"    Prevout amount = {trusted_input[40:48].hex()}")
        print(f"    SHA-256 HMAC = {trusted_input[48:].hex()}")
        # Note: Signature value can't be asserted since the HMAC key is secret in the device
        assert trusted_input[:2] == bytes.fromhex("3200")
        assert trusted_input[36:40] == out_index
        assert trusted_input[40:48] == out_amount
        if out_hash:
            assert trusted_input[4:36] == out_hash

    @staticmethod
    def check_signature(resp: bytes,
                        expected_resp: Optional[bytes] = None) -> None:
        # Signature is DER-encoded as: # 30|parity_bit zz 02 xx R 02 yy S sigHashType
        # with:
        # - parity_bit: a ledger extension to the BTC standard
        # - zz: length of the payload, excluding sigHasType byte (zz = xx + yy + 4)
        # - xx: len of R
        # - yy: len of S
        # - sigHashType: always 01 when present (i.e. only for Untrusted Tx Input Hash Sign APDU)
        parity_bit = resp[0] & 1
        offs_r = 4
        len_r = resp[offs_r - 1]
        offs_s = offs_r + len_r + 2
        len_s = resp[offs_s - 1]
        print(f"    OK, response = {resp.hex()}")
        print(f"     - Parity = {'odd' if parity_bit else 'even'}")
        print(f"     - R = {resp[offs_r:offs_r+len_r].hex()} ({len_r} bytes)")
        print(f"     - S = {resp[offs_s:offs_s+len_s].hex()} ({len_s} bytes)")
        if resp[1] == len(resp) - 3:
            print(f"     - sigHashType = {bytes([resp[-1]]).hex()}")
        # If no expected sig provided, check sig DER encoding & sigHashType byte only
        if expected_resp is None:
            assert resp[0] & 0xFE == 0x30
            assert resp[1] == len_r + len_s + 4
            # "-2" below for SignMessage APDU as it doesn't return sigHashType as last byte
            assert resp[1] in (len(resp) - 3, len(resp) - 2)
            assert resp[offs_r - 2] == resp[offs_s - 2] == 0x02
            if resp[1] == len(resp) - 3:
                assert resp[-1] == 1
        else:
            assert resp == expected_resp

    @staticmethod
    def check_raw_apdu_resp(expected: str, received: bytes) -> None:
        # Not a very elegant way to skip sections of the received response that vary
        # (marked with 2 '-' char per byte to skip in the expected response i.e. '--'),
        # but does the job.
        def expected_len(exp_str: str) -> int:
            tok = exp_str.split('-')
            dash_count = exp_str.count('-') >> 1
            return dash_count + (len("".join([t for t in tok if len(tok)])) >> 1)

        assert len(received) == expected_len(expected)
        recv = received.hex()
        for exp_char, recv_char in zip(expected, recv):
            if exp_char != '-':
                assert recv_char == exp_char

    @staticmethod
    def split_pubkey_data(data: bytes) -> BtcPublicKey:
        """
        Decompose the response from GetWalletPublicKey APDU into its constituents
        """
        return BtcPublicKey(data)

    @staticmethod
    def check_public_key_hash(key_data: BtcPublicKey) -> None:
        """TBC"""
        sha256 = hashlib.new("sha256")
        ripemd = hashlib.new("ripemd160")
        sha256.update(key_data.pubkey)
        ripemd.update(sha256.digest())
        pubkey_hash = ripemd.digest()
        assert len(pubkey_hash) == 20
        assert pubkey_hash == key_data.pubkey_hash


class BaseTestZcash(BaseTestBtc):
    """
    Base class for BTX-derived Zcash tx tests
    """
    def send_ljs_apdus(self, apdus: List[Any], device: DeviceAppProxy):
        # Send the Get Version APDUs
        for apdu in apdus:
            try:
                response: Optional[bytes] = None
                for command in apdu.commands:
                    response: bytes = device.send_raw_apdu(bytes.fromhex(command))
                if response:
                    if apdu.expected_resp is not None:
                        self.check_raw_apdu_resp(apdu.expected_resp, response)
                    elif apdu.check_sig_format is not None and apdu.check_sig_format is True:
                        self.check_signature(response)  # Only format is checked
            except CommException as error:
                if apdu.expected_sw is not None and error.sw.hex() == apdu.expected_sw:
                    continue
                raise error
