from typing import Optional, List
from .apduabstract import ApduSet, ApduDict, CApdu, BytesOrStr
from .deviceappproxy import DeviceAppProxy, dongle_connected, CommException


class BTC_P1:
    # GetPublicKey
    SHOW_ADDR = bytes.fromhex("00")
    HIDE_ADDR = bytes.fromhex("01")
    VAL_TOKEN = bytes.fromhex("02")
    # GetTrustedInput, UntrustedHashTxInputStart
    FIRST_BLOCK = bytes.fromhex("00")
    NEXT_BLOCK = bytes.fromhex("80")
    # UntrustedHashTxInputFinalize
    MORE_BLOCKS = bytes.fromhex("00")
    LAST_BLOCK = bytes.fromhex("80")
    CHANGE_PATH = bytes.fromhex("ff")


class BTC_P2:
    # GetPublicKey
    LEGACY_ADDR = bytes.fromhex("00")
    P2SH_P2WPKH_ADDR = bytes.fromhex("01")
    BECH32_ADDR = bytes.fromhex("02")
    # UntrustedHashTxInputStart
    STD_INPUTS_ = bytes.fromhex("00")
    SEGWIT_INPUTS = bytes.fromhex("02")
    BCH_ADDR = bytes.fromhex("03")
    OVW_RULES = bytes.fromhex("04") # Overwinter rules (Bitcoin Cash)
    SPL_RULES = bytes.fromhex("05") # Sapling rules (Zcash, Komodo)
    TX_NEXT_INPUT = bytes.fromhex("80")


class DeviceAppBtc(DeviceAppProxy):

    default_chunk_size = 50

    default_mnemonic = "dose bike detect wedding history hazard blast surprise hundred ankle"\
                       "sorry charge ozone often gauge photo sponsor faith business taste front"\
                       "differ bounce chaos"

    apdus: ApduDict = {
        "getWalletPublicKey": CApdu(cla='e0', ins='40', typ=CApdu.Type.INOUT),
        "getTrustedInput":    CApdu(cla='e0', ins='42', p2='00', typ=CApdu.Type.INOUT),
        "untrustedHashTxInputStart": CApdu(cla='e0', ins='44', typ=CApdu.Type.IN),
        "untrustedHashSign": CApdu(cla='e0', ins='48', p1='00', p2='00', typ=CApdu.Type.INOUT),
        "untrustedHashTxInputFinalize": CApdu(cla='e0', ins='4a', p2='00', typ=CApdu.Type.INOUT),
        # Other APDUs supported by the BTC app not needed for these tests
    }

    def __init__(self, 
                 mnemonic: str = default_mnemonic) -> None:
        self.btc = ApduSet(DeviceAppBtc.apdus, 
                          max_lc=DeviceAppBtc.default_chunk_size)
        super().__init__(mnemonic=mnemonic, 
                         chunk_size=DeviceAppBtc.default_chunk_size)


    def getTrustedInput(self, 
                        data: BytesOrStr, 
                        chunks_len: Optional[List[int]] = None) -> bytes:
        return self.sendApdu("getTrustedInput", "00", "00", data, chunks_lengths=chunks_len)

    def getWalletPublicKey(self, 
                           data: BytesOrStr) -> bytes:
        return self.sendApdu("getWalletPublicKey", "00", "00", data)
    
    def untrustedTxInputHashStart(self, 
                                  p1: BytesOrStr, 
                                  p2: BytesOrStr, 
                                  data: BytesOrStr, 
                                  chunks_len: Optional[List[int]] = None) -> bytes:
        return self.sendApdu("untrustedHashTxInputStart", p1, p2, data, chunks_lengths=chunks_len)

    def untrustedTxInputHashFinalize(self, 
                                     p1: BytesOrStr, 
                                     data: BytesOrStr, 
                                     chunks_len: Optional[List[int]] = None ) -> bytes:
        return self.sendApdu("untrustedHashTxInputFinalize", p1, "00", data)

    def untrustedHashSign(self, 
                          data: BytesOrStr) -> bytes:
        return self.sendApdu("untrustedHashSign", "00", "00", data)

