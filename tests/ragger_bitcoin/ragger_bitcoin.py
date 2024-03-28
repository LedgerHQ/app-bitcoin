from typing import Tuple, List, Optional, Union
from pathlib import Path
import base64

from ledger_bitcoin.client_base import TransportClient, PartialSignature
from ledger_bitcoin.common import Chain
from ledger_bitcoin.wallet import WalletPolicy
from ledger_bitcoin.psbt import PSBT
from ledger_bitcoin.client_legacy import LegacyClient, check_keypath
from ledger_bitcoin.btchip.btchip import btchip

from ragger.navigator import Navigator
from ragger_bitcoin.ragger_instructions import Instructions
from ragger_bitcoin.ragger_adaptor import RaggerAdaptor


TESTS_ROOT_DIR = Path(__file__).parent

class RaggerClient(LegacyClient):
    def __init__(self, comm_client: TransportClient, screenshot_dir: Path = TESTS_ROOT_DIR) -> None:
        self.app = btchip(RaggerAdaptor(comm_client, screenshot_dir))
        self.chain = Chain.TEST

    def get_extended_pubkey(self, path: str, display: bool = False, navigator: Optional[Navigator] = None,
                            testname: str = "",
                            instructions: Instructions = None) -> str:

        if navigator:
            self.app.dongle.set_navigation(True, navigator, testname, instructions)

        response = LegacyClient.get_extended_pubkey(self, path, display)

        self.app.dongle.set_navigation(False, navigator, testname, instructions)

        return response

    def sign_psbt(self, psbt: Union[PSBT, bytes, str], wallet: WalletPolicy, wallet_hmac:
                  Optional[bytes], navigator: Optional[Navigator] = None,
                  testname: str = "", instructions: Instructions = None) -> List[Tuple[int, PartialSignature]]:

        if navigator:
            self.app.dongle.set_navigation(True, navigator, testname, instructions)

        result = LegacyClient.sign_psbt(self, psbt, wallet, wallet_hmac)

        self.app.dongle.set_navigation(False, navigator, testname, instructions)

        return result

    def sign_message(self, message: Union[str, bytes], bip32_path: str, navigator:
                     Optional[Navigator] = None,
                     instructions: Instructions = None,
                     testname: str = ""
                     ) -> str:

        if navigator:
            self.app.dongle.set_navigation(True, navigator, testname, instructions)

        if not check_keypath(bip32_path):
            raise ValueError("Invalid bip32_path")
        if isinstance(message, str):
            message = bytearray(message, 'utf-8')
        else:
            message = bytearray(message)
        bip32_path = bip32_path[2:]
        # First display on screen what address you're signing for
        self.app.getWalletPublicKey(bip32_path, True)
        self.app.signMessagePrepare(bip32_path, message)
        signature = self.app.signMessageSign()

        self.app.dongle.set_navigation(False, navigator, testname, instructions)

        return base64.b64encode(signature).decode('utf-8')


def createRaggerClient(backend, screenshot_dir: Path = TESTS_ROOT_DIR) -> RaggerClient:
    return RaggerClient(backend, screenshot_dir)

