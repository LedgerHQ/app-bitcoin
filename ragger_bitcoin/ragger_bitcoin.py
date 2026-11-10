from typing import Any, List, Optional, Tuple, Union
from pathlib import Path

from ledger_bitcoin import Chain, Client, SignPsbtYieldedObject, TransportClient, WalletPolicy
from ledger_bitcoin.client import print_apdu, print_response
from ledger_bitcoin.transport import ApduException

from ragger.navigator import Navigator
from ragger_bitcoin.ragger_instructions import Instructions
from ragger.utils import pack_APDU

TESTS_ROOT_DIR = Path(__file__).parent


class RaggerClient(Client):
    """A client that exchanges APDUs through a ragger backend, and can navigate the device's
    screens while the device is waiting for the user.

    Each method accepts an optional `navigator`, with the `instructions` to follow and the
    `testname` used for the screenshots. Every APDU of the call is then sent asynchronously;
    whenever the device does not answer within a second (because it is waiting for the user),
    the next group of instructions is followed.
    """

    def __init__(self, comm_client: TransportClient, chain: Chain = Chain.MAIN, debug: bool = False, screenshot_dir: Path = TESTS_ROOT_DIR) -> None:
        super().__init__(comm_client, chain, debug)
        self.screenshot_dir = screenshot_dir
        self.navigate = False
        self.navigator = None
        self.testname = ""
        self.instructions = None
        # index of the group of instructions to follow at the next screen interaction
        self.instructions_index = 0

    def _apdu_exchange(self, apdu: dict, tick_timeout: int = 0) -> Tuple[int, bytes]:
        if self.navigate:
            sw, response, self.instructions_index = self.ragger_navigate(
                self.navigator, apdu, self.instructions, self.testname, self.instructions_index)
            return sw, response

        try:
            if self.debug:
                print_apdu(apdu)

            response = self.transport_client.exchange(
                **apdu, tick_timeout=tick_timeout)
            if self.debug:
                print_response(response.status, response.data)

            return response.status, response.data
        except ApduException as e:
            if self.debug:
                print_response(e.sw, e.data)

            return e.sw, e.data

    def last_async_response(self) -> Tuple[int, bytes]:
        return self.transport_client.last_async_response.status, self.transport_client.last_async_response.data

    def ragger_navigate(self, navigator: Navigator, apdu: dict, instructions: Instructions, testname: str, index: int) -> Tuple[int, bytes, int]:
        sub_index = 0

        if instructions:
            text = instructions.data['text']
            instruction_until_text = instructions.data['instruction_until_text']
            instruction_on_text = instructions.data['instruction_on_text']
            save_screenshot = instructions.data['save_screenshot']
        else:
            text = []
            instruction_until_text = []
            instruction_on_text = []
            save_screenshot = []

        cla, ins, p1, p2, data = (apdu[k] for k in ("cla", "ins", "p1", "p2", "data"))
        self.transport_client.apdu_timeout = 1.0
        with self.transport_client.exchange_async_raw(pack_APDU(cla, ins, p1, p2, data)) as done:
            if not done:
                for t, instr_approve, instr_next, compare in zip(text[index],
                                                                 instruction_on_text[index],
                                                                 instruction_until_text[index],
                                                                 save_screenshot[index]):
                    if compare:
                        navigator.navigate_until_text_and_compare(instr_next,
                                                                  [instr_approve],
                                                                  t,
                                                                  self.screenshot_dir,
                                                                  Path(
                                                                      f"{testname}_{index}_{sub_index}"),
                                                                  screen_change_after_last_instruction=False,
                                                                  screen_change_before_first_instruction=True)
                    else:
                        navigator.navigate_until_text(instr_next,
                                                      [instr_approve],
                                                      t,
                                                      screen_change_after_last_instruction=False,
                                                      screen_change_before_first_instruction=True)
                    sub_index += 1
                index += 1
        sw, response = self.last_async_response()
        return sw, response, index

    def _with_navigation(self, navigator: Optional[Navigator], testname: str, instructions: Optional[Instructions], call):
        """Runs `call()`, navigating with `instructions` if a `navigator` is given."""
        if navigator:
            self.navigate = True
            self.navigator = navigator
            self.testname = testname
            self.instructions = instructions
            self.instructions_index = 0
        try:
            return call()
        finally:
            self.navigate = False

    def get_extended_pubkey(self, path: str, display: bool = False, navigator: Optional[Navigator] = None,
                            testname: str = "",
                            instructions: Instructions = None) -> str:
        return self._with_navigation(navigator, testname, instructions,
                                     lambda: Client.get_extended_pubkey(self, path, display))

    def register_wallet(self, wallet: WalletPolicy, navigator: Optional[Navigator] = None,
                        testname: str = "", instructions: Instructions = None) -> Tuple[bytes, bytes]:
        return self._with_navigation(navigator, testname, instructions,
                                     lambda: Client.register_wallet(self, wallet))

    def get_wallet_address(
        self,
        wallet: WalletPolicy,
        wallet_hmac: Optional[bytes],
        change: int,
        address_index: int,
        display: bool,
        navigator: Optional[Navigator] = None,
        instructions: Instructions = None,
        testname: str = ""
    ) -> str:
        return self._with_navigation(navigator, testname, instructions,
                                     lambda: Client.get_wallet_address(
                                         self, wallet, wallet_hmac, change, address_index, display))

    def sign_psbt(self, psbt: Union[bytes, str, Any], wallet: WalletPolicy, wallet_hmac:
                  Optional[bytes], navigator: Optional[Navigator] = None,
                  testname: str = "", instructions: Instructions = None) -> List[Tuple[int, SignPsbtYieldedObject]]:
        return self._with_navigation(navigator, testname, instructions,
                                     lambda: Client.sign_psbt(self, psbt, wallet, wallet_hmac))

    def sign_message(self, message: Union[str, bytes], bip32_path: str, navigator:
                     Optional[Navigator] = None,
                     instructions: Instructions = None,
                     testname: str = ""
                     ) -> str:
        return self._with_navigation(navigator, testname, instructions,
                                     lambda: Client.sign_message(self, message, bip32_path))


def createRaggerClient(backend, chain: Chain = Chain.MAIN, debug: bool = False, screenshot_dir:
                       Path = TESTS_ROOT_DIR) -> RaggerClient:
    return RaggerClient(backend, chain, debug, screenshot_dir)
