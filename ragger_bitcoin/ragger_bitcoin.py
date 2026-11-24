from contextlib import contextmanager
from typing import Iterator, Tuple, List, Optional, Union
from pathlib import Path

from ledger_bitcoin.common import Chain
from ledger_bitcoin.client_command import ClientCommandInterpreter
from ledger_bitcoin.client_base import TransportClient, PartialSignature
from ledger_bitcoin.wallet import WalletPolicy
from ledger_bitcoin.psbt import PSBT
from ledger_bitcoin.client import NewClient
from ledger_bitcoin.client_base import print_response, print_apdu, ApduException

from ragger.navigator import Navigator, NavInsID
from ragger_bitcoin.ragger_instructions import Instructions
from ragger.utils import pack_APDU

TESTS_ROOT_DIR = Path(__file__).parent


class RaggerClient(NewClient):
    def __init__(self, comm_client: TransportClient, chain: Chain = Chain.MAIN, debug: bool = False, screenshot_dir: Path = TESTS_ROOT_DIR) -> None:
        super().__init__(comm_client, chain, debug)
        self.screenshot_dir = screenshot_dir
        self.navigate = False
        self.navigator = None
        self.testname = ""
        self.instructions = None

    def _apdu_exchange(self, apdu: dict, tick_timeout: int = 0) -> Tuple[int, bytes]:
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

    def _make_request(
        self, apdu: dict, client_intepreter: ClientCommandInterpreter = None
    ) -> Tuple[int, bytes]:

        if self.navigate:
            sw, response = self._make_request_with_navigation(navigator=self.navigator,
                                                              apdu=apdu,
                                                              client_intepreter=client_intepreter,
                                                              testname=self.testname,
                                                              instructions=self.instructions
                                                              )

        else:
            sw, response = NewClient._make_request(
                self, apdu, client_intepreter)
        return sw, response

    @contextmanager
    def _navigation(self, navigator: Optional[Navigator], testname: str,
                    instructions: Optional[Instructions]) -> Iterator[None]:
        # Navigation applies to the requests of this call only: not to the requests of a nested
        # call without a navigator (e.g. the address check in register_wallet), nor to later calls
        # if this one raises.
        saved = (self.navigate, self.navigator, self.testname, self.instructions)
        self.navigate = navigator is not None
        self.navigator, self.testname, self.instructions = navigator, testname, instructions
        try:
            yield
        finally:
            self.navigate, self.navigator, self.testname, self.instructions = saved

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

        cla, ins, p1, p2, data = apdu.values()
        self.transport_client.apdu_timeout = 1.0;
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

    def _make_request_with_navigation(self, navigator: Navigator, apdu: dict, client_intepreter:
                                      ClientCommandInterpreter = None,
                                      testname: str = "", instructions: Instructions = None) -> Tuple[int, bytes]:

        index = 0

        sw, response, index = self.ragger_navigate(
            navigator, apdu, instructions, testname, index)

        while sw == 0xE000:
            if not client_intepreter:
                raise RuntimeError(
                    "Unexpected SW_INTERRUPTED_EXECUTION received.")

            command_response = client_intepreter.execute(response)
            apdu = self.builder.continue_interrupted(command_response)

            sw, response, index = self.ragger_navigate(
                navigator, apdu, instructions, testname, index)

        # A request that succeeds without showing all the expected screens skipped the review.
        # A final status screen (e.g. "Transaction signed") does not block the APDU, so it is only
        # navigated if a later APDU happens to still be pending: it is not required.
        if sw == 0x9000 and instructions:
            required = len(instructions.data['text'])
            if required > 0 and all(i == NavInsID.USE_CASE_STATUS_DISMISS
                                    for i in instructions.data['instruction_on_text'][-1]):
                required -= 1
            if index < required:
                raise RuntimeError(
                    f"Request completed after {index} of the {required} expected UI interactions")
        return sw, response

    def get_extended_pubkey(self, path: str, display: bool = False, navigator: Optional[Navigator] = None,
                            testname: str = "",
                            instructions: Instructions = None) -> str:

        with self._navigation(navigator, testname, instructions):
            response = NewClient.get_extended_pubkey(self, path, display)

        return response

    def register_wallet(self, wallet: WalletPolicy, navigator: Optional[Navigator] = None,
                        testname: str = "", instructions: Instructions = None) -> Tuple[bytes, bytes]:

        with self._navigation(navigator, testname, instructions):
            wallet_id, wallet_hmac = NewClient.register_wallet(self, wallet)

        return wallet_id, wallet_hmac

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

        with self._navigation(navigator, testname, instructions):
            result = NewClient.get_wallet_address(
                self, wallet, wallet_hmac, change, address_index, display)

        return result

    def sign_psbt(self, psbt: Union[PSBT, bytes, str], wallet: WalletPolicy, wallet_hmac:
                  Optional[bytes], navigator: Optional[Navigator] = None,
                  testname: str = "", instructions: Instructions = None) -> List[Tuple[int, PartialSignature]]:

        with self._navigation(navigator, testname, instructions):
            result = NewClient.sign_psbt(self, psbt, wallet, wallet_hmac)

        return result

    def sign_message(self, message: Union[str, bytes], bip32_path: str, navigator:
                     Optional[Navigator] = None,
                     instructions: Instructions = None,
                     testname: str = ""
                     ) -> str:

        with self._navigation(navigator, testname, instructions):
            response = NewClient.sign_message(self, message, bip32_path)

        return response


def createRaggerClient(backend, chain: Chain = Chain.MAIN, debug: bool = False, screenshot_dir:
                       Path = TESTS_ROOT_DIR) -> RaggerClient:
    return RaggerClient(backend, chain, debug, screenshot_dir)
