from typing import Tuple, Union
from pathlib import Path

from ragger.navigator import Navigator
from ragger.utils import RAPDU
from ragger_bitcoin.ragger_instructions import Instructions

# Interface with ledger_bitcoin library


class RaggerAdaptor:
    def __init__(self, comm_client, screenshot_dir):
        self.transport_client = comm_client
        self.navigate = False
        self.navigator = None
        self.testname = ""
        self.instructions = None
        self.screenshot_dir = screenshot_dir
        self.instructions_index = 0

    def set_navigation(self, navigate, navigator, testname, instructions):
        self.navigate = navigate
        self.navigator = navigator
        self.testname = testname
        self.instructions = instructions
        self.instructions_index = 0

    def exchange(self, apdu: Union[bytes, bytearray]) -> bytearray:
        if self.navigate:
            _, response, self.instructions_index = self.ragger_navigate(
                self.navigator, apdu, self.instructions, self.testname, self.instructions_index)
        else:
            rapdu = self.transport_client.exchange_raw(apdu)
            response = rapdu.data
        return bytearray(response)

    def last_async_response(self) -> RAPDU:
        return self.transport_client.last_async_response

    def ragger_navigate(self, navigator: Navigator, apdu: dict, instructions: Instructions,
                        testname: str, index: int) -> Tuple[int, bytes, int]:
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

        try:
            response = self.transport_client.exchange_raw(apdu, tick_timeout=2)
        except TimeoutError:
            with self.transport_client.exchange_async_raw(apdu):
                for t, instr_approve, instr_next, compare in zip(text[index],
                                                                 instruction_on_text[index],
                                                                 instruction_until_text[index],
                                                                 save_screenshot[index]):
                    if compare:
                        navigator.navigate_until_text_and_compare(
                            instr_next, [instr_approve],
                            t, self.screenshot_dir, Path(f"{testname}_{index}_{sub_index}"),
                            screen_change_after_last_instruction=False,
                            screen_change_before_first_instruction=True)
                    else:
                        navigator.navigate_until_text(instr_next,
                                                      [instr_approve],
                                                      t,
                                                      screen_change_after_last_instruction=False,
                                                      screen_change_before_first_instruction=True)
                    sub_index += 1

            response = self.last_async_response()
            index += 1
        return response.status, response.data, index
