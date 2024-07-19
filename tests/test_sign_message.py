
from ragger.navigator import Navigator
from ragger.firmware import Firmware
from ragger_bitcoin import RaggerClient
from ragger_bitcoin.ragger_instructions import Instructions
from ragger.navigator import NavInsID


def message_instruction_approve(model: Firmware) -> Instructions:
    instructions = Instructions(model)
    if model.name.startswith("nano"):
        instructions.new_request("Approve")
        instructions.nano_skip_screen("Message")
        instructions.same_request("Sign")
    else:
        instructions.address_confirm()
        instructions.same_request("Address", NavInsID.SWIPE_CENTER_TO_LEFT,
                                  NavInsID.USE_CASE_STATUS_DISMISS)
        instructions.confirm_message()
    return instructions


def test_sign_message(navigator: Navigator, firmware: Firmware,
                      client: RaggerClient, test_name: str):
    message = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks."
    bip32_path = "m/44'/1'/0'/0/0"
    result = client.sign_message(message=message, bip32_path=bip32_path, navigator=navigator,
                                 instructions=message_instruction_approve(firmware),
                                 testname=test_name)

    assert result == "MUUCIQDkeGEVZZiRjMfh+z4ELx81gBdBwIK1IIEHkXZ6FiqcqQIgfaAberpvF+XbOCM5Cd/ljogNyU3w2OIL8eYCyZ6Ru2k="
