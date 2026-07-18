import pytest

from ragger.navigator import NavInsID, NavIns
from ragger.firmware import Firmware
from ragger.firmware.touch.positions import STAX_X_CENTER, FLEX_X_CENTER, APEX_P_X_CENTER

from ragger_bitcoin.ragger_instructions import Instructions, get_max_ext_output_simplified_number


def message_instruction_approve(model: Firmware, save_screenshot=True) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.nano_skip_screen("Path", save_screenshot=save_screenshot)
        instructions.same_request("Sign message", save_screenshot=save_screenshot)
    else:
        instructions.review_message(save_screenshot=save_screenshot)
        instructions.confirm_message(save_screenshot=save_screenshot)

    return instructions


def bip322_instruction_approve(model: Firmware, save_screenshot=True) -> Instructions:
    # Navigation for the BIP-322 message review (account/address/message pairs, then sign)
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.nano_skip_screen("Address", save_screenshot=save_screenshot)
        instructions.same_request("Sign message", save_screenshot=save_screenshot)
    else:
        instructions.review_message(save_screenshot=save_screenshot)
        instructions.confirm_message(save_screenshot=save_screenshot)

    return instructions


def message_instruction_approve_long(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.nano_skip_screen("Path")
        instructions.same_request("Sign message")
    else:
        # TODO: to wrap below to review_message_long() and
        # to use coordinates from positions.py when available in Ragger
        if (model.name == "apex_p"):
            MORE_POS = (APEX_P_X_CENTER, 250)
            CROSS_POS = (28, 370)
        elif model.name == "stax":
            MORE_POS = (STAX_X_CENTER, 425)
            CROSS_POS =(40, 625)
        elif model.name == "flex":
            MORE_POS = (FLEX_X_CENTER, 365)
            CROSS_POS = (50, 550)

        instructions.new_request("Review", NavInsID.USE_CASE_REVIEW_TAP,
                         NavInsID.USE_CASE_REVIEW_TAP)
        instructions.same_request("Message", NavInsID.USE_CASE_REVIEW_TAP,
                         NavIns(NavInsID.TOUCH, MORE_POS))
        instructions.same_request("Message", NavInsID.USE_CASE_REVIEW_TAP,
                         NavIns(NavInsID.TOUCH, CROSS_POS))
        instructions.confirm_message()
    return instructions


def message_instruction_reject(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Reject message")
    else:
        instructions.reject_message()

    return instructions


def pubkey_instruction_approve(model: Firmware, save_screenshot=True) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Approve", save_screenshot=save_screenshot)
    else:
        instructions.choice_confirm(save_screenshot=save_screenshot)
        instructions.status_dismiss("approved", save_screenshot=save_screenshot)
    return instructions


def pubkey_instruction_reject_early(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    # It does not make sense for Nano devices
    # as with them it is possible to reject only on the
    # last step.
    if model.name.startswith("nano"):
        pytest.skip()
    else:
        instructions.new_request("Path", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.CANCEL_FOOTER_TAP)
        instructions.same_request("Reject", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_CHOICE_CONFIRM)
        instructions.status_dismiss("rejected", status_on_same_request=False)
    return instructions


def pubkey_reject(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Reject")
    else:
        instructions.choice_reject()
        instructions.same_request("Reject", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_CHOICE_CONFIRM)
        instructions.status_dismiss("rejected", status_on_same_request=False)

    return instructions


def wallet_instruction_approve(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Confirm")
    else:
        instructions.address_confirm()
    return instructions


def register_wallet_instruction_approve(model: Firmware, save_screenshot=True) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Register account", save_screenshot=save_screenshot)
    else:
        instructions.choice_confirm(save_screenshot=save_screenshot)
        instructions.choice_confirm(save_screenshot=save_screenshot)
        instructions.choice_confirm(save_screenshot=save_screenshot)
    return instructions


def register_wallet_instruction_approve_no_save(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Register account", save_screenshot=False)
    else:
        instructions.choice_confirm(save_screenshot=False)
        instructions.choice_confirm(save_screenshot=False)
        instructions.choice_confirm(save_screenshot=False)
    return instructions


def register_wallet_instruction_approve_long(model: Firmware, save_screenshot=True) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Register account", save_screenshot=save_screenshot)
    else:
        instructions.choice_confirm(save_screenshot=save_screenshot)
        instructions.choice_confirm(save_screenshot=save_screenshot)
        instructions.choice_confirm(save_screenshot=save_screenshot)
        instructions.choice_confirm(save_screenshot=save_screenshot)
    return instructions


def register_wallet_instruction_approve_unusual(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Register account")
    else:
        instructions.choice_confirm()
        instructions.choice_confirm()
    return instructions


def register_wallet_instruction_reject(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Reject operation")
    else:
        instructions.choice_reject()
        instructions.status_dismiss("rejected", status_on_same_request=False)

    return instructions


def sign_psbt_instruction_tap(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        return instructions

    instructions.review_start(save_screenshot=False)
    return instructions


def sign_psbt_instruction_approve(model: Firmware, save_screenshot: bool = True, *, has_spend_from_wallet: bool = False, to_on_next_page: bool = False, fees_on_next_page: bool = False, has_unverifiedwarning: bool = False, has_sighashwarning: bool = False, has_feewarning: bool = False, has_external_inputs: bool = False, amounts_unavailable: bool = False, go_back: bool = False) -> Instructions:
    # amounts_unavailable: open-outputs sighash (NONE/SINGLE) -> the review shows no
    # outputs/amounts, only the "Amounts & fees" notice.
    instructions = Instructions(model)

    funcdict = {
      'new_request': instructions.new_request,
      'same_request': instructions.same_request
    }
    which_func = 'new_request'

    # It is probably possibile to factorize between Nano and touch screen devices
    if model.name.startswith("nano"):
        if has_sighashwarning:
            # This transaction uses non-standard signing rules- actually clicking "Continue anyway"
            funcdict[which_func]("Continue anyway", save_screenshot=save_screenshot)
            which_func = 'same_request'

        if has_external_inputs:
            # This transaction has external inputs- actually clicking "Continue anyway"
            funcdict[which_func]("Continue anyway", save_screenshot=save_screenshot)
            which_func = 'same_request'

        if has_unverifiedwarning:
            # Non-default sighash - actually clicking "Continue anyway"
            funcdict[which_func]("Continue anyway", save_screenshot=save_screenshot)
            which_func = 'same_request'

        run_num = 1
        # if go_back is True then
        #     1. we go forward once until "Sign transaction" screen
        #     2. then back until "Review" screen
        #     3. then again forwar signing finaly the transaction
        while True:
            if not go_back or run_num >= 2:
               funcdict[which_func]("Sign transaction", save_screenshot=save_screenshot)
               break
            else:
                funcdict[which_func]("Sign transaction", NavInsID.RIGHT_CLICK, NavInsID.LEFT_CLICK,
                                     save_screenshot=save_screenshot)
                which_func = 'same_request'
                funcdict[which_func]("Review", NavInsID.LEFT_CLICK, NavInsID.RIGHT_CLICK,
                                     save_screenshot=save_screenshot)
            run_num = run_num + 1

    else:
        # All the warnings below, plus the review that follows, are shown by the firmware
        # within a single APDU exchange. They must therefore live in one request group
        if has_sighashwarning:
            # This transaction uses non-standard signing rules- actually clicking "Continue anyway"
            funcdict[which_func]("Continue anyway", NavInsID.USE_CASE_REVIEW_TAP,
                                 NavInsID.USE_CASE_CHOICE_REJECT, save_screenshot=save_screenshot)
            which_func = 'same_request'

        if has_external_inputs:
            # This transaction has external inputs- actually clicking "Continue anyway"
            funcdict[which_func]("Continue anyway", NavInsID.USE_CASE_REVIEW_TAP,
                                 NavInsID.USE_CASE_CHOICE_REJECT, save_screenshot=save_screenshot)
            which_func = 'same_request'

        if has_unverifiedwarning:
            # Non-default sighash - actually clicking "Continue anyway"
            funcdict[which_func]("Continue anyway", NavInsID.USE_CASE_REVIEW_TAP,
                                 NavInsID.USE_CASE_CHOICE_REJECT, save_screenshot=save_screenshot)
            which_func = 'same_request'

        funcdict[which_func]("Review", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP,
                                 save_screenshot=save_screenshot)
        which_func = 'same_request'

        review_anchor = "Amounts & fees" if amounts_unavailable else "Amount"
        run_num = 1
        while True:
            funcdict[which_func](review_anchor, NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP,
                                      save_screenshot=save_screenshot)
            if to_on_next_page:
                funcdict[which_func]("To", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP,
                                          save_screenshot=save_screenshot)
            if fees_on_next_page:
                funcdict[which_func]("Fees", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP,
                                          save_screenshot=save_screenshot)
            if has_feewarning:
                funcdict[which_func](
                    "High fees warning", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP, save_screenshot=save_screenshot)

            if not go_back or run_num >= 2:
                instructions.confirm_transaction(save_screenshot=save_screenshot)
                break
            else:
                funcdict[which_func]("Sign", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_PREVIOUS,
                          save_screenshot=save_screenshot)
                which_func = 'same_request'
                funcdict[which_func]("Review", NavInsID.USE_CASE_REVIEW_PREVIOUS, NavInsID.USE_CASE_REVIEW_TAP,
                                     save_screenshot=save_screenshot)
            run_num = run_num + 1

    return instructions


def sign_psbt_instruction_approve_selftransfer(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Sign transaction")
    else:
        instructions.new_request(
            "Review", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP)
        instructions.same_request(
            "Amount", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP)
        instructions.confirm_transaction()
    return instructions


def sign_psbt_instruction_approve_generic(model: Firmware, output_count: int, save_screenshot: bool = True, go_back: bool = False) -> Instructions:
    instructions = Instructions(model)
    if (output_count <= get_max_ext_output_simplified_number(model)):
       # Classical case
       return sign_psbt_instruction_approve(model, save_screenshot, has_feewarning = True, go_back = go_back);

    # Streaming case
    if model.name.startswith("nano"):
        instructions.new_request("Loading transaction")
        instructions.new_request("Sign transaction", save_screenshot=save_screenshot)
    else:
        instructions.review_start(
            output_count=output_count, save_screenshot=save_screenshot)
        instructions.review_fees(save_screenshot=save_screenshot)
        instructions.confirm_transaction(save_screenshot=save_screenshot)
    return instructions


def e2e_register_wallet_instruction(model: Firmware, n_keys) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Register account", save_screenshot=False)
    else:
        for _ in range(n_keys + 1):
            instructions.choice_confirm(save_screenshot=False)
            instructions.choice_confirm(save_screenshot=False)
    return instructions


def e2e_sign_psbt_instruction(model: Firmware) -> Instructions:
    return sign_psbt_instruction_approve(model, save_screenshot=False, has_spend_from_wallet=True)
