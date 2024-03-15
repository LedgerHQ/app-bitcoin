from ragger.navigator import Navigator
from ragger.firmware import Firmware
from ragger_bitcoin import RaggerClient
from ragger_bitcoin.ragger_instructions import Instructions
from ragger.navigator import NavInsID


def pubkey_instruction_approve(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Approve")
    else:
        instructions.address_confirm()
        instructions.same_request("ADDRESS", NavInsID.USE_CASE_REVIEW_TAP,
                                  NavInsID.USE_CASE_STATUS_DISMISS)
    return instructions


def pubkey_instruction_warning_approve(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Approve")
        instructions.same_request("Approve")
    else:
        instructions.new_request("Unusual", NavInsID.USE_CASE_REVIEW_TAP,
                                 NavInsID.USE_CASE_CHOICE_CONFIRM)
        instructions.same_request("Confirm", NavInsID.USE_CASE_ADDRESS_CONFIRMATION_TAP,
                                  NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM)
        instructions.same_request("ADDRESS", NavInsID.USE_CASE_REVIEW_TAP,
                                  NavInsID.USE_CASE_STATUS_DISMISS)
    return instructions


def test_get_public_key(navigator: Navigator, firmware: Firmware,
                        client: RaggerClient, test_name: str):
    testcases = {
        "m/84'/1'/2'/0/10":
        "tpubDG9YpSUwScWJBBSrhnAT47NcT4NZGLcY18cpkaiWHnkUCi19EtCh8Heeox268NaFF6o56nVeSXuTyK6jpzTvV1h68Kr3edA8AZp27MiLUNt"}
    for path, pubkey in testcases.items():
        assert pubkey == client.get_extended_pubkey(
            path=path,
            display=True,
            navigator=navigator,
            instructions=pubkey_instruction_approve(firmware),
            testname=f"{test_name}_{path}"
        )
    testcases = {
        "m/44'/1'/0'": "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT",
        "m/44'/1'/10'": "tpubDCwYjpDhUdPGp21gSpVay2QPJVh6WNySWMXPhbcu1DsxH31dF7mY18oibbu5RxCLBc1Szerjscuc3D5HyvfYqfRvc9mesewnFqGmPjney4d",
        "m/44'/1'/2'/1/42": "tpubDGF9YgHKv6qh777rcqVhpmDrbNzgophJM9ec7nHiSfrbss7fVBXoqhmZfohmJSvhNakDHAspPHjVVNL657tLbmTXvSeGev2vj5kzjMaeupT",
        "m/48'/1'/4'/1'/0/7": "tpubDK8WPFx4WJo1R9mEL7Wq325wBiXvkAe8ipgb9Q1QBDTDUD2YeCfutWtzY88NPokZqJyRPKHLGwTNLT7jBG59aC6VH8q47LDGQitPB6tX2d7",
        "m/49'/1'/1'/1/3": "tpubDGnetmJDCL18TyaaoyRAYbkSE9wbHktSdTS4mfsR6inC8c2r6TjdBt3wkqEQhHYPtXpa46xpxDaCXU2PRNUGVvDzAHPG6hHRavYbwAGfnFr",
        "m/86'/1'/4'/1/12": "tpubDHTZ815MvTaRmo6Qg1rnU6TEU4ZkWyA56jA1UgpmMcBGomnSsyo34EZLoctzZY9MTJ6j7bhccceUeXZZLxZj5vgkVMYfcZ7DNPsyRdFpS3f",
    }

    for path, pubkey in testcases.items():
        assert pubkey == client.get_extended_pubkey(
            path=path,
            display=True,
            navigator=navigator,
            instructions=pubkey_instruction_warning_approve(firmware),
            testname=f"{test_name}_{path}"
        )
