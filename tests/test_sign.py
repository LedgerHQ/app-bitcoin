from pathlib import Path

from ledger_bitcoin import WalletPolicy, PartialSignature

from ledger_bitcoin.psbt import PSBT

from ragger_bitcoin import RaggerClient
from ragger_bitcoin.ragger_instructions import Instructions
from ragger.navigator import Navigator
from ragger.firmware import Firmware
tests_root: Path = Path(__file__).parent


CURRENCY_TICKER = "TEST"


def sign_psbt_instruction_approve(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Accept")
        instructions.same_request("Accept")
    else:
        instructions.confirm_transaction()
    return instructions


def sign_psbt_instruction_approve_2(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Accept")
        instructions.new_request("Accept")
    else:
        instructions.navigate_end_of_flow()
        instructions.confirm_transaction()
    return instructions


def open_psbt_from_file(filename: str) -> PSBT:
    raw_psbt_base64 = open(filename, "r").read()

    psbt = PSBT()
    psbt.deserialize(raw_psbt_base64)
    return psbt


def test_sign_psbt_singlesig_pkh_1to1(
        navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):

    # PSBT for a legacy 1-input 1-output spend (no change address)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/pkh-1to1.psbt")

    wallet = WalletPolicy(
        "",
        "pkh(@0/**)",
        ["[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"],
    )

    # expected sigs:
    # #0:
    #  "pubkey" : "02ee8608207e21028426f69e76447d7e3d5e077049f5e683c3136c2314762a4718",
    #  "signature" : "3045022100e55b3ca788721aae8def2eadff710e524ffe8c9dec1764fdaa89584f9726e196022012a30fbcf9e1a24df31a1010356b794ab8de438b4250684757ed5772402540f401"
    result = client.sign_psbt(psbt, wallet, None, navigator=navigator,
                              instructions=sign_psbt_instruction_approve(firmware),
                              testname=test_name)

    assert result == [(0, PartialSignature(pubkey=bytes.fromhex("02ee8608207e21028426f69e76447d7e3d5e077049f5e683c3136c2314762a4718"), signature=bytes.fromhex(
        "3045022100e55b3ca788721aae8def2eadff710e524ffe8c9dec1764fdaa89584f9726e196022012a30fbcf9e1a24df31a1010356b794ab8de438b4250684757ed5772402540f401")))]


def test_sign_psbt_singlesig_sh_wpkh_1to2(
        navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):

    # PSBT for a wrapped segwit 1-input 2-output spend (1 change address)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/sh-wpkh-1to2.psbt")

    wallet = WalletPolicy(
        "",
        "sh(wpkh(@0/**))",
        ["[f5acc2fd/49'/1'/0']tpubDC871vGLAiKPcwAw22EjhKVLk5L98UGXBEcGR8gpcigLQVDDfgcYW24QBEyTHTSFEjgJgbaHU8CdRi9vmG4cPm1kPLmZhJEP17FMBdNheh3"],
    )

    # expected sigs:
    # #0:
    #  "pubkey" : "024ba3b77d933de9fa3f9583348c40f3caaf2effad5b6e244ece8abbfcc7244f67",
    #  "signature" : "30440220720722b08489c2a50d10edea8e21880086c8e8f22889a16815e306daeea4665b02203fcf453fa490b76cf4f929714065fc90a519b7b97ab18914f9451b5a4b45241201"
    result = client.sign_psbt(psbt, wallet, None, navigator=navigator,
                              instructions=sign_psbt_instruction_approve_2(firmware),
                              testname=test_name)

    assert len(result) == 1

    assert result == [(
        0,
        PartialSignature(
            pubkey=bytes.fromhex(
                "024ba3b77d933de9fa3f9583348c40f3caaf2effad5b6e244ece8abbfcc7244f67"),
            signature=bytes.fromhex(
                "30440220720722b08489c2a50d10edea8e21880086c8e8f22889a16815e306daeea4665b02203fcf453fa490b76cf4f929714065fc90a519b7b97ab18914f9451b5a4b45241201"
            )
        )
    )]


def test_sign_psbt_singlesig_wpkh_1to2(
        navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):

    # PSBT for a legacy 1-input 2-output spend (1 change address)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-1to2.psbt")

    wallet = WalletPolicy(
        "",
        "wpkh(@0/**)",
        ["[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"],
    )

    result = client.sign_psbt(psbt, wallet, None, navigator=navigator,
                              instructions=sign_psbt_instruction_approve_2(firmware),
                              testname=test_name)
    result = client.sign_psbt(psbt, wallet, None, navigator=navigator,
                              instructions=sign_psbt_instruction_approve_2(firmware),
                              testname=f"{test_name}_2")

    # expected sigs
    # #0:
    #   "pubkey" : "03ee2c3d98eb1f93c0a1aa8e5a4009b70eb7b44ead15f1666f136b012ad58d3068",
    #   "signature" : "3045022100ab44f34dd7e87c9054591297a101e8500a0641d1d591878d0d23cf8096fa79e802205d12d1062d925e27b57bdcf994ecf332ad0a8e67b8fe407bab2101255da632aa01"

    assert result == [(0, PartialSignature(pubkey=bytes.fromhex("03ee2c3d98eb1f93c0a1aa8e5a4009b70eb7b44ead15f1666f136b012ad58d3068"), signature=bytes.fromhex(
        "3045022100ab44f34dd7e87c9054591297a101e8500a0641d1d591878d0d23cf8096fa79e802205d12d1062d925e27b57bdcf994ecf332ad0a8e67b8fe407bab2101255da632aa01")))]


def test_sign_psbt_singlesig_wpkh_2to2(
        navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    # PSBT for a legacy 2-input 2-output spend (1 change address)

    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-2to2.psbt")

    wallet = WalletPolicy(
        "",
        "wpkh(@0/**)",
        ["[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"],
    )

    result = client.sign_psbt(psbt, wallet, None, navigator=navigator,
                              instructions=sign_psbt_instruction_approve(firmware),
                              testname=test_name)

    assert result == [(
        0,
        PartialSignature(
            pubkey=bytes.fromhex(
                "03455ee7cedc97b0ba435b80066fc92c963a34c600317981d135330c4ee43ac7a3"),
            signature=bytes.fromhex(
                "304402206b3e877655f08c6e7b1b74d6d893a82cdf799f68a5ae7cecae63a71b0339e5ce022019b94aa3fb6635956e109f3d89c996b1bfbbaf3c619134b5a302badfaf52180e01"
            )
        )
    ), (
        1,
        PartialSignature(
            pubkey=bytes.fromhex(
                "0271b5b779ad870838587797bcf6f0c7aec5abe76a709d724f48d2e26cf874f0a0"),
            signature=bytes.fromhex(
                "3045022100e2e98e4f8c70274f10145c89a5d86e216d0376bdf9f42f829e4315ea67d79d210220743589fd4f55e540540a976a5af58acd610fa5e188a5096dfe7d36baf3afb94001"
            )
        )
    )]
