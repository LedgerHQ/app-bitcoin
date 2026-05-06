import pytest

from typing import List, Tuple

import hmac
from hashlib import sha256
from decimal import Decimal

from ledger_bitcoin._script import is_p2tr
from ledger_bitcoin.exception.errors import IncorrectDataError, NotSupportedError
from ledger_bitcoin.exception.device_exception import DeviceException
from ledger_bitcoin.psbt import PSBT
from ledger_bitcoin.wallet import WalletPolicy
from ledger_bitcoin import MusigPubNonce, MusigPartialSignature, PartialSignature, SignPsbtYieldedObject

from test_utils import SpeculosGlobals, get_internal_xpub, count_internal_key_placeholders

from ragger_bitcoin import RaggerClient
from ragger_bitcoin.ragger_instructions import Instructions
from ragger.navigator import Navigator
from ragger.firmware import Firmware
from ragger.error import ExceptionRAPDU

from .instructions import e2e_register_wallet_instruction, e2e_sign_psbt_instruction

from .conftest import AuthServiceProxy, create_new_wallet, generate_blocks, get_unique_wallet_name, get_wallet_rpc, import_descriptors_with_privkeys, testnet_to_regtest_addr as T


# Removes all the BIP_IN_TAP_BIP32_DERIVATION entries that are not for the musig aggregate keys
# Returns a new PSBT without modifying the original
def strip_non_musig2_derivations(psbt: PSBT) -> PSBT:
    psbt_clone = PSBT()
    psbt_clone.deserialize(psbt.serialize())
    for input in psbt_clone.inputs:
        if input.witness_utxo is not None and is_p2tr(input.witness_utxo.scriptPubKey):
            for key, (_, deriv) in list(input.tap_bip32_paths.items()):
                # a bit hacky, but musig key derivations in wallet policies are always 2 steps
                if len(deriv.path) != 2:
                    del input.tap_bip32_paths[key]
    return psbt_clone


def run_test_e2e_musig2(navigator: Navigator, client: RaggerClient, wallet_policy: WalletPolicy, core_wallet_names: List[str], rpc: AuthServiceProxy, rpc_test_wallet: AuthServiceProxy, speculos_globals: SpeculosGlobals,
                        instructions_register_wallet: Instructions,
                        instructions_sign_psbt: Instructions, test_name: str):
    wallet_id, wallet_hmac = client.register_wallet(wallet_policy, navigator,
                                                    instructions=instructions_register_wallet, testname=f"{test_name}_register")

    assert wallet_id == wallet_policy.id

    assert hmac.compare_digest(
        hmac.new(speculos_globals.wallet_registration_key,
                 wallet_id, sha256).digest(),
        wallet_hmac,
    )

    address_hww = client.get_wallet_address(
        wallet_policy, wallet_hmac, 0, 3, False)

    # ==> verify the address matches what bitcoin-core computes
    receive_descriptor = wallet_policy.get_descriptor(change=False)
    receive_descriptor_info = rpc.getdescriptorinfo(receive_descriptor)
    # bitcoin-core adds the checksum, and requires it for other calls
    receive_descriptor_chk: str = receive_descriptor_info["descriptor"]
    address_core = rpc.deriveaddresses(receive_descriptor_chk, [3, 3])[0]

    assert T(address_hww) == address_core

    # also get the change descriptor for later
    change_descriptor = wallet_policy.get_descriptor(change=True)
    change_descriptor_info = rpc.getdescriptorinfo(change_descriptor)
    change_descriptor_chk: str = change_descriptor_info["descriptor"]

    # ==> import wallet in bitcoin-core

    new_core_wallet_name = get_unique_wallet_name()
    rpc.createwallet(
        wallet_name=new_core_wallet_name,
        disable_private_keys=True,
        descriptors=True,
    )
    core_wallet_rpc = get_wallet_rpc(new_core_wallet_name)

    core_wallet_rpc.importdescriptors([{
        "desc": receive_descriptor_chk,
        "active": True,
        "internal": False,
        "timestamp": "now"
    }, {
        "desc": change_descriptor_chk,
        "active": True,
        "internal": True,
        "timestamp": "now"
    }])

    # ==> fund the wallet and get prevout info

    rpc_test_wallet.sendtoaddress(T(address_hww), "0.1")
    generate_blocks(1)

    assert core_wallet_rpc.getbalances()["mine"]["trusted"] == Decimal("0.1")

    # ==> prepare a psbt spending from the wallet

    out_address = rpc_test_wallet.getnewaddress()

    result = core_wallet_rpc.walletcreatefundedpsbt(
        outputs={
            out_address: Decimal("0.01")
        },
        options={
            # We need a fixed position to be able to know how to navigate in the flows
            "changePosition": 1
        }
    )

    # ==> import descriptor for each bitcoin-core wallet
    for core_wallet_name in core_wallet_names:
        import_descriptors_with_privkeys(
            core_wallet_name, receive_descriptor_chk, change_descriptor_chk)

    psbt_b64 = result["psbt"]

    # Round 1: get nonces

    # ==> get nonce from the hww

    n_internal_keys = count_internal_key_placeholders(
        speculos_globals.seed, "test", wallet_policy, only_musig=True)

    psbt = PSBT()
    psbt.deserialize(psbt_b64)
    psbt.tx.nVersion = 2  # Ensure transaction version 2 (walletcreatefundedpsbt may produce version 1)
    psbt_b64 = psbt.serialize()

    psbt_stripped = strip_non_musig2_derivations(psbt)
    hww_yielded: List[Tuple[int, SignPsbtYieldedObject]] = client.sign_psbt(psbt_stripped, wallet_policy, wallet_hmac, navigator,
                                                                            instructions=instructions_sign_psbt,
                                                                            testname=f"{test_name}_sign")

    for (input_index, yielded) in hww_yielded:
        if isinstance(yielded, MusigPubNonce):
            psbt_key = (
                yielded.participant_pubkey,
                yielded.aggregate_pubkey,
                yielded.tapleaf_hash
            )

            assert len(yielded.aggregate_pubkey) == 33

            psbt.inputs[input_index].musig2_pub_nonces[psbt_key] = yielded.pubnonce
        elif isinstance(yielded, PartialSignature):
            # depending on the policy, a PartialSignature might be returned
            pass
        else:
            # We don't expect a MusigPartialSignature here
            raise ValueError(
                f"sign_psbt yielded an unexpected object for input {input_index}:", yielded)

            # should be true as long as all inputs are internal
    assert len(hww_yielded) == n_internal_keys * len(psbt.inputs)

    signed_psbt_hww_b64 = psbt.serialize()

    # ==> Process it with bitcoin-core to get the musig pubnonces
    partial_psbts = [signed_psbt_hww_b64]

    # partial_psbts = []

    for core_wallet_name in core_wallet_names:
        psbt_res = get_wallet_rpc(
            core_wallet_name).walletprocesspsbt(psbt_b64)["psbt"]
        partial_psbts.append(psbt_res)

    combined_psbt = rpc.combinepsbt(partial_psbts)

    # Round 2: get Musig Partial Signatures

    psbt = PSBT()
    psbt.deserialize(combined_psbt)

    psbt_stripped = strip_non_musig2_derivations(psbt)
    hww_yielded: List[Tuple[int, SignPsbtYieldedObject]] = client.sign_psbt(psbt_stripped, wallet_policy, wallet_hmac, navigator,
                                                                            instructions=instructions_sign_psbt,
                                                                            testname=f"{test_name}_sign")

    for (input_index, yielded) in hww_yielded:
        if isinstance(yielded, MusigPartialSignature):
            psbt_key = (
                yielded.participant_pubkey,
                yielded.aggregate_pubkey,
                yielded.tapleaf_hash
            )

            assert len(yielded.aggregate_pubkey) == 33

            psbt.inputs[input_index].musig2_partial_sigs[psbt_key] = yielded.partial_signature
        elif isinstance(yielded, PartialSignature):
            # depending on the policy, a PartialSignature might be returned
            pass
        else:
            # We don't expect a MusigPubNonce here, we should be in the second round
            raise ValueError(
                f"sign_psbt yielded an unexpected object for input {input_index}:", yielded)

    # should be true as long as all inputs are internal
    assert len(hww_yielded) == n_internal_keys * len(psbt.inputs)

    signed_psbt_hww_b64 = psbt.serialize()

    # ==> Get Musig partial signatures with each bitcoin-core wallet

    partial_psbts = [signed_psbt_hww_b64]
    for core_wallet_name in core_wallet_names:
        psbt_res = get_wallet_rpc(
            core_wallet_name).walletprocesspsbt(combined_psbt)["psbt"]
        partial_psbts.append(psbt_res)

    # ==> finalize the psbt, extract tx and broadcast
    combined_psbt = rpc.combinepsbt(partial_psbts)
    result = rpc.finalizepsbt(combined_psbt)

    assert result["complete"] == True
    rawtx = result["hex"]

    # make sure the transaction is valid by broadcasting it (would fail if rejected)
    rpc.sendrawtransaction(rawtx)


def run_test_invalid(client: RaggerClient, descriptor_template: str, keys_info: List[str]):
    wallet_policy = WalletPolicy(
        name="Invalid wallet",
        descriptor_template=descriptor_template,
        keys_info=keys_info)

    with pytest.raises(ExceptionRAPDU) as e:
        client.register_wallet(wallet_policy)
    assert DeviceException.exc.get(e.value.status) == IncorrectDataError or DeviceException.exc.get(
        e.value.status) == NotSupportedError


def test_e2e_musig2_keypath(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                            test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    path = "48'/1'/0'/2'"
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)

    core_wallet_name, core_xpub_orig = create_new_wallet()
    wallet_policy = WalletPolicy(
        name="Musig 2 my ears",
        descriptor_template="tr(musig(@0,@1)/**)",
        keys_info=[
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpub_orig}",
        ])

    run_test_e2e_musig2(navigator, client, wallet_policy, [core_wallet_name], rpc, rpc_test_wallet, speculos_globals,
                        e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_musig2_keypath2(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                             test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    # We spend with the musig2 in the keypath, but there is a taptree

    path = "48'/1'/0'/2'"
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)

    core_wallet_name, core_xpub_orig = create_new_wallet()
    _, core_xpub_orig_2 = create_new_wallet()
    wallet_policy = WalletPolicy(
        name="Musig 2 my ears",
        descriptor_template="tr(musig(@0,@1)/**,pk(@2/**))",
        keys_info=[
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpub_orig}",
            f"{core_xpub_orig_2}",
        ])

    run_test_e2e_musig2(navigator, client, wallet_policy, [core_wallet_name], rpc, rpc_test_wallet, speculos_globals,
                        e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_musig2_scriptpath(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                               test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    path = "48'/1'/0'/2'"
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)

    core_wallet_name, core_xpub_orig = create_new_wallet()

    # In this policy, the keypath is unspendable

    wallet_policy = WalletPolicy(
        name="Musig 2 my ears",
        descriptor_template="tr(@0/**,pk(musig(@1,@2)/**))",
        keys_info=[
            "tpubD6NzVbkrYhZ4WLczPJWReQycCJdd6YVWXubbVUFnJ5KgU5MDQrD998ZJLSmaB7GVcCnJSDWprxmrGkJ6SvgQC6QAffVpqSvonXmeizXcrkN",
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpub_orig}",
        ])

    run_test_e2e_musig2(navigator, client, wallet_policy, [core_wallet_name], rpc, rpc_test_wallet, speculos_globals,
                        e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_musig2_3of3keypath_decaying_scriptpath(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                                                    test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    path = "48'/1'/0'/2'"
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)

    core_wallet_name_1, core_xpub_orig_1 = create_new_wallet()
    core_wallet_name_2, core_xpub_orig_2 = create_new_wallet()

    wallet_policy = WalletPolicy(
        name="3-of-3-to-2-of-3",
        descriptor_template="tr(musig(@0,@1,@2)/**,and_v(v:multi_a(2,@0/**,@1/**,@2/**),older(12960)))",
        keys_info=[
            f"{core_xpub_orig_1}",
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpub_orig_2}",
        ])

    run_test_e2e_musig2(navigator, client, wallet_policy, [core_wallet_name_1, core_wallet_name_2], rpc, rpc_test_wallet, speculos_globals,
                        e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_musig2_5of5(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                         test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals, enable_slow_tests: int):
    # 5 is the maximum number of keys we support have in a musig2 policy
    # In this test, we have a musig with 5 keys in both the keypath and the script path

    # slow test, only run it if --enable_slow_tests is set to a value greater than 0
    if enable_slow_tests < 1:
        pytest.skip()

    path = "48'/1'/0'/2'"
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)

    num_core_wallets = 8
    core_wallet_names = []
    core_xpubs_orig = []

    for _ in range(num_core_wallets):
        name, xpub = create_new_wallet()
        core_wallet_names.append(name)
        core_xpubs_orig.append(xpub)

    wallet_policy = WalletPolicy(
        name="MuSig Take 5",
        descriptor_template="tr(musig(@0,@1,@2,@3,@4)/**,pk(musig(@5,@6,@7,@1,@8)/**))",
        keys_info=[
            f"{core_xpubs_orig[0]}",
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpubs_orig[1]}",
            f"{core_xpubs_orig[2]}",
            f"{core_xpubs_orig[3]}",
            f"{core_xpubs_orig[4]}",
            f"{core_xpubs_orig[5]}",
            f"{core_xpubs_orig[6]}",
            f"{core_xpubs_orig[7]}",
        ])

    run_test_e2e_musig2(navigator, client, wallet_policy, core_wallet_names, rpc, rpc_test_wallet, speculos_globals,
                        e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_musig_invalid(client: RaggerClient, speculos_globals: SpeculosGlobals):
    path = "48'/1'/0'/2'"
    text_xpub_1 = "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    internal_xpub_orig = f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}"

    # Some of these tests are for script syntax that is not currently supported in wallet policies.
    # Still worth adding the tests, as they should stay invalid even if such syntax is supported in the future.

    two_keys = [internal_xpub_orig, text_xpub_1]

    # no musig solo
    run_test_invalid(client, "tr(musig(@0)/**))", [internal_xpub_orig])

    # Invalid per BIP-390
    run_test_invalid(client, "pk(musig(@0,@1)/**)", two_keys)
    run_test_invalid(client, "pkh(musig(@0,@1)/**)", two_keys)
    run_test_invalid(client, "wpkh(musig(@0,@1)/**)", two_keys)
    run_test_invalid(client, "combo(musig(@0,@1)/**)", two_keys)
    run_test_invalid(client, "sh(wpkh(musig(@0,@1)/**))", two_keys)
    run_test_invalid(client, "sh(wsh(musig(@0,@1)/**))", two_keys)
    run_test_invalid(client, "wsh(musig(@0,@1)/**)", two_keys)
    run_test_invalid(client, "sh(musig(@0,@1)/**)", two_keys)
    run_test_invalid(client, "sh(musig(@0/**,@1/**)/**)", two_keys)

    # nonsensical
    run_test_invalid(client, "musig(@0,@1)/**", two_keys)

    # Invalid per BIP-388
    run_test_invalid(client, "tr(musig(@0,@0,@1)/**))", two_keys)
    run_test_invalid(  # repeated musig() placeholders
        client, "tr(musig(@0,@1)/**,pk(musig(@1,@0)/**))", two_keys)
    run_test_invalid(client, "tr(musig(@0,@1))", two_keys)

    # supported in BIP-390, not in BIP-388
    run_test_invalid(client, "tr(musig(@0/**,@1/**))",  two_keys)
