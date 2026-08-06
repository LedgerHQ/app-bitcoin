import pytest

from typing import List

import hmac
from hashlib import sha256
from decimal import Decimal

from ledger_bitcoin import MultisigWallet, AddressType
from ledger_bitcoin.psbt import PSBT
from ledger_bitcoin.wallet import WalletPolicy

from test_utils import SpeculosGlobals, get_internal_xpub, count_internal_key_placeholders

from ragger_bitcoin import RaggerClient
from ragger_bitcoin.ragger_instructions import Instructions
from ragger.navigator import Navigator
from ragger.firmware import Firmware

from .instructions import e2e_register_wallet_instruction, e2e_sign_psbt_instruction

from .conftest import create_new_wallet, generate_blocks, get_unique_wallet_name, get_wallet_rpc, import_descriptors_with_privkeys, testnet_to_regtest_addr as T
from .conftest import AuthServiceProxy


def run_test(navigator: Navigator, client: RaggerClient, wallet_policy: WalletPolicy,
             core_wallet_names: List[str], rpc: AuthServiceProxy, rpc_test_wallet: AuthServiceProxy,
             speculos_globals: SpeculosGlobals, instructions_register_wallet: Instructions,
             instructions_sign_psbt: Instructions, test_name: str = ""):

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
    receive_descriptor_chk = receive_descriptor_info["descriptor"]
    address_core = rpc.deriveaddresses(receive_descriptor_chk, [3, 3])[0]

    assert T(address_hww) == address_core

    # also get the change descriptor for later
    change_descriptor = wallet_policy.get_descriptor(change=True)
    change_descriptor_info = rpc.getdescriptorinfo(change_descriptor)
    change_descriptor_chk = change_descriptor_info["descriptor"]

    # ==> import wallet in bitcoin-core

    multisig_wallet_name = get_unique_wallet_name()
    rpc.createwallet(
        wallet_name=multisig_wallet_name,
        disable_private_keys=True,
        descriptors=True,
    )
    multisig_rpc = get_wallet_rpc(multisig_wallet_name)
    multisig_rpc.importdescriptors([{
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

    # ==> fund the multisig wallet and get prevout info

    rpc_test_wallet.sendtoaddress(T(address_hww), "0.1")
    generate_blocks(1)

    assert multisig_rpc.getbalances()["mine"]["trusted"] == Decimal("0.1")

    # ==> prepare a psbt spending from the multisig wallet

    out_address = rpc_test_wallet.getnewaddress()

    result = multisig_rpc.walletcreatefundedpsbt(
        outputs={
            out_address: Decimal("0.01")
        },
        options={
            # We need a fixed position to be able to know how to navigate in the flows
            "changePosition": 1
        }
    )

    psbt_b64 = result["psbt"]

    # ==> sign it with the hww

    psbt = PSBT()
    psbt.deserialize(psbt_b64)
    psbt.tx.nVersion = 2  # Ensure transaction version 2 (walletcreatefundedpsbt may produce version 1)
    psbt_b64 = psbt.serialize()

    hww_sigs = client.sign_psbt(psbt, wallet_policy, wallet_hmac, navigator,
                                instructions=instructions_sign_psbt,
                                testname=f"{test_name}_sign")

    n_internal_keys = count_internal_key_placeholders(
        speculos_globals.seed, "test", wallet_policy)
    # should be true as long as all inputs are internal
    assert len(hww_sigs) == n_internal_keys * len(psbt.inputs)

    for i, part_sig in hww_sigs:
        psbt.inputs[i].partial_sigs[part_sig.pubkey] = part_sig.signature

    signed_psbt_hww_b64 = psbt.serialize()

    # ==> import descriptor for each bitcoin-core wallet
    for core_wallet_name in core_wallet_names:
        import_descriptors_with_privkeys(
            core_wallet_name, receive_descriptor_chk, change_descriptor_chk)

    # ==> sign it with bitcoin-core
    partial_psbts = [signed_psbt_hww_b64]

    for core_wallet_name in core_wallet_names:
        partial_psbts.append(get_wallet_rpc(
            core_wallet_name).walletprocesspsbt(psbt_b64)["psbt"])

    # ==> finalize the psbt, extract tx and broadcast
    combined_psbt = rpc.combinepsbt(partial_psbts)
    result = rpc.finalizepsbt(combined_psbt)

    assert result["complete"] == True
    rawtx = result["hex"]

    # make sure the transaction is valid by broadcasting it (would fail if rejected)
    rpc.sendrawtransaction(rawtx)


def test_e2e_multisig_2_of_2(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str, rpc: AuthServiceProxy, rpc_test_wallet, speculos_globals:
                             SpeculosGlobals):
    path = "48'/1'/0'/2'"
    core_wallet_name, core_xpub_orig = create_new_wallet()

    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    wallet_policy = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            f"{core_xpub_orig}",
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
        ],
    )

    run_test(navigator, client, wallet_policy, [core_wallet_name], rpc, rpc_test_wallet,
             speculos_globals, e2e_register_wallet_instruction(
                 firmware, wallet_policy.n_keys),
             e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_multisig_multiple_internal_keys(navigator: Navigator, firmware: Firmware, client:
                                             RaggerClient, test_name: str, rpc: AuthServiceProxy, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    # test an edge case of a multisig where the wallet controls more than one key
    # 3-of-5 multisig where 2 keys are internal

    path_1 = "48'/1'/0'/2'"
    internal_xpub_1 = get_internal_xpub(speculos_globals.seed, path_1)
    path_2 = "48'/1'/1'/2'"
    internal_xpub_2 = get_internal_xpub(speculos_globals.seed, path_2)

    _, core_xpub_orig_1 = create_new_wallet()
    _, core_xpub_orig_2 = create_new_wallet()
    core_wallet_name_3, core_xpub_orig_3 = create_new_wallet()

    wallet_policy = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.WIT,
        threshold=3,
        keys_info=[
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path_1}]{internal_xpub_1}",
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path_2}]{internal_xpub_2}",
            f"{core_xpub_orig_1}",
            f"{core_xpub_orig_2}",
            f"{core_xpub_orig_3}",
        ],
    )

    run_test(navigator, client, wallet_policy, [core_wallet_name_3],
             rpc, rpc_test_wallet, speculos_globals,
             e2e_register_wallet_instruction(firmware, wallet_policy.n_keys),
             e2e_sign_psbt_instruction(firmware), test_name)


@pytest.mark.timeout(0)  # disable timeout
def test_e2e_multisig_15keys(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str, rpc: AuthServiceProxy, rpc_test_wallet, speculos_globals: SpeculosGlobals, enable_slow_tests: int):
    # Largest supported quorum in a multisig.
    # The time for an end-to-end execution on a real Ledger Nano S (including user's input) is about 520 seconds.

    # slow test, only run it if --enable_slow_tests is set to a value greater than 0
    if enable_slow_tests < 1:
        pytest.skip()

    core_wallet_names: List[str] = []
    core_xpub_origs: List[str] = []
    for _ in range(14):
        name, xpub_orig = create_new_wallet()
        core_wallet_names.append(name)
        core_xpub_origs.append(xpub_orig)

    path = "48'/1'/0'/2'"
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)

    wallet_policy = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.WIT,
        threshold=2,
        sorted=True,
        keys_info=core_xpub_origs +
        [f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}"],
    )

    run_test(navigator, client, wallet_policy, core_wallet_names,
             rpc, rpc_test_wallet, speculos_globals,
             e2e_register_wallet_instruction(firmware, wallet_policy.n_keys),
             e2e_sign_psbt_instruction(firmware), test_name)
