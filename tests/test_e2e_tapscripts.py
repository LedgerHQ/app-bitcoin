import pytest

from typing import List

import hmac
from hashlib import sha256
from decimal import Decimal

from ledger_bitcoin.exception.errors import IncorrectDataError, NotSupportedError
from ledger_bitcoin.exception.device_exception import DeviceException
from ledger_bitcoin.psbt import PSBT
from ledger_bitcoin.wallet import WalletPolicy

from test_utils import SpeculosGlobals, get_internal_xpub, count_internal_key_placeholders

from ragger_bitcoin import RaggerClient
from ragger_bitcoin.ragger_instructions import Instructions
from ragger.navigator import Navigator
from ragger.firmware import Firmware
from ragger.error import ExceptionRAPDU

from .instructions import e2e_register_wallet_instruction, e2e_sign_psbt_instruction
from .conftest import AuthServiceProxy, import_descriptors_with_privkeys
from .conftest import create_new_wallet, generate_blocks, get_unique_wallet_name, get_wallet_rpc, testnet_to_regtest_addr as T


def run_test_e2e(navigator: Navigator, client: RaggerClient, wallet_policy: WalletPolicy,
                 core_wallet_names: List[str], rpc: AuthServiceProxy, rpc_test_wallet: AuthServiceProxy,
                 speculos_globals: SpeculosGlobals, instructions_register_wallet: Instructions,
                 instructions_sign_psbt: Instructions, test_name: str = ""):

    wallet_id, wallet_hmac = client.register_wallet(wallet_policy, navigator,
                                                    instructions=instructions_register_wallet, testname=f"{test_name}_register")
    assert wallet_id == wallet_policy.id

    assert hmac.compare_digest(
        hmac.new(speculos_globals.wallet_registration_key, wallet_id, sha256).digest(),
        wallet_hmac,
    )

    address_hww = client.get_wallet_address(wallet_policy, wallet_hmac, 0, 3, False)

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

    # ==> prepare a psbt spending from the wallet

    out_address = rpc_test_wallet.getnewaddress()

    result = multisig_rpc.walletcreatefundedpsbt(
        outputs={
            out_address: Decimal("0.01")
        },
        options={
            "changePosition": 1 # We need a fixed position to be able to know how to navigate in the flows
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

    # only correct for taproot policies
    for i, part_sig in hww_sigs:
        if part_sig.tapleaf_hash is not None:
            # signature for a script spend
            psbt.inputs[i].tap_script_sigs[(part_sig.pubkey, part_sig.tapleaf_hash)] = part_sig.signature
        else:
            # key path spend
            psbt.inputs[i].tap_key_sig = part_sig.signature

    signed_psbt_hww_b64 = psbt.serialize()

    n_internal_keys = count_internal_key_placeholders(speculos_globals.seed, "test", wallet_policy)
    assert len(hww_sigs) == n_internal_keys * len(psbt.inputs)  # should be true as long as all inputs are internal

    # ==> import descriptor for each bitcoin-core wallet
    for core_wallet_name in core_wallet_names:
        import_descriptors_with_privkeys(
            core_wallet_name, receive_descriptor_chk, change_descriptor_chk)

    # ==> sign it with bitcoin-core

    partial_psbts = [signed_psbt_hww_b64]
    for core_wallet_name in core_wallet_names:
        partial_psbt_response = get_wallet_rpc(core_wallet_name).walletprocesspsbt(psbt_b64)
        partial_psbts.append(partial_psbt_response["psbt"])

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
    assert len(e.value.data) == 0


def test_e2e_tapscript_one_of_two_keypath(navigator: Navigator, firmware: Firmware, client:
                                          RaggerClient, test_name: str, rpc, rpc_test_wallet,
                                          speculos_globals: SpeculosGlobals):
    # One of two keys, with the foreign key in the key path spend
    # tr(my_key,pk(foreign_key_1))

    path = "499'/1'/0'"
    _, core_xpub_orig = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    wallet_policy = WalletPolicy(
        name="Tapscript 1-of-2",
        descriptor_template="tr(@0/**,pk(@1/**))",
        keys_info=[
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpub_orig}",
        ])

    run_test_e2e(navigator, client, wallet_policy, [], rpc, rpc_test_wallet, speculos_globals,
                 e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_tapscript_one_of_two_scriptpath(navigator: Navigator, firmware: Firmware, client:
                                             RaggerClient, test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    # One of two keys, with the foreign key in the key path spend
    # tr(foreign_key,pk(my_key))

    path = "499'/1'/0'"
    _, core_xpub_orig = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    wallet_policy = WalletPolicy(
        name="Tapscript 1-of-2",
        descriptor_template="tr(@0/**,pk(@1/**))",
        keys_info=[
            f"{core_xpub_orig}",
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
        ])

    run_test_e2e(navigator, client, wallet_policy, [], rpc, rpc_test_wallet, speculos_globals,
                 e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_tapscript_one_of_three_keypath(navigator: Navigator, firmware: Firmware, client:
                                            RaggerClient, test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    # One of three keys, with the internal one in the key-path spend
    # tr(my_key,{pk(foreign_key_1,foreign_key_2)})

    path = "499'/1'/0'"
    _, core_xpub_orig_1 = create_new_wallet()
    _, core_xpub_orig_2 = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    wallet_policy = WalletPolicy(
        name="Tapscript 1-of-3",
        descriptor_template="tr(@0/**,{pk(@1/**),pk(@2/**)})",
        keys_info=[
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpub_orig_1}",
            f"{core_xpub_orig_2}",
        ])

    run_test_e2e(navigator, client, wallet_policy, [], rpc, rpc_test_wallet, speculos_globals,
                 e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_tapscript_one_of_three_scriptpath(navigator: Navigator, firmware: Firmware, client:
                                               RaggerClient, test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    # One of three keys, with the internal one in on of the scripts
    # tr(foreign_key_1,{pk(my_key,foreign_key_2)})

    path = "499'/1'/0'"
    _, core_xpub_orig_1 = create_new_wallet()
    _, core_xpub_orig_2 = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    wallet_policy = WalletPolicy(
        name="Tapscript 1-of-3",
        descriptor_template="tr(@0/**,{pk(@1/**),pk(@2/**)})",
        keys_info=[
            f"{core_xpub_orig_1}",
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpub_orig_2}",
        ])

    run_test_e2e(navigator, client, wallet_policy, [], rpc, rpc_test_wallet, speculos_globals,
                 e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_tapscript_multi_a_2of2(navigator: Navigator, firmware: Firmware, client:
                                    RaggerClient, test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    # tr(foreign_key_1,multi_a(2,my_key,foreign_key_2))

    path = "499'/1'/0'"
    _, core_xpub_orig_1 = create_new_wallet()
    core_wallet_name2, core_xpub_orig_2 = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    wallet_policy = WalletPolicy(
        name="Tapscript 1 or 2-of-2",
        descriptor_template="tr(@0/**,multi_a(2,@1/**,@2/**))",
        keys_info=[
            f"{core_xpub_orig_1}",
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpub_orig_2}",
        ])

    run_test_e2e(navigator, client, wallet_policy, [core_wallet_name2], rpc, rpc_test_wallet, speculos_globals,
                 e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_tapscript_maxdepth(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                                test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    # A taproot tree with maximum supported depth, where the internal key is in the deepest script
    MAX_TAPTREE_POLICY_DEPTH = 9

    # Make the most unbalanced tree where each script is a simple pk()
    parts = [f"pk(@{i}/**)" for i in range(1, MAX_TAPTREE_POLICY_DEPTH)]
    descriptor_template = "tr(@0/**,{" + ',{'.join(parts) + \
        f",pk(@{MAX_TAPTREE_POLICY_DEPTH}/**)" + "}" * (MAX_TAPTREE_POLICY_DEPTH - 1) + ")"

    keys_info = []
    for _ in range(MAX_TAPTREE_POLICY_DEPTH):
        _, core_xpub_orig = create_new_wallet()
        keys_info.append(core_xpub_orig)

    # the last (deepest) script is the only one we sign with the ledger key
    path = "499'/1'/0'"
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    keys_info.append(f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}")

    wallet_policy = WalletPolicy(
        name="Tapscriptception",
        descriptor_template=descriptor_template,
        keys_info=keys_info)

    run_test_e2e(navigator, client, wallet_policy, [], rpc, rpc_test_wallet, speculos_globals,
                 e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_tapscript_large(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                             test_name: str, rpc, rpc_test_wallet, speculos_globals:
                             SpeculosGlobals):
    # A quite large tapscript with 8 tapleaves and 10 keys in total.

    keys_info = []

    core_wallet_name = None
    for i in range(10 - 1):
        core_wallet_name_i, core_xpub_orig = create_new_wallet()
        if i == 6:
            # sign with bitcoin-core using the seventh external key (it will be key @6 in the policy)
            core_wallet_name = core_wallet_name_i
        keys_info.append(core_xpub_orig)

    path = "499'/1'/0'"
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)

    # the internal key is key @9, in a 2-of-4 multisig
    keys_info.insert(9, f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}")

    wallet_policy = WalletPolicy(
        name="Tapzilla",
        descriptor_template="tr(@0/**,{{{sortedmulti_a(1,@1/**,@2/**,@3/**,@4/**,@5/**),multi_a(2,@6/<2;3>/*,@7/**,@8/**)},{multi_a(2,@9/**,@6/**,@0/<2;3>/*,@1/<2;3>/*),pk(@2/<2;3>/*)}},{{multi_a(2,@3/<2;3>/*,@4/<2;3>/*),multi_a(3,@5/<2;3>/*,@7/<2;3>/*,@8/<2;3>/*)},{multi_a(2,@9/<2;3>/*,@0/<4;5>/*),pk(@1/<4;5>/*)}}})",
        keys_info=keys_info)

    run_test_e2e(navigator, client, wallet_policy, [core_wallet_name], rpc, rpc_test_wallet, speculos_globals,
                 e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_tapminiscript_keypath_or_decaying_3of3(navigator: Navigator, firmware: Firmware,
                                                    client: RaggerClient, test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    # The key path is external
    # The only script path is a decaying 3-of-3 that becomes a 2-of-3 after the timelock.
    # Only one internal key in the script path.

    path = "499'/1'/0'"
    _, core_xpub_orig_1 = create_new_wallet()
    core_name_2, core_xpub_orig_2 = create_new_wallet()
    core_name_3, core_xpub_orig_3 = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    wallet_policy = WalletPolicy(
        name="Internal or decaying 3-of-3",
        descriptor_template="tr(@0/**,thresh(3,pk(@1/**),s:pk(@2/**),s:pk(@3/**),sln:older(12960)))",
        keys_info=[
            f"{core_xpub_orig_1}",
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpub_orig_2}",
            f"{core_xpub_orig_3}",
        ])

    run_test_e2e(navigator, client, wallet_policy, [core_name_2, core_name_3], rpc, rpc_test_wallet, speculos_globals,
                 e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_tapminiscript_with_hash256(navigator: Navigator, firmware: Firmware, client:
                                        RaggerClient, test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    # a taptree containing a hash challenge in a script path (but we're signing for the other script path)
    path = "499'/1'/0'"
    _, core_xpub_orig_1 = create_new_wallet()
    _, core_xpub_orig_2 = create_new_wallet()
    core_name_3, core_xpub_orig_3 = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    wallet_policy = WalletPolicy(
        name="Hash challenge",
        descriptor_template="tr(@0/**,{and_v(v:pk(@1/**),hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588)),multi_a(2,@2/**,@3/**)})",
        keys_info=[
            f"{core_xpub_orig_1}",
            f"{core_xpub_orig_2}",
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpub_orig_3}",
        ])

    run_test_e2e(navigator, client, wallet_policy, [core_name_3], rpc, rpc_test_wallet, speculos_globals,
                 e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_tapminiscript_mixed_leaves(navigator: Navigator, firmware: Firmware, client:
                                        RaggerClient, test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    # A leaf has miniscript, a leaf has sortedmulti_a (which is not miniscript)

    path = "499'/1'/0'"
    _, core_xpub_orig_1 = create_new_wallet()
    _, core_xpub_orig_2 = create_new_wallet()
    _, core_xpub_orig_3 = create_new_wallet()
    _, core_xpub_orig_4 = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    wallet_policy = WalletPolicy(
        name="Mixed tapminiscript and not",
        descriptor_template="tr(@0/**,{sortedmulti_a(1,@1/**,@2/**),or_b(pk(@3/**),s:pk(@4/**))})",
        keys_info=[
            f"{core_xpub_orig_1}",
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpub_orig_2}",
            f"{core_xpub_orig_3}",
            f"{core_xpub_orig_4}",
        ])

    run_test_e2e(navigator, client, wallet_policy, [], rpc, rpc_test_wallet, speculos_globals,
                 e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_invalid_tapminiscript(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                               test_name: str, speculos_globals: SpeculosGlobals):
    path = "48'/1'/0'/2'"
    _, core_xpub_orig1 = create_new_wallet()
    _, core_xpub_orig2 = create_new_wallet()
    _, core_xpub_orig3 = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    internal_xpub_orig = f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}"

    # can't have scripts in the key path
    run_test_invalid(client, "tr(pk(@0/**))", [internal_xpub_orig])
    run_test_invalid(client, "tr(pk(@0/**),pk(@1/**))", [internal_xpub_orig, core_xpub_orig1])

    # test scripts that are invalid inside taproot trees
    run_test_invalid(client, "tr(@0,sh(pk(@1/**)))", [internal_xpub_orig, core_xpub_orig1])
    run_test_invalid(client, "tr(@0,wsh(pk(@1/**)))", [internal_xpub_orig, core_xpub_orig1])
    run_test_invalid(client, "tr(@0,multi(1,@1/**,@2/**))", [internal_xpub_orig, core_xpub_orig1, core_xpub_orig2])
    run_test_invalid(client, "tr(@0,sortedmulti(1,@1/**,@2/**))",
                     [internal_xpub_orig, core_xpub_orig1, core_xpub_orig2])

    # sortedmulti_a is not valid tapminiscript (but it's valid as a tapscript)
    run_test_invalid(client, "tr(@0,or_d(pk(@1/**),sortedmulti_a(2,@2/**,@3/**)))",
                     [
                         internal_xpub_orig,
                         f"{core_xpub_orig1}",
                         f"{core_xpub_orig2}",
                         f"{core_xpub_orig3}",
                     ])
