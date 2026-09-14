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

from .conftest import create_new_wallet, generate_blocks, get_unique_wallet_name, get_wallet_rpc, import_descriptors_with_privkeys, testnet_to_regtest_addr as T
from .conftest import AuthServiceProxy


def run_test_e2e(navigator: Navigator, client: RaggerClient, wallet_policy: WalletPolicy, core_wallet_names: List[str], rpc: AuthServiceProxy, rpc_test_wallet: AuthServiceProxy, speculos_globals: SpeculosGlobals,
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


def test_e2e_miniscript_one_of_two_1(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                                     test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    # One of two keys (equally likely)
    # or(pk(key_1),pk(key_2))

    path = "499'/1'/0'"
    _, core_xpub_orig = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    wallet_policy = WalletPolicy(
        name="Joint account",
        descriptor_template="wsh(or_b(pk(@0/**),s:pk(@1/**)))",
        keys_info=[
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpub_orig}",
        ])

    run_test_e2e(navigator, client, wallet_policy, [], rpc, rpc_test_wallet, speculos_globals,
                 e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_miniscript_one_of_two_2(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                                     test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    # One of two keys (one likely, one unlikely)
    # or(99@pk(key_likely),pk(key_unlikely))

    path = "499'/1'/0'"
    _, core_xpub_orig = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    wallet_policy = WalletPolicy(
        name="Joint account",
        descriptor_template="wsh(or_d(pk(@0/**),pkh(@1/**)))",
        keys_info=[
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpub_orig}",
        ])

    run_test_e2e(navigator, client, wallet_policy, [_], rpc, rpc_test_wallet, speculos_globals,
                 e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_miniscript_2fa(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                            test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    # A user and a 2FA service need to sign off, but after 90 days the user alone is enough
    # and(pk(key_user),or(99@pk(key_service),older(12960)))

    path = "48'/1'/0'/2'"
    core_wallet_name, core_xpub_orig = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    wallet_policy = WalletPolicy(
        name="2FA wallet",
        descriptor_template="wsh(and_v(v:pk(@0/**),or_d(pk(@1/**),older(12960))))",
        keys_info=[
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpub_orig}",
        ])

    run_test_e2e(navigator, client, wallet_policy, [core_wallet_name], rpc, rpc_test_wallet, speculos_globals,
                 e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_miniscript_decaying_3of3(navigator: Navigator, firmware: Firmware, client:
                                      RaggerClient, test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    # A 3-of-3 that becomes a 2-of-3 after 90 days
    # thresh(3,pk(key_1),pk(key_2),pk(key_3),older(12960))

    path = "48'/1'/0'/2'"
    core_wallet_name1, core_xpub_orig1 = create_new_wallet()
    core_wallet_name2, core_xpub_orig2 = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    wallet_policy = WalletPolicy(
        name="Decaying 3of3",
        descriptor_template="wsh(thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@2/**),sln:older(12960)))",
        keys_info=[
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpub_orig1}",
            f"{core_xpub_orig2}",
        ])

    run_test_e2e(navigator, client, wallet_policy, [core_wallet_name1, core_wallet_name2], rpc, rpc_test_wallet, speculos_globals,
                 e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_miniscript_bolt3_offered_htlc(navigator: Navigator, firmware: Firmware, client:
                                           RaggerClient, test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    # The BOLT #3 offered HTLC policy
    # or(pk(key_revocation),and(pk(key_remote),or(pk(key_local),hash160(H))))

    path = "48'/1'/0'/2'"
    core_wallet_name1, core_xpub_orig1 = create_new_wallet()
    core_wallet_name2, core_xpub_orig2 = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    H = "395e368b267d64945f30e4b71de1054f364c9473"  # random
    wallet_policy = WalletPolicy(
        name="BOLT #3 offered",
        descriptor_template=f"wsh(t:or_c(pk(@0/**),and_v(v:pk(@1/**),or_c(pk(@2/**),v:hash160({H})))))",
        keys_info=[
            f"{core_xpub_orig1}",
            f"{core_xpub_orig2}",
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
        ])

    run_test_e2e(navigator, client, wallet_policy, [core_wallet_name1, core_wallet_name2], rpc, rpc_test_wallet, speculos_globals,
                 e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_miniscript_bolt3_received_htlc(navigator: Navigator, firmware: Firmware, client:
                                            RaggerClient, test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    # The BOLT #3 received HTLC policy
    # andor(pk(key_remote),or_i(and_v(v:pkh(key_local),hash160(H)),older(1008)),pk(key_revocation))

    path = "48'/1'/0'/2'"
    core_wallet_name1, core_xpub_orig1 = create_new_wallet()
    core_wallet_name2, core_xpub_orig2 = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    H = "395e368b267d64945f30e4b71de1054f364c9473"  # random
    wallet_policy = WalletPolicy(
        name="BOLT #3 received",
        descriptor_template=f"wsh(andor(pk(@0/**),or_i(and_v(v:pkh(@1/**),hash160({H})),older(1008)),pk(@2/**)))",
        keys_info=[
            f"{core_xpub_orig1}",
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpub_orig2}",
        ])

    run_test_e2e(navigator, client, wallet_policy, [core_wallet_name1, core_wallet_name2], rpc, rpc_test_wallet, speculos_globals,
                 e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_miniscript_me_or_3of5(navigator: Navigator, firmware: Firmware, client:
                                   RaggerClient, test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    path = "48'/1'/0'/2'"
    _, core_xpub_orig1 = create_new_wallet()
    _, core_xpub_orig2 = create_new_wallet()
    _, core_xpub_orig3 = create_new_wallet()
    _, core_xpub_orig4 = create_new_wallet()
    _, core_xpub_orig5 = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    internal_xpub_orig = f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}"

    wallet_policy = WalletPolicy(
        name="Me or them",
        descriptor_template="wsh(or_d(pk(@0/**),multi(3,@1/**,@2/**,@3/**,@4/**,@5/**)))",
        keys_info=[
            internal_xpub_orig,
            f"{core_xpub_orig1}",
            f"{core_xpub_orig2}",
            f"{core_xpub_orig3}",
            f"{core_xpub_orig4}",
            f"{core_xpub_orig5}",
        ])

    run_test_e2e(navigator, client, wallet_policy, [], rpc, rpc_test_wallet, speculos_globals,
                 e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_miniscript_me_large_vault(navigator: Navigator, firmware: Firmware, client:
                                       RaggerClient, test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    path = "48'/1'/0'/2'"
    _, core_xpub_orig1 = create_new_wallet()
    _, core_xpub_orig2 = create_new_wallet()
    _, core_xpub_orig3 = create_new_wallet()
    _, core_xpub_orig4 = create_new_wallet()
    _, core_xpub_orig5 = create_new_wallet()
    _, core_xpub_orig6 = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    internal_xpub_orig = f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}"

    wallet_policy = WalletPolicy(
        name="Large vault",
        descriptor_template="wsh(or_d(pk(@0/**),andor(thresh(1,utv:thresh(1,pkh(@1/**),a:pkh(@2/**)),autv:thresh(1,pkh(@3/**),a:pkh(@4/**))),after(1685577600),and_v(v:and_v(v:pkh(@5/**),thresh(1,pkh(@6/**))),after(1685318400)))))",
        keys_info=[
            internal_xpub_orig,
            f"{core_xpub_orig1}",
            f"{core_xpub_orig2}",
            f"{core_xpub_orig3}",
            f"{core_xpub_orig4}",
            f"{core_xpub_orig5}",
            f"{core_xpub_orig6}",
        ])

    run_test_e2e(navigator, client, wallet_policy, [], rpc, rpc_test_wallet, speculos_globals,
                 e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_miniscript_me_and_bob_or_me_and_carl_1(navigator: Navigator, firmware: Firmware,
                                                    client: RaggerClient, test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    # policy: or(and(pk(A1), pk(B)),and(pk(A2), pk(C)))
    # where A1 and A2 are both internal keys; therefore, two signatures per input must be returned

    core_wallet_name1, core_xpub_orig1 = create_new_wallet()
    _, core_xpub_orig2 = create_new_wallet()

    path1 = "44'/1'/0'"
    path2 = "44'/1'/1'"
    internal_xpub_1 = get_internal_xpub(speculos_globals.seed, path1)
    internal_xpub_orig_1 = f"[{speculos_globals.master_key_fingerprint.hex()}/{path1}]{internal_xpub_1}"
    internal_xpub_2 = get_internal_xpub(speculos_globals.seed, path2)
    internal_xpub_orig_2 = f"[{speculos_globals.master_key_fingerprint.hex()}/{path2}]{internal_xpub_2}"

    wallet_policy = WalletPolicy(
        name="Me and Bob or me and Carl",
        descriptor_template="wsh(c:andor(pk(@0/**),pk_k(@1/**),and_v(v:pk(@2/**),pk_k(@3/**))))",
        keys_info=[
            internal_xpub_orig_1,
            f"{core_xpub_orig1}",
            internal_xpub_orig_2,
            f"{core_xpub_orig2}",
        ])

    run_test_e2e(navigator, client, wallet_policy, [core_wallet_name1], rpc, rpc_test_wallet, speculos_globals,
                 e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_miniscript_policy_with_a(navigator: Navigator, firmware: Firmware, client:
                                      RaggerClient, test_name: str,  rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    # versions 2.1.0 and 2.1.1 of the app incorrectly compiled the 'a:' wrapper, producing incorrect addresses

    _, core_xpub_orig1 = create_new_wallet()
    core_wallet_name2, core_xpub_orig2 = create_new_wallet()
    _, core_xpub_orig3 = create_new_wallet()
    _, core_xpub_orig4 = create_new_wallet()

    path = "48'/1'/0'/2'"
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    internal_xpub_orig = f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}"

    wallet_policy = WalletPolicy(
        name="Policy with a:",
        descriptor_template="wsh(or_i(and_v(v:pkh(@0/**),older(65535)),or_d(multi(2,@1/**,@2/**),and_v(v:thresh(1,pkh(@3/**),a:pkh(@4/**)),older(64231)))))",
        keys_info=[
            f"{core_xpub_orig1}",
            internal_xpub_orig,
            f"{core_xpub_orig2}",
            f"{core_xpub_orig3}",
            f"{core_xpub_orig4}",
        ])

    run_test_e2e(navigator, client, wallet_policy, [core_wallet_name2], rpc, rpc_test_wallet, speculos_globals,
                 e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_invalid_miniscript(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                            test_name: str, rpc, speculos_globals: SpeculosGlobals):
    path = "48'/1'/0'/2'"
    _, core_xpub_orig1 = create_new_wallet()
    _, core_xpub_orig2 = create_new_wallet()
    _, core_xpub_orig3 = create_new_wallet()
    _, core_xpub_orig4 = create_new_wallet()
    _, core_xpub_orig5 = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    internal_xpub_orig = f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}"

    # sh(sh(...)), wsh(sh(...)), wsh(wsh(...)) are invalid
    run_test_invalid(client, "sh(sh(pkh(@0/**)))", [internal_xpub_orig])
    run_test_invalid(client, "wsh(sh(pkh(@0/**)))", [internal_xpub_orig])
    run_test_invalid(client, "wsh(wsh(pkh(@0/**)))", [internal_xpub_orig])

    # sh(wsh(...)) is meaningful with valid miniscript, but current implementation of miniscript assumes wsh(...)
    run_test_invalid(client, "sh(wsh(or_d(pk(@0/**),pkh(@1/**))))",
                     [internal_xpub_orig, core_xpub_orig1])

    # tr must be top-level
    run_test_invalid(client, "wsh(tr(pk(@0/**)))", [internal_xpub_orig])
    run_test_invalid(client, "sh(tr(pk(@0/**)))", [internal_xpub_orig])

    # valid miniscript must be inside wsh()
    run_test_invalid(client, "or_d(pk(@0/**),pkh(@1/**))",
                     [internal_xpub_orig, core_xpub_orig1])
    run_test_invalid(client, "sh(or_d(pk(@0/**),pkh(@1/**)))",
                     [internal_xpub_orig, core_xpub_orig1])

    # sortedmulti is not valid miniscript, can only be used as a descriptor inside sh or wsh
    run_test_invalid(client, "wsh(or_d(pk(@0/**),sortedmulti(3,@1/**,@2/**,@3/**,@4/**,@5/**)))",
                     [
                         internal_xpub_orig,
                         f"{core_xpub_orig1}",
                         f"{core_xpub_orig2}",
                         f"{core_xpub_orig3}",
                         f"{core_xpub_orig4}",
                         f"{core_xpub_orig5}",
                     ])
