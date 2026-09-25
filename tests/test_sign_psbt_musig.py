
from pathlib import Path

from hashlib import sha256
import hmac
from typing import Dict, Optional, Tuple

import pytest

from ragger.error import ExceptionRAPDU

from ledger_bitcoin.exception.errors import IncorrectDataError
from ledger_bitcoin.exception.device_exception import DeviceException
from ledger_bitcoin.client_base import Client, MusigPartialSignature, MusigPubNonce
from ledger_bitcoin.key import ExtendedKey, KeyOriginInfo
from ledger_bitcoin.psbt import PSBT
from ragger.navigator import Navigator
from ragger.firmware import Firmware

from ledger_bitcoin.wallet import WalletPolicy
from ragger_bitcoin import RaggerClient
from test_utils import SpeculosGlobals, bip0327
from test_utils.musig2 import HotMusig2Cosigner, MuSig2KeyPlaceholder, PsbtMusig2Cosigner, TrDescriptorTemplate, aggregate_musig_pubkey, process_placeholder, run_musig2_test, tapleaf_hash
from test_utils.taproot import taproot_output_script
from .instructions import *

tests_root: Path = Path(__file__).parent


# for now, we assume that there's a single internal musig placeholder, with a single internal key
class LedgerMusig2Cosigner(PsbtMusig2Cosigner):
    """
    Implements a PsbtMusig2Cosigner that uses a BitcoinClient
    """

    def __init__(self, client: Client, wallet_policy: WalletPolicy, wallet_hmac: bytes, *, navigator: Optional[Navigator] = None,
                 testname: str = "", instructions: Instructions = None) -> None:
        super().__init__()

        self.client = client
        self.wallet_policy = wallet_policy
        self.wallet_hmac = wallet_hmac

        self.navigator = navigator
        self.testname = testname
        self.instructions = instructions

        self.fingerprint = client.get_master_fingerprint()

        desc_tmpl = TrDescriptorTemplate.from_string(
            wallet_policy.descriptor_template)

        self.pubkey = None
        for _, (placeholder, _) in enumerate(desc_tmpl.placeholders()):
            if not isinstance(placeholder, MuSig2KeyPlaceholder):
                continue

            for i in placeholder.key_indexes:
                key_info = self.wallet_policy.keys_info[i]
                if key_info[0] == "[" and key_info[1:9] == self.fingerprint.hex():
                    xpub = key_info[key_info.find(']') + 1:]
                    self.pubkey = ExtendedKey.deserialize(xpub)
                    break

            if self.pubkey is not None:
                break

        if self.pubkey is None:
            raise ValueError("no musig with an internal key in wallet policy")

    def get_participant_pubkey(self) -> bip0327.Point:
        return bip0327.cpoint(self.pubkey.pubkey)

    def generate_public_nonces(self, psbt: PSBT) -> None:
        print("PSBT before nonce generation:", psbt.serialize())
        res = self.client.sign_psbt(
            psbt, self.wallet_policy, self.wallet_hmac, navigator=self.navigator, testname=self.testname, instructions=self.instructions)
        print("Pubnonces:", res)
        for (input_index, yielded) in res:
            if isinstance(yielded, MusigPubNonce):
                psbt_key = (
                    yielded.participant_pubkey,
                    yielded.aggregate_pubkey,
                    yielded.tapleaf_hash
                )
                print("Adding pubnonce to psbt for Ledger input", input_index)
                print("Key:", psbt_key)
                print("Value:", yielded.pubnonce)

                assert len(yielded.aggregate_pubkey) == 33

                psbt.inputs[input_index].musig2_pub_nonces[psbt_key] = yielded.pubnonce

    def generate_partial_signatures(self, psbt: PSBT) -> None:
        print("PSBT before partial signature generation:", psbt.serialize())
        res = self.client.sign_psbt(
            psbt, self.wallet_policy, self.wallet_hmac, navigator=self.navigator, testname=self.testname, instructions=self.instructions)
        print("Ledger result of second round:", res)
        for (input_index, yielded) in res:
            if isinstance(yielded, MusigPartialSignature):
                psbt_key = (
                    yielded.participant_pubkey,
                    yielded.aggregate_pubkey,
                    yielded.tapleaf_hash
                )

                print("Adding partial signature to psbt for Ledger input", input_index)
                print("Key:", psbt_key)
                print("Value:", yielded.partial_signature)

                psbt.inputs[input_index].musig2_partial_sigs[psbt_key] = yielded.partial_signature
            elif isinstance(yielded, MusigPubNonce):
                raise ValueError("Expected partial signatures, got a pubnonce")


KEYPATH_COSIGNER_1_XPUB = "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"
KEYPATH_COSIGNER_2_XPRIV = "tprv8gFWbQBTLFhbX3EK3cS7LmenwE3JjXbD9kN9yXfq7LcBm81RSf8vPGPqGPjZSeX41LX9ZN14St3z8YxW48aq5Yhr9pQZVAyuBthfi6quTCf"
KEYPATH_COSIGNER_2_XPUB = "tpubDCwYjpDhUdPGQWG6wG6hkBJuWFZEtrn7j3xwG3i8XcQabcGC53xWZm1hSXrUPFS5UvZ3QhdPSjXWNfWmFGTioARHuG5J7XguEjgg7p8PxAm"

KEYPATH_PSBT_B64 = "cHNidP8BAIACAAAAAdF2HhQ2XCgTpd3Sel7VkS5FvESbwo1rgeuG4tBt9GICAAAAAAD9////AQAAAAAAAAAARGpCVGhpcyBpbnB1dHMgaGFzIHR3byBwdWJrZXlzIGJ1dCB5b3Ugb25seSBzZWUgb25lLiAjbXBjZ2FuZyByZXZlbmdlAAAAAAABASuf/gQAAAAAACJRIMH9/r7QY6oUg0DEUTLmcY2N6BRmriuQkp49kyg2TNbtIRaQZkYWUCCfi7xZsFr10WFcUPX3nBiNe+dC/ZMiUvaPDA0AW4+8kwAAAAADAAAAAAA="

KEYPATH_SIGHASHES = [
    bytes.fromhex(
        "a3aeecb6c236b4a7e72c95fa138250d449b97a75c573f8ab612356279ff64046")
]


def keypath_wallet_policy(speculos_globals: SpeculosGlobals) -> Tuple[WalletPolicy, bytes]:
    wallet_policy = WalletPolicy(
        name="Musig for my ears",
        descriptor_template="tr(musig(@0,@1)/**)",
        keys_info=[KEYPATH_COSIGNER_1_XPUB, KEYPATH_COSIGNER_2_XPUB]
    )
    wallet_hmac = hmac.new(
        speculos_globals.wallet_registration_key, wallet_policy.id, sha256).digest()
    return wallet_policy, wallet_hmac


def test_sign_psbt_musig2_keypath(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str, speculos_globals: SpeculosGlobals):
    cosigner_2_xpriv = KEYPATH_COSIGNER_2_XPRIV

    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    psbt = PSBT()
    psbt.deserialize(KEYPATH_PSBT_B64)

    sighashes = KEYPATH_SIGHASHES

    signer_1 = LedgerMusig2Cosigner(client, wallet_policy, wallet_hmac,
                                    navigator=navigator, instructions=sign_psbt_instruction_approve(firmware, save_screenshot=False, has_spend_from_wallet=True, has_feewarning=True), testname=test_name)
    signer_2 = HotMusig2Cosigner(wallet_policy, cosigner_2_xpriv)

    run_musig2_test(wallet_policy, psbt, [signer_1, signer_2], sighashes)


def test_sign_psbt_musig2_scriptpath(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str, speculos_globals: SpeculosGlobals):
    cosigner_1_xpub = "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"

    cosigner_2_xpriv = "tprv8gFWbQBTLFhbX3EK3cS7LmenwE3JjXbD9kN9yXfq7LcBm81RSf8vPGPqGPjZSeX41LX9ZN14St3z8YxW48aq5Yhr9pQZVAyuBthfi6quTCf"
    cosigner_2_xpub = ExtendedKey.deserialize(
        cosigner_2_xpriv).neutered().to_string()

    wallet_policy = WalletPolicy(
        name="Musig2 in the scriptpath",
        descriptor_template="tr(@0/**,pk(musig(@1,@2)/**))",
        keys_info=[
            "tpubD6NzVbkrYhZ4WLczPJWReQycCJdd6YVWXubbVUFnJ5KgU5MDQrD998ZJLSmaB7GVcCnJSDWprxmrGkJ6SvgQC6QAffVpqSvonXmeizXcrkN",
            cosigner_1_xpub,
            cosigner_2_xpub
        ]
    )
    wallet_hmac = hmac.new(
        speculos_globals.wallet_registration_key, wallet_policy.id, sha256).digest()

    psbt_b64 = "cHNidP8BAFoCAAAAAdOnEESfpXpBe9X59Q4jxz1u9E4Wovn2bkAuuyqUUY0mAAAAAAD9////AQAAAAAAAAAAHmocTXVzaWcyLiBOb3cgZXZlbiBpbiBTY3JpcHRzLgAAAAAAAQErOTAAAAAAAAAiUSDtVR7h2JYPJC463zrCcmfKriiugHBXAcXDP1O2ptF2LyIVwethFsEeXf/x51pIczoAIsj9RoVePIBTyk/rOMW8B6uIIyCQZkYWUCCfi7xZsFr10WFcUPX3nBiNe+dC/ZMiUvaPDKzAIRaQZkYWUCCfi7xZsFr10WFcUPX3nBiNe+dC/ZMiUvaPDC0BuYMCXh1wIlpyBMdMaCFPSwOeOyvhqg+FJ+fOMoWlJsRbj7yTAAAAAAMAAAABFyDrYRbBHl3/8edaSHM6ACLI/UaFXjyAU8pP6zjFvAeriAEYILmDAl4dcCJacgTHTGghT0sDnjsr4aoPhSfnzjKFpSbEAAA="
    psbt = PSBT()
    psbt.deserialize(psbt_b64)

    sighashes = [
        bytes.fromhex(
            "28f86cd95c144ed4a877701ae7166867e8805b654c43d9f44da45d7b0070c313")
    ]

    signer_1 = LedgerMusig2Cosigner(client, wallet_policy, wallet_hmac,
                                    navigator=navigator, instructions=sign_psbt_instruction_approve(firmware, save_screenshot=False, has_spend_from_wallet=True), testname=test_name)
    signer_2 = HotMusig2Cosigner(wallet_policy, cosigner_2_xpriv)

    run_musig2_test(wallet_policy, psbt, [signer_1, signer_2], sighashes)


def musig_pubnonce_ids(wallet_policy: WalletPolicy, psbt: PSBT) -> Dict[Tuple[int, int], Tuple[bytes, Optional[bytes]]]:
    """
    For each (input index, musig() key placeholder index) pair of the psbt, returns the
    (aggregate pubkey after the tweaks, tapleaf hash) pair that, together with the participant's
    pubkey, identifies the pubnonces and partial signatures in the psbt.
    """
    desc_tmpl = TrDescriptorTemplate.from_string(wallet_policy.descriptor_template)
    result = {}
    for placeholder_index, (placeholder, tapleaf_desc) in enumerate(desc_tmpl.placeholders()):
        if not isinstance(placeholder, MuSig2KeyPlaceholder):
            continue

        agg_xpub_str, keyagg_ctx = aggregate_musig_pubkey(
            wallet_policy.keys_info[i] for i in placeholder.key_indexes)
        agg_xpub = ExtendedKey.deserialize(agg_xpub_str)

        for input_index, input in enumerate(psbt.inputs):
            res = process_placeholder(
                wallet_policy, input, placeholder, keyagg_ctx, agg_xpub, tapleaf_desc, desc_tmpl)
            if res is not None:
                (_, _, leaf_script, aggpk_tweaked) = res
                result[(input_index, placeholder_index)] = (
                    aggpk_tweaked, tapleaf_hash(leaf_script))
    return result


class Round1OnOtherTxCosigner(LedgerMusig2Cosigner):
    """
    A LedgerMusig2Cosigner that executes round 1 on a completely different transaction than the one
    that is going to be signed, and then reuses the resulting pubnonces. This is what a software
    wallet does when it pre-generates the pubnonces before the transaction is known.
    """

    def __init__(self, other_psbt: PSBT, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.other_psbt = other_psbt

    def generate_public_nonces(self, psbt: PSBT) -> None:
        # the device only ever sees the unrelated transaction during round 1
        super().generate_public_nonces(self.other_psbt)

        # Transplant the pubnonces into the transaction that will actually be signed.
        src_ids = musig_pubnonce_ids(self.wallet_policy, self.other_psbt)
        dst_ids = musig_pubnonce_ids(self.wallet_policy, psbt)
        n_transplanted = 0
        for (input_index, placeholder_index), (src_aggpk, src_leaf_hash) in src_ids.items():
            dst_aggpk, dst_leaf_hash = dst_ids[(input_index, placeholder_index)]
            src_key = (self.pubkey.pubkey, src_aggpk, src_leaf_hash)
            if src_key in self.other_psbt.inputs[input_index].musig2_pub_nonces:
                psbt.inputs[input_index].musig2_pub_nonces[(self.pubkey.pubkey, dst_aggpk, dst_leaf_hash)] = \
                    self.other_psbt.inputs[input_index].musig2_pub_nonces[src_key]
                n_transplanted += 1
        assert n_transplanted > 0


def test_sign_psbt_musig2_round1_on_another_transaction(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str, speculos_globals: SpeculosGlobals):
    # Neither the pubnonces nor the psbt_session_id depend on the transaction, therefore pubnonces
    # obtained in round 1 for one transaction are valid for any other transaction of the same wallet
    # policy, as long as the inputs are at the same indexes.
    # This is needed by software wallets that want to pre-generate the pubnonces before the
    # transaction is known, keeping the UX of musig similar to a regular multisig.
    #
    # This test would have failed on versions of the app until 2.5.1, since the psbt_session_id
    # used to depend on the transaction.
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    psbt = PSBT()
    psbt.deserialize(KEYPATH_PSBT_B64)

    other_psbt = PSBT()
    other_psbt.deserialize(KEYPATH_PSBT_B64)
    other_psbt.tx.vin[0].prevout.hash ^= 1
    other_psbt.tx.vout[0].nValue += 1000
    other_psbt.tx.rehash()

    other_input = other_psbt.inputs[0]
    ((_, (_, key_origin)),) = other_input.tap_bip32_paths.items()
    assert key_origin.path == [0, 3]
    other_steps = [1, 7]  # change address with index 7, instead of receive address with index 3
    agg_xpub = ExtendedKey.deserialize(aggregate_musig_pubkey(wallet_policy.keys_info)[0])
    other_internal_key = agg_xpub.derive_pub_path(other_steps).pubkey[1:]
    other_input.tap_bip32_paths = {
        other_internal_key: (set(), KeyOriginInfo(key_origin.fingerprint, other_steps))
    }
    other_input.witness_utxo.scriptPubKey = taproot_output_script(other_internal_key, None)

    assert musig_pubnonce_ids(wallet_policy, other_psbt)[(0, 0)] != \
        musig_pubnonce_ids(wallet_policy, psbt)[(0, 0)]

    signer_1 = Round1OnOtherTxCosigner(other_psbt, client, wallet_policy, wallet_hmac,
                                       navigator=navigator, instructions=sign_psbt_instruction_approve(firmware, save_screenshot=False, has_spend_from_wallet=True, has_feewarning=True), testname=test_name)
    signer_2 = HotMusig2Cosigner(wallet_policy, KEYPATH_COSIGNER_2_XPRIV)

    # run_musig2_test also aggregates the partial signatures and checks the resulting Schnorr
    # signature against the sighash of `psbt`
    run_musig2_test(wallet_policy, psbt, [signer_1, signer_2], KEYPATH_SIGHASHES)


class Round1ForOtherPolicyCosigner(PsbtMusig2Cosigner):
    """
    Not a real cosigner: when asked for its pubnonces, it makes the device execute round 1 for a
    different wallet policy, on a copy of the psbt. Used to check that this does not interfere with
    the pending session of the policy that is actually being signed.
    """

    def __init__(self, ledger_cosigner: LedgerMusig2Cosigner) -> None:
        super().__init__()
        self.ledger_cosigner = ledger_cosigner

    def get_participant_pubkey(self) -> bip0327.Point:
        return self.ledger_cosigner.get_participant_pubkey()

    def generate_public_nonces(self, psbt: PSBT) -> None:
        # the copy must not contain any pubnonce, or the device would execute round 2
        psbt_copy = PSBT()
        psbt_copy.deserialize(psbt.serialize())
        for input in psbt_copy.inputs:
            input.musig2_pub_nonces.clear()
        self.ledger_cosigner.generate_public_nonces(psbt_copy)
        assert any(len(input.musig2_pub_nonces) > 0 for input in psbt_copy.inputs)

    def generate_partial_signatures(self, psbt: PSBT) -> None:
        pass


def test_sign_psbt_musig2_policies_with_same_keys(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str, speculos_globals: SpeculosGlobals):
    # Two wallet policies with the same keys, but different descriptor templates, must not share the
    # same psbt_session_id: otherwise, round 1 for one policy would delete the session that the
    # other policy is waiting to use in round 2.
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    # The keys in musig() are sorted, so this policy has the same aggregate key and the same
    # addresses as wallet_policy; it can therefore execute round 1 on the very same psbt.
    other_wallet_policy = WalletPolicy(
        name="Musig for my other ears",
        descriptor_template="tr(musig(@1,@0)/**)",
        keys_info=wallet_policy.keys_info
    )
    other_wallet_hmac = hmac.new(
        speculos_globals.wallet_registration_key, other_wallet_policy.id, sha256).digest()
    assert other_wallet_policy.id != wallet_policy.id

    psbt = PSBT()
    psbt.deserialize(KEYPATH_PSBT_B64)

    signer_1 = LedgerMusig2Cosigner(client, wallet_policy, wallet_hmac,
                                    navigator=navigator, instructions=sign_psbt_instruction_approve(firmware, save_screenshot=False, has_spend_from_wallet=True, has_feewarning=True), testname=test_name)
    interloper = Round1ForOtherPolicyCosigner(
        LedgerMusig2Cosigner(client, other_wallet_policy, other_wallet_hmac, testname=test_name))
    signer_2 = HotMusig2Cosigner(wallet_policy, KEYPATH_COSIGNER_2_XPRIV)

    # the device executes round 1 for wallet_policy, then for other_wallet_policy, then round 2 for
    # wallet_policy
    run_musig2_test(wallet_policy, psbt, [signer_1, interloper, signer_2], KEYPATH_SIGHASHES)


def test_sign_psbt_musig2_wrong_pubnonce(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str, speculos_globals: SpeculosGlobals):
    # If the pubnonce in the psbt is not the one that the device would derive for the current
    # session, the device must refuse to produce a partial signature: signing anyway would produce a
    # partial signature that does not match the aggregate nonce.
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    psbt = PSBT()
    psbt.deserialize(KEYPATH_PSBT_B64)

    signer_1 = LedgerMusig2Cosigner(client, wallet_policy, wallet_hmac,
                                    navigator=navigator, instructions=sign_psbt_instruction_approve(firmware, save_screenshot=False, has_spend_from_wallet=True, has_feewarning=True), testname=test_name)
    signer_2 = HotMusig2Cosigner(
        wallet_policy, KEYPATH_COSIGNER_2_XPRIV)

    # Round 1: both cosigners add their pubnonce
    signer_1.generate_public_nonces(psbt)
    signer_2.generate_public_nonces(psbt)

    # Replace the device's pubnonce with a different, but still valid, one. Corrupting the bytes
    # arbitrarily would not do: the device would fail earlier while aggregating the nonces, which is
    # a different error path.
    ledger_pubkey = signer_1.pubkey.pubkey
    n_replaced = 0
    for input in psbt.inputs:
        for psbt_key in input.musig2_pub_nonces.keys():
            if psbt_key[0] != ledger_pubkey:
                continue
            _, other_pubnonce = bip0327.nonce_gen_internal(
                rand_=b'\x42' * 32, sk=None, pk=ledger_pubkey, aggpk=None, msg=None, extra_in=None)
            assert other_pubnonce != input.musig2_pub_nonces[psbt_key]
            input.musig2_pub_nonces[psbt_key] = other_pubnonce
            n_replaced += 1
    assert n_replaced == 1

    # Round 2 must fail, rather than yielding a partial signature for a nonce it did not commit to
    with pytest.raises(ExceptionRAPDU) as e:
        signer_1.generate_partial_signatures(psbt)

    assert DeviceException.exc.get(e.value.status) == IncorrectDataError
