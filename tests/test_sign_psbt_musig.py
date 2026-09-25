
from pathlib import Path

from hashlib import sha256
import hmac
from typing import Optional, Tuple

import pytest

from ragger.error import ExceptionRAPDU

from ledger_bitcoin.exception.errors import IncorrectDataError
from ledger_bitcoin.exception.device_exception import DeviceException
from ledger_bitcoin.client_base import Client, MusigPartialSignature, MusigPubNonce
from ledger_bitcoin.key import ExtendedKey
from ledger_bitcoin.psbt import PSBT
from ragger.navigator import Navigator
from ragger.firmware import Firmware

from ledger_bitcoin.wallet import WalletPolicy
from ragger_bitcoin import RaggerClient
from test_utils import SpeculosGlobals, bip0327
from test_utils.musig2 import HotMusig2Cosigner, MuSig2KeyPlaceholder, PsbtMusig2Cosigner, TrDescriptorTemplate, run_musig2_test
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
