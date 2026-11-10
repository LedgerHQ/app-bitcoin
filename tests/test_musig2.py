# The tests in this file are for the MuSig2 standalone python signer implementation in test_utils.

from test_utils.bitcoin.key import ExtendedKey
from ledger_bitcoin import WalletPolicy
from test_utils.bitcoin.psbt import PSBT

from test_utils.musig2 import HotMusig2Cosigner, run_musig2_test


def test_musig2_hotsigner_keypath():
    cosigner_1_xpriv = "tprv8gFWbQBTLFhbVcpeAJ1nGbPetqLo2a5Duqu3E5wXUFJ4auLcBAfwhJscGbPjzKNvpCdG3KK3BLCTLi8YKy4PXnA1hxdowdpTaMqTcF5ZpUz"
    cosigner_1_xpub = "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"

    cosigner_2_xpriv = "tprv8gFWbQBTLFhbX3EK3cS7LmenwE3JjXbD9kN9yXfq7LcBm81RSf8vPGPqGPjZSeX41LX9ZN14St3z8YxW48aq5Yhr9pQZVAyuBthfi6quTCf"
    cosigner_2_xpub = "tpubDCwYjpDhUdPGQWG6wG6hkBJuWFZEtrn7j3xwG3i8XcQabcGC53xWZm1hSXrUPFS5UvZ3QhdPSjXWNfWmFGTioARHuG5J7XguEjgg7p8PxAm"

    wallet_policy = WalletPolicy(
        name="Musig for my ears",
        descriptor_template="tr(musig(@0,@1)/**)",
        keys_info=[cosigner_1_xpub, cosigner_2_xpub]
    )

    psbt_b64 = "cHNidP8BAIACAAAAAdF2HhQ2XCgTpd3Sel7VkS5FvESbwo1rgeuG4tBt9GICAAAAAAD9////AQAAAAAAAAAARGpCVGhpcyBpbnB1dHMgaGFzIHR3byBwdWJrZXlzIGJ1dCB5b3Ugb25seSBzZWUgb25lLiAjbXBjZ2FuZyByZXZlbmdlAAAAAAABASuf/gQAAAAAACJRIMH9/r7QY6oUg0DEUTLmcY2N6BRmriuQkp49kyg2TNbtIRaQZkYWUCCfi7xZsFr10WFcUPX3nBiNe+dC/ZMiUvaPDA0AW4+8kwAAAAADAAAAAAA="
    psbt = PSBT()
    psbt.deserialize(psbt_b64)

    sighashes = [
        bytes.fromhex(
            "a3aeecb6c236b4a7e72c95fa138250d449b97a75c573f8ab612356279ff64046")
    ]

    signer_1 = HotMusig2Cosigner(wallet_policy, cosigner_1_xpriv)
    signer_2 = HotMusig2Cosigner(wallet_policy, cosigner_2_xpriv)

    run_musig2_test(wallet_policy, psbt, [signer_1, signer_2], sighashes)


def test_musig2_hotsigner_scriptpath():
    cosigner_1_xpriv = "tprv8gFWbQBTLFhbVcpeAJ1nGbPetqLo2a5Duqu3E5wXUFJ4auLcBAfwhJscGbPjzKNvpCdG3KK3BLCTLi8YKy4PXnA1hxdowdpTaMqTcF5ZpUz"
    cosigner_1_xpub = ExtendedKey.deserialize(
        cosigner_1_xpriv).neutered().to_string()

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

    psbt_b64 = "cHNidP8BAFoCAAAAAdOnEESfpXpBe9X59Q4jxz1u9E4Wovn2bkAuuyqUUY0mAAAAAAD9////AQAAAAAAAAAAHmocTXVzaWcyLiBOb3cgZXZlbiBpbiBTY3JpcHRzLgAAAAAAAQErOTAAAAAAAAAiUSDtVR7h2JYPJC463zrCcmfKriiugHBXAcXDP1O2ptF2LyIVwethFsEeXf/x51pIczoAIsj9RoVePIBTyk/rOMW8B6uIIyCQZkYWUCCfi7xZsFr10WFcUPX3nBiNe+dC/ZMiUvaPDKzAIRaQZkYWUCCfi7xZsFr10WFcUPX3nBiNe+dC/ZMiUvaPDC0BuYMCXh1wIlpyBMdMaCFPSwOeOyvhqg+FJ+fOMoWlJsRbj7yTAAAAAAMAAAABFyDrYRbBHl3/8edaSHM6ACLI/UaFXjyAU8pP6zjFvAeriAEYILmDAl4dcCJacgTHTGghT0sDnjsr4aoPhSfnzjKFpSbEAAA="
    psbt = PSBT()
    psbt.deserialize(psbt_b64)

    sighashes = [
        bytes.fromhex(
            "28f86cd95c144ed4a877701ae7166867e8805b654c43d9f44da45d7b0070c313")
    ]

    signer_1 = HotMusig2Cosigner(wallet_policy, cosigner_1_xpriv)
    signer_2 = HotMusig2Cosigner(wallet_policy, cosigner_2_xpriv)

    run_musig2_test(wallet_policy, psbt, [signer_1, signer_2], sighashes)
