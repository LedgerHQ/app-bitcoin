
from pathlib import Path
from hashlib import sha256
import hmac

import pytest

from ledger_bitcoin import WalletPolicy, Client
from test_utils.bitcoin.psbt import PSBT

from test_utils import SpeculosGlobals, txmaker

tests_root: Path = Path(__file__).parent


def make_psbt(wallet_policy: WalletPolicy, n_inputs: int, n_outputs: int) -> PSBT:
    in_amounts = [10000 + 10000 * i for i in range(n_inputs)]
    total_in = sum(in_amounts)
    out_amounts = [total_in // n_outputs - i for i in range(n_outputs)]

    change_index = 1

    psbt = txmaker.createPsbt(
        wallet_policy,
        in_amounts,
        out_amounts,
        [i == change_index for i in range(n_outputs)]
    )

    sum_in = sum(in_amounts)
    sum_out = sum(out_amounts)

    assert sum_out < sum_in

    return psbt


def run_test(client: Client, wallet_policy: WalletPolicy, n_inputs: int, speculos_globals: SpeculosGlobals, benchmark):

    wallet_hmac = None
    if wallet_policy.name != "":
        wallet_hmac = hmac.new(
            speculos_globals.wallet_registration_key, wallet_policy.id, sha256).digest()

    psbt = make_psbt(wallet_policy, n_inputs, 2)

    # the following code might count repetitions incorrectly for more than 10 keys
    assert len(wallet_policy.keys_info) <= 10

    n_internal_placeholders = 0
    for key_index, key_info in enumerate(wallet_policy.keys_info):
        if key_info.startswith(f"[{speculos_globals.master_key_fingerprint.hex()}"):
            # this is incorrect if more than 10 keys, as key indexes are more than one digit
            n_internal_placeholders += wallet_policy.descriptor_template.count(
                f"@{key_index}")

    assert n_internal_placeholders >= 1

    def sign_tx():
        result = client.sign_psbt(psbt, wallet_policy, wallet_hmac)

        assert len(result) == n_inputs * n_internal_placeholders

    benchmark.pedantic(sign_tx, rounds=1)


@pytest.mark.parametrize("n_inputs", [1, 3, 10])
def test_perf_sign_psbt_singlesig_pkh(client: Client, n_inputs: int, speculos_globals: SpeculosGlobals, benchmark):
    # PSBT for a legacy 2-output spend (1 change address)

    wallet_policy = WalletPolicy(
        "",
        "pkh(@0/**)",
        [
            "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"
        ],
    )

    run_test(client, wallet_policy, n_inputs, speculos_globals, benchmark)


@pytest.mark.parametrize("n_inputs", [1, 3, 10])
def test_perf_sign_psbt_singlesig_wpkh(client: Client, n_inputs: int, speculos_globals: SpeculosGlobals, benchmark):
    # PSBT for a segwit 2-output spend (1 change address)

    wallet_policy = WalletPolicy(
        "",
        "wpkh(@0/**)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"
        ],
    )

    run_test(client, wallet_policy, n_inputs, speculos_globals, benchmark)


@pytest.mark.parametrize("n_inputs", [1, 3, 10])
def test_perf_sign_psbt_singlesig_tr(client: Client, n_inputs: int, speculos_globals: SpeculosGlobals, benchmark):
    # PSBT for a taproot 2-output spend (1 change address)

    wallet_policy = WalletPolicy(
        name="",
        descriptor_template="tr(@0/**)",
        keys_info=[
            f"[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U",
        ],
    )

    run_test(client, wallet_policy, n_inputs, speculos_globals, benchmark)


@pytest.mark.parametrize("n_inputs", [1, 3, 10])
def test_perf_sign_psbt_multisig2of3_wsh(client: Client, n_inputs: int, speculos_globals: SpeculosGlobals, benchmark):
    wallet_policy = WalletPolicy(
        name="Cold storage",
        descriptor_template="wsh(sortedmulti(2,@0/**,@1/**,@2/**))",
        keys_info=[
            "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
            "tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
            "tpubDF4kujkh5dAhC1pFgBToZybXdvJFXXGX4BWdDxWqP7EUpG8gxkfMQeDjGPDnTr9e4NrkFmDM1ocav3Jz6x79CRZbxGr9dzFokJLuvDDnyRh"
        ],
    )

    run_test(client, wallet_policy, n_inputs, speculos_globals, benchmark)


@pytest.mark.parametrize("n_inputs", [1, 3, 10])
def test_perf_sign_psbt_multisig3of5_wsh(client: Client, n_inputs: int, speculos_globals: SpeculosGlobals, benchmark):
    wallet_policy = WalletPolicy(
        name="Cold storage",
        descriptor_template="wsh(sortedmulti(3,@0/**,@1/**,@2/**,@3/**,@4/**))",
        keys_info=[
            "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
            "tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
            "tpubDF4kujkh5dAhC1pFgBToZybXdvJFXXGX4BWdDxWqP7EUpG8gxkfMQeDjGPDnTr9e4NrkFmDM1ocav3Jz6x79CRZbxGr9dzFokJLuvDDnyRh",
            "tpubDD3ULTdBbyuMMMs8BCsJKgZgEnZjjbsbtV6ig3xtkQnaSc1gu9kNhmDDEW49HoLzDNA4y2TMqRzj4BugrrtcpXkjoHSoMVhJwfZLUFmv6yn",
            "tpubDDyh1VAY2sHfGHE59muC5PWa3tosSTm62sNTDSmZUsx9TbyBdoVkZibYZuDoqJ8dJ6v6eYZz6SE1d6sDv45NgJFB1oqCLGzyiQBGyjexc7V"
        ],
    )

    run_test(client, wallet_policy, n_inputs, speculos_globals, benchmark)


@pytest.mark.parametrize("n_inputs", [1, 3, 10])
def test_perf_sign_psbt_tapminiscript_2paths(client: Client, n_inputs: int, speculos_globals: SpeculosGlobals, benchmark):
    # A taproot miniscript policy where the two placeholders (in different spending paths) are internal
    # The app signs for both spending paths.
    wallet_policy = WalletPolicy(
        name="Cold storage",
        descriptor_template="wsh(or_d(multi(4,@0/<0;1>/*,@1/<0;1>/*,@2/<0;1>/*,@3/<0;1>/*),and_v(v:thresh(3,pkh(@0/<2;3>/*),a:pkh(@1/<2;3>/*),a:pkh(@2/<2;3>/*),a:pkh(@3/<2;3>/*)),older(65535))))",
        keys_info=[
            "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
            "tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
            "tpubDF4kujkh5dAhC1pFgBToZybXdvJFXXGX4BWdDxWqP7EUpG8gxkfMQeDjGPDnTr9e4NrkFmDM1ocav3Jz6x79CRZbxGr9dzFokJLuvDDnyRh",
            "tpubDD3ULTdBbyuMMMs8BCsJKgZgEnZjjbsbtV6ig3xtkQnaSc1gu9kNhmDDEW49HoLzDNA4y2TMqRzj4BugrrtcpXkjoHSoMVhJwfZLUFmv6yn",
        ],
    )

    run_test(client, wallet_policy, n_inputs, speculos_globals, benchmark)
