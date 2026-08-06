import pytest

from ragger_bitcoin import RaggerClient
from ragger.navigator import Navigator
from ragger.backend import SpeculosBackend
from ragger.firmware import Firmware
from ragger.error import ExceptionRAPDU

from ledger_bitcoin.exception.errors import NotSupportedError, DenyError, IncorrectDataError
from ledger_bitcoin.exception.device_exception import DeviceException
from .instructions import pubkey_instruction_approve, pubkey_instruction_reject_early, pubkey_reject


def test_get_extended_pubkey_standard_display(navigator: Navigator, firmware: Firmware, client:
                                              RaggerClient, test_name: str):
    testcases = {
        # path: (expected_pubkey, save_screenshot)
        "m/44'/1'/0'": ("tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT", True),
        "m/44'/1'/10'": ("tpubDCwYjpDhUdPGp21gSpVay2QPJVh6WNySWMXPhbcu1DsxH31dF7mY18oibbu5RxCLBc1Szerjscuc3D5HyvfYqfRvc9mesewnFqGmPjney4d", True),
        "m/44'/1'/2'/1/42": ("tpubDGF9YgHKv6qh777rcqVhpmDrbNzgophJM9ec7nHiSfrbss7fVBXoqhmZfohmJSvhNakDHAspPHjVVNL657tLbmTXvSeGev2vj5kzjMaeupT", True),
        "m/48'/1'/4'/1'/0/7": ("tpubDK8WPFx4WJo1R9mEL7Wq325wBiXvkAe8ipgb9Q1QBDTDUD2YeCfutWtzY88NPokZqJyRPKHLGwTNLT7jBG59aC6VH8q47LDGQitPB6tX2d7", True),
        "m/49'/1'/1'/1/3": ("tpubDGnetmJDCL18TyaaoyRAYbkSE9wbHktSdTS4mfsR6inC8c2r6TjdBt3wkqEQhHYPtXpa46xpxDaCXU2PRNUGVvDzAHPG6hHRavYbwAGfnFr", True),
        "m/84'/1'/2'/0/10": ("tpubDG9YpSUwScWJBBSrhnAT47NcT4NZGLcY18cpkaiWHnkUCi19EtCh8Heeox268NaFF6o56nVeSXuTyK6jpzTvV1h68Kr3edA8AZp27MiLUNt", True),
        "m/86'/1'/4'/1/12": ("tpubDHTZ815MvTaRmo6Qg1rnU6TEU4ZkWyA56jA1UgpmMcBGomnSsyo34EZLoctzZY9MTJ6j7bhccceUeXZZLxZj5vgkVMYfcZ7DNPsyRdFpS3f", True),
        # the following path tests compatibility with Unchained Capital's multisig setup
        "m/45'/2'/0'/1'": ("tpubDFL11pFAgsKed5bv9Tkxe51xyB4qo1cPDwK6c8WZ4wiVEjtGDg5YuMXNk9yZcB6b47k2oaSWADJF3CRmk97qAwnaiRieT2ocWzh4rq2b3F3", True),
        "m/48'/1'/0'/2'/0'/1'/2'/3'/0/1": ("tpubDSegeM6ezY6VYgNjYiUxk94ZwLYeuUzHpUYff4LLdEEUVUd8VpgGUxyxZ9oRiEepZzmFZogVWFEWznRj3oJgEuWjcg6BERCxTCYdaxwtShk", False)
    }

    for path, (pubkey, save_screenshot) in testcases.items():
        assert pubkey == client.get_extended_pubkey(
            path=path,
            display=True,
            navigator=navigator,
            instructions=pubkey_instruction_approve(firmware, save_screenshot=save_screenshot),
            testname=f"{test_name}_{path}"
        )


def test_get_extended_pubkey_standard_nodisplay(client: RaggerClient):
    testcases = {
        "m/44'/1'/0'": "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT",
        "m/44'/1'/10'": "tpubDCwYjpDhUdPGp21gSpVay2QPJVh6WNySWMXPhbcu1DsxH31dF7mY18oibbu5RxCLBc1Szerjscuc3D5HyvfYqfRvc9mesewnFqGmPjney4d",
        "m/44'/1'/2'/1/42": "tpubDGF9YgHKv6qh777rcqVhpmDrbNzgophJM9ec7nHiSfrbss7fVBXoqhmZfohmJSvhNakDHAspPHjVVNL657tLbmTXvSeGev2vj5kzjMaeupT",
        "m/48'/1'/4'/1'/0/7": "tpubDK8WPFx4WJo1R9mEL7Wq325wBiXvkAe8ipgb9Q1QBDTDUD2YeCfutWtzY88NPokZqJyRPKHLGwTNLT7jBG59aC6VH8q47LDGQitPB6tX2d7",
        "m/49'/1'/1'/1/3": "tpubDGnetmJDCL18TyaaoyRAYbkSE9wbHktSdTS4mfsR6inC8c2r6TjdBt3wkqEQhHYPtXpa46xpxDaCXU2PRNUGVvDzAHPG6hHRavYbwAGfnFr",
        "m/84'/1'/2'/0/10": "tpubDG9YpSUwScWJBBSrhnAT47NcT4NZGLcY18cpkaiWHnkUCi19EtCh8Heeox268NaFF6o56nVeSXuTyK6jpzTvV1h68Kr3edA8AZp27MiLUNt",
        "m/86'/1'/4'/1/12": "tpubDHTZ815MvTaRmo6Qg1rnU6TEU4ZkWyA56jA1UgpmMcBGomnSsyo34EZLoctzZY9MTJ6j7bhccceUeXZZLxZj5vgkVMYfcZ7DNPsyRdFpS3f",
        "m/87'/1'/0'": "tpubDCfRoKFmEJ2uJdvBmrUngREKnaab4P6vC5NbMaeLhjdr3b5zEoruPKByWBJJag5qTdc5FptiSRpuY7AReZPcQAQqCVCUDj3R6DJuyzjMAmh",
        # support up to 8 steps
        "m/86'/1'/4'/1/2/3/4/5": "tpubDNcjumrTe1BBYEc1FmMaJZQw47mbvb4LfX4YwqC6GQ18PfMfuH3BEYREfdHm2gWXkSJ3JiXHF11iKnbJxzxp5qkgo8BBy2L48FRvrLhpTuh",
        # the following two paths test compatibility with Unchained Capital's multisig setup
        "m/45'/1'/0'": "tpubDCy2BKyxJFzACNgThkunvdnkHNotREK9LQDw8L9J1gx26SyzfoeJynJgWekzkramggmahVAgeHPxfpnvFtJ7hcYADrsVUnsPSei2tY9fBLL",
        "m/45'/1'/0'/1": "tpubDFGDxRGdGFKekUtPuta4p9Kw2a2PSeyyhSTa7KNENJfBuJ78EEsL1LxwAA8ddSxZFWBT9gYRuLDoa2rwdix56WRsq77vAJ2iqeyPw6UBeyt",
    }

    for path, pubkey in testcases.items():
        assert pubkey == client.get_extended_pubkey(
            path=path,
            display=False
        )


def test_get_extended_pubkey_exception_nodisplay(client: RaggerClient):
    # as these paths are not standard, the app should reject immediately if display=False
    testcases = {
        # Electrum path exception
        "m/4541509'/1112098098'": "tpubDAs3mrkQXkGyzp7Yo9SXiZNW7Tmia5EmdUpXjuBQvBDDGGr9CnVHehSB6P5RZFY3bwkYBweXir8MhmvPXqYHHVxKrFkm3mfZ5UkjG5ZH8Ui",
    }

    for path, pubkey in testcases.items():
        assert pubkey == client.get_extended_pubkey(
            path=path,
            display=False
        )


def test_get_extended_pubkey_nonstandard_nodisplay(client: RaggerClient):
    # as these paths are not standard, the app should reject immediately if display=False
    testcases = [
        "m",  # unusual to export the root key
        "m/44'",
        "m/44'/1'",
        "m/44'/10'/0'",  # wrong coin_type
        "m/44'/1'/0",  # first step should be hardened
        "m/44'/1/0'",  # second step should be hardened
        "m/44/1'/0'",  # third step should be hardened
        "m/48'/1'/0'/0'",  # script_type is 1' or 2' for BIP-0048
        "m/48'/1'/0'/3'",  # script_type is 1' or 2' for BIP-0048
        "m/999'/1'/0'",  # no standard with this purpose
        "m/45'/2'/0'",  # BIP-45 path with wrong COIN_TYPE
        "m/45'/1'" # BIP-45 too short path
    ]

    for path in testcases:
        with pytest.raises(ExceptionRAPDU) as e:
            client.get_extended_pubkey(
                path=path,
                display=False
            )
        assert DeviceException.exc.get(e.value.status) == NotSupportedError
        assert len(e.value.data) == 0

def test_get_extended_pubkey_nonstandard_display(navigator: Navigator, firmware: Firmware, client:
                                              RaggerClient, test_name: str):
    testcases = {
        "m/45'": "tpubDA4runSouWhEn4C36dL1PwpMhWi1LCgc7EkYJXLExjVr3eWNE5p5ZRUe7LN7cY8YwCroQsLECcv9ufij8EUpDHM2WQM9Cba8Ztf6Zo8jpFf",
    }

    for path, pubkey in testcases.items():
        assert pubkey == client.get_extended_pubkey(
            path=path,
            display=True,
            navigator=navigator,
            instructions=pubkey_instruction_approve(firmware),
            testname=f"{test_name}_{path}"
        )


def test_get_extended_pubkey_non_standard(navigator: Navigator, firmware: Firmware, client:
                                          RaggerClient,
                                          test_name: str):
    # Test the successful UX flow for a non-standard path (here, root path)
    # (Slow test, not feasible to repeat it for many paths)

    # The test will be re-enabled for Speculos once the installation parameters are supported
    # Deriving a key at root level without HAVE_APPLICATION_FLAG_DERIVE_MASTER permission
    with pytest.raises(ExceptionRAPDU) as e:
        client.get_extended_pubkey(
            path="m",  # root pubkey
            display=True,
            navigator=navigator,
            instructions=pubkey_instruction_approve(firmware),
            testname=test_name
        )
    assert DeviceException.exc.get(e.value.status) == NotSupportedError
    assert len(e.value.data) == 0
    # Deriving a key at unauthorized path
    # The below part does not raise exception when built with COIN=bitcoin_recovery as all paths are permitted
    with pytest.raises(ExceptionRAPDU) as e:
        client.get_extended_pubkey(
            path="m/44'/2'/333'",
            display=True,
            navigator=navigator,
            instructions=pubkey_instruction_approve(firmware),
            testname=test_name
        )
    assert DeviceException.exc.get(e.value.status) == NotSupportedError
    assert len(e.value.data) == 0

    # Deriving a key with a path exceeding maximum one
    with pytest.raises(ExceptionRAPDU) as e:
        client.get_extended_pubkey(
            path="m/48'/1'/0'/2'/0'/1'/2'/3'/0/1/2",
            display=True,
            navigator=navigator,
            instructions=pubkey_instruction_approve(firmware),
            testname=test_name
        )
    assert DeviceException.exc.get(e.value.status) == IncorrectDataError
    assert len(e.value.data) == 0



def test_get_extended_pubkey_non_standard_reject_early(navigator: Navigator, firmware: Firmware,
                                                       client: RaggerClient, test_name: str):
    # Test rejecting after the "Reject if you're not sure" warning
    # (Slow test, not feasible to repeat it for many paths)

    # Deriving with a suspicious path without displaying
    with pytest.raises(ExceptionRAPDU) as e:
        client.get_extended_pubkey(
            path="m/46'/1'/333'",
            display=False,
            navigator=navigator,
            instructions=pubkey_instruction_reject_early(firmware),
            testname=test_name
        )
    assert DeviceException.exc.get(e.value.status) == NotSupportedError
    assert len(e.value.data) == 0

    # Deriving with a suspicious path with displaying, but rejecting as early as the path is displayed
    with pytest.raises(ExceptionRAPDU) as e:
        client.get_extended_pubkey(
            path="m/46'/1'/333'",
            display=True,
            navigator=navigator,
            instructions=pubkey_instruction_reject_early(firmware),
            testname=test_name
        )
    assert DeviceException.exc.get(e.value.status) == DenyError
    assert len(e.value.data) == 0


def test_get_extended_pubkey_non_standard_reject(navigator: Navigator, firmware: Firmware, client:
                                                 RaggerClient, test_name: str):
    # Test rejecting at the end
    # (Slow test, not feasible to repeat it for many paths)

    # Deriving with a suspicious path with displaying, but rejecting on the last screen
    with pytest.raises(ExceptionRAPDU) as e:
        client.get_extended_pubkey(
            path="m/46'/1'/333'",
            display=True,
            navigator=navigator,
            instructions=pubkey_reject(firmware),
            testname=test_name,
        )
    assert DeviceException.exc.get(e.value.status) == DenyError
    assert len(e.value.data) == 0
