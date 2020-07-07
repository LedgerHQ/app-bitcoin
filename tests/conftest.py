from dataclasses import dataclass, field
from typing import List, Optional
import pytest


@dataclass
class LedgerjsApdu:
    commands: List[str]
    expected_resp: Optional[str] = field(default=None)
    expected_sw: Optional[str] = field(default=None)
    check_sig_format: Optional[bool] = field(default=None)


@dataclass
class SignTxTestData:
    tx_to_sign: bytes
    utxos: List[bytes]
    output_paths: List[bytes]
    change_path: bytes
    # expected_sig: List[bytes]


@dataclass
class TrustedInputTestData:
    # Tx to compute a TrustedInput from.
    tx: bytes
    # List of the outputs values to be tested, as expressed in the raw tx.
    prevout_amount: List[bytes]
    # Optional, index (not offset!) in the tx of the output to compute the TrustedInput from. Ignored
    # if num_outputs is set.
    prevout_idx: Optional[int] = field(default=None)
    # Optional, number of outputs in the tx. If set, all the tx outputs will be used to generate
    # each a corresponding TrustedInput, prevout_idx is ignored and prevout_amount must contain the
    # values of all the outputs of that tx, in order. If not set, then prevout_idx must be set.
    num_outputs: Optional[int] = field(default=None)


# ----------------------- Test data for test_btc_get_trusted_input.py -----------------------


# Test data definitions
def btc_gti_test_data() -> List[TrustedInputTestData]:
    # BTC Testnet
    # txid: 45a13dfa44c91a92eac8d39d85941d223e5d4d210e85c0d3acf724760f08fcfe
    # VO_P2WPKH
    standard_tx = TrustedInputTestData(
        tx=bytes.fromhex(
            "02000000"
            "02"
            "40d1ae8a596b34f48b303e853c56f8f6f54c483babc16978eb182e2154d5f2ab000000006b"
            "483045022100ca145f0694ffaedd333d3724ce3f4e44aabc0ed5128113660d11"
            "f917b3c5205302207bec7c66328bace92bd525f385a9aa1261b83e0f92310ea1"
            "850488b40bd25a5d0121032006c64cdd0485e068c1e22ba0fa267ca02ca0c2b3"
            "4cdc6dd08cba23796b6ee7fdffffff"
            "40d1ae8a596b34f48b303e853c56f8f6f54c483babc16978eb182e2154d5f2ab010000006a"
            "47304402202a5d54a1635a7a0ae22cef76d8144ca2a1c3c035c87e7cd0280ab4"
            "3d3451090602200c7e07e384b3620ccd2f97b5c08f5893357c653edc2b8570f0"
            "99d9ff34a0285c012102d82f3fa29d38297db8e1879010c27f27533439c868b1"
            "cc6af27dd3d33b243decfdffffff"
            "01"
            "d7ee7c01000000001976a9140ea263ff8b0da6e8d187de76f6a362beadab781188ac"
            "e3691900"
        ),
        prevout_idx=0,
        prevout_amount=[bytes.fromhex("d7ee7c0100000000")]
    )

    segwit_tx = TrustedInputTestData(
        tx=bytes.fromhex(
            "020000000001"
            "02"
            "daf4d7b97a62dd9933bd6977b5da9a3edb7c2d853678c9932108f1eb4d27b7a90000000000fdffffff"
            "daf4d7b97a62dd9933bd6977b5da9a3edb7c2d853678c9932108f1eb4d27b7a90100000000fdffffff"
            "01"
            "01410f0000000000160014e4d3a1ec51102902f6bbede1318047880c9c7680"
            "024730440220495838c36533616d8cbd6474842459596f4f312dce5483fe6507"
            "91c82e17221c02200660520a2584144915efa8519a72819091e5ed78c52689b2"
            "4235182f17d96302012102ddf4af49ff0eae1d507cc50c86f903cd6aa0395f32"
            "39759c440ea67556a3b91b"
            "0247304402200090c2507517abc7a9cb32452aabc8d1c8a0aee75ce63618ccd9"
            "01542415f2db02205bb1d22cb6e8173e91dc82780481ea55867b8e753c35424d"
            "a664f1d2662ecb1301210254c54648226a45dd2ad79f736ebf7d5f0fc03b6f8f"
            "0e6d4a61df4e531aaca431"
            "a7011900"
        ),
        prevout_idx=0,
        prevout_amount=[bytes.fromhex("01410f0000000000")]
    )

    segwit_tx_2_outputs = TrustedInputTestData(
        tx=bytes.fromhex(
            "020000000001"
            "01"
            "1541bf80c7b109c50032345d7b6ad6935d5868520477966448dc78ab8f493db10000000017"
            "160014d44d01d48f9a0d5dfa73dab21c30f7757aed846afeffffff"
            "02"
            "9b3242bf0100000017a914ff31b9075c4ac9aee85668026c263bc93d016e5a87"
            "102700000000000017a9141e852ac84f8385d76441c584e41f445aaf1624ea87"
            "0247304402206e54747dabff52f5c88230a3036125323e21c6c950719f671332"
            "cdd0305620a302204a2f2a6474f155a316505e2224eeab6391d5e6daf22acd76"
            "728bf74bc0b48e1a0121033c88f6ef44902190f859e4a6df23ecff4d86a2114b"
            "d9cf56e4d9b65c68b8121d"
            "1f7f1900"
        ),
        num_outputs=2,
        prevout_amount=[bytes.fromhex(amount) for amount in ("9b3242bf01000000", "1027000000000000")]
    )

    return [standard_tx, segwit_tx, segwit_tx_2_outputs]


# ----------------------- Test data for test_btc_rawtx_ljs.py -----------------------


def ledgerjs_test_data() -> List[List[LedgerjsApdu]]:
    # Test data below is extracted from ledgerjs repo, file "ledgerjs/packages/hw-app-btc/tests/Btc.test.js"
    ljs_btc_get_wallet_public_key = [
        LedgerjsApdu(   # GET PUBLIC KEY - on 44'/0'/0'/0 path
            commands=["e040000011048000002c800000008000000000000000"],
            # Response id seed-dependent, mening verification is possible only w/ speculos (test seed known).
            # TODO: implement a simulator class a la DeviceAppSoft with BTC tx-related
            # functions (seed derivation, signature, etc).
            # expected_resp="410486b865b52b753d0a84d09bc20063fab5d8453ec33c215d4019a5801c9c6438b917770b2782e29a9ecc6edb"
            # "67cd1f0fbf05ec4c1236884b6d686d6be3b1588abb2231334b453654666641724c683466564d36756f517a76735971357677657"
            # "44a63564dbce80dd580792cd18af542790e56aa813178dc28644bb5f03dbd44c85f2d2e7a"
        )
    ]

    ljs_btc3 = [
        LedgerjsApdu(   # GET TRUSTED INPUT
            commands=[
                "e042000009000000010100000001",
                "e0428000254ea60aeac5252c14291d428915bd7ccd1bfc4af009f4d4dc57ae597ed0420b71010000008a",
                "e042800032"
                "47304402201f36a12c240dbf9e566bc04321050b1984cd6eaf6caee8f02bb0bfec08e3354b022012ee2aeadcbbfd1e92959f",
                "e042800032"
                "57c15c1c6debb757b798451b104665aa3010569b49014104090b15bde569386734abf2a2b99f9ca6a50656627e77de663ca7",
                "e04280002a325702769986cf26cc9dd7fdea0af432c8e2becc867c932e1b9dd742f2a108997c2252e2bdebffffffff",
                "e04280000102",
                "e04280002281b72e00000000001976a91472a5d75c8d2d0565b656a5232703b167d50d5a2b88ac",
                "e042800022a0860100000000001976a9144533f5fb9b4817f713c48f0bfe96b9f50c476c9b88ac",
                "e04280000400000000"
            ],
            expected_resp="3200" + "--" * 2
            + "c773da236484dae8f0fdba3d7e0ba1d05070d1a34fc44943e638441262a04f1001000000a086010000000000" + "--" * 8
        ),
        LedgerjsApdu(   # UNTRUSTED HASH TRANSACTION INPUT START -
            commands=[
                "e0440000050100000001",
                "e04480002600c773da236484dae8f0fdba3d7e0ba1d05070d1a34fc44943e638441262a04f100100000069",
                "e044800032"
                "52210289b4a3ad52a919abd2bdd6920d8a6879b1e788c38aa76f0440a6f32a9f1996d02103a3393b1439d1693b063482c04b",
                "e044800032"
                "d40142db97bdf139eedd1b51ffb7070a37eac321030b9a409a1e476b0d5d17b804fcdb81cf30f9b99c6f3ae1178206e08bc5",
                "e04480000900639853aeffffffff"
            ]
        ),
        LedgerjsApdu(   # UNTRUSTED HASH TRANSACTION INPUT FINALIZE FULL - prevout amount + output script
            commands=["e04a80002301905f0100000000001976a91472a5d75c8d2d0565b656a5232703b167d50d5a2b88ac"],
            expected_resp="0000"
        ),
        LedgerjsApdu(   # UNTRUSTED HASH SIGN - on 0'/0/0 path
            commands=["e04800001303800000000000000000000000000000000001"],
            check_sig_format=True
        )
    ]

    ljs_btc4 = [
        LedgerjsApdu(   # SIGN MESSAGE - part 1, on 44'/0'/0'/0 path + data to sign ("test")
            commands=["e04e000117048000002c800000008000000000000000000474657374"],
            expected_resp="0000"
        ),
        LedgerjsApdu(  # SIGN MESSAGE - part 2, Null byte as end of msg
            commands=["e04e80000100"],
            check_sig_format=True
        )
    ]

    ljs_sign_message = [
        LedgerjsApdu(   # SIGN MESSAGE - on 44'/0'/0/0 path + data to sign (binary)
            commands=["e04e00011d058000002c800000008000000000000000000000000006666f6f626172"],
            expected_resp="0000"
        ),
        LedgerjsApdu(   # SIGN MESSAGE - Null byte as end of message
            commands=["e04e80000100"],
            check_sig_format=True
        )
    ]

    return [ljs_btc_get_wallet_public_key, ljs_btc3, ljs_btc4, ljs_sign_message]


# ----------------------- Test data for test_btc_rawtx_zcash.py -----------------------


def zcash_prefix_cmds() -> List[List[LedgerjsApdu]]:
    # Test data below is from a Zcash test log from Live team"
    prefix_cmds = [
        LedgerjsApdu(   # Get version
            commands=["b001000000"],
            # expected_resp="01055a63617368--------------0102" # i.e. "Zcash" + "1.3.23" (not checked)
        ),
        LedgerjsApdu(
            commands=[
                "e040000015058000002c80000085800000000000000000000000",  # GET PUBLIC KEY - on 44'/133'/0'/0/0 path
                "e016000000",   # Coin info
            ],
            expected_resp="1cb81cbd01055a63617368035a4543"  # "Zcash" + "ZEC"
        ),
        LedgerjsApdu(
            commands=[
                "e040000009028000002c80000085",   # Get Public Key - on path 44'/133'
                "e016000000",   # Coin info
            ],
            expected_resp="1cb81cbd01055a63617368035a4543"
        ),
        LedgerjsApdu(
            commands=[
                "e040000009028000002c80000085",             # path 44'/133'
                "e04000000d038000002c8000008580000000",     # path 44'/133'/0'
                "e04000000d038000002c8000008580000001",     # path 44'/133'/1'
                "b001000000"
            ],
            # expected_resp="01055a63617368--------------0102"
        ),
        LedgerjsApdu(
            commands=[
                "e040000015058000002c80000085800000000000000000000004",   # Get Public Key - on path 44'/133'/0'/0/4
                "e016000000",   # Coin info
            ],
            expected_resp="1cb81cbd01055a63617368035a4543"
        ),
        LedgerjsApdu(
            commands=["b001000000"],
            # expected_resp="01055a63617368--------------0102"
        ),
        LedgerjsApdu(
            commands=[
                "e040000015058000002c80000085800000000000000000000004",   # Get Public Key - on path 44'/133'/0'/0/4
                "e016000000"
            ],
            expected_resp="1cb81cbd01055a63617368035a4543"
        ),
        LedgerjsApdu(
            commands=["b001000000"],
            # expected_resp="01055a63617368--------------0102"
        )
    ]
    return [prefix_cmds]


def zcash_ledgerjs_test_data() -> List[List[LedgerjsApdu]]:
    zcash_tx_sign_gti = [
        LedgerjsApdu(   # GET TRUSTED INPUT
            commands=[
                "e042000009000000010400008001",
                "e042800025edc69b8179fd7c6a11a8a1ba5d17017df5e09296c3a1acdada0d94e199f68857010000006b",
                "e042800032"
                "483045022100e8043cd498714122a78b6ecbf8ced1f74d1c65093c5e2649336dfa248aea9ccf022023b13e57595635452130",
                "e042800032"
                "1c91ed0fe7072d295aa232215e74e50d01a73b005dac01210201e1c9d8186c093d116ec619b7dad2b7ff0e7dd16f42d458da",
                "e04280000b1100831dc4ff72ffffff00",
                "e04280000102",
                "e042800022a0860100000000001976a914fa9737ab9964860ca0c3e9ad6c7eb3bc9c8f6fb588ac",
                "e0428000224d949100000000001976a914b714c60805804d86eb72a38c65ba8370582d09e888ac",
                "e04280000400000000",
            ],
            expected_resp="3200" + "--" * 2
            + "20b7c68231303b2425a91b12f05bd6935072e9901137ae30222ef6d60849fc51010000004d94910000000000" + "--" * 8
        ),
    ]

    zcash_tx_to_sign_abandonned = [
        LedgerjsApdu(   # GET PUBLIC KEY
            commands=["e040000015058000002c80000085800000000000000100000001"],  # on 44'/133'/0'/1/1
        ),
        LedgerjsApdu(   # UNTRUSTED HASH TRANSACTION INPUT START
            commands=[
                "e0440005090400008085202f8901",
                "e04480053b"
                "013832004d0420b7c68231303b2425a91b12f05bd6935072e9901137ae30222ef6d60849fc51010000004d94910000000000"
                "45e1e144cb88d4d800",
                "e044800504ffffff00",
            ]
        ),
        LedgerjsApdu(   # UNTRUSTED HASH TRANSACTION INPUT FINALIZE FULL
            commands=[
                "e04aff0015058000002c80000085800000000000000100000003",
                # "e04a000032"
                # "0240420f00000000001976a91490360f7a0b0e50d5dd0c924fc1d6e7adb8519c9388ac39498200000000001976a91425ea06"
                "e04a0000230140420f00000000001976a91490360f7a0b0e50d5dd0c924fc1d6e7adb8519c9388ac"
            ],  # tx aborted on 2nd command
            expected_sw="6985"
        ),
    ]

    zcash_tx_sign_restart_prefix_cmds = [
        LedgerjsApdu(
            commands=["b001000000"],
            # expected_resp="01055a63617368--------------0102"
        ),
        LedgerjsApdu(
            commands=[
                "e040000015058000002c80000085800000000000000000000004",
                "e016000000",
            ],
            expected_resp="1cb81cbd01055a63617368035a4543"
        ),
        LedgerjsApdu(
            commands=["b001000000"],
            # expected_resp="01055a63617368--------------0102"
        )
    ]

    zcash_tx_to_sign_finalized = zcash_tx_sign_gti + [
        LedgerjsApdu(   # GET PUBLIC KEY
            commands=["e040000015058000002c80000085800000000000000100000001"],  # on 44'/133'/0'/1/1
        ),
        LedgerjsApdu(   # UNTRUSTED HASH TRANSACTION INPUT START
            commands=[
                "e0440005090400008085202f8901",
                "e04480053b"
                "013832004d0420b7c68231303b2425a91b12f05bd6935072e9901137ae30222ef6d60849fc51010000004d94910000000000"
                "45e1e144cb88d4d800",
                "e044800504ffffff00",
            ]
        ),
        LedgerjsApdu(   # UNTRUSTED HASH TRANSACTION INPUT FINALIZE FULL
            commands=[
                "e04aff0015058000002c80000085800000000000000100000003",
                # "e04a000032"
                # "0240420f00000000001976a91490360f7a0b0e50d5dd0c924fc1d6e7adb8519c9388ac39498200000000001976a91425ea06"
                "e04a0000230140420f00000000001976a91490360f7a0b0e50d5dd0c924fc1d6e7adb8519c9388ac"
                "e04a8000045eb3f840"
            ],
            expected_resp="0000"
        ),

        LedgerjsApdu(
            commands=[
                "e0440085090400008085202f8901",
                "e04480853b"
                "013832004d0420b7c68231303b2425a91b12f05bd6935072e9901137ae30222ef6d60849fc51010000004d94910000000000"
                "45e1e144cb88d4d819",
                "e04480851d76a9140a146582553b2f5537e13cef6659e82ed8f69b8f88acffffff00",
                "e048000015058000002c80000085800000000000000100000001"
            ],
            check_sig_format=True
        )
    ]

    return [zcash_prefix_cmds, zcash_tx_sign_gti, zcash_tx_to_sign_abandonned,
            zcash_tx_sign_restart_prefix_cmds, zcash_tx_to_sign_finalized]


@pytest.fixture
def zcash_utxo_single() -> bytes:
    return bytes.fromhex(
        # https://sochain.com/api/v2/tx/ZEC/ec9033381c1cc53ada837ef9981c03ead1c7c41700ff3a954389cfaddc949256
        # Zcash Sapling
        "0400008085202f89"
        "01"
        "53685b8809efc50dd7d5cb0906b307a1b8aa5157baa5fc1bd6fe2d0344dd193a000000006b"
        "483045022100ca0be9f37a4975432a52bb65b25e483f6f93d577955290bb7fb0"
        "060a93bfc92002203e0627dff004d3c72a957dc9f8e4e0e696e69d125e4d8e27"
        "5d119001924d3b48012103b243171fae5516d1dc15f9178cfcc5fdc67b0a8830"
        "55c117b01ba8af29b953f6"
        "ffffffff"
        "01"
        "40720700000000001976a91449964a736f3713d64283fd0018626ba50091c7e988ac"
        "00000000"
        "000000000000000000000000000000"
    )


@pytest.fixture
def zcash_sign_tx_test_data() -> SignTxTestData:
    test_utxos = [
        # Considered a segwit tx - segwit flags couldn't be extracted from raw
        # Get Trusted Input APDUs as they are not supposed to be sent w/ these APDUs.
        bytes.fromhex(
            # Zcash Sapling
            "0400008085202f89"
            "01"
            "edc69b8179fd7c6a11a8a1ba5d17017df5e09296c3a1acdada0d94e199f68857010000006b"
            "483045022100e8043cd498714122a78b6ecbf8ced1f74d1c65093c5e2649336d"
            "fa248aea9ccf022023b13e575956354521301c91ed0fe7072d295aa232215e74"
            "e50d01a73b005dac01210201e1c9d8186c093d116ec619b7dad2b7ff0e7dd16f"
            "42d458da1100831dc4ff72"
            "ffffff00"
            "02"
            "a0860100000000001976a914fa9737ab9964860ca0c3e9ad6c7eb3bc9c8f6fb588ac"
            "4d949100000000001976a914b714c60805804d86eb72a38c65ba8370582d09e888ac"
            "00000000"
            "000000000000000000000000000000"
        )
    ]

    test_tx_to_sign = bytes.fromhex(
        # Zcash Sapling
        "0400008085202f89"
        "01"
        "d35f0793da27a5eacfe984c73b1907af4b50f3aa3794ba1bb555b9233addf33f0100000000"
        "ffffff00"
        "02"
        "40420f00000000001976a91490360f7a0b0e50d5dd0c924fc1d6e7adb8519c9388ac"
        "2b518200000000001976a91490360f7a0b0e50d5dd0c924fc1d6e7adb8519c9388ac"
        "5eb3f840"
        "000000000000000000000000000000"
    )

    test_change_path = bytes.fromhex("058000002c80000085800000000000000100000003")   # 44'/133'/0'/1/3
    test_output_paths = [
        bytes.fromhex("058000002c80000085800000000000000100000001"),    # 44'/133'/0'/1/1
        bytes.fromhex("058000002c80000085800000000000000000000004")     # 44'/133'/0'/0/4
    ]

    return SignTxTestData(
        tx_to_sign=test_tx_to_sign,
        utxos=test_utxos,
        output_paths=test_output_paths,
        change_path=test_change_path
    )


# ----------------------- Test data for test_btc_rawtx_zcash2.py -----------------------


# Test data below is from a Zcash test log from Live team"
def zcash2_prefix_cmds() -> List[List[LedgerjsApdu]]:
    prefix_cmds = [
        LedgerjsApdu(   # Get version
            commands=[
                "b001000000",
                "b001000000"
            ],
            # expected_resp="01055a63617368--------------0102" # i.e. "Zcash" + "1.3.23" (not checked)
        ),
        LedgerjsApdu(
            commands=[
                "e040000015058000002c80000085800000010000000000000007",  # GET PUBLIC KEY - on 44'/133'/1'/0/7 path
                "e016000000",   # Coin info
            ],
            expected_resp="1cb81cbd01055a63617368035a4543"  # "Zcash" + "ZEC"
        ),
        LedgerjsApdu(
            commands=[
                "e040000015058000002c80000085800000010000000000000007",  # GET PUBLIC KEY - on 44'/133'/1'/0/7 path
                "e016000000",   # Coin info
            ],
            expected_resp="1cb81cbd01055a63617368035a4543"  # "Zcash" + "ZEC"
        ),
        LedgerjsApdu(   # Get version
            commands=[
                "b001000000"
            ],
            # expected_resp="01055a63617368--------------0102" # i.e. "Zcash" + "1.3.23" (not checked)
        ),
        LedgerjsApdu(
            commands=[
                "e040000015058000002c80000085800000000000000000000002",   # Get Public Key - on path 44'/133'/0'/0/2
                "e016000000",   # Coin info
            ],
            expected_resp="1cb81cbd01055a63617368035a4543"
        ),
        LedgerjsApdu(   # Get version
            commands=[
                "b001000000"
            ],
            # expected_resp="01055a63617368--------------0102" # i.e. "Zcash" + "1.3.23" (not checked)
        )
    ]
    return [prefix_cmds]


@pytest.fixture
def zcash2_sign_tx_test_data() -> SignTxTestData:
    test_utxos = [
        # Zcash Overwinter
        bytes.fromhex(
            "030000807082c403"
            "03"
            "f6959fbdd8cc614211e4db1ca287a766441dcda8d786f70d956ad19de03373a40100000069"
            "46304302203dc5102d80e08cb8dee8e83894026a234d84ddd92da1605405a677"
            "ead9fcb21a021f40bedfa4b5611fc00a6d43aedb6ea0769175c2eb4ce4f68963"
            "c3a6103228080121028aceaa654c031435beb9bcf80d656a7519a6732f3da3c8"
            "14559396131ea3532effffff00"
            "5ae818ee42a08d5c335d850cacb4b5996e5d2bc1cd5f0c5b46733652771c23b9010000006b"
            "483045022100df24e46115778a766068f1b744a7ffd2b0ae4e09b34259eecb2f"
            "5871f5e3ff7802207c83c3c13c8113f904da3ea4d4ceedb0db4e8518fb43e9fb"
            "8aeda64d1a69c76b012103e604d3cbc5c8aa4f9c53f84157be926d443054ba93"
            "b60fbddf0aea053173f595ffffff00"
            "6065c6c49cd132fc148f947b5aa5fd2a4e0ae4b5a884ccb3247b5ccbfa3ecc58010000006a"
            "473044022064d92d88b8223f9e502214b2abf8eb72b91ad7ed69ae9597cb510a"
            "3c94c7a2b00220327b4b852c2a81ad918bb341e7cd1c7e15903fc3e298663d75"
            "675c4ab180be890121037dbc2659579d22c284a3ea2e3b5d0881f678583e2b4a"
            "8b19dbd50f384d4b2535ffffff00"
            "02"
            "002d3101000000001976a914772b6723ec72c99f6a37009407006fe1c790733988ac"
            "13b62400000000001976a914d46156a9e784f5f28fdbbaa4ed8301170be6cc0388ac"
            "00000000"
            "0000000000"
        )
    ]

    test_tx_to_sign = bytes.fromhex(
        # Zcash Sapling
        "0400008085202f89"
        "01"
        "605d4c86ca4511e962dbd968ab6805deeff0f076f6a8c6069dadefb0378c72440100000019"
        "76a914d46156a9e784f5f28fdbbaa4ed8301170be6cc0388acffffff00"
        "02"
        "c05c1500000000001976a914130715c4e654cff3fced8a9d6876310083d44f2e88ac"
        "e9540f00000000001976a91478dff3b7ed9dac8e9177c587375937f9d057769588ac"
        "00000000"
        "000000000000000000000000000000"
    )

    test_change_path = bytes.fromhex("058000002c80000085800000000000000100000007")   # 44'/133'/0'/1/7
    test_output_paths = [bytes.fromhex("058000002c80000085800000000000000100000006")]    # 44'/133'/0'/1/6

    return SignTxTestData(
        tx_to_sign=test_tx_to_sign,
        utxos=test_utxos,
        output_paths=test_output_paths,
        change_path=test_change_path,
    )


# ----------------------- Test data for test_btc_segwit_tx_ljs.py -----------------------


@pytest.fixture
def segwit_sign_tx_test_data() -> SignTxTestData:
    test_utxos = [
        bytes.fromhex(
            "02000000"
            "0001"
            "01"
            "1541bf80c7b109c50032345d7b6ad6935d5868520477966448dc78ab8f493db10000000017"
            "160014d44d01d48f9a0d5dfa73dab21c30f7757aed846afeffffff"
            "02"
            "9b3242bf0100000017a914ff31b9075c4ac9aee85668026c263bc93d016e5a87"
            "102700000000000017a9141e852ac84f8385d76441c584e41f445aaf1624ea87"
            "0247"
            "304402206e54747dabff52f5c88230a3036125323e21c6c950719f671332cdd0"
            "305620a302204a2f2a6474f155a316505e2224eeab6391d5e6daf22acd76728b"
            "f74bc0b48e1a0121033c88f6ef44902190f859e4a6df23ecff4d86a2114bd9cf"
            "56e4d9b65c68b8121d"
            "1f7f1900"
        ),
        bytes.fromhex(
            "01000000"
            "0001"
            "02"
            "7ab1cb19a44db08984031508ec97de727b32a8176cc00fce727065e86984c8df0000000017"
            "160014d815dddcf8cf1b820419dcb1206a2a78cfa60320ffffff00"
            "78958127caf18fc38733b7bc061d10bca72831b48be1d6ac91e296b8880033270000000017"
            "160014d815dddcf8cf1b820419dcb1206a2a78cfa60320ffffff00"
            "02"
            "102700000000000017a91493520844497c54e709756c819afecfffaf28761187"
            "c84b1a000000000017a9148f1f7cf3c847e4057be46990c4a00be4271f3cfa87"
            "0247"
            "3044022009116da9433c3efad4eaf5206a780115d6e4b2974152bdceba220c45"
            "70e527a802202b06ca9eb93df1c9fc5b0e14dc1f6698adc8cbc15d3ec4d364b7"
            "bef002c493d701210293137bc1a9b7993a1d2a462188efc45d965d135f53746b"
            "6b146a3cec9905322602473044022034eceb661d9e5f777468089b262f6b25e1"
            "41218f0ec9e435a98368d3f347944d02206041228b4e43a1e1fbd70ca15d3308"
            "af730eedae9ec053afec97bd977be7685b01210293137bc1a9b7993a1d2a4621"
            "88efc45d965d135f53746b6b146a3cec99053226"
            "00000000"
        )
    ]

    test_tx_to_sign = bytes.fromhex(
        "01000000"
        "0001"
        # Inputs
        "02"
        "027a726f8aa4e81a45241099a9820e6cb7d8920a686701ad98000721101fa0aa0100000017"
        "160014d815dddcf8cf1b820419dcb1206a2a78cfa60320ffffff00"
        "f0b7b7ad837b4d3535bea79a2fa355262df910873b7a51afa1e4279c6b6f6e6f0000000017"
        "160014eee02beeb4a8f15bbe4926130c086bd47afe8dbcffffff00"
        # Outputs
        "02"
        "102700000000000017a9142406cd1d50d3be6e67c8b72f3e430a1645b0d74287"
        "0e2600000000000017a9143ae394774f1348be3a6bc2a55b67e3566d13408987"
        # witnesses
        "02483045022100f4d05565991d98573629c7f98c4f575a4915600a83a0057716"
        "f1f4865054927f022010f30365e0685ee46d81586b50f5dd201ddedab39cfd7d"
        "16d3b17f94844ae6d501210293137bc1a9b7993a1d2a462188efc45d965d135f"
        "53746b6b146a3cec9905322602473044022030c4c770db75aa1d3ed877c6f995"
        "a1e6055be00c88efefb2fb2db8c596f2999a02205529649f4366427e1d9ed3cf"
        "8dc80fe25e04ce4ac19b71578fb6da2b5788d45b012103cfbca92ae924a3bd87"
        "529956cb4f372a45daeafdb443e12a781881759e6f48ce03cfbca92ae924a3bd"
        "87529956cb4f372a45daeafdb443e12a781881759e6f48ce03cfbca92ae924a3"
        "bd87529956cb4f372a45daeafdb443e12a781881759e6f48ce"
        "00000000"
    )

    # TODO: expected signature to be checked should be extracted from tx (when tx is confirmed).
    #  - Confirmed tx signature parsing should be added to helper tx parser
    #  - Pubkey from tx's scriptPubKey should be used to decrypt the signature for each input and
    #    resulting hash should be compared against recomputed tx's inputs hashes (WIP).
    # test_expected_der_sig = [
    # ]

    test_output_paths = [
        bytes.fromhex("0580000031800000018000000000000000000001f6"),  # 49'/1'/0'/0/502
        bytes.fromhex("0580000031800000018000000000000000000001f7")   # 49'/1'/0'/0/503
    ]
    test_change_path = bytes.fromhex("058000003180000001800000000000000100000045")  # 49'/1'/0'/1/69

    return SignTxTestData(
        tx_to_sign=test_tx_to_sign,
        utxos=test_utxos,
        output_paths=test_output_paths,
        change_path=test_change_path,
        # expected_sig=test_expected_der_sig
    )


# ----------------------- Test data for test_btc_signature.py -----------------------


# BTC Testnet segwit tx used as a "prevout" tx.
# Note: UTXO transactiopns must be ordered in this list in the same order as their
# matching hashes in the tx to sign.
# txid: 2CE0F1697564D5DAA5AFDB778E32782CC95443D9A6E39F39519991094DEF8753
# VO_P2WPKH
@pytest.fixture
def btc_sign_tx_test_data() -> SignTxTestData:
    test_utxos = [
        bytes.fromhex(
            "02000000"
            "0001"
            "02"
            "daf4d7b97a62dd9933bd6977b5da9a3edb7c2d853678c9932108f1eb4d27b7a90000000000fdffffff"
            "daf4d7b97a62dd9933bd6977b5da9a3edb7c2d853678c9932108f1eb4d27b7a90100000000fdffffff"
            "01"
            "01410f0000000000160014e4d3a1ec51102902f6bbede1318047880c9c7680"
            "0247"
            "30440220495838c36533616d8cbd6474842459596f4f312dce5483fe650791c8"
            "2e17221c02200660520a2584144915efa8519a72819091e5ed78c52689b24235"
            "182f17d96302012102ddf4af49ff0eae1d507cc50c86f903cd6aa0395f323975"
            "9c440ea67556a3b91b"
            "0247"
            "304402200090c2507517abc7a9cb32452aabc8d1c8a0aee75ce63618ccd90154"
            "2415f2db02205bb1d22cb6e8173e91dc82780481ea55867b8e753c35424da664"
            "f1d2662ecb1301210254c54648226a45dd2ad79f736ebf7d5f0fc03b6f8f0e6d"
            "4a61df4e531aaca431"
            "a7011900"
        ),
    ]

    # The tx we want to sign, referencing the hash of the prevout segwit tx above
    # in its input.
    test_tx_to_sign = bytes.fromhex(
        "02000000"
        "01"
        "2CE0F1697564D5DAA5AFDB778E32782CC95443D9A6E39F39519991094DEF8753000000001976a914e4d3a1ec"
        "51102902f6bbede1318047880c9c768088acfdffffff"
        "02"
        "1027000000000000160014161d283ebbe0e6bc3d90f4c456f75221e1b3ca0f"
        "64190f00000000001600144c5133c242683d33c61c4964611d82dcfe0d7a9a"
        "a7011900"
    )

    # Expected signature (except last sigHashType byte) was extracted from raw tx at:
    # https://tbtc.bitaps.com/raw/transaction/a9a7ffabd6629009488546eb1fafd5ae2c3d0008bc4570c20c273e51b2ce5abe
    # TODO: expected signature to be checked should be extracted from tx (when tx is confirmed). See previous TODO.
    # test_expected_der_sig = [
    #     bytes.fromhex(      # for output #1
    #         "3044"
    #         "02202cadfbd881f592ea82e69038c7ada8f1ae50919e3be92ad1cd5fcc0bd142b2f5"
    #         "0220646a699b5532fcdf38b196157e216c8808ae7bde5e786b8f3cbf2502d0f14c13"
    #         "01"),
    # ]

    test_output_paths = [bytes.fromhex("058000005480000001800000000000000000000000"), ]    # 84'/1'/0'/0/0
    test_change_path = bytes.fromhex("058000005480000001800000000000000100000001")         # 84'/1'/0'/1/1

    return SignTxTestData(
        tx_to_sign=test_tx_to_sign,
        utxos=test_utxos,
        output_paths=test_output_paths,
        change_path=test_change_path,
        # expected_sig=test_expected_der_sig
    )
