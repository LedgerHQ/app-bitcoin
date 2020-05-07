import pytest
from dataclasses import dataclass, field
from typing import List, Optional
from helpers.basetest import BaseTestBtc, LedgerjsApdu
from helpers.deviceappbtc import DeviceAppBtc


# Test data below is extracted from ledgerjs repo, file "ledgerjs/packages/hw-app-btc/tests/Btc.test.js"
test_btc_get_wallet_public_key = [
    LedgerjsApdu(   # GET PUBLIC KEY - on 44'/0'/0'/0 path
        commands=["e040000011048000002c800000008000000000000000"],
        # Response id seed-dependent, mening verification is possible only w/ speculos (test seed known). 
        # TODO: implement a simulator class a la DeviceAppSoft with BTC tx-related 
        # functions (seed derivation, signature, etc).
        #expected_resp="410486b865b52b753d0a84d09bc20063fab5d8453ec33c215d4019a5801c9c6438b917770b2782e29a9ecc6edb67cd1f0fbf05ec4c1236884b6d686d6be3b1588abb2231334b453654666641724c683466564d36756f517a7673597135767765744a63564dbce80dd580792cd18af542790e56aa813178dc28644bb5f03dbd44c85f2d2e7a"
    )
]

test_btc2 =  [
    LedgerjsApdu(   # GET TRUSTED INPUT
        commands=[
            "e042000009000000010100000001",
            "e0428000254ea60aeac5252c14291d428915bd7ccd1bfc4af009f4d4dc57ae597ed0420b71010000008a",
            "e04280003247304402201f36a12c240dbf9e566bc04321050b1984cd6eaf6caee8f02bb0bfec08e3354b022012ee2aeadcbbfd1e92959f",
            "e04280003257c15c1c6debb757b798451b104665aa3010569b49014104090b15bde569386734abf2a2b99f9ca6a50656627e77de663ca7",
            "e04280002a325702769986cf26cc9dd7fdea0af432c8e2becc867c932e1b9dd742f2a108997c2252e2bdebffffffff",
            "e04280000102",
            "e04280002281b72e00000000001976a91472a5d75c8d2d0565b656a5232703b167d50d5a2b88ac",
            "e042800022a0860100000000001976a9144533f5fb9b4817f713c48f0bfe96b9f50c476c9b88ac",
            "e04280000400000000",
        ],
        expected_resp="3200" + "--"*2 + "c773da236484dae8f0fdba3d7e0ba1d05070d1a34fc44943e638441262a04f1001000000a086010000000000" + "--"*8
    ), 
    LedgerjsApdu(   # GET PUBLIC KEY
        commands=["e04000000d03800000000000000000000000"],
        #expected_resp="41046666422d00f1b308fc7527198749f06fedb028b979c09f60d0348ef79c985e4138b86996b354774c434488d61c7fb20a83293ef3195d422fde9354e6cf2a74ce223137383731457244716465764c544c57424836577a6a556331454b4744517a434d41612d17bc55b7aa153ae07fba348692c2976e6889b769783d475ba7488fb54770"
    ),
    LedgerjsApdu(   # UNTRUSTED HASH TRANSACTION INPUT START
        commands=[
            "e0440000050100000001",
            "e04480003b013832005df4c773da236484dae8f0fdba3d7e0ba1d05070d1a34fc44943e638441262a04f1001000000a086010000000000b890da969aa6f31019",
            "e04480001d76a9144533f5fb9b4817f713c48f0bfe96b9f50c476c9b88acffffffff",
        ]
    ),
    LedgerjsApdu(   # UNTRUSTED HASH TRANSACTION INPUT FINALIZE FULL
        commands=[
            "e04a80002301905f0100000000001976a91472a5d75c8d2d0565b656a5232703b167d50d5a2b88ac",
            "e04800001303800000000000000000000000000000000001"
        ],
        expected_resp="0000"
    ),
    LedgerjsApdu(   # UNTRUSTED HASH SIGN - output will be different than ledgerjs test
        commands=["e04800001303800000000000000000000000000000000001"],
        check_sig_format=True      # Only check DER format
    )
]

test_btc3 = [
    LedgerjsApdu(   # GET TRUSTED INPUT
        commands=[
            "e042000009000000010100000001",
            "e0428000254ea60aeac5252c14291d428915bd7ccd1bfc4af009f4d4dc57ae597ed0420b71010000008a",
            "e04280003247304402201f36a12c240dbf9e566bc04321050b1984cd6eaf6caee8f02bb0bfec08e3354b022012ee2aeadcbbfd1e92959f",
            "e04280003257c15c1c6debb757b798451b104665aa3010569b49014104090b15bde569386734abf2a2b99f9ca6a50656627e77de663ca7",
            "e04280002a325702769986cf26cc9dd7fdea0af432c8e2becc867c932e1b9dd742f2a108997c2252e2bdebffffffff",
            "e04280000102",
            "e04280002281b72e00000000001976a91472a5d75c8d2d0565b656a5232703b167d50d5a2b88ac",
            "e042800022a0860100000000001976a9144533f5fb9b4817f713c48f0bfe96b9f50c476c9b88ac",
            "e04280000400000000"
        ],
        expected_resp="3200" + "--"*2 + "c773da236484dae8f0fdba3d7e0ba1d05070d1a34fc44943e638441262a04f1001000000a086010000000000" + "--"*8
    ),
    LedgerjsApdu(   # UNTRUSTED HASH TRANSACTION INPUT START - 
        commands= [
            "e0440000050100000001",
            "e04480002600c773da236484dae8f0fdba3d7e0ba1d05070d1a34fc44943e638441262a04f100100000069",
            "e04480003252210289b4a3ad52a919abd2bdd6920d8a6879b1e788c38aa76f0440a6f32a9f1996d02103a3393b1439d1693b063482c04b",
            "e044800032d40142db97bdf139eedd1b51ffb7070a37eac321030b9a409a1e476b0d5d17b804fcdb81cf30f9b99c6f3ae1178206e08bc5",
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

test_btc4 = [
    LedgerjsApdu(   # SIGN MESSAGE - part 1, on 44'/0'/0'/0 path + data to sign ("test")
        commands=["e04e000117048000002c800000008000000000000000000474657374"],
        expected_resp="0000"
    ),
    LedgerjsApdu(  # SIGN MESSAGE - part 2, Null byte as end of msg
        commands=["e04e80000100"],
        check_sig_format=True
    )
]

test_btc_seg_multi = [
    LedgerjsApdu(   # GET PUBLIC KEY
        commands=[
            "e040000015058000003180000001800000050000000000000000",
            "e040000015058000003180000001800000050000000000000000",
        ]
    ),
    LedgerjsApdu(   # UNTRUSTED HASH TRANSACTION INPUT START - Inputs + prevout amounts, no scripts
        commands=[
            "e0440002050100000002",
            "e04480022e02f5f6920fea15dda9c093b565cecbe8ba50160071d9bc8bc3474e09ab25a3367d00000000c03b47030000000000",
            "e044800204ffffffff",
            "e04480022e023b9b487a91eee1293090cc9aba5acdde99e562e55b135609a766ffec4dd1100a0000000080778e060000000000",
            "e044800204ffffffff",
        ]
    ), 
    LedgerjsApdu(   # UNTRUSTED HASH TRANSACTION INPUT FINALIZE FULL - Output 1
        commands=["e04a80002101ecd3e7020000000017a9142397c9bb7a3b8a08368a72b3e58c7bb85055579287"],
        expected_resp="0000"
    ),
    LedgerjsApdu(   # UNTRUSTED HASH TRANSACTION INPUT START - Continue w/ pseudo tx w/ input 1 + script + seq
        commands=[
            "e0440080050100000001",
            "e04480802e02f5f6920fea15dda9c093b565cecbe8ba50160071d9bc8bc3474e09ab25a3367d00000000c03b47030000000019",
            "e04480801d76a9140a146582553b2f5537e13cef6659e82ed8f69b8f88acffffffff"
        ]
    ),
    LedgerjsApdu(   # UNTRUSTED HASH SIGN - for input 1
        commands=["e04800001b058000003180000001800000050000000000000000000000000001"],
        check_sig_format=True
    ),
    LedgerjsApdu(  # UNTRUSTED HASH TRANSACTION INPUT START - Continue w/ pseudo tx w/ input 2 + script + seq
        commands=[
            "e0440080050100000001",
            "e04480802e023b9b487a91eee1293090cc9aba5acdde99e562e55b135609a766ffec4dd1100a0000000080778e060000000019"
            "e04480801d76a9140a146582553b2f5537e13cef6659e82ed8f69b8f88acffffffff"
        ]
    ),
    LedgerjsApdu(   # UNTRUSTED HASH SIGN - for input 2
        commands=["e04800001b058000003180000001800000050000000000000000000000000001"],
        check_sig_format=True
    )
]

test_btc_sig_p2sh_seg = [
    LedgerjsApdu(   # UNTRUSTED HASH TRANSACTION INPUT START - Input 1 + prevout amount, no script
        commands=[
            "e0440002050100000001",
            "e04480022e021ba3852a59cded8d2760434fa75af58a617b21e4fbe1cf9c826ea2f14f80927d00000000102700000000000000",
        ]
    ),
    LedgerjsApdu(   # UNTRUSTED HASH TRANSACTION INPUT FINALIZE FULL - Output 1
        commands=["e04a8000230188130000000000001976a9140ae1441568d0d293764a347b191025c51556cecd88ac"],
        expected_resp="0000"
    ),
    LedgerjsApdu(   # UNTRUSTED HASH TRANSACTION INPUT START - Pseudo tx w/ input 1 + p2sh script
        commands=[
            "e04480802e021ba3852a59cded8d2760434fa75af58a617b21e4fbe1cf9c826ea2f14f80927d00000000102700000000000047",
            "e0448080325121026666422d00f1b308fc7527198749f06fedb028b979c09f60d0348ef79c985e41210384257cf895f1ca492bbee5d748",
            "e0448080195ae0ef479036fdf59e15b92e37970a98d6fe7552aeffffffff"
        ]
    ),
    LedgerjsApdu(   # UNTRUSTED HASH SIGN - on 0'/0/0 path
        commands=["e04800001303800000000000000000000000000000000001"],
        check_sig_format=True
    )
]

test_sign_message = [
    LedgerjsApdu(   # SIGN MESSAGE - on 44'/0'/0/0 path + data to sign (binary)
        commands=["e04e00011d058000002c800000008000000000000000000000000006666f6f626172"],
        expected_resp="0000"
    ),
    LedgerjsApdu(   # SIGN MESSAGE - Null byte as end of message
        commands=["e04e80000100"],
        check_sig_format=True
    )
]


@pytest.mark.manual
@pytest.mark.btc
class TestLedgerjsBtcTx(BaseTestBtc):

    # Some test data deactivated as they pre-date the last version of the btc tx parser
    ledgerjs_test_data = [ test_btc_get_wallet_public_key, test_btc3, test_btc4, 
                           test_sign_message,] 
                           # test_btc_sig_p2sh_seg, test_btc_seg_multi, test_btc2]

    @pytest.mark.parametrize('test_data', ledgerjs_test_data)
    def test_replay_ledgerjs_tests(self, test_data: List[LedgerjsApdu]) -> None:
        """
        Verify the Btc app with test Tx extracted from the ledjerjs package 
        that are supposedly known to work.
        """
        apdus = test_data
        btc = DeviceAppBtc()
        # All apdus shall return 9000 + potentially some data
        for apdu in apdus:      
            for command in apdu.commands:
                response = btc.sendRawApdu(bytes.fromhex(command))
            if apdu.expected_resp is not None:
                self.check_raw_apdu_resp(apdu.expected_resp, response)
            elif apdu.check_sig_format is not None and apdu.check_sig_format == True:
                self.check_signature(response)  # Only format is checked
