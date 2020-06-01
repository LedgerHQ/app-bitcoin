import pytest
from dataclasses import dataclass, field
from functools import reduce
from typing import List, Optional
from helpers.basetest import BaseTestBtc, LedgerjsApdu, TxData, CONSENSUS_BRANCH_ID
from helpers.deviceappbtc import DeviceAppBtc, CommException


# Test data below is from a Zcash test log from Live team"
test_zcash_prefix_cmds = [
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

test_zcash_tx_sign_gti =  [
    LedgerjsApdu(   # GET TRUSTED INPUT
        commands=[
            "e042000009000000010400008001",
            "e042800025edc69b8179fd7c6a11a8a1ba5d17017df5e09296c3a1acdada0d94e199f68857010000006b",
            "e042800032483045022100e8043cd498714122a78b6ecbf8ced1f74d1c65093c5e2649336dfa248aea9ccf022023b13e57595635452130",
            "e0428000321c91ed0fe7072d295aa232215e74e50d01a73b005dac01210201e1c9d8186c093d116ec619b7dad2b7ff0e7dd16f42d458da",
            "e04280000b1100831dc4ff72ffffff00",
            "e04280000102",
            "e042800022a0860100000000001976a914fa9737ab9964860ca0c3e9ad6c7eb3bc9c8f6fb588ac",
            "e0428000224d949100000000001976a914b714c60805804d86eb72a38c65ba8370582d09e888ac",
            "e04280000400000000",
        ],
        expected_resp="3200" + "--"*2 + "20b7c68231303b2425a91b12f05bd6935072e9901137ae30222ef6d60849fc51010000004d94910000000000" + "--"*8
    ), 
]

test_zcash_tx_to_sign_abandonned = [
    LedgerjsApdu(   # GET PUBLIC KEY
        commands=["e040000015058000002c80000085800000000000000100000001"],  # on 44'/133'/0'/1/1
    ),
    LedgerjsApdu(   # UNTRUSTED HASH TRANSACTION INPUT START
        commands=[
            "e0440005090400008085202f8901",
            "e04480053b013832004d0420b7c68231303b2425a91b12f05bd6935072e9901137ae30222ef6d60849fc51010000004d9491000000000045e1e144cb88d4d800",
            "e044800504ffffff00",
        ]
    ),
    LedgerjsApdu(   # UNTRUSTED HASH TRANSACTION INPUT FINALIZE FULL
        commands=[
            "e04aff0015058000002c80000085800000000000000100000003",
            # "e04a0000320240420f00000000001976a91490360f7a0b0e50d5dd0c924fc1d6e7adb8519c9388ac39498200000000001976a91425ea06"
            "e04a0000230140420f00000000001976a91490360f7a0b0e50d5dd0c924fc1d6e7adb8519c9388ac"
        ],  # tx aborted on 2nd command
        expected_sw="6985"
    ),
]

test_zcash_tx_sign_restart_prefix_cmds = [
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

test_zcash_tx_to_sign_finalized = test_zcash_tx_sign_gti + [
    LedgerjsApdu(   # GET PUBLIC KEY
        commands=["e040000015058000002c80000085800000000000000100000001"],  # on 44'/133'/0'/1/1
    ),
    LedgerjsApdu(   # UNTRUSTED HASH TRANSACTION INPUT START
        commands=[
            "e0440005090400008085202f8901",
            "e04480053b""013832004d""0420b7c68231303b2425a91b12f05bd6935072e9901137ae30222ef6d60849fc51""01000000""4d94910000000000""45e1e144cb88d4d8""00",
            "e044800504ffffff00",
        ]
    ),
    LedgerjsApdu(   # UNTRUSTED HASH TRANSACTION INPUT FINALIZE FULL
        commands=[
            "e04aff0015058000002c80000085800000000000000100000003",
            # "e04a0000320240420f00000000001976a91490360f7a0b0e50d5dd0c924fc1d6e7adb8519c9388ac39498200000000001976a91425ea06"
            
            "e04a0000230140420f00000000001976a91490360f7a0b0e50d5dd0c924fc1d6e7adb8519c9388ac"
            "e04a8000045eb3f840"
        ],
        expected_resp="0000"
    ),

    LedgerjsApdu(
        commands=[
            "e044008509""0400008085202f8901",
            "e04480853b""013832004d04""20b7c68231303b2425a91b12f05bd6935072e9901137ae30222ef6d60849fc51""01000000""4d94910000000000""45e1e144cb88d4d8""19",
            "e04480851d""76a9140a146582553b2f5537e13cef6659e82ed8f69b8f88ac""ffffff00",

            "e048000015""058000002c80000085800000000000000100000001"
        ],
        check_sig_format=True
    )
]


ledgerjs_test_data = [
    test_zcash_prefix_cmds, test_zcash_tx_sign_gti, test_zcash_tx_to_sign_abandonned, 
    test_zcash_tx_sign_restart_prefix_cmds, test_zcash_tx_to_sign_finalized
]


utxo_single = bytes.fromhex(
    # https://sochain.com/api/v2/tx/ZEC/ec9033381c1cc53ada837ef9981c03ead1c7c41700ff3a954389cfaddc949256
    # Version @offset 0
    "04000080"
    # versionGroupId @offset 4
    "85202f89"
    # Input count @offset 8
    "01"
    # Input prevout hash @offset 9
    "53685b8809efc50dd7d5cb0906b307a1b8aa5157baa5fc1bd6fe2d0344dd193a"
    # Input prevout idx @offset 41
    "00000000"
    # Input script length @offset 45
    "6b"
    # Input script (107 bytes) @ offset 46
    "483045022100ca0be9f37a4975432a52bb65b25e483f6f93d577955290bb7fb0"
    "060a93bfc92002203e0627dff004d3c72a957dc9f8e4e0e696e69d125e4d8e27"
    "5d119001924d3b48012103b243171fae5516d1dc15f9178cfcc5fdc67b0a8830"
    "55c117b01ba8af29b953f6"
    # Input sequence @offset 151
    "ffffffff"
    # Output count @offset 155
    "01"
    # Output #1 value @offset 156
    "4072070000000000"
    # Output #1 script length @offset 164
    "19"
    # Output #1 script (25 bytes) @offset 165
    "76a91449964a736f3713d64283fd0018626ba50091c7e988ac"
    # Locktime @offset 190
    "00000000"
    # Extra payload (size of everything remaining, specific to btc app inner protocol @offset 194
    "0F"
    # Expiry @offset 195
    "00000000"
    # valueBalance @offset 199
    "0000000000000000"
    # vShieldedSpend @offset 207
    "00"
    # vShieldedOutput @offset 208
    "00"
    # vJoinSplit @offset 209
    "00"
)


utxos = [
    # Considered a segwit tx - segwit flags couldn't be extracted from raw 
    # Get Trusted Input APDUs as they are not supposed to be sent w/ these APDUs.
    bytes.fromhex(
        # Version @offset 0
        "04000080"
        # versionGroupId @offset 4
        "85202f89"
        # Input count @offset 8
        "01"
        # Input prevout hash @offset 9
        "edc69b8179fd7c6a11a8a1ba5d17017df5e09296c3a1acdada0d94e199f68857"
        # Input prevout idx @offset 41
        "01000000"
        # Input script length @offset 45
        "6b"
        # Input script (107 bytes) @ offset 46
        "483045022100e8043cd498714122a78b6ecbf8ced1f74d1c65093c5e2649336d"
        "fa248aea9ccf022023b13e575956354521301c91ed0fe7072d295aa232215e74"
        "e50d01a73b005dac01210201e1c9d8186c093d116ec619b7dad2b7ff0e7dd16f"
        "42d458da1100831dc4ff72"
        # Input sequence @offset 153
        "ffffff00"
        # Output count @offset 157
        "02"
        # Output #1 value @offset 160
        "a086010000000000"
        # Output #1 script length @offset 168
        "19"
        # Output #1 script (25 bytes) @offset 167
        "76a914fa9737ab9964860ca0c3e9ad6c7eb3bc9c8f6fb588ac"
        # Output #2 value @offset 192
        "4d94910000000000"      # 9 540 685 units of ZEC smallest currency available
        # Output #2 script length @offset 200
        "19"
        # Output #2 script (25 bytes) @offset 201
        "76a914b714c60805804d86eb72a38c65ba8370582d09e888ac"
        # Locktime @offset 226
        "00000000"
        # Extra payload (size of everything remaining, specific to btc app inner protocol @offset 230
        "0F"
        # Expiry @offset 231
        "00000000"
        # valueBalance @offset 235
        "0000000000000000"
        # vShieldedSpend @offset 243
        "00"
        # vShieldedOutput @offset 244
        "00"
        # vJoinSplit @offset 245
        "00"
    )
]

tx_to_sign = bytes.fromhex(
    # version @offset 0
    "04000080"
    # Some Zcash flags (?) @offset 4 
    "85202f89"
    # Input count @offset 8
    "01"
    # Input's prevout hash @offset 9
    "d35f0793da27a5eacfe984c73b1907af4b50f3aa3794ba1bb555b9233addf33f"
    # Prevout idx @offset 41
    "01000000"
    # input sequence @offset 45
    "ffffff00"
    # Output count @offset 49
    "02"
    # Output #1 value @offset 50
    "40420f0000000000"      # 1 000 000 units of available balance spent
    # Output #1 script (26 bytes) @offset 58
    "1976a91490360f7a0b0e50d5dd0c924fc1d6e7adb8519c9388ac"
    # Output #2 value @offset 84
    "2b51820000000000"
    # Output #2 scritp (26 bytes) @offset 92
    "1976a91490360f7a0b0e50d5dd0c924fc1d6e7adb8519c9388ac"
    # Locktime @offset 118
    "5eb3f840"
)

change_path = bytes.fromhex("058000002c80000085800000000000000100000003")   # 44'/133'/0'/1/3
output_paths = [
    bytes.fromhex("058000002c80000085800000000000000100000001"),    # 44'/133'/0'/1/1
    bytes.fromhex("058000002c80000085800000000000000000000004")     # 44'/133'/0'/0/4
]

@pytest.mark.zcash
class TestLedgerjsZcashTx(BaseTestBtc):

    def _send_raw_apdus(self, apdus: List[LedgerjsApdu], device: DeviceAppBtc):
        # Send the Get Version APDUs 
        for apdu in apdus:   
            try:
                for command in apdu.commands:
                    response = device.sendRawApdu(bytes.fromhex(command))
                if apdu.expected_resp is not None:
                    self.check_raw_apdu_resp(apdu.expected_resp, response)
                elif apdu.check_sig_format is not None and apdu.check_sig_format == True:
                    self.check_signature(response)  # Only format is checked
            except CommException as error:
                if apdu.expected_sw is not None and error.sw.hex() == apdu.expected_sw:
                    continue
                raise error


    @pytest.mark.skip(reason="Hardcoded TrustedInput can't be replayed on a different device than the one that generated it")
    @pytest.mark.manual
    @pytest.mark.parametrize('test_data', ledgerjs_test_data)
    def test_replay_zcash_test(self, test_data: List[LedgerjsApdu]) -> None:
        """
        Replay of raw apdus from @gre. 
        
        First time an output is presented for validation, it must be rejected by user
        Then tx will be restarted and on 2nd presentation of outputs they have to be 
        accepted.
        """
        apdus = test_data
        btc = DeviceAppBtc()
        self._send_raw_apdus(apdus, btc)

    @pytest.mark.manual
    def test_get_single_trusted_input(self) -> None:

        btc = DeviceAppBtc()

        # 1. Get Trusted Input
        print("\n--* Get Trusted Input - from utxos")
        input_datum =  bytes.fromhex("00000000") + utxo_single
        utxo_chunk_len = [
            4 + 5 + 4,  # len(prevout_index (BE)||version||input_count||versionGroupId)
            37,  # len(prevout_hash||prevout_index||len(scriptSig))
            -1,  # len(scriptSig, from last byte of previous chunk) + len(input_sequence)
            1,  # len(output_count)
            34,  # len(output_value #1||len(scriptPubkey #1)||scriptPubkey #1)
            4 + 1,  # len(locktime || extra_data)
            4+16+1+1+1  # len(Expiry||valueBalance||vShieldedSpend||vShieldedOutput||vJoinSplit)
        ]

        trusted_input = btc.getTrustedInput(data=input_datum, chunks_len=utxo_chunk_len)

        self.check_trusted_input(
            trusted_input,
            out_index=bytes.fromhex("00000000"),
            out_amount=bytes.fromhex("4072070000000000"),
            out_hash=bytes.fromhex("569294dcadcf8943953aff0017c4c7d1ea031c98f97e83da3ac51c1c383390ec")
        )

        print("    OK")

    @pytest.mark.manual
    def test_replay_zcash_test2(self) -> None:
        """
        Adapted version to work around some hw limitations
        """
        # Send the Get Version raw apdus
        apdus = test_zcash_prefix_cmds
        btc = DeviceAppBtc()
        self._send_raw_apdus(apdus, btc)

        # 1. Get Trusted Input
        print("\n--* Get Trusted Input - from utxos")
        output_indexes = [
            tx_to_sign[41+4-1:41-1:-1],     # out_index in tx_to_sign input must be passed BE as prefix to utxo tx
        ]
        input_data = [out_idx + utxo for out_idx, utxo in zip(output_indexes, utxos)]
        utxos_chunks_len = [
            [   # utxo #1
                4+5+4,                # len(prevout_index (BE)||version||input_count||versionGroupId)
                37,                 # len(prevout_hash||prevout_index||len(scriptSig))
                -1,                 # len(scriptSig, from last byte of previous chunk) + len(input_sequence)
                1,                  # len(output_count)
                34,                 # len(output_value #1||len(scriptPubkey #1)||scriptPubkey #1)
                34,                 # len(output_value #2||len(scriptPubkey #2)||scriptPubkey #2)
                4 + 1,              # len(locktime)
                4 + 16 + 1 + 1 + 1  # len(Expiry||valueBalance||vShieldedSpend||vShieldedOutput||vJoinSplit)
            ]
        ]
        trusted_inputs = [
            btc.getTrustedInput(
                data=input_datum,
                chunks_len=chunks_len
            )
            for (input_datum, chunks_len) in zip(input_data, utxos_chunks_len)
        ]
        print("    OK")

        out_amounts = [utxos[0][192:192+8]]     # UTXO tx's 2nd output's value
        prevout_hashes = [tx_to_sign[9:9+32]]
        for trusted_input, out_idx, out_amount, prevout_hash in zip(
            trusted_inputs, output_indexes, out_amounts, prevout_hashes
            ):
            self.check_trusted_input(
                trusted_input, 
                out_index=out_idx[::-1],  # LE for comparison w/ out_idx in trusted_input
                out_amount=out_amount,      # utxo output #1 is requested in tx to sign input
                out_hash=prevout_hash       # prevout hash in tx to sign
            )

        # 2.0 Get public keys for output paths & compute their hashes
        print("\n--* Get Wallet Public Key - for each tx output path")
        wpk_responses = [btc.getWalletPublicKey(output_path) for output_path in output_paths]
        print("    OK")
        pubkeys_data = [self.split_pubkey_data(data) for data in wpk_responses]
        for pubkey in pubkeys_data:
            print(pubkey)

        # 2.1 Construct a pseudo-tx without input script, to be hashed 1st.
        print("\n--* Untrusted Transaction Input Hash Start - Hash tx to sign first w/ all inputs having a null script length")
        input_sequences = [tx_to_sign[45:45+4]]
        ptx_to_hash_part1 = [tx_to_sign[:9]]
        for trusted_input, input_sequence in zip(trusted_inputs, input_sequences):
            ptx_to_hash_part1.extend([
                bytes.fromhex("01"),            # TrustedInput marker byte, triggers the TrustedInput's HMAC verification
                bytes([len(trusted_input)]),
                trusted_input,
                bytes.fromhex("00"),            # Input script length = 0 (no sigScript)
                input_sequence
            ])
        ptx_to_hash_part1 = reduce(lambda x, y: x+y, ptx_to_hash_part1)     # Get a single bytes object

        ptx_to_hash_part1_chunks_len = [
            9                                   # len(version||flags||input_count) - skip segwit version+flag bytes
        ]
        for trusted_input in trusted_inputs:
            ptx_to_hash_part1_chunks_len.extend([
                1 + 1 + len(trusted_input) + 1, # len(trusted_input_marker||len(trusted_input)||trusted_input||len(scriptSig) == 0)
                4                               # len(input_sequence)
            ])

        btc.untrustedTxInputHashStart(
            p1="00",
            p2="05",    # Value used for Zcash
            data=ptx_to_hash_part1,
            chunks_len=ptx_to_hash_part1_chunks_len
        )
        print("    OK")

        # 2.2 Finalize the input-centric-, pseudo-tx hash with the remainder of that tx
        # 2.2.1 Start with change address path
        print("\n--* Untrusted Transaction Input Hash Finalize Full - Handle change address")
        ptx_to_hash_part2 = change_path
        ptx_to_hash_part2_chunks_len = [len(ptx_to_hash_part2)]
        
        btc.untrustedTxInputHashFinalize(
            p1="ff",    # to derive BIP 32 change address
            data=ptx_to_hash_part2,
            chunks_len=ptx_to_hash_part2_chunks_len
        )
        print("    OK")

        # 2.2.2 Continue w/ tx to sign outputs & scripts
        print("\n--* Untrusted Transaction Input Hash Finalize Full - Continue w/ hash of tx output")
        ptx_to_hash_part3 = tx_to_sign[49:118]          # output_count||repeated(output_amount||scriptPubkey)
        ptx_to_hash_part3_chunks_len = [len(ptx_to_hash_part3)]

        response = btc.untrustedTxInputHashFinalize(
            p1="00",
            data=ptx_to_hash_part3,
            chunks_len=ptx_to_hash_part3_chunks_len
        )
        assert response == bytes.fromhex("0000")
        print("    OK")
        # We're done w/ the hashing of the pseudo-tx with all inputs w/o scriptSig.

        # 2.2.3. Zcash-specific: "When using Overwinter/Sapling, UNTRUSTED HASH SIGN is 
        #        called with an empty authorization and nExpiryHeight following the first 
        #        UNTRUSTED HASH TRANSACTION INPUT FINALIZE FULL"
        print("\n--* Untrusted Has Sign - with empty Auth & nExpiryHeight")
        branch_id_data = [
            bytes.fromhex(
                "00"                    # Number of derivations (None)
                "00"                    # Empty validation code
            ),
            tx_to_sign[-4:],            # locktime
            bytes.fromhex("01"),        # SigHashType - always 01
            bytes.fromhex("00000000")   # Empty nExpiryHeight
        ]
        response = btc.untrustedHashSign(
            data = reduce(lambda x, y: x+y, branch_id_data)
        )


        # 3. Sign each input individually. Because inputs are segwit, hash each input with its scriptSig 
        #    and sequence individually, each in a pseudo-tx w/o output_count, outputs nor locktime. 
        print("\n--* Untrusted Transaction Input Hash Start, step 2 - Hash again each input individually (only 1)")
        # Inputs are P2WPKH, so use 0x1976a914{20-byte-pubkey-hash}88ac from utxo as scriptSig in this step.
        #
        # From btc.asc: "The input scripts shall be prepared by the host for the transaction signing process as 
        #   per bitcoin rules : the current input script being signed shall be the previous output script (or the 
        #   redeeming script when consuming a P2SH output, or the scriptCode when consuming a BIP 143 output), and 
        #   other input script shall be null."
        input_scripts = [utxos[0][196:196 + utxos[0][196] + 1]]
        # input_scripts = [tx_to_sign[45:45 + tx_to_sign[45] + 1]]
        # input_scripts = [bytes.fromhex("1976a914") + pubkey.pubkey_hash + bytes.fromhex("88ac") 
                        #  for pubkey in pubkeys_data]
        ptx_for_inputs = [
            [   tx_to_sign[:8],                 # Tx version||zcash flags
                bytes.fromhex("0101"),          # Input_count||TrustedInput marker byte
                bytes([len(trusted_input)]),
                trusted_input,
                input_script,
                input_sequence
            ] for trusted_input, input_script, input_sequence in zip(trusted_inputs, input_scripts, input_sequences)
        ]

        ptx_chunks_lengths = [
            [
                9,                              # len(version||zcash flags||input_count) - segwit flag+version not sent
                1 + 1 + len(trusted_input) + 1, # len(trusted_input_marker||len(trusted_input)||trusted_input||scriptSig_len == 0x19)
                -1                              # get len(scripSig) from last byte of previous chunk + len(input_sequence)
            ] for trusted_input in trusted_inputs
        ]

        # Hash & sign each input individually
        for ptx_for_input, ptx_chunks_len, output_path in zip(ptx_for_inputs, ptx_chunks_lengths, output_paths):
            # 3.1 Send pseudo-tx w/ sigScript
            btc.untrustedTxInputHashStart(
                p1="00",
                p2="80",        # to continue previously started tx hash, be it BTc or other BTC-like coin
                data=reduce(lambda x,y: x+y, ptx_for_input),
                chunks_len=ptx_chunks_len
            )
            print("    Final hash OK")

            # 3.2 Sign tx at last. Param is:
            #       Num_derivs||Dest output path||RFU (0x00)||tx locktime||sigHashType(always 0x01)||Branch_id for overwinter (4B)
            print("\n--* Untrusted Transaction Hash Sign")
            tx_to_sign_data = output_path   \
                + bytes.fromhex("00")       \
                + tx_to_sign[-4:]           \
                + bytes.fromhex("01")       \
                + bytes.fromhex("00000000")

            response = btc.untrustedHashSign(
                data = tx_to_sign_data
            )
            self.check_signature(response)  # Check sig format only
            # self.check_signature(response, expected_der_sig)  # Can't test sig value as it depends on signing device seed
            print("    Signature OK\n")

