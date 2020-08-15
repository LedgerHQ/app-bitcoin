import pytest
from dataclasses import dataclass, field
from functools import reduce
from typing import List, Optional
from helpers.basetest import BaseTestBtc, LedgerjsApdu, TxData, CONSENSUS_BRANCH_ID
from helpers.deviceappbtc import DeviceAppBtc, CommException


# Test data below is from a Zcash test log from Live team"
test_zcash_prefix_cmds = [
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

ledgerjs_test_data = [
    test_zcash_prefix_cmds
]


utxos = [
    bytes.fromhex(
        # Version @offset 0
        "04000080"
        # Input count @offset 4
        "03"
        # Input #1 prevout hash @offset 5
        "f6959fbdd8cc614211e4db1ca287a766441dcda8d786f70d956ad19de03373a4"
        # Input #1 prevout idx @offset 37
        "01000000"
        # Input #1 script length @offset 41
        "69"
        # Input #1 script (105 bytes) @ offset 42
        "46304302203dc5102d80e08cb8dee8e83894026a234d84ddd92da1605405a677"
        "ead9fcb21a021f40bedfa4b5611fc00a6d43aedb6ea0769175c2eb4ce4f68963"
        "c3a6103228080121028aceaa654c031435beb9bcf80d656a7519a6732f3da3c8"
        "14559396131ea3532e"
        # Input #1 sequence @offset 147
        "ffffff00"
        # Input #3 prevout hash @offset 151
        "5ae818ee42a08d5c335d850cacb4b5996e5d2bc1cd5f0c5b46733652771c23b9"
        # Input #2 prevout idx @offset 183
        "01000000"
        # Input #2 script length @offset 187
        "6b"
        # Input #2 script (107 bytes) @ offset 188
        "483045022100df24e46115778a766068f1b744a7ffd2b0ae4e09b34259eecb2f"
        "5871f5e3ff7802207c83c3c13c8113f904da3ea4d4ceedb0db4e8518fb43e9fb"
        "8aeda64d1a69c76b012103e604d3cbc5c8aa4f9c53f84157be926d443054ba93"
        "b60fbddf0aea053173f595"
        # Input #2 sequence @offset 295
        "ffffff00"
        # Input #3 prevout hash @offset 299
        "6065c6c49cd132fc148f947b5aa5fd2a4e0ae4b5a884ccb3247b5ccbfa3ecc58"
        # Input #3 prevout idx @offset 331
        "01000000"
        # Input #3 script length @offset 335
        "6a"
        # Input #3 script (106 bytes) @ offset 336
        "473044022064d92d88b8223f9e502214b2abf8eb72b91ad7ed69ae9597cb510a"
        "3c94c7a2b00220327b4b852c2a81ad918bb341e7cd1c7e15903fc3e298663d75"
        "675c4ab180be890121037dbc2659579d22c284a3ea2e3b5d0881f678583e2b4a"
        "8b19dbd50f384d4b2535"
        # Input #3 sequence @offset 442
        "ffffff00"
        # Output count @offset 446
        "02"
        # Output #1 value @offset 447
        "002d310100000000"
        # Output #1 script length @offset 455
        "19"
        # Output #1 script (25 bytes) @offset 456
        "76a914772b6723ec72c99f6a37009407006fe1c790733988ac"
        # Output #2 value @offset 481
        "13b6240000000000"
        # Output #2 script length @offset 489
        "19"
        # Output #2 script (25 bytes) @offset 490
        "76a914d46156a9e784f5f28fdbbaa4ed8301170be6cc0388ac"
        # Locktime @offset 515
        "00000000"
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
    "bf86afb1ac362f58d07a2c23ed65eb0cf19e6d1743bd1f6a482c665cb874e174"
    # Prevout idx @offset 41
    "01000000"
    # input script length byte @offset 45
    "19"
    # Input script (25 bytes) @offset 46
    "76a914d46156a9e784f5f28fdbbaa4ed8301170be6cc0388ac"
    # input sequence @offset 71
    "ffffff00"
    # Output count @offset 75
    "02"
    # Output #1 value @offset 76
    "c05c150000000000"
    # Output #1 script (26 bytes) @offset 84
    "1976a914130715c4e654cff3fced8a9d6876310083d44f2e88ac"
    # Output #2 value @offset 110
    "e9540f0000000000"
    # Output #2 scritp (26 bytes) @offset 118
    "1976a91478dff3b7ed9dac8e9177c587375937f9d057769588ac"
    # Locktime @offset 144
    "00000000"
)

change_path = bytes.fromhex("058000002c80000085800000000000000100000007")   # 44'/133'/0'/1/7
output_paths = [bytes.fromhex("058000002c80000085800000000000000100000006")]    # 44'/133'/0'/1/6


class TestLedgerjsZcashTx2(BaseTestBtc):

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


    @pytest.mark.zcash
    @pytest.mark.manual
    def test_replay_zcash_with_trusted_inputs(self) -> None:
        """
        Replay of real Zcash tx from @ArnaudU's log, trusted inputs on
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
                4+5,            # len(prevout_index (BE)||version||input_count)
                37,             # len(prevout1_hash||prevout1_index||len(scriptSig1))
                -1,             # len(scriptSig1, from last byte of previous chunk) + len(input_sequence1)
                37,             # len(prevout2_hash||prevout2_index||len(scriptSig2))
                -1,             # len(scriptSig2, from last byte of previous chunk) + len(input_sequence2)
                37,             # len(prevout3_hash||prevout3_index||len(scriptSig3))
                -1,             # len(scriptSig3, from last byte of previous chunk) + len(input_sequence3)
                1,              # len(output_count) 
                34,             # len(output_value #1||len(scriptPubkey #1)||scriptPubkey #1) 
                34,             # len(output_value #2||len(scriptPubkey #2)||scriptPubkey #2) 
                4               # len(locktime)
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

        out_amounts = [utxos[0][481:481+8]]     # UTXO tx's 2nd output's value
        prevout_hashes = [tx_to_sign[9:9+32]]
        for trusted_input, out_idx, out_amount, prevout_hash in zip(
            trusted_inputs, output_indexes, out_amounts, prevout_hashes
            ):
            self.check_trusted_input(
                trusted_input, 
                out_index=out_idx[::-1],    # LE for comparison w/ out_idx in trusted_input
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
        input_sequences = [tx_to_sign[71:71+4]]
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
            9                                   # len(version||zcash flags||input_count)
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
        ptx_to_hash_part3 = tx_to_sign[75:-4]          # output_count||repeated(output_amount||scriptPubkey)
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
        input_scripts = [utxos[0][489:489 + utxos[0][489] + 1]]
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


    @pytest.mark.zcash
    @pytest.mark.manual
    def test_replay_zcash_no_trusted_inputs(self) -> None:
        """
        Replay of real Zcash tx from @ArnaudU's log, trusted inputs off
        """
        # Send the Get Version raw apdus
        apdus = test_zcash_prefix_cmds
        btc = DeviceAppBtc()
        self._send_raw_apdus(apdus, btc)

        out_amounts = [utxos[0][481:481+8]]     # UTXO tx's 2nd output's value
        prevout_hashes = [tx_to_sign[9:9+32]]

        # 2.0 Get public keys for output paths & compute their hashes
        print("\n--* Get Wallet Public Key - for each tx output path")
        wpk_responses = [btc.getWalletPublicKey(output_path) for output_path in output_paths]
        print("    OK")
        pubkeys_data = [self.split_pubkey_data(data) for data in wpk_responses]
        for pubkey in pubkeys_data:
            print(pubkey)

        # 2.1 Construct a pseudo-tx without input script, to be hashed 1st.
        print("\n--* Untrusted Transaction Input Hash Start - Hash tx to sign first w/ all inputs having a null script length")
        input_sequences = [tx_to_sign[71:71+4]]
        ptx_to_hash_part1 = [tx_to_sign[:9]]
        std_inputs = [tx_to_sign[9:45]]
        for std_input, input_sequence in zip(std_inputs, input_sequences):
            ptx_to_hash_part1.extend([
                # bytes.fromhex("00"),          # standard input marker byte, relaxed mode
                bytes.fromhex("02"),            # segwit-like input marker byte for zcash
                std_input,                      # utxo tx hash + utxo tx prevout idx (segwit-like)
                out_amounts[0],                 # idx #1 prevout amount (segwit-like)
                bytes.fromhex("00"),            # Input script length = 0 (no scriptSig)
                input_sequence
            ])
        ptx_to_hash_part1 = reduce(lambda x, y: x+y, ptx_to_hash_part1)     # Get a single bytes object

        ptx_to_hash_part1_chunks_len = [
            9                                   # len(version||zcash flags||input_count)
        ]
        for std_input in std_inputs:
            ptx_to_hash_part1_chunks_len.extend([
                1 + len(std_input) + 8 + 1,         # len(std_input_marker||std_input||amount||len(scriptSig) == 0)
                4                               # len(input_sequence)
            ])

        btc.untrustedTxInputHashStart(
            p1="00",
            # p2="02",    # /!\ "02" to activate BIP 143 signature (b/c the pseudo-tx 
            #             # contains segwit inputs encapsulated in TrustedInputs).
            p2="05",    # Value used for Zcash (TBC if bit 143 sig is activated when bit#1 is 0)
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
        ptx_to_hash_part3 = tx_to_sign[75:-4]          # output_count||repeated(output_amount||scriptPubkey)
        ptx_to_hash_part3_chunks_len = [len(ptx_to_hash_part3)]

        response = btc.untrustedTxInputHashFinalize(
            p1="00",
            data=ptx_to_hash_part3,
            chunks_len=ptx_to_hash_part3_chunks_len
        )
        assert response == bytes.fromhex("0000")
        print("    OK")
        # We're done w/ the hashing of the pseudo-tx with all inputs w/o scriptSig.

        # 2.2.3. Zcash-specific - provide the Zcash branchId
        print("\n--* Untrusted Has Sign - provide Zcash branchId as a fake derivation path")
        branch_id_data = [
            bytes.fromhex(
                "00"                    # Number of derivations (None)
                "00"                    # RFU byte
            ),
            tx_to_sign[-4:],            # locktime
            bytes.fromhex("01"),        # SigHashType - always 01
            bytes.fromhex("00000000")   # As in @ArnaudU's log
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
        input_scripts = [utxos[0][489:489 + utxos[0][489] + 1]]
        # input_scripts = [tx_to_sign[45:45 + tx_to_sign[45] + 1]]
        ptx_for_inputs = [
            [   tx_to_sign[:8],                 # Tx version||zcash flags
                bytes.fromhex("0102"),          # Input_count||segwit-like Input marker byte
                std_input,
                utxos[0][481:481+8],            # prevout @idx 1 amount (if segwit-like)
                input_script,
                input_sequence
            ] for std_input, input_script, input_sequence in zip(std_inputs, input_scripts, input_sequences)
        ]

        ptx_chunks_lengths = [
            [
                9,                              # len(version||zcash flags||input_count) - segwit flag+version not sent
                # 1 + len(trusted_input) + 1,     # len(std_input_marker||std_input||scriptSig_len == 0x19)
                1 + len(std_input) + 8 + 1,     # len(std_input_marker||std_input||scriptSig_len == 0x19)
                -1                              # get len(scripSig) from last byte of previous chunk + len(input_sequence)
            ] for std_input in std_inputs
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
            #       Num_derivs||Dest output path||RFU (0x00)||tx locktime||sigHashType(always 0x01)||empty nExpiryHeight (as per spec) (4B)
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

