# 
# Note on 'chunks_len' values used in tests:
# -----------------------------------------
# The BTC app tx parser requires the tx data to be sent in chunks. For some tx fields 
# it doesn't matter where the field is cut but for others it does and the rule is unclear.
#
# Until I get a simple to use and working Tx parser class done, a workaround is
# used to split the tx in chunks of specific lengths, as done in ledgerjs' Btc.test.js 
# file. Tx chunks lengths are gathered in a list, following the grammar below:
#
#   chunks_lengths := list_of(chunk_desc,) i.e. [chunk_desc, chunk_desc,...]
#   chunk_desc     := offs_len_tuple | length | -1
#   offs_len_tuple := (offset, length) | (length1, skip_length, length2)
#
# with:
#   offset: 
#       the offset of the 1st byte in the tx for the data chunk to be sent. Allows to skip some 
#       parts of the tx which should not be sent to the tx parser.
#   length: 
#       the length of the chunk to be sent
#   length1, length2:
#       the lengths of 2 non-contiguous chunks of data in the tx separated by a block of 
#       skip_length bytes. The 2 non-contiguous blocks are concatenated together and the bloc
#       of skip_length bytes is ignored. This is used when 2 non-contiguous parts of the tx
#       must be sent in the same APDU but without the in-between bytes.
#   -1: 
#       the length of the chunk to be sent is the last byte of the previous chunk + 4. This is 
#       used to send input/output scripts + their following 4-byte sequence_number in chunks.
#       Sequence_number can't be sent separately from its output script as it puts the
#       BTC app's tx parser in an invalid state (sw 0x6F01 returned, not clear why). This implicit 
#       +4 is to work around that limitation (but design-wise, it introduces knowledge of the tx 
#       format in the _sendApdu() method used by the tests :/).

import pytest
from typing import Optional, List
from functools import reduce
from helpers.basetest import BaseTestBtc, BtcPublicKey, TxData
from helpers.deviceappbtc import DeviceAppBtc

utxos = [
    bytes.fromhex(
        # Version no (4 bytes) @offset 0
        "02000000"
        # Marker + Flag (optional 2 bytes, 0001 indicates the presence of witness data)
        # /!\ Remove flag for `GetTrustedInput` @offset 4
        "0001"
        # In-counter (varint 1-9 bytes) @offset 6
        "01"
        # 1st Previous Transaction hash (32 bytes) @offset 7
        "1541bf80c7b109c50032345d7b6ad6935d5868520477966448dc78ab8f493db1"
        # 1st Previous Txout-index (4 bytes) @offset 39
        "00000000"
        # 1st Txin-script length (varint 1-9 bytes) @offset 43
        "17"
        # Txin-script (a.k.a scriptSig) because P2SH @offset 44
        "160014d44d01d48f9a0d5dfa73dab21c30f7757aed846a"
        # sequence_no (4 bytes) @offset 67
        "feffffff"
        # Out-counter (varint 1-9 bytes) @offset 71
        "02"
        # value in satoshis (8 bytes) @offset 72
        "9b3242bf01000000"  # 999681 satoshis = 0,00999681 BTC
        # Txout-script length (varint 1-9 bytes) @offset 80
        "17"
        # Txout-script (a.k.a scriptPubKey) @offset 81
        "a914ff31b9075c4ac9aee85668026c263bc93d016e5a87"
        # value in satoshis (8 bytes) @offset 104
        "1027000000000000"  # 999681 satoshis = 0,00999681 BTC
        # Txout-script length (varint 1-9 bytes) @offset 112
        "17"
        # Txout-script (a.k.a scriptPubKey) @offset 113
        "a9141e852ac84f8385d76441c584e41f445aaf1624ea87"
        # Witnesses (1 for each input if Marker+Flag=0001) @offset 136
        # /!\ remove witnesses for GetTrustedInput
        "0247"
        "304402206e54747dabff52f5c88230a3036125323e21c6c950719f671332"
        "cdd0305620a302204a2f2a6474f155a316505e2224eeab6391d5e6daf22a"
        "cd76728bf74bc0b48e1a0121033c88f6ef44902190f859e4a6df23ecff4d"
        "86a2114bd9cf56e4d9b65c68b8121d"
        # lock_time (4 bytes) @offset  @offset 243
        "1f7f1900"
    ),
    bytes.fromhex(
        # Version (4bytes) @offset 0
        "01000000"
        # Segwit (2 bytes) version+flag @offset 4
        "0001"
        # Input count @offset 6
        "02"
        # Input #1 prevout_hash (32 bytes) @offset 7
        "7ab1cb19a44db08984031508ec97de727b32a8176cc00fce727065e86984c8df"
        # Input #1 prevout_idx (4 bytes) @offset 39
        "00000000"
        # Input #1 scriptSig len @offset 43
        "17"
        # Input #1 scriptSig (23 bytes) @offset 44
        "160014d815dddcf8cf1b820419dcb1206a2a78cfa60320"
        # Input #1 sequence (4 bytes) @offset 67
        "ffffff00"
        # Input #2 prevout_hash (32 bytes) @offset 71
        "78958127caf18fc38733b7bc061d10bca72831b48be1d6ac91e296b888003327"
        # Input #2 prevout_idx (4 bytes) @offset 103
        "00000000"
        # Input #2 scriptSig length @offset 107
        "17"
        # Input #1 scriptSig (23 bytes) @offset 108 
        "160014d815dddcf8cf1b820419dcb1206a2a78cfa60320"
        # Input #2 sequence (4 bytes) @offset 131
        "ffffff00"
        # Output count @ @offset 135
        "02"
        # Output # 1 value (8 bytes) @offset 136
        "1027000000000000"
        # Output #1 scriptPubkey (24 bytes) @offset 144
        "17"
        "a91493520844497c54e709756c819afecfffaf28761187"
        # Output #2 value (8 bytes) @offset 168
        "c84b1a0000000000"
        # Output #2 scriptPubkey (24 bytes) @offset 176
        "17"
        "a9148f1f7cf3c847e4057be46990c4a00be4271f3cfa87"
        # Witnesses (214 bytes) @offset 200
        "0247"
        "3044022009116da9433c3efad4eaf5206a780115d6e4b2974152bdceba220c45"
        "70e527a802202b06ca9eb93df1c9fc5b0e14dc1f6698adc8cbc15d3ec4d364b7"
        "bef002c493d701210293137bc1a9b7993a1d2a462188efc45d965d135f53746b"
        "6b146a3cec9905322602473044022034eceb661d9e5f777468089b262f6b25e1"
        "41218f0ec9e435a98368d3f347944d02206041228b4e43a1e1fbd70ca15d3308"
        "af730eedae9ec053afec97bd977be7685b01210293137bc1a9b7993a1d2a4621"
        "88efc45d965d135f53746b6b146a3cec99053226"
        # locktime (4 bytes) @offset 414 (or -4)
        "00000000")
]

tx_to_sign = bytes.fromhex(
    # Version
    "01000000"
    # Segwit flag+version
    "0001"
    # Input count
    "02"
    # Prevout hash (txid) @offset 7
    "027a726f8aa4e81a45241099a9820e6cb7d8920a686701ad98000721101fa0aa"
    # Prevout index @offset 39
    "01000000"
    # scriptSig @offset 43
    "17"
    "160014d815dddcf8cf1b820419dcb1206a2a78cfa60320"
    # Input sequence @offset 67
    "ffffff00"
    # Input #2 prevout hash (32 bytes) @offset 71
    "f0b7b7ad837b4d3535bea79a2fa355262df910873b7a51afa1e4279c6b6f6e6f"
    # Input #2 prevout index (4 bytes) @offset 103
    "00000000"
    # Input #2 scriptSig @offset 107
    "17"
    "160014eee02beeb4a8f15bbe4926130c086bd47afe8dbc"
    #Input #2 sequence (4 bytes) @offset 131
    "ffffff00"

    # Output count @offset 135
    "02"
    # Amount #1 @offset (8 bytes) 136
    "1027000000000000"
    # scriptPubkey #1 (24 bytes) @offset 144
    "17"
    "a9142406cd1d50d3be6e67c8b72f3e430a1645b0d74287"
    # Amount #2 (8 bytes) @offset 168
    "0e26000000000000"
    # scriptPubkey #2 (24 bytes) @ offset 176
    "17" 
    "a9143ae394774f1348be3a6bc2a55b67e3566d13408987"
    
    # Signed DER-encoded withness from testnet (@offset 200)
    # /!\ Do not send to UntrustedSignHash! But the signature it contains 
    #     can be used to verify the test output, provided the same seed and
    #     derivation paths are used.
    "02""48"
        #Input #1 sig @offset 202
        "30""45"
            "02""21"    
                "00f4d05565991d98573629c7f98c4f575a4915600a83a0057716f1f4865054927f"
            "02""20"
                "10f30365e0685ee46d81586b50f5dd201ddedab39cfd7d16d3b17f94844ae6d5"
    "01""21"
        "0293137bc1a9b7993a1d2a462188efc45d965d135f53746b6b146a3cec99053226"
    "02""47"
        # Input #2 sig @offset 309
        "30""44"
            "02""20"
                "30c4c770db75aa1d3ed877c6f995a1e6055be00c88efefb2fb2db8c596f2999a"
            "02""20"
                "5529649f4366427e1d9ed3cf8dc80fe25e04ce4ac19b71578fb6da2b5788d45b"
    "01""21"
        "03cfbca92ae924a3bd87529956cb4f372a45daeafdb443e12a781881759e6f48ce"
    
    # locktime @offset -4
    "00000000"
)

expected_der_sig = [
    tx_to_sign[202:202+2+tx_to_sign[203]+1],
    tx_to_sign[309:309+2+tx_to_sign[309]+1]
]

output_paths = [
    bytes.fromhex("05""80000031""80000001""80000000""00000000""000001f6"),  # 49'/1'/0'/0/502
    bytes.fromhex("05""80000031""80000001""80000000""00000000""000001f7")   # 49'/1'/0'/0/503
]
change_path = bytes.fromhex("05""80000031""80000001""80000000""00000001""00000045") # 49'/1'/0'/1/69

test12_data = TxData(
    tx_to_sign=tx_to_sign,
    utxos=utxos,
    output_paths=output_paths,
    change_path=change_path,
    expected_sig=expected_der_sig
)

@pytest.mark.btc
@pytest.mark.manual
class TestBtcSegwitTxLjs(BaseTestBtc):

    @pytest.mark.parametrize("test_data", [test12_data])
    def test_sign_tx_with_multiple_trusted_segwit_inputs(self, test_data: TxData):
        """
        Submit segwit input as TrustedInput for signature.
        Signature obtained should be the same as no segwit inputs were used directly were used.
        """
        # Start test
        tx_to_sign = test_data.tx_to_sign
        utxos = test_data.utxos
        output_paths = test_data.output_paths
        change_path = test_data.change_path
        expected_der_sig = test_data.expected_sig

        btc = DeviceAppBtc()

        # 1. Get trusted inputs (submit output index + prevout tx)
        output_indexes = [
            tx_to_sign[39+4-1:39-1:-1],     # out_index in tx_to_sign input must be passed BE as prefix to utxo tx
            tx_to_sign[103+4-1:103-1:-1]
        ]
        input_data = [out_idx + utxo for out_idx, utxo in zip(output_indexes, utxos)]
        utxos_chunks_len = [
            [   # utxo #1
                (4+4, 2, 1),    # len(prevout_index (BE)||version||input_count) - (skip 2-byte segwit Marker+flags)
                37,             # len(prevout_hash||prevout_index||len(scriptSig))
                -1,             # len(scriptSig, from last byte of previous chunk) + len(input_sequence)
                1,              # len(output_count) 
                32,             # len(output_value #1||len(scriptPubkey #1)||scriptPubkey #1) 
                32,             # len(output_value #2||len(scriptPubkey #2)||scriptPubkey #2) 
                (243+4, 4)      # len(locktime) - skip witness data
            ],
            [   # utxo #2
                (4+4, 2, 1),    # len(prevout_index (BE)||version||input_count) - (skip 2-byte segwit Marker+flags)
                37,             # len(prevout1_hash||prevout1_index||len(scriptSig1))
                -1,             # len(scriptSig1, from last byte of previous chunk) + len(input_sequence1)
                37,             # len(prevout2_hash||prevout2_index||len(scriptSig2))
                -1,             # len(scriptSig2, from last byte of previous chunk) + len(input_sequence2)
                1,              # len(output_count) 
                32,             # len(output_value #1||len(scriptPubkey #1)||scriptPubkey #1) 
                32,             # len(output_value #2||len(scriptPubkey #2)||scriptPubkey #2) 
                (414+4, 4)      # len(locktime) - skip witness data
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

        out_amounts = [utxos[0][104:104+8], utxos[1][136:136+8]]
        prevout_hashes = [tx_to_sign[7:7+32], tx_to_sign[71:71+32]]
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

        # 2.1 Construct a pseudo-tx without input script, to be hashed 1st. The original segwit input 
        #     being replaced with the previously obtained TrustedInput, it is prefixed it with the marker
        #     byte for TrustedInputs (0x01) that the BTC app expects to check the Trusted Input's HMAC.
        print("\n--* Untrusted Transaction Input Hash Start - Hash tx to sign first w/ all inputs having a null script length")
        input_sequences = [tx_to_sign[67:67+4], tx_to_sign[131:131+4]]
        ptx_to_hash_part1 = [tx_to_sign[:7]]
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
            (4, 2, 1)                           # len(version||input_count) - skip segwit version+flag bytes
        ]
        for trusted_input in trusted_inputs:
            ptx_to_hash_part1_chunks_len.extend([
                1 + 1 + len(trusted_input) + 1, # len(trusted_input_marker||len(trusted_input)||trusted_input||len(scriptSig) == 0)
                4                               # len(input_sequence)
            ])

        btc.untrustedTxInputHashStart(
            p1="00",
            p2="02",    # /!\ "02" to activate BIP 143 signature (b/c the pseudo-tx 
                        # contains segwit inputs encapsulated in TrustedInputs).
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
        ptx_to_hash_part3 = tx_to_sign[135:200]          # output_count||repeated(output_amount||scriptPubkey)
        ptx_to_hash_part3_chunks_len = [len(ptx_to_hash_part3)]

        response = btc.untrustedTxInputHashFinalize(
            p1="00",
            data=ptx_to_hash_part3,
            chunks_len=ptx_to_hash_part3_chunks_len
        )
        assert response == bytes.fromhex("0000")
        print("    OK")
        # We're done w/ the hashing of the pseudo-tx with all inputs w/o scriptSig.

        # 3. Sign each input individually. Because inputs are segwit, hash each input with its scriptSig 
        #    and sequence individually, each in a pseudo-tx w/o output_count, outputs nor locktime. 
        print("\n--* Untrusted Transaction Input Hash Start, step 2 - Hash again each input individually (only 1)")
        # Inputs are P2WPKH, so use 0x1976a914{20-byte-pubkey-hash}88ac as scriptSig in this step.
        input_scripts = [bytes.fromhex("1976a914") + pubkey.pubkey_hash + bytes.fromhex("88ac") 
                         for pubkey in pubkeys_data]
        ptx_for_inputs = [
            [   tx_to_sign[:4],                 # Tx version
                bytes.fromhex("0101"),          # Input_count||TrustedInput marker byte
                bytes([len(trusted_input)]),
                trusted_input,
                input_script,
                input_sequence
            ] for trusted_input, input_script, input_sequence in zip(trusted_inputs, input_scripts, input_sequences)
        ]

        ptx_chunks_lengths = [
            [
                5,                              # len(version||input_count) - segwit flag+version not sent
                1 + 1 + len(trusted_input) + 1, # len(trusted_input_marker||len(trusted_input)||trusted_input||scriptSig_len == 0x19)
                -1                              # get len(scripSig) from last byte of previous chunk + len(input_sequence)
            ] for trusted_input in trusted_inputs
        ]

        # Hash & sign each input individually
        for ptx_for_input, ptx_chunks_len, output_path in zip(ptx_for_inputs, ptx_chunks_lengths, output_paths):
            # 3.1 Send pseudo-tx w/ sigScript
            btc.untrustedTxInputHashStart(
                p1="00",
                p2="80",        # to continue previously started tx hash
                data=reduce(lambda x,y: x+y, ptx_for_input),
                chunks_len=ptx_chunks_len
            )
            print("    Final hash OK")

            # 3.2 Sign tx at last. Param is:
            #       Num_derivs||Dest output path||User validation code length (0x00)||tx locktime||sigHashType(always 0x01)
            print("\n--* Untrusted Transaction Hash Sign")
            tx_to_sign_data = output_path   \
                + bytes.fromhex("00")       \
                + tx_to_sign[-4:]           \
                + bytes.fromhex("01")

            response = btc.untrustedHashSign(
                data = tx_to_sign_data
            )
            self.check_signature(response)  # Check sig format only
            # self.check_signature(response, expected_der_sig)  # Can't test sig value as it depends on signing device seed
            print("    Signature OK\n")


    @pytest.mark.parametrize("test_data", [test12_data])
    def test_sign_tx_with_multiple_segwit_inputs(self, test_data: TxData):
        """
        Submit segwit input as is, without encapsulating them into a TrustedInput first.
        Signature obtained should be the same as for if TrustedInputs were used.
        """
        # Start test
        tx_to_sign = test_data.tx_to_sign
        utxos = test_data.utxos
        output_paths = test_data.output_paths
        change_path = test_data.change_path
        expected_der_sig = test_data.expected_sig

        btc = DeviceAppBtc()

        # 1.0 Get public keys for output paths & compute their hashes
        print("\n--* Get Wallet Public Key - for each tx output path")
        wpk_responses = [btc.getWalletPublicKey(output_path) for output_path in output_paths]
        print("    OK")
        pubkeys_data = [self.split_pubkey_data(data) for data in wpk_responses]
        for pubkey in pubkeys_data:
            print(pubkey)

        # 2.1 Construct a pseudo-tx without input script, to be hashed 1st. The original segwit input 
        #     is used as is, prefixed with the segwit input marker byte (0x02).
        print("\n--* Untrusted Transaction Input Hash Start - Hash tx to sign first w/ all inputs having a null script length")
        segwit_inputs = [   # Format is: prevout_hash||prevout_index||prevout_amount
            tx_to_sign[7:7+32+4] + utxos[0][104:104+8],     # 104 = output #1 offset in 1st utxo, ugly hardcoding when all info is in tx :-(
            tx_to_sign[71:71+32+4] + utxos[1][136:136+8]    # 136 = output #0 offset in 2nd utxo
        ]
        input_sequences = [tx_to_sign[67:67+4], tx_to_sign[131:131+4]]
        ptx_to_hash_part1 = [tx_to_sign[:7]]
        for segwit_input, input_sequence in zip(segwit_inputs, input_sequences):
            ptx_to_hash_part1.extend([
                bytes.fromhex("02"),            # segwit input marker byte
                segwit_input,
                bytes.fromhex("00"),            # Input script length = 0 (no sigScript)
                input_sequence
            ])
        ptx_to_hash_part1 = reduce(lambda x, y: x+y, ptx_to_hash_part1)     # Get a single bytes object

        ptx_to_hash_part1_chunks_len = [
            (4, 2, 1)                           # len(version||input_count) - skip segwit version+flag bytes
        ]
        for segwit_input in segwit_inputs:
            ptx_to_hash_part1_chunks_len.extend([
                1 + len(segwit_input) + 1,  # len(segwit_input_marker||segwit_input||len(scriptSig) == 0)
                4                           # len(input_sequence)
            ])

        btc.untrustedTxInputHashStart(
            p1="00",
            p2="02",    # /!\ "02" to activate BIP 143 signature (b/c the pseudo-tx 
                        # contains segwit inputs).
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
        ptx_to_hash_part3 = tx_to_sign[135:200]          # output_count||repeated(output_amount||scriptPubkey)
        ptx_to_hash_part3_chunks_len = [len(ptx_to_hash_part3)]

        response = btc.untrustedTxInputHashFinalize(
            p1="00",
            data=ptx_to_hash_part3,
            chunks_len=ptx_to_hash_part3_chunks_len
        )
        assert response == bytes.fromhex("0000")
        print("    OK")
        # We're done w/ the hashing of the pseudo-tx with all inputs w/o scriptSig.

        # 3. Sign each input individually. Because inputs are true segwit, hash each input with its scriptSig 
        #    and sequence individually, each in a pseudo-tx w/o output_count, outputs nor locktime. 
        print("\n--* Untrusted Transaction Input Hash Start, step 2 - Hash again each input individually (2)")
        # Inputs are P2WPKH, so use 0x1976a914{20-byte-pubkey-hash}88ac as scriptSig in this step.
        input_scripts = [bytes.fromhex("1976a914") + pubkey.pubkey_hash + bytes.fromhex("88ac") 
                         for pubkey in pubkeys_data]
        ptx_for_inputs = [
            [   tx_to_sign[:4],                 # Tx version
                bytes.fromhex("0102"),          # input_count||segwit input marker byte
                segwit_input,
                input_script,
                input_sequence
            ] for trusted_input, input_script, input_sequence in zip(segwit_inputs, input_scripts, input_sequences)
        ]

        ptx_chunks_lengths = [
            [
                5,                  # len(version||input_count) - segwit flag+version not sent
                1 + len(segwit_input) + 1,  # len(segwit_input_marker||segwit_input||scriptSig_len == 0x19)
                -1                          # get len(scripSig) from last byte of previous chunk + len(input_sequence)
            ] for segwit_input in segwit_inputs
        ]

        # Hash & sign each input individually
        for ptx_for_input, ptx_chunks_len, output_path in zip(ptx_for_inputs, ptx_chunks_lengths, output_paths):
            # 3.1 Send pseudo-tx w/ sigScript
            btc.untrustedTxInputHashStart(
                p1="00",
                p2="80",        # to continue previously started tx hash
                data=reduce(lambda x,y: x+y, ptx_for_input),
                chunks_len=ptx_chunks_len
            )
            print("    Final hash OK")

            # 3.2 Sign tx at last. Param is:
            #       Num_derivs||Dest output path||User validation code length (0x00)||tx locktime||sigHashType(always 0x01)
            print("\n--* Untrusted Transaction Hash Sign")
            tx_to_sign_data = output_path   \
                + bytes.fromhex("00")       \
                + tx_to_sign[-4:]           \
                + bytes.fromhex("01")

            response = btc.untrustedHashSign(
                data = tx_to_sign_data
            )
            self.check_signature(response)  # print only
            # self.check_signature(response, expected_der_sig)
            print("    Signature OK\n")

