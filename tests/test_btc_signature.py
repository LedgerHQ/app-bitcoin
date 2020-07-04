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

# BTC Testnet segwit tx used as a "prevout" tx.
# txid: 2CE0F1697564D5DAA5AFDB778E32782CC95443D9A6E39F39519991094DEF8753
# VO_P2WPKH
utxos = [
    bytes.fromhex(
        # Version no (4 bytes) @offset 0
        "02000000"
        # Segwit Marker + Flag @offset 4
        # /!\ It must be removed from the tx data passed to GetTrustedInput
        "0001"
        # In-counter (varint 1-9 bytes) @offset 6
        "02"
        # 1st Previous Transaction hash (32 bytes) @offset 7
        "daf4d7b97a62dd9933bd6977b5da9a3edb7c2d853678c9932108f1eb4d27b7a9"
        # 1st Previous Txout-index (4 bytes) @offset 39
        "00000000"
        # 1st Txin-script length (varint 1-9 bytes) @offset 43
        "00"
        # /!\ no Txin-script (a.k.a scriptSig) because P2WPKH
        # sequence_no (4 bytes) @offset 44
        "fdffffff"
        # 2nd Previous Transaction hash (32 bytes) @offset 48
        "daf4d7b97a62dd9933bd6977b5da9a3edb7c2d853678c9932108f1eb4d27b7a9"
        # 2nd Previous Txout-index (4 bytes) @offset 80
        "01000000"
        # 2nd Tx-in script length (varint 1-9 bytes) @offset 84
        "00"
        # /!\ no Txin-script (a.k.a scriptSig) because P2WPKH
        # sequence_no (4 bytes) @offset 85
        "fdffffff"
        # Out-counter (varint 1-9 bytes) @offset 89
        "01"
        # value in satoshis (8 bytes) @offset 90
        "01410f0000000000"  # 999681 satoshis = 0,00999681 BTC
        # Txout-script length (varint 1-9 bytes) @offset 98
        "16"  # 22
        # Txout-script (a.k.a scriptPubKey, ) @offset 99
        "0014e4d3a1ec51102902f6bbede1318047880c9c7680"
        # Witnesses (1 for each input if Marker+Flag=0001) @offset 121
        # /!\ They will be removed from the tx data passed to GetTrustedInput
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
        # lock_time (4 bytes) @offset 335
        "a7011900"
    ),
]

# The tx we want to sign, referencing the hash of the prevout segwit tx above 
# in its input.
tx_to_sign = bytes.fromhex(
    # Version no (4 bytes) @offset 0
    "02000000"
    # In-counter (varint 1-9 bytes) @offset 4
    "01"
    # Txid (hash) of prevout segwit tx (32 bytes) @offset 5 
    # /!\ It will be replaced, along with following prevout index 
    #     by the result from GetTrustedInput
    "2CE0F1697564D5DAA5AFDB778E32782CC95443D9A6E39F39519991094DEF8753"
    # Previous Txout-index (4 bytes) @offset 37
    "00000000"
    # scriptSig length (varint 1-9 bytes) @offset 41
    "19"
    # scriptSig (25 bytes) @offset 42
    "76a914e4d3a1ec51102902f6bbede1318047880c9c768088ac"
    # sequence_no (4 bytes) @offset 67
    "fdffffff"
    # Out-counter (varint 1-9 bytes) @offset 71
    "02"
    # 1st value in satoshis (8 bytes) @offset 72
    "1027000000000000"  # 10000 satoshis = 0.0001 BTC
    # 1st scriptPubkey length (varint 1-9 bytes) @offset 80
    "16"
    # 1st scriptPubkey (22 bytes) @offset 81
    "0014161d283ebbe0e6bc3d90f4c456f75221e1b3ca0f"
    # 2nd value in satoshis (8 bytes) @offset 103
    "64190f0000000000"  # 989540 satoshis = 0,0098954 BTC
    # 2nd scriptPubkey length (varint 1-9 bytes)  @offset 104
    "16"
    # 2nd scriptPubkey (22 bytes)  @offset 105
    "00144c5133c242683d33c61c4964611d82dcfe0d7a9a"
    # lock_time (4 bytes) @offset -4
    "a7011900"
)

# Expected signature (except last sigHashType byte) was extracted from raw tx at: 
# https://tbtc.bitaps.com/raw/transaction/a9a7ffabd6629009488546eb1fafd5ae2c3d0008bc4570c20c273e51b2ce5abe 
expected_der_sig = [
    bytes.fromhex(      # for output #1
        "3044"
            "0220" "2cadfbd881f592ea82e69038c7ada8f1ae50919e3be92ad1cd5fcc0bd142b2f5"
            "0220" "646a699b5532fcdf38b196157e216c8808ae7bde5e786b8f3cbf2502d0f14c13" 
        "01"),
]

output_paths = [bytes.fromhex("05""80000054""80000001""80000000""00000000""00000000"),]     # 84'/1'/0'/0/0
change_path = bytes.fromhex("05""80000054""80000001""80000000""00000001""00000001")         # 84'/1'/0'/1/1

test12_data = TxData(
    tx_to_sign=tx_to_sign,
    utxos=utxos,
    output_paths=output_paths,
    change_path=change_path,
    expected_sig=expected_der_sig
)

@pytest.mark.btc
@pytest.mark.manual
class TestBtcTxSignature(BaseTestBtc):

    @pytest.mark.parametrize("test_data", [test12_data])
    def test_submit_trusted_segwit_input_btc_transaction(self, test_data: TxData) -> None:
        """
        Test signing a btc transaction w/ segwit inputs submitted as TrustedInputs

        From app doc "btc.asc": 
          "When using Segregated Witness Inputs the signing mechanism differs 
           slightly:
           - The transaction shall be processed first with all inputs having a null script length 
           - Then each input to sign shall be processed as part of a pseudo transaction with a 
             single input and no outputs."

        - Attention: Seed to initialize device with is:
            "palm hammer feel bulk sting broccoli six stay ramp develop hip pony play"
            "never tourist phrase wrist prepare ladder egg lottery aware dinner express"
        """
        # Start test
        tx_to_sign = test_data.tx_to_sign
        utxos = test_data.utxos
        output_paths = test_data.output_paths
        change_path = test_data.change_path
        expected_der_sig = test_data.expected_sig

        btc = DeviceAppBtc()

        # 1. Get trusted inputs (submit prevout tx + output index)
        print("\n--* Get Trusted Inputs")
        # Data to submit is: prevout_index (BE)||utxo tx
        output_indexes = [
            tx_to_sign[37+4-1:37-1:-1],
        ]
        input_data = [out_idx + utxo for out_idx, utxo in zip(output_indexes, utxos)]
        utxos_chunks_len = [
            [
                (4+4, 2, 1),    # len(prevout_index (BE)||version||input_count) - (skip 2-byte segwit Marker+flags)
                37,             # len(prevout_hash #1||prevout_index #1||len(scriptSig #1) = 0x00)
                4,              # len(input_sequence)
                37,             # len(prevout_hash #2||prevout_index #2||len(scriptSig #2) = 0x00)
                4,              # len(input_sequence)
                1,              # len(output_count)
                31,             # len(output_value||len(scriptPubkey)||scriptPubkey)
                (335+4, 4)      # len(locktime) - skip witness data
            ],
        ]
        trusted_inputs = [
            btc.getTrustedInput(
                data=input_datum,
                chunks_len=chunks_len
            )
            for (input_datum, chunks_len) in zip(input_data, utxos_chunks_len)
        ]
        print("    OK")

        out_amounts = [utxos[0][90:90+8]]
        prevout_hashes = [tx_to_sign[5:5+32]]
        for trusted_input, out_idx, out_amount, prevout_hash in zip(
            trusted_inputs, output_indexes, out_amounts, prevout_hashes
            ):
            self.check_trusted_input(
                trusted_input, 
                out_index=out_idx[::-1],    # LE for comparison w/ out_idx in trusted_input
                out_amount=out_amount,      # utxo output #1 is requested in tx to sign input
                out_hash=prevout_hash       # prevout hash in tx to sign
            )

        # Not needed for this tx that already contains a P2WPKH scriptSig in its input, see step 3.
        # # 2.0 Get public keys for output paths & compute their hashes
        # print("\n--* Get Wallet Public Key - for each tx output path")
        # wpk_responses = [btc.getWalletPublicKey(output_path) for output_path in output_paths]
        # print("    OK")
        # pubkeys_data = [self.split_pubkey_data(data) for data in wpk_responses]
        # for pubkey in pubkeys_data:
        #     print(pubkey)

        # 2.1 Construct a pseudo-tx without input script, to be hashed 1st. The original segwit input 
        #     being replaced with the previously obtained TrustedInput, it is prefixed it with the marker
        #     byte for TrustedInputs (0x01) that the BTC app expects to check the Trusted Input's HMAC.
        print("\n--* Untrusted Transaction Input Hash Start - Hash tx to sign first w/ all inputs having a null script length")
        input_sequences = [tx_to_sign[67:67+4]]
        ptx_to_hash_part1 = [tx_to_sign[:5]]
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
            5,                              # len(version||input_count)
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
        ptx_to_hash_part3 = tx_to_sign[71:-4]          # output_count||repeated(output_amount||scriptPubkey)
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
        
        # # Inputs are P2WPKH, so use 0x1976a914{20-byte-pubkey-hash}88ac as scriptSig in this step.
        input_scripts = [tx_to_sign[41:41 + tx_to_sign[41] + 1]]    # tx already contains the correct input script for P2WPKH
        # input_scripts = [bytes.fromhex("1976a914") + pubkey.pubkey_hash + bytes.fromhex("88ac") 
        #                  for pubkey in pubkeys_data]

        # Inputs scripts in the tx to sign are already w/ the correct form 
        ptx_for_inputs = [
            [   tx_to_sign[:5],                         # Tx version||Input_count
                bytes.fromhex("01"),                    # TrustedInput marker
                bytes([len(trusted_input)]),
                trusted_input,           
                input_script,
                input_sequence
            ] for trusted_input, input_script, input_sequence in zip(trusted_inputs, input_scripts, input_sequences)
        ]

        ptx_chunks_lengths = [
            [
                5,                              # len(version||input_count)
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
            self.check_signature(response)
            #self.check_signature(response, expected_der_sig)
            print("    Signature OK\n")


    @pytest.mark.parametrize("test_data", [test12_data])
    def test_sign_tx_with_untrusted_segwit_input_shows_warning(self, test_data: TxData):
        """
        Submit segwit inputs as is, without encapsulating them into a TrustedInput first.
        
        Signature obtained should be the same as for TrustedInputs were used, and device
        should display a warning screen.
        """
        # Start test
        tx_to_sign = test_data.tx_to_sign
        utxos = test_data.utxos
        output_paths = test_data.output_paths
        change_path = test_data.change_path
        expected_der_sig = test_data.expected_sig

        btc = DeviceAppBtc()

        # Not needed for this tx that already contains a P2WPKH scriptSig in its input, see step 3.
        # # 1. Get public keys for output paths & compute their hashes
        # print("\n--* Get Wallet Public Key - for each tx output path")
        # wpk_responses = [btc.getWalletPublicKey(output_path) for output_path in output_paths]
        # print("    OK")
        # pubkeys_data = [self.split_pubkey_data(data) for data in wpk_responses]
        # for pubkey in pubkeys_data:
        #     print(pubkey)

        # 2.1 Construct a pseudo-tx without input script, to be hashed 1st. The original segwit input 
        #     is used as is, prefixed with the segwit input marker byte (0x02).
        print("\n--* Untrusted Transaction Input Hash Start - Hash tx to sign first w/ all inputs having a null script length")
        segwit_inputs = [   # Format is: prevout_hash||prevout_index||prevout_amount
            tx_to_sign[5:5+32+4] + utxos[0][90:90+8]    # 104 = output #0 offset in utxo
        ]
        input_sequences = [tx_to_sign[67:67+4]]
        ptx_to_hash_part1 = [tx_to_sign[:5]]
        for segwit_input, input_sequence in zip(segwit_inputs, input_sequences):
            ptx_to_hash_part1.extend([
                bytes.fromhex("02"),        # segwit input marker byte
                segwit_input,
                bytes.fromhex("00"),        # Input script length = 0 (no sigScript)
                input_sequence
            ])
        ptx_to_hash_part1 = reduce(lambda x, y: x+y, ptx_to_hash_part1)     # Get a single bytes object

        ptx_to_hash_part1_chunks_len = [
            5                               # len(version||input_count) - skip segwit version+flag bytes
        ]
        for segwit_input in segwit_inputs:
            ptx_to_hash_part1_chunks_len.extend([
                1 + len(segwit_input) + 1,  # len(segwit_input_marker||segwit_input||len(scriptSig) == 0)
                4                           # len(input_sequence)
            ])

        btc.untrustedTxInputHashStart(
            p1="00",
            p2="02",    # /!\ "02" to activate BIP 143 signature (b/c the pseudo-tx 
                        # contains a segwit input).
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
        ptx_to_hash_part3 = tx_to_sign[71:-4]          # output_count||repeated(output_amount||scriptPubkey)
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
        input_scripts = [tx_to_sign[41:41 + tx_to_sign[41] + 1]]   # script is already in correct form inside tx
        # input_scripts = [bytes.fromhex("1976a914") + pubkey.pubkey_hash + bytes.fromhex("88ac") 
        #                  for pubkey in pubkeys_data]
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
            #self.check_signature(response, expected_der_sig)
            print("    Signature OK\n")

