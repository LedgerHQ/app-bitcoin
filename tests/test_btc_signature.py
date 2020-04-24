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
from helpers.basetest import BaseTestBtc
from helpers.deviceappbtc import DeviceAppBtc, BTC_P1, BTC_P2


class TestBtcTxSignature(BaseTestBtc):

    def test_submit_native_segwit_btc_transaction(self) -> None:
        """
        Test signing a btc transaction w/ segwit inputs submitted as TrustedInputs
        """
        # BTC Testnet segwit tx used as a "prevout" tx.
        # txid: 2CE0F1697564D5DAA5AFDB778E32782CC95443D9A6E39F39519991094DEF8753
        # VO_P2WPKH
        utxos = bytes.fromhex(
            # Version no (4 bytes)
            "02000000"
            # Marker + Flag (optional 2 bytes, 0001 indicates the presence of witness data)
            # /!\ Remove flag for `GetTrustedInput`
            "0001"
            # In-counter (varint 1-9 bytes)
            "02"
            # 1st Previous Transaction hash (32 bytes)
            "daf4d7b97a62dd9933bd6977b5da9a3edb7c2d853678c9932108f1eb4d27b7a9"
            # 1st Previous Txout-index (4 bytes)
            "00000000"
            # 1st Txin-script length (varint 1-9 bytes)
            "00"
            # /!\ no Txin-script (a.k.a scriptSig) because P2WPKH
            # sequence_no (4 bytes)
            "fdffffff"
            # 2nd Previous Transaction hash (32 bytes)
            "daf4d7b97a62dd9933bd6977b5da9a3edb7c2d853678c9932108f1eb4d27b7a9"
            # 2nd Previous Txout-index (4 bytes)
            "01000000"
            # 2nd Tx-in script length (varint 1-9 bytes)
            "00"
            # /!\ no Txin-script (a.k.a scriptSig) because P2WPKH
            # sequence_no (4 bytes)
            "fdffffff"
            # Out-counter (varint 1-9 bytes)
            "01"
            # value in satoshis (8 bytes)
            "01410f0000000000"  # 999681 satoshis = 0,00999681 BTC
            # Txout-script length (varint 1-9 bytes)
            "16"  # 22
            # Txout-script (a.k.a scriptPubKey)
            "0014e4d3a1ec51102902f6bbede1318047880c9c7680"
            # Witnesses (1 for each input if Marker+Flag=0001)
            # /!\ remove witnesses for `GetTrustedInput`
            "0247"
            "3044""0220""495838c36533616d8cbd6474842459596f4f312dce5483fe650791c8"
            "2e17221c""0220""0660520a2584144915efa8519a72819091e5ed78c52689b24235"
            "182f17d96302""01""2102""ddf4af49ff0eae1d507cc50c86f903cd6aa0395f323975"
            "9c440ea67556a3b91b"
            "0247"
            "3044""0220""0090c2507517abc7a9cb32452aabc8d1c8a0aee75ce63618ccd90154"
            "2415f2db""0220""5bb1d22cb6e8173e91dc82780481ea55867b8e753c35424da664"
            "f1d2662ecb13""01""2102""54c54648226a45dd2ad79f736ebf7d5f0fc03b6f8f0e6d"
            "4a61df4e531aaca431"
            # lock_time (4 bytes)
            "a7011900"
        )

        # The tx we want to sign, referencing the hash of the prevout segwit tx above 
        # in its input.
        # 
        tx_to_sign = bytes.fromhex(
            # Version no (4 bytes)
            "02000000"
            # In-counter (varint 1-9 bytes)
            "01"
            # /!\ Input+index of prevout segwit tx will be replaced by `result from GetTrustedInput
            # # Previous Transaction hash (32 bytes)
            "2CE0F1697564D5DAA5AFDB778E32782CC95443D9A6E39F39519991094DEF8753"
            # Previous Txout-index (4 bytes)
            "00000000"
            # Txin-script length (varint 1-9 bytes)
            "19"  # (25 bytes)
            # Txin-script (a.k.a. scriptSig)
            "76a914e4d3a1ec51102902f6bbede1318047880c9c768088ac"
            # sequence_no (4 bytes)
            "fdffffff"
            # Out-counter (varint 1-9 bytes)
            "02"
            # 1st valuein satoshis (8 bytes)
            "1027000000000000"  # 10000 satoshis = 0.0001 BTC
            # 1st Txout-script length (varint 1-9 bytes)
            "16"  # 22
            # 1st Txout-script (a.k.a. scriptPubKey)
            "0014161d283ebbe0e6bc3d90f4c456f75221e1b3ca0f"
            # 2nd value in satoshis (8 bytes)
            "64190f0000000000"  # 989540 satoshis = 0,0098954 BTC
            # 2nd Txout-script length (varint 1-9 bytes)
            "16"  # 22
            # 2nd Txout-script (a.k.a. scriptPubKey)
            "00144c5133c242683d33c61c4964611d82dcfe0d7a9a"
            # lock_time (4 bytes)
            "a7011900"
        )

        btc = DeviceAppBtc()

        # 1. Get trusted inputs (submit prevout tx + output index, same as test above)
        print("\n--* Get Trusted Inputs")
        trusted_input = btc.getTrustedInput(
            data=tx_to_sign[37+4-1:37-1:-1] + utxos,   # Index prefix must be passed BE
            chunks_len=utxos_chunks_len
        )
        utxos_chunks_len = [(4+4, 2, 1), 37, 4, 37, 4, 1, 31, (335+4, 4)]

        self.check_trusted_input(
            trusted_input, 
            out_index=tx_to_sign[37:37+4], 
            out_amount=utxos[90:90+8],
            out_hash=tx_to_sign[5:5+32]
        )

        # # 2. Send Untrusted Transaction Input Hash Start (up to outputs count, excluded)
        # # Insert trusted input in the tx to sign in place of inputs
        # print("\n--* Untrusted Transaction Input Hash Start")
        # tx_to_sign_part1 = bytes.fromhex(   # 1st part goes up to input sequence 
        #     tx_to_sign[:5].hex()                        \
        #     + "01" + bytes([len(trusted_input)]).hex()  \
        #     + trusted_input.hex()                       \
        #     + tx_to_sign[41:41 + 1 + tx_to_sign[41] + 4].hex()
        # )

        # tx_part1_chunks_len = [
        #     5,                          # len(version||input_count)
        #     1+1+len(trusted_input)+1,   # len(trustedInput marker "01"||len(trusted_input)||trusted_input||scriptSig_len)
        #     -1                          # get len(scriptSig) from previous chunk (0x19=25), add len(input_script_sequence) 
        # ]
        # btc.untrustedTxInputHashStart(
        #     p1="00",
        #     # p2="00",    # Tx contains Trusted inputs in place of inputs from a segwit tx.
        #     p2="02",    # Tx contains segwit inputs (actually Trusted inputs from segwit inputs)
        #     data=tx_to_sign_part1,
        #     chunks_len=tx_part1_chunks_len)
        # print("    OK")

        # # 3. Send Untrusted Transaction Input Hash Finalize (from outputs_count up to
        # #    tx locktime, excluded). No chunks required here.
        # print("\n--* Untrusted Transaction Input Hash Finalize Full")
        # tx_to_sign_part2 = tx_to_sign[71:-4]
        # response = btc.untrustedTxInputHashFinalize(
        #     p1="00",
        #     data=tx_to_sign_part2)
        # print(f"    OK, Response = {response.hex()}")
        # assert response.hex() == "0000"

        # #4. Send Untrusted Hash Sign (w/ random BIP32 path, RFU (00) byte, BE-encoded 
        # #   locktime & sigHashType = 01)
        # print("\n--* Untrusted Transaction Sign")
        # in_data = bytes.fromhex("03"+"80000000"+"00000000"+"00000000")  \
        #         + bytes(1)                                              \
        #         + bytes(reversed(tx_to_sign[-4:]))                      \
        #         + bytes.fromhex("01")

        # response = btc.untrustedHashSign(data=in_data)
        # print(f"    OK, (R,S) = {response[:-1].hex()}")
        # print(f"    sigHasType = {bytes([response[-1]]).hex()}")

        # 2.1 Construct a pseudo-tx without input script, to be sent hashed 1st...
        print("\n--* Untrusted Transaction Input Hash Start - Hash tx first w/ all inputs having a null script length")
        ptx_to_hash_part1 = tx_to_sign[:5]              \
                          + bytes.fromhex("01")         \
                          + bytes([len(trusted_input)]) \
                          + trusted_input               \
                          + bytes.fromhex("00")         \
                          + tx_to_sign[67:67+4]
        ptx_to_hash_part1_chunks_len = [
            5,                              # len(version||input_count)
            1 + 1 + len(trusted_input) + 1, # len(segwit_input_marker||len(trusted_input)||trusted_input||len(scriptSig) == 0)
            4                               # len(input_sequence)
        ]

        btc.untrustedTxInputHashStart(
            p1="00",
            p2="02",    # Tx contains segwit inputs  encapsulated in TrustedInputs
            data=ptx_to_hash_part1,
            chunks_len=ptx_to_hash_part1_chunks_len)
        print("    OK")

        # 2.2 Finalize the input-centric-, pseudo-tx hash with the remainder of that tx
        # 2.2.1 Start with change address path
        print("\n--* Untrusted Transaction Input Hash Finalize Full - Handle change address")
        ptx_to_hash_part2 = bytes.fromhex(
            "05"                                        # Number of path elements
            "8000002C80000001800000000000000100000045") # Change output on 44'/1'/0'/1/69
        ptx_to_hash_part2_chunks_len = [1 + ptx_to_hash_part2[0]*4]

        btc.untrustedTxInputHashFinalize(
            p1="ff",            # derive change addr Bip-32 path
            data=ptx_to_hash_part2,
            chunks_len=ptx_to_hash_part2_chunks_len
        )
        print("    OK")

        # 2.2.2 Continue w/ tx to sign outputs & scripts
        print("\n--* Untrusted Transaction Input Hash Finalize Full - Continue w/ hash of tx output")
        ptx_to_hash_part3 = tx_to_sign[71:-4]          # output_count||repeated(output_amount||scriptPubkey)
        ptx_to_hash_part3_chunks_len = [len(ptx_to_hash_part3)]

        btc.untrustedTxInputHashFinalize(
            p1="00",
            data=ptx_to_hash_part3,
            chunks_len=ptx_to_hash_part3_chunks_len
        )
        print("    OK")
        # We're done w/ the hashing of the pseudo-tx with all inputs w/o scriptSig.

        # 2.3. Now hash each input with its scriptSig and sequence individually, each in a pseudo-tx 
        #      w/o output_count, outputs nor locktime
        print("\n--* Untrusted Transaction Input Hash Start, step 2 - Hash again each input individually (only 1)")
        ptx_for_input1 = tx_to_sign[:5]                             \
                        + bytes.fromhex("01")                       \
                        + bytes([len(trusted_input)])               \
                        + trusted_input                             \
                        + tx_to_sign[41:41 + tx_to_sign[41] + 1]    \
                        + tx_to_sign[67:67+4]
        ptx_for_input1_chunks_len = [
            5,                              # len(version||input_count)
            1 + 1 + len(trusted_input) + 1, # len(segwit_input_marker||len(trusted_input)||trusted_input||scriptSig_len == 0x19)
            -1,                             # get len(scripSig) from last byte of previous chunk & send scriptSig + input_sequence
            1                               # len(output_count == 0, no outputs)
        ]

        btc.untrustedTxInputHashStart(
            p1="00",
            p2="80",            # Continue previously started tx hash
            data=ptx_for_input1,
            chunks_len=ptx_for_input1_chunks_len
        )
        print("    OK")

        # 3. Sign tx at last
        print("\n--* untrusted Transaction Sign")
        tx_to_sign_data = bytes.fromhex(
            "05"                                        # Number of path elements
            "8000002C80000000800000000000000000000001"  # Dest output on 44'/0'/0'/1/502
            "00"                                        # RFU byte
            "00000000"                                  # Locktime
            "01"                                        # sigHashType = 0x01
        )

        response = btc.untrustedHashSign(
            data = tx_to_sign_data
        )        
        print(f"    OK, (R,S) = {response[:-1].hex()}")
        print(f"    sigHashType = {bytes([response[-1]]).hex()}")


    # @pytest.mark.skip(reason="Can't seem to work out how to split the tx data to send correctly to the app."
    #                          "Warning screen is shown however. Comment decorator to run.")
    def test_submit_true_segwit_tx_shows_warning(self) -> None:
        """Test signing a btc transaction w/ segwit inputs submitted as such shows warning screen
        
        This mimics the behavior of a wallet that has not yet been updated to prevent  
        signing tx with unverified segwit inputs .

        BTC Testnet segwit tx used as a "prevout" tx.
        txid: 5387ef4d09919951399fe3a6d94354c92c78328e77dbafa5dad5647569f1e02c
        VO_P2WPKH
        """
        # Amount of the 1st output of a segwit tx utxo
        segwit_prevout_0_amount = bytes.fromhex("40420f0000000000") # 0.1 BTC

        # The tx we want to sign, referencing the hash of a prevout segwit tx in its input.
        tx_to_sign = bytes.fromhex(
            # Version no (4 bytes)
            "02000000"
            # In-counter (varint 1-9 bytes)
            "01"
            # /!\ Input+index of prevout segwit tx will be replaced by `result from GetTrustedInput
            # # Previous Transaction hash (32 bytes)
            "2CE0F1697564D5DAA5AFDB778E32782CC95443D9A6E39F39519991094DEF8753"  # <- Hash of a segwit tx
            # Previous Txout-index (4 bytes)
            "00000000"
            # Txin-script length (varint 1-9 bytes)
            "19"  # (25 bytes)
            # Txin-script (a.k.a. scriptSig)
            "76a914e4d3a1ec51102902f6bbede1318047880c9c768088ac"
            # sequence_no (4 bytes)
            "fdffffff"

            # Out-counter (varint 1-9 bytes)
            "02"
            # 1st valuein satoshis (8 bytes)
            "1027000000000000"  # 10000 satoshis = 0.0001 BTC
            # 1st Txout-script length (varint 1-9 bytes)
            "16"  # 22
            # 1st Txout-script (a.k.a. scriptPubKey)
            "0014161d283ebbe0e6bc3d90f4c456f75221e1b3ca0f"
            # 2nd value in satoshis (8 bytes)
            "64190f0000000000"  # 989540 satoshis = 0,0989540 BTC
            # 2nd Txout-script length (varint 1-9 bytes)
            "16"  # 22
            # 2nd Txout-script (a.k.a. scriptPubKey)
            "00144c5133c242683d33c61c4964611d82dcfe0d7a9a"
            # lock_time (4 bytes)
            "a7011900"
        )

        btc = DeviceAppBtc()

        # Send Untrusted Transaction Input Hash Start without performing a GetTrustedInput 
        # first (as would do a wallet not yet updated). 
        # From app doc "btc.asc": 
        #   "When using Segregated Witness Inputs the signing mechanism differs 
        #    slightly:
        #    - The transaction shall be processed first with all inputs having a null script length 
        #    - Then each input to sign shall be processed as part of a pseudo transaction with a 
        #      single input and no outputs."
        
        # 1.1 Construct a pseudo-tx without input script, to be sent hashed 1st...
        print("\n--* Untrusted Transaction Input Hash Start - Hash tx first w/ all inputs having a null script length")
        ptx_to_hash_part1 = tx_to_sign[:5]          \
                          + bytes.fromhex("02")     \
                          + tx_to_sign[5:41]        \
                          + segwit_prevout_0_amount \
                          + bytes.fromhex("00")     \
                          + tx_to_sign[67:71]
        ptx_to_hash_part1_chunks_len = [
            5,                  # len(version||input_count)
            1+ 32 + 4 + 8 + 1,  # len(segwit_input_marker||input_hash||prevout_index||prevou_amount||scriptSig_len == 0)
            4                   # len(input_sequence)
        ]

        btc.untrustedTxInputHashStart(
            p1="00",
            p2="02",    # Tx contains segwit inputs, this value should show a warning on 
                        # the device but operation should be allowed to proceed
            data=ptx_to_hash_part1,
            chunks_len=ptx_to_hash_part1_chunks_len)
        print("    OK")

        # 1.2 Finalize the input-centric-, pseudo-tx hash with the remainder of that tx
        # 1.2.1 Start with change address path
        print("\n--* Untrusted Transaction Input Hash Finalize Full - Handle change address")
        ptx_to_hash_part2 = bytes.fromhex(
            "05"                                        # Number of path elements
            "8000003180000001800000000000000100000045") # Bip-32 path for change output
        ptx_to_hash_part2_chunks_len = [1 + 5*4]

        btc.untrustedTxInputHashFinalize(
            p1="ff",            # derive change addr Bip-32 path
            data=ptx_to_hash_part2,
            chunks_len=ptx_to_hash_part2_chunks_len
        )
        print("    OK")

        # 1.2.2 Continue w/ tx to sign outputs & scripts
        print("\n--* Untrusted Transaction Input Hash Finalize Full - COntinue w/ hash of tx output")
        ptx_to_hash_part3 = tx_to_sign[71:-4]          # output_count||repeated(output_amount||scriptPubkey)
        ptx_to_hash_part3_chunks_len = [len(ptx_to_hash_part3)]

        btc.untrustedTxInputHashFinalize(
            p1="00",
            data=ptx_to_hash_part3,
            chunks_len=ptx_to_hash_part3_chunks_len
        )
        print("    OK")
        # We're done w/ the hashing of the pseudo-tx with all inputs w/o scriptSig.

        # 2. Now hash each input with its scriptSig individually, each in a pseudo-tx w/o outputs
        print("\n--* Untrusted Transaction Input Hash Start, step 2 - Hash again each input individually (only 1)")
        ptx2_for_input1 = tx_to_sign[:5]            \
                        + bytes.fromhex("02")       \
                        + tx_to_sign[5:41]          \
                        + segwit_prevout_0_amount   \
                        + tx_to_sign[41:71]
        ptx2_for_input1_chunks_len = [
            5,                          # len(version||input_count)
            1 + 32 + 4 + 8 + 1,         # len(segwit_input_marker||input_hash||prevout_index||prevout_amount||scriptSig_len)
            -1                          # get len(scripSig) from last byte of previous chunk & send scriptSig + input_sequence
        ]

        btc.untrustedTxInputHashStart(
            p1="00",
            p2="80",            # Continue previously started tx hash
            data=ptx2_for_input1,
            chunks_len=ptx2_for_input1_chunks_len
        )
        print("    OK")

        # 3. Sign tx at last
        print("\n--* untrusted Transaction Sign")
        tx_to_sign_data = bytes.fromhex(
            "05"                                        # Number of path elements
            "80000031800000018000000000000000000001f6"  # Bip-32 path for change output
            "00"                                        # RFU byte
            "00000000"                                  # Locktime
            "01"                                        # sigHashType = 0x01
        )

        response = btc.untrustedHashSign(
            data = tx_to_sign_data
        )        
        print(f"    OK, (R,S) = {response[:-1].hex()}")
        print(f"    sigHashType = {bytes([response[-1]]).hex()}")
