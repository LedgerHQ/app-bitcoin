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
        Test signing a segwit btc transaction w/ segwit inputs submitted as TrustedInputs
        """
        # BTC Testnet segwit tx used as a "prevout" tx.
        # txid: # txid: b55f049ff0ac10a60efbc3ee3ececda0bd5aaa53920893a405e0c7e28d8f6b70
        # VO_P2WPKH
        utxos = bytes.fromhex(
            # Version no (4 bytes)
            "01000000"
            # Marker + Flag (optional 2 bytes, 0001 indicates the presence of witness data)
            # /!\ Remove flag for `GetTrustedInput`
            "0001"
            # In-counter (varint 1-9 bytes)
            "01"
            # 1st Previous Transaction hash (32 bytes)
            "38bab7ce202ddd90d34ee680a813e04b89baf757e122929ed7767510158ebde2"
            # 1st Previous Txout-index (4 bytes)
            "00000000"
            # 1st Txin-script length (varint 1-9 bytes)
            "00"
            # /!\ no Txin-script (a.k.a scriptSig) because P2WPKH
            # sequence_no (4 bytes)
            "fdffffff"
            
            # Out-counter (varint 1-9 bytes)
            "02"
            # value #1 in satoshis (8 bytes)
            "50c3000000000000"
            # Txout-script length (varint 1-9 bytes)
            "17"
            # Txout-script (a.k.a scriptPubKey)
            "a914eefe62cdd4867e7145c0e072c3fd406a9601cd5987"
            # value #2 in satoshis (8 bytes)
            "cdae020000000000"
            # Txout-script length (varint 1-9 bytes)
            "16"
            # Txout-script (a.k.a scriptPubKey)
            "0014f2d26abc4515f6d40b7ad608feacc2d63ddcbad8"
            # Witnesses (1 for each input if Marker+Flag=0001)
            # /!\ remove witnesses for `GetTrustedInput`
            "0248"
            "3045022100c12ec14236c032315a49a844cf3e7f6f34f70d00e32a1ea65e3cea"
            "254cfa0a1102207080d761994af9b1a368869549221918d1d11590dc474168c0"
            "e8a107c133d569012102fc6eac4eefb230853ad358dc3eaef837d9380194afa4"
            "d06dc25a78de4a156690"
            # lock_time (4 bytes)
            "00000000"
        )
        utxos_chunks_len = [(4+4, 2, 1), 37, 4, 1, 32, 31, (220+4, 4)]

        # The tx we want to sign, referencing the hash of the prevout segwit tx above 
        # in its input.
        # txid: 8dfeff659950d0d4dd2f16dd1f923af3c5fce415aebe65ff4c322f2b14f07774
        tx_to_sign = bytes.fromhex(
            # Version no (4 bytes)
            "01000000"
            # Marker + Flag (optional 2 bytes, 0001 indicates the presence of witness data)
            "0001"
            # In-counter (varint 1-9 bytes)
            "01"
            # 1st Previous Transaction hash (32 bytes)
            "706b8f8de2c7e005a493089253aa5abda0cdce3eeec3fb0ea610acf09f045fb5"
            # 1st Previous Txout-index (4 bytes)
            "01000000"
            # 1st Txin-script length (varint 1-9 bytes)
            "00"
            # /!\ no Txin-script (a.k.a scriptSig) because P2WPKH
            # sequence_no (4 bytes)
            "fdffffff"
            # Out-counter (varint 1-9 bytes)
            "02"
            # value #1 in satoshis (8 bytes)
            "50c3000000000000"
            # Txout-script length (varint 1-9 bytes)
            "17"
            # Txout-script (a.k.a scriptPubKey)
            "a914c0d141a52cca86ef99005dbf5330afabd3d0116587"
            # value #2 in satoshis (8 bytes)
            "eaea010000000000"
            # Txout-script length (varint 1-9 bytes)
            "17"
            # Txout-script (a.k.a scriptPubKey)
            "a914a358bee7e63850d47f0b755fdd2bc57ed7ffbb6787"
            # Witnesses (1 for each input if Marker+Flag=0001)
            "0247"
            "304402203d40a28aa482a7e41b17f6a3421f666e551b3d803f08dd0ec17ab4b7"
            "f15f0ba202204613b6bce44de69281ccd383e14c94d718ea0cc61544edacce0b"
            "3eb06e1379780121028fa3df72b855e99beb2e576f68db666174bf1235d7c3e7"
            "7803290dda0129f91a"
            # lock_time (4 bytes)
            "00000000"
        )

        btc = DeviceAppBtc()

        # 1. Get trusted inputs (submit prevout tx + output index, same as test above)
        print("\n--* Get Trusted Inputs")
        trusted_input = btc.getTrustedInput(
            data=tx_to_sign[39+4-1:39-1:-1] + utxos,   # Input index to look up must be sent BE before tx
            chunks_len=utxos_chunks_len
        )
        self.check_trusted_input(
            trusted_input, 
            out_index=tx_to_sign[39:39+4], 
            out_amount=utxos[81:81+8],
            out_hash=tx_to_sign[7:7+32]
        )

        # 2.1 Construct a pseudo-tx without input script, to be sent hashed 1st...
        print("\n--* Untrusted Transaction Input Hash Start - Hash tx first w/ all inputs having a null script length")
        ptx_to_hash_part1 = tx_to_sign[:7]          \
                          + bytes.fromhex("01") + bytes([len(trusted_input)]) + trusted_input   \
                          + bytes.fromhex("00")     \
                          + tx_to_sign[44:44+4]
        ptx_to_hash_part1_chunks_len = [
            (4, 2, 1),                       # len(version||input_count) i.e. skip segwit Version+flag bytes
            1 + 1 + len(trusted_input) + 1,  # len(segwit_input_marker||len(trusted_input)||trusted_input||scriptSig_len == 0)
            4                                # len(input_sequence)
        ]

        btc.untrustedTxInputHashStart(
            p1="00",
            p2="02",    # Tx contains segwit inputs encapsulated in TrustedInputs
            data=ptx_to_hash_part1,
            chunks_len=ptx_to_hash_part1_chunks_len)
        print("    OK")

        # 2.2 Finalize the input-centric-, pseudo-tx hash with the remainder of that tx
        # 2.2.1 Start with change address path
        print("\n--* Untrusted Transaction Input Hash Finalize Full - Handle change address")
        ptx_to_hash_part2 = bytes.fromhex(
            "05"                                        # Number of path elements
            "8000003180000001800000000000000100000045") # Bip-32 path for change output
        ptx_to_hash_part2_chunks_len = [1 + ptx_to_hash_part2[0]*4]

        btc.untrustedTxInputHashFinalize(
            p1="ff",            # derive change addr Bip-32 path
            data=ptx_to_hash_part2,
            chunks_len=ptx_to_hash_part2_chunks_len
        )
        print("    OK")

        # 2.2.2 Continue w/ tx to sign outputs & scripts
        print("\n--* Untrusted Transaction Input Hash Finalize Full - COntinue w/ hash of tx output")
        ptx_to_hash_part3 = tx_to_sign[48:-4]          # output_count||repeated(output_amount||scriptPubkey)
        ptx_to_hash_part3_chunks_len = [len(ptx_to_hash_part3)]

        btc.untrustedTxInputHashFinalize(
            p1="00",
            data=ptx_to_hash_part3,
            chunks_len=ptx_to_hash_part3_chunks_len
        )
        print("    OK")
        # We're done w/ the hashing of the pseudo-tx with all inputs w/o scriptSig.

        # 2.3. Now hash each input with its scriptSig and sequence individually (no scriptSig in that tx's inputs), 
        #      each in a pseudo-tx w/o output_count, outputs nor locktime
        print("\n--* Untrusted Transaction Input Hash Start, step 2 - Hash again each input individually (only 1)")
        ptx2_for_input1 = tx_to_sign[:7]            \
                          + bytes.fromhex("01") + bytes([len(trusted_input)]) + trusted_input   \
                          + bytes.fromhex("00")     \
                          + tx_to_sign[44:44+4]

        ptx2_for_input1_chunks_len = [
            (4, 2, 1),                      # len(version||input_count) i.e. skip segwit version+flag bytes
            1 + 1 + len(trusted_input) + 1, # len(trusted_input_marker||len(trusted_input)||trusted_input||scriptSig_len == 0)
            1                               # get len(scripSig) from last byte of previous chunk (no scriptSig) + input_sequence
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
            "80000031800000008000000000000000000001f6"  # Bip-32 path for inputs
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
        # Amount of the 1st output of a segwit tx
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
