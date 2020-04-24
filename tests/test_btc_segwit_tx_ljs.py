import pytest
from typing import Optional, List
from helpers.basetest import BaseTestBtc
from helpers.deviceappbtc import DeviceAppBtc

class TestBtcSegwitTxLjs(BaseTestBtc):

    def test_get_trusted_inputs_from_segwit_tx(self):
        utxo = bytes.fromhex(
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
            # /!\ remove witnesses for `GetTrustedInput`
            "0247"
            "304402206e54747dabff52f5c88230a3036125323e21c6c950719f671332"
            "cdd0305620a302204a2f2a6474f155a316505e2224eeab6391d5e6daf22a"
            "cd76728bf74bc0b48e1a0121033c88f6ef44902190f859e4a6df23ecff4d"
            "86a2114bd9cf56e4d9b65c68b8121d"
            # lock_time (4 bytes) @offset  @offset 243
            "1f7f1900"
        )
        utxo_chunks_len = [(4+4, 2, 1), 37, -1, 1, 32, 32, (243+4, 4)]  # All "+4" to account for output index prepended
                                                                        # to tx in data parameter of btc.getTrustedInput()
        tx_to_sign = bytes.fromhex(
            # Version
            "01000000"
            # Segwit flag+version
            "0001"
            # Input count
            "01"
            # Prevout hash (txid) @offset 7
            "027a726f8aa4e81a45241099a9820e6cb7d8920a686701ad98000721101fa0aa"
            # Prevout index @offset 39
            "01000000"
            # scriptSig @offset 43
            "17"
            "160014d815dddcf8cf1b820419dcb1206a2a78cfa60320"
            # Input sequence @offset 67
            "ffffff00"
            # Output count @offset 71
            "02"
            # Amount #1 @offset 72
            "e803000000000000"
            # scriptPubkey #1 @offset 80
            "17"
            "a9142406cd1d50d3be6e67c8b72f3e430a1645b0d74287"
            # Amount #2 @offset 104
            "8022000000000000"
            # scriptPubkey #2 @ offset 112
            "17" 
            "a9143ae394774f1348be3a6bc2a55b67e3566d13408987"
            
            # Signed DER-encoded withness from testnet (@offset 136), but on unknown paths 
            # so not useable to verify signature for this test
            "02""47"
             "30""44"
               "02""21"
                 "00a6c0dac43262d4f6aa3bb81d49c1562c564b29b145a098398043d74d8392163d"
               "021f"
                 "4784c070027006911d73d636d646570b752f6ee2c062b1ac156a0c01fd866c"
               "01"
               "210293137bc1a9b7993a1d2a462188efc45d965d135f53746b6b146a3cec99053226"
            # locktime @offset -4
            "00000000"
        )

        output_path = bytes.fromhex("05""80000031""80000001""80000000""00000000""000001f6") # 49'/1'/0'/0/502
        change_path = bytes.fromhex("05""80000031""80000001""80000000""00000001""00000045") # 49'/1'/0'/1/69
        # expected_der_sig = bytes.fromhex(
        #     "30""45"
        #       "02""21" 
        #       # R
        #       "00ec8673325e32ab0a6212be1e8563db135f9826d792550141b93c042ab343da6a"
        #       "02""20"
        #       # S
        #       "7ed313c9269f547dfc273101507057d22d4b496a718c1d132c1c1fb187c9449a"
        #       # sigHashType
        #       "01"
        # )

        # Start test
        btc = DeviceAppBtc()

        # 1. Get trusted inputs (submit prevout tx + output index, same as test above)
        trusted_input = btc.getTrustedInput(
            data=tx_to_sign[39+4-1:39-1:-1]     # out_index in tx_to_sign input must be passed BE as prefix to utxo tx
                + utxo,
            chunks_len=utxo_chunks_len
        )
        self.check_trusted_input(
            trusted_input, 
            out_index=tx_to_sign[39:39+4], 
            out_amount=utxo[104:104+8],         # utxo output #1 is requested in tx to sign input
            out_hash=tx_to_sign[7:7+32]         # prevout hash in tx to sign
        )

        # 2.1 Construct a pseudo-tx without input script, to be hashed 1st. The original segwit input 
        #     being replaced with the previously obtained TrustedInput, it is prefixed it with the marker
        #     byte for TrustedInputs (0x01).
        print("\n--* Untrusted Transaction Input Hash Start - Hash tx to sign first w/ all inputs having a null script length")
        ptx_to_hash_part1 = tx_to_sign[:7]              \
                          + bytes.fromhex("01")         \
                          + bytes([len(trusted_input)]) \
                          + trusted_input               \
                          + bytes.fromhex("00")         \
                          + tx_to_sign[67:67+4]
        ptx_to_hash_part1_chunks_len = [
            (4, 2, 1),                      # len(version||input_count) i.e. skip segwit version+flag bytes
            1 + 1 + len(trusted_input) + 1, # len(trusted_input_marker||len(trusted_input)||trusted_input||len(scriptSig) == 0)
            4                               # len(input_sequence)
        ]

        btc.untrustedTxInputHashStart(
            p1="00",
            p2="02",        # "02" to activate BIP143 signature (b/c pseudo-tx contains segwit inputs encapsulated in TrustedInputs).
            data=ptx_to_hash_part1,
            chunks_len=ptx_to_hash_part1_chunks_len
        )
        print("    OK")

        # 2.2 Finalize the input-centric-, pseudo-tx hash with the remainder of tx
        # 2.2.1 Start with change address path
        print("\n--* Untrusted Transaction Input Hash Finalize Full - Handle change address")
        ptx_to_hash_part2 = change_path
        ptx_to_hash_part2_chunks_len = [1 + ptx_to_hash_part2[0]*4]     # len(num_derivations) + num_derivations*4 bytes

        btc.untrustedTxInputHashFinalize(
            p1="ff",            # derive BIP 32 change address
            data=ptx_to_hash_part2,
            chunks_len=ptx_to_hash_part2_chunks_len
        )
        print("    OK")

        # 2.2.2 Continue w/ tx to sign outputs & scripts
        print("\n--* Untrusted Transaction Input Hash Finalize Full - Continue w/ hash of tx output")
        ptx_to_hash_part3 = tx_to_sign[71:136]          # output_count||repeated(output_amount||scriptPubkey)
        ptx_to_hash_part3_chunks_len = [len(ptx_to_hash_part3)]

        response = btc.untrustedTxInputHashFinalize(
            p1="00",
            data=ptx_to_hash_part3,
            chunks_len=ptx_to_hash_part3_chunks_len
        )
        assert response == bytes.fromhex("0000")
        print("    OK")
        # We're done w/ the hashing of the pseudo-tx with all inputs w/o scriptSig.

        # 2.3. Now hash each input with its scriptSig and sequence individually, each in a pseudo-tx
        #      w/o output_count, outputs nor locktime
        print("\n--* Untrusted Transaction Input Hash Start, step 2 - Hash again each input individually (only 1)")
        ptx_for_input1 = tx_to_sign[:7]                             \
                        + bytes.fromhex("01")                       \
                        + bytes([len(trusted_input)])               \
                        + trusted_input                             \
                        + tx_to_sign[43:43 + tx_to_sign[43] + 1]    \
                        + tx_to_sign[67:67+4]                       \
                        + bytes.fromhex("00")
        ptx_for_input1_chunks_len = [
            (4, 2, 1),                      # len(version||input_count)  i.e. skip segwit version+flag bytes
            1 + 1 + len(trusted_input) + 1, # len(trusted_input_marker||len(trusted_input)||trusted_input||scriptSig_len == 0x19)
            -1                              # get len(scripSig) from last byte of previous chunk & send scriptSig + input_sequence
        ]
        btc.untrustedTxInputHashStart(
            p1="00",
            p2="80",            # Continue previously started tx hash
            data=ptx_for_input1,
            chunks_len=ptx_for_input1_chunks_len
        )
        print("    OK")

        # 3. Sign tx at last. Param is:
        #       Num_derivations||Dest output path||User validation code length (0x00)||tx locktime||sigHashType(always 0x01)
        print("\n--* untrusted Transaction Sign")
        tx_to_sign_data = output_path   \
            + bytes.fromhex("00")       \
            + tx_to_sign[-4:]           \
            + bytes.fromhex("01")

        response = btc.untrustedHashSign(
            data = tx_to_sign_data
        )
        self.check_signature(response)  # print only
        # self.check_signature(response, expected_der_sig)

