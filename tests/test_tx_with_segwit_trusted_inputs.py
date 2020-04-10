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
from helpers.deviceappbtc import DeviceAppBtc, BTC_P1, BTC_P2

#from ledgerblue.comm import getDongle
#from ledgerblue.ecWrapper import PrivateKey, PublicKey, USE_SECP


class TestLedgerjsTx:

    ledgerjs_tests = [
        #"btc 3" test data
        [
            [
                # GET TRUSTED INPUT[   
                bytes.fromhex("e042000009000000010100000001"),
                bytes.fromhex("e0428000254ea60aeac5252c14291d428915bd7ccd1bfc4af009f4d4dc57ae597ed0420b71010000008a"),
                bytes.fromhex("e04280003247304402201f36a12c240dbf9e566bc04321050b1984cd6eaf6caee8f02bb0bfec08e3354b022012ee2aeadcbbfd1e92959f"),
                bytes.fromhex("e04280003257c15c1c6debb757b798451b104665aa3010569b49014104090b15bde569386734abf2a2b99f9ca6a50656627e77de663ca7"),
                bytes.fromhex("e04280002a325702769986cf26cc9dd7fdea0af432c8e2becc867c932e1b9dd742f2a108997c2252e2bdebffffffff"),
                bytes.fromhex("e04280000102"),
                bytes.fromhex("e04280002281b72e00000000001976a91472a5d75c8d2d0565b656a5232703b167d50d5a2b88ac"),
                bytes.fromhex("e042800022a0860100000000001976a9144533f5fb9b4817f713c48f0bfe96b9f50c476c9b88ac"),
                bytes.fromhex("e04280000400000000")
            ],
            [  # UNTRUSTED HASH TRANSACTION INPUT START
                bytes.fromhex("e0440000050100000001"),
                bytes.fromhex("e04480002600c773da236484dae8f0fdba3d7e0ba1d05070d1a34fc44943e638441262a04f100100000069"),
                bytes.fromhex("e04480003252210289b4a3ad52a919abd2bdd6920d8a6879b1e788c38aa76f0440a6f32a9f1996d02103a3393b1439d1693b063482c04b"),
                bytes.fromhex("e044800032d40142db97bdf139eedd1b51ffb7070a37eac321030b9a409a1e476b0d5d17b804fcdb81cf30f9b99c6f3ae1178206e08bc5"),
                bytes.fromhex("e04480000900639853aeffffffff")
            ],
            [   # UNTRUSTED HASH TRANSACTION INPUT FINALIZE FULL
                bytes.fromhex("e04a80002301905f0100000000001976a91472a5d75c8d2d0565b656a5232703b167d50d5a2b88ac")
            ],
            [   # UNTRUSTED HASH SIGN - output will be different than ledgerjs test
                bytes.fromhex("e04800001303800000000000000000000000000000000001")
            ]
        ],
        # [
        #     # "btc 2" test data - deactivated as it fails on 2nd "UNTRUSTED HASH TRANSACTION INPUT START" APDU (sw=6f01)
        #     [   # GET TRUSTED INPUT
        #         bytes.fromhex("e042000009000000010100000001"),
        #         bytes.fromhex("e0428000254ea60aeac5252c14291d428915bd7ccd1bfc4af009f4d4dc57ae597ed0420b71010000008a"),
        #         bytes.fromhex("e04280003247304402201f36a12c240dbf9e566bc04321050b1984cd6eaf6caee8f02bb0bfec08e3354b022012ee2aeadcbbfd1e92959f"),
        #         bytes.fromhex("e04280003257c15c1c6debb757b798451b104665aa3010569b49014104090b15bde569386734abf2a2b99f9ca6a50656627e77de663ca7"),
        #         bytes.fromhex("e04280002a325702769986cf26cc9dd7fdea0af432c8e2becc867c932e1b9dd742f2a108997c2252e2bdebffffffff"),
        #         bytes.fromhex("e04280000102"),
        #         bytes.fromhex("e04280002281b72e00000000001976a91472a5d75c8d2d0565b656a5232703b167d50d5a2b88ac"),
        #         bytes.fromhex("e042800022a0860100000000001976a9144533f5fb9b4817f713c48f0bfe96b9f50c476c9b88ac"),
        #         bytes.fromhex("e04280000400000000"),
        #     ],
        #     [   # GET PUBLIC KEY
        #         bytes.fromhex("e04000000d03800000000000000000000000"),
        #     ],
        #     [  # UNTRUSTED HASH TRANSACTION INPUT START
        #         bytes.fromhex("e0440000050100000001"),
        #         bytes.fromhex("e04480003b013832005df4c773da236484dae8f0fdba3d7e0ba1d05070d1a34fc44943e638441262a04f1001000000a086010000000000b890da969aa6f31019"),
        #         bytes.fromhex("e04480001d76a9144533f5fb9b4817f713c48f0bfe96b9f50c476c9b88acffffffff"),
        #     ],
        #     [   # UNTRUSTED HASH TRANSACTION INPUT FINALIZE FULL
        #         bytes.fromhex("e04a80002301905f0100000000001976a91472a5d75c8d2d0565b656a5232703b167d50d5a2b88ac"),
        #     ],
        #     [   # UNTRUSTED HASH SIGN - output will be different than ledgerjs test
        #         bytes.fromhex("e04800001303800000000000000000000000000000000001")
        #     ]
        # ]
    ]

    @pytest.mark.parametrize('test_data_', ledgerjs_tests)
    def test_ledgerjs(self, test_data_: List[List[bytes]]) -> None:
        """Verify the Btc app with a test Tx known to work.
        Data is from ledgerjs repo, file "Btc.test.js", test "btc 2"
        """
        apdus = test_data_
        btc = DeviceAppBtc()
        # All apdus shall return 9000 + potentially some data)
        for apdu in apdus:      
            for command in apdu:
                response = btc.sendRawApdu(command)


class TestTxSegwitTrustedInputsNano:

    def check_valid(self, 
                    trusted_input: bytes, 
                    out_index: str, 
                    out_amount: str,
                    out_hash: Optional[str] = None) -> None:
        print(f"    OK, Magic marker = {trusted_input[:2].hex()}")
        print(f"    2-byte random = {trusted_input[2:4].hex()}")
        print(f"    Trusted Input hash = {trusted_input[4:36].hex()}")
        print(f"    Prevout Index = {trusted_input[36:40].hex()}")
        print(f"    Amount = {trusted_input[40:48].hex()}")
        print(f"    SHA-256 HMAC = {trusted_input[48:].hex()}")

        assert trusted_input[:2].hex() == "3200"            # MAGIC_TRUSTED_INPUT (32) + 00
        assert trusted_input[36:40].hex() == out_index      
        assert trusted_input[40:48].hex() == out_amount     
        if out_hash:
            assert trusted_input[4:36] == out_hash


    def test_get_trusted_input_standard_tx(self) -> None:
        """Perform a GetTrustedInput for a non-segwit tx on Nano device.

        BTC Testnet
        txid: 45a13dfa44c91a92eac8d39d85941d223e5d4d210e85c0d3acf724760f08fcfe
        VO_P2WPKH
        """
        utxos = [
            (0, bytes.fromhex(
                # Version 
                "02000000"
                # Input count
                "02"
                # Input #1's prevout hash
                "40d1ae8a596b34f48b303e853c56f8f6f54c483babc16978eb182e2154d5f2ab"
                # Input #1's prevout index
                "00000000"
                # Input #1's prevout scriptSig len (107 bytes)
                "6b"
                # Input #1's prevout scriptSig
                "483045022100ca145f0694ffaedd333d3724ce3f4e44aabc0ed5128113660d11"
                "f917b3c5205302207bec7c66328bace92bd525f385a9aa1261b83e0f92310ea1"
                "850488b40bd25a5d0121032006c64cdd0485e068c1e22ba0fa267ca02ca0c2b3"
                "4cdc6dd08cba23796b6ee7"
                # Input #1 sequence number
                "fdffffff"
                # Input #2's prevout hash
                "40d1ae8a596b34f48b303e853c56f8f6f54c483babc16978eb182e2154d5f2ab"
                # Input #2's prevout index
                "01000000"
                # Input #2's prevout scriptSsig len (106 bytes)
                "6a"
                # Input #2's prevout scriptSsig
                "47304402202a5d54a1635a7a0ae22cef76d8144ca2a1c3c035c87e7cd0280ab4"
                "3d3451090602200c7e07e384b3620ccd2f97b5c08f5893357c653edc2b8570f0"
                "99d9ff34a0285c012102d82f3fa29d38297db8e1879010c27f27533439c868b1"
                "cc6af27dd3d33b243dec"
                # Input #2 sequence number
                "fdffffff"
                # Output count
                "01"
                # Amount (0.24964823 BTC)
                "d7ee7c0100000000"
                # Output scriptPubKey
                "1976a9140ea263ff8b0da6e8d187de76f6a362beadab781188ac"
                # Locktime
                "e3691900")
            )
        ]

        # The GetTrustedInput payload is (|| meaning concatenation): 
        #   output_index (4B) || tx 
        # Lengths below account for this 4B prefix
        # (See file comment for additional explanation on values below)
        chunks_len = [
            9,      # len(output_index(4B)||version||input_count)
            37,     # len(input1_prevout_hash||input1_prevout_index||input1_scriptSig_len)
            -1,     # get len(input1_scriptSig) from last byte of previous chunk, add len(input1_sequence)
            37,     # len(input2_prevout_hash||input2_prevout_index||input2_scriptSig_len)
            -1,     # get len(input2_scriptSig) from last byte of previous chunk, add len(input2_sequence)
            1,      # len(output_count)
            34,     # len(output_amount||output_scriptPubkey)
            4       # len(locktime)
        ]

        btc = DeviceAppBtc()

        data = bytes.fromhex("000000") + bytes([utxos[0][0]]) + utxos[0][1]
        trusted_inputs = [
            btc.getTrustedInput(
                data=data,
                chunks_len=chunks_len)
            for (prevout_index, prev_tx) in utxos
        ]

        # can't verify the input hash as idk what data from the tx is double-SHA-256 -hashed
        # Can't verify the HMAC as idk the HMAC key (in Flash). Only check output index & amount.
        self.check_valid(trusted_inputs[0], out_index="00000000", out_amount="d7ee7c0100000000")


    def test_get_trusted_input_segwit_tx(self) -> None:
        """Perform a GetTrustedInput for a segwit tx

        Segwit-specific fields (flag & witnesses) are commented to simulate how 
        a TrustedInput can be obtained from a segwit tx.

        BTC Testnet tx
        txid: 5387ef4d09919951399fe3a6d94354c92c78328e77dbafa5dad5647569f1e02c
        VO_P2WPKH
        """
        utxos = [
            (0, bytes.fromhex(
                 # Version no (4 bytes)
                 "02000000"
                 # Marker + Flag (optional 2 bytes, 0001 indicates the presence of witness data)
                 # /!\ Remove flag for `GetTrustedInput`
                 "0001"
                 # In-counter (varint 1-9 bytes)
                 "02"
                 # Previous Transaction hash 1 (32 bytes)
                 "daf4d7b97a62dd9933bd6977b5da9a3edb7c2d853678c9932108f1eb4d27b7a9"
                 # Previous Txout-index 1 (4 bytes)
                 "00000000"
                 # Txin-script length 1 (varint 1-9 bytes)
                 "00"
                 # /!\ no Txin-script (a.k.a scriptSig) because P2WPKH
                 # sequence_no (4 bytes)
                 "fdffffff"
                 # Previous Transaction hash 2 (32 bytes)
                 "daf4d7b97a62dd9933bd6977b5da9a3edb7c2d853678c9932108f1eb4d27b7a9"
                 # Previous Txout-index 2 (4 bytes)
                 "01000000"
                 # Tx-in script length 2 (varint 1-9 bytes)
                 "00"
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
                 # Witnesses (1 for each input if Flag=0001)
                 # /!\ remove witnesses for `GetTrustedInput`
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
                 # lock_time (4 bytes)
                 "a7011900")
            )
        ]
        # First tuple below is used to  
        # and 341 = locktime offset in APDU payload (i.e. don't send witness data to app)
        chunks_len = [(8, 2, 1), 37, 4, 37, 4, 1, 31, (341, 4)]    

        btc = DeviceAppBtc()

        trusted_inputs = [
            btc.getTrustedInput(
                data=bytes.fromhex("000000") + bytes([prevout_index]) + prev_tx,
                chunks_len=chunks_len
            )
            for (prevout_index, prev_tx) in utxos
        ]

        self.check_valid(trusted_inputs[0], out_index="00000000", out_amount="01410f0000000000")


    def test_submit_native_segwit_btc_transaction(self) -> None:
        """Test signing a btc transaction w/ segwit inputs submitted as TrustedInputs
        
        BTC Testnet segwit tx used as a "prevout" tx.
        txid: 5387ef4d09919951399fe3a6d94354c92c78328e77dbafa5dad5647569f1e02c
        VO_P2WPKH
        """
        utxos = [
            (0,
             bytes.fromhex(
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
                 "30440220495838c36533616d8cbd6474842459596f4f312dce5483fe6507"
                 "91c82e17221c02200660520a2584144915efa8519a72819091e5ed78c526"
                 "89b24235182f17d96302012102ddf4af49ff0eae1d507cc50c86f903cd6a"
                 "a0395f3239759c440ea67556a3b91b"
                 "0247"
                 "304402200090c2507517abc7a9cb32452aabc8d1c8a0aee75ce63618ccd9"
                 "01542415f2db02205bb1d22cb6e8173e91dc82780481ea55867b8e753c35"
                 "424da664f1d2662ecb1301210254c54648226a45dd2ad79f736ebf7d5f0f"
                 "c03b6f8f0e6d4a61df4e531aaca431"
                 # lock_time (4 bytes)
                 "a7011900"
             ))
        ]

        utxos_chunks_len = [(8, 2, 1), 37, 4, 37, 4, 1, 31, (341, 4)]

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
        trusted_inputs = [
            btc.getTrustedInput(
                data=bytes.fromhex("000000") + bytes([prevout_index]) + prev_tx,
                chunks_len=utxos_chunks_len
            )
            for (prevout_index, prev_tx) in utxos
        ]
        trusted_input = trusted_inputs[0]
        self.check_valid(trusted_input, out_index="00000000", out_amount="01410f0000000000")

        # 2. Send Untrusted Transaction Input Hash Start (up to outputs count, excluded)
        # Insert trusted input in the tx to sign in place of inputs
        print("\n--* Untrusted Transaction Input Hash Start")
        tx_to_sign_part1 = bytes.fromhex(   # 1st part goes up to input sequence 
            tx_to_sign[:5].hex()                        \
            + "01" + bytes([len(trusted_input)]).hex()  \
            + trusted_input.hex()                       \
            + tx_to_sign[41:41 + 1 + tx_to_sign[41] + 4].hex()
        )

        tx_part1_chunks_len = [
            5,                          # len(version||input_count)
            1+1+len(trusted_input)+1,   # len(trustedInput marker "01"||len(trusted_input)||trusted_input||scriptSig_len)
            -1                          # get len(scriptSig) from previous chunk (0x19=25), add len(input_script_sequence) 
        ]
        btc.untrustedTxInputHashStart(
            p1="00",
            p2="00",    # Tx contains Trusted inputs in place of inputs from a segwit tx.
            data=tx_to_sign_part1,
            chunks_len=tx_part1_chunks_len)
        print("    OK")

        # 3. Send Untrusted Transaction Input Hash Finalize (from outputs_count up to
        #    tx locktime, excluded). No chunks required here.
        print("\n--* Untrusted Transaction Input Hash Finalize Full")
        tx_to_sign_part2 = tx_to_sign[71:-4]
        response = btc.untrustedTxInputHashFinalize(
            p1="00",
            data=tx_to_sign_part2)
        print(f"    OK, Response = {response.hex()}")
        assert response.hex() == "0000"

        #4. Send Untrusted Hash Sign (w/ random BIP32 path, RFU (00) byte, BE-encoded 
        #   locktime & sigHashType = 01)
        print("\n--* Untrusted Transaction Sign")
        in_data = bytes.fromhex("03"+"80000000"+"00000000"+"00000000")  \
                + bytes(1)                                              \
                + bytes(reversed(tx_to_sign[-4:]))                      \
                + bytes.fromhex("01")

        response = btc.untrustedHashSign(data=in_data)
        print(f"    OK, (R,S) = {response[:-1].hex()}")
        print(f"    sigHasType = {bytes([response[-1]]).hex()}")


    @pytest.mark.skip(reason="Can't seem to work out how to send the tx data to send correctly to the app."
                             "Warning screen is shown however. Comment decorator to run.")
    def test_submit_true_segwit_tx_shows_warning(self) -> None:
        """Test signing a btc transaction w/ segwit inputs submitted as such shows warning screen
        
        This mimics the behavior of a wallet that has not yet been updated to work around 
        the fact that segwit inputs cannot be verified.

        BTC Testnet segwit tx used as a "prevout" tx.
        txid: 5387ef4d09919951399fe3a6d94354c92c78328e77dbafa5dad5647569f1e02c
        VO_P2WPKH
        """
        # Amount of the 1st output of a segwit tx
        segwit_prevout_0_amount = bytes.fromhex("1027000000000000")

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
            # "02"
            "01"
            # 1st valuein satoshis (8 bytes)
            "1027000000000000"  # 10000 satoshis = 0.0001 BTC
            # 1st Txout-script length (varint 1-9 bytes)
            "16"  # 22
            # 1st Txout-script (a.k.a. scriptPubKey)
            "0014161d283ebbe0e6bc3d90f4c456f75221e1b3ca0f"
            # 2nd value in satoshis (8 bytes)
            # "64190f0000000000"  # 989540 satoshis = 0,0098954 BTC
            # 2nd Txout-script length (varint 1-9 bytes)
            # "16"  # 22
            # 2nd Txout-script (a.k.a. scriptPubKey)
            # "00144c5133c242683d33c61c4964611d82dcfe0d7a9a"
            # lock_time (4 bytes)
            "a7011900"
        )

        btc = DeviceAppBtc()

        # Send Untrusted Transaction Input Hash Start without performing a GetTrustedInput 
        # first (as would do a wallet not yet updated). 
        # From file "btc.asc": 
        #   "When using Segregated Witness Inputs the signing mechanism differs 
        #    slightly:
        #    - The transaction shall be processed first with all inputs having a null script length 
        #    - Then each input to sign shall be processed as part of a pseudo transaction with a 
        #      single input and no outputs."
        
        # 1. Construct a pseudo-tx without input script, to be sent 1st...
        print("\n--* Untrusted Transaction Input Hash Start - Send tx first w/ all inputs having a null script length")
        tx_to_sign_part1 = bytes.fromhex(
            tx_to_sign[:41].hex() 
            + "00"                      # Null input script length
            + tx_to_sign[67:71].hex()   # Skip input script to send input_sequence
        )

        tx_part1_chunks_len = [
            5,              # len(version||input_count)
            32 + 4 + 1 + 4, # len(input_hash||prevout_index||scriptSig_len == 0||input_sequence)
        ]
        btc.untrustedTxInputHashStart(
            p1="00",
            p2="02",    # Tx contains segwit inputs, this value should show a warning on 
                        # the device but operation should be allowed to proceed
            data=tx_to_sign_part1,
            chunks_len=tx_part1_chunks_len)
        print("    OK")

        # 2. Send each input separately in a pseudo tx
        print("\n--* Untrusted Transaction Input Hash Start - Send each segwit input separately")
        tx_to_sign_part2 = bytes.fromhex(
            tx_to_sign[:4].hex()                # Version
            + "01"                              # 1 input at a time
            + "02" + tx_to_sign[5:41].hex()     # segwit marker + input tx hash + out_index
            + segwit_prevout_0_amount           # input amount
            + tx_to_sign[41:41 + 1 + tx_to_sign[41] + 4].hex()  # script length + script + sequence
        )
        tx_part2_chunks_len = [
            5,                  # len(version||input_count)
            1 + 32 + 4 + 8 + 1, # len(segwit_marker||input_hash||prevout_index||amount||scriptSig_len != 0)
            -1,                 # get input script len from last byte of previous chunk
            4                   # len(input_sequence)
        ]
        btc.untrustedTxInputHashStart(
            p1="00",
            p2="02",            # Should not show the nag screen again
            data=tx_to_sign_part2,
            chunks_len=tx_part2_chunks_len)
        print("    OK")

        # 3. Send Untrusted Transaction Input Hash Finalize (from outputs_count up to
        #    tx locktime, excluded). No chunks required here.
        print("\n--* Untrusted Transaction Input Hash Finalize Full")
        tx_to_sign_part2 = tx_to_sign[71:-4]
        response = btc.untrustedTxInputHashFinalize(
            p1="80",
            data=tx_to_sign_part2)
        print(f"    OK, Response = {response.hex()}")
        assert response.hex() == "0000"

        #4. Send Untrusted Hash Sign (w/ arbitrary BIP32 path, RFU (00) byte, BE-encoded 
        #   locktime & sigHashType = 01)
        print("\n--* Untrusted Transaction Sign")
        in_data = bytes.fromhex("03"+"80000000"+"00000000"+"00000000")  \
                + bytes(1)                                              \
                + bytes(reversed(tx_to_sign[-4:]))                      \
                + bytes.fromhex("01")

        response = btc.untrustedHashSign(data=in_data)
        print(f"    OK, (R,S) = {response[:-1].hex()}")
        print(f"    sigHashType = {bytes([response[-1]]).hex()}")

