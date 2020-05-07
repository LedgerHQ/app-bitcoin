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
from dataclasses import dataclass, field
from typing import Optional, List
from helpers.basetest import BaseTestBtc
from helpers.deviceappbtc import DeviceAppBtc, BTC_P1, BTC_P2


@dataclass
class TrustedInputTestData:
    # Tx to compute a TrustedInput from.
    tx: bytes
    # List of lengths of the chunks that will be sent as APDU payloads. Depending on the APDU
    # the APDU, the BTC app accepts payloads (composed from the tx and other data) of specific 
    # sizes. See https://blog.ledger.com/btchip-doc/bitcoin-technical-beta.html#_get_trusted_input.
    chunks_len: List[int]
    # List of the outputs values to be tested, as expressed in the raw tx.
    prevout_amount: List[bytes]
    # Optional, index (not offset!) in the tx of the output to compute the TrustedInput from. Ignored 
    # if num_outputs is set.
    prevout_idx: Optional[int] = field(default=None)
    # Optional, number of outputs in the tx. If set, all the tx outputs will be used to generate 
    # each a corresponding TrustedInput, prevout_idx is ignored and prevout_amount must contain the
    # values of all the outputs of that tx, in order. If not set, then prevout_idx must be set.
    num_outputs: Optional[int] = field(default=None)


# Test data definition

# BTC Testnet
# txid: 45a13dfa44c91a92eac8d39d85941d223e5d4d210e85c0d3acf724760f08fcfe
# VO_P2WPKH
standard_tx = TrustedInputTestData(
    tx=bytes.fromhex(
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
        "e3691900"
    ),
    # The GetTrustedInput payload is (|| meaning concatenation):  output_index (4B, BE) || tx
    # Lengths below account for this 4B prefix (see file comment for more explanation on values below)
    chunks_len=[
        9,      # len(output_index(4B)||version||input_count)
        37,     # len(input1_prevout_hash||input1_prevout_index||input1_scriptSig_len)
        -1,     # get len(input1_scriptSig) from last byte of previous chunk, add len(input1_sequence)
        37,     # len(input2_prevout_hash||input2_prevout_index||input2_scriptSig_len)
        -1,     # get len(input2_scriptSig) from last byte of previous chunk, add len(input2_sequence)
        1,      # len(output_count)
        34,     # len(output_amount||output_scriptPubkey)
        4       # len(locktime)
    ],
    prevout_idx=0,
    prevout_amount=[bytes.fromhex("d7ee7c0100000000")]
)

segwit_tx = TrustedInputTestData(
    tx=bytes.fromhex(
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
        "a7011900"
    ),
        # First tuple in list below is used to concatenate output_idx||version||input_count while
        # skip the 2-byte segwit-specific flag ("0001") in between.
        # Value 341 = locktime offset in APDU payload (i.e. skip all witness data).
        # Finally, tx contains no scriptSig, so no "-1" trick is necessary.
    chunks_len= [(4+4, 2, 1), 37, 4, 37, 4, 1, 31, (335+4, 4)],
    prevout_idx=0,
    prevout_amount=[bytes.fromhex("01410f0000000000")]
)

segwwit_tx_2_outputs = TrustedInputTestData(
    tx=bytes.fromhex(
        # Version no (4 bytes)
        "02000000"
        # Marker + Flag (optional 2 bytes, 0001 indicates the presence of witness data)
        # /!\ Remove flag for `GetTrustedInput`
        "0001"
        # In-counter (varint 1-9 bytes)
        "01"
        # 1st Previous Transaction hash (32 bytes)
        "1541bf80c7b109c50032345d7b6ad6935d5868520477966448dc78ab8f493db1"
        # 1st Previous Txout-index (4 bytes)
        "00000000"
        # 1st Txin-script length (varint 1-9 bytes)
        "17"
        # Txin-script (a.k.a scriptSig) because P2SH
        "160014d44d01d48f9a0d5dfa73dab21c30f7757aed846a"
        # sequence_no (4 bytes)
        "feffffff"
        # Out-counter (varint 1-9 bytes)
        "02"
        # value in satoshis (8 bytes)
        "9b3242bf01000000"  # 999681 satoshis = 0,00999681 BTC
        # Txout-script length (varint 1-9 bytes)
        "17"
        # Txout-script (a.k.a scriptPubKey)
        "a914ff31b9075c4ac9aee85668026c263bc93d016e5a87"
        # value in satoshis (8 bytes)
        "1027000000000000"  # 999681 satoshis = 0,00999681 BTC
        # Txout-script length (varint 1-9 bytes)
        "17"
        # Txout-script (a.k.a scriptPubKey)
        "a9141e852ac84f8385d76441c584e41f445aaf1624ea87"
        # Witnesses (1 for each input if Marker+Flag=0001)
        # /!\ remove witnesses for `GetTrustedInput`
        "0247"
        "304402206e54747dabff52f5c88230a3036125323e21c6c950719f671332"
        "cdd0305620a302204a2f2a6474f155a316505e2224eeab6391d5e6daf22a"
        "cd76728bf74bc0b48e1a0121033c88f6ef44902190f859e4a6df23ecff4d"
        "86a2114bd9cf56e4d9b65c68b8121d"
        # lock_time (4 bytes)
        "1f7f1900"
    ),
    chunks_len=[(8, 2, 1), 37, -1, 1, 32, 32, (253, 4)],
    num_outputs=2,
    prevout_amount=[bytes.fromhex(amount) for amount in ("9b3242bf01000000", "1027000000000000")]
)

@pytest.mark.btc
class TestBtcTxGetTrustedInput(BaseTestBtc):
    """
    Tests of the GetTrustedInput APDU
    """
    test_data = [ standard_tx, segwit_tx ]

    @pytest.mark.parametrize("testdata", test_data)
    def test_get_trusted_input(self, testdata: TrustedInputTestData) -> None:
        """
        Perform a GetTrustedInput for a non-segwit tx on Nano device.
        """
        btc = DeviceAppBtc()

        prevout_idx = [idx for idx in range(testdata.num_outputs)] \
            if testdata.num_outputs is not None else [testdata.prevout_idx]

        # Get TrustedInputs for all requested outputs in the tx
        trusted_inputs = [
            btc.getTrustedInput(
                data=idx.to_bytes(4, 'big') + testdata.tx,
                chunks_len=testdata.chunks_len 
            )
            for idx in prevout_idx
        ]

        # Check each TrustedInput content
        for (trusted_input, idx, amount) in zip(trusted_inputs, prevout_idx, testdata.prevout_amount):
            self.check_trusted_input(
                trusted_input, 
                out_index=idx.to_bytes(4, 'little'), 
                out_amount=amount
            )

