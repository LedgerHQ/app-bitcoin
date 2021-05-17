from io import BytesIO

from bitcoin_client.hwi.serialization import CTransaction
from bitcoin_client.utils import deser_trusted_input


def test_get_trusted_inputs(cmd):
    raw_tx: bytes = bytes.fromhex(
        # Version no (4 bytes little endian)
        "02000000"
        # In-counter (varint 1-9 bytes)
        "02"
        # [1] Previous Transaction hash (32 bytes)
        "40d1ae8a596b34f48b303e853c56f8f6f54c483babc16978eb182e2154d5f2ab"
        # [1] Previous Txout-index (4 bytes little endian)
        "00000000"
        # [1] Txin-script length (varint 1-9 bytes)
        "6b"
        # [1] scriptSig (0x6b = 107 bytes)
        "48"
        "3045"
        "0221"
        # r
        "00ca145f0694ffaedd333d3724ce3f4e44aabc0ed5128113660d11f917b3c52053"
        "0220"
        # s
        "7bec7c66328bace92bd525f385a9aa1261b83e0f92310ea1850488b40bd25a5d"
        # sighash
        "01"
        "21"
        # compressed public key
        "032006c64cdd0485e068c1e22ba0fa267ca02ca0c2b34cdc6dd08cba23796b6ee7"
        # [1] sequence_no (4 bytes little endian)
        "fdffffff"
        # [2] Previous Transaction hash (32 bytes)
        "40d1ae8a596b34f48b303e853c56f8f6f54c483babc16978eb182e2154d5f2ab"
        # [2] Previous Txout-index (4 bytes little endian)
        "01000000"
        # [2] Txin-script length (varint 1-9 bytes)
        "6a"
        # [2] scriptSig (0x6a = 106 bytes)
        "47"
        "3044"
        "0220"
        # r
        "2a5d54a1635a7a0ae22cef76d8144ca2a1c3c035c87e7cd0280ab43d34510906"
        "0220"
        # s
        "0c7e07e384b3620ccd2f97b5c08f5893357c653edc2b8570f099d9ff34a0285c"
        "01"
        "21"
        # compressed public key
        "02d82f3fa29d38297db8e1879010c27f27533439c868b1cc6af27dd3d33b243dec"
        # [2] sequence_no (4 bytes little endian)
        "fdffffff"
        # Out-counter (varint 1-9 bytes)
        "01"
        # [1] Value (8 bytes little endian)
        "d7ee7c0100000000"  # 0.24964823 BTC
        # [1] Txout-script length (varint 1-9 bytes)
        "19"
        # [1] scriptPubKey (0x19 = 25 bytes)
        "76a914"
        "0ea263ff8b0da6e8d187de76f6a362beadab7811"
        "88ac"
        # lock_time (4 bytes little endian)
        "e3691900"
    )

    bip141_raw_tx: bytes = bytes.fromhex(
        # Version no (4 bytes little endian)
        "02000000"
        # marker (1 byte) + flag (1 byte)
        "0001"
        # In-counter (varint 1-9 bytes)
        "02"
        # [1] Previous Transaction hash (32 bytes)
        "e7576f53b5d92f9880b125d0622782fef40b0121eb4555c9d3a7be54e635cd6e"
        # [1] Previous Txout-index (4 bytes little endian)
        "00000000"
        # [1] Txin-script length (varint 1-9 bytes)
        "17"
        # [1] scriptSig (0x17 = 23 bytes)
        "160014"
        "4c9fca3fd23ae5cc1f0dfe46b446da611219c020"  # hash160(pubkey)
        # [1] sequence_no (4 bytes little endian)
        "fdffffff"
        # [2] Previous Transaction hash (32 bytes)
        "4ba91d8e1cedbfecdceda7f3432f618a2f0e122c66a63fe0c53a14de6305e5dc"
        # [2] Previous Txout-index (4 bytes little endian)
        "01000000"
        # [2] Txin-script length (varint 1-9 bytes)
        "17"
        # [2] scriptSig (0x17 = 23 bytes)
        "160014"
        "92a9159a0ae40a748c18bd486ea13da85422450c"  # hash160(pubkey)
        # [2] sequence_no (4 bytes little endian)
        "fdffffff"
        # Out-counter (varint 1-9 bytes)
        "02"
        # [1] Value (8 bytes little endian)
        "7f19060000000000"
        # [1] Txout-script length (varint 1-9 bytes)
        "17"
        # [1] scriptPubKey (0x17 = 23 bytes)
        "a9141a56dea1ff8a3f633916560fed5942400d17080b87"
        # [2] Value (8 bytes little endian)
        "60ae0a0000000000"
        # [2] Txout-script length (varint 1-9 bytes)
        "17"
        # [2] scriptPubKey (0x17 = 23 bytes)
        "a9147c28b075f506d829e2e2bacf897c1b5b0d309c1a87"
        # Witnesses
        "02"  # number of items to push on the stack
        "48"  # length of 1st stack item
        # 1st item
        "3045"
        "0221"
        # r
        "00c791ff9a5886903fbd3c1289f281e1d5a3e330f1558ea5df725bcd780b285677"
        "0220"
        # s
        "2d76349a78585ea66df6eef5ab48a0348cc337994a1d6357a6e4e4328a343f6d"
        "01"
        # 2nd item
        "21"  # length of 2nd stack item
        # compressed public key
        "02623ed09f8c192938f7a638fbdd5dd7c297f86e41be8d7dff4f1c904f0685f227"
        "02"  # number of items to push on the stack
        # 1st item
        "48"  # length of 1st stack item
        "3045"
        "0221"
        # r
        "008f2f017f5fa4fdd7dcfe41c83f4a71a726626cdb490d652edcb408b9a4638b7a"
        "0220"
        # s
        "439c15a7f7a03f2876dec5392f2247437b57b227fea294f4019d06462f938b53"
        "01"
        # 2nd item
        "21"  # length of 2nd stack item
        # compressed public key
        "0347e9143aa6457c72a48d85b5065edc40d3a49f319d54fc4979dc3b95de949a41"
        # lock_time (4 bytes little endian)
        "d7681900"
    )
    tx: CTransaction
    bip141_tx: CTransaction
    output_index: int
    trusted_input: bytes

    tx = CTransaction()
    tx.deserialize(BytesIO(raw_tx))
    tx.calc_sha256()

    output_index = 0
    trusted_input = cmd.get_trusted_input(utxo=tx, output_index=output_index)

    _, _, _, prev_txid, out_index, amount, _ = deser_trusted_input(trusted_input)
    assert out_index == output_index
    assert prev_txid == tx.sha256.to_bytes(32, byteorder="little")
    assert amount == tx.vout[out_index].nValue

    bip141_tx = CTransaction()
    bip141_tx.deserialize(BytesIO(bip141_raw_tx))
    bip141_tx.calc_sha256()

    output_index = 1
    trusted_input = cmd.get_trusted_input(utxo=bip141_tx, output_index=output_index)

    _, _, _, prev_txid, out_index, amount, _ = deser_trusted_input(trusted_input)
    assert out_index == output_index
    assert prev_txid == bip141_tx.sha256.to_bytes(32, byteorder="little")
    assert amount == bip141_tx.vout[out_index].nValue
