import struct
from typing import List

from bitcoin_client.hwi.serialization import CTransaction, hash256, ser_string


def bip143_digest(tx: CTransaction,
                  amount: int,
                  input_index: int,
                  sig_hash: int = 0x01) -> bytes:
    hash_prev_outs: bytes = b"".join([
        txin.prevout.serialize() for txin in tx.vin
    ])

    hash_sequence: bytes = b"".join([
        struct.pack("<I", txin.nSequence) for txin in tx.vin
    ])

    hash_outputs: bytes = b"".join([
        txout.serialize() for txout in tx.vout
    ])

    digest: bytes = hash256(
        b"".join([
            struct.pack("<i", tx.nVersion),
            hash256(hash_prev_outs),
            hash256(hash_sequence),
            tx.vin[input_index].prevout.serialize(),  # outpoint
            ser_string(tx.vin[input_index].scriptSig),
            struct.pack("<q", amount),
            struct.pack("<I", tx.vin[input_index].nSequence),
            hash256(hash_outputs),
            struct.pack("<I", tx.nLockTime),
            sig_hash.to_bytes(4, byteorder="little")
        ])
    )
    # print(f"version: {struct.pack('<i', tx.nVersion).hex()}")
    # print(f"hash_prev_outs: {hash256(hash_prev_outs).hex()}")
    # print(f"hash_sequence: {hash256(hash_sequence).hex()}")
    # print(f"outpoint: {tx.vin[input_index].prevout.serialize().hex()}")
    # print(f"scriptSig: {ser_string(tx.vin[input_index].scriptSig).hex()}")
    # print(f"amount: {struct.pack('<q', amount).hex()}")
    # print(f"sequence: {struct.pack('<I', tx.vin[input_index].nSequence).hex()}")
    # print(f"hash_outputs: {hash256(hash_outputs).hex()}")
    # print(f"lock_time: {struct.pack('<I', tx.nLockTime).hex()}")
    # print(f"digest: {digest.hex()}")

    return digest


def bip32_path_from_string(path: str) -> List[bytes]:
    """Convert BIP32 path string to list of bytes."""
    splitted_path: List[str] = path.split("/")

    if "m" in splitted_path and splitted_path[0] == "m":
        splitted_path = splitted_path[1:]

    return [int(p).to_bytes(4, byteorder="big") if "'" not in p
            else (0x80000000 | int(p[:-1])).to_bytes(4, byteorder="big")
            for p in splitted_path]


def compress_pub_key(pub_key: bytes) -> bytes:
    """Convert uncompressed to compressed public key."""
    if pub_key[-1] & 1:
        return b"\x03" + pub_key[1:33]

    return b"\x02" + pub_key[1:33]