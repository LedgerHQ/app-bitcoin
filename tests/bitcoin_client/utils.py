from typing import Tuple, Iterator


MAX_APDU_LEN: int = 255


def chunkify(data: bytes, chunk_len: int) -> Iterator[Tuple[bool, bytes]]:
    """Split `data` into chunk of length `chunk_len`.`"""
    size: int = len(data)

    if size <= chunk_len:
        yield True, data
        return

    chunk: int = size // chunk_len
    remaining: int = size % chunk_len
    offset: int = 0

    for i in range(chunk):
        yield False, data[offset:offset + chunk_len]
        offset += chunk_len

    if remaining:
        yield True, data[offset:]


def deser_trusted_input(trusted_input: bytes
                        ) -> Tuple[int, int, bytes, bytes, int, int, bytes]:
    """Deserialize trusted input into 7 items."""
    assert len(trusted_input) == 56

    offset: int = 0
    magic_trusted_input: int = trusted_input[offset]
    assert magic_trusted_input == 0x32
    offset += 1
    zero: int = trusted_input[offset]
    assert zero == 0x00
    offset += 1
    random: bytes = trusted_input[offset:offset + 2]
    offset += 2
    prev_txid: bytes = trusted_input[offset:offset + 32]
    offset += 32
    out_index: int = int.from_bytes(trusted_input[offset:offset + 4],
                                    byteorder="little")
    offset += 4
    amount: int = int.from_bytes(trusted_input[offset:offset + 8],
                                 byteorder="little")
    offset += 8
    hmac: bytes = trusted_input[offset:offset + 8]
    offset += 8

    assert offset == len(trusted_input)

    return (magic_trusted_input, zero, random,
            prev_txid, out_index, amount, hmac)
