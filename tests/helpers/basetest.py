from typing import Optional

class BaseTestBtc:
    """
    Base class for tests of BTC app, contains data validators. 
    """
    def check_trusted_input(self,
                            trusted_input: bytes, 
                            out_index: bytes, 
                            out_amount: bytes,
                            out_hash: Optional[bytes] = None) -> None:
        print(f"    Magic marker = {trusted_input[:2].hex()}")
        print(f"    2-byte nonce = {trusted_input[2:4].hex()}")
        print(f"    Transaction hash (txid) = {trusted_input[4:36].hex()}")
        print(f"    Prevout index = {trusted_input[36:40].hex()}")
        print(f"    Prevout amount = {trusted_input[40:48].hex()}")
        print(f"    SHA-256 HMAC = {trusted_input[48:].hex()}")
        # Note: Signature value can't be asserted since the HMAC key is secret in the device
        assert trusted_input[:2] == bytes.fromhex("3200")
        assert trusted_input[36:40] == out_index      
        assert trusted_input[40:48] == out_amount     
        if out_hash:
            assert trusted_input[4:36] == out_hash

    def check_signature(self, 
                        resp: bytes, 
                        expected_resp: Optional[bytes]=None) -> None:
        # Signature is DER-encoded as: # 30|parity_bit zz 02 xx R 02 yy S sigHashType
        # with:
        # - parity_bit: a ledger extension to the BTC standard
        # - zz: length of the payload, excluding sigHasType byte (zz = xx + yy + 4)
        # - xx: len of R
        # - yy: len of S
        # - sigHashType: always 01
        parity_bit = resp[0] & 1
        offs_r = 4
        len_r = resp[offs_r - 1]
        offs_s = offs_r + len_r + 2
        len_s = resp[offs_s - 1]
        print(f"    OK, response = {resp.hex()}")
        print(f"     - Parity = {'odd' if parity_bit else 'even'}")
        print(f"     - R = {resp[offs_r:offs_r+len_r].hex()} ({len_r} bytes)")    
        print(f"     - S = {resp[offs_s:offs_s+len_s].hex()} ({len_s} bytes)")
        print(f"     - sigHashType = {bytes([resp[-1]]).hex()}")
        # If no expected sig provided, check sig DER encoding & sigHashType byte only
        if expected_resp is None:
            assert resp[0] & 0xFE == 0x30
            assert resp[1] == len_r + len_s + 4 == len(resp) - 3
            assert resp[offs_r - 2] == resp[offs_s - 2] == 0x02
            assert resp[-1] == 1
        else:
            assert resp == expected_resp

    def check_raw_apdu_resp(self, expected: str, received: str):
        # Not a very elegant way to skip sections of the received response that vary 
        # (marked with '-' chars in the expected response), but does the job
        assert len(received) == len(expected)
        for i in range(len(expected)):
            if expected[i] != '-':
                assert received[i] == expected[i] 

