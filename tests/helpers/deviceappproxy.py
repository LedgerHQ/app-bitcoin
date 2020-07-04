from typing import Optional, List
from .apduabstract import BytesOrStr
from ledgerblue.comm import getDongle, CommException


#decorator that try to connect to a physical dongle before executing a method
def dongle_connected(func: callable) -> callable:
    def wrapper(self, *args, **kwargs):
        if not hasattr(self, "dongle") or not hasattr(self.dongle, "opened") or not self.dongle.opened:
            self.dongle = getDongle(False)
        ret = func(self, *args, **kwargs)
        self.close()
        return ret
    return wrapper


class DeviceAppProxy:

    def __init__(self, 
                mnemonic: str = "",
                debug: bool = True,
                delay_connect: bool = True,
                chunk_size: int = 200 + 11) -> None:
        self.chunk_size = chunk_size
        self.mnemonic = mnemonic
        if not delay_connect:
            self.dongle = getDongle(debug)

    @dongle_connected
    def sendApdu(self, 
                  name: str, 
                  p1: BytesOrStr, 
                  p2: BytesOrStr, 
                  data: Optional[BytesOrStr] = None,
                  le: Optional[BytesOrStr] = None, 
                  chunks_lengths: Optional[List[int]] = None) -> bytes:
        # Get the APDU as bytes & send them to device
        apdu = self.btc.apdu(name, p1=p1, p2=p2, data=data, le=le)
        hdr = apdu[0:4]
        payload = apdu[5:]

        if chunks_lengths:
            # Large APDU is split in chunks the lengths of which are provided in chunks_lengths param
            offs = 0
            skip_bytes = 0
            for i in range(len(chunks_lengths)):
                if i > 0:
                    hdr = hdr[:2] + (hdr[2] | 0x80).to_bytes(1, 'big') + hdr[3:]
                chunk_len = chunks_lengths[i]
                
                if type(chunk_len) is tuple:
                    if len(chunk_len) not in (2, 3):
                        raise ValueError("Tuples in chunks_lengths must contain exactly 2 ou 3 integers e.g. (offset, len) or (len1, skip_len, len2)")
                    if len(chunk_len) == 2:     # chunk_len = (offset, len)
                        offs = chunk_len[0]
                        chunk_len = chunk_len[1]
                        chunk = payload[offs:offs+chunk_len]
                    else:                       # chunk_len = (len1, skip_len, len2)
                        skip_bytes = chunk_len[1]
                        chunk = payload[offs:offs+chunk_len[0]]
                        start_chunk2 = offs + chunk_len[0] + skip_bytes
                        chunk += payload[start_chunk2:start_chunk2+chunk_len[2]]
                        chunk_len = chunk_len[0] + chunk_len[2]
                elif chunk_len != -1:   # type is int
                    chunk = payload[offs:offs+chunk_len]

                if chunk_len == -1:     # inputs, total length is in last byte of previous chunks
                    total_len = int(payload[offs - 1]) + 4
                    response = self._send_chunked_apdu(apdu=hdr, data=payload[offs:offs+total_len])
                    offs += total_len
                else:            
                    capdu = hdr + chunk_len.to_bytes(1,'big') + chunk
                    print(f"[device <] {capdu.hex()}")
                    if not hasattr(self, "dongle") or not hasattr(self.dongle, "opened") or not self.dongle.opened:
                        self.dongle = getDongle(False)  # in case a previous self.send_chunked_apdu() call closed it
                    response = self.dongle.exchange(capdu)
                    offs += chunk_len + skip_bytes
                    skip_bytes = 0
                    _resp = response.hex() if len(response) else "OK"
                    print(f"[device >] {_resp}")
        else:
            # Auto splitting of large APDUs into chunks of equal length until payload is exhausted
            response = self._send_chunked_apdu(apdu=hdr, data=payload)        
        return response

    @dongle_connected
    def sendRawApdu(self, 
                    apdu: bytes) -> bytes:
        print(f"[device <] {apdu.hex()}")
        response = self.dongle.exchange(apdu)
        _resp = response.hex() if len(response) else "OK"
        print(f"[device >] {_resp}")
        return response

    @dongle_connected
    def _send_chunked_apdu(self, 
                           apdu: bytes, 
                           data: bytes) -> bytes:
        for chunk in [data[i:i + self.chunk_size] for i in range(0, len(data), self.chunk_size)]:
            # tmp test overflow
            # if len(chunk) < chunkSize:
            #    print("increasing virtually last apdu")
            #    chunk += b'\x99'
            # 6A82 expected in this case
            capdu = apdu + len(chunk).to_bytes(1,'big') + chunk
            print(f"[device <] {capdu.hex()}")
            response = self.dongle.exchange(bytes(capdu))
            _resp = response.hex() if len(response) else "OK"
            print(f"[device >] {_resp}")
            apdu = apdu[:2] + (apdu[2] | 0x80).to_bytes(1,'big') + apdu[3:]

        return response

    def close(self) -> None:
        if hasattr(self, "dongle"):
            if hasattr(self.dongle, "opened") and self.dongle.opened:
                self.dongle.close()
            self.dongle = None
