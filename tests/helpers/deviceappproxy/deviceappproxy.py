import subprocess
import time
from typing import Optional, Union, List, cast
from ledgerblue.comm import getDongle
from ledgerblue.commTCP import DongleServer
from .apduabstract import BytesOrStr, CApdu


# decorator that try to connect to a physical dongle before executing a method
def dongle_connected(func: callable) -> callable:
    def wrapper(self, *args, **kwargs):
        if not hasattr(self, "dongle") or not hasattr(self.dongle, "opened") or not self.dongle.opened:
            self.dongle: DongleServer = cast(DongleServer, getDongle(False))
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
        self.dongle: Optional[DongleServer] = None
        self.chunk_size = chunk_size
        self.mnemonic = mnemonic
        self.process = None
        if not delay_connect:
            self.dongle = getDongle(debug)

    @dongle_connected
    def send_apdu(self,
                  apdu: Union[CApdu, bytes],
                  data: Optional[List[BytesOrStr]] = None,
                  p1_msb_means_next: bool = True) -> BytesOrStr:
        """Send APDUs to a Ledger device."""
        def _bytes(str_bytes: BytesOrStr) -> bytes:
            ret = str_bytes if type(str_bytes) is bytes \
                else bytes([cast(int, str_bytes)]) if type(str_bytes) is int \
                else bytes.fromhex(str_bytes) if type(str_bytes) is str else None
            if ret:
                return ret
            raise TypeError(f"{str_bytes} cannot be converted to bytes")

        def _set_p1(header: bytearray,
                    data_chunk: bytes,
                    chunks_list: List[bytes],
                    p1_msb_is_next_blk: bool) -> None:
            if p1_msb_is_next_blk:
                header[2] |= 0x80  # Set "Next block" signalization bit after 1st chunk.
            elif data_chunk == chunks_list[-1]:   # And p1 msb means "last block"
                header[2] |= 0x80     # Set "Last block" signalization bit for last chunk

        def _send_chunked_apdu(apdu_header: bytearray,
                               apdu_payload: bytes,
                               p1_msb_is_next: bool) -> bytes:
            resp: Optional[bytes] = None
            chunks = [apdu_payload[i:i + self.chunk_size] for i in range(0, len(apdu_payload), self.chunk_size)]
            for chunk in chunks:
                c_apdu = apdu_header + len(chunk).to_bytes(1, 'big') + chunk
                print(f"[device <] {c_apdu.hex()}")
                resp = self.dongle.exchange(bytes(c_apdu))
                chunk_resp = resp.hex() if len(resp) else "OK"
                print(f"[device >] {chunk_resp}")
                _set_p1(apdu_header, chunk, chunks, p1_msb_is_next)
            return resp

        # Get the APDU as bytes & send them to device
        hdr: bytearray = bytearray(apdu[0:4])
        response: BytesOrStr = None

        if data and len(data) > 1:
            # Payload already split in chunks of the appropriate lengths
            payload_chunks = [_bytes(d) for d in data]
            for _chunk in payload_chunks:
                capdu = bytearray(hdr + len(_chunk).to_bytes(1, 'big') + _chunk)
                print(f"[device <] {capdu.hex()}")
                if not hasattr(self, "dongle") or not hasattr(self.dongle, "opened") or not self.dongle.opened:
                    # In case a previous _send_chunked_apdu() call closed the dongle
                    self.dongle = getDongle(False)
                response = self.dongle.exchange(capdu)
                _resp = response.hex() if len(response) else "OK"
                print(f"[device >] {_resp}")
                _set_p1(hdr, _chunk, payload_chunks, p1_msb_means_next)
        else:
            # Payload is a single chunk. Perform auto splitting, if necessary, of large payloads into chunks of
            # equal length until payload is exhausted
            response = _send_chunked_apdu(apdu_header=hdr,
                                          apdu_payload=data[0],
                                          p1_msb_is_next=p1_msb_means_next)
        return response

    @dongle_connected
    def send_raw_apdu(self,
                      apdu: bytes) -> BytesOrStr:
        print(f"[device <] {apdu.hex()}")
        response: BytesOrStr = self.dongle.exchange(apdu)
        _resp: Union[bytes, str] = response.hex() if len(response) else "OK"
        print(f"[device >] {_resp}")
        return response

    def close(self) -> None:
        if hasattr(self, "dongle"):
            if hasattr(self.dongle, "opened") and self.dongle.opened:
                cast(DongleServer, self.dongle).close()
            self.dongle = None

    def run(self,
            speculos_path: str,
            app_path: str,
            library_path: Optional[str] = None,
            model: Union[str, str] = 'nanos',
            sdk: str = '1.6',
            args: Optional[List] = None,
            headless: bool = True,
            finger_port: int = 0,
            deterministic_rng: str = "",
            rampage: str = ""):
        """Launch an app within Speculos"""

        # if the app is already running, do nothing
        if self.process:
            return

        cmd = [speculos_path, '--seed', self.mnemonic, '--model', model, '--sdk', sdk]
        if args:
            cmd += args
        if headless:
            cmd += ['--display', 'headless']
        if finger_port:
            cmd += ['--finger-port', str(finger_port)]
        if deterministic_rng:
            cmd += ['--deterministic-rng', deterministic_rng]
        if rampage:
            cmd += ['--rampage', rampage]
        if library_path:
            cmd += ['-l', 'Bitcoin:' + library_path]
        cmd += [app_path]

        print('[*]', cmd)
        self.process = subprocess.Popen(cmd)
        time.sleep(1)

    def stop(self):
        # if the app is already running, do nothing
        if not self.process:
            return

        if self.process.poll() is None:
            self.process.terminate()
            time.sleep(0.2)
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait()
