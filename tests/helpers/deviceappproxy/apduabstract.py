from typing import List, Dict, Optional, cast, NewType, Tuple, AnyStr
from dataclasses import dataclass, field


@dataclass
class CApdu:
    class Type:
        IN: int = 0
        OUT: int = 1
        INOUT: int = 2
    data: List[bytes]
    cla: AnyStr = field(default="00")
    ins: AnyStr = field(default="00")
    p1: AnyStr = field(default="00")
    p2: AnyStr = field(default="00")
    lc: AnyStr = field(default="00")
    le: AnyStr = field(default="00")
    typ: Type = field(default=Type.INOUT)


ApduDict = NewType("ApduDict", Dict[str, CApdu])


class ApduSet:
    """Collects a set of CApdu objects and provides their raw version, ready
    to be sent to a device/an app"
    """
    _apdus: ApduDict = {}

    def __init__(self, apdus: Optional[ApduDict] = None, max_lc: int = 255) -> None:
        self.apdus = apdus
        self.max_lc = max_lc

    @staticmethod
    def _bytes(data: AnyStr) -> bytes:
        if isinstance(data, (bytes, bytearray)):
            return data
        if isinstance(data, int):
            return bytes([cast(int, data)])
        if isinstance(data, str):
            return bytes.fromhex(data)
        raise TypeError(f"{data} cannot be converted to bytes")

    @property
    def apdus(self) -> Optional[ApduDict]:
        return ApduSet._apdus if len(ApduSet._apdus.keys()) > 0 else None

    @apdus.setter
    def apdus(self, new_apdus: ApduDict, overwrite: bool = False) -> None:
        """Sets a new CApsu internal dictionary if it wasn't set at instanciation time,
        unless overwrite is True."""
        if not self.apdus or overwrite is True:
            if not isinstance(new_apdus, dict):
                raise ValueError("Attribute newApdus must be a dictionary containing CApdu "
                                 "instances as values")
            ApduSet._apdus = new_apdus

    def apdu(self, name: str,
             p1: Optional[AnyStr] = None,
             p2: Optional[AnyStr] = None,
             data: Optional[List[AnyStr]] = None,
             le: Optional[AnyStr] = None) -> Tuple[bytes, List[Optional[bytes]]]:
        """Returns the raw bytes for the C-APDU header requested by name.
        """

        def _bytesbuf(apdu: CApdu, apdu_keys: List[str]) -> bytes:
            """Concatenates all @apdu attributes whose names are provided in @apdu_keys,
            into a single byte buffer."""
            return b''.join(self._bytes(getattr(apdu, k)) if k in apdu.__dict__ else self._bytes(k) for k in apdu_keys)

        if not self.apdus:
            raise ValueError("ApduSet object is empty! Provide an ApduDict either at instanciation"
                             " or with the 'apdus' attribute.")
        if name not in self.apdus:
            raise KeyError(f"{name} APDU is not supported by this instance")
        # Compose APDU depending on its type into a byte buffer
        self.set_params(key=name, p1=p1, p2=p2, data=data, le=le)
        # Determine APDU type
        apdu_is_in_only_or_inout: bool = self._apdus[name].typ == CApdu.Type.IN \
                                         or self._apdus[name].typ == CApdu.Type.INOUT
        apdu_is_out_only: bool = self._apdus[name].typ == CApdu.Type.OUT
        # Return the C-APDU header with correct Lc
        return (
            _bytesbuf(
                self.apdus[name],
                ['cla', 'ins', 'p1', 'p2', 'lc' if apdu_is_in_only_or_inout else 'le' if apdu_is_out_only else '00']
            ),
            self.apdus[name].data
        )

    def __setitem__(self, key: str, value: CApdu) -> None:
        """Change an existing APDU or add a new one to the APDU dict
        """
        if not isinstance(value, CApdu):
            raise ValueError(f"Syntax '{self.__class__.__name__}[{key}] = value' "
                             f"only accept CApdu instances as value")
        self.apdus[key] = value

    def set_params(self, key: str,
                   p1: Optional[AnyStr] = None,
                   p2: Optional[AnyStr] = None,
                   data: Optional[List[AnyStr]] = None,
                   le: Optional[AnyStr] = None):
        """Set the parameters and payload of a specific APDU
        """
        # Check all params
        if self.apdus.keys() is None or key not in self.apdus:
            raise KeyError(f"{key} APDU is not supported by this instance (or instance is empty?)")
        params_valid: bool = all(bool(isinstance(param, (str, bytes, list))) for param in (p1, p2, data))
        if not params_valid:
            raise ValueError("Parameters must either be single byte (e.g. p1 or p2), multiple bytes"
                             " (e.g. data) or an hex string adhering to these constraints")
        # Set APDU parameters & payload
        params_invalid: bool = any(bool(param and len(self._bytes(param)) > 1) for param in (p1, p2, le))
        if params_invalid:
            raise ValueError("When provided, P1, P2 and Le parameters must be 1-byte long")

        # Set default values for p1, p2 and le if they were not provided
        self.apdus[key].p1 = self._bytes(p1) if p1 is not None else self._bytes("00")
        self.apdus[key].p2 = self._bytes(p2) if p2 is not None else self._bytes("00")
        self.apdus[key].le = self._bytes(le) if le is not None else self._bytes("00")
        if data is not None:
            # Concatenate payload chunks to compute Lc
            data_len: int = len(b''.join(data))
            self.apdus[key].data = [self._bytes(d) for d in data if d is not None]
            if self.apdus[key].typ in (CApdu.Type.IN, CApdu.Type.INOUT):
                self.apdus[key].lc = data_len.to_bytes(1, 'big') if data_len < self.max_lc else b'\x00'
            elif self.apdus[key].typ == CApdu.Type.OUT:
                self.apdus[key].le = self._bytes(le) if le is not None else b'\x00'
