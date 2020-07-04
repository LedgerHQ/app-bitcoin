from typing import List, Dict, Union, Optional
from dataclasses import dataclass, field
from functools import reduce


# Type aliases
BytesOrStr = Union[bytes, str]


@dataclass
class CApdu:
    @dataclass
    class Type:
        IN: int = 0
        OUT: int = 1
        INOUT: int = 2
    cla: BytesOrStr = field(default="00")
    ins: BytesOrStr = field(default="00")
    p1: BytesOrStr = field(default="00")
    p2: BytesOrStr = field(default="00")
    lc: BytesOrStr = field(default="00")
    le: BytesOrStr = field(default="00")
    data: BytesOrStr = field(default="")
    typ: Type = field(default=Type.INOUT)


ApduDict = Dict[str, CApdu]


class ApduSet:
    """Collects a set of CApdu objects and provides their raw version, ready
    to be sent to a device/an app"
    """
    _apdus: ApduDict = {}
    
    def __init__(self, apdus: Optional[ApduDict] = None, max_lc: int = 255 ) -> None:
        self.apdus = apdus
        self.max_lc = max_lc
    
    def _bytes(self, data: BytesOrStr) -> bytes:
        if type(data) is bytes:
            return data
        if type(data) is int:
            return bytes([data])
        if type(data) is str:
            return bytes.fromhex(data)
        raise TypeError(f"{data} cannot be converted to bytes")

    def _bytesbuf(self, apdu: CApdu, apdu_keys: List[str]) -> bytes:
        """Concatenates all @apdu attributes whose names are provided in @apdu_keys,
        into a single byte buffer.
        """
        return reduce(lambda x, y: x + y, 
                      [self._bytes(getattr(apdu, k)) for k in apdu.__dict__ if k in apdu_keys])

    @property
    def apdus(self) -> Optional[ApduDict]:
        return ApduSet._apdus if len(ApduSet._apdus.keys()) > 0 else None

    @apdus.setter
    def apdus(self, newApdus: ApduDict, overwrite: bool = False) -> None:
        """Sets a new CApsu internal dictionary if it wasn't set at instanciation time,
        unless overwrite is True."""
        if not self.apdus or overwrite is True:
            if type(newApdus) is not dict:
                raise ValueError("Attribute newApdus must be a dictionary containing CApdu instances as values")
            ApduSet._apdus = newApdus

    def apdu(self, name: str, 
             p1: Optional[BytesOrStr] = None, 
             p2: Optional[BytesOrStr] = None,
             data: Optional[BytesOrStr] = None,
             le: Optional[BytesOrStr] = None) -> bytes:
        """Returns the raw bytes for the APDU requested by name.
        """
        if not self.apdus:
            raise ValueError("ApduSet object is empty! Provide an ApduDict either at instanciation"\
                             " or with the 'apdus' attribute.")
        if name not in self.apdus:
            raise KeyError(f"{name} APDU is not supported by this instance")
        # Compose APDU depending on its type into a byte buffer
        self.set_params(key=name, p1=p1, p2=p2, data=data, le=le)
        return self._bytesbuf(
            self.apdus[name], 
            ('cla', 'ins', 'p1', 'p2', 
             'lc' if self._apdus[name].typ == CApdu.Type.IN or self._apdus[name].typ == CApdu.Type.INOUT 
                else 'le' if self._apdus[name].typ == CApdu.Type.OUT
                else '00',
             'data' if self._apdus[name].typ == CApdu.Type.IN or self._apdus[name].typ == CApdu.Type.INOUT
                else ''
            )
        )

    def __setitem__(self, key: str, value: CApdu) -> None:
        """Change an existing APDU or add a new one to the APDU dict
        """ 
        if type(value) is not CApdu:
            raise ValueError(f"Syntax '{self.__class__.__name__}[{key}] = value' only accept CApdu instances as value")
        self.apdus[key] = value

    def set_params(self, key: str, 
                  p1: Optional[BytesOrStr] = None, 
                  p2: Optional[BytesOrStr] = None, 
                  data: Optional[BytesOrStr] = None,
                  le: Optional[BytesOrStr] = None) -> None:
        """Set the parameters and payload of a specific APDU
        """
        # Check all params
        if self.apdus.keys() is None or key not in self.apdus:
            raise KeyError(f"{key} APDU is not supported by this instance (or instance is empty?)")
        params_valid = reduce(lambda x, y: x and y, 
                              [True if type(param) in [str, bytes] else False for param in (p1, p2, data)])
        if not params_valid:
            raise ValueError("Parameters must either be single byte (p1, p2),multiple bytes (data) or an hex string"
                             " adhering to these constraints")
        # Set APDU parameters & payload
        if (p1 is not None and len(self._bytes(p1)) > 1)\
        or (p2 is not None and len(self._bytes(p2)) > 1)\
        or (le is not None and len(self._bytes(le)) > 1):
            raise ValueError("When provided, P1, P2 and Le parameters must be 1-byte long")
        #Set default values for p1, p2 and le if they were not provided
        self.apdus[key].p1 = self._bytes(p1) if p1 is not None else self._bytes("00")
        self.apdus[key].p2 = self._bytes(p2) if p2 is not None else self._bytes("00")
        self.apdus[key].le = self._bytes(le) if le is not None else self._bytes("00")
        # Format the binary APD
        if data is not None:
            datalen = len(self.apdus[key].data)
            self.apdus[key].data = self._bytes(data)
            if self.apdus[key].typ in (CApdu.Type.IN, CApdu.Type.INOUT):
                self.apdus[key].lc = bytes([datalen if datalen < self.max_lc else 0])
            elif self.apdus[key].typ == CApdu.Type.OUT:
                self.apdus[key].le = bytes(le)



### TODO: Not ready, to be completed later to replace list of chunks lengths
#@dataclass
#class Tx:
#    @dataclass
#    class Inputs:
#        prevout_hash: bytes = field(default=bytes(32))
#        prevout_index: bytes = field(default=bytes(4))
#        script_sig_len: bytes   # Varint
#        script_sig: bytes 
#        sequence: bytes = field(default=bytes(4))
#
#    @dataclass
#    class Outputs:
#        value: bytes = field(default=bytes(8))
#        pubkey_script_len: bytes    # Varint
#        pubkey_script: bytes        # Variable length
#
#    version: bytes = field(default=bytes(4))
#    flag: Optional[bytes] = field(default=bytes(2))
#    inputs_count: bytes     # Varint
#    inputs: List[Inputs]    # variable length
#    outputs_count: bytes    # Varint
#    outputs: List[Outputs]  # variable length
#    witness_count: bytes    # Varint
#    witness: List[Witness]  # VAriable length
#    locktime: bytes = field(default=bytes(4))
#
#    @classmethod
#    def parse(cls, rawtx: BytesOrStr) -> None:
#        pass
#
