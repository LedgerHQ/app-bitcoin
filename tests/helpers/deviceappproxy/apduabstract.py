from typing import List, Dict, Optional, Union, cast, NewType, Tuple, AnyStr
# from dataclasses import dataclass, field

ApduType = NewType("ApduType", int)


# @dataclass
class CApdu:
    """
    Dataclass representing the various parts of a Command APDU (C-APDU), as defined by
    the ISO 7916-3 standard (see for details).

    The attributes of that class map the APDU fields defined by the standard as follow:

    | Attribute | ISO 7816-3 | Meaning                                                                     |
    |           | field name |                                                                             |
    |:---------:|:----------:|-----------------------------------------------------------------------------|
    |    cla    |    CLA     | CLAss byte: provides  secure apps segregation.                              |
    |    ins    |    INS     | INStruction byte: the action the secure app needs to perform                |
    |    p1     |     P1     | Parameter byte 1: allows to parameterize the selected action                |
    |    p2     |     P2     | Parameter byte 2: as above                                                  |
    |    lc     |     Lc     | Length in bytes of the incoming payload data (0 if None)                    |
    |   data    |    Data    | Optional incoming payload data related to action to perform                 |
    |    le     |     Le     | Expected length (bytes) of optional outgoing response data (absent if None) |

    Attribute typ is the C-APDU type among:
    - INcoming: command provides an Lc-byte long input data payload, expects no response data
    - OUTgoing: command provides no input payload, but expects an Le-byte long response back
    - INOUT: command is both incoming and outgoing
    """
    class Type:
        IN: ApduType = 0
        OUT: ApduType = 1
        INOUT: ApduType = 2

    # Max length data that can be sent in a raw C-APDU payload is the same
    # for all CApdu instances hence it is a class attribute
    max_lc: int = 255

    def __init__(self,
                 typ: ApduType = Type.INOUT,
                 cla: AnyStr = "00",
                 ins: AnyStr = "00",
                 p1: AnyStr = "00",
                 p2: AnyStr = "00",
                 data: Union[List[AnyStr], Tuple[AnyStr]] = (),
                 le: AnyStr = "00",
                 max_lc: int = 255) -> None:
        self.data: List[bytes] = data if data else []
        self.cla: AnyStr = cla
        self.ins: AnyStr = ins
        self.p1: AnyStr = p1
        self.p2: AnyStr = p2
        self.lc: AnyStr = "00"
        self.le: AnyStr = le
        self.typ: ApduType = typ
        CApdu.max_lc = max_lc

    @staticmethod
    def _bytes(data: AnyStr) -> bytes:
        if isinstance(data, (bytes, bytearray)):
            return data
        if isinstance(data, int):
            return bytes([cast(int, data)])
        if isinstance(data, str):
            return bytes.fromhex(data)
        raise TypeError(f"{data} cannot be converted to bytes")

    def _bytesbuf(self, apdu_keys: List[str]) -> bytes:
        """Concatenates all @apdu attributes whose names are provided in @apdu_keys,
        into a single byte buffer. If an element of apdu_keys is not a CApdu attribute name,
         then it must be a string representing an hex integer."""
        return b''.join(self._bytes(getattr(self, k)) if k in self.__dict__ else self._bytes(k) for k in apdu_keys)

    @classmethod
    def set_max_lc(cls, max_lc):
        cls.max_lc = max_lc

    def set_params(self,
                   p1: Optional[AnyStr] = None,
                   p2: Optional[AnyStr] = None,
                   data: Optional[List[AnyStr]] = None,
                   le: Optional[AnyStr] = None):
        """Updates the p1, p2, data and le attributes a CApdu instance
        """
        # Check all params
        params_invalid: bool = any(bool(param and len(self._bytes(param)) > 1) for param in (p1, p2, le))
        if params_invalid:
            raise ValueError("When provided, P1, P2 and Le parameters must be 1-byte long")

        # Set APDU parameters & payload
        self.p1 = self._bytes(p1) if p1 else self._bytes("00")
        self.p2 = self._bytes(p2) if p2 else self._bytes("00")
        self.le = self._bytes(le) if le else self._bytes("00")
        if data:
            # Concatenate payload chunks to compute Lc
            data_len: int = len(b''.join(data))
            self.data = [self._bytes(d) for d in data if d is not None]
            if self.typ in (CApdu.Type.IN, CApdu.Type.INOUT):
                self.lc = data_len.to_bytes(1, 'big') if data_len < CApdu.max_lc else b'\x00'
            elif self.typ == CApdu.Type.OUT:
                self.le = self._bytes(le) if le is not None else b'\x00'

    @property
    def header(self) -> bytes:
        # Determine APDU type
        apdu_is_in_only_or_inout = (self.typ == CApdu.Type.IN or self.typ == CApdu.Type.INOUT)
        apdu_is_out_only = (self.typ == CApdu.Type.OUT)
        # Concatenate the individual C-APDU header fields into a 5-byte buffer
        return self._bytesbuf(
            ['cla', 'ins', 'p1', 'p2', 'lc' if apdu_is_in_only_or_inout else 'le' if apdu_is_out_only else '00']
        )


ApduDictType = NewType("ApduDictType", Dict[str, CApdu])


class ApduDict:
    """
    Collects a set of CApdu objects and provides their raw byte version.

    Once the payload for an APDU defined in the stored CApdu object is provided, this class
    computes the correct values of the Lc and Le bytes that are part of the C-APDU header
    before returning the bytes buffer, containing the fully formatted C-APDU ready to be sent
    to a secure app running on a Ledger Device or Speculos.

    This class doesn't manage the transport layer of ISO 7816-3 (i.e. T=0/T=1). This part
    is delegated to the DeviceAppProxy class.
    """
    def __init__(self, apdus: Optional[ApduDictType] = None, max_lc: int = 255) -> None:
        # We expect an ApduDictType object which entries each associate a symbolic APDU command name
        # to a CApdu instance containing the values of the various fields of that command.
        self._apdus = apdus
        # self._max_lc = max_lc
        # Set CApdu class attribute max_lc through the 1st dict element
        list(self._apdus.values())[0].set_max_lc(max_lc)

    @property
    def apdus(self) -> Optional[ApduDictType]:
        return self._apdus if len(self._apdus.keys()) > 0 else None

    def apdu(self, name: str,
             p1: Optional[AnyStr] = None,
             p2: Optional[AnyStr] = None,
             data: Optional[List[AnyStr]] = None,
             le: Optional[AnyStr] = None) -> Tuple[bytes, List[Optional[bytes]]]:
        """
        Returns the raw bytes for the C-APDU header requested by name, as a tuple of elements
        ready to be unpacked and passed as parameters to the DeviceAppProxy.send_apdu() method.
        """
        # Set values provided by caller for p1, p2, data and le in internal ApduDict object.
        # When building the full APDU later, the fields not provided will use the defaults set
        # in the ApduDict's CApdu instances.
        self._apdus[name].set_params(p1=p1, p2=p2, data=data, le=le)
        # self.set_params(key=name, p1=p1, p2=p2, data=data, le=le)

        # Return a tuple composed of 2 byte buffers: the C-APDU header buffer (i.e. CLA || INS || P1 || P2 || Lc/Le)
        # and the payload data buffer.
        return self._apdus[name].header, self._apdus[name].data
