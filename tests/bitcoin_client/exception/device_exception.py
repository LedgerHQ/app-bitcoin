import enum
from typing import Dict, Any, Optional

from .errors import *


class DeviceException(Exception):  # pylint: disable=too-few-public-methods
    exc: Dict[int, Any] = {
        0x6700: IncorrectLengthError,
        0x6981: CommandIncompatibleFileStructureError,
        0x6982: SecurityStatusNotSatisfiedError,
        0x6985: ConditionOfUseNotSatisfiedError,
        0x6A80: IncorrectDataError,
        0x6A84: NotEnoughMemorySpaceError,
        0x6A88: ReferencedDataNotFoundError,
        0x6A89: FileAlreadyExistsError,
        0x6A8A: SwapWithoutTrustedInputsError,
        0x6B00: IncorrectP1P2Error,
        0x6D00: InsNotSupportedError,
        0x6E00: ClaNotSupportedError,
        0x6F00: TechnicalProblemError,
        0x9240: MemoryProblemError,
        0x9400: NoEFSelectedError,
        0x9402: InvalidOffsetError,
        0x9404: FileNotFoundError,
        0x9408: InconsistentFileError,
        0x9484: AlgorithmNotSupportedError,
        0x9485: InvalidKCVError,
        0x9802: CodeNotInitializedError,
        0x9804: AccessConditionNotFullfilledError,
        0x9808: ContradictionSecretCodeStatusError,
        0x9810: ContradictionInvalidationError,
        0x9840: CodeBlockedError,
        0x9850: MaxValueReachedError,
        0x6300: GPAuthFailedError,
        0x6F42: LicensingError,
        0x6FAA: HaltedError
    }

    def __new__(cls,
                error_code: int,
                ins: Optional[enum.IntEnum] = None,
                message: str = ""
                ) -> Any:
        error_message: str = (f"Error in {ins!r} command"
                              if ins else "Error in command")

        if error_code in DeviceException.exc:
            return DeviceException.exc[error_code](hex(error_code),
                                                   error_message,
                                                   message)

        return UnknownDeviceError(hex(error_code), error_message, message)
