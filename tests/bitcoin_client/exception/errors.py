class UnknownDeviceError(Exception):
    pass


class IncorrectLengthError(Exception):
    pass


class CommandIncompatibleFileStructureError(Exception):
    pass


class SecurityStatusNotSatisfiedError(Exception):
    pass


class ConditionOfUseNotSatisfiedError(Exception):
    pass


class IncorrectDataError(Exception):
    pass


class NotEnoughMemorySpaceError(Exception):
    pass


class ReferencedDataNotFoundError(Exception):
    pass


class FileAlreadyExistsError(Exception):
    pass


class SwapWithoutTrustedInputsError(Exception):
    pass


class IncorrectP1P2Error(Exception):
    pass


class InsNotSupportedError(Exception):
    pass


class ClaNotSupportedError(Exception):
    pass


class TechnicalProblemError(Exception):
    pass


class MemoryProblemError(Exception):
    pass


class NoEFSelectedError(Exception):
    pass


class InvalidOffsetError(Exception):
    pass


class FileNotFoundError(Exception):
    pass


class InconsistentFileError(Exception):
    pass


class AlgorithmNotSupportedError(Exception):
    pass


class InvalidKCVError(Exception):
    pass


class CodeNotInitializedError(Exception):
    pass


class AccessConditionNotFullfilledError(Exception):
    pass


class ContradictionSecretCodeStatusError(Exception):
    pass


class ContradictionInvalidationError(Exception):
    pass


class CodeBlockedError(Exception):
    pass


class MaxValueReachedError(Exception):
    pass


class GPAuthFailedError(Exception):
    pass


class LicensingError(Exception):
    pass


class HaltedError(Exception):
    pass
