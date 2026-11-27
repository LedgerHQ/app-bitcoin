import base64
import enum
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple, Union

from packaging.version import parse as parse_version

from . import _native
from .common import Chain
from .exception import DeviceException
from .transport import ApduException, TransportClient
from .wallet import WalletPolicy


class BitcoinInsType(enum.IntEnum):
    GET_EXTENDED_PUBKEY = 0x00
    GET_VERSION = 0x01
    REGISTER_WALLET = 0x02
    GET_WALLET_ADDRESS = 0x03
    SIGN_PSBT = 0x04
    GET_MASTER_FINGERPRINT = 0x05
    SIGN_MESSAGE = 0x10


@dataclass(frozen=True)
class PartialSignature:
    """Represents a partial signature returned by sign_psbt. Such objects can be added to the PSBT.

    It always contains a pubkey and a signature.
    The pubkey is a compressed 33-byte for legacy and segwit Scripts, or 32-byte x-only key for taproot.
    The signature is in the format it would be pushed on the scriptSig or the witness stack, therefore of
    variable length, and possibly concatenated with the SIGHASH flag byte if appropriate.

    The tapleaf_hash is also filled if signing for a tapscript.

    Note: not to be confused with 'partial signature' of protocols like MuSig2;
    """
    pubkey: bytes
    signature: bytes
    tapleaf_hash: Optional[bytes] = None


@dataclass(frozen=True)
class MusigPubNonce:
    """Represents a pubnonce returned by sign_psbt during the first round of a Musig2 signing session.

    It always contains
    - the participant_pubkey, a 33-byte compressed pubkey;
    - aggregate_pubkey, the 33-byte compressed pubkey key that is the aggregate of all the participant
      pubkeys, with the necessary tweaks; its x-only version is the key present in the Script;
    - the 66-byte pubnonce.

    The tapleaf_hash is also filled if signing for a tapscript; `None` otherwise.
    """
    participant_pubkey: bytes
    aggregate_pubkey: bytes
    tapleaf_hash: Optional[bytes]
    pubnonce: bytes


@dataclass(frozen=True)
class MusigPartialSignature:
    """Represents a partial signature returned by sign_psbt during the second round of a Musig2 signing session.

    It always contains
    - the participant_pubkey, a 33-byte compressed pubkey;
    - aggregate_pubkey, the 33-byte compressed pubkey key that is the aggregate of all the participant
      pubkeys, with the necessary tweaks; its x-only version is the key present in the Script;
    - the partial_signature, the 32-byte partial signature for this participant.

    The tapleaf_hash is also filled if signing for a tapscript; `None` otherwise
    """
    participant_pubkey: bytes
    aggregate_pubkey: bytes
    tapleaf_hash: Optional[bytes]
    partial_signature: bytes


@dataclass(frozen=True)
class UnknownSignPsbtYieldedObject:
    """Represents an unknown object returned by sign_psbt, for forward compatibility.

    It contains the tag and the opaque bytes returned by the device.
    """
    tag: int
    data: bytes


SignPsbtYieldedObject = Union[PartialSignature,
                              MusigPubNonce, MusigPartialSignature, UnknownSignPsbtYieldedObject]


_YIELDED_TYPES = {
    "partial_signature": PartialSignature,
    "musig_pubnonce": MusigPubNonce,
    "musig_partial_signature": MusigPartialSignature,
    "unknown": UnknownSignPsbtYieldedObject,
}


def print_apdu(apdu_dict: dict) -> None:
    serialized_apdu = b''.join([
        apdu_dict["cla"].to_bytes(1, byteorder='big'),
        apdu_dict["ins"].to_bytes(1, byteorder='big'),
        apdu_dict["p1"].to_bytes(1, byteorder='big'),
        apdu_dict["p2"].to_bytes(1, byteorder='big'),
        len(apdu_dict["data"]).to_bytes(1, byteorder='big'),
        apdu_dict["data"]
    ])
    print(f"=> {serialized_apdu.hex()}")


def print_response(sw: int, data: bytes) -> None:
    print(f"<= {data.hex()}{sw.to_bytes(2, byteorder='big').hex()}")


def _psbt_bytes(psbt: Any) -> bytes:
    """The binary serialization of a PSBT given as bytes (binary), as a base64 string, or as an
    object whose `serialize()` method returns either."""
    if hasattr(psbt, "serialize"):
        psbt = psbt.serialize()
    if isinstance(psbt, str):
        return base64.b64decode(psbt)
    if isinstance(psbt, (bytes, bytearray)):
        return bytes(psbt)
    raise TypeError("The PSBT must be bytes, a base64 string, or have a serialize() method")


def _check_wallet(wallet: WalletPolicy) -> None:
    if not isinstance(wallet, WalletPolicy):
        raise ValueError("wallet type must be WalletPolicy, with version either WALLET_POLICY_V1 or WALLET_POLICY_V2")


class Client:
    """Client for the Ledger Bitcoin application, version 2.1.0 or later.

    The protocol is implemented by the Rust client of the Bitcoin application, which this
    package wraps; this class owns the transport and runs the exchanges. To use a different
    transport, a subclass can override `_apdu_exchange`.
    """

    def __init__(self, transport_client: TransportClient, chain: Chain = Chain.MAIN, debug: bool = False) -> None:
        self.transport_client = transport_client
        self.chain = chain
        self.debug = debug

    def _apdu_exchange(self, apdu: dict) -> Tuple[int, bytes]:
        """Sends one APDU, given as a dict with the keys cla, ins, p1, p2 and data; returns the
        status word and the response data."""
        try:
            if self.debug:
                print_apdu(apdu)

            response = self.transport_client.apdu_exchange(**apdu)
            if self.debug:
                print_response(0x9000, response)

            return 0x9000, response
        except ApduException as e:
            if self.debug:
                print_response(e.sw, e.data)

            return e.sw, e.data

    def _run(self, operation: _native.Operation) -> Any:
        """Runs the exchanges of a native operation, and returns its output."""
        apdu = operation.next_apdu()
        while apdu is not None:
            cla, ins, p1, p2, data = apdu
            sw, response = self._apdu_exchange({"cla": cla, "ins": ins, "p1": p1, "p2": p2, "data": data})
            try:
                apdu = operation.step(sw, bytes(response))
            except _native.DeviceError as e:
                ins, sw, _ = e.args
                try:
                    ins = BitcoinInsType(ins)
                except ValueError:
                    pass
                raise DeviceException(error_code=sw, ins=ins) from None
        return operation.output()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.transport_client.stop()

    def stop(self) -> None:
        """Stops the transport_client."""

        self.transport_client.stop()

    def get_version(self) -> Tuple[str, str, bytes]:
        """Queries the hardware wallet for the currently running app's name, version and state flags.

        Returns
        -------
        Tuple[str, str, bytes]
            The first element is the app's name, as a short string.
            The second element is the app's version.
            The third element is a binary string representing the platform's global state (pin lock etc).
        """
        return self._run(_native.Operation.get_version())

    def get_extended_pubkey(self, path: str, display: bool = False) -> str:
        """Gets the serialized extended public key for certain BIP32 path. Optionally, validate with the user.

        Parameters
        ----------
        path : str
            BIP32 path of the public key you want.
        display : bool
            Whether you want to display address and ask confirmation on the device.

        Returns
        -------
        str
            The requested serialized extended public key.
        """
        return self._run(_native.Operation.get_extended_pubkey(path, display))

    def register_wallet(self, wallet: WalletPolicy) -> Tuple[bytes, bytes]:
        """Registers a wallet policy with the user. After approval returns the wallet id and hmac to be stored on the client.

        Before returning, the first receive address of the wallet is requested from the device,
        and verified independently.

        Parameters
        ----------
        wallet : WalletPolicy
            The Wallet policy to register on the device.

        Returns
        -------
        Tuple[bytes, bytes]
            The first element the 32-byte wallet id.
            The second element is the hmac.
        """
        _check_wallet(wallet)
        return self._run(_native.Operation.register_wallet(*wallet._native_args()))

    def get_wallet_address(
        self,
        wallet: WalletPolicy,
        wallet_hmac: Optional[bytes],
        change: int,
        address_index: int,
        display: bool,
    ) -> str:
        """For a given wallet that was already registered on the device (or a standard wallet that does not need registration),
        returns the address for a certain `change`/`address_index` combination.

        The address is verified independently before being returned.

        Parameters
        ----------
        wallet : WalletPolicy
            The registered wallet policy, or a standard wallet policy.

        wallet_hmac: Optional[bytes]
            For a registered wallet, the hmac obtained at wallet registration. `None` for a standard wallet policy.

        change: int
            0 for a standard receive address, 1 for a change address. Other values are invalid.

        address_index: int
            The address index in the last step of the BIP32 derivation.

        display: bool
            Whether you want to display address and ask confirmation on the device.

        Returns
        -------
        str
            The requested address.
        """
        _check_wallet(wallet)
        return self._run(_native.Operation.get_wallet_address(
            *wallet._native_args(), wallet_hmac, change, address_index, display))

    def sign_psbt(self, psbt: Union[bytes, str, Any], wallet: WalletPolicy, wallet_hmac: Optional[bytes]) -> List[Tuple[int, SignPsbtYieldedObject]]:
        """Signs a PSBT using a registered wallet (or a standard wallet that does not need registration).

        Signature requires explicit approval from the user.

        Parameters
        ----------
        psbt : bytes | str | object with a serialize() method
            A PSBT of version 0 or 2, either serialized (`bytes`), base64-encoded (`str`), or an
            object whose `serialize()` method returns either. Its fields are sent to the device
            exactly as serialized.

        wallet : WalletPolicy
            The registered wallet policy, or a standard wallet policy.

        wallet_hmac: Optional[bytes]
            For a registered wallet, the hmac obtained at wallet registration. `None` for a standard wallet policy.

        Returns
        -------
        List[Tuple[int, SignPsbtYieldedObject]]
            A list of tuples returned by the hardware wallets, where each element is a tuple of:
            - an integer, the index of the input being signed;
            - an instance of `PartialSignature`, `MusigPubNonce` or `MusigPartialSignature`, or
              `UnknownSignPsbtYieldedObject` for an object unknown to this version of the client.
        """
        _check_wallet(wallet)
        results = self._run(_native.Operation.sign_psbt(_psbt_bytes(psbt), *wallet._native_args(), wallet_hmac))
        return [(input_index, _YIELDED_TYPES[kind](**fields)) for input_index, kind, fields in results]

    def get_master_fingerprint(self) -> bytes:
        """Gets the fingerprint of the master public key, as per BIP-32.

        Returns
        -------
        bytes
            The fingerprint of the master public key, as an array of 4 bytes.
        """
        return self._run(_native.Operation.get_master_fingerprint())

    def sign_message(self, message: Union[str, bytes], bip32_path: str) -> str:
        """
        Signs a message using the legacy Bitcoin Core signed message format.
        The message is signed with the key corresponding to the BIP32 path.

        Parameters
        ----------
        message : str | bytes
            The message to be signed. A string is UTF-8 encoded.
        bip32_path : str
            The BIP32 derivation for the key to sign the message.

        Returns
        -------
        str
            The Base64-encoded signature.
        """
        if isinstance(message, str):
            message = message.encode("utf-8")

        signature = self._run(_native.Operation.sign_message(message, bip32_path))
        return base64.b64encode(signature).decode('utf-8')


# Before version 1.0.0 of this package, `Client` was the base class of `NewClient` and of the
# client for legacy versions of the app.
NewClient = Client


class UnsupportedAppVersionError(Exception):
    """The running app is older than version 2.1.0, which this client does not support."""


def createClient(comm_client: Optional[TransportClient] = None, chain: Chain = Chain.MAIN, debug: bool = False) -> Client:
    """Returns a client after checking that the running app is supported (version 2.1.0 or later).

    If `comm_client` is not given, connects to a device over HID.
    """
    if comm_client is None:
        comm_client = TransportClient("hid")

    client = Client(comm_client, chain, debug)
    app_name, app_version, _ = client.get_version()

    version = parse_version(app_version)

    if app_name in ["Bitcoin Legacy", "Bitcoin Test Legacy"] or version.major < 2 or (version.major == 2 and version.minor == 0):
        raise UnsupportedAppVersionError(
            f"Version {app_version} of the '{app_name}' app is not supported; versions before 2.1.0 are "
            "supported by ledger_bitcoin<1.0.0")

    return client
