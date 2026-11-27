//! This module contains types that are specific to the Ledger Bitcoin application protocol.

use core::convert::TryFrom;
use core::{fmt, str::FromStr};

use bitcoin::{
    address::NetworkUnchecked,
    bip32::{DerivationPath, Fingerprint, Xpub},
    consensus::encode::{deserialize_partial, Decodable, Encodable, Error as EncodeError},
    hashes::Hash,
    io::{Read, Write},
    psbt::Psbt,
    secp256k1::ecdsa::Signature,
    taproot::TapLeafHash,
    Address, PublicKey,
};

use crate::{
    apdu::{APDUCommand, StatusWord},
    command,
    interpreter::{get_merkleized_map_commitment, ClientCommandInterpreter, InterpreterError},
    psbt::{get_v2_maps, PartialSignature, PartialSignatureError, PsbtV2Error},
    wallet::WalletPolicy,
};

/// A command to send to the device, together with the state needed to answer the client
/// commands that the device may send while executing it.
///
/// The `prepare_*` functions build a request for each command of the Bitcoin app. The caller sends
/// [`Request::command`] to the device, and passes each response to [`Request::step`] until it
/// returns [`Step::Done`] or an error.
///
/// A request is single-use: once it is done or has failed, [`Request::step`] returns
/// [`RequestError::Finished`]. To retry, for example after a transport error, prepare a new
/// request.
///
/// ```
/// use ledger_bitcoin_client::{
///     apdu::{APDUCommand, StatusWord},
///     protocol::{Request, RequestError, Step},
/// };
///
/// /// Runs `request`, returning the device's final response.
/// fn run<E: From<RequestError>>(
///     request: &mut Request,
///     mut exchange: impl FnMut(&APDUCommand) -> Result<(StatusWord, Vec<u8>), E>,
/// ) -> Result<Vec<u8>, E> {
///     let (mut status, mut data) = exchange(request.command())?;
///     loop {
///         match request.step(status, data)? {
///             Step::Continue(command) => (status, data) = exchange(&command)?,
///             Step::Done(data) => return Ok(data),
///         }
///     }
/// }
/// ```
#[derive(Debug)]
pub struct Request {
    command: APDUCommand,
    interpreter: Option<ClientCommandInterpreter>,
    finished: bool,
}

impl Request {
    /// A request for a command that the device never interrupts with client commands.
    pub fn new(command: APDUCommand) -> Self {
        Self {
            command,
            interpreter: None,
            finished: false,
        }
    }

    /// A request whose client commands are answered by `interpreter`.
    pub fn with_interpreter(command: APDUCommand, interpreter: ClientCommandInterpreter) -> Self {
        Self {
            command,
            interpreter: Some(interpreter),
            finished: false,
        }
    }

    /// The command to send to the device first.
    pub fn command(&self) -> &APDUCommand {
        &self.command
    }

    /// The interpreter answering the client commands, if the command can be interrupted.
    pub fn interpreter_mut(&mut self) -> Option<&mut ClientCommandInterpreter> {
        self.interpreter.as_mut()
    }

    /// Handles a response of the device to the request's command, or to a previous
    /// [`Step::Continue`] command. `data` excludes the status word.
    ///
    /// On success, returns [`Step::Done`] with the response data. If the device interrupted the
    /// execution with a client command, the interpreter answers it, and the answer must be sent
    /// with [`Step::Continue`]. Any other status, or an interruption of a request without an
    /// interpreter, is a [`RequestError::Device`] error for the request's command, with the
    /// response data.
    ///
    /// After [`Step::Done`] or an error, the request is finished, and every further call returns
    /// [`RequestError::Finished`].
    pub fn step(&mut self, status: StatusWord, data: Vec<u8>) -> Result<Step, RequestError> {
        if self.finished {
            return Err(RequestError::Finished);
        }
        let step = match (status, self.interpreter.as_mut()) {
            (StatusWord::OK, _) => Ok(Step::Done(data)),
            (StatusWord::InterruptedExecution, Some(interpreter)) => interpreter
                .execute(data)
                .map(|response| Step::Continue(command::continue_interrupted(response)))
                .map_err(RequestError::Interpreter),
            _ => Err(RequestError::Device {
                command: self.command.ins,
                status,
                data,
            }),
        };
        self.finished = !matches!(step, Ok(Step::Continue(_)));
        step
    }

    /// Consumes the request and returns the values that the device yielded while executing it.
    ///
    /// They are complete only if the request is done: after an error, they are the values
    /// yielded before it.
    pub fn into_yielded(self) -> Vec<Vec<u8>> {
        self.interpreter
            .map(ClientCommandInterpreter::yielded)
            .unwrap_or_default()
    }
}

/// What to do after a response of the device; see [`Request::step`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Send this command to the device, and pass its response to [`Request::step`].
    Continue(APDUCommand),
    /// The request is complete, with this response data.
    Done(Vec<u8>),
}

/// An error executing a [`Request`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    /// The device returned an error status for the request's command. When the app reports an
    /// error code, as it does for some failures, `data` is that 2-byte code.
    #[non_exhaustive]
    Device {
        command: u8,
        status: StatusWord,
        data: Vec<u8>,
    },
    /// A client command sent by the device could not be answered.
    Interpreter(InterpreterError),
    /// The request is already done or has failed.
    Finished,
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Device {
                command,
                status,
                data,
            } => write_device_error(f, *command, *status, data),
            Self::Interpreter(error) => fmt::Display::fmt(error, f),
            Self::Finished => f.write_str("The request is already finished"),
        }
    }
}

impl std::error::Error for RequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            // Transparent: the interpreter error is the message itself.
            Self::Interpreter(error) => error.source(),
            Self::Device { .. } | Self::Finished => None,
        }
    }
}

/// Formats a failure of `command` with `status`, and the response data if any.
pub(crate) fn write_device_error(
    f: &mut fmt::Formatter<'_>,
    command: u8,
    status: StatusWord,
    data: &[u8],
) -> fmt::Result {
    write!(f, "Command {:#04x} failed with status {}", command, status)?;
    if !data.is_empty() {
        f.write_str(" (response data: ")?;
        for byte in data {
            write!(f, "{:02x}", byte)?;
        }
        f.write_str(")")?;
    }
    Ok(())
}

/// Prepares GET_VERSION.
pub fn prepare_get_version() -> Request {
    Request::new(command::get_version())
}

/// Prepares GET_MASTER_FINGERPRINT.
pub fn prepare_get_master_fingerprint() -> Request {
    Request::new(command::get_master_fingerprint())
}

/// Prepares GET_EXTENDED_PUBKEY.
pub fn prepare_get_extended_pubkey(path: &DerivationPath, display: bool) -> Request {
    Request::new(command::get_extended_pubkey(path, display))
}

/// Prepares REGISTER_WALLET, with the wallet policy and its keys known to the interpreter.
///
/// To make sure that the device registered the intended wallet policy, the convenience clients
/// with the `paranoid_client` feature request an address with the returned HMAC, without
/// displaying it, and verify it with `WalletPolicy::check_address` before returning the HMAC.
/// With `run` being the exchange loop shown in [`Request`]:
///
/// ```
/// # #[cfg(feature = "paranoid_client")]
/// # mod example {
/// use ledger_bitcoin_client::{protocol::*, wallet::{AddressCheckError, WalletPolicy}};
///
/// fn register_wallet<E>(
///     wallet: &WalletPolicy,
///     mut run: impl FnMut(&mut Request) -> Result<Vec<u8>, E>,
/// ) -> Result<([u8; 32], [u8; 32]), E>
/// where
///     E: From<ResponseError> + From<AddressCheckError>,
/// {
///     let data = run(&mut prepare_register_wallet(wallet))?;
///     let (id, hmac) = parse_wallet_registration(&data)?;
///     let data = run(&mut prepare_get_wallet_address(wallet, Some(&hmac), false, 0, false))?;
///     wallet.check_address(false, 0, &parse_wallet_address(&data)?)?;
///     Ok((id, hmac))
/// }
/// # }
/// ```
pub fn prepare_register_wallet(wallet: &WalletPolicy) -> Request {
    Request::with_interpreter(
        command::register_wallet(wallet),
        ClientCommandInterpreter::for_wallet(wallet),
    )
}

/// Prepares GET_WALLET_ADDRESS, with the wallet policy and its keys known to the interpreter.
///
/// This does not verify the address that the device returns; with the `paranoid_client`
/// feature, `WalletPolicy::check_address` does.
pub fn prepare_get_wallet_address(
    wallet: &WalletPolicy,
    hmac: Option<&[u8; 32]>,
    change: bool,
    address_index: u32,
    display: bool,
) -> Request {
    Request::with_interpreter(
        command::get_wallet_address(wallet, hmac, change, address_index, display),
        ClientCommandInterpreter::for_wallet(wallet),
    )
}

/// Prepares SIGN_PSBT, with the wallet policy, its keys and the PSBT maps known to the
/// interpreter.
///
/// Fails if the PSBT cannot be converted to the PSBTv2 maps that the device expects.
pub fn prepare_sign_psbt(
    psbt: &Psbt,
    wallet: &WalletPolicy,
    hmac: Option<&[u8; 32]>,
) -> Result<Request, PsbtV2Error> {
    let mut interpreter = ClientCommandInterpreter::for_wallet(wallet);
    let maps = get_v2_maps(psbt)?;
    interpreter.add_known_mapping(&maps.global);
    let global_commitment = get_merkleized_map_commitment(&maps.global);
    let mut input_commitments = Vec::with_capacity(maps.inputs.len());
    for map in &maps.inputs {
        interpreter.add_known_mapping(map);
        input_commitments.push(get_merkleized_map_commitment(map));
    }
    let input_root = interpreter.add_known_list(&input_commitments);
    let mut output_commitments = Vec::with_capacity(maps.outputs.len());
    for map in &maps.outputs {
        interpreter.add_known_mapping(map);
        output_commitments.push(get_merkleized_map_commitment(map));
    }
    let output_root = interpreter.add_known_list(&output_commitments);
    let command = command::sign_psbt(
        &global_commitment,
        maps.inputs.len(),
        &input_root,
        maps.outputs.len(),
        &output_root,
        wallet,
        hmac,
    );
    Ok(Request::with_interpreter(command, interpreter))
}

/// Prepares SIGN_MESSAGE, with the message chunks known to the interpreter.
pub fn prepare_sign_message(message: &[u8], path: &DerivationPath) -> Request {
    let chunks: Vec<&[u8]> = message.chunks(MESSAGE_CHUNK_SIZE).collect();
    let mut interpreter = ClientCommandInterpreter::new();
    let root = interpreter.add_known_list(&chunks);
    Request::with_interpreter(
        command::sign_message(message.len(), &root, path),
        interpreter,
    )
}

/// The size of the chunks of the message in SIGN_MESSAGE; the last one can be shorter.
const MESSAGE_CHUNK_SIZE: usize = 64;

/// An error parsing the response to a command.
///
/// The convenience clients report these errors as `UnexpectedResult`, with the response bytes.
#[non_exhaustive]
#[derive(Debug)]
pub enum ResponseError {
    /// The response ends before `field`.
    #[non_exhaustive]
    Truncated { field: &'static str },
    /// `field` is not encoded as expected.
    #[non_exhaustive]
    InvalidFormat { field: &'static str },
    /// A fixed-length response has the wrong length.
    #[non_exhaustive]
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    /// `field` could not be decoded.
    #[non_exhaustive]
    Decode {
        field: &'static str,
        source: EncodeError,
    },
    /// The response continues after its last field.
    #[non_exhaustive]
    TrailingBytes { count: usize },
}

impl fmt::Display for ResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { field } => write!(f, "Truncated {}", field),
            Self::InvalidFormat { field } => write!(f, "Invalid {} format", field),
            Self::InvalidLength {
                field,
                expected,
                actual,
            } => write!(
                f,
                "Invalid {} length: expected {}, got {}",
                field, expected, actual
            ),
            Self::Decode { field, source } => write!(f, "Failed to decode {}: {}", field, source),
            Self::TrailingBytes { count } => write!(f, "{} unexpected trailing bytes", count),
        }
    }
}

impl std::error::Error for ResponseError {}

/// Parses the response to GET_VERSION: the app name, version and flags.
///
/// The flags are empty if the response has none, as when the dashboard answers instead of an app.
pub fn parse_version(data: &[u8]) -> Result<(String, String, Vec<u8>), ResponseError> {
    match data.first() {
        None => return Err(ResponseError::Truncated { field: "format" }),
        Some(1) => (),
        Some(_) => return Err(ResponseError::InvalidFormat { field: "format" }),
    }
    let mut offset = 1;
    let (name, read): (String, usize) =
        deserialize_partial(&data[offset..]).map_err(|source| ResponseError::Decode {
            field: "name",
            source,
        })?;
    offset += read;
    let (version, read): (String, usize) =
        deserialize_partial(&data[offset..]).map_err(|source| ResponseError::Decode {
            field: "version",
            source,
        })?;
    offset += read;
    let flags = if offset == data.len() {
        Vec::new()
    } else {
        let (flags, read): (Vec<u8>, usize) =
            deserialize_partial(&data[offset..]).map_err(|source| ResponseError::Decode {
                field: "flags",
                source,
            })?;
        offset += read;
        flags
    };
    check_no_trailing_bytes(data, offset)?;
    Ok((name, version, flags))
}

/// Parses the response to GET_MASTER_FINGERPRINT: exactly 4 bytes.
pub fn parse_master_fingerprint(data: &[u8]) -> Result<Fingerprint, ResponseError> {
    let fingerprint: [u8; 4] = fixed_length(data, "fingerprint")?;
    Ok(fingerprint.into())
}

/// Parses the response to GET_EXTENDED_PUBKEY: a serialized extended public key.
pub fn parse_extended_pubkey(data: &[u8]) -> Result<Xpub, ResponseError> {
    let field = "extended pubkey";
    Xpub::from_str(utf8(data, field)?).map_err(|_| ResponseError::InvalidFormat { field })
}

/// Parses the response to GET_WALLET_ADDRESS: an address, whose network is not checked.
pub fn parse_wallet_address(data: &[u8]) -> Result<Address<NetworkUnchecked>, ResponseError> {
    let field = "wallet address";
    Address::from_str(utf8(data, field)?).map_err(|_| ResponseError::InvalidFormat { field })
}

/// Parses the response to REGISTER_WALLET: the 32-byte wallet ID and the 32-byte HMAC.
pub fn parse_wallet_registration(data: &[u8]) -> Result<([u8; 32], [u8; 32]), ResponseError> {
    let registration: [u8; 64] = fixed_length(data, "wallet registration")?;
    let mut id = [0; 32];
    id.copy_from_slice(&registration[..32]);
    let mut hmac = [0; 32];
    hmac.copy_from_slice(&registration[32..]);
    Ok((id, hmac))
}

fn fixed_length<const N: usize>(
    data: &[u8],
    field: &'static str,
) -> Result<[u8; N], ResponseError> {
    <[u8; N]>::try_from(data).map_err(|_| ResponseError::InvalidLength {
        field,
        expected: N,
        actual: data.len(),
    })
}

fn utf8<'a>(data: &'a [u8], field: &'static str) -> Result<&'a str, ResponseError> {
    core::str::from_utf8(data).map_err(|_| ResponseError::InvalidFormat { field })
}

fn check_no_trailing_bytes(data: &[u8], parsed: usize) -> Result<(), ResponseError> {
    match data.len() - parsed {
        0 => Ok(()),
        count => Err(ResponseError::TrailingBytes { count }),
    }
}

/// Parses the response to SIGN_MESSAGE: the header byte and the compact ECDSA signature.
/// This checks the encoding, not that the signature is valid for the message.
pub fn parse_message_signature(data: &[u8]) -> Result<(u8, Signature), ResponseError> {
    if data.len() != 65 {
        return Err(ResponseError::InvalidLength {
            field: "message signature",
            expected: 65,
            actual: data.len(),
        });
    }
    let signature =
        Signature::from_compact(&data[1..]).map_err(|_| ResponseError::InvalidFormat {
            field: "message signature",
        })?;
    Ok((data[0], signature))
}

/// A variable-length unsigned integer using the same wire encoding as
/// Bitcoin's `CompactSize`, but without the upper-bound limit enforced by the
/// `bitcoin` crate's [`VarInt`](bitcoin::consensus::encode::VarInt).
///
/// The Ledger protocol reuses the CompactSize encoding for tag values (e.g.
/// `0xFFFFFFFF`) that exceed `MAX_COMPACT_SIZE`.  This type can be used for
/// both serialization and deserialization of any `u64` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct UncheckedVarInt(pub u64);

impl Encodable for UncheckedVarInt {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, bitcoin::io::Error> {
        match self.0 {
            0..=0xFC => {
                (self.0 as u8).consensus_encode(w)?;
                Ok(1)
            }
            0xFD..=0xFFFF => {
                0xFDu8.consensus_encode(w)?;
                (self.0 as u16).consensus_encode(w)?;
                Ok(3)
            }
            0x10000..=0xFFFFFFFF => {
                0xFEu8.consensus_encode(w)?;
                (self.0 as u32).consensus_encode(w)?;
                Ok(5)
            }
            _ => {
                0xFFu8.consensus_encode(w)?;
                self.0.consensus_encode(w)?;
                Ok(9)
            }
        }
    }
}

impl Decodable for UncheckedVarInt {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, EncodeError> {
        let n = u8::consensus_decode(r)?;
        match n {
            0xFF => {
                let x = u64::consensus_decode(r)?;
                if x < 0x1_0000_0000 {
                    Err(EncodeError::NonMinimalVarInt)
                } else {
                    Ok(UncheckedVarInt(x))
                }
            }
            0xFE => {
                let x = u32::consensus_decode(r)?;
                if x < 0x10000 {
                    Err(EncodeError::NonMinimalVarInt)
                } else {
                    Ok(UncheckedVarInt(x as u64))
                }
            }
            0xFD => {
                let x = u16::consensus_decode(r)?;
                if x < 0xFD {
                    Err(EncodeError::NonMinimalVarInt)
                } else {
                    Ok(UncheckedVarInt(x as u64))
                }
            }
            n => Ok(UncheckedVarInt(n as u64)),
        }
    }
}

/// Tag yielded by the device to introduce a MuSig2 pubnonce payload.
pub const CCMD_YIELD_MUSIG_PUBNONCE_TAG: u64 = 0xFFFFFFFF;
/// Tag yielded by the device to introduce a MuSig2 partial-signature payload.
pub const CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG: u64 = 0xFFFFFFFE;

/// A MuSig2 public nonce yielded by the device during the first round of a
/// MuSig2 signing session, as specified in BIP-373.
#[derive(Debug, Clone)]
pub struct MusigPubNonce {
    /// The 33-byte compressed pubkey of this participant.
    pub participant_pubkey: PublicKey,
    /// The 33-byte compressed aggregate pubkey.
    pub aggregate_pubkey: PublicKey,
    /// The tapleaf hash, if signing for a tapscript; `None` otherwise.
    pub tapleaf_hash: Option<TapLeafHash>,
    /// The 66-byte pubnonce.
    pub pubnonce: [u8; 66],
}

/// A MuSig2 partial signature yielded by the device during the second round of
/// a MuSig2 signing session, as specified in BIP-373
///
/// Note: not to be confused with [`PartialSignature`], which represents a
/// regular ECDSA or Schnorr signature for a single input.
#[derive(Debug, Clone)]
pub struct MusigPartialSignature {
    /// The 33-byte compressed pubkey of this participant.
    pub participant_pubkey: PublicKey,
    /// The 33-byte compressed aggregate pubkey.
    pub aggregate_pubkey: PublicKey,
    /// The tapleaf hash, if signing for a tapscript; `None` otherwise.
    pub tapleaf_hash: Option<TapLeafHash>,
    /// The 32-byte partial signature for this participant.
    pub partial_signature: [u8; 32],
}

/// An object yielded by the device while signing a PSBT.
///
/// The variants cover the different kinds of payload the device can produce.
/// The enum is `#[non_exhaustive]`: callers must include a wildcard arm so that
/// new payload kinds introduced in future protocol versions do not cause
/// compilation failures in existing code.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum SignPsbtYieldedObject {
    /// A regular partial signature for a PSBT input.
    Partial(PartialSignature),
    /// A MuSig2 public nonce (round 1).
    MusigPubNonce(MusigPubNonce),
    /// A MuSig2 partial signature (round 2).
    MusigPartialSignature(MusigPartialSignature),
    /// An object with a tag in the reserved range that this version does not know: the tag, and
    /// the data that follows the input index.
    #[non_exhaustive]
    Unknown { tag: u64, data: Vec<u8> },
}

/// A value yielded by the device during SIGN_PSBT that could not be parsed.
#[non_exhaustive]
#[derive(Debug)]
pub struct SignPsbtResultsError {
    /// The yielded value.
    pub data: Vec<u8>,
    /// Why it could not be parsed.
    pub source: PartialSignatureError,
}

impl fmt::Display for SignPsbtResultsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The reason is the error's source.
        f.write_str("Invalid value yielded by SIGN_PSBT")
    }
}

impl std::error::Error for SignPsbtResultsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Parses the values yielded by the device during SIGN_PSBT, in order; see
/// [`parse_sign_psbt_yielded`]. Once the request is done, [`Request::into_yielded`] returns them.
///
/// Fails on the first value that cannot be parsed.
pub fn parse_sign_psbt_results(
    yielded: Vec<Vec<u8>>,
) -> Result<Vec<(usize, SignPsbtYieldedObject)>, SignPsbtResultsError> {
    yielded
        .into_iter()
        .map(|data| {
            parse_sign_psbt_yielded(&data).map_err(|source| SignPsbtResultsError { data, source })
        })
        .collect()
}

fn checked_input_index(index: u64) -> Result<usize, PartialSignatureError> {
    u32::try_from(index)
        .map(|index| index as usize)
        .map_err(|_| PartialSignatureError::InvalidInputIndex)
}

/// Parses a single payload yielded by the device during `sign_psbt`.
///
/// On success returns the input index together with the decoded object.
/// Input indices must fit in a `u32`, independently of the host pointer width.
pub fn parse_sign_psbt_yielded(
    data: &[u8],
) -> Result<(usize, SignPsbtYieldedObject), PartialSignatureError> {
    let (UncheckedVarInt(tag), i): (UncheckedVarInt, usize) =
        deserialize_partial(data).map_err(|_| PartialSignatureError::InvalidLength)?;

    match tag {
        CCMD_YIELD_MUSIG_PUBNONCE_TAG => {
            let (UncheckedVarInt(input_index), j): (UncheckedVarInt, usize) =
                deserialize_partial(&data[i..])
                    .map_err(|_| PartialSignatureError::InvalidLength)?;
            let rest = &data[i + j..];
            // Layout: 66-byte pubnonce || 33-byte participant pubkey ||
            //         33-byte aggregate pubkey || optional 32-byte tapleaf hash.
            if rest.len() != 132 && rest.len() != 164 {
                return Err(PartialSignatureError::InvalidLength);
            }
            let mut pubnonce = [0u8; 66];
            pubnonce.copy_from_slice(&rest[0..66]);
            let participant_pubkey =
                PublicKey::from_slice(&rest[66..99]).map_err(PartialSignatureError::PubKey)?;
            let aggregate_pubkey =
                PublicKey::from_slice(&rest[99..132]).map_err(PartialSignatureError::PubKey)?;
            let tapleaf_hash = if rest.len() == 164 {
                Some(
                    TapLeafHash::from_slice(&rest[132..164])
                        .map_err(PartialSignatureError::TapLeaf)?,
                )
            } else {
                None
            };
            Ok((
                checked_input_index(input_index)?,
                SignPsbtYieldedObject::MusigPubNonce(MusigPubNonce {
                    participant_pubkey,
                    aggregate_pubkey,
                    tapleaf_hash,
                    pubnonce,
                }),
            ))
        }
        CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG => {
            let (UncheckedVarInt(input_index), j): (UncheckedVarInt, usize) =
                deserialize_partial(&data[i..])
                    .map_err(|_| PartialSignatureError::InvalidLength)?;
            let rest = &data[i + j..];
            // Layout: 32-byte partial signature || 33-byte participant pubkey ||
            //         33-byte aggregate pubkey || optional 32-byte tapleaf hash.
            if rest.len() != 98 && rest.len() != 130 {
                return Err(PartialSignatureError::InvalidLength);
            }
            let mut partial_signature = [0u8; 32];
            partial_signature.copy_from_slice(&rest[0..32]);
            let participant_pubkey =
                PublicKey::from_slice(&rest[32..65]).map_err(PartialSignatureError::PubKey)?;
            let aggregate_pubkey =
                PublicKey::from_slice(&rest[65..98]).map_err(PartialSignatureError::PubKey)?;
            let tapleaf_hash = if rest.len() == 130 {
                Some(
                    TapLeafHash::from_slice(&rest[98..130])
                        .map_err(PartialSignatureError::TapLeaf)?,
                )
            } else {
                None
            };
            Ok((
                checked_input_index(input_index)?,
                SignPsbtYieldedObject::MusigPartialSignature(MusigPartialSignature {
                    participant_pubkey,
                    aggregate_pubkey,
                    tapleaf_hash,
                    partial_signature,
                }),
            ))
        }
        // Reserved tag range used by the protocol for non-input-index payloads.
        // Tags in this range that are not explicitly handled above are unknown to this client version, and reserved
        // for future use.
        tag if tag >= 0x80000000 => {
            // Future tags are expected to follow the same layout, using the first varint to refer to the input index
            let (UncheckedVarInt(input_index), j): (UncheckedVarInt, usize) =
                deserialize_partial(&data[i..])
                    .map_err(|_| PartialSignatureError::InvalidLength)?;
            let rest = &data[i + j..];
            Ok((
                checked_input_index(input_index)?,
                SignPsbtYieldedObject::Unknown {
                    tag,
                    data: rest.to_vec(),
                },
            ))
        }
        // Otherwise the leading varint is the input index and the remainder is a regular partial signature.
        // These are the only payloads that were used in protocol versions prior to the introduction of the tags.
        _ => {
            let input_index = checked_input_index(tag)?;
            let ps = PartialSignature::from_slice(&data[i..])?;
            Ok((input_index, SignPsbtYieldedObject::Partial(ps)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::encode::serialize;
    use hex_literal::hex;

    // Arbitrary valid compressed secp256k1 pubkey (no special meaning).
    const PUBKEY: [u8; 33] =
        hex!("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa");
    // x-only version of the same pubkey (drops the 0x03 prefix).
    const XONLY: [u8; 32] =
        hex!("4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa");
    // 32-byte tapleaf hash placeholder (any 32 bytes are accepted by from_slice).
    const TAPLEAF: [u8; 32] =
        hex!("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

    fn parse_ok(payload: &[u8]) -> (usize, SignPsbtYieldedObject) {
        match parse_sign_psbt_yielded(payload) {
            Ok(v) => v,
            Err(_) => panic!("parse_sign_psbt_yielded returned an unexpected error"),
        }
    }

    #[test]
    fn parse_legacy_partial_taproot_no_tapleaf() {
        // Layout (untagged, used by protocol versions <= 2.1):
        //   varint(input_index) || key_augment_len(=32) || 32-byte x-only pk || 64-byte schnorr sig
        let mut payload = serialize(&UncheckedVarInt(3));
        payload.push(32);
        payload.extend(XONLY);
        payload.extend([0xAAu8; 64]);

        let (idx, obj) = parse_ok(&payload);
        assert_eq!(idx, 3);
        match obj {
            SignPsbtYieldedObject::Partial(PartialSignature::TapScriptSig(_, tlh, _)) => {
                assert!(tlh.is_none());
            }
            other => panic!("expected TapScriptSig without tapleaf, got {:?}", other),
        }
    }

    fn build_musig_pubnonce(input_index: u64, with_tapleaf: bool) -> Vec<u8> {
        let mut payload = serialize(&UncheckedVarInt(CCMD_YIELD_MUSIG_PUBNONCE_TAG));
        payload.extend(serialize(&UncheckedVarInt(input_index)));
        payload.extend([0xAAu8; 66]); // pubnonce
        payload.extend(PUBKEY); // participant pk (33)
        payload.extend(PUBKEY); // aggregate pk  (33)
        if with_tapleaf {
            payload.extend(TAPLEAF);
        }
        payload
    }

    #[test]
    fn parse_musig_pubnonce_without_tapleaf() {
        let payload = build_musig_pubnonce(7, false);
        let (idx, obj) = parse_ok(&payload);
        assert_eq!(idx, 7);
        match obj {
            SignPsbtYieldedObject::MusigPubNonce(n) => {
                assert!(n.tapleaf_hash.is_none());
                assert_eq!(n.pubnonce, [0xAAu8; 66]);
                assert_eq!(n.participant_pubkey.to_bytes(), PUBKEY);
                assert_eq!(n.aggregate_pubkey.to_bytes(), PUBKEY);
            }
            other => panic!("expected MusigPubNonce, got {:?}", other),
        }
    }

    #[test]
    fn parse_musig_pubnonce_with_tapleaf() {
        let payload = build_musig_pubnonce(0, true);
        let (idx, obj) = parse_ok(&payload);
        assert_eq!(idx, 0);
        match obj {
            SignPsbtYieldedObject::MusigPubNonce(n) => {
                let tlh = n.tapleaf_hash.expect("tapleaf hash should be present");
                assert_eq!(tlh.to_byte_array(), TAPLEAF);
            }
            other => panic!("expected MusigPubNonce, got {:?}", other),
        }
    }

    fn build_musig_partial_sig(input_index: u64, with_tapleaf: bool) -> Vec<u8> {
        let mut payload = serialize(&UncheckedVarInt(CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG));
        payload.extend(serialize(&UncheckedVarInt(input_index)));
        payload.extend([0xBBu8; 32]); // partial signature
        payload.extend(PUBKEY); // participant pk (33)
        payload.extend(PUBKEY); // aggregate pk  (33)
        if with_tapleaf {
            payload.extend(TAPLEAF);
        }
        payload
    }

    #[test]
    fn parse_musig_partial_signature_without_tapleaf() {
        let payload = build_musig_partial_sig(2, false);
        let (idx, obj) = parse_ok(&payload);
        assert_eq!(idx, 2);
        match obj {
            SignPsbtYieldedObject::MusigPartialSignature(s) => {
                assert!(s.tapleaf_hash.is_none());
                assert_eq!(s.partial_signature, [0xBBu8; 32]);
                assert_eq!(s.participant_pubkey.to_bytes(), PUBKEY);
                assert_eq!(s.aggregate_pubkey.to_bytes(), PUBKEY);
            }
            other => panic!("expected MusigPartialSignature, got {:?}", other),
        }
    }

    #[test]
    fn parse_musig_partial_signature_with_tapleaf() {
        let payload = build_musig_partial_sig(42, true);
        let (idx, obj) = parse_ok(&payload);
        assert_eq!(idx, 42);
        match obj {
            SignPsbtYieldedObject::MusigPartialSignature(s) => {
                let tlh = s.tapleaf_hash.expect("tapleaf hash should be present");
                assert_eq!(tlh.to_byte_array(), TAPLEAF);
            }
            other => panic!("expected MusigPartialSignature, got {:?}", other),
        }
    }

    #[test]
    fn parse_unknown_reserved_tag() {
        // Any tag in the reserved range (>= 0x80000000) that this client version does
        // not explicitly handle must surface as `Unknown` while preserving the tag, the
        // input_index and the trailing payload verbatim.
        const UNKNOWN_TAG: u64 = 0x89AB_CDEF;
        let trailer = hex!("deadbeef");

        let mut payload = serialize(&UncheckedVarInt(UNKNOWN_TAG));
        payload.extend(serialize(&UncheckedVarInt(11)));
        payload.extend(&trailer);

        let (idx, obj) = parse_ok(&payload);
        assert_eq!(idx, 11);
        match obj {
            SignPsbtYieldedObject::Unknown { tag, data } => {
                assert_eq!(tag, UNKNOWN_TAG);
                assert_eq!(data, trailer);
            }
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    #[test]
    fn parse_musig_pubnonce_wrong_trailer_length_is_error() {
        // Drop one byte from the aggregate pubkey to make the trailer length invalid
        // (133 bytes instead of 132 or 164).
        let mut payload = build_musig_pubnonce(0, false);
        payload.push(0x00);
        assert!(matches!(
            parse_sign_psbt_yielded(&payload),
            Err(PartialSignatureError::InvalidLength)
        ));
    }

    #[test]
    fn parse_musig_partial_signature_wrong_trailer_length_is_error() {
        let mut payload = build_musig_partial_sig(0, false);
        payload.push(0x00);
        assert!(matches!(
            parse_sign_psbt_yielded(&payload),
            Err(PartialSignatureError::InvalidLength)
        ));
    }

    #[test]
    fn musig_variants_reject_truncation_and_invalid_keys() {
        // The tag, the input index, the value, then the participant's public key.
        for (builder, tag, value_len) in [
            (
                build_musig_pubnonce as fn(u64, bool) -> Vec<u8>,
                CCMD_YIELD_MUSIG_PUBNONCE_TAG,
                66,
            ),
            (
                build_musig_partial_sig as fn(u64, bool) -> Vec<u8>,
                CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG,
                32,
            ),
        ] {
            for tapleaf in [false, true] {
                let input_index = 2;
                let mut payload = builder(input_index, tapleaf);
                assert!(matches!(
                    parse_sign_psbt_yielded(&payload[..payload.len() - 1]),
                    Err(PartialSignatureError::InvalidLength)
                ));
                let participant_offset = serialize(&UncheckedVarInt(tag)).len()
                    + serialize(&UncheckedVarInt(input_index)).len()
                    + value_len;
                payload[participant_offset] = 0xff;
                assert!(matches!(
                    parse_sign_psbt_yielded(&payload),
                    Err(PartialSignatureError::PubKey(_))
                ));
            }
        }
    }

    #[test]
    fn legacy_signature_encodings_reject_malformed_keys_and_signatures() {
        // The input index (0), the key length, the key, then the signature.
        for malformed in [vec![0], vec![0, 64, 1], vec![0, 32], vec![0, 33, 0, 0]] {
            assert!(parse_sign_psbt_yielded(&malformed).is_err());
        }
        let mut payload = vec![0, 32];
        payload.extend(XONLY);
        payload.extend([0xaa; 63]); // One byte short of a Schnorr signature.
        assert!(matches!(
            parse_sign_psbt_yielded(&payload),
            Err(PartialSignatureError::TaprootSig(_))
        ));
    }

    #[test]
    fn yielded_input_indices_have_platform_independent_u32_bounds() {
        for tag in [
            CCMD_YIELD_MUSIG_PUBNONCE_TAG,
            CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG,
            0x8000_0000,
            u64::MAX,
        ] {
            for index in [u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX] {
                let payload = match tag {
                    CCMD_YIELD_MUSIG_PUBNONCE_TAG => build_musig_pubnonce(index, false),
                    CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG => build_musig_partial_sig(index, false),
                    _ => [
                        serialize(&UncheckedVarInt(tag)),
                        serialize(&UncheckedVarInt(index)),
                    ]
                    .concat(),
                };
                let parsed = parse_sign_psbt_yielded(&payload);
                if index == u32::MAX as u64 {
                    assert_eq!(parsed.unwrap().0, u32::MAX as usize);
                } else {
                    assert!(matches!(
                        parsed,
                        Err(PartialSignatureError::InvalidInputIndex)
                    ));
                }
            }
        }
        const MAX_UNTAGGED_INPUT_INDEX: u64 = 0x7fff_ffff;
        let mut regular = serialize(&UncheckedVarInt(MAX_UNTAGGED_INPUT_INDEX));
        regular.push(32);
        regular.extend(XONLY);
        regular.extend([0xaa; 64]);
        assert_eq!(parse_ok(&regular).0, MAX_UNTAGGED_INPUT_INDEX as usize);
    }

    #[test]
    fn malformed_compact_size_is_not_an_out_of_range_index() {
        for malformed in [
            vec![],
            vec![0xfd],
            vec![0xfd, 1, 0],
            vec![0xfe, 0, 1, 0, 0],
            vec![0xff, 0, 0, 0, 0, 0, 0, 0, 0],
        ] {
            assert!(matches!(
                parse_sign_psbt_yielded(&malformed),
                Err(PartialSignatureError::InvalidLength)
            ));
            for tag in [
                CCMD_YIELD_MUSIG_PUBNONCE_TAG,
                CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG,
                u64::MAX,
            ] {
                let mut payload = serialize(&UncheckedVarInt(tag));
                payload.extend(&malformed);
                assert!(matches!(
                    parse_sign_psbt_yielded(&payload),
                    Err(PartialSignatureError::InvalidLength)
                ));
            }
        }
    }
}
