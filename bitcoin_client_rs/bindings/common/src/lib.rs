//! Transport-free operations of the Ledger Bitcoin client, in the shape its language bindings
//! need.
//!
//! An [`Operation`] is one client call (for example, signing a PSBT) as a state machine over
//! APDUs. The host sends [`Operation::next_apdu`] with its own transport, passes the response to
//! [`Operation::step`], and repeats until no APDU is left; [`Operation::output`] then returns the
//! result:
//!
//! ```ignore
//! let mut apdu = operation.next_apdu();
//! while let Some(command) = apdu {
//!     let (sw, data) = transport.exchange(&command);
//!     apdu = operation.step(sw, data)?;
//! }
//! let output = operation.output()?;
//! ```
//!
//! All the protocol logic runs here: the delegated client commands, the follow-up request that
//! checks a newly registered wallet, response parsing, and the independent verification of
//! wallet addresses. Each binding only owns its transport loop and the conversion of [`Output`]
//! to its own types. Arguments and results are plain strings and bytes, so that no binding has
//! to expose rust-bitcoin types.

use core::{fmt, mem, str::FromStr};

use bitcoin::{bip32::DerivationPath, hashes::Hash};
use ledger_bitcoin_client::{
    apdu::{APDUCommand, StatusWord},
    command,
    interpreter::ClientCommandInterpreter,
    protocol::{self, RequestError, SignPsbtYieldedObject, Step},
    wallet::{Version, WalletPolicy, WalletPubKey},
};

const SW_OK: u16 = 0x9000;
const SW_INTERRUPTED_EXECUTION: u16 = 0xE000;

/// An APDU command to send to the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Apdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
}

impl Apdu {
    /// The APDU's wire encoding: the four header bytes, the data length and the data.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![self.cla, self.ins, self.p1, self.p2, self.data.len() as u8];
        out.extend_from_slice(&self.data);
        out
    }
}

impl From<&APDUCommand> for Apdu {
    fn from(command: &APDUCommand) -> Self {
        Self {
            cla: command.cla,
            ins: command.ins,
            p1: command.p1,
            p2: command.p2,
            data: command.data.clone(),
        }
    }
}

/// Why an operation could not be created or did not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// An argument of the call is invalid; nothing was sent to the device.
    InvalidArgument(String),
    /// The device answered with a status word other than success. `ins` is the instruction of
    /// the request that failed (never the one of a continuation), and `data` is the response
    /// data that came with the status word.
    Device { ins: u8, sw: u16, data: Vec<u8> },
    /// The device's answer is malformed or inconsistent, or its address is not confirmed by the
    /// independent verification.
    InvalidResponse(String),
    /// [`Operation::step`] or [`Operation::output`] was called in a state that does not allow it.
    InvalidState(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(message) | Self::InvalidResponse(message) => f.write_str(message),
            Self::Device { ins, sw, .. } => {
                write!(f, "Command {:#04x} failed with status {:#06x}", ins, sw)
            }
            Self::InvalidState(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {}

fn invalid_argument(message: impl Into<String>) -> Error {
    Error::InvalidArgument(message.into())
}

fn invalid_response(message: impl fmt::Display) -> Error {
    Error::InvalidResponse(message.to_string())
}

/// Builds a wallet policy from its BIP-388 parts: a name, a descriptor template, and the key
/// information strings that its `@i` placeholders refer to. `version` is 1 or 2.
pub fn wallet_policy(
    name: &str,
    descriptor_template: &str,
    keys: &[impl AsRef<str>],
    version: u8,
) -> Result<WalletPolicy, Error> {
    let version = match version {
        1 => Version::V1,
        2 => Version::V2,
        _ => return Err(invalid_argument("Invalid wallet policy version")),
    };
    // the serialization has a single byte for the name length
    if name.len() > u8::MAX as usize {
        return Err(invalid_argument("Wallet name too long"));
    }
    let keys = keys
        .iter()
        .map(|key| {
            WalletPubKey::from_str(key.as_ref()).map_err(|error| {
                invalid_argument(format!("Invalid key '{}': {}", key.as_ref(), error))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(WalletPolicy::new(
        name.into(),
        version,
        descriptor_template.into(),
        keys,
    ))
}

/// Parses a BIP-32 derivation path like `m/84'/1'/0'`. The `m/` prefix is optional, and
/// hardened steps may be marked with `'` or `h`.
pub fn derivation_path(path: &str) -> Result<DerivationPath, Error> {
    DerivationPath::from_str(path)
        .map_err(|error| invalid_argument(format!("Invalid BIP-32 path '{}': {}", path, error)))
}

fn wallet_hmac(hmac: Option<&[u8]>) -> Result<Option<[u8; 32]>, Error> {
    hmac.map(|hmac| <[u8; 32]>::try_from(hmac).map_err(|_| invalid_argument("Invalid HMAC length")))
        .transpose()
}

/// An object yielded by the device while signing a PSBT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Yielded {
    /// A signature, exactly as it goes on the scriptSig or witness stack (including the sighash
    /// byte when there is one). `pubkey` is a 33-byte compressed key, or a 32-byte x-only key
    /// for taproot; `tapleaf_hash` is set for tapscript spends.
    PartialSignature {
        pubkey: Vec<u8>,
        signature: Vec<u8>,
        tapleaf_hash: Option<Vec<u8>>,
    },
    /// A MuSig2 public nonce (round 1).
    MusigPubNonce {
        participant_pubkey: Vec<u8>,
        aggregate_pubkey: Vec<u8>,
        tapleaf_hash: Option<Vec<u8>>,
        pubnonce: Vec<u8>,
    },
    /// A MuSig2 partial signature (round 2).
    MusigPartialSignature {
        participant_pubkey: Vec<u8>,
        aggregate_pubkey: Vec<u8>,
        tapleaf_hash: Option<Vec<u8>>,
        partial_signature: Vec<u8>,
    },
    /// A payload with a tag that this client does not know, for forward compatibility: `data`
    /// follows the input index.
    Unknown { tag: u64, data: Vec<u8> },
}

/// The result of a completed operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Version {
        name: String,
        version: String,
        flags: Vec<u8>,
    },
    MasterFingerprint([u8; 4]),
    ExtendedPubkey(String),
    WalletRegistration {
        id: [u8; 32],
        hmac: [u8; 32],
    },
    WalletAddress(String),
    /// The input index of each yielded object, in the order the device yielded them.
    PsbtSignatures(Vec<(u32, Yielded)>),
    /// The 65-byte signature: the header byte followed by the compact signature.
    MessageSignature(Vec<u8>),
}

/// What an operation does with the final response of each of its requests.
enum Kind {
    Version,
    MasterFingerprint,
    ExtendedPubkey,
    RegisterWallet(Box<WalletPolicy>),
    /// After a registration: the address request that independently checks the wallet.
    RegisterWalletCheck {
        wallet: Box<WalletPolicy>,
        id: [u8; 32],
        hmac: [u8; 32],
    },
    WalletAddress {
        wallet: Box<WalletPolicy>,
        change: bool,
        address_index: u32,
    },
    SignPsbt,
    SignMessage,
}

enum State {
    Pending {
        kind: Kind,
        command: APDUCommand,
        /// The instruction of the request, which continuations keep referring to.
        ins: u8,
        interpreter: Option<ClientCommandInterpreter>,
    },
    Done(Output),
    /// Failed, or its output was taken.
    Finished,
}

/// One client call, as a state machine over the APDUs it exchanges with the device.
pub struct Operation {
    state: State,
}

impl Operation {
    fn new(
        kind: Kind,
        command: APDUCommand,
        interpreter: Option<ClientCommandInterpreter>,
    ) -> Self {
        Self {
            state: State::Pending {
                kind,
                ins: command.ins,
                command,
                interpreter,
            },
        }
    }

    /// Returns the running app's name, version and state flags.
    pub fn get_version() -> Self {
        Self::new(Kind::Version, command::get_version(), None)
    }

    /// Returns the fingerprint of the master public key.
    pub fn get_master_fingerprint() -> Self {
        Self::new(
            Kind::MasterFingerprint,
            command::get_master_fingerprint(),
            None,
        )
    }

    /// Returns the extended public key at `path`, optionally showing it on the device.
    pub fn get_extended_pubkey(path: &str, display: bool) -> Result<Self, Error> {
        Ok(Self::new(
            Kind::ExtendedPubkey,
            command::get_extended_pubkey(&derivation_path(path)?, display),
            None,
        ))
    }

    /// Registers `wallet`, returning its id and HMAC once the address at index 0 that the device
    /// derives for it has been independently verified.
    pub fn register_wallet(wallet: WalletPolicy) -> Self {
        let (command, interpreter) = protocol::prepare_register_wallet(&wallet);
        Self::new(
            Kind::RegisterWallet(Box::new(wallet)),
            command,
            Some(interpreter),
        )
    }

    /// Returns (and optionally shows) an address of `wallet`, after independently verifying it.
    /// `change` is 0 or 1; `hmac` is required for a wallet that is not a default one.
    pub fn get_wallet_address(
        wallet: WalletPolicy,
        hmac: Option<&[u8]>,
        change: u32,
        address_index: u32,
        display: bool,
    ) -> Result<Self, Error> {
        let change = match change {
            0 => false,
            1 => true,
            _ => return Err(invalid_argument("Invalid change")),
        };
        let hmac = wallet_hmac(hmac)?;
        let (command, interpreter) = protocol::prepare_get_wallet_address(
            &wallet,
            hmac.as_ref(),
            change,
            address_index,
            display,
        );
        Ok(Self::new(
            Kind::WalletAddress {
                wallet: Box::new(wallet),
                change,
                address_index,
            },
            command,
            Some(interpreter),
        ))
    }

    /// Signs the serialized PSBT `psbt` (version 0 or 2) with `wallet`. Its key-value pairs are
    /// sent to the device exactly as serialized.
    pub fn sign_psbt(
        psbt: &[u8],
        wallet: &WalletPolicy,
        hmac: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let hmac = wallet_hmac(hmac)?;
        let (command, interpreter) = protocol::prepare_sign_psbt_bytes(psbt, wallet, hmac.as_ref())
            .map_err(|error| invalid_argument(format!("Invalid PSBT: {}", error)))?;
        Ok(Self::new(Kind::SignPsbt, command, Some(interpreter)))
    }

    /// Signs `message` with the key at `path`, as in the `signmessage` RPC of Bitcoin Core.
    pub fn sign_message(message: &[u8], path: &str) -> Result<Self, Error> {
        let (command, interpreter) =
            protocol::prepare_sign_message(message, &derivation_path(path)?);
        Ok(Self::new(Kind::SignMessage, command, Some(interpreter)))
    }

    /// The APDU to send next, or `None` once the operation has completed or failed.
    pub fn next_apdu(&self) -> Option<Apdu> {
        match &self.state {
            State::Pending { command, .. } => Some(Apdu::from(command)),
            _ => None,
        }
    }

    /// The number of objects yielded so far by the request in progress, such as the signatures
    /// of a PSBT.
    pub fn yielded_count(&self) -> usize {
        match &self.state {
            State::Pending {
                interpreter: Some(interpreter),
                ..
            } => interpreter.yielded_count(),
            _ => 0,
        }
    }

    /// Processes the response to [`Operation::next_apdu`]: its status word, and its data without
    /// the status word. Returns the next APDU to send, or `None` when the operation completed.
    /// An error ends the operation.
    pub fn step(&mut self, sw: u16, data: Vec<u8>) -> Result<Option<Apdu>, Error> {
        let (kind, ins, mut interpreter) = match mem::replace(&mut self.state, State::Finished) {
            State::Pending {
                kind,
                ins,
                interpreter,
                ..
            } => (kind, ins, interpreter),
            State::Done(output) => {
                self.state = State::Done(output);
                return Err(Error::InvalidState("The operation has already completed"));
            }
            State::Finished => return Err(Error::InvalidState("The operation has finished")),
        };

        let status = match sw {
            SW_OK => StatusWord::OK,
            SW_INTERRUPTED_EXECUTION if interpreter.is_some() => StatusWord::InterruptedExecution,
            SW_INTERRUPTED_EXECUTION => {
                return Err(invalid_response(
                    "Unexpected SW_INTERRUPTED_EXECUTION received",
                ))
            }
            _ => return Err(Error::Device { ins, sw, data }),
        };
        let data = match protocol::handle_response(ins, status, data, interpreter.as_mut()) {
            Ok(Step::Continue(command)) => {
                self.state = State::Pending {
                    kind,
                    command,
                    ins,
                    interpreter,
                };
                return Ok(self.next_apdu());
            }
            Ok(Step::Done(data)) => data,
            Err(RequestError::Interpreter(error)) => return Err(invalid_response(error)),
            Err(error) => return Err(invalid_response(error)),
        };

        self.state = complete(kind, data, interpreter)?;
        Ok(self.next_apdu())
    }

    /// Takes the result of a completed operation.
    pub fn output(&mut self) -> Result<Output, Error> {
        match mem::replace(&mut self.state, State::Finished) {
            State::Done(output) => Ok(output),
            state @ State::Pending { .. } => {
                self.state = state;
                Err(Error::InvalidState("The operation has not completed"))
            }
            State::Finished => Err(Error::InvalidState("The operation has finished")),
        }
    }
}

/// Handles the successful final response of a request: either the operation's output, or the
/// next request of the operation.
fn complete(
    kind: Kind,
    data: Vec<u8>,
    interpreter: Option<ClientCommandInterpreter>,
) -> Result<State, Error> {
    let output = match kind {
        Kind::Version => {
            let (name, version, flags) =
                protocol::parse_version(&data).map_err(invalid_response)?;
            Output::Version {
                name,
                version,
                flags,
            }
        }
        Kind::MasterFingerprint => Output::MasterFingerprint(
            protocol::parse_master_fingerprint(&data)
                .map_err(invalid_response)?
                .to_bytes(),
        ),
        Kind::ExtendedPubkey => Output::ExtendedPubkey(
            protocol::parse_extended_pubkey(&data)
                .map_err(invalid_response)?
                .to_string(),
        ),
        Kind::RegisterWallet(wallet) => {
            let (id, hmac) =
                protocol::parse_wallet_registration(&data).map_err(invalid_response)?;
            let (command, interpreter) =
                protocol::prepare_get_wallet_address(&wallet, Some(&hmac), false, 0, false);
            return Ok(State::Pending {
                kind: Kind::RegisterWalletCheck { wallet, id, hmac },
                ins: command.ins,
                command,
                interpreter: Some(interpreter),
            });
        }
        Kind::RegisterWalletCheck { wallet, id, hmac } => {
            check_address(&wallet, false, 0, &data)?;
            Output::WalletRegistration { id, hmac }
        }
        Kind::WalletAddress {
            wallet,
            change,
            address_index,
        } => Output::WalletAddress(check_address(&wallet, change, address_index, &data)?),
        Kind::SignPsbt => {
            let yielded = interpreter.map(|i| i.yielded()).unwrap_or_default();
            Output::PsbtSignatures(sign_psbt_results(yielded)?)
        }
        Kind::SignMessage => {
            protocol::parse_message_signature(&data).map_err(invalid_response)?;
            Output::MessageSignature(data)
        }
    };
    Ok(State::Done(output))
}

/// Parses an address response and verifies it independently, returning it as the device sent it.
fn check_address(
    wallet: &WalletPolicy,
    change: bool,
    address_index: u32,
    data: &[u8],
) -> Result<String, Error> {
    let address = protocol::parse_wallet_address(data).map_err(invalid_response)?;
    wallet
        .check_address(change, address_index, &address)
        .map_err(invalid_response)?;
    Ok(String::from_utf8_lossy(data).into_owned())
}

fn sign_psbt_results(yielded: Vec<Vec<u8>>) -> Result<Vec<(u32, Yielded)>, Error> {
    if yielded.iter().any(|data| data.len() <= 1) {
        return Err(invalid_response("Invalid response"));
    }
    yielded
        .iter()
        .map(|data| {
            let (input_index, object) =
                protocol::parse_sign_psbt_yielded(data).map_err(|error| {
                    invalid_response(format!("Invalid SIGN_PSBT yielded value: {:?}", error))
                })?;
            Ok((input_index as u32, yielded_object(data, object)?))
        })
        .collect()
}

/// Converts a validated yielded object. Regular signatures are taken from the raw bytes, so
/// that they are returned exactly as the device produced them.
fn yielded_object(data: &[u8], object: SignPsbtYieldedObject) -> Result<Yielded, Error> {
    let malformed = || invalid_response("Invalid SIGN_PSBT yielded value");
    let (tag, offset) = read_compact_size(data).ok_or_else(malformed)?;
    Ok(match object {
        SignPsbtYieldedObject::Partial(_) => {
            // <input index> <pubkey_augm length> <pubkey_augm> <signature>
            let rest = &data[offset..];
            let len = *rest.first().ok_or_else(malformed)? as usize;
            let pubkey_augm = rest.get(1..1 + len).ok_or_else(malformed)?;
            let signature = rest[1 + len..].to_vec();
            if len == 64 {
                Yielded::PartialSignature {
                    pubkey: pubkey_augm[..32].to_vec(),
                    signature,
                    tapleaf_hash: Some(pubkey_augm[32..].to_vec()),
                }
            } else {
                Yielded::PartialSignature {
                    pubkey: pubkey_augm.to_vec(),
                    signature,
                    tapleaf_hash: None,
                }
            }
        }
        SignPsbtYieldedObject::MusigPubNonce(nonce) => Yielded::MusigPubNonce {
            participant_pubkey: nonce.participant_pubkey.to_bytes(),
            aggregate_pubkey: nonce.aggregate_pubkey.to_bytes(),
            tapleaf_hash: nonce.tapleaf_hash.map(|hash| hash.to_byte_array().to_vec()),
            pubnonce: nonce.pubnonce.to_vec(),
        },
        SignPsbtYieldedObject::MusigPartialSignature(signature) => Yielded::MusigPartialSignature {
            participant_pubkey: signature.participant_pubkey.to_bytes(),
            aggregate_pubkey: signature.aggregate_pubkey.to_bytes(),
            tapleaf_hash: signature
                .tapleaf_hash
                .map(|hash| hash.to_byte_array().to_vec()),
            partial_signature: signature.partial_signature.to_vec(),
        },
        SignPsbtYieldedObject::Unknown(data) => Yielded::Unknown { tag, data },
        _ => return Err(malformed()),
    })
}

/// Reads a compact-size integer, without the minimality checks (tags use the full range).
fn read_compact_size(data: &[u8]) -> Option<(u64, usize)> {
    let (len, prefix_len) = match *data.first()? {
        0xFD => (2, 1),
        0xFE => (4, 1),
        0xFF => (8, 1),
        n => return Some((n as u64, 1)),
    };
    let bytes = data.get(prefix_len..prefix_len + len)?;
    let mut value = [0u8; 8];
    value[..len].copy_from_slice(bytes);
    Some((u64::from_le_bytes(value), prefix_len + len))
}
