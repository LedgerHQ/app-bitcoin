pub mod command;
pub mod interpreter;
pub mod merkle;

#[cfg(feature = "paranoid_client")]
mod bip327;

pub mod apdu;
#[cfg(feature = "client")]
pub mod client;
pub mod error;
pub mod protocol;
pub mod psbt;
pub mod wallet;

#[cfg(feature = "async")]
pub mod async_client;

#[cfg(feature = "client")]
pub use client::{BitcoinClient, Transport};
pub use protocol::{MusigPartialSignature, MusigPubNonce, SignPsbtYieldedObject};
pub use psbt::{PartialSignature, PartialSignatureError};
pub use wallet::{WalletPolicy, WalletPubKey};
