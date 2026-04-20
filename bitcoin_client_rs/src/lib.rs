mod command;
mod interpreter;
mod merkle;

#[cfg(feature = "paranoid_client")]
mod bip327;

pub mod apdu;
pub mod client;
pub mod error;
pub mod psbt;
pub mod wallet;

#[cfg(feature = "async")]
pub mod async_client;

pub use client::{BitcoinClient, Transport};
pub use wallet::{WalletPolicy, WalletPubKey};
