# Ledger Bitcoin application client

Client library in [Rust](https://www.rust-lang.org/) for the Ledger 
Bitcoin application with minimal dependencies.

If you wish to contribute to this library, please read
[CONTRIBUTING.md](CONTRIBUTING.md).

## Minimum Supported Rust Version

`bitcoin_client_rs` should always compile using **Rust 1.60**.

## Getting started

The `client::BitcoinClient` struct implements the methods that call and
interpret the commands between the Ledger device and your software. 


```rust
pub struct BitcoinClient<T: Transport> {...}
impl<T: Transport> BitcoinClient<T> {
    pub fn get_extended_pubkey(
        &self,
        path: &bitcoin::util::bip32::DerivationPath,
        display: bool,
    ) -> Result<bitcoin::util::bip32::ExtendedPubKey, BitcoinClientError<T::Error>>;
}
```

It requires an internal connection implementing the `client::Transport`
Trait.

```rust
pub trait Transport {
    type Error: Debug;
    fn exchange(&self, command: &APDUCommand) -> Result<(StatusWord, Vec<u8>), Self::Error>;
}
```

In order to satisfy this Trait, it is possible to import the
`ledger-transport-hid` crate from https://github.com/Zondax/ledger-rs.
Please, read the `examples/ledger_hwi/src/transport.rs` file to find an example.

## Transport-free protocol use

The default features are `client`, `async`, and `paranoid_client`. Disable
defaults to use the public `command`, `interpreter`, `merkle`, `protocol`,
`psbt`, and `wallet` modules without either convenience client. Set
`default-features = false` on the dependency in Cargo.toml.

`protocol` exposes response parsers and message/PSBT preparation, returning an
APDU command and `ClientCommandInterpreter` state for a caller-owned exchange
loop. `ClientCommandInterpreter::for_wallet` prepares wallet requests;
`psbt::apply_partial_signature` validates input indices before updating a PSBT.
The parsers check response encodings, not signed message digests.

Enable `client` for synchronous `BitcoinClient`/`Transport`, or `async` for
both client modules. The independent `paranoid_client` feature enables
`protocol::check_address` and its existing miniscript dependency without
enabling either client. When driving exchanges yourself, call this verifier
for returned addresses and perform the authenticated address follow-up after
registration. Default convenience clients already perform these checks.
Both pure feature combinations support `wasm32-unknown-unknown`.

## The `async` feature

The optional feature `async` adds the `async_client` module to the crate
and imports the `async_trait` library. The `async_client::BitcoinClient` 
struct is an asynchronous equivalent to the `BitcoinClient` struct. It 
requires an internal connection implementing the `async_client::Transport` Trait.

```rust
#[async_trait]
pub trait Transport {
    type Error: Debug;
    async fn exchange(&self, command: &APDUCommand) -> Result<(StatusWord, Vec<u8>), Self::Error>;
}
```

## The `no-std` support

Work in progress.

## Example

The code source for a simple tool to communicate with either a Ledger device or Speculos
emulator can be found in the `examples` directory.

Example of a command to retrieve the extended pubkey with the given
derivation path and display it on the device screen:  
```
cargo run --package ledger_hwi -- \
get-extended-pubkey --derivation-path "m/44'/0'/0'/0/0" --display
```

## Acknowledgements

The initial version of this client was contributed by Edouard PARIS.
