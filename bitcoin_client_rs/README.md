# Ledger Bitcoin application client

Client library in [Rust](https://www.rust-lang.org/) for the Ledger 
Bitcoin application with minimal dependencies.

If you wish to contribute to this library, please read
[CONTRIBUTING.md](CONTRIBUTING.md).

## Minimum Supported Rust Version

`bitcoin_client_rs` compiles with **Rust 1.78** or newer, as declared by
`rust-version` in Cargo.toml.

## Getting started

The `client::BitcoinClient` struct implements the methods that call and
interpret the commands between the Ledger device and your software. 


```rust
pub struct BitcoinClient<T: Transport> {...}
impl<T: Transport> BitcoinClient<T> {
    pub fn get_extended_pubkey(
        &self,
        path: &bitcoin::bip32::DerivationPath,
        display: bool,
    ) -> Result<bitcoin::bip32::Xpub, BitcoinClientError<T::Error>>;
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

The default features are `client`, `async` and `paranoid_client`. With
`default-features = false`, the crate exposes the protocol without the
convenience clients, in the `apdu`, `command`, `interpreter`, `protocol`,
`psbt` and `wallet` modules. This lets an application that owns the device I/O
reuse the protocol implementation.

Each command has a `protocol::prepare_*` function returning a `Request` (in a
`Result` for `prepare_sign_psbt`, as converting the PSBT can fail), which
answers the client commands of the device in `Request::step`, and most have a
`protocol::parse_*` function for the final response. The documentation of
`protocol::Request` shows the exchange loop.

Enable `client` for the synchronous `BitcoinClient`, or `async` for both
clients.

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

## WASM and `no_std`

The transport-free build, with or without `paranoid_client`, supports
`wasm32-unknown-unknown`. It remains **std-based**, as on native targets.
Disabling the convenience clients does not make this crate `no_std`;
`no_std` targets are not supported.

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
