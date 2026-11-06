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

The default features are `client`, `async`, and `paranoid_client`. Disable
defaults to use the public `command`, `interpreter`, `merkle`, `protocol`,
`psbt`, and `wallet` modules without either convenience client. Set
`default-features = false` on the dependency in Cargo.toml.

`protocol::prepare_register_wallet`, `prepare_get_wallet_address`,
`prepare_sign_message`, and `prepare_sign_psbt` each return an APDU command and
`ClientCommandInterpreter` state for a caller-owned exchange loop. PSBT
preparation is fallible because it translates the input to PSBTv2 maps.
Pass each response's typed `StatusWord` and owned payload (without status bytes)
to `protocol::handle_response`, always using the **original request instruction**.
Exchange `Step::Continue(command)` and repeat; `Step::Done(data)` is terminal.
`RequestError` distinguishes device-status errors from interpreter errors.
The protocol layer performs no transport I/O and selects no runtime.

`protocol` also exposes response parsers with detailed `ResponseError`
diagnostics. Convenience clients deliberately preserve their existing
`UnexpectedResult { command, data }` errors instead. After successful PSBT
signing, pass `interpreter.yielded()` to `protocol::parse_sign_psbt_results`.
Empty yield lists succeed; a yield of at most one byte takes precedence over
other parsing errors and reports all yields concatenated. Other failures own
only the offending yield, with a typed `PartialSignatureError` reason.
The terminal success payload is not a yield and is ignored by the clients.

Yielded input indices must fit in a `u32` on every host; tags still support the
full `u64` range. The parsers check encodings, not signed message digests.

Enable `client` for synchronous `BitcoinClient`/`Transport`, or `async` for
both client modules.

### Migrating to 0.8

This is a breaking feature/API release. In 0.7, `default-features = false`
still exposed the synchronous client. In 0.8, add `features = ["client"]`
to keep it, or `features = ["async"]` to enable both clients.

The public protocol `continue_interrupted` helper is replaced by the full
`handle_response` step above; the low-level `command::continue_interrupted`
builder remains available.

Well-encoded yielded indices above `u32::MAX` now return
`PartialSignatureError::InvalidInputIndex`; malformed CompactSize encodings
still return `InvalidLength`.

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
