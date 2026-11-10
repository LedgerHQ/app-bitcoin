//! The WebAssembly module of the `@ledgerhq/ledger-bitcoin` package.
//!
//! It exposes the transport-free [`Operation`](bindings::Operation) of the Rust client; the
//! TypeScript side of the package owns the (asynchronous) transport, runs the APDU loop, and
//! converts the results into its public types. Calls into this module are synchronous.
//!
//! Errors are JavaScript `Error`s with a `code` property: `InvalidArgument`, `Device` (with the
//! `ins`, `sw` and `data` of the failed request), `InvalidResponse` or `InvalidState`.

use js_sys::{Array, Error, Object, Reflect, Uint8Array};
use ledger_bitcoin_client_bindings::{self as bindings, Output, Yielded};
use wasm_bindgen::prelude::*;

fn set(object: &Object, key: &str, value: impl Into<JsValue>) {
    // setting a property of a plain object cannot fail
    Reflect::set(object, &JsValue::from_str(key), &value.into()).expect("plain object");
}

fn bytes(data: &[u8]) -> Uint8Array {
    Uint8Array::from(data)
}

fn optional_bytes(data: &Option<Vec<u8>>) -> JsValue {
    data.as_deref()
        .map_or(JsValue::UNDEFINED, |data| bytes(data).into())
}

fn to_js_error(error: bindings::Error) -> JsValue {
    let js_error = Error::new(&error.to_string());
    let object: &Object = js_error.as_ref();
    match error {
        bindings::Error::InvalidArgument(_) => set(object, "code", "InvalidArgument"),
        bindings::Error::Device { ins, sw, data } => {
            set(object, "code", "Device");
            set(object, "ins", ins);
            set(object, "sw", sw);
            set(object, "data", bytes(&data));
        }
        bindings::Error::InvalidResponse(_) => set(object, "code", "InvalidResponse"),
        bindings::Error::InvalidState(_) => set(object, "code", "InvalidState"),
    }
    js_error.into()
}

fn wallet(
    name: &str,
    descriptor_template: &str,
    keys: Vec<String>,
    version: u8,
) -> Result<ledger_bitcoin_client::wallet::WalletPolicy, JsValue> {
    bindings::wallet_policy(name, descriptor_template, &keys, version).map_err(to_js_error)
}

/// An APDU command to send to the device.
#[wasm_bindgen]
pub struct Apdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    #[wasm_bindgen(getter_with_clone)]
    pub data: Vec<u8>,
}

impl From<bindings::Apdu> for Apdu {
    fn from(apdu: bindings::Apdu) -> Self {
        Self {
            cla: apdu.cla,
            ins: apdu.ins,
            p1: apdu.p1,
            p2: apdu.p2,
            data: apdu.data,
        }
    }
}

/// A yielded object as `{ kind, ...fields }`, with camelCase field names.
fn yielded_object(yielded: &Yielded) -> Object {
    let object = Object::new();
    match yielded {
        Yielded::PartialSignature {
            pubkey,
            signature,
            tapleaf_hash,
        } => {
            set(&object, "kind", "partialSignature");
            set(&object, "pubkey", bytes(pubkey));
            set(&object, "signature", bytes(signature));
            set(&object, "tapleafHash", optional_bytes(tapleaf_hash));
        }
        Yielded::MusigPubNonce {
            participant_pubkey,
            aggregate_pubkey,
            tapleaf_hash,
            pubnonce,
        } => {
            set(&object, "kind", "musigPubNonce");
            set(&object, "participantPubkey", bytes(participant_pubkey));
            set(&object, "aggregatePubkey", bytes(aggregate_pubkey));
            set(&object, "tapleafHash", optional_bytes(tapleaf_hash));
            set(&object, "pubnonce", bytes(pubnonce));
        }
        Yielded::MusigPartialSignature {
            participant_pubkey,
            aggregate_pubkey,
            tapleaf_hash,
            partial_signature,
        } => {
            set(&object, "kind", "musigPartialSignature");
            set(&object, "participantPubkey", bytes(participant_pubkey));
            set(&object, "aggregatePubkey", bytes(aggregate_pubkey));
            set(&object, "tapleafHash", optional_bytes(tapleaf_hash));
            set(&object, "partialSignature", bytes(partial_signature));
        }
        Yielded::Unknown { tag, data } => {
            set(&object, "kind", "unknown");
            // tags are at most 64 bits
            set(&object, "tag", js_sys::BigInt::from(*tag));
            set(&object, "data", bytes(data));
        }
    }
    object
}

fn output_value(output: Output) -> JsValue {
    match output {
        Output::Version {
            name,
            version,
            flags,
        } => {
            let object = Object::new();
            set(&object, "name", name);
            set(&object, "version", version);
            set(&object, "flags", bytes(&flags));
            object.into()
        }
        Output::MasterFingerprint(fingerprint) => bytes(&fingerprint).into(),
        Output::ExtendedPubkey(xpub) => xpub.into(),
        Output::WalletRegistration { id, hmac } => {
            let object = Object::new();
            set(&object, "id", bytes(&id));
            set(&object, "hmac", bytes(&hmac));
            object.into()
        }
        Output::WalletAddress(address) => address.into(),
        Output::PsbtSignatures(results) => results
            .iter()
            .map(|(index, yielded)| Array::of2(&JsValue::from(*index), &yielded_object(yielded)))
            .collect::<Array>()
            .into(),
        Output::MessageSignature(signature) => bytes(&signature).into(),
    }
}

/// One client call, as a state machine over the APDUs it exchanges with the device.
///
/// Send `nextApdu()`, pass each response to `step(sw, data)` (which returns the next APDU, or
/// `undefined` once the operation completed), then call `output()`.
#[wasm_bindgen]
pub struct Operation {
    inner: bindings::Operation,
}

impl From<bindings::Operation> for Operation {
    fn from(inner: bindings::Operation) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
impl Operation {
    #[wasm_bindgen(js_name = getVersion)]
    pub fn get_version() -> Operation {
        bindings::Operation::get_version().into()
    }

    #[wasm_bindgen(js_name = getMasterFingerprint)]
    pub fn get_master_fingerprint() -> Operation {
        bindings::Operation::get_master_fingerprint().into()
    }

    #[wasm_bindgen(js_name = getExtendedPubkey)]
    pub fn get_extended_pubkey(path: &str, display: bool) -> Result<Operation, JsValue> {
        bindings::Operation::get_extended_pubkey(path, display)
            .map(Operation::from)
            .map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = registerWallet)]
    pub fn register_wallet(
        name: &str,
        descriptor_template: &str,
        keys: Vec<String>,
        version: u8,
    ) -> Result<Operation, JsValue> {
        Ok(
            bindings::Operation::register_wallet(wallet(name, descriptor_template, keys, version)?)
                .into(),
        )
    }

    #[wasm_bindgen(js_name = getWalletAddress)]
    #[allow(clippy::too_many_arguments)]
    pub fn get_wallet_address(
        name: &str,
        descriptor_template: &str,
        keys: Vec<String>,
        version: u8,
        hmac: Option<Vec<u8>>,
        change: u32,
        address_index: u32,
        display: bool,
    ) -> Result<Operation, JsValue> {
        bindings::Operation::get_wallet_address(
            wallet(name, descriptor_template, keys, version)?,
            hmac.as_deref(),
            change,
            address_index,
            display,
        )
        .map(Operation::from)
        .map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = signPsbt)]
    pub fn sign_psbt(
        psbt: &[u8],
        name: &str,
        descriptor_template: &str,
        keys: Vec<String>,
        version: u8,
        hmac: Option<Vec<u8>>,
    ) -> Result<Operation, JsValue> {
        bindings::Operation::sign_psbt(
            psbt,
            &wallet(name, descriptor_template, keys, version)?,
            hmac.as_deref(),
        )
        .map(Operation::from)
        .map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = signMessage)]
    pub fn sign_message(message: &[u8], path: &str) -> Result<Operation, JsValue> {
        bindings::Operation::sign_message(message, path)
            .map(Operation::from)
            .map_err(to_js_error)
    }

    /// The APDU to send next, or undefined once the operation has completed or failed.
    #[wasm_bindgen(js_name = nextApdu)]
    pub fn next_apdu(&self) -> Option<Apdu> {
        self.inner.next_apdu().map(Apdu::from)
    }

    /// Processes the response to the last APDU: its status word, and its data without the
    /// status word. Returns the next APDU, or undefined once the operation has completed.
    pub fn step(&mut self, sw: u16, data: Vec<u8>) -> Result<Option<Apdu>, JsValue> {
        self.inner
            .step(sw, data)
            .map(|apdu| apdu.map(Apdu::from))
            .map_err(to_js_error)
    }

    /// The number of objects yielded so far by the request in progress.
    #[wasm_bindgen(js_name = yieldedCount)]
    pub fn yielded_count(&self) -> usize {
        self.inner.yielded_count()
    }

    /// Takes the result of the completed operation.
    pub fn output(&mut self) -> Result<JsValue, JsValue> {
        self.inner.output().map(output_value).map_err(to_js_error)
    }
}

/// The serialization of a wallet policy, as registered on the device.
#[wasm_bindgen(js_name = walletPolicySerialize)]
pub fn wallet_policy_serialize(
    name: &str,
    descriptor_template: &str,
    keys: Vec<String>,
    version: u8,
) -> Result<Vec<u8>, JsValue> {
    Ok(wallet(name, descriptor_template, keys, version)?.serialize())
}

/// The id of a wallet policy: the SHA-256 hash of its serialization.
#[wasm_bindgen(js_name = walletPolicyId)]
pub fn wallet_policy_id(
    name: &str,
    descriptor_template: &str,
    keys: Vec<String>,
    version: u8,
) -> Result<Vec<u8>, JsValue> {
    Ok(wallet(name, descriptor_template, keys, version)?
        .id()
        .to_vec())
}
