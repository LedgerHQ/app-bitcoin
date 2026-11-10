//! The native module of the `ledger_bitcoin` Python package.
//!
//! It exposes the transport-free [`Operation`](bindings::Operation) of the Rust client; the
//! Python side of the package owns the transport, runs the APDU loop, and converts the results
//! into its public types. Wallet policies cross the boundary as their BIP-388 parts (name,
//! descriptor template, key information strings and version).

use ledger_bitcoin_client_bindings::{self as bindings, Output, Yielded};
use pyo3::{
    create_exception,
    exceptions::{PyException, PyRuntimeError, PyValueError},
    prelude::*,
    types::{PyBytes, PyDict, PyTuple},
};

create_exception!(
    _native,
    DeviceError,
    PyException,
    "The device answered with an error status word. Its args are (ins, sw, data): the \
     instruction of the request, the status word and the response data."
);

fn to_py_err(error: bindings::Error) -> PyErr {
    match error {
        bindings::Error::InvalidArgument(message) => PyValueError::new_err(message),
        bindings::Error::Device { ins, sw, data } => DeviceError::new_err((ins, sw, data)),
        error @ (bindings::Error::InvalidResponse(_) | bindings::Error::InvalidState(_)) => {
            PyRuntimeError::new_err(error.to_string())
        }
    }
}

fn wallet(
    name: &str,
    descriptor_template: &str,
    keys: Vec<String>,
    version: u8,
) -> PyResult<ledger_bitcoin_client::wallet::WalletPolicy> {
    bindings::wallet_policy(name, descriptor_template, &keys, version).map_err(to_py_err)
}

/// An APDU as a `(cla, ins, p1, p2, data)` tuple.
fn apdu_tuple<'py>(
    py: Python<'py>,
    apdu: Option<bindings::Apdu>,
) -> PyResult<Option<Bound<'py, PyTuple>>> {
    apdu.map(|apdu| {
        (
            apdu.cla,
            apdu.ins,
            apdu.p1,
            apdu.p2,
            PyBytes::new(py, &apdu.data),
        )
            .into_pyobject(py)
    })
    .transpose()
}

fn optional_bytes<'py>(py: Python<'py>, bytes: &Option<Vec<u8>>) -> Option<Bound<'py, PyBytes>> {
    bytes.as_ref().map(|bytes| PyBytes::new(py, bytes))
}

/// A yielded object as an `(input_index, kind, fields)` tuple, where `fields` is a dict of
/// the fields of `kind`.
fn yielded_tuple<'py>(
    py: Python<'py>,
    input_index: u32,
    yielded: &Yielded,
) -> PyResult<Bound<'py, PyTuple>> {
    let fields = PyDict::new(py);
    let kind = match yielded {
        Yielded::PartialSignature {
            pubkey,
            signature,
            tapleaf_hash,
        } => {
            fields.set_item("pubkey", PyBytes::new(py, pubkey))?;
            fields.set_item("signature", PyBytes::new(py, signature))?;
            fields.set_item("tapleaf_hash", optional_bytes(py, tapleaf_hash))?;
            "partial_signature"
        }
        Yielded::MusigPubNonce {
            participant_pubkey,
            aggregate_pubkey,
            tapleaf_hash,
            pubnonce,
        } => {
            fields.set_item("participant_pubkey", PyBytes::new(py, participant_pubkey))?;
            fields.set_item("aggregate_pubkey", PyBytes::new(py, aggregate_pubkey))?;
            fields.set_item("tapleaf_hash", optional_bytes(py, tapleaf_hash))?;
            fields.set_item("pubnonce", PyBytes::new(py, pubnonce))?;
            "musig_pubnonce"
        }
        Yielded::MusigPartialSignature {
            participant_pubkey,
            aggregate_pubkey,
            tapleaf_hash,
            partial_signature,
        } => {
            fields.set_item("participant_pubkey", PyBytes::new(py, participant_pubkey))?;
            fields.set_item("aggregate_pubkey", PyBytes::new(py, aggregate_pubkey))?;
            fields.set_item("tapleaf_hash", optional_bytes(py, tapleaf_hash))?;
            fields.set_item("partial_signature", PyBytes::new(py, partial_signature))?;
            "musig_partial_signature"
        }
        Yielded::Unknown { tag, data } => {
            fields.set_item("tag", tag)?;
            fields.set_item("data", PyBytes::new(py, data))?;
            "unknown"
        }
    };
    (input_index, kind, fields).into_pyobject(py)
}

fn output_object<'py>(py: Python<'py>, output: Output) -> PyResult<Bound<'py, PyAny>> {
    Ok(match output {
        Output::Version {
            name,
            version,
            flags,
        } => (name, version, PyBytes::new(py, &flags))
            .into_pyobject(py)?
            .into_any(),
        Output::MasterFingerprint(fingerprint) => PyBytes::new(py, &fingerprint).into_any(),
        Output::ExtendedPubkey(xpub) => xpub.into_pyobject(py)?.into_any(),
        Output::WalletRegistration { id, hmac } => (PyBytes::new(py, &id), PyBytes::new(py, &hmac))
            .into_pyobject(py)?
            .into_any(),
        Output::WalletAddress(address) => address.into_pyobject(py)?.into_any(),
        Output::PsbtSignatures(results) => results
            .iter()
            .map(|(index, yielded)| yielded_tuple(py, *index, yielded))
            .collect::<PyResult<Vec<_>>>()?
            .into_pyobject(py)?
            .into_any(),
        Output::MessageSignature(signature) => PyBytes::new(py, &signature).into_any(),
    })
}

/// One client call, as a state machine over the APDUs it exchanges with the device.
///
/// Send `next_apdu()`, pass each response to `step(sw, data)` (which returns the next APDU, or
/// `None` once the operation completed), then call `output()`. APDUs are
/// `(cla, ins, p1, p2, data)` tuples.
#[pyclass(module = "ledger_bitcoin._native")]
struct Operation {
    inner: bindings::Operation,
}

impl From<bindings::Operation> for Operation {
    fn from(inner: bindings::Operation) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl Operation {
    #[staticmethod]
    fn get_version() -> Self {
        bindings::Operation::get_version().into()
    }

    #[staticmethod]
    fn get_master_fingerprint() -> Self {
        bindings::Operation::get_master_fingerprint().into()
    }

    #[staticmethod]
    fn get_extended_pubkey(path: &str, display: bool) -> PyResult<Self> {
        bindings::Operation::get_extended_pubkey(path, display)
            .map(Self::from)
            .map_err(to_py_err)
    }

    #[staticmethod]
    fn register_wallet(
        name: &str,
        descriptor_template: &str,
        keys: Vec<String>,
        version: u8,
    ) -> PyResult<Self> {
        Ok(
            bindings::Operation::register_wallet(wallet(name, descriptor_template, keys, version)?)
                .into(),
        )
    }

    #[staticmethod]
    #[allow(clippy::too_many_arguments)]
    fn get_wallet_address(
        name: &str,
        descriptor_template: &str,
        keys: Vec<String>,
        version: u8,
        hmac: Option<&[u8]>,
        change: u32,
        address_index: u32,
        display: bool,
    ) -> PyResult<Self> {
        bindings::Operation::get_wallet_address(
            wallet(name, descriptor_template, keys, version)?,
            hmac,
            change,
            address_index,
            display,
        )
        .map(Self::from)
        .map_err(to_py_err)
    }

    #[staticmethod]
    fn sign_psbt(
        psbt: &[u8],
        name: &str,
        descriptor_template: &str,
        keys: Vec<String>,
        version: u8,
        hmac: Option<&[u8]>,
    ) -> PyResult<Self> {
        bindings::Operation::sign_psbt(
            psbt,
            &wallet(name, descriptor_template, keys, version)?,
            hmac,
        )
        .map(Self::from)
        .map_err(to_py_err)
    }

    #[staticmethod]
    fn sign_message(message: &[u8], path: &str) -> PyResult<Self> {
        bindings::Operation::sign_message(message, path)
            .map(Self::from)
            .map_err(to_py_err)
    }

    /// The APDU to send next, or None once the operation has completed or failed.
    fn next_apdu<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyTuple>>> {
        apdu_tuple(py, self.inner.next_apdu())
    }

    /// Processes the response to the last APDU: its status word, and its data without the
    /// status word. Returns the next APDU, or None once the operation has completed.
    fn step<'py>(
        &mut self,
        py: Python<'py>,
        sw: u16,
        data: Vec<u8>,
    ) -> PyResult<Option<Bound<'py, PyTuple>>> {
        let apdu = self.inner.step(sw, data).map_err(to_py_err)?;
        apdu_tuple(py, apdu)
    }

    /// The number of objects yielded so far by the request in progress.
    fn yielded_count(&self) -> usize {
        self.inner.yielded_count()
    }

    /// Takes the result of the completed operation.
    fn output<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let output = self.inner.output().map_err(to_py_err)?;
        output_object(py, output)
    }
}

/// The serialization of a wallet policy, as registered on the device.
#[pyfunction]
fn wallet_policy_serialize<'py>(
    py: Python<'py>,
    name: &str,
    descriptor_template: &str,
    keys: Vec<String>,
    version: u8,
) -> PyResult<Bound<'py, PyBytes>> {
    Ok(PyBytes::new(
        py,
        &wallet(name, descriptor_template, keys, version)?.serialize(),
    ))
}

/// The id of a wallet policy: the SHA-256 hash of its serialization.
#[pyfunction]
fn wallet_policy_id<'py>(
    py: Python<'py>,
    name: &str,
    descriptor_template: &str,
    keys: Vec<String>,
    version: u8,
) -> PyResult<Bound<'py, PyBytes>> {
    Ok(PyBytes::new(
        py,
        &wallet(name, descriptor_template, keys, version)?.id(),
    ))
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Operation>()?;
    m.add_function(wrap_pyfunction!(wallet_policy_serialize, m)?)?;
    m.add_function(wrap_pyfunction!(wallet_policy_id, m)?)?;
    m.add("DeviceError", m.py().get_type::<DeviceError>())?;
    Ok(())
}
