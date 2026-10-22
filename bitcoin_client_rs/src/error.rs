#![cfg(feature = "client")]

use core::fmt::Debug;

use crate::{apdu::StatusWord, interpreter::InterpreterError};

#[derive(Debug)]
pub enum BitcoinClientError<T: Debug> {
    ClientError(String),
    InvalidPsbt,
    Transport(T),
    Interpreter(InterpreterError),
    Device { command: u8, status: StatusWord },
    UnexpectedResult { command: u8, data: Vec<u8> },
    InvalidResponse(String),
    UnsupportedAppVersion,
}

impl<T: Debug> From<InterpreterError> for BitcoinClientError<T> {
    fn from(e: InterpreterError) -> BitcoinClientError<T> {
        BitcoinClientError::Interpreter(e)
    }
}

#[cfg(feature = "paranoid_client")]
impl<T: Debug> From<crate::protocol::AddressCheckError> for BitcoinClientError<T> {
    fn from(error: crate::protocol::AddressCheckError) -> Self {
        match error {
            crate::protocol::AddressCheckError::Mismatch => Self::InvalidResponse(error.to_string()),
            _ => Self::ClientError(error.to_string()),
        }
    }
}
