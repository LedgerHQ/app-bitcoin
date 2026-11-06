use core::fmt::Debug;

use crate::{apdu::StatusWord, interpreter::InterpreterError, protocol::RequestError};

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

impl<T: Debug> From<RequestError> for BitcoinClientError<T> {
    fn from(error: RequestError) -> Self {
        match error {
            RequestError::Device { command, status } => Self::Device { command, status },
            RequestError::Interpreter(error) => Self::Interpreter(error),
        }
    }
}
