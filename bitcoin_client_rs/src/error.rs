use core::fmt::{self, Debug};

use crate::{apdu::StatusWord, interpreter::InterpreterError, protocol::RequestError};

/// An error of the convenience clients.
#[non_exhaustive]
#[derive(Debug)]
pub enum BitcoinClientError<T: Debug> {
    ClientError(String),
    InvalidPsbt,
    /// An error of the transport. As `T` only needs to implement `Debug`, the message of this
    /// error shows it, and [`source`](std::error::Error::source) does not return it.
    Transport(T),
    Interpreter(InterpreterError),
    /// The device returned an error status. When the app reports an error code, as it does for
    /// some failures, `data` is that 2-byte code.
    #[non_exhaustive]
    Device {
        command: u8,
        status: StatusWord,
        data: Vec<u8>,
    },
    #[non_exhaustive]
    UnexpectedResult {
        command: u8,
        data: Vec<u8>,
    },
    InvalidResponse(String),
    UnsupportedAppVersion,
}

impl<T: Debug> fmt::Display for BitcoinClientError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientError(message) | Self::InvalidResponse(message) => f.write_str(message),
            Self::InvalidPsbt => f.write_str("Invalid PSBT"),
            Self::Transport(error) => write!(f, "Transport error: {:?}", error),
            Self::Interpreter(error) => fmt::Display::fmt(error, f),
            Self::Device {
                command,
                status,
                data,
            } => crate::protocol::write_device_error(f, *command, *status, data),
            Self::UnexpectedResult { command, data } => write!(
                f,
                "Unexpected response to command {:#04x} ({} bytes)",
                command,
                data.len()
            ),
            Self::UnsupportedAppVersion => f.write_str("Unsupported app version"),
        }
    }
}

impl<T: Debug> std::error::Error for BitcoinClientError<T> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            // Transparent: the interpreter error is the message itself.
            Self::Interpreter(error) => error.source(),
            _ => None,
        }
    }
}

impl<T: Debug> From<InterpreterError> for BitcoinClientError<T> {
    fn from(e: InterpreterError) -> BitcoinClientError<T> {
        BitcoinClientError::Interpreter(e)
    }
}

impl<T: Debug> From<RequestError> for BitcoinClientError<T> {
    fn from(error: RequestError) -> Self {
        match error {
            RequestError::Device {
                command,
                status,
                data,
            } => Self::Device {
                command,
                status,
                data,
            },
            RequestError::Interpreter(error) => Self::Interpreter(error),
            RequestError::Finished => Self::ClientError(error.to_string()),
        }
    }
}
