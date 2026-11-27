use core::convert::TryFrom;
use core::fmt::{self, Debug};

// p2 encodes the protocol version implemented
pub const CURRENT_PROTOCOL_VERSION: u8 = 1;

#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Cla {
    Default = 0xB0,
    Bitcoin = 0xE1,
    Framework = 0xF8,
}

#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BitcoinCommandCode {
    GetExtendedPubkey = 0x00,
    GetVersion = 0x01,
    RegisterWallet = 0x02,
    GetWalletAddress = 0x03,
    SignPSBT = 0x04,
    GetMasterFingerprint = 0x05,
    SignMessage = 0x10,
}

#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameworkCommandCode {
    ContinueInterrupted = 0x01,
}

#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ClientCommandCode {
    Yield = 0x10,
    GetPreimage = 0x40,
    GetMerkleLeafProof = 0x41,
    GetMerkleLeafIndex = 0x42,
    GetMoreElements = 0xA0,
}

impl TryFrom<u8> for ClientCommandCode {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x10 => Ok(ClientCommandCode::Yield),
            0x40 => Ok(ClientCommandCode::GetPreimage),
            0x41 => Ok(ClientCommandCode::GetMerkleLeafProof),
            0x42 => Ok(ClientCommandCode::GetMerkleLeafIndex),
            0xA0 => Ok(ClientCommandCode::GetMoreElements),
            _ => Err(()),
        }
    }
}

/// The status word that ends each response of the device.
///
/// The statuses that the Bitcoin app and the OS can send are associated constants, which can be
/// used in patterns. Any other value is kept as is.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct StatusWord(pub u16);

#[allow(non_upper_case_globals)]
impl StatusWord {
    /// The device is locked
    pub const DeviceLocked: Self = Self(0x5515);
    /// Security status not satisfied, for example because the device is locked
    pub const SecurityStatusNotSatisfied: Self = Self(0x6982);
    /// Rejected by user
    pub const Deny: Self = Self(0x6985);
    /// Incorrect Data
    pub const IncorrectData: Self = Self(0x6A80);
    /// Not Supported
    pub const NotSupported: Self = Self(0x6A82);
    /// Wrong P1P2
    pub const WrongP1P2: Self = Self(0x6A86);
    /// Wrong DataLength
    pub const WrongDataLength: Self = Self(0x6A87);
    /// The transaction does not match the swap parameters
    pub const SwapFail: Self = Self(0x6B00);
    /// Ins not supported
    pub const InsNotSupported: Self = Self(0x6D00);
    /// Cla not supported
    pub const ClaNotSupported: Self = Self(0x6E00);
    /// Wrong response length
    pub const WrongResponseLength: Self = Self(0xB000);
    /// Bad state
    pub const BadState: Self = Self(0xB007);
    /// Signature fail
    pub const SignatureFail: Self = Self(0xB008);
    /// Success
    pub const OK: Self = Self(0x9000);
    /// The command is interrupted, and requires the client's response
    pub const InterruptedExecution: Self = Self(0xE000);

    /// The name of the status, if it is one of the associated constants.
    pub fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::DeviceLocked => "DeviceLocked",
            Self::SecurityStatusNotSatisfied => "SecurityStatusNotSatisfied",
            Self::Deny => "Deny",
            Self::IncorrectData => "IncorrectData",
            Self::NotSupported => "NotSupported",
            Self::WrongP1P2 => "WrongP1P2",
            Self::WrongDataLength => "WrongDataLength",
            Self::SwapFail => "SwapFail",
            Self::InsNotSupported => "InsNotSupported",
            Self::ClaNotSupported => "ClaNotSupported",
            Self::WrongResponseLength => "WrongResponseLength",
            Self::BadState => "BadState",
            Self::SignatureFail => "SignatureFail",
            Self::OK => "OK",
            Self::InterruptedExecution => "InterruptedExecution",
            _ => return None,
        })
    }
}

impl From<u16> for StatusWord {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<StatusWord> for u16 {
    fn from(status: StatusWord) -> Self {
        status.0
    }
}

impl fmt::Debug for StatusWord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "StatusWord({:#06x})", self.0),
        }
    }
}

impl fmt::Display for StatusWord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#06x}", self.0)?;
        if let Some(name) = self.name() {
            write!(f, " ({})", name)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct APDUCommand {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
}

impl APDUCommand {
    pub fn encode(&self) -> Vec<u8> {
        let mut vec = vec![self.cla, self.ins, self.p1, self.p2, self.data.len() as u8];
        vec.extend(self.data.iter());
        vec
    }
}

impl core::default::Default for APDUCommand {
    fn default() -> Self {
        Self {
            cla: Cla::Default as u8,
            ins: 0x00,
            p1: 0x00,
            p2: CURRENT_PROTOCOL_VERSION,
            data: Vec::new(),
        }
    }
}
