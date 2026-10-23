use core::fmt::Debug;

use async_trait::async_trait;

use bitcoin::{
    address,
    bip32::{DerivationPath, Fingerprint, Xpub},
    secp256k1::ecdsa::Signature,
    Psbt,
};

use crate::{
    apdu::{APDUCommand, StatusWord},
    command,
    error::BitcoinClientError,
    interpreter::ClientCommandInterpreter,
    protocol::*,
    wallet::WalletPolicy,
};

/// BitcoinClient calls and interprets commands with the Ledger Device.
/// The methods can only be used by an asynchronous engine like tokio.
pub struct BitcoinClient<T: Transport> {
    transport: T,
}

impl<T: Transport> BitcoinClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    async fn make_request(
        &self,
        req: &APDUCommand,
        interpreter: Option<&mut ClientCommandInterpreter>,
    ) -> Result<Vec<u8>, BitcoinClientError<T::Error>> {
        let (mut sw, mut data) = self
            .transport
            .exchange(req)
            .await
            .map_err(BitcoinClientError::Transport)?;

        if let Some(interpreter) = interpreter {
            while sw == StatusWord::InterruptedExecution {
                let response = interpreter.execute(data)?;
                let res = self
                    .transport
                    .exchange(&command::continue_interrupted(response))
                    .await
                    .map_err(BitcoinClientError::Transport)?;
                sw = res.0;
                data = res.1;
            }
        }

        if sw != StatusWord::OK {
            Err(BitcoinClientError::Device {
                status: sw,
                command: req.ins,
            })
        } else {
            Ok(data)
        }
    }

    /// Returns the currently running app's name, version and state flags
    pub async fn get_version(
        &self,
    ) -> Result<(String, String, Vec<u8>), BitcoinClientError<T::Error>> {
        let cmd = command::get_version();
        let data = self.make_request(&cmd, None).await?;
        parse_version(&data).map_err(|_| BitcoinClientError::UnexpectedResult {
            command: cmd.ins,
            data,
        })
    }

    /// Retrieve the master fingerprint.
    pub async fn get_master_fingerprint(
        &self,
    ) -> Result<Fingerprint, BitcoinClientError<T::Error>> {
        let cmd = command::get_master_fingerprint();
        let data = self.make_request(&cmd, None).await?;
        parse_master_fingerprint(&data).map_err(|_| BitcoinClientError::UnexpectedResult {
            command: cmd.ins,
            data,
        })
    }

    /// Retrieve the bip32 extended pubkey derived with the given path
    /// and optionally display it on screen
    pub async fn get_extended_pubkey(
        &self,
        path: &DerivationPath,
        display: bool,
    ) -> Result<Xpub, BitcoinClientError<T::Error>> {
        let cmd = command::get_extended_pubkey(path, display);
        let data = self.make_request(&cmd, None).await?;
        parse_extended_pubkey(&data).map_err(|_| BitcoinClientError::UnexpectedResult {
            command: cmd.ins,
            data,
        })
    }

    /// Registers the given wallet policy, returns the wallet ID and HMAC.
    pub async fn register_wallet(
        &self,
        wallet: &WalletPolicy,
    ) -> Result<([u8; 32], [u8; 32]), BitcoinClientError<T::Error>> {
        let cmd = command::register_wallet(wallet);
        let mut intpr = ClientCommandInterpreter::for_wallet(wallet);
        let data = self.make_request(&cmd, Some(&mut intpr)).await?;
        let (id, hmac) =
            parse_wallet_registration(&data).map_err(|_| BitcoinClientError::UnexpectedResult {
                command: cmd.ins,
                data,
            })?;

        #[cfg(feature = "paranoid_client")]
        {
            self.get_wallet_address(wallet, Some(&hmac), false, 0, false)
                .await?;
        }

        Ok((id, hmac))
    }

    /// For a given wallet that was already registered on the device (or a standard wallet that does not need registration),
    /// returns the address for a certain `change`/`address_index` combination.
    pub async fn get_wallet_address(
        &self,
        wallet: &WalletPolicy,
        wallet_hmac: Option<&[u8; 32]>,
        change: bool,
        address_index: u32,
        display: bool,
    ) -> Result<bitcoin::Address<address::NetworkUnchecked>, BitcoinClientError<T::Error>> {
        let mut intpr = ClientCommandInterpreter::for_wallet(wallet);
        let cmd = command::get_wallet_address(wallet, wallet_hmac, change, address_index, display);
        let data = self.make_request(&cmd, Some(&mut intpr)).await?;
        let address =
            parse_wallet_address(&data).map_err(|_| BitcoinClientError::UnexpectedResult {
                command: cmd.ins,
                data,
            })?;

        #[cfg(feature = "paranoid_client")]
        {
            check_address(wallet, change, address_index, &address)
                .map_err(BitcoinClientError::from)?;
        }

        Ok(address)
    }

    /// Signs a PSBT using a registered wallet (or a standard wallet that does not need registration).
    /// Signature requires explicit approval from the user.
    ///
    /// Each yielded payload is decoded into a [`SignPsbtYieldedObject`], which
    /// covers regular partial signatures as well as MuSig2 round 1 / round 2
    /// payloads.
    #[allow(clippy::type_complexity)]
    pub async fn sign_psbt(
        &self,
        psbt: &Psbt,
        wallet: &WalletPolicy,
        wallet_hmac: Option<&[u8; 32]>,
    ) -> Result<Vec<(usize, SignPsbtYieldedObject)>, BitcoinClientError<T::Error>> {
        let (cmd, mut intpr) = prepare_sign_psbt(psbt, wallet, wallet_hmac)
            .map_err(|_| BitcoinClientError::InvalidPsbt)?;

        self.make_request(&cmd, Some(&mut intpr)).await?;

        let results = intpr.yielded();
        if results.iter().any(|res| res.len() <= 1) {
            return Err(BitcoinClientError::UnexpectedResult {
                command: cmd.ins,
                data: results.into_iter().fold(Vec::new(), |mut acc, res| {
                    acc.extend(res);
                    acc
                }),
            });
        }

        let mut yielded_objects = Vec::new();
        for result in results {
            let (input_index, obj) = parse_sign_psbt_yielded(&result).map_err(|_| {
                BitcoinClientError::UnexpectedResult {
                    command: cmd.ins,
                    data: result,
                }
            })?;
            yielded_objects.push((input_index, obj));
        }

        Ok(yielded_objects)
    }

    /// Sign a message with the key derived with the given derivation path.
    /// Result is the header byte (31-34: P2PKH compressed) and the ecdsa signature.
    pub async fn sign_message(
        &self,
        message: &[u8],
        path: &DerivationPath,
    ) -> Result<(u8, Signature), BitcoinClientError<T::Error>> {
        let (cmd, mut intpr) = prepare_sign_message(message, path);
        let data = self.make_request(&cmd, Some(&mut intpr)).await?;
        parse_message_signature(&data).map_err(|_| BitcoinClientError::UnexpectedResult {
            command: cmd.ins,
            data,
        })
    }
}

/// Asynchronous communication layer between the bitcoin client and the Ledger device.
#[async_trait]
pub trait Transport {
    type Error: Debug;
    async fn exchange(&self, command: &APDUCommand) -> Result<(StatusWord, Vec<u8>), Self::Error>;
}
