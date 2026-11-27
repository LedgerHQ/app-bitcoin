use core::convert::TryFrom;
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "async")]
use async_trait::async_trait;
use bitcoin::hashes::hex::FromHex;

#[cfg(feature = "async")]
use ledger_bitcoin_client::async_client;
use ledger_bitcoin_client::{
    apdu::{APDUCommand, StatusWord},
    client,
};

#[derive(Default, Clone)]
pub struct RecordStore {
    pub queue: Vec<(Vec<u8>, Vec<u8>)>,
}

impl RecordStore {
    pub fn new(exchanges: &Vec<String>) -> RecordStore {
        let mut store = RecordStore::default();
        let mut command: Vec<u8> = Vec::new();
        for (i, exchange) in exchanges.iter().enumerate() {
            let exchange = exchange.replace(" ", "");
            if let Some(cmd) = exchange.strip_prefix("=>") {
                command = Vec::from_hex(cmd).expect(&format!("Wrong tests data {}: {}", i, cmd));
            }
            if let Some(resp) = exchange.strip_prefix("<=") {
                let resp = Vec::from_hex(resp).expect(&format!("Wrong tests data {}: {}", i, resp));
                store.queue.push((command.clone(), resp));
            }
        }

        store
    }
}

pub struct TransportReplayer {
    store: RecordStore,
    current: AtomicUsize,
}

impl TransportReplayer {
    pub fn new(store: RecordStore) -> TransportReplayer {
        TransportReplayer {
            store,
            current: AtomicUsize::new(0),
        }
    }

    fn replay(&self, command: &APDUCommand) -> Result<(StatusWord, Vec<u8>), MockError> {
        let payload = command.encode();
        let current = self.current.load(Ordering::Relaxed);
        if let Some((req, res)) = self.store.queue.get(current) {
            if payload != *req {
                return Err(MockError::ExchangeNotFound(current, hex::encode(payload)));
            }
            self.current.store(current + 1, Ordering::Relaxed);
            let res = res.as_slice();
            let mut buff = [b'\0'; 2];
            buff.copy_from_slice(&res[res.len() - 2..res.len()]);
            let sw = u16::from_be_bytes(buff);
            let answer = &res[0..res.len() - 2];
            return Ok((
                StatusWord::try_from(sw).expect("Wrong tests data"),
                answer.to_vec(),
            ));
        }
        Err(MockError::ExchangeNotFound(current, hex::encode(payload)))
    }
}

impl client::Transport for TransportReplayer {
    type Error = MockError;
    fn exchange(&self, command: &APDUCommand) -> Result<(StatusWord, Vec<u8>), Self::Error> {
        self.replay(command)
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl async_client::Transport for TransportReplayer {
    type Error = MockError;
    async fn exchange(&self, command: &APDUCommand) -> Result<(StatusWord, Vec<u8>), Self::Error> {
        self.replay(command)
    }
}

#[derive(Debug)]
pub enum MockError {
    ExchangeNotFound(usize, String),
}
