use std::collections::HashMap;
use std::sync::Arc;

use crate::error::MutinyError;
use crate::storage::MutinyStorage;
use bitcoin::{psbt::Psbt, Transaction, Txid};
use core::time::Duration;
use gloo_net::websocket::futures::WebSocket;
use hex_conservative::DisplayHex;
use once_cell::sync::Lazy;
use payjoin::receive::v2::Enrolled;
use payjoin::OhttpKeys;
use pj::send::RequestContext;
use serde::{Deserialize, Serialize};
use url::Url;

pub(crate) static OHTTP_RELAYS: [Lazy<Url>; 2] = [
    Lazy::new(|| Url::parse("https://pj.bobspacebkk.com").expect("Invalid URL")),
    Lazy::new(|| Url::parse("https://ohttp-relay.obscuravpn.io").expect("Invalid URL")),
];

pub fn random_ohttp_relay() -> &'static Url {
    let mut buf = [0u8; 1];
    getrandom::getrandom(&mut buf).expect("Failed to get random byte");
    let idx = (buf[0] as usize) % OHTTP_RELAYS.len();
    &OHTTP_RELAYS[idx]
}

pub(crate) static PAYJOIN_DIR: Lazy<Url> =
    Lazy::new(|| Url::parse("https://payjo.in").expect("Invalid URL"));

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecvSession {
    pub enrolled: Enrolled,
    pub expiry: Duration,
    pub payjoin_tx: Option<Transaction>,
}

impl RecvSession {
    pub fn pubkey(&self) -> [u8; 33] {
        self.enrolled.pubkey()
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SendSession {
    pub original_psbt: Psbt,
    pub req_ctx: RequestContext,
    pub labels: Vec<String>,
    pub expiry: Duration,
}

pub trait PayjoinStorage {
    fn list_recv_sessions(&self) -> Result<Vec<RecvSession>, MutinyError>;
    fn store_new_recv_session(&self, session: Enrolled) -> Result<RecvSession, MutinyError>;
    fn update_recv_session(&self, session: RecvSession) -> Result<(), MutinyError>;
    fn delete_recv_session(&self, id: &[u8; 33]) -> Result<(), MutinyError>;

    fn list_send_sessions(&self) -> Result<Vec<SendSession>, MutinyError>;
    fn store_new_send_session(
        &self,
        labels: Vec<String>,
        original_psbt: Psbt,
        req_ctx: RequestContext,
    ) -> Result<SendSession, MutinyError>;
    fn update_send_session(&self, session: SendSession) -> Result<(), MutinyError>;
    fn delete_send_session(&self, session: SendSession) -> Result<(), MutinyError>;
}

const RECV_PAYJOIN_KEY_PREFIX: &str = "recvpj/";
const SEND_PAYJOIN_KEY_PREFIX: &str = "sendpj/";

fn get_recv_key(id: &[u8; 33]) -> String {
    format!("{RECV_PAYJOIN_KEY_PREFIX}{}", id.as_hex())
}

fn get_send_key(original_txid: Txid) -> String {
    format!("{RECV_PAYJOIN_KEY_PREFIX}{}", original_txid)
}

impl<S: MutinyStorage> PayjoinStorage for S {
    fn list_recv_sessions(&self) -> Result<Vec<RecvSession>, MutinyError> {
        let map: HashMap<String, RecvSession> = self.scan(RECV_PAYJOIN_KEY_PREFIX, None)?;
        Ok(map.values().map(|v| v.to_owned()).collect())
    }

    fn store_new_recv_session(&self, enrolled: Enrolled) -> Result<RecvSession, MutinyError> {
        let in_24_hours = crate::utils::now() + Duration::from_secs(60 * 60 * 24);
        let session = RecvSession {
            enrolled,
            expiry: in_24_hours,
            payjoin_tx: None,
        };
        self.set_data(get_recv_key(&session.pubkey()), session.clone(), None)
            .map(|_| session)
    }

    fn update_recv_session(&self, session: RecvSession) -> Result<(), MutinyError> {
        self.set_data(get_recv_key(&session.pubkey()), session, None)
    }

    fn delete_recv_session(&self, id: &[u8; 33]) -> Result<(), MutinyError> {
        self.delete(&[get_recv_key(id)])
    }

    fn store_new_send_session(
        &self,
        labels: Vec<String>,
        original_psbt: Psbt,
        req_ctx: RequestContext,
    ) -> Result<SendSession, MutinyError> {
        let in_24_hours = crate::utils::now() + Duration::from_secs(60 * 60 * 24);
        let o_txid = original_psbt.clone().extract_tx().txid();
        let session = SendSession {
            labels,
            original_psbt,
            expiry: in_24_hours,
            req_ctx,
        };
        self.set_data(o_txid.to_string(), session.clone(), None)
            .map(|_| session)
    }

    fn list_send_sessions(&self) -> Result<Vec<SendSession>, MutinyError> {
        let map: HashMap<String, SendSession> = self.scan(SEND_PAYJOIN_KEY_PREFIX, None)?;
        Ok(map.values().map(|v| v.to_owned()).collect())
    }

    fn update_send_session(&self, session: SendSession) -> Result<(), MutinyError> {
        let o_txid = session.clone().original_psbt.extract_tx().txid();
        self.set_data(get_send_key(o_txid), session, None)
    }

    fn delete_send_session(&self, session: SendSession) -> Result<(), MutinyError> {
        let o_txid = session.original_psbt.extract_tx().txid();
        self.delete(&[get_send_key(o_txid)])
    }
}

pub async fn fetch_ohttp_keys() -> Result<OhttpKeys, Error> {
    use futures_util::{AsyncReadExt, AsyncWriteExt};

    let tls_connector = {
        let root_store = futures_rustls::rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let config = futures_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        futures_rustls::TlsConnector::from(Arc::new(config))
    };
    let directory_host = PAYJOIN_DIR.host_str().ok_or(Error::BadDirectoryHost)?;
    let domain = futures_rustls::rustls::pki_types::ServerName::try_from(directory_host)
        .map_err(|_| Error::BadDirectoryHost)?
        .to_owned();

    let ws = WebSocket::open(&format!(
        "wss://{}:443",
        random_ohttp_relay()
            .host_str()
            .ok_or(Error::BadOhttpWsHost)?
    ))
    .map_err(|_| Error::BadOhttpWsHost)?;

    let mut tls_stream = tls_connector
        .connect(domain, ws)
        .await
        .map_err(|e| Error::RequestFailed(e.to_string()))?;
    let ohttp_keys_req = format!(
        "GET /ohttp-keys HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        directory_host
    );
    tls_stream
        .write_all(ohttp_keys_req.as_bytes())
        .await
        .map_err(|e| Error::RequestFailed(e.to_string()))?;
    tls_stream
        .flush()
        .await
        .map_err(|e| Error::RequestFailed(e.to_string()))?;
    let mut response_bytes = Vec::new();
    tls_stream
        .read_to_end(&mut response_bytes)
        .await
        .map_err(|e| Error::RequestFailed(e.to_string()))?;
    let (_headers, res_body) = separate_headers_and_body(&response_bytes)?;
    payjoin::OhttpKeys::decode(res_body).map_err(|_| Error::OhttpDecodeFailed)
}

fn separate_headers_and_body(response_bytes: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let separator = b"\r\n\r\n";

    // Search for the separator
    if let Some(position) = response_bytes
        .windows(separator.len())
        .position(|window| window == separator)
    {
        // The body starts immediately after the separator
        let body_start_index = position + separator.len();
        let headers = &response_bytes[..position];
        let body = &response_bytes[body_start_index..];

        Ok((headers, body))
    } else {
        Err(Error::RequestFailed(
            "No header-body separator found in the response".to_string(),
        ))
    }
}

#[derive(Debug)]
pub enum Error {
    Reqwest(reqwest::Error),
    ReceiverStateMachine(String),
    Txid(bitcoin::hashes::hex::Error),
    OhttpDecodeFailed,
    Shutdown,
    SessionExpired,
    BadDirectoryHost,
    BadOhttpWsHost,
    RequestFailed(String),
    CancelPayjoinTx,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            Error::Reqwest(e) => write!(f, "Reqwest error: {}", e),
            Error::ReceiverStateMachine(e) => write!(f, "Payjoin state machine error: {}", e),
            Error::Txid(e) => write!(f, "Payjoin txid error: {}", e),
            Error::OhttpDecodeFailed => write!(f, "Failed to decode ohttp keys"),
            Error::Shutdown => write!(f, "Payjoin stopped by application shutdown"),
            Error::SessionExpired => write!(f, "Payjoin session expired. Create a new payment request and have the sender try again."),
            Error::BadDirectoryHost => write!(f, "Bad directory host"),
            Error::BadOhttpWsHost => write!(f, "Bad ohttp ws host"),
            Error::RequestFailed(e) => write!(f, "Request failed: {}", e),
            Error::CancelPayjoinTx => write!(f, "Failed to cancel payjoin tx in wallet"),
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Reqwest(e)
    }
}

impl From<payjoin::receive::Error> for Error {
    fn from(e: payjoin::receive::Error) -> Self {
        Error::ReceiverStateMachine(e.to_string())
    }
}
