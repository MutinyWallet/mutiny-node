use once_cell::sync::Lazy;
use payjoin::OhttpKeys;
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

pub async fn fetch_ohttp_keys(directory: Url) -> Result<OhttpKeys, Error> {
    let http_client = reqwest::Client::builder().build()?;

    let ohttp_keys_res = http_client
        .get(format!("{}/ohttp-keys", directory.as_ref()))
        .send()
        .await?
        .bytes()
        .await?;
    OhttpKeys::decode(ohttp_keys_res.as_ref()).map_err(|_| Error::OhttpDecodeFailed)
}

#[derive(Debug)]
pub enum Error {
    Reqwest(reqwest::Error),
    ReceiverStateMachine(String),
    Txid(bitcoin::hashes::hex::Error),
    OhttpDecodeFailed,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            Error::Reqwest(e) => write!(f, "Reqwest error: {}", e),
            Error::ReceiverStateMachine(e) => write!(f, "Payjoin state machine error: {}", e),
            Error::Txid(e) => write!(f, "Payjoin txid error: {}", e),
            Error::OhttpDecodeFailed => write!(f, "Failed to decode ohttp keys"),
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
