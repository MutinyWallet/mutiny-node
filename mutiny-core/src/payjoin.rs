use once_cell::sync::Lazy;
use payjoin::OhttpKeys;
use url::Url;

pub(crate) static OHTTP_RELAYS: [Lazy<Url>; 3] = [
    Lazy::new(|| Url::parse("https://ohttp.payjoin.org").expect("Invalid URL")),
    Lazy::new(|| Url::parse("https://ohttp-relay.obscuravpn.io").expect("Invalid URL")),
    Lazy::new(|| Url::parse("https://pj.bobspacebkk.com").expect("Invalid URL")),
];

pub(crate) static PAYJOIN_DIR: Lazy<Url> =
    Lazy::new(|| Url::parse("https://payjo.in").expect("Invalid URL"));

pub async fn fetch_ohttp_keys(
    _ohttp_relay: Url,
    directory: Url,
) -> Result<OhttpKeys, Box<dyn std::error::Error>> {
    let http_client = reqwest::Client::builder().build().unwrap();

    let ohttp_keys_res = http_client
        .get(format!("{}/ohttp-keys", directory.as_ref()))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    Ok(OhttpKeys::decode(ohttp_keys_res.as_ref())?)
}

#[derive(Debug)]
pub enum Error {
    Reqwest(reqwest::Error),
    ReceiverStateMachine(payjoin::receive::Error),
    Wallet(payjoin::Error),
    Txid(bitcoin::hashes::hex::Error),
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            Error::Reqwest(e) => write!(f, "Reqwest error: {}", e),
            Error::ReceiverStateMachine(e) => write!(f, "Payjoin error: {}", e),
            Error::Wallet(e) => write!(f, "Payjoin wallet error: {}", e),
            Error::Txid(e) => write!(f, "Payjoin txid error: {}", e),
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
        Error::ReceiverStateMachine(e)
    }
}
