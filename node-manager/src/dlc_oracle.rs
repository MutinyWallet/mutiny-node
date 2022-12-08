#[allow(unused)]
#[allow(dead_code)]
use std::io::Cursor;

use chrono::{DateTime, NaiveDateTime, SecondsFormat, Utc};
use dlc_manager::contract::ser::Serializable;
use dlc_manager::error::Error;
use dlc_manager::Oracle;
use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
use secp256k1::{schnorr::Signature, XOnlyPublicKey};

use crate::error::MutinyStorageError;
use crate::localstorage::MutinyBrowserStorage;

pub struct MutinyOracle {
    storage: MutinyBrowserStorage,
    host: String,
    pubkey: XOnlyPublicKey,
}

const ORACLE_ANNOUNCEMENT_KEY_PREFIX: &str = "oracle_announcement_";
const ORACLE_ATTESTATION_KEY_PREFIX: &str = "oracle_attestation_";

impl MutinyOracle {
    pub async fn new(host: &str, storage: MutinyBrowserStorage) -> Result<MutinyOracle, Error> {
        if host.is_empty() {
            return Err(Error::InvalidParameters("Invalid host".to_string()));
        }
        let host = if !host.ends_with('/') {
            format!("{host}/")
        } else {
            host.to_string()
        };
        let path = pubkey_path(&host);
        let pubkey = get::<PublicKeyResponse>(&path).await?.public_key;
        Ok(MutinyOracle {
            storage,
            host,
            pubkey,
        })
    }

    pub async fn fetch(&self, event_id: &str) -> Result<(), Error> {
        let (asset_id, date_time) = parse_event_id(event_id)?;
        let path = announcement_path(&self.host, &asset_id, &date_time);
        let announcement = get::<AnnouncementResponse>(&path).await?;

        let key = format!("{ORACLE_ANNOUNCEMENT_KEY_PREFIX}{event_id}");
        self.storage.set(key, announcement)?;

        let (asset_id, date_time) = parse_event_id(event_id)?;
        let path = attestation_path(&self.host, &asset_id, &date_time);
        let AttestationResponse {
            event_id: _,
            signatures,
            values,
        } = get::<AttestationResponse>(&path).await?;

        let attestation = OracleAttestation {
            oracle_public_key: self.pubkey,
            signatures,
            outcomes: values,
        };

        let key = format!("{ORACLE_ATTESTATION_KEY_PREFIX}{event_id}");
        self.storage.set(key, attestation.serialize()?)?;

        Ok(())
    }
}

impl Oracle for MutinyOracle {
    fn get_public_key(&self) -> XOnlyPublicKey {
        self.pubkey
    }

    fn get_announcement(&self, event_id: &str) -> Result<OracleAnnouncement, Error> {
        let key = format!("{ORACLE_ANNOUNCEMENT_KEY_PREFIX}{event_id}");
        let result: Result<OracleAnnouncement, MutinyStorageError> = self.storage.get(key);

        result.map_err(|_| Error::StorageError("Failed to read from storage".to_string()))
    }

    fn get_attestation(&self, event_id: &str) -> Result<OracleAttestation, Error> {
        let key = format!("{ORACLE_ATTESTATION_KEY_PREFIX}{event_id}");
        let result: Result<Vec<u8>, MutinyStorageError> = self.storage.get(key);

        match result {
            Ok(bytes) => {
                let ann = OracleAttestation::deserialize(&mut Cursor::new(bytes))
                    .map_err(|e| Error::StorageError(format!("{}", e)))?;
                Ok(ann)
            }
            Err(_) => Err(Error::StorageError(
                "Failed to read from storage".to_string(),
            )),
        }
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyResponse {
    public_key: XOnlyPublicKey,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct EventDescriptor {
    base: u16,
    is_signed: bool,
    unit: String,
    precision: i32,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct Event {
    nonces: Vec<XOnlyPublicKey>,
    event_maturity: DateTime<Utc>,
    event_id: String,
    event_descriptor: EventDescriptor,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AnnouncementResponse {
    oracle_public_key: XOnlyPublicKey,
    oracle_event: Event,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AttestationResponse {
    event_id: String,
    signatures: Vec<Signature>,
    values: Vec<String>,
}

fn pubkey_path(host: &str) -> String {
    format!("{}{}", host, "oracle/publickey")
}

fn announcement_path(host: &str, asset_id: &str, date_time: &DateTime<Utc>) -> String {
    format!(
        "{}asset/{}/announcement/{}",
        host,
        asset_id,
        date_time.to_rfc3339_opts(SecondsFormat::Secs, true)
    )
}

fn attestation_path(host: &str, asset_id: &str, date_time: &DateTime<Utc>) -> String {
    format!(
        "{}asset/{}/attestation/{}",
        host,
        asset_id,
        date_time.to_rfc3339_opts(SecondsFormat::Secs, true)
    )
}

fn parse_event_id(event_id: &str) -> Result<(String, DateTime<Utc>), Error> {
    let asset_id = &event_id[..6];
    let timestamp_str = &event_id[6..];
    let timestamp: i64 = timestamp_str
        .parse()
        .map_err(|_| Error::OracleError("Invalid timestamp format".to_string()))?;
    let naive_date_time = NaiveDateTime::from_timestamp_opt(timestamp, 0).ok_or_else(|| {
        Error::InvalidParameters(format!("Invalid timestamp {} in event id", timestamp))
    })?;
    let date_time = DateTime::from_utc(naive_date_time, Utc);
    println!("{}", date_time);
    Ok((asset_id.to_string(), date_time))
}

async fn get<T>(path: &str) -> Result<T, Error>
where
    T: serde::de::DeserializeOwned,
{
    reqwest::get(path)
        .await
        .map_err(|x| Error::IOError(std::io::Error::new(std::io::ErrorKind::Other, x)))?
        .json::<T>()
        .await
        .map_err(|e| Error::OracleError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    const url: &str = "https://oracle.p2pderivatives.io/";

    #[test]
    fn parse_event_test() {
        let event_id = "btcusd1624943400";
        let expected_asset_id = "btcusd";
        let expected_date_time = DateTime::parse_from_rfc3339("2021-06-29T05:10:00Z").unwrap();

        let (asset_id, date_time) = parse_event_id(event_id).expect("Error parsing event id");

        assert_eq!(expected_asset_id, asset_id);
        assert_eq!(expected_date_time, date_time);
    }

    // #[test]
    // async fn get_public_key_test() {
    //     let storage = MutinyBrowserStorage::new("".to_string());
    //     let expected_pk: XOnlyPublicKey =
    //         "ce4b7ad2b45de01f0897aa716f67b4c2f596e54506431e693f898712fe7e9bf3"
    //             .parse()
    //             .unwrap();
    //
    //     let client = MutinyOracle::new(url, storage)
    //         .await
    //         .expect("Error creating client instance.");
    //
    //     assert_eq!(expected_pk, client.get_public_key());
    //
    //     cleanup_test();
    // }
    //
    // #[test]
    // async fn get_announcement_test() {
    //     let storage = MutinyBrowserStorage::new("".to_string());
    //     let client = MutinyOracle::new(url, storage)
    //         .await
    //         .expect("Error creating client instance");
    //
    //     let event_id = "btcusd1624943400";
    //
    //     let _ = client.fetch(event_id).await;
    //     let ann = client
    //         .get_announcement(event_id)
    //         .expect("Error getting announcement");
    //
    //     assert_eq!(ann.oracle_event.oracle_nonces.len(), 20);
    //
    //     cleanup_test();
    // }
    //
    // #[test]
    // async fn get_attestation_test() {
    //     let storage = MutinyBrowserStorage::new("".to_string());
    //
    //     let client = MutinyOracle::new(url, storage)
    //         .await
    //         .expect("Error creating client instance");
    //
    //     let event_id = "btcusd1624943400";
    //     client.fetch(event_id).await.expect("failed to fetch");
    //
    //     let attestation = client
    //         .get_attestation(event_id)
    //         .expect("Error getting attestation");
    //
    //     assert_eq!(attestation.signatures.len(), 20);
    //
    //     cleanup_test();
    // }
}
