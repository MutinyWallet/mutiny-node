use crate::auth::MutinyAuthClient;
use crate::encrypt::{decrypt_with_key, encrypt_with_key};
use crate::{error::MutinyError, logging::MutinyLogger};
use anyhow::anyhow;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use hex_conservative::DisplayHex;
use lightning::util::logger::*;
use lightning::{log_error, log_info};
use reqwest::{Method, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

pub struct MutinyVssClient {
    auth_client: Option<Arc<MutinyAuthClient>>,
    client: Option<reqwest::Client>,
    url: String,
    store_id: Option<String>,
    encryption_key: SecretKey,
    pub logger: Arc<MutinyLogger>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyVersion {
    pub key: String,
    pub version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VssKeyValueItem {
    pub key: String,
    pub value: Value,
    pub version: u32,
}

impl VssKeyValueItem {
    /// Encrypts the value of the item using the encryption key
    /// and returns an encrypted version of the item
    pub(crate) fn encrypt(self, encryption_key: &SecretKey) -> EncryptedVssKeyValueItem {
        // should we handle this unwrap better?
        let bytes = self.value.to_string().into_bytes();

        let value = encrypt_with_key(encryption_key, &bytes);

        EncryptedVssKeyValueItem {
            key: self.key,
            value,
            version: self.version,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedVssKeyValueItem {
    pub key: String,
    pub value: Vec<u8>,
    pub version: u32,
}

impl EncryptedVssKeyValueItem {
    pub(crate) fn decrypt(
        self,
        encryption_key: &SecretKey,
    ) -> Result<VssKeyValueItem, MutinyError> {
        let decrypted = decrypt_with_key(encryption_key, self.value)?;
        let decrypted_value = String::from_utf8(decrypted)?;
        let value = serde_json::from_str(&decrypted_value)?;

        Ok(VssKeyValueItem {
            key: self.key,
            value,
            version: self.version,
        })
    }
}

impl MutinyVssClient {
    pub fn new_authenticated(
        auth_client: Arc<MutinyAuthClient>,
        url: String,
        encryption_key: SecretKey,
        logger: Arc<MutinyLogger>,
    ) -> Self {
        log_info!(logger, "Creating authenticated vss client");
        Self {
            auth_client: Some(auth_client),
            client: None,
            url,
            store_id: None, // we get this from the auth client
            encryption_key,
            logger,
        }
    }

    pub fn new_unauthenticated(
        url: String,
        encryption_key: SecretKey,
        logger: Arc<MutinyLogger>,
    ) -> Self {
        log_info!(logger, "Creating unauthenticated vss client");
        let pk = encryption_key
            .public_key(&Secp256k1::new())
            .serialize()
            .to_lower_hex_string();
        Self {
            auth_client: None,
            client: Some(reqwest::Client::new()),
            url,
            store_id: Some(pk),
            encryption_key,
            logger,
        }
    }

    async fn make_request(
        &self,
        method: Method,
        url: Url,
        body: Option<Value>,
    ) -> Result<reqwest::Response, MutinyError> {
        match (self.auth_client.as_ref(), self.client.as_ref()) {
            (Some(auth), _) => auth.request(method, url, body).await,
            (None, Some(client)) => {
                let mut request = client.request(method, url);
                if let Some(body) = body {
                    request = request.json(&body);
                }
                request.send().await.map_err(|e| {
                    log_error!(self.logger, "Error making request: {e}");
                    MutinyError::Other(anyhow!("Error making request: {e}"))
                })
            }
            (None, None) => unreachable!("No auth client or http client"),
        }
    }

    pub async fn put_objects(&self, items: Vec<VssKeyValueItem>) -> Result<(), MutinyError> {
        let url = Url::parse(&format!("{}/putObjects", self.url)).map_err(|e| {
            log_error!(self.logger, "Error parsing put objects url: {e}");
            MutinyError::InvalidArgumentsError
        })?;

        let items = items
            .into_iter()
            .map(|item| item.encrypt(&self.encryption_key))
            .collect::<Vec<_>>();

        // todo do we need global version here?
        let body = json!({ "store_id": self.store_id, "transaction_items": items });

        self.make_request(Method::PUT, url, Some(body)).await?;

        Ok(())
    }

    pub async fn get_object(&self, key: &str) -> Result<VssKeyValueItem, MutinyError> {
        let url = Url::parse(&format!("{}/getObject", self.url)).map_err(|e| {
            log_error!(self.logger, "Error parsing get objects url: {e}");
            MutinyError::InvalidArgumentsError
        })?;

        let body = json!({ "store_id": self.store_id, "key": key });

        let result: EncryptedVssKeyValueItem = self
            .make_request(Method::POST, url, Some(body))
            .await?
            .json()
            .await
            .map_err(|e| {
                log_error!(self.logger, "Error parsing get objects response: {e}");
                MutinyError::Other(anyhow!("Error parsing get objects response: {e}"))
            })?;

        result.decrypt(&self.encryption_key)
    }

    pub async fn list_key_versions(
        &self,
        key_prefix: Option<String>,
    ) -> Result<Vec<KeyVersion>, MutinyError> {
        let url = Url::parse(&format!("{}/listKeyVersions", self.url)).map_err(|e| {
            log_error!(self.logger, "Error parsing list key versions url: {e}");
            MutinyError::InvalidArgumentsError
        })?;

        let body = json!({ "store_id": self.store_id, "key_prefix": key_prefix });

        let result = self
            .make_request(Method::POST, url, Some(body))
            .await?
            .json()
            .await
            .map_err(|e| {
                log_error!(self.logger, "Error parsing list key versions response: {e}");
                MutinyError::Other(anyhow!("Error parsing list key versions response: {e}"))
            })?;

        Ok(result)
    }
}
