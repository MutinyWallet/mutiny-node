use crate::auth::MutinyAuthClient;
use crate::encrypt::{decrypt_with_key, encrypt_with_key};
use crate::{error::MutinyError, logging::MutinyLogger};
use anyhow::anyhow;
use bitcoin::secp256k1::SecretKey;
use lightning::log_error;
use lightning::util::logger::*;
use reqwest::{Method, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

pub struct MutinyVssClient {
    auth_client: Arc<MutinyAuthClient>,
    url: String,
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
    pub fn new(
        auth_client: Arc<MutinyAuthClient>,
        url: String,
        encryption_key: SecretKey,
        logger: Arc<MutinyLogger>,
    ) -> Self {
        Self {
            auth_client,
            url,
            encryption_key,
            logger,
        }
    }

    pub async fn put_objects(&self, items: Vec<VssKeyValueItem>) -> Result<(), MutinyError> {
        let url = Url::parse(&format!("{}/putObjects", self.url)).map_err(|e| {
            log_error!(self.logger, "Error parsing put objects url: {e}");
            MutinyError::Other(anyhow!("Error parsing put objects url: {e}"))
        })?;

        let items = items
            .into_iter()
            .map(|item| item.encrypt(&self.encryption_key))
            .collect::<Vec<_>>();

        // todo do we need global version here?
        let body = json!({ "transaction_items": items });

        self.auth_client
            .request(Method::PUT, url, Some(body))
            .await?;

        Ok(())
    }

    pub async fn get_object(&self, key: &str) -> Result<VssKeyValueItem, MutinyError> {
        let url = Url::parse(&format!("{}/getObject", self.url)).map_err(|e| {
            log_error!(self.logger, "Error parsing get objects url: {e}");
            MutinyError::Other(anyhow!("Error parsing get objects url: {e}"))
        })?;

        let body = json!({ "key": key });
        let result: EncryptedVssKeyValueItem = self
            .auth_client
            .request(Method::POST, url, Some(body))
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
            MutinyError::Other(anyhow!("Error parsing list key versions url: {e}"))
        })?;

        let body = json!({ "key_prefix": key_prefix });
        let result = self
            .auth_client
            .request(Method::POST, url, Some(body))
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

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::test_utils::*;

    #[tokio::test]
    async fn test_vss() {
        let client = create_vss_client().await;

        let key = "hello".to_string();
        let value: Value = serde_json::from_str("\"world\"").unwrap();
        let obj = VssKeyValueItem {
            key: key.clone(),
            value: value.clone(),
            version: 0,
        };

        client.put_objects(vec![obj.clone()]).await.unwrap();

        let result = client.get_object(&key).await.unwrap();
        assert_eq!(obj, result);

        let result = client.list_key_versions(None).await.unwrap();
        let key_version = KeyVersion { key, version: 0 };

        assert_eq!(vec![key_version], result);
        assert_eq!(result.len(), 1);
    }

    #[tokio::test]
    async fn test_vss_versions() {
        let client = create_vss_client().await;

        let key = "hello".to_string();
        let value: Value = serde_json::from_str("\"world\"").unwrap();
        let obj = VssKeyValueItem {
            key: key.clone(),
            value: value.clone(),
            version: 0,
        };

        client.put_objects(vec![obj.clone()]).await.unwrap();
        let result = client.get_object(&key).await.unwrap();
        assert_eq!(obj.clone(), result);

        let value1: Value = serde_json::from_str("\"new world\"").unwrap();
        let obj1 = VssKeyValueItem {
            key: key.clone(),
            value: value1.clone(),
            version: 1,
        };

        client.put_objects(vec![obj1.clone()]).await.unwrap();
        let result = client.get_object(&key).await.unwrap();
        assert_eq!(obj1, result);

        // check we get version 1
        client.put_objects(vec![obj]).await.unwrap();
        let result = client.get_object(&key).await.unwrap();
        assert_eq!(obj1, result);
    }
}
