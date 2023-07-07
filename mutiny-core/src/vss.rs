#![allow(dead_code)]
use crate::auth::MutinyAuthClient;
use crate::{error::MutinyError, logging::MutinyLogger};
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::Aes256;
use anyhow::anyhow;
use bitcoin::secp256k1;
use bitcoin::secp256k1::SecretKey;
use cbc::{Decryptor, Encryptor};
use lightning::log_error;
use lightning::util::logger::*;
use reqwest::{Method, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

pub struct MutinyVssClient {
    auth_client: Arc<MutinyAuthClient>,
    url: String,
    encryption_key: SecretKey,
    logger: Arc<MutinyLogger>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VssKeyValueItem {
    pub key: String,
    pub value: Option<Value>,
    pub version: u32,
}

impl VssKeyValueItem {
    /// Encrypts the value of the item using the encryption key
    /// and returns an encrypted version of the item
    pub(crate) fn encrypt(self, encryption_key: &SecretKey) -> EncryptedVssKeyValueItem {
        // should we handle this unwrap better?
        let bytes = self.value.unwrap().to_string().into_bytes();
        let iv: [u8; 16] = secp256k1::rand::random();

        let cipher = Aes256CbcEnc::new(&encryption_key.secret_bytes().into(), &iv.into());
        let mut encrypted: Vec<u8> = cipher.encrypt_padded_vec_mut::<Pkcs7>(&bytes);
        encrypted.extend(iv);
        let encrypted_value = base64::encode(encrypted);

        EncryptedVssKeyValueItem {
            key: self.key,
            value: encrypted_value,
            version: self.version,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedVssKeyValueItem {
    pub key: String,
    pub value: String,
    pub version: u32,
}

impl EncryptedVssKeyValueItem {
    pub(crate) fn decrypt(self, encryption_key: &SecretKey) -> VssKeyValueItem {
        let bytes = base64::decode(self.value).unwrap();
        // split last 16 bytes off as iv
        let iv = &bytes[bytes.len() - 16..];
        let bytes = &bytes[..bytes.len() - 16];

        let cipher = Aes256CbcDec::new(&encryption_key.secret_bytes().into(), iv.into());
        let decrypted: Vec<u8> = cipher.decrypt_padded_vec_mut::<Pkcs7>(bytes).unwrap();
        let decrypted_value = String::from_utf8(decrypted).unwrap();
        let value = serde_json::from_str(&decrypted_value).unwrap();

        VssKeyValueItem {
            key: self.key,
            value: Some(value),
            version: self.version,
        }
    }
}

impl MutinyVssClient {
    pub(crate) fn new(
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

        // check value is defined for all items
        for item in &items {
            if item.value.is_none() {
                return Err(MutinyError::Other(anyhow!(
                    "Value must be defined for all items"
                )));
            }
        }

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

        Ok(result.decrypt(&self.encryption_key))
    }

    pub async fn list_key_versions(
        &self,
        key_prefix: Option<String>,
    ) -> Result<Vec<VssKeyValueItem>, MutinyError> {
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
    use crate::auth::MutinyAuthClient;
    use crate::logging::MutinyLogger;
    use crate::test_utils::*;
    use std::sync::Arc;

    async fn create_client() -> MutinyVssClient {
        // Set up test auth client
        let auth_manager = create_manager();
        let lnurl_client = Arc::new(
            lnurl::Builder::default()
                .build_async()
                .expect("failed to make lnurl client"),
        );
        let logger = Arc::new(MutinyLogger::default());
        let url = "https://auth-staging.mutinywallet.com";

        let auth_client =
            MutinyAuthClient::new(auth_manager, lnurl_client, logger.clone(), url.to_string());

        // Test authenticate method
        match auth_client.authenticate().await {
            Ok(_) => assert!(auth_client.is_authenticated().is_some()),
            Err(e) => panic!("Authentication failed with error: {:?}", e),
        };

        let encryption_key = SecretKey::from_slice(&[2; 32]).unwrap();

        MutinyVssClient::new(
            Arc::new(auth_client),
            "https://storage-staging.mutinywallet.com".to_string(),
            encryption_key,
            logger,
        )
    }

    #[tokio::test]
    async fn test_vss() {
        let client = create_client().await;

        let key = "hello".to_string();
        let value: Value = serde_json::from_str("\"world\"").unwrap();
        let obj = VssKeyValueItem {
            key: key.clone(),
            value: Some(value.clone()),
            version: 0,
        };

        client.put_objects(vec![obj.clone()]).await.unwrap();

        let result = client.get_object(&key).await.unwrap();
        assert_eq!(obj, result);

        let result = client.list_key_versions(None).await.unwrap();
        let key_version = VssKeyValueItem {
            key,
            value: None,
            version: 0,
        };

        assert_eq!(vec![key_version], result);
        assert_eq!(result.len(), 1);
    }

    #[tokio::test]
    async fn test_vss_versions() {
        let client = create_client().await;

        let key = "hello".to_string();
        let value: Value = serde_json::from_str("\"world\"").unwrap();
        let obj = VssKeyValueItem {
            key: key.clone(),
            value: Some(value.clone()),
            version: 0,
        };

        client.put_objects(vec![obj.clone()]).await.unwrap();
        let result = client.get_object(&key).await.unwrap();
        assert_eq!(obj.clone(), result);

        let value1: Value = serde_json::from_str("\"new world\"").unwrap();
        let obj1 = VssKeyValueItem {
            key: key.clone(),
            value: Some(value1.clone()),
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
