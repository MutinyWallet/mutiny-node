#![allow(dead_code)]
use crate::auth::MutinyAuthClient;
use crate::{error::MutinyError, logging::MutinyLogger};
use anyhow::anyhow;
use lightning::log_error;
use lightning::util::logger::*;
use reqwest::{Method, Url};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

pub struct MutinyVssClient {
    auth_client: Arc<MutinyAuthClient>,
    url: String,
    logger: Arc<MutinyLogger>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VssKeyValueItem {
    pub key: String,
    pub value: Option<String>,
    pub version: u32,
}

impl MutinyVssClient {
    pub(crate) fn new(
        auth_client: Arc<MutinyAuthClient>,
        url: String,
        logger: Arc<MutinyLogger>,
    ) -> Self {
        Self {
            auth_client,
            url,
            logger,
        }
    }

    pub async fn put_objects(&self, items: Vec<VssKeyValueItem>) -> Result<(), MutinyError> {
        let url = Url::parse(&format!("{}/putObjects", self.url)).map_err(|e| {
            log_error!(self.logger, "Error parsing put objects url: {e}");
            MutinyError::Other(anyhow!("Error parsing put objects url: {e}"))
        })?;

        // todo do we need global version here?
        let body = json!({ "transaction_items": items });

        self.auth_client
            .request(Method::PUT, url, Some(body))
            .await?;

        Ok(())
    }

    pub async fn get_objects(&self, key: &str) -> Result<VssKeyValueItem, MutinyError> {
        let url = Url::parse(&format!("{}/getObject", self.url)).map_err(|e| {
            log_error!(self.logger, "Error parsing get objects url: {e}");
            MutinyError::Other(anyhow!("Error parsing get objects url: {e}"))
        })?;

        let body = json!({ "key": key });
        let result = self
            .auth_client
            .request(Method::POST, url, Some(body))
            .await?
            .json()
            .await
            .map_err(|e| {
                log_error!(self.logger, "Error parsing get objects response: {e}");
                MutinyError::Other(anyhow!("Error parsing get objects response: {e}"))
            })?;

        Ok(result)
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

        MutinyVssClient::new(
            Arc::new(auth_client),
            "https://storage-staging.mutinywallet.com".to_string(),
            logger,
        )
    }

    #[tokio::test]
    async fn test_vss() {
        let client = create_client().await;

        let key = "hello".to_string();
        let value = "world".to_string();
        let obj = VssKeyValueItem {
            key: key.clone(),
            value: Some(value.clone()),
            version: 0,
        };

        client.put_objects(vec![obj.clone()]).await.unwrap();

        let result = client.get_objects(&key).await.unwrap();
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
        let value = "world1".to_string();
        let obj = VssKeyValueItem {
            key: key.clone(),
            value: Some(value.clone()),
            version: 0,
        };

        client.put_objects(vec![obj.clone()]).await.unwrap();
        let result = client.get_objects(&key).await.unwrap();
        assert_eq!(obj.clone(), result);

        let value1 = "new world".to_string();
        let obj1 = VssKeyValueItem {
            key: key.clone(),
            value: Some(value1.clone()),
            version: 1,
        };

        client.put_objects(vec![obj1.clone()]).await.unwrap();
        let result = client.get_objects(&key).await.unwrap();
        assert_eq!(obj1, result);

        // check we get version 1
        client.put_objects(vec![obj]).await.unwrap();
        let result = client.get_objects(&key).await.unwrap();
        assert_eq!(obj1, result);
    }
}
