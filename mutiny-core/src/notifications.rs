use crate::auth::MutinyAuthClient;
use crate::{error::MutinyError, logging::MutinyLogger};
use anyhow::anyhow;
use lightning::util::logger::*;
use lightning::{log_error, log_info};
use nostr::secp256k1::XOnlyPublicKey;
use reqwest::{Method, Url};
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Clone)]
pub struct MutinyNotificationClient {
    auth_client: Option<Arc<MutinyAuthClient>>,
    client: Option<reqwest::Client>,
    url: String,
    id: Option<String>,
    pub logger: Arc<MutinyLogger>,
}

impl MutinyNotificationClient {
    pub fn new_authenticated(
        auth_client: Arc<MutinyAuthClient>,
        url: String,
        logger: Arc<MutinyLogger>,
    ) -> Self {
        log_info!(logger, "Creating authenticated notification client");
        Self {
            auth_client: Some(auth_client),
            client: None,
            url,
            id: None, // we get this from the auth client
            logger,
        }
    }

    pub fn new_unauthenticated(
        url: String,
        identifier_key: String,
        logger: Arc<MutinyLogger>,
    ) -> Self {
        log_info!(logger, "Creating unauthenticated notification client");
        Self {
            auth_client: None,
            client: Some(reqwest::Client::new()),
            url,
            id: Some(identifier_key),
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

    pub async fn register(&self, info: Value) -> Result<(), MutinyError> {
        let url = Url::parse(&format!("{}/register", self.url)).map_err(|e| {
            log_error!(self.logger, "Error parsing register url: {e}");
            MutinyError::InvalidArgumentsError
        })?;

        let body = json!({"id": self.id, "info": info});

        self.make_request(Method::POST, url, Some(body)).await?;

        Ok(())
    }

    pub async fn register_nwc(
        &self,
        author: XOnlyPublicKey,
        tagged: XOnlyPublicKey,
        relay: &str,
        name: &str,
    ) -> Result<(), MutinyError> {
        let url = Url::parse(&format!("{}/register-nwc", self.url)).map_err(|e| {
            log_error!(self.logger, "Error parsing register url: {e}");
            MutinyError::InvalidArgumentsError
        })?;

        let body = json!({"id": self.id, "author": author, "tagged": tagged, "relay": relay, "name": name});

        self.make_request(Method::POST, url, Some(body)).await?;

        Ok(())
    }
}
