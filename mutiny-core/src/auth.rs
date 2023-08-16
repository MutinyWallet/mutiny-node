#![allow(dead_code)]
use crate::{
    error::MutinyError,
    lnurlauth::{make_lnurl_auth_connection, AuthManager},
    logging::MutinyLogger,
    networking::websocket::{SimpleWebSocket, WebSocketImpl},
    utils,
};
use jwt_compact::UntrustedToken;
use lightning::util::logger::*;
use lightning::{log_error, log_info};
use lnurl::{lnurl::LnUrl, AsyncClient as LnUrlClient};
use reqwest::Client;
use reqwest::{Method, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct CustomClaims {
    sub: String,
}

pub struct MutinyAuthClient {
    pub auth: AuthManager,
    lnurl_client: Arc<LnUrlClient>,
    url: String,
    http_client: Client,
    jwt: RwLock<Option<String>>,
    logger: Arc<MutinyLogger>,
}

impl MutinyAuthClient {
    pub fn new(
        auth: AuthManager,
        lnurl_client: Arc<LnUrlClient>,
        logger: Arc<MutinyLogger>,
        url: String,
    ) -> Self {
        let http_client = Client::new();
        Self {
            auth,
            lnurl_client,
            url,
            http_client,
            jwt: RwLock::new(None),
            logger,
        }
    }

    pub async fn authenticate(&self) -> Result<(), MutinyError> {
        self.retrieve_new_jwt().await?;
        Ok(())
    }

    pub fn is_authenticated(&self) -> Option<String> {
        if let Some(ref jwt) = *self.jwt.try_read().unwrap() {
            return Some(jwt.to_string()); // TODO parse and make sure still valid
        }
        None
    }

    pub async fn request(
        &self,
        method: Method,
        url: Url,
        body: Option<Value>,
    ) -> Result<reqwest::Response, MutinyError> {
        let res = self
            .authenticated_request(method.clone(), url.clone(), body.clone())
            .await?;
        match res.status() {
            StatusCode::UNAUTHORIZED => {
                // If we get a 401, refresh the JWT and try again
                self.retrieve_new_jwt().await?;
                self.authenticated_request(method, url, body).await
            }
            StatusCode::OK | StatusCode::ACCEPTED | StatusCode::CREATED => Ok(res),
            code => {
                log_error!(self.logger, "Received unexpected status code: {code}");
                Err(MutinyError::ConnectionFailed)
            }
        }
    }

    async fn authenticated_request(
        &self,
        method: Method,
        url: Url,
        body: Option<Value>,
    ) -> Result<reqwest::Response, MutinyError> {
        let mut request = self.http_client.request(method, url);

        let mut jwt = self.is_authenticated();
        if jwt.is_none() {
            jwt = Some(self.retrieve_new_jwt().await?);
        }
        request = request.bearer_auth(jwt.expect("either had one or retrieved new"));

        if let Some(json) = body {
            request = request.json(&json);
        }

        utils::fetch_with_timeout(
            &self.http_client,
            request.build().expect("should build req"),
        )
        .await
    }

    async fn retrieve_new_jwt(&self) -> Result<String, MutinyError> {
        let mut url = Url::parse(&self.url).map_err(|_| MutinyError::LnUrlFailure)?;
        let ws_scheme = match url.scheme() {
            "http" => "ws",
            "https" => "wss",
            _ => return Err(MutinyError::LnUrlFailure),
        };
        url.set_scheme(ws_scheme)
            .map_err(|_| MutinyError::LnUrlFailure)?;
        url.set_path("/v2/lnurlAuth");

        let mut ws = WebSocketImpl::new(url.to_string()).await.map_err(|e| {
            log_error!(self.logger, "Error starting up auth ws: {e}");
            MutinyError::LnUrlFailure
        })?;

        let lnurl_auth_str = ws.recv().await.map_err(|e| {
            log_error!(self.logger, "Error receiving LNURL from ws: {e}");
            MutinyError::LnUrlFailure
        })?;
        let lnurl = match LnUrl::from_str(&lnurl_auth_str) {
            Ok(l) => l,
            Err(e) => {
                log_error!(
                    self.logger,
                    "Error parsing LNURL string {lnurl_auth_str}: {e}"
                );
                return Err(MutinyError::LnUrlFailure);
            }
        };

        make_lnurl_auth_connection(
            self.auth.clone(),
            self.lnurl_client.clone(),
            lnurl,
            self.logger.clone(),
        )
        .await?;

        // Listen for JWT string to be returned
        let jwt = match ws.recv().await {
            Ok(jwt) => {
                // basic validation to make sure it is a valid string
                let _ = UntrustedToken::new(&jwt).map_err(|e| {
                    log_error!(self.logger, "Could not validate JWT {jwt}: {e}");
                    MutinyError::LnUrlFailure
                })?;
                jwt
            }
            Err(e) => {
                log_error!(self.logger, "Error trying to retrieve JWT: {e}");
                return Err(MutinyError::LnUrlFailure);
            }
        };

        log_info!(self.logger, "Retrieved new JWT token");
        *self.jwt.try_write()? = Some(jwt.clone());
        Ok(jwt)
    }
}

#[cfg(test)]
mod tests {
    use super::MutinyAuthClient;
    use crate::logging::MutinyLogger;
    use crate::test_utils::*;
    use reqwest::{Method, Url};
    use std::sync::Arc;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn test_authentication() {
        let test_name = "test_authentication";
        log!("{}", test_name);

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
            MutinyAuthClient::new(auth_manager, lnurl_client, logger, url.to_string());

        // Test authenticate method
        match auth_client.authenticate().await {
            Ok(_) => assert!(auth_client.is_authenticated().is_some()),
            Err(e) => panic!("Authentication failed with error: {:?}", e),
        };

        // Test request method
        let test_url = Url::parse("https://auth-staging.mutinywallet.com/v1/check").unwrap();
        let method = Method::GET;
        let body = None;

        match auth_client.request(method, test_url, body).await {
            Ok(response) => {
                assert!(response.status().is_success());
            }
            Err(e) => panic!("Request failed with error: {:?}", e),
        };
    }
}
