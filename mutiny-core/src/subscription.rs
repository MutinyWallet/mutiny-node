use std::sync::Arc;

use lightning::log_error;
use lightning::util::logger::*;
use reqwest::{Method, StatusCode, Url};
use serde::{Deserialize, Serialize};

use crate::{auth::MutinyAuthClient, error::MutinyError, logging::MutinyLogger, Plan};

pub(crate) struct MutinySubscriptionClient {
    auth_client: Arc<MutinyAuthClient>,
    url: String,
    logger: Arc<MutinyLogger>,
}

impl MutinySubscriptionClient {
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

    pub async fn check_subscribed(&self) -> Result<Option<u64>, MutinyError> {
        let url = Url::parse(&format!("{}/v1/check-subscribed", self.url)).map_err(|e| {
            log_error!(self.logger, "Error parsing check subscribed url: {e}");
            MutinyError::ConnectionFailed
        })?;
        let res = self
            .auth_client
            .request(Method::GET, url, None)
            .await?
            .json::<CheckSubscribedResponse>()
            .await
            .map_err(|e| {
                log_error!(self.logger, "Error parsing subscribe response: {e}");
                MutinyError::ConnectionFailed
            })?;
        if let Some(expired) = res.expired_date {
            Ok(Some(expired))
        } else {
            Ok(None)
        }
    }

    pub async fn get_plans(&self) -> Result<Vec<Plan>, MutinyError> {
        let url = Url::parse(&format!("{}/v1/plans", self.url)).map_err(|e| {
            log_error!(self.logger, "Error parsing plan url: {e}");
            MutinyError::ConnectionFailed
        })?;
        let res = self
            .auth_client
            .request(Method::GET, url, None)
            .await?
            .json::<Vec<Plan>>()
            .await
            .map_err(|e| {
                log_error!(self.logger, "Error parsing plans: {e}");
                MutinyError::ConnectionFailed
            })?;

        Ok(res)
    }

    pub async fn subscribe_to_plan(&self, id: u8) -> Result<String, MutinyError> {
        let url = Url::parse(&format!("{}/v1/plans/{}/subscribe", self.url, id)).map_err(|e| {
            log_error!(self.logger, "Error parsing subscribe url: {e}");
            MutinyError::ConnectionFailed
        })?;
        let res = self
            .auth_client
            .request(Method::POST, url, None)
            .await?
            .json::<UserInvoiceResponse>()
            .await
            .map_err(|e| {
                log_error!(self.logger, "Error parsing subscription invoice: {e}");
                MutinyError::ConnectionFailed
            })?;

        Ok(res.inv)
    }

    pub async fn submit_nwc(&self, wallet_connect_string: String) -> Result<(), MutinyError> {
        let url = Url::parse(&format!("{}/v1/wallet-connect", self.url)).map_err(|e| {
            log_error!(self.logger, "Error parsing wallet connect url: {e}");
            MutinyError::ConnectionFailed
        })?;
        let body = serde_json::to_value(WalletConnectRequest {
            wallet_connect_string,
        })?;

        let res = self
            .auth_client
            .request(Method::POST, url, Some(body))
            .await?;

        match res.status() {
            StatusCode::OK => Ok(()), // If status is 200 OK, return Ok(()).
            status => {
                log_error!(self.logger, "Unexpected status code: {status}");
                Err(MutinyError::ConnectionFailed)
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct CheckSubscribedResponse {
    pub expired_date: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct UserInvoiceResponse {
    inv: String,
}

#[derive(Serialize, Deserialize)]
pub struct WalletConnectRequest {
    wallet_connect_string: String,
}
