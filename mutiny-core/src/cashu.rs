use crate::error::MutinyError;
use moksha_core::primitives::PostMeltBolt11Response;
use moksha_core::primitives::{
    CashuErrorResponse, PostMeltBolt11Request, PostMeltQuoteBolt11Request,
    PostMeltQuoteBolt11Response,
};
use reqwest::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};
use url::Url;

#[derive(Clone)]
pub struct CashuHttpClient {
    client: Client,
}

impl CashuHttpClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    pub async fn post_melt_quote_bolt11(
        &self,
        url: &Url,
        melt_quote_request: PostMeltQuoteBolt11Request,
    ) -> Result<PostMeltQuoteBolt11Response, MutinyError> {
        self.mint_post(
            &url.join("/v1/melt/quote/bolt11")?,
            json!(melt_quote_request),
        )
        .await
    }

    pub async fn post_melt_bolt11(
        &self,
        url: &Url,
        melt_request: PostMeltBolt11Request,
    ) -> Result<PostMeltBolt11Response, MutinyError> {
        self.mint_post(&url.join("/v1/melt/bolt11")?, json!(melt_request))
            .await
    }

    async fn mint_post<T: serde::de::DeserializeOwned>(
        &self,
        url: &Url,
        body: Value,
    ) -> Result<T, MutinyError> {
        let res = self
            .client
            .post(url.clone())
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|_| MutinyError::CashuMintError)?;
        Self::parse_cashu_mint_response(res).await
    }

    async fn parse_cashu_mint_response<T: serde::de::DeserializeOwned>(
        res: reqwest::Response,
    ) -> Result<T, MutinyError> {
        match res.status() {
            StatusCode::OK => {
                let response_text = res.text().await.map_err(|_| MutinyError::CashuMintError)?;
                match serde_json::from_str::<T>(&response_text) {
                    Ok(data) => Ok(data),
                    Err(_) => Err(MutinyError::CashuMintError),
                }
            }
            _ => {
                let txt = res.text().await.map_err(|_| MutinyError::CashuMintError)?;
                let data = serde_json::from_str::<CashuErrorResponse>(&txt)
                    .map_err(|_| MutinyError::CashuMintError)?;

                match data.code {
                    // error code in nutshell for tokens that have been spent
                    11001 => Err(MutinyError::TokenAlreadySpent),
                    _ => Err(MutinyError::CashuMintError),
                }
            }
        }
    }
}
