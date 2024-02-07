use crate::lsp::{FeeRequest, InvoiceRequest, Lsp, LspConfig};
use crate::{error::MutinyError, utils};
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use lightning::ln::PaymentHash;
use lightning_invoice::Bolt11Invoice;
use reqwest::Client;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::str::FromStr;

use super::FeeResponse;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VoltageConfig {
    pub url: String,
    pub pubkey: Option<PublicKey>,
    pub connection_string: Option<String>,
}

// Need custom Deserializer to handle old encoding
impl<'de> Deserialize<'de> for VoltageConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: Value = Value::deserialize(deserializer)?;
        match value {
            // old encoding was a string, parse as the url
            Value::String(url) => Ok(VoltageConfig {
                url,
                pubkey: None,
                connection_string: None,
            }),
            // new encoding is an object, parse as such
            Value::Object(map) => {
                let url = map
                    .get("url")
                    .and_then(Value::as_str)
                    .ok_or_else(|| serde::de::Error::missing_field("url"))?
                    .to_string();
                let pubkey = map
                    .get("pubkey")
                    .and_then(Value::as_str)
                    .map(PublicKey::from_str)
                    .transpose()
                    .map_err(|_| serde::de::Error::custom("invalid pubkey"))?;
                let connection_string = map
                    .get("connection_string")
                    .and_then(Value::as_str)
                    .map(String::from);
                Ok(VoltageConfig {
                    url,
                    pubkey,
                    connection_string,
                })
            }
            _ => Err(serde::de::Error::custom("invalid value for VoltageConfig")),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LspClient {
    pub pubkey: PublicKey,
    pub connection_string: String,
    pub url: String,
    pub http_client: Client,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct GetInfoResponse {
    pub pubkey: PublicKey,
    pub connection_methods: Vec<GetInfoAddress>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct GetInfoAddress {
    #[serde(rename = "type")]
    pub item_type: GetInfoAddressType,
    pub port: u16,
    pub address: String,
}

/// Type of connection
#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum GetInfoAddressType {
    Dns,
    IPV4,
    IPV6,
    TORV2,
    TORV3,
    Websocket,
}

#[derive(Serialize, Deserialize)]
pub struct ProposalRequest {
    pub bolt11: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub fee_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct ProposalResponse {
    pub jit_bolt11: String,
}

#[derive(Deserialize, Debug)]
struct ErrorResponse {
    error: String,
    message: String,
}

const GET_INFO_PATH: &str = "/api/v1/info";
const PROPOSAL_PATH: &str = "/api/v1/proposal";
const FEE_PATH: &str = "/api/v1/fee";

impl LspClient {
    pub async fn new(config: VoltageConfig) -> Result<Self, MutinyError> {
        let http_client = Client::new();

        // if we have both pubkey and connection string, use them, otherwise request them from the LSP
        let (pubkey, connection_string) = match (config.pubkey, config.connection_string) {
            (Some(pk), Some(string)) => (pk, string),
            _ => Self::fetch_connection_info(&http_client, &config.url).await?,
        };

        Ok(LspClient {
            pubkey,
            url: config.url,
            connection_string,
            http_client,
        })
    }

    /// Get the pubkey and connection string from the LSP from the /info endpoint
    async fn fetch_connection_info(
        http_client: &Client,
        url: &str,
    ) -> Result<(PublicKey, String), MutinyError> {
        let request = http_client
            .get(format!("{}{}", url, GET_INFO_PATH))
            .build()
            .map_err(|_| MutinyError::LspGenericError)?;
        let response: reqwest::Response = utils::fetch_with_timeout(http_client, request).await?;

        let get_info_response: GetInfoResponse = response
            .json()
            .await
            .map_err(|_| MutinyError::LspGenericError)?;

        let connection_string = get_info_response
            .connection_methods
            .iter()
            .filter(|address| {
                matches!(
                    address.item_type,
                    GetInfoAddressType::IPV4 | GetInfoAddressType::IPV6 | GetInfoAddressType::TORV3
                )
            })
            .min_by_key(|address| match address.item_type {
                // Prioritize IPV4, then 6, then tor
                // TODO support websocket one day
                GetInfoAddressType::IPV4 => 0,
                GetInfoAddressType::IPV6 => 1,
                GetInfoAddressType::TORV3 => 2,
                _ => unreachable!(),
            })
            .map(|address| {
                format!(
                    "{}@{}:{}",
                    get_info_response.pubkey, address.address, address.port
                )
            })
            .ok_or_else(|| anyhow::anyhow!("No suitable connection method found"))?;

        Ok((get_info_response.pubkey, connection_string))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Lsp for LspClient {
    async fn get_lsp_invoice(
        &self,
        invoice_request: InvoiceRequest,
    ) -> Result<Bolt11Invoice, MutinyError> {
        let fee_id = invoice_request.fee_id.ok_or(MutinyError::LspGenericError)?;

        let bolt11 = invoice_request
            .bolt11
            .ok_or(MutinyError::LspInvoiceRequired)?;

        let payload = ProposalRequest {
            bolt11,
            host: None,
            port: None,
            fee_id,
        };

        let request = self
            .http_client
            .post(format!("{}{}", &self.url, PROPOSAL_PATH))
            .json(&payload)
            .build()
            .map_err(|_| MutinyError::LspGenericError)?;

        let response: reqwest::Response =
            utils::fetch_with_timeout(&self.http_client, request).await?;
        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            let proposal_response: ProposalResponse = response
                .json()
                .await
                .map_err(|_| MutinyError::LspGenericError)?;

            let inv = Bolt11Invoice::from_str(&proposal_response.jit_bolt11)?;
            return Ok(inv);
        } else if response.status().as_u16() >= 400 {
            // If it's not OK, copy the response body to a string and try to parse as ErrorResponse
            let response_body = response
                .text()
                .await
                .map_err(|_| MutinyError::LspGenericError)?;

            if let Ok(error_body) = serde_json::from_str::<ErrorResponse>(&response_body) {
                if error_body.error == "Internal Server Error" {
                    if error_body.message == "Cannot fund new channel at this time" {
                        return Err(MutinyError::LspFundingError);
                    } else if error_body.message.starts_with("Failed to connect to peer") {
                        return Err(MutinyError::LspConnectionError);
                    } else if error_body.message == "Invoice amount is too high" {
                        return Err(MutinyError::LspAmountTooHighError);
                    }
                }
            }
        }

        Err(MutinyError::LspGenericError)
    }

    async fn get_lsp_fee_msat(&self, fee_request: FeeRequest) -> Result<FeeResponse, MutinyError> {
        let request = self
            .http_client
            .post(format!("{}{}", &self.url, FEE_PATH))
            .json(&fee_request)
            .build()
            .map_err(|_| MutinyError::LspGenericError)?;
        let response: reqwest::Response =
            utils::fetch_with_timeout(&self.http_client, request).await?;

        let fee_response: FeeResponse = response
            .json()
            .await
            .map_err(|_| MutinyError::LspGenericError)?;

        Ok(fee_response)
    }

    fn get_lsp_pubkey(&self) -> PublicKey {
        self.pubkey
    }

    fn get_lsp_connection_string(&self) -> String {
        self.connection_string.clone()
    }

    fn get_config(&self) -> LspConfig {
        LspConfig::VoltageFlow(VoltageConfig {
            url: self.url.clone(),
            pubkey: Some(self.pubkey),
            connection_string: Some(self.connection_string.clone()),
        })
    }

    fn get_expected_skimmed_fee_msat(&self, _payment_hash: PaymentHash, _payment_size: u64) -> u64 {
        0
    }
}
