use crate::logging::MutinyLogger;
use crate::lsp::{FeeRequest, InvoiceRequest, Lsp, LspConfig};
use crate::{error::MutinyError, utils};
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use lightning::ln::PaymentHash;
use lightning::log_error;
use lightning::util::logger::Logger;
use lightning_invoice::Bolt11Invoice;
use reqwest::Client;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::str::FromStr;
use std::sync::Arc;

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

#[derive(Clone)]
pub(crate) struct LspClient {
    pub pubkey: PublicKey,
    pub connection_string: String,
    pub url: String,
    pub http_client: Client,
    pub logger: Arc<MutinyLogger>,
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
    pub async fn new(
        config: VoltageConfig,
        logger: Arc<MutinyLogger>,
    ) -> Result<Self, MutinyError> {
        let http_client = Client::new();

        // if we have both pubkey and connection string, use them, otherwise request them from the LSP
        let (pubkey, connection_string) = match (config.pubkey, config.connection_string) {
            (Some(pk), Some(string)) => (pk, string),
            _ => Self::fetch_connection_info(&http_client, &config.url, &logger).await?,
        };

        Ok(LspClient {
            pubkey,
            url: config.url,
            connection_string,
            http_client,
            logger,
        })
    }

    /// Get the pubkey and connection string from the LSP from the /info endpoint
    async fn fetch_connection_info(
        http_client: &Client,
        url: &str,
        logger: &MutinyLogger,
    ) -> Result<(PublicKey, String), MutinyError> {
        let builder = http_client.get(format!("{}{}", url, GET_INFO_PATH));
        let request = add_x_auth_token_if_needed(url, builder)?;

        let response: reqwest::Response = utils::fetch_with_timeout(http_client, request)
            .await
            .map_err(|e| {
                log_error!(logger, "Error fetching connection info: {e}");
                MutinyError::LspGenericError
            })?;

        let get_info_response: GetInfoResponse = response.json().await.map_err(|e| {
            log_error!(logger, "Error fetching connection info: {e}");
            MutinyError::LspGenericError
        })?;

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

    /// Get the pubkey and connection string from the LSP from the /info endpoint
    /// and set them on the LSP client
    pub(crate) async fn set_connection_info(&mut self) -> Result<(), MutinyError> {
        let (pubkey, connection_string) =
            Self::fetch_connection_info(&self.http_client, &self.url, &self.logger).await?;
        self.pubkey = pubkey;
        self.connection_string = connection_string;
        Ok(())
    }

    /// Verify that the invoice has all the parameters we expect
    /// Returns an Option with an error message if the invoice is invalid
    pub(crate) fn verify_invoice(
        &self,
        our_invoice: &Bolt11Invoice,
        lsp_invoice: &Bolt11Invoice,
        lsp_fee_msats: u64,
    ) -> Option<String> {
        if lsp_invoice.network() != our_invoice.network() {
            return Some(format!(
                "Received invoice on wrong network: {} != {}",
                lsp_invoice.network(),
                our_invoice.network()
            ));
        }

        if lsp_invoice.payment_hash() != our_invoice.payment_hash() {
            return Some(format!(
                "Received invoice with wrong payment hash: {} != {}",
                lsp_invoice.payment_hash(),
                our_invoice.payment_hash()
            ));
        }

        let invoice_pubkey = lsp_invoice.recover_payee_pub_key();
        if invoice_pubkey != self.pubkey {
            return Some(format!(
                "Received invoice from wrong node: {invoice_pubkey} != {}",
                self.pubkey
            ));
        }

        if lsp_invoice.amount_milli_satoshis().is_none() {
            return Some("Invoice amount is missing".to_string());
        }

        if our_invoice.amount_milli_satoshis().is_none() {
            return Some("Invoice amount is missing".to_string());
        }

        let lsp_invoice_amt = lsp_invoice.amount_milli_satoshis().expect("just checked");
        let our_invoice_amt = our_invoice.amount_milli_satoshis().expect("just checked");

        let expected_lsp_invoice_amt = our_invoice_amt + lsp_fee_msats;

        // verify invoice within 10 sats of our target
        if lsp_invoice_amt.abs_diff(expected_lsp_invoice_amt) > 10_000 {
            return Some(format!(
                "Received invoice with wrong amount: {lsp_invoice_amt} when amount was {expected_lsp_invoice_amt}",
            ));
        }

        None
    }
}

/// Adds the x-auth-token header if needed
fn add_x_auth_token_if_needed(
    lsp_url: &str,
    builder: reqwest::RequestBuilder,
) -> Result<reqwest::Request, MutinyError> {
    if lsp_url.contains("lnolymp.us") {
        Ok(builder
            .header("X-Auth-Token", "mutiny")
            .build()
            .map_err(|_| MutinyError::LspGenericError)?)
    } else {
        Ok(builder.build().map_err(|_| MutinyError::LspGenericError)?)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Lsp for LspClient {
    async fn get_lsp_invoice(
        &self,
        invoice_request: InvoiceRequest,
    ) -> Result<Bolt11Invoice, MutinyError> {
        let bolt11 = invoice_request
            .bolt11
            .ok_or(MutinyError::LspInvoiceRequired)?;

        let payload = ProposalRequest {
            bolt11,
            host: None,
            port: None,
            fee_id: invoice_request.fee_id,
        };

        let builder = self
            .http_client
            .post(format!("{}{}", &self.url, PROPOSAL_PATH))
            .json(&payload);

        let request = add_x_auth_token_if_needed(&self.url, builder)?;

        let response: reqwest::Response =
            utils::fetch_with_timeout(&self.http_client, request).await?;
        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            let proposal_response: ProposalResponse = response.json().await.map_err(|e| {
                log_error!(
                    self.logger,
                    "Error fetching invoice, could not parse response: {e}"
                );
                MutinyError::LspGenericError
            })?;

            let inv = Bolt11Invoice::from_str(&proposal_response.jit_bolt11)?;
            return Ok(inv);
        } else if response.status().as_u16() >= 400 {
            // If it's not OK, copy the response body to a string and try to parse as ErrorResponse
            let response_body = response.text().await.map_err(|e| {
                log_error!(
                    self.logger,
                    "Error fetching invoice, could not parse error response: {e}"
                );
                MutinyError::LspGenericError
            })?;
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
            } else {
                log_error!(
                    self.logger,
                    "Error fetching invoice, could not parse error response: {response_body}"
                );
            }
        }

        log_error!(
            self.logger,
            "Error fetching invoice, got unexpected status code from LSP {status}"
        );

        Err(MutinyError::LspGenericError)
    }

    async fn get_lsp_fee_msat(&self, fee_request: FeeRequest) -> Result<FeeResponse, MutinyError> {
        let builder = self
            .http_client
            .post(format!("{}{}", &self.url, FEE_PATH))
            .json(&fee_request);

        let request = add_x_auth_token_if_needed(&self.url, builder)?;

        let response: reqwest::Response = utils::fetch_with_timeout(&self.http_client, request)
            .await
            .map_err(|e| {
                log_error!(self.logger, "Error fetching fee from LSP: {e}");
                MutinyError::LspGenericError
            })?;

        let fee_response: FeeResponse = response.json().await.map_err(|e| {
            log_error!(
                self.logger,
                "Error fetching fee from LSP, could not parse response: {e}"
            );
            MutinyError::LspGenericError
        })?;

        Ok(fee_response)
    }

    async fn get_lsp_pubkey(&self) -> PublicKey {
        self.pubkey
    }

    async fn get_lsp_connection_string(&self) -> String {
        self.connection_string.clone()
    }

    async fn get_config(&self) -> LspConfig {
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

#[cfg(test)]
mod test {
    use crate::logging::MutinyLogger;
    use crate::lsp::voltage::{LspClient, VoltageConfig};
    use crate::test_utils::{create_dummy_invoice, create_dummy_invoice_with_payment_hash};
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::Network;
    use futures::executor::block_on;
    use std::sync::Arc;

    #[test]
    fn test_verify_invoice() {
        let secret = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let pk = secret.public_key(&Secp256k1::new());
        let client = block_on(LspClient::new(
            VoltageConfig {
                url: "http://localhost:8080".to_string(),
                pubkey: Some(pk),
                connection_string: Some(format!("{pk}@localhost:9735")),
            },
            Arc::new(MutinyLogger::default()),
        ))
        .unwrap();

        let invoice_amount_msats = 100_000_000; // 100k sats
        let lsp_fee_msat = 1_000; // 1 sat fee
        let amount_minus_fee = invoice_amount_msats - lsp_fee_msat;

        // we create our invoices with `amount_minus_fee` so we pay the fee, not the sender
        let (our_invoice, preimage) =
            create_dummy_invoice(Some(amount_minus_fee), Network::Regtest, None);
        let payment_hash = sha256::Hash::hash(&preimage);

        // check good invoice
        let lsp_invoice = create_dummy_invoice_with_payment_hash(
            Some(invoice_amount_msats),
            Network::Regtest,
            Some(secret),
            payment_hash,
        );
        assert!(client
            .verify_invoice(&our_invoice, &lsp_invoice, lsp_fee_msat)
            .is_none());

        // check invoice wrong network
        let lsp_invoice = create_dummy_invoice_with_payment_hash(
            Some(invoice_amount_msats),
            Network::Bitcoin,
            Some(secret),
            payment_hash,
        );
        let err = client
            .verify_invoice(&our_invoice, &lsp_invoice, lsp_fee_msat)
            .unwrap();
        assert!(err.contains("Received invoice on wrong network"));

        // check invoice wrong payment_hash
        let lsp_invoice = create_dummy_invoice_with_payment_hash(
            Some(invoice_amount_msats),
            Network::Regtest,
            Some(secret),
            sha256::Hash::all_zeros(),
        );
        let err = client
            .verify_invoice(&our_invoice, &lsp_invoice, lsp_fee_msat)
            .unwrap();
        assert!(err.contains("Received invoice with wrong payment hash"));

        // check invoice wrong key
        let lsp_invoice = create_dummy_invoice_with_payment_hash(
            Some(invoice_amount_msats),
            Network::Regtest,
            None,
            payment_hash,
        );
        let err = client
            .verify_invoice(&our_invoice, &lsp_invoice, lsp_fee_msat)
            .unwrap();
        assert!(err.contains("Received invoice from wrong node"));

        // check invoice no amount
        let lsp_invoice = create_dummy_invoice_with_payment_hash(
            None,
            Network::Regtest,
            Some(secret),
            payment_hash,
        );
        let err = client
            .verify_invoice(&our_invoice, &lsp_invoice, lsp_fee_msat)
            .unwrap();
        assert!(err.contains("Invoice amount is missing"));

        // check invoice amount way too low
        let lsp_invoice = create_dummy_invoice_with_payment_hash(
            Some(1),
            Network::Regtest,
            Some(secret),
            payment_hash,
        );
        let err = client
            .verify_invoice(&our_invoice, &lsp_invoice, lsp_fee_msat)
            .unwrap();
        assert!(err.contains("Received invoice with wrong amount"));

        // check invoice amount way too high
        let lsp_invoice = create_dummy_invoice_with_payment_hash(
            Some(invoice_amount_msats * 10),
            Network::Regtest,
            Some(secret),
            payment_hash,
        );
        let err = client
            .verify_invoice(&our_invoice, &lsp_invoice, lsp_fee_msat)
            .unwrap();
        assert!(err.contains("Received invoice with wrong amount"));

        // check invoice amount small difference
        let lsp_invoice = create_dummy_invoice_with_payment_hash(
            Some(invoice_amount_msats + 10_001),
            Network::Regtest,
            Some(secret),
            payment_hash,
        );
        let err = client
            .verify_invoice(&our_invoice, &lsp_invoice, lsp_fee_msat)
            .unwrap();
        assert!(err.contains("Received invoice with wrong amount"));

        // check invoice amount small difference
        let lsp_invoice = create_dummy_invoice_with_payment_hash(
            Some(invoice_amount_msats - 10_001),
            Network::Regtest,
            Some(secret),
            payment_hash,
        );
        let err = client
            .verify_invoice(&our_invoice, &lsp_invoice, lsp_fee_msat)
            .unwrap();
        assert!(err.contains("Received invoice with wrong amount"));

        // change fee to 10k sats
        let lsp_fee_msat = 10_000_000; // 10k sats fee
        let amount_minus_fee = invoice_amount_msats - lsp_fee_msat;

        // we create our invoices with `amount_minus_fee` so we pay the fee, not the sender
        let (our_invoice, preimage) =
            create_dummy_invoice(Some(amount_minus_fee), Network::Regtest, None);
        let payment_hash = sha256::Hash::hash(&preimage);

        // check good invoice
        let lsp_invoice = create_dummy_invoice_with_payment_hash(
            Some(invoice_amount_msats),
            Network::Regtest,
            Some(secret),
            payment_hash,
        );
        assert!(client
            .verify_invoice(&our_invoice, &lsp_invoice, lsp_fee_msat)
            .is_none());

        // check invoice amount small difference
        let lsp_invoice = create_dummy_invoice_with_payment_hash(
            Some(amount_minus_fee + 10_001),
            Network::Regtest,
            Some(secret),
            payment_hash,
        );
        let err = client
            .verify_invoice(&our_invoice, &lsp_invoice, lsp_fee_msat)
            .unwrap();
        assert!(err.contains("Received invoice with wrong amount"));

        // check invoice amount small difference
        let lsp_invoice = create_dummy_invoice_with_payment_hash(
            Some(amount_minus_fee - 10_001),
            Network::Regtest,
            Some(secret),
            payment_hash,
        );
        let err = client
            .verify_invoice(&our_invoice, &lsp_invoice, lsp_fee_msat)
            .unwrap();
        assert!(err.contains("Received invoice with wrong amount"));
    }
}
