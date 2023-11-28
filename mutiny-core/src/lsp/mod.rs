use crate::error::MutinyError;
use crate::keymanager::PhantomKeysManager;
use crate::ldkstorage::PhantomChannelManager;
use crate::logging::MutinyLogger;
use crate::node::LiquidityManager;
use crate::storage::MutinyStorage;
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use bitcoin::Network;
use lsps::{LspsClient, LspsConfig};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use voltage::LspClient;

pub mod lsps;
pub mod voltage;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LspConfig {
    VoltageFlow(String),
    LspsFlow(LspsConfig),
}

impl LspConfig {
    pub fn new_voltage_flow(url: String) -> Self {
        Self::VoltageFlow(url)
    }

    pub fn new_lsps_flow(connection_string: String, token: Option<String>) -> Self {
        Self::LspsFlow(LspsConfig {
            connection_string,
            token,
        })
    }
}

pub fn deserialize_lsp_config<'de, D>(deserializer: D) -> Result<Option<LspConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v: Option<Value> = Option::deserialize(deserializer)?;
    match v {
        Some(Value::String(s)) => Ok(Some(LspConfig::VoltageFlow(s))),
        Some(Value::Object(_)) => LspConfig::deserialize(v.unwrap())
            .map(Some)
            .map_err(|e| serde::de::Error::custom(format!("invalid lsp config: {e}"))),
        Some(Value::Null) => Ok(None),
        Some(x) => Err(serde::de::Error::custom(format!(
            "invalid lsp config: {x:?}"
        ))),
        None => Ok(None),
    }
}

#[derive(Serialize, Deserialize)]
pub struct InvoiceRequest {
    pub bolt11: Option<String>,
    pub user_channel_id: u128,
}

#[derive(Serialize, Deserialize)]
pub struct FeeRequest {
    pub pubkey: String,
    pub amount_msat: u64,
    pub user_channel_id: u128,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub(crate) trait Lsp {
    async fn get_lsp_fee_msat(&self, fee_request: FeeRequest) -> Result<u64, MutinyError>;
    async fn get_lsp_invoice(&self, invoice_request: InvoiceRequest)
        -> Result<String, MutinyError>;
    fn get_lsp_pubkey(&self) -> PublicKey;
    fn get_lsp_connection_string(&self) -> String;
    fn get_config(&self) -> LspConfig;
}

#[derive(Clone)]
pub enum AnyLsp<S: MutinyStorage> {
    VoltageFlow(LspClient),
    LspsFlow(LspsClient<S>),
}

impl<S: MutinyStorage> AnyLsp<S> {
    pub async fn new_voltage_flow(url: &str) -> Result<Self, MutinyError> {
        Ok(Self::VoltageFlow(LspClient::new(url).await?))
    }

    pub fn new_lsps_flow(
        connection_string: String,
        token: Option<String>,
        liquidity_manager: Arc<LiquidityManager<S>>,
        channel_manager: Arc<PhantomChannelManager<S>>,
        keys_manager: Arc<PhantomKeysManager<S>>,
        network: Network,
        logger: Arc<MutinyLogger>,
    ) -> Result<Self, MutinyError> {
        let lsps_client = LspsClient::new(
            connection_string,
            token,
            liquidity_manager,
            channel_manager,
            keys_manager,
            network,
            logger,
        )?;
        Ok(Self::LspsFlow(lsps_client))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<S: MutinyStorage> Lsp for AnyLsp<S> {
    async fn get_lsp_fee_msat(&self, fee_request: FeeRequest) -> Result<u64, MutinyError> {
        match self {
            AnyLsp::VoltageFlow(client) => client.get_lsp_fee_msat(fee_request).await,
            AnyLsp::LspsFlow(client) => client.get_lsp_fee_msat(fee_request).await,
        }
    }

    async fn get_lsp_invoice(
        &self,
        invoice_request: InvoiceRequest,
    ) -> Result<String, MutinyError> {
        match self {
            AnyLsp::VoltageFlow(client) => client.get_lsp_invoice(invoice_request).await,
            AnyLsp::LspsFlow(client) => client.get_lsp_invoice(invoice_request).await,
        }
    }

    fn get_lsp_pubkey(&self) -> PublicKey {
        match self {
            AnyLsp::VoltageFlow(client) => client.get_lsp_pubkey(),
            AnyLsp::LspsFlow(client) => client.get_lsp_pubkey(),
        }
    }

    fn get_lsp_connection_string(&self) -> String {
        match self {
            AnyLsp::VoltageFlow(client) => client.get_lsp_connection_string(),
            AnyLsp::LspsFlow(client) => client.get_lsp_connection_string(),
        }
    }

    fn get_config(&self) -> LspConfig {
        match self {
            AnyLsp::VoltageFlow(client) => client.get_config(),
            AnyLsp::LspsFlow(client) => client.get_config(),
        }
    }
}
