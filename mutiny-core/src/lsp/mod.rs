use serde::{Deserialize, Serialize};
use async_trait::async_trait;
use crate::{error::MutinyError, storage::MutinyStorage};
use bitcoin::secp256k1::PublicKey;
use self::{voltage::LspClient, lsps::LspsClient};

pub mod voltage;
pub mod lsps;

// TODO: need a way to go from AnyLsp back to LspConfig

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct LspsConfig {
    pub connection_string: String,
    pub token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub enum LspConfig {
    Voltage(String),
    LSPS(LspsConfig)
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
    pub user_channel_id: u128
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub(crate) trait Lsp {
    async fn get_lsp_fee_msat(&self, fee_request: FeeRequest) -> Result<u64, MutinyError>;
    async fn get_lsp_invoice(&self, invoice_request: InvoiceRequest) -> Result<String, MutinyError>;
    fn get_lsp_pubkey(&self) -> PublicKey;
    fn get_lsp_connection_string(&self) -> String;
}

#[derive(Clone)]
pub enum AnyLsp<S: MutinyStorage> {
    Voltage(LspClient),
    Lsps(LspsClient<S>)
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<S: MutinyStorage> Lsp for AnyLsp<S> {
    async fn get_lsp_fee_msat(&self, fee_request: FeeRequest) -> Result<u64, MutinyError> {
        match self {
            AnyLsp::Voltage(client) => client.get_lsp_fee_msat(fee_request).await,
            AnyLsp::Lsps(client) => client.get_lsp_fee_msat(fee_request).await,
        }
    }

    async fn get_lsp_invoice(&self, invoice_request: InvoiceRequest) -> Result<String, MutinyError> {
        match self {
            AnyLsp::Voltage(client) => client.get_lsp_invoice(invoice_request).await,
            AnyLsp::Lsps(client) => client.get_lsp_invoice(invoice_request).await,
        }
    }

    fn get_lsp_pubkey(&self) -> PublicKey {
        match self {
            AnyLsp::Voltage(client) => client.get_lsp_pubkey(),
            AnyLsp::Lsps(client) => client.get_lsp_pubkey(),
        }
    }

    fn get_lsp_connection_string(&self) -> String {
        match self {
            AnyLsp::Voltage(client) => client.get_lsp_connection_string(),
            AnyLsp::Lsps(client) => client.get_lsp_connection_string(),
        }
    }
}

impl<S: MutinyStorage> From<AnyLsp<S>> for LspConfig {
    fn from(lsp: AnyLsp<S>) -> LspConfig {
        match lsp {
            AnyLsp::Lsps(client) => {
                LspConfig::LSPS(LspsConfig { connection_string: client.connection_string.clone(), token: client.token.clone() })
            },
            AnyLsp::Voltage(client) => {
                LspConfig::Voltage(client.url)
            }
        }
    }
}