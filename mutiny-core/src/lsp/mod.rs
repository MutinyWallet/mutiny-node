use crate::error::MutinyError;
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod voltage;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LspConfig {
    VoltageFlow(String),
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
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub(crate) trait Lsp {
    async fn get_lsp_fee_msat(&self, fee_request: FeeRequest) -> Result<u64, MutinyError>;
    async fn get_lsp_invoice(&self, invoice_request: InvoiceRequest)
        -> Result<String, MutinyError>;
    fn get_lsp_pubkey(&self) -> PublicKey;
    fn get_lsp_connection_string(&self) -> String;
}
