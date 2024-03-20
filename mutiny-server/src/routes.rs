use axum::{Extension, Json};
use axum::http::StatusCode;
use bitcoin::{Address};
use serde_json::{json, Value};
use mutiny_core::{InvoiceHandler, MutinyWallet};
use lightning_invoice::Bolt11Invoice;
use std::str::FromStr;
use mutiny_core::error::MutinyError;
use serde::Deserialize;
use crate::sled::SledStorage;

#[derive(Clone)]
pub struct State {
    pub mutiny_wallet: MutinyWallet<SledStorage>,
}

pub async fn new_address(Extension(state): Extension<State>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let address = state.mutiny_wallet.node_manager.get_new_address(vec![]).map_err(|e|handle_mutiny_err(e))?;
    Ok(Json(json!(address)))
}

#[derive(Deserialize)]
pub struct SendTo {
    amount: u64,
    address: String
}

pub async fn send_to_address(
    Extension(state): Extension<State>,
    Json(payload): Json<SendTo>
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let address = Address::from_str(payload.address.as_str()).map_err(|_e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid address"})),
        )
    })?;

    let tx_id = state.mutiny_wallet.node_manager.send_to_address(address, payload.amount, vec!["test".to_string()], None)
        .await
        .map_err(|e| handle_mutiny_err(e))?;

    Ok(Json(json!({
        "txid": tx_id.to_string()
    })))
}

#[derive(Deserialize)]
pub struct Amount {
    amount: u64,
}

pub async fn open_channel(
    Extension(state): Extension<State>,
    Json(payload): Json<Amount>
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    //let amount = get_amount_params(&params)?;
    let channel = state.mutiny_wallet.node_manager.open_channel(None, None, payload.amount, None, None)
        .await
        .map_err(|e| handle_mutiny_err(e))?;
    Ok(Json(json!(channel)))
}

pub async fn create_invoice(
    Extension(state): Extension<State>,
    Json(payload): Json<Amount>
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let invoice = state.mutiny_wallet.create_invoice(payload.amount, vec!["test".to_string()])
        .await
        .map_err(|e| handle_mutiny_err(e))?;
    Ok(Json(json!(invoice)))
}

#[derive(Deserialize)]
pub struct Invoice {
    invoice: String,
}

pub async fn pay_invoice(
    Extension(state): Extension<State>,
    Json(payload): Json<Invoice>
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let invoice = Bolt11Invoice::from_str(payload.invoice.as_str()).map_err(|_e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid invoice provided"})),
        )
    })?;
    let invoice = state.mutiny_wallet.pay_invoice(&invoice, None, vec!["test".to_string()])
        .await
        .map_err(|e| handle_mutiny_err(e))?;
    Ok(Json(json!(invoice)))
}

pub async fn get_balance(
    Extension(state): Extension<State>
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let balance = state.mutiny_wallet.get_balance()
        .await
        .map_err(|e| handle_mutiny_err(e))?;
    Ok(Json(json!(balance)))
}

fn handle_mutiny_err(err: MutinyError) -> (StatusCode, Json<Value>) {
    let err = json!({
        "status": "ERROR",
        "reason": format!("{err}"),
    });
    (StatusCode::INTERNAL_SERVER_ERROR, Json(err))
}
