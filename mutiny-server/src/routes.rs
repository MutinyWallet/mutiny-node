use crate::extractor::Form;
use crate::sled::SledStorage;

use axum::http::StatusCode;
use axum::{Extension, Json};
use bitcoin::{secp256k1::PublicKey, Address};
use lightning_invoice::Bolt11Invoice;
use mutiny_core::error::MutinyError;
use mutiny_core::{InvoiceHandler, MutinyWallet};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::str::FromStr;

#[derive(Clone)]
pub struct State {
    pub mutiny_wallet: MutinyWallet<SledStorage>,
}

pub async fn new_address(
    Extension(state): Extension<State>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let address = state
        .mutiny_wallet
        .node_manager
        .get_new_address(vec![])
        .map_err(|e| handle_mutiny_err(e))?;
    Ok(Json(json!(address)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendTo {
    amount_sat: u64,
    address: String,
    fee_rate_sat_byte: Option<f32>,
    label: Option<String>,
}

pub async fn send_to_address(
    Extension(state): Extension<State>,
    Form(request): Form<SendTo>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let address = match Address::from_str(request.address.as_str()) {
        Ok(address) => address,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid address"})),
            ))
        }
    };

    let label = match request.label {
        Some(label) => vec![label.to_string()],
        None => Vec::new(),
    };

    let tx_id = state
        .mutiny_wallet
        .node_manager
        .send_to_address(
            address,
            request.amount_sat,
            label,
            request.fee_rate_sat_byte,
        )
        .await
        .map_err(|e| handle_mutiny_err(e))?;

    Ok(Json(json!(tx_id.to_string())))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenChannel {
    amount_sat: u64,
    fee_rate: Option<f32>,
    node_pubkey: Option<String>,
}

pub async fn open_channel(
    Extension(state): Extension<State>,
    Form(request): Form<OpenChannel>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let to_pubkey = match request.node_pubkey {
        Some(pubkey) => {
            let pubkey = match PublicKey::from_str(pubkey.as_str()) {
                Ok(pk) => pk,
                Err(_) => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "invalid node pubkey"})),
                    ))
                }
            };
            Some(pubkey)
        }
        None => None,
    };

    let channel = state
        .mutiny_wallet
        .node_manager
        .open_channel(None, to_pubkey, request.amount_sat, request.fee_rate, None)
        .await
        .map_err(|e| handle_mutiny_err(e))?;
    Ok(Json(json!(channel)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateInvoiceRequest {
    amount_sat: u64,
    label: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateInvoiceResponse {
    amount_sat: u64,
    payment_hash: String,
    serialized: String,
}

pub async fn create_invoice(
    Extension(state): Extension<State>,
    Form(request): Form<CreateInvoiceRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let label = match request.label {
        Some(label) => vec![label.to_string()],
        None => Vec::new(),
    };

    let invoice = state
        .mutiny_wallet
        .create_invoice(request.amount_sat, label)
        .await
        .map_err(|e| handle_mutiny_err(e))?;

    let amount_sat = match invoice.amount_sats {
        Some(amount) => amount,
        None => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "unable to create invoice"})),
            ))
        }
    };

    let pr = match invoice.bolt11 {
        Some(amount) => amount,
        None => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "unable to create invoice"})),
            ))
        }
    }
    .to_string();

    let invoice = CreateInvoiceResponse {
        amount_sat,
        payment_hash: invoice.payment_hash.to_string(),
        serialized: pr,
    };

    Ok(Json(json!(invoice)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayInvoiceRequest {
    amount_sat: Option<u64>,
    invoice: Bolt11Invoice,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayInvoiceResponse {
    recipient_amount_sat: u64,
    routing_fee_sat: u64,
    payment_hash: String,
    payment_preimage: String,
}

pub async fn pay_invoice(
    Extension(state): Extension<State>,
    Form(request): Form<PayInvoiceRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let invoice = state
        .mutiny_wallet
        .pay_invoice(&request.invoice, request.amount_sat, Vec::new())
        .await
        .map_err(|e| handle_mutiny_err(e))?;

    let amount_sat = match invoice.amount_sats {
        Some(amount) => amount,
        None => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "unable to pay invoice"})),
            ))
        }
    };

    let fees = match invoice.fees_paid {
        Some(fee) => fee,
        None => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "unable to pay invoice"})),
            ))
        }
    };

    let preimage = match invoice.preimage {
        Some(preimage) => preimage,
        None => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "unable to pay invoice"})),
            ))
        }
    };

    let invoice = PayInvoiceResponse {
        recipient_amount_sat: amount_sat,
        routing_fee_sat: fees,
        payment_hash: invoice.payment_hash.to_string(),
        payment_preimage: preimage,
    };

    Ok(Json(json!(invoice)))
}

pub async fn get_balance(
    Extension(state): Extension<State>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let balance = state
        .mutiny_wallet
        .get_balance()
        .await
        .map_err(|e| handle_mutiny_err(e))?;
    Ok(Json(json!(balance)))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfoResponse {
    node_id: String,
    channels: Vec<Channel>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Channel {
    state: String,
    channel_id: String,
    balance_sat: u64,
    inbound_liquidity_sat: u64,
    capacity_sat: u64,
    funding_tx_id: Option<String>,
}

pub async fn get_node_info(
    Extension(state): Extension<State>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let nodes = state
        .mutiny_wallet
        .node_manager
        .list_nodes()
        .await
        .map_err(|e| handle_mutiny_err(e))?;
    let node_pubkey: PublicKey;
    if !nodes.is_empty() {
        node_pubkey = nodes[0];
    } else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "unable to get node info"})),
        ));
    }

    let channels = state
        .mutiny_wallet
        .node_manager
        .list_channels()
        .await
        .map_err(|e| handle_mutiny_err(e))?;
    let channels = channels
        .into_iter()
        .map(|channel| {
            let state = match channel.is_usable {
                true => "usable",
                false => "unusable",
            }
            .to_string();
            let funding_tx_id = match channel.outpoint {
                Some(outpoint) => Some(outpoint.txid.to_string()),
                None => None,
            };

            Channel {
                state,
                channel_id: channel.user_chan_id,
                balance_sat: channel.balance,
                inbound_liquidity_sat: channel.inbound,
                capacity_sat: channel.size,
                funding_tx_id,
            }
        })
        .collect();

    let node_info = NodeInfoResponse {
        node_id: node_pubkey.to_string(),
        channels,
    };

    Ok(Json(json!(node_info)))
}

fn handle_mutiny_err(err: MutinyError) -> (StatusCode, Json<Value>) {
    let err = json!({
        "error": format!("{err}"),
    });
    (StatusCode::INTERNAL_SERVER_ERROR, Json(err))
}
