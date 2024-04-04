use crate::extractor::Form;
use crate::sled::SledStorage;

use axum::extract::Path;
use axum::http::StatusCode;
use axum::{Extension, Json};
use bitcoin::hashes::sha256::Hash;
use bitcoin::{secp256k1::PublicKey, Address};
use lightning_invoice::Bolt11Invoice;
use mutiny_core::error::MutinyError;
use mutiny_core::event::HTLCStatus;
use mutiny_core::{InvoiceHandler, MutinyInvoice, MutinyWallet};
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
        .map_err(handle_mutiny_err)?;
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
    let address = Address::from_str(request.address.as_str()).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid address"})),
        )
    })?;

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
        .map_err(handle_mutiny_err)?;

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
            let pubkey = PublicKey::from_str(pubkey.as_str()).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "invalid node pubkey"})),
                )
            })?;
            Some(pubkey)
        }
        None => None,
    };

    let channel = state
        .mutiny_wallet
        .node_manager
        .open_channel(None, to_pubkey, request.amount_sat, request.fee_rate, None)
        .await
        .map_err(handle_mutiny_err)?;
    Ok(Json(json!(channel)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseChannelRequest {
    channel_id: String,
    address: Option<String>,
}

pub async fn close_channel(
    Extension(state): Extension<State>,
    Form(request): Form<CloseChannelRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let channels = state
        .mutiny_wallet
        .node_manager
        .list_channels()
        .await
        .map_err(handle_mutiny_err)?;

    let outpoint = match channels
        .into_iter()
        .find(|channel| channel.user_chan_id == request.channel_id)
    {
        Some(channel) => match channel.outpoint {
            Some(outpoint) => outpoint,
            None => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "unable to close channel"})),
                ))
            }
        },
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "channel does not exist"})),
            ))
        }
    };

    let address = match request.address {
        Some(address) => {
            let address = Address::from_str(address.as_str()).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "invalid address"})),
                )
            })?;

            let address = address
                .require_network(state.mutiny_wallet.get_network())
                .map_err(|_| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "invalid address"})),
                    )
                })?;
            Some(address)
        }
        None => None,
    };

    state
        .mutiny_wallet
        .node_manager
        .close_channel(&outpoint, address, false, false)
        .await
        .map_err(handle_mutiny_err)?;

    Ok(Json(json!("ok")))
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
        .map_err(handle_mutiny_err)?;

    let amount_sat = invoice.amount_sats.ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "unable to create invoice"})),
    ))?;

    let pr = invoice.bolt11.ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "unable to create invoice"})),
    ))?;

    let invoice = CreateInvoiceResponse {
        amount_sat,
        payment_hash: invoice.payment_hash.to_string(),
        serialized: pr.to_string(),
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
        .map_err(handle_mutiny_err)?;

    let amount_sat = invoice.amount_sats.ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "unable to pay invoice"})),
    ))?;

    let fees = invoice.fees_paid.ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "unable to pay invoice"})),
    ))?;

    let preimage = invoice.preimage.ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "unable to pay invoice"})),
    ))?;

    let invoice = PayInvoiceResponse {
        recipient_amount_sat: amount_sat,
        routing_fee_sat: fees,
        payment_hash: invoice.payment_hash.to_string(),
        payment_preimage: preimage,
    };

    Ok(Json(json!(invoice)))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentResponse {
    payment_hash: String,
    preimage: Option<String>,
    description: Option<String>,
    invoice: Option<String>,
    incoming: bool,
    is_paid: bool,
    amount_sats: u64,
    fees: u64,
}

pub async fn get_incoming_payments(
    Extension(state): Extension<State>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let invoices = state
        .mutiny_wallet
        .list_invoices()
        .map_err(handle_mutiny_err)?;

    let invoices: Vec<MutinyInvoice> = invoices
        .into_iter()
        .filter(|invoice| invoice.inbound && invoice.status != HTLCStatus::Succeeded)
        .collect();

    let mut payments = Vec::with_capacity(invoices.len());
    for invoice in invoices.into_iter() {
        let pr = invoice.bolt11.as_ref().map(|bolt11| bolt11.to_string());
        let (is_paid, amount_sats, fees) = get_payment_info(&invoice)?;

        let payment = PaymentResponse {
            payment_hash: invoice.payment_hash.to_string(),
            preimage: invoice.preimage,
            description: invoice.description,
            invoice: pr,
            incoming: invoice.inbound,
            is_paid,
            amount_sats,
            fees,
        };
        payments.push(payment);
    }

    Ok(Json(json!(payments)))
}

pub async fn get_payment(
    Extension(state): Extension<State>,
    Path(payment_hash): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let hash = Hash::from_str(payment_hash.as_str()).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid payment hash"})),
        )
    })?;

    let invoice = state
        .mutiny_wallet
        .get_invoice_by_hash(&hash)
        .await
        .map_err(handle_mutiny_err)?;

    let pr = invoice.bolt11.as_ref().map(|bolt11| bolt11.to_string());
    let (is_paid, amount_sats, fees) = get_payment_info(&invoice)?;

    let payment = PaymentResponse {
        payment_hash: hash.to_string(),
        preimage: invoice.preimage,
        description: invoice.description,
        invoice: pr,
        incoming: invoice.inbound,
        is_paid,
        amount_sats,
        fees,
    };

    Ok(Json(json!(payment)))
}

pub async fn get_balance(
    Extension(state): Extension<State>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let balance = state
        .mutiny_wallet
        .get_balance()
        .await
        .map_err(handle_mutiny_err)?;
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
    state: ChannelState,
    channel_id: String,
    balance_sat: u64,
    inbound_liquidity_sat: u64,
    capacity_sat: u64,
    funding_tx_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum ChannelState {
    Usable,
    Unusable,
}

pub async fn get_node_info(
    Extension(state): Extension<State>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let nodes = state
        .mutiny_wallet
        .node_manager
        .list_nodes()
        .await
        .map_err(handle_mutiny_err)?;

    let node_pubkey: PublicKey = if !nodes.is_empty() {
        nodes[0]
    } else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "unable to get node info"})),
        ));
    };

    let channels = state
        .mutiny_wallet
        .node_manager
        .list_channels()
        .await
        .map_err(handle_mutiny_err)?;

    let channels = channels
        .into_iter()
        .map(|channel| {
            let state = match channel.is_usable {
                true => ChannelState::Usable,
                false => ChannelState::Unusable,
            };

            let funding_tx_id = channel.outpoint.map(|outpoint| outpoint.txid.to_string());

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

fn get_payment_info(
    invoice: &MutinyInvoice,
) -> Result<(bool, u64, u64), (StatusCode, Json<Value>)> {
    let (is_paid, amount_sat, fees) = match invoice.status {
        HTLCStatus::Succeeded => {
            let amount_sat = invoice.amount_sats.ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "unable to fetch payment"})),
            ))?;

            let fees = invoice.fees_paid.ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "unable to fetch payment"})),
            ))?;

            (true, amount_sat, fees)
        }
        _ => (false, 0, 0),
    };
    Ok((is_paid, amount_sat, fees))
}
