use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, ThirtyTwoByteHash};
use bitcoin::OutPoint;
use gloo_utils::format::JsValueSerdeExt;
use hex_conservative::DisplayHex;
use lightning_invoice::Bolt11Invoice;

use mutiny_core::event::HTLCStatus;

use mutiny_core::*;
use serde::{Deserialize, Serialize};

use std::str::FromStr;
use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
#[wasm_bindgen]
pub struct MutinyInvoice {
    bolt11: Option<Bolt11Invoice>,
    description: Option<String>,
    payment_hash: String,
    preimage: Option<String>,
    payee_pubkey: Option<String>,
    pub amount_sats: Option<u64>,
    pub expire: u64,
    pub expired: bool,
    status: String,
    privacy_level: String,
    pub fees_paid: Option<u64>,
    pub inbound: bool,
    pub last_updated: u64,
    pub potential_hodl_invoice: bool,
    labels: Vec<String>,
}

#[wasm_bindgen]
impl MutinyInvoice {
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> JsValue {
        JsValue::from_serde(&serde_json::to_value(self).unwrap()).unwrap()
    }

    #[wasm_bindgen(getter)]
    pub fn bolt11(&self) -> Option<String> {
        self.bolt11.clone().map(|b| b.to_string())
    }

    #[wasm_bindgen(getter)]
    pub fn description(&self) -> Option<String> {
        self.description.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn payment_hash(&self) -> String {
        self.payment_hash.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn preimage(&self) -> Option<String> {
        self.preimage.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn payee_pubkey(&self) -> Option<String> {
        self.payee_pubkey.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn status(&self) -> String {
        self.status.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn privacy_level(&self) -> String {
        self.privacy_level.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn paid(&self) -> bool {
        self.status == HTLCStatus::Succeeded.to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn labels(&self) -> Vec<String> {
        self.labels.clone()
    }
}

impl From<mutiny_core::MutinyInvoice> for MutinyInvoice {
    fn from(m: mutiny_core::MutinyInvoice) -> Self {
        let potential_hodl_invoice = match m.bolt11 {
            Some(ref b) => utils::is_hodl_invoice(b),
            None => false,
        };
        let now = utils::now().as_secs();
        MutinyInvoice {
            bolt11: m.bolt11,
            description: m.description,
            payment_hash: m.payment_hash.to_byte_array().to_lower_hex_string(),
            preimage: m.preimage,
            payee_pubkey: m.payee_pubkey.map(|p| p.serialize().to_lower_hex_string()),
            amount_sats: m.amount_sats,
            expire: m.expire,
            expired: m.expire < now,
            status: m.status.to_string(),
            privacy_level: m.privacy_level.to_string(),
            fees_paid: m.fees_paid,
            inbound: m.inbound,
            last_updated: m.last_updated,
            potential_hodl_invoice,
            labels: m.labels,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
#[wasm_bindgen]
pub struct MutinyPeer {
    pubkey: String,
    connection_string: Option<String>,
    alias: Option<String>,
    color: Option<String>,
    label: Option<String>,
    pub is_connected: bool,
}

#[wasm_bindgen]
impl MutinyPeer {
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> JsValue {
        JsValue::from_serde(&serde_json::to_value(self).unwrap()).unwrap()
    }

    #[wasm_bindgen(getter)]
    pub fn pubkey(&self) -> String {
        self.pubkey.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn connection_string(&self) -> Option<String> {
        self.connection_string.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn alias(&self) -> Option<String> {
        self.alias.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn color(&self) -> Option<String> {
        self.color.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn label(&self) -> Option<String> {
        self.label.clone()
    }
}

impl From<nodemanager::MutinyPeer> for MutinyPeer {
    fn from(m: nodemanager::MutinyPeer) -> Self {
        MutinyPeer {
            pubkey: m.pubkey.serialize().to_lower_hex_string(),
            connection_string: m.connection_string,
            alias: m.alias,
            color: m.color,
            label: m.label,
            is_connected: m.is_connected,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
#[wasm_bindgen]
pub struct MutinyChannel {
    user_chan_id: String,
    pub balance: u64,
    pub size: u64,
    pub reserve: u64,
    pub inbound: u64,
    outpoint: Option<String>,
    peer: String,
    pub confirmations_required: Option<u32>,
    pub confirmations: u32,
    pub is_outbound: bool,
    pub is_usable: bool,
    pub is_anchor: bool,
}

#[wasm_bindgen]
impl MutinyChannel {
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> JsValue {
        JsValue::from_serde(&serde_json::to_value(self).unwrap()).unwrap()
    }

    #[wasm_bindgen(getter)]
    pub fn user_chan_id(&self) -> String {
        self.user_chan_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn outpoint(&self) -> Option<String> {
        self.outpoint.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn peer(&self) -> String {
        self.peer.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn confirmed(&self) -> bool {
        match self.confirmations_required {
            Some(c) => self.confirmations >= c,
            None => false,
        }
    }
}

impl From<nodemanager::MutinyChannel> for MutinyChannel {
    fn from(m: nodemanager::MutinyChannel) -> Self {
        MutinyChannel {
            user_chan_id: m.user_chan_id,
            balance: m.balance,
            size: m.size,
            reserve: m.reserve,
            inbound: m.inbound,
            outpoint: m.outpoint.map(|o| o.to_string()),
            peer: m.peer.serialize().to_lower_hex_string(),
            confirmations_required: m.confirmations_required,
            confirmations: m.confirmations,
            is_outbound: m.is_outbound,
            is_usable: m.is_usable,
            is_anchor: m.is_anchor,
        }
    }
}

impl From<MutinyChannel> for nodemanager::MutinyChannel {
    fn from(m: MutinyChannel) -> Self {
        nodemanager::MutinyChannel {
            user_chan_id: m.user_chan_id,
            balance: m.balance,
            size: m.size,
            reserve: m.reserve,
            inbound: m.inbound,
            outpoint: m
                .outpoint
                .map(|o| OutPoint::from_str(&o).expect("Invalid outpoint")),
            peer: PublicKey::from_str(&m.peer).expect("Invalid peer pubkey"),
            confirmations_required: m.confirmations_required,
            confirmations: m.confirmations,
            is_outbound: m.is_outbound,
            is_usable: m.is_usable,
            is_anchor: m.is_anchor,
        }
    }
}

/// Information about a channel that was closed.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[wasm_bindgen]
pub struct ChannelClosure {
    channel_id: Option<String>,
    node_id: Option<String>,
    reason: String,
    pub timestamp: u64,
}

#[wasm_bindgen]
impl ChannelClosure {
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> JsValue {
        JsValue::from_serde(&serde_json::to_value(self).unwrap()).unwrap()
    }

    #[wasm_bindgen(getter)]
    pub fn channel_id(&self) -> Option<String> {
        self.channel_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn node_id(&self) -> Option<String> {
        self.node_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn reason(&self) -> String {
        self.reason.clone()
    }
}

impl PartialOrd for ChannelClosure {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ChannelClosure {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.timestamp.cmp(&other.timestamp)
    }
}

impl From<nodemanager::ChannelClosure> for ChannelClosure {
    fn from(c: nodemanager::ChannelClosure) -> Self {
        ChannelClosure {
            channel_id: c.channel_id.map(|c| c.to_lower_hex_string()),
            node_id: c.node_id.map(|c| c.serialize().to_lower_hex_string()),
            reason: c.reason,
            timestamp: c.timestamp,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
#[wasm_bindgen]
pub struct MutinyBalance {
    pub confirmed: u64,
    pub unconfirmed: u64,
    pub lightning: u64,
    pub force_close: u64,
}

#[wasm_bindgen]
impl MutinyBalance {
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> JsValue {
        JsValue::from_serde(&serde_json::to_value(self).unwrap()).unwrap()
    }
}

impl From<mutiny_core::MutinyBalance> for MutinyBalance {
    fn from(m: mutiny_core::MutinyBalance) -> Self {
        MutinyBalance {
            confirmed: m.confirmed,
            unconfirmed: m.unconfirmed,
            lightning: m.lightning,
            force_close: m.force_close,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
#[wasm_bindgen]
pub struct LnUrlParams {
    pub max: u64,
    pub min: u64,
    tag: String,
}

#[wasm_bindgen]
impl LnUrlParams {
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> JsValue {
        JsValue::from_serde(&serde_json::to_value(self).unwrap()).unwrap()
    }

    #[wasm_bindgen(getter)]
    pub fn tag(&self) -> String {
        self.tag.clone()
    }
}

impl From<mutiny_core::LnUrlParams> for LnUrlParams {
    fn from(m: mutiny_core::LnUrlParams) -> Self {
        LnUrlParams {
            max: m.max,
            min: m.min,
            tag: m.tag,
        }
    }
}

// This is the NodeIdentity that refer to a specific node
// Used for public facing identification.
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
#[wasm_bindgen]
pub struct NodeIdentity {
    uuid: String,
    pubkey: PublicKey,
}

#[wasm_bindgen]
impl NodeIdentity {
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> JsValue {
        JsValue::from_serde(&serde_json::to_value(self).unwrap()).unwrap()
    }

    #[wasm_bindgen(getter)]
    pub fn uuid(&self) -> String {
        self.uuid.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn pubkey(&self) -> String {
        self.pubkey.to_string()
    }
}

impl From<nodemanager::NodeIdentity> for NodeIdentity {
    fn from(m: nodemanager::NodeIdentity) -> Self {
        NodeIdentity {
            uuid: m.uuid,
            pubkey: m.pubkey,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
#[wasm_bindgen]
pub struct MutinyBip21RawMaterials {
    pub(crate) address: String,
    pub(crate) invoice: Option<String>,
    pub(crate) btc_amount: Option<String>,
    pub(crate) labels: Vec<String>,
}

#[wasm_bindgen]
impl MutinyBip21RawMaterials {
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> JsValue {
        JsValue::from_serde(&serde_json::to_value(self).unwrap()).unwrap()
    }

    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.address.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn invoice(&self) -> Option<String> {
        self.invoice.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn btc_amount(&self) -> Option<String> {
        self.btc_amount.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn labels(&self) -> Vec<String> {
        self.labels.clone()
    }
}

impl From<nodemanager::MutinyBip21RawMaterials> for MutinyBip21RawMaterials {
    fn from(m: nodemanager::MutinyBip21RawMaterials) -> Self {
        MutinyBip21RawMaterials {
            address: m.address.to_string(),
            invoice: m.invoice.map(|i| i.to_string()),
            btc_amount: m.btc_amount,
            labels: m.labels,
        }
    }
}

/// FedimintSweepResult is the result of how much was swept and the fees paid.
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
#[wasm_bindgen]
pub struct FedimintSweepResult {
    pub amount: u64,
    pub fees: Option<u64>,
}

#[wasm_bindgen]
impl FedimintSweepResult {
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> JsValue {
        JsValue::from_serde(&serde_json::to_value(self).unwrap()).unwrap()
    }
}

impl From<mutiny_core::FedimintSweepResult> for FedimintSweepResult {
    fn from(m: mutiny_core::FedimintSweepResult) -> Self {
        FedimintSweepResult {
            amount: m.amount,
            fees: m.fees,
        }
    }
}
