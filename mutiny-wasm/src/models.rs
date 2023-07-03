use bitcoin::hashes::hex::ToHex;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, OutPoint, XOnlyPublicKey};
use gloo_utils::format::JsValueSerdeExt;
use lightning_invoice::{Invoice, InvoiceDescription};
use lnurl::lightning_address::LightningAddress;
use lnurl::lnurl::LnUrl;
use mutiny_core::labels::Contact as MutinyContact;
use mutiny_core::redshift::{RedshiftRecipient, RedshiftStatus};
use mutiny_core::*;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use wasm_bindgen::prelude::*;

use crate::{error::MutinyJsError, utils};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[wasm_bindgen]
pub enum ActivityType {
    OnChain,
    Lightning,
    ChannelOpen,
    ChannelClose,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[wasm_bindgen]
pub struct ActivityItem {
    pub kind: ActivityType,
    id: String,
    pub amount_sats: Option<u64>,
    pub inbound: bool,
    pub(crate) labels: Vec<String>,
    pub(crate) contacts: Vec<Contact>,
    pub last_updated: Option<u64>,
}

#[wasm_bindgen]
impl ActivityItem {
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> JsValue {
        JsValue::from_serde(&serde_json::to_value(self).unwrap()).unwrap()
    }

    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn labels(&self) -> JsValue /* Vec<String> */ {
        JsValue::from_serde(&self.labels).unwrap()
    }

    #[wasm_bindgen(getter)]
    pub fn contacts(&self) -> JsValue /* Vec<Contact> */ {
        JsValue::from_serde(&self.contacts).unwrap()
    }
}

impl From<nodemanager::ActivityItem> for ActivityItem {
    fn from(a: nodemanager::ActivityItem) -> Self {
        let kind = match a {
            nodemanager::ActivityItem::OnChain(_) => {
                if a.is_channel_open() {
                    ActivityType::ChannelOpen
                } else {
                    ActivityType::OnChain
                }
            }
            nodemanager::ActivityItem::Lightning(_) => ActivityType::Lightning,
            nodemanager::ActivityItem::ChannelClosed(_) => ActivityType::ChannelClose,
        };

        let id = match a {
            nodemanager::ActivityItem::OnChain(ref t) => t.txid.to_hex(),
            nodemanager::ActivityItem::Lightning(ref ln) => ln.payment_hash.to_hex(),
            nodemanager::ActivityItem::ChannelClosed(ref c) => {
                c.user_channel_id.map(|c| c.to_hex()).unwrap_or_default()
            }
        };

        let (inbound, amount_sats) = match a {
            nodemanager::ActivityItem::OnChain(ref t) => {
                let inbound = t.received > t.sent;
                let amount_sats = if inbound {
                    Some(t.received - t.sent)
                } else {
                    Some(t.sent - t.received)
                };
                (inbound, amount_sats)
            }
            nodemanager::ActivityItem::Lightning(ref ln) => (ln.inbound, ln.amount_sats),
            nodemanager::ActivityItem::ChannelClosed(_) => (false, None),
        };

        ActivityItem {
            kind,
            id,
            amount_sats,
            inbound,
            labels: a.labels(),
            contacts: vec![],
            last_updated: a.last_updated(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
#[wasm_bindgen]
pub struct MutinyInvoice {
    bolt11: Option<Invoice>,
    description: Option<String>,
    payment_hash: String,
    preimage: Option<String>,
    payee_pubkey: Option<String>,
    pub amount_sats: Option<u64>,
    pub expire: u64,
    pub paid: bool,
    pub fees_paid: Option<u64>,
    pub inbound: bool,
    pub last_updated: u64,
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
    pub fn labels(&self) -> JsValue /* Vec<String> */ {
        JsValue::from_serde(&self.labels).unwrap()
    }
}

impl From<nodemanager::MutinyInvoice> for MutinyInvoice {
    fn from(m: nodemanager::MutinyInvoice) -> Self {
        MutinyInvoice {
            bolt11: m.bolt11,
            description: m.description,
            payment_hash: m.payment_hash.to_hex(),
            preimage: m.preimage,
            payee_pubkey: m.payee_pubkey.map(|p| p.to_hex()),
            amount_sats: m.amount_sats,
            expire: m.expire,
            paid: m.paid,
            fees_paid: m.fees_paid,
            inbound: m.inbound,
            last_updated: m.last_updated,
            labels: m.labels,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
#[wasm_bindgen]
pub struct MutinyPeer {
    pubkey: PublicKey,
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
        self.pubkey.to_hex()
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
            pubkey: m.pubkey,
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
    pub balance: u64,
    pub size: u64,
    pub reserve: u64,
    outpoint: Option<String>,
    peer: String,
    pub confirmations_required: Option<u32>,
    pub confirmations: u32,
}

#[wasm_bindgen]
impl MutinyChannel {
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> JsValue {
        JsValue::from_serde(&serde_json::to_value(self).unwrap()).unwrap()
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
            balance: m.balance,
            size: m.size,
            reserve: m.reserve,
            outpoint: m.outpoint.map(|o| o.to_string()),
            peer: m.peer.to_hex(),
            confirmations_required: m.confirmations_required,
            confirmations: m.confirmations,
        }
    }
}

/// Information about a channel that was closed.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[wasm_bindgen]
pub struct ChannelClosure {
    channel_id: Option<[u8; 32]>,
    node_id: Option<PublicKey>,
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
        self.channel_id.map(|c| c.to_hex())
    }

    #[wasm_bindgen(getter)]
    pub fn node_id(&self) -> Option<String> {
        self.node_id.map(|n| n.to_string())
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
            channel_id: c.channel_id,
            node_id: c.node_id,
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

impl From<nodemanager::MutinyBalance> for MutinyBalance {
    fn from(m: nodemanager::MutinyBalance) -> Self {
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

impl From<nodemanager::LnUrlParams> for LnUrlParams {
    fn from(m: nodemanager::LnUrlParams) -> Self {
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
    address: String,
    invoice: String,
    btc_amount: Option<String>,
    labels: Vec<String>,
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
    pub fn invoice(&self) -> String {
        self.invoice.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn btc_amount(&self) -> Option<String> {
        self.btc_amount.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn labels(&self) -> JsValue /* Vec<String> */ {
        JsValue::from_serde(&self.labels).unwrap()
    }
}

impl From<nodemanager::MutinyBip21RawMaterials> for MutinyBip21RawMaterials {
    fn from(m: nodemanager::MutinyBip21RawMaterials) -> Self {
        MutinyBip21RawMaterials {
            address: m.address.to_string(),
            invoice: m.invoice.to_string(),
            btc_amount: m.btc_amount,
            labels: m.labels,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[wasm_bindgen]
pub struct AuthProfile {
    pub index: u32,
    name: String,
    used_services: Vec<String>,
}

#[wasm_bindgen]
impl AuthProfile {
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> JsValue {
        JsValue::from_serde(&serde_json::to_value(self).unwrap()).unwrap()
    }

    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.name.to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn used_services(&self) -> JsValue /* Vec<String> */ {
        JsValue::from_serde(&serde_json::to_value(&self.used_services).unwrap()).unwrap()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct Redshift {
    id: String,
    input_utxo: OutPoint,
    status: RedshiftStatus,
    sending_node: PublicKey,
    lightning_recipient_pubkey: Option<PublicKey>,
    onchain_recipient: Option<Address>,
    output_utxo: Option<OutPoint>,
    introduction_channel: Option<OutPoint>,
    output_channel: Option<Vec<OutPoint>>,
    introduction_node: PublicKey,
    pub amount_sats: u64,
    pub sats_sent: u64,
    pub change_amt: Option<u64>,
    pub fees_paid: u64,
}

#[wasm_bindgen]
impl Redshift {
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> JsValue {
        JsValue::from_serde(&serde_json::to_value(self).unwrap()).unwrap()
    }

    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn input_utxo(&self) -> String {
        self.input_utxo.to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn status(&self) -> String {
        match self.status {
            RedshiftStatus::ChannelOpening => "ChannelOpening".to_string(),
            RedshiftStatus::ChannelOpened => "ChannelOpened".to_string(),
            RedshiftStatus::AttemptingPayments => "AttemptingPayments".to_string(),
            RedshiftStatus::ClosingChannels => "ClosingChannels".to_string(),
            RedshiftStatus::Completed => "Completed".to_string(),
            RedshiftStatus::Failed(_) => "Failed".to_string(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn sending_node(&self) -> String {
        self.sending_node.to_hex()
    }

    #[wasm_bindgen(getter)]
    pub fn lightning_recipient_pubkey(&self) -> Option<String> {
        self.lightning_recipient_pubkey.map(|o| o.to_hex())
    }

    #[wasm_bindgen(getter)]
    pub fn onchain_recipient(&self) -> Option<String> {
        self.onchain_recipient.clone().map(|o| o.to_string())
    }

    #[wasm_bindgen(getter)]
    pub fn output_utxo(&self) -> Option<String> {
        self.output_utxo.map(|o| o.to_string())
    }

    #[wasm_bindgen(getter)]
    pub fn introduction_channel(&self) -> Option<String> {
        self.introduction_channel.map(|o| o.to_string())
    }

    #[wasm_bindgen(getter)]
    pub fn output_channel(&self) -> JsValue /* Option<Vec<String>> */ {
        JsValue::from_serde(&serde_json::to_value(&self.output_channel).unwrap()).unwrap()
    }

    #[wasm_bindgen(getter)]
    pub fn introduction_node(&self) -> String {
        self.introduction_node.to_hex()
    }
}

impl From<redshift::Redshift> for Redshift {
    fn from(rs: redshift::Redshift) -> Self {
        let (lightning_recipient_pubkey, onchain_recipient) = match rs.recipient {
            RedshiftRecipient::Lightning(pk) => (Some(pk), None),
            RedshiftRecipient::OnChain(addr) => (None, addr),
        };

        Redshift {
            id: rs.id.to_hex(),
            input_utxo: rs.input_utxo,
            status: rs.status,
            sending_node: rs.sending_node,
            lightning_recipient_pubkey,
            onchain_recipient,
            output_utxo: rs.output_utxo,
            introduction_channel: rs.introduction_channel,
            output_channel: rs.output_channel,
            introduction_node: rs.introduction_node,
            amount_sats: rs.amount_sats,
            sats_sent: rs.sats_sent,
            change_amt: rs.change_amt,
            fees_paid: rs.fees_paid,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq, Hash)]
#[wasm_bindgen]
pub enum TagKind {
    Label,
    Contact,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[wasm_bindgen]
pub struct TagItem {
    id: String,
    pub kind: TagKind,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    npub: Option<XOnlyPublicKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ln_address: Option<LightningAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lnurl: Option<LnUrl>,
    /// Epoch time in seconds when this tag was last used
    pub last_used_time: u64,
}

#[wasm_bindgen]
impl TagItem {
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> JsValue {
        JsValue::from_serde(&serde_json::to_value(self).unwrap()).unwrap()
    }

    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.name.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn npub(&self) -> Option<String> {
        self.npub.map(|a| a.to_string())
    }

    #[wasm_bindgen(getter)]
    pub fn ln_address(&self) -> Option<String> {
        self.ln_address.clone().map(|a| a.to_string())
    }

    #[wasm_bindgen(getter)]
    pub fn lnurl(&self) -> Option<String> {
        self.lnurl.clone().map(|a| a.to_string())
    }
}

impl From<(String, MutinyContact)> for TagItem {
    fn from(m: (String, MutinyContact)) -> Self {
        let (id, contact) = m;
        TagItem {
            id,
            kind: TagKind::Contact,
            name: contact.name,
            npub: contact.npub,
            ln_address: contact.ln_address,
            lnurl: contact.lnurl,
            last_used_time: contact.last_used,
        }
    }
}

impl From<labels::TagItem> for TagItem {
    fn from(m: labels::TagItem) -> Self {
        match m {
            labels::TagItem::Label((label, item)) => TagItem {
                id: label.clone(),
                kind: TagKind::Label,
                name: label,
                npub: None,
                ln_address: None,
                lnurl: None,
                last_used_time: item.last_used_time,
            },
            labels::TagItem::Contact(contact) => contact.into(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[wasm_bindgen]
pub struct Contact {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    npub: Option<XOnlyPublicKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ln_address: Option<LightningAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lnurl: Option<LnUrl>,
    pub last_used: u64,
}

#[wasm_bindgen]
impl Contact {
    #[wasm_bindgen(constructor)]
    pub fn new(
        name: String,
        npub: Option<String>,
        ln_address: Option<String>,
        lnurl: Option<String>,
    ) -> Result<Contact, MutinyJsError> {
        // Convert the parameters into the types expected by the struct
        let npub = npub.map(|s| XOnlyPublicKey::from_str(&s)).transpose()?;
        let ln_address = ln_address
            .map(|s| LightningAddress::from_str(&s))
            .transpose()?;
        let lnurl = lnurl.map(|s| LnUrl::from_str(&s)).transpose()?;

        Ok(Contact {
            name,
            npub,
            ln_address,
            lnurl,
            last_used: utils::now().as_secs(),
        })
    }

    #[wasm_bindgen(getter)]
    pub fn value(&self) -> JsValue {
        JsValue::from_serde(&serde_json::to_value(self).unwrap()).unwrap()
    }

    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.name.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn npub(&self) -> Option<String> {
        self.npub.map(|a| a.to_string())
    }

    #[wasm_bindgen(getter)]
    pub fn ln_address(&self) -> Option<String> {
        self.ln_address.clone().map(|a| a.to_string())
    }

    #[wasm_bindgen(getter)]
    pub fn lnurl(&self) -> Option<String> {
        self.lnurl.clone().map(|a| a.to_string())
    }
}

impl From<Contact> for MutinyContact {
    fn from(c: Contact) -> Self {
        MutinyContact {
            name: c.name,
            npub: c.npub,
            ln_address: c.ln_address,
            lnurl: c.lnurl,
            archived: Some(false),
            last_used: c.last_used,
        }
    }
}

impl From<MutinyContact> for Contact {
    fn from(c: MutinyContact) -> Self {
        Contact {
            name: c.name,
            npub: c.npub,
            ln_address: c.ln_address,
            lnurl: c.lnurl,
            last_used: c.last_used,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct NwcProfile {
    name: String,
    pub index: u32,
    /// Maximum amount of sats that can be sent in a single payment
    pub max_single_amt_sats: u64,
    relay: String,
    pub enabled: bool,
    /// Require approval before sending a payment
    pub require_approval: bool,
    nwc_uri: String,
}

#[wasm_bindgen]
impl NwcProfile {
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> JsValue {
        JsValue::from_serde(&serde_json::to_value(self).unwrap()).unwrap()
    }

    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.name.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn relay(&self) -> String {
        self.relay.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn nwc_uri(&self) -> String {
        self.nwc_uri.clone()
    }
}

impl From<nostr::nwc::NwcProfile> for NwcProfile {
    fn from(value: nostr::nwc::NwcProfile) -> Self {
        NwcProfile {
            name: value.name,
            index: value.index,
            max_single_amt_sats: value.max_single_amt_sats,
            relay: value.relay,
            enabled: value.enabled,
            require_approval: value.require_approval,
            nwc_uri: value.nwc_uri,
        }
    }
}

/// An invoice received over Nostr Wallet Connect that is pending approval or rejection
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PendingNwcInvoice {
    /// Index of the profile that received the invoice
    pub index: u32,
    /// The invoice that awaiting approval
    pub invoice: String,
    /// The id of the invoice, this is the payment hash
    pub id: String,
    /// The amount of sats that the invoice is for
    pub amount_sats: u64,
    /// The description of the invoice
    pub invoice_description: Option<String>,
    /// Invoice expire time in seconds since epoch
    pub expiry: u64,
}

impl From<nostr::nwc::PendingNwcInvoice> for PendingNwcInvoice {
    fn from(value: nostr::nwc::PendingNwcInvoice) -> Self {
        let invoice_description = match value.invoice.description() {
            InvoiceDescription::Direct(desc) => Some(desc.to_string()),
            InvoiceDescription::Hash(_) => None,
        };

        let timestamp = value.invoice.duration_since_epoch().as_secs();
        let expiry = timestamp + value.invoice.expiry_time().as_secs();

        PendingNwcInvoice {
            index: value.index,
            invoice: value.invoice.to_string(),
            id: value.invoice.payment_hash().to_hex(),
            amount_sats: value.invoice.amount_milli_satoshis().unwrap_or_default() / 1_000,
            invoice_description,
            expiry,
        }
    }
}
