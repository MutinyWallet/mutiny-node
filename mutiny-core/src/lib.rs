#![crate_name = "mutiny_core"]
// wasm is considered "extra_unused_type_parameters"
#![allow(
    async_fn_in_trait,
    incomplete_features,
    clippy::extra_unused_type_parameters,
    clippy::arc_with_non_send_sync,
    type_alias_bounds
)]
extern crate core;

pub mod auth;
mod chain;
pub mod encrypt;
pub mod error;
pub mod event;
mod fees;
mod gossip;
// mod hermes;
mod key;
mod keymanager;
pub mod labels;
mod ldkstorage;
pub mod lnurlauth;
pub mod logging;
pub mod lsp;
mod messagehandler;
mod networking;
mod node;
pub mod nodemanager;
// pub mod nostr;
mod onchain;
mod peermanager;
pub mod scorer;
pub mod storage;
mod subscription;
pub mod utils;
pub mod vss;

#[cfg(test)]
mod test_utils;

use crate::error::MutinyError;
pub use crate::gossip::{GOSSIP_SYNC_TIME_KEY, NETWORK_GRAPH_KEY, PROB_SCORER_KEY};
pub use crate::keymanager::generate_seed;
pub use crate::ldkstorage::{CHANNEL_CLOSURE_PREFIX, CHANNEL_MANAGER_KEY, MONITORS_PREFIX_KEY};
use crate::lnurlauth::AuthManager;
use crate::nodemanager::NodeManager;
use crate::storage::get_invoice_by_hash;
use crate::utils::sleep;
use crate::utils::spawn;
use crate::{auth::MutinyAuthClient, logging::MutinyLogger};
use crate::{
    event::{HTLCStatus, MillisatAmount, PaymentInfo},
    onchain::FULL_SYNC_STOP_GAP,
};
use crate::{labels::LabelStorage, nodemanager::NodeBalance};
use crate::{
    lnurlauth::make_lnurl_auth_connection,
    nodemanager::{ChannelClosure, MutinyBip21RawMaterials},
};
use crate::{logging::LOGGING_KEY, nodemanager::NodeManagerBuilder};
use crate::{
    onchain::get_esplora_url,
    storage::{
        get_payment_hash_from_key, get_transaction_details, list_payment_info,
        persist_payment_info, IndexItem, MutinyStorage, DEVICE_ID_KEY, EXPECTED_NETWORK_KEY,
        NEED_FULL_SYNC_KEY, ONCHAIN_PREFIX, PAYMENT_INBOUND_PREFIX_KEY,
        PAYMENT_OUTBOUND_PREFIX_KEY, TRANSACTION_DETAILS_PREFIX_KEY,
    },
};
use bdk_chain::ConfirmationTime;
use bip39::Mnemonic;
pub use bitcoin;
use bitcoin::secp256k1::{PublicKey, ThirtyTwoByteHash};
use bitcoin::{bip32::ExtendedPrivKey, Transaction};
use bitcoin::{hashes::sha256, Network, Txid};
use bitcoin::{hashes::Hash, Address};

use futures_util::lock::Mutex;
use hex_conservative::{DisplayHex, FromHex};
use itertools::Itertools;
pub use lightning;
use lightning::chain::BestBlock;
use lightning::ln::PaymentHash;
use lightning::util::logger::Logger;
use lightning::{log_debug, log_error, log_info, log_trace, log_warn};
pub use lightning_invoice;
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription};
use lnurl::{lnurl::LnUrl, AsyncClient as LnUrlClient, LnUrlResponse, Response};

use serde::{Deserialize, Serialize};

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;
use std::{collections::HashMap, sync::atomic::AtomicBool};
use std::{str::FromStr, sync::atomic::Ordering};

#[cfg(target_arch = "wasm32")]
use web_time::Instant;

#[cfg(test)]
use mockall::{automock, predicate::*};

pub const DEVICE_LOCK_INTERVAL_SECS: u64 = 30;
const BITCOIN_PRICE_CACHE_SEC: u64 = 300;
const DEFAULT_PAYMENT_TIMEOUT: u64 = 30;
const DUST_LIMIT: u64 = 546;

#[cfg_attr(test, automock)]
pub trait InvoiceHandler {
    fn logger(&self) -> &MutinyLogger;
    fn skip_hodl_invoices(&self) -> bool;
    fn get_network(&self) -> Network;
    async fn get_best_block(&self) -> Result<BestBlock, MutinyError>;
    async fn lookup_payment(&self, payment_hash: &[u8; 32]) -> Option<MutinyInvoice>;
    async fn pay_invoice(
        &self,
        invoice: &Bolt11Invoice,
        amt_sats: Option<u64>,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError>;
    async fn create_invoice(
        &self,
        amount: u64,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError>;
}

pub struct LnUrlParams {
    pub max: u64,
    pub min: u64,
    pub tag: String,
}

#[derive(Copy, Clone)]
pub struct MutinyBalance {
    pub confirmed: u64,
    pub unconfirmed: u64,
    pub lightning: u64,
    pub force_close: u64,
}

impl MutinyBalance {
    fn new(ln_balance: NodeBalance) -> Self {
        Self {
            confirmed: ln_balance.confirmed,
            unconfirmed: ln_balance.unconfirmed,
            lightning: ln_balance.lightning,
            force_close: ln_balance.force_close,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ActivityItem {
    OnChain(TransactionDetails),
    Lightning(Box<MutinyInvoice>),
    ChannelClosed(ChannelClosure),
}

/// A wallet transaction
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TransactionDetails {
    /// Optional transaction
    pub transaction: Option<Transaction>,
    /// Transaction id
    pub txid: Option<Txid>,
    /// Internal id before a transaction id is created
    pub internal_id: Txid,
    /// Received value (sats)
    /// Sum of owned outputs of this transaction.
    pub received: u64,
    /// Sent value (sats)
    /// Sum of owned inputs of this transaction.
    pub sent: u64,
    /// Fee value in sats if it was available.
    pub fee: Option<u64>,
    /// If the transaction is confirmed, contains height and Unix timestamp of the block containing the
    /// transaction, unconfirmed transaction contains `None`.
    pub confirmation_time: ConfirmationTime,
    /// Labels associated with this transaction
    pub labels: Vec<String>,
}

impl PartialOrd for TransactionDetails {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TransactionDetails {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        match (self.confirmation_time, other.confirmation_time) {
            (ConfirmationTime::Confirmed { .. }, ConfirmationTime::Confirmed { .. }) => self
                .confirmation_time
                .cmp(&self.confirmation_time)
                .then_with(|| self.txid.cmp(&other.txid)),
            (ConfirmationTime::Confirmed { .. }, ConfirmationTime::Unconfirmed { .. }) => {
                core::cmp::Ordering::Less
            }
            (ConfirmationTime::Unconfirmed { .. }, ConfirmationTime::Confirmed { .. }) => {
                core::cmp::Ordering::Greater
            }
            (
                ConfirmationTime::Unconfirmed { last_seen: a },
                ConfirmationTime::Unconfirmed { last_seen: b },
            ) => a.cmp(&b).then_with(|| self.txid.cmp(&other.txid)),
        }
    }
}

impl ActivityItem {
    pub fn last_updated(&self) -> Option<u64> {
        match self {
            ActivityItem::OnChain(t) => match t.confirmation_time {
                ConfirmationTime::Confirmed { time, .. } => Some(time),
                ConfirmationTime::Unconfirmed { .. } => None,
            },
            ActivityItem::Lightning(i) => match i.status {
                HTLCStatus::Succeeded => Some(i.last_updated),
                HTLCStatus::Failed => Some(i.last_updated),
                HTLCStatus::Pending | HTLCStatus::InFlight => None,
            },
            ActivityItem::ChannelClosed(c) => Some(c.timestamp),
        }
    }

    pub fn labels(&self) -> Vec<String> {
        match self {
            ActivityItem::OnChain(t) => t.labels.clone(),
            ActivityItem::Lightning(i) => i.labels.clone(),
            ActivityItem::ChannelClosed(_) => vec![],
        }
    }

    pub fn is_channel_open(&self) -> bool {
        match self {
            ActivityItem::OnChain(onchain) => {
                onchain.labels.iter().any(|l| l.contains("LN Channel:"))
            }
            ActivityItem::Lightning(_) => false,
            ActivityItem::ChannelClosed(_) => false,
        }
    }
}

impl PartialOrd for ActivityItem {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ActivityItem {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // We want None to be greater than Some because those are pending transactions
        // so those should be at the top of the list
        let sort = match (self.last_updated(), other.last_updated()) {
            (Some(self_time), Some(other_time)) => self_time.cmp(&other_time),
            (Some(_), None) => core::cmp::Ordering::Less,
            (None, Some(_)) => core::cmp::Ordering::Greater,
            (None, None) => {
                // if both are none, do lightning first
                match (self, other) {
                    (ActivityItem::Lightning(_), ActivityItem::OnChain(_)) => {
                        core::cmp::Ordering::Greater
                    }
                    (ActivityItem::OnChain(_), ActivityItem::Lightning(_)) => {
                        core::cmp::Ordering::Less
                    }
                    (ActivityItem::Lightning(l1), ActivityItem::Lightning(l2)) => {
                        // compare lightning by expire time
                        l1.expire.cmp(&l2.expire)
                    }
                    (ActivityItem::OnChain(o1), ActivityItem::OnChain(o2)) => {
                        // compare onchain by confirmation time (which will be last seen for unconfirmed)
                        o1.confirmation_time.cmp(&o2.confirmation_time)
                    }
                    _ => core::cmp::Ordering::Equal,
                }
            }
        };

        // if the sort is equal, sort by serialization so we have a stable sort
        sort.then_with(|| {
            serde_json::to_string(self)
                .unwrap()
                .cmp(&serde_json::to_string(other).unwrap())
        })
    }
}

/// Privacy Level for a payment
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Default, Hash)]
pub enum PrivacyLevel {
    /// A public payment that is visible to everyone.
    Public,
    /// A private payment that is only visible to the sender and receiver.
    Private,
    /// A payment where the receiver does not know the sender.
    Anonymous,
    /// No information is shared about the payment.
    #[default]
    NotAvailable,
}

impl core::fmt::Display for PrivacyLevel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PrivacyLevel::Public => write!(f, "Public"),
            PrivacyLevel::Private => write!(f, "Private"),
            PrivacyLevel::Anonymous => write!(f, "Anonymous"),
            PrivacyLevel::NotAvailable => write!(f, "Not Available"),
        }
    }
}

impl FromStr for PrivacyLevel {
    type Err = MutinyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Public" => Ok(PrivacyLevel::Public),
            "Private" => Ok(PrivacyLevel::Private),
            "Anonymous" => Ok(PrivacyLevel::Anonymous),
            "Not Available" => Ok(PrivacyLevel::NotAvailable),
            _ => Err(MutinyError::InvalidArgumentsError),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct MutinyInvoice {
    pub bolt11: Option<Bolt11Invoice>,
    pub description: Option<String>,
    pub payment_hash: sha256::Hash,
    pub preimage: Option<String>,
    pub payee_pubkey: Option<PublicKey>,
    pub amount_sats: Option<u64>,
    pub expire: u64,
    pub status: HTLCStatus,
    #[serde(default)]
    pub privacy_level: PrivacyLevel,
    pub fees_paid: Option<u64>,
    pub inbound: bool,
    pub labels: Vec<String>,
    pub last_updated: u64,
}

#[cfg(test)]
impl Default for MutinyInvoice {
    fn default() -> Self {
        MutinyInvoice {
            bolt11: None,
            description: None,
            payment_hash: sha256::Hash::all_zeros(),
            preimage: None,
            payee_pubkey: None,
            amount_sats: None,
            expire: 0,
            status: HTLCStatus::Pending,
            privacy_level: PrivacyLevel::NotAvailable,
            fees_paid: None,
            inbound: false,
            labels: vec![],
            last_updated: 0,
        }
    }
}

impl MutinyInvoice {
    pub fn paid(&self) -> bool {
        self.status == HTLCStatus::Succeeded
    }
}

impl From<Bolt11Invoice> for MutinyInvoice {
    fn from(value: Bolt11Invoice) -> Self {
        let description = match value.description() {
            Bolt11InvoiceDescription::Direct(a) => {
                let desc = a.clone().into_inner();
                if desc.0.is_empty() {
                    None
                } else {
                    Some(desc.0)
                }
            }
            Bolt11InvoiceDescription::Hash(_) => None,
        };

        let timestamp = value.duration_since_epoch().as_secs();
        let expiry = timestamp + value.expiry_time().as_secs();

        let payment_hash = value.payment_hash().to_owned();
        let payee_pubkey = value.payee_pub_key().map(|p| p.to_owned());
        let amount_sats = value.amount_milli_satoshis().map(|m| m / 1000);

        MutinyInvoice {
            bolt11: Some(value),
            description,
            payment_hash,
            preimage: None,
            payee_pubkey,
            amount_sats,
            expire: expiry,
            status: HTLCStatus::Pending,
            privacy_level: PrivacyLevel::NotAvailable,
            fees_paid: None,
            inbound: true,
            labels: vec![],
            last_updated: timestamp,
        }
    }
}

impl From<MutinyInvoice> for PaymentInfo {
    fn from(invoice: MutinyInvoice) -> Self {
        let preimage: Option<[u8; 32]> = invoice
            .preimage
            .map(|s| FromHex::from_hex(&s).expect("preimage should decode"));
        let secret = None;
        let status = invoice.status;
        let amt_msat = invoice
            .amount_sats
            .map(|s| MillisatAmount(Some(s)))
            .unwrap_or(MillisatAmount(None));
        let fee_paid_msat = invoice.fees_paid.map(|f| f * 1_000);
        let bolt11 = invoice.bolt11;
        let payee_pubkey = invoice.payee_pubkey;
        let last_update = invoice.last_updated;

        PaymentInfo {
            preimage,
            secret,
            status,
            amt_msat,
            fee_paid_msat,
            bolt11,
            payee_pubkey,
            privacy_level: invoice.privacy_level,
            last_update,
        }
    }
}

impl MutinyInvoice {
    pub(crate) fn from(
        i: PaymentInfo,
        payment_hash: PaymentHash,
        inbound: bool,
        labels: Vec<String>,
    ) -> Result<Self, MutinyError> {
        match i.bolt11 {
            Some(invoice) => {
                // Construct an invoice from a bolt11, easy
                let amount_sats = if let Some(inv_amt) = invoice.amount_milli_satoshis() {
                    if inv_amt == 0 {
                        i.amt_msat.0.map(|a| a / 1_000)
                    } else {
                        Some(inv_amt / 1_000)
                    }
                } else {
                    i.amt_msat.0.map(|a| a / 1_000)
                };
                Ok(MutinyInvoice {
                    inbound,
                    last_updated: i.last_update,
                    status: i.status,
                    labels,
                    amount_sats,
                    payee_pubkey: i.payee_pubkey,
                    preimage: i.preimage.map(|p| p.to_lower_hex_string()),
                    fees_paid: i.fee_paid_msat.map(|f| f / 1_000),
                    privacy_level: i.privacy_level,
                    ..invoice.into()
                })
            }
            None => {
                let amount_sats: Option<u64> = i.amt_msat.0.map(|s| s / 1_000);
                let fees_paid = i.fee_paid_msat.map(|f| f / 1_000);
                let preimage = i.preimage.map(|p| p.to_lower_hex_string());
                let payment_hash = sha256::Hash::from_byte_array(payment_hash.0);
                let invoice = MutinyInvoice {
                    bolt11: None,
                    description: None,
                    payment_hash,
                    preimage,
                    payee_pubkey: i.payee_pubkey,
                    amount_sats,
                    expire: i.last_update,
                    status: i.status,
                    privacy_level: i.privacy_level,
                    fees_paid,
                    inbound,
                    labels,
                    last_updated: i.last_update,
                };
                Ok(invoice)
            }
        }
    }
}

/// FedimintSweepResult is the result of how much was swept and the fees paid.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FedimintSweepResult {
    /// The final amount that was swept.
    /// This should be the amount specified if it was not max.
    pub amount: u64,

    /// The total fees paid for the sweep.
    pub fees: Option<u64>,
}

pub struct MutinyWalletConfigBuilder {
    // xprivkey: ExtendedPrivKey,
    #[cfg(target_arch = "wasm32")]
    websocket_proxy_addr: Option<String>,
    network: Option<Network>,
    user_esplora_url: Option<String>,
    user_rgs_url: Option<String>,
    lsp_url: Option<String>,
    lsp_connection_string: Option<String>,
    lsp_token: Option<String>,
    auth_client: Option<Arc<MutinyAuthClient>>,
    subscription_url: Option<String>,
    scorer_url: Option<String>,
    blind_auth_url: Option<String>,
    hermes_url: Option<String>,
    do_not_connect_peers: bool,
    skip_device_lock: bool,
    pub safe_mode: bool,
    skip_hodl_invoices: bool,
}

impl MutinyWalletConfigBuilder {
    pub fn new(_xprivkey: ExtendedPrivKey) -> MutinyWalletConfigBuilder {
        MutinyWalletConfigBuilder {
            // xprivkey,
            #[cfg(target_arch = "wasm32")]
            websocket_proxy_addr: None,
            network: None,
            user_esplora_url: None,
            user_rgs_url: None,
            lsp_url: None,
            lsp_connection_string: None,
            lsp_token: None,
            auth_client: None,
            subscription_url: None,
            scorer_url: None,
            blind_auth_url: None,
            hermes_url: None,
            do_not_connect_peers: false,
            skip_device_lock: false,
            safe_mode: false,
            skip_hodl_invoices: true,
        }
    }

    /// Required
    pub fn with_network(mut self, network: Network) -> MutinyWalletConfigBuilder {
        self.network = Some(network);
        self
    }

    #[cfg(target_arch = "wasm32")]
    pub fn with_websocket_proxy_addr(&mut self, websocket_proxy_addr: String) {
        self.websocket_proxy_addr = Some(websocket_proxy_addr);
    }

    pub fn with_user_esplora_url(&mut self, user_esplora_url: String) {
        self.user_esplora_url = Some(user_esplora_url);
    }

    pub fn with_user_rgs_url(&mut self, user_rgs_url: String) {
        self.user_rgs_url = Some(user_rgs_url);
    }

    pub fn with_lsp_url(&mut self, lsp_url: String) {
        self.lsp_url = Some(lsp_url);
    }

    pub fn with_lsp_connection_string(&mut self, lsp_connection_string: String) {
        self.lsp_connection_string = Some(lsp_connection_string);
    }

    pub fn with_lsp_token(&mut self, lsp_token: String) {
        self.lsp_token = Some(lsp_token);
    }

    pub fn with_auth_client(&mut self, auth_client: Arc<MutinyAuthClient>) {
        self.auth_client = Some(auth_client);
    }

    pub fn with_subscription_url(&mut self, subscription_url: String) {
        self.subscription_url = Some(subscription_url);
    }

    pub fn with_scorer_url(&mut self, scorer_url: String) {
        self.scorer_url = Some(scorer_url);
    }

    pub fn with_blind_auth_url(&mut self, blind_auth_url: String) {
        self.blind_auth_url = Some(blind_auth_url);
    }

    pub fn with_hermes_url(&mut self, hermes_url: String) {
        self.hermes_url = Some(hermes_url);
    }

    pub fn do_not_connect_peers(&mut self) {
        self.do_not_connect_peers = true;
    }

    pub fn with_skip_device_lock(&mut self) {
        self.skip_device_lock = true;
    }

    pub fn with_safe_mode(&mut self) {
        self.safe_mode = true;
        self.skip_device_lock = true;
    }

    pub fn do_not_skip_hodl_invoices(&mut self) {
        self.skip_hodl_invoices = false;
    }

    pub fn build(self) -> MutinyWalletConfig {
        let network = self.network.expect("network is required");

        MutinyWalletConfig {
            // xprivkey: self.xprivkey,
            #[cfg(target_arch = "wasm32")]
            websocket_proxy_addr: self.websocket_proxy_addr,
            network,
            user_esplora_url: self.user_esplora_url,
            user_rgs_url: self.user_rgs_url,
            lsp_url: self.lsp_url,
            lsp_connection_string: self.lsp_connection_string,
            lsp_token: self.lsp_token,
            auth_client: self.auth_client,
            subscription_url: self.subscription_url,
            scorer_url: self.scorer_url,
            blind_auth_url: self.blind_auth_url,
            hermes_url: self.hermes_url,
            do_not_connect_peers: self.do_not_connect_peers,
            skip_device_lock: self.skip_device_lock,
            safe_mode: self.safe_mode,
            skip_hodl_invoices: self.skip_hodl_invoices,
        }
    }
}

#[derive(Clone)]
pub struct MutinyWalletConfig {
    // xprivkey: ExtendedPrivKey,
    #[cfg(target_arch = "wasm32")]
    websocket_proxy_addr: Option<String>,
    network: Network,
    user_esplora_url: Option<String>,
    user_rgs_url: Option<String>,
    lsp_url: Option<String>,
    lsp_connection_string: Option<String>,
    lsp_token: Option<String>,
    auth_client: Option<Arc<MutinyAuthClient>>,
    subscription_url: Option<String>,
    scorer_url: Option<String>,
    blind_auth_url: Option<String>,
    hermes_url: Option<String>,
    do_not_connect_peers: bool,
    skip_device_lock: bool,
    pub safe_mode: bool,
    skip_hodl_invoices: bool,
}

pub struct MutinyWalletBuilder<S: MutinyStorage> {
    xprivkey: ExtendedPrivKey,
    storage: S,
    config: Option<MutinyWalletConfig>,
    session_id: Option<String>,
    network: Option<Network>,
    auth_client: Option<Arc<MutinyAuthClient>>,
    blind_auth_url: Option<String>,
    hermes_url: Option<String>,
    subscription_url: Option<String>,
    do_not_connect_peers: bool,
    skip_hodl_invoices: bool,
    skip_device_lock: bool,
    safe_mode: bool,
}

impl<S: MutinyStorage> MutinyWalletBuilder<S> {
    pub fn new(xprivkey: ExtendedPrivKey, storage: S) -> MutinyWalletBuilder<S> {
        MutinyWalletBuilder::<S> {
            xprivkey,
            storage,
            config: None,
            session_id: None,
            network: None,
            auth_client: None,
            subscription_url: None,
            blind_auth_url: None,
            hermes_url: None,
            do_not_connect_peers: false,
            skip_device_lock: false,
            safe_mode: false,
            skip_hodl_invoices: true,
        }
    }

    pub fn with_config(mut self, config: MutinyWalletConfig) -> MutinyWalletBuilder<S> {
        self.network = Some(config.network);
        self.do_not_connect_peers = config.do_not_connect_peers;
        self.skip_hodl_invoices = config.skip_hodl_invoices;
        self.skip_device_lock = config.skip_device_lock;
        self.safe_mode = config.safe_mode;
        self.auth_client = config.auth_client.clone();
        self.subscription_url = config.subscription_url.clone();
        self.blind_auth_url = config.blind_auth_url.clone();
        self.hermes_url = config.hermes_url.clone();
        self.config = Some(config);
        self
    }

    pub fn with_session_id(&mut self, session_id: String) {
        self.session_id = Some(session_id);
    }

    pub fn with_network(&mut self, network: Network) {
        self.network = Some(network);
    }

    pub fn with_auth_client(&mut self, auth_client: Arc<MutinyAuthClient>) {
        self.auth_client = Some(auth_client);
    }

    pub fn with_subscription_url(&mut self, subscription_url: String) {
        self.subscription_url = Some(subscription_url);
    }

    pub fn with_blind_auth_url(&mut self, blind_auth_url: String) {
        self.blind_auth_url = Some(blind_auth_url);
    }

    pub fn with_hermes_url(&mut self, hermes_url: String) {
        self.hermes_url = Some(hermes_url);
    }

    pub fn do_not_connect_peers(&mut self) {
        self.do_not_connect_peers = true;
    }

    pub fn do_not_skip_hodl_invoices(&mut self) {
        self.skip_hodl_invoices = false;
    }

    pub fn with_skip_device_lock(&mut self) {
        self.skip_device_lock = true;
    }

    pub fn with_safe_mode(&mut self) {
        self.safe_mode = true;
        self.skip_device_lock = true;
    }

    pub async fn build(self) -> Result<MutinyWallet<S>, MutinyError> {
        let network = self
            .network
            .map_or_else(|| Err(MutinyError::InvalidArgumentsError), Ok)?;
        let config = self.config.unwrap_or(
            MutinyWalletConfigBuilder::new(self.xprivkey)
                .with_network(network)
                .build(),
        );

        let expected_network = self.storage.get::<Network>(EXPECTED_NETWORK_KEY)?;
        match expected_network {
            Some(n) => {
                if n != network {
                    return Err(MutinyError::NetworkMismatch);
                }
            }
            None => self
                .storage
                .set_data(EXPECTED_NETWORK_KEY.to_string(), self.network, None)?,
        }

        let stop = Arc::new(AtomicBool::new(false));
        let logger = Arc::new(MutinyLogger::with_writer(
            stop.clone(),
            self.storage.clone(),
            self.session_id,
        ));

        // Need to prevent other devices from running at the same time
        log_trace!(logger, "checking device lock");
        if !config.skip_device_lock {
            let start = Instant::now();
            log_trace!(logger, "Checking device lock");
            if let Some(lock) = self.storage.get_device_lock()? {
                log_info!(logger, "Current device lock: {lock:?}");
            }
            self.storage.set_device_lock().await?;
            log_trace!(
                logger,
                "Device lock set: took {}ms",
                start.elapsed().as_millis()
            );
        }
        log_trace!(logger, "finished checking device lock");

        // spawn thread to claim device lock
        log_trace!(logger, "spawning claim device lock");
        let storage_clone = self.storage.clone();
        let logger_clone = logger.clone();
        let stop_clone = stop.clone();
        spawn(async move {
            loop {
                if stop_clone.load(Ordering::Relaxed) {
                    if let Err(e) = storage_clone.release_device_lock().await {
                        log_error!(logger_clone, "Error releasing device lock: {e}");
                    }
                    break;
                }
                sleep((DEVICE_LOCK_INTERVAL_SECS * 1_000) as i32).await;
                if let Err(e) = storage_clone.set_device_lock().await {
                    log_error!(logger_clone, "Error setting device lock: {e}");
                }
            }
        });
        log_trace!(logger, "finished spawning claim device lock");

        log_trace!(logger, "setting up esplora");
        let esplora_server_url = get_esplora_url(network, config.user_esplora_url.clone());
        let esplora = esplora_client::Builder::new(&esplora_server_url).build_async()?;
        let esplora = Arc::new(esplora);
        log_trace!(logger, "finished setting up esplora");

        log_trace!(logger, "setting up node manager");
        let start = Instant::now();
        let mut nm_builder = NodeManagerBuilder::new(self.xprivkey, self.storage.clone())
            .with_config(config.clone());
        nm_builder.with_logger(logger.clone());
        nm_builder.with_esplora(esplora.clone());
        let node_manager = Arc::new(nm_builder.build().await?);

        log_trace!(
            logger,
            "NodeManager started, took: {}ms",
            start.elapsed().as_millis()
        );

        // start syncing node manager
        log_trace!(logger, "starting node manager sync");
        NodeManager::start_sync(node_manager.clone());
        log_trace!(logger, "finished node manager sync");

        if !self.skip_hodl_invoices {
            log_warn!(
                logger,
                "Starting with HODL invoices enabled. This is not recommended!"
            );
        }

        let start = Instant::now();

        log_trace!(logger, "creating lnurl client");
        let lnurl_client = Arc::new(
            lnurl::Builder::default()
                .build_async()
                .expect("failed to make lnurl client"),
        );
        log_trace!(logger, "finished creating lnurl client");

        // auth manager, take from auth_client if it already exists
        log_trace!(logger, "creating auth manager");
        let auth = if let Some(auth_client) = self.auth_client.clone() {
            auth_client.auth.clone()
        } else {
            AuthManager::new(self.xprivkey)?
        };
        log_trace!(logger, "finished creating auth manager");

        // populate the activity index
        log_trace!(logger, "populating activity index");
        let mut activity_index = node_manager
            .wallet
            .list_transactions(false)?
            .into_iter()
            .map(|t| IndexItem {
                timestamp: match t.confirmation_time {
                    ConfirmationTime::Confirmed { time, .. } => Some(time),
                    ConfirmationTime::Unconfirmed { .. } => None,
                },
                key: format!("{ONCHAIN_PREFIX}{}", t.internal_id),
            })
            .collect::<Vec<_>>();

        // add any transaction details stored from fedimint
        let transaction_details = self
            .storage
            .scan::<TransactionDetails>(TRANSACTION_DETAILS_PREFIX_KEY, None)?
            .into_iter()
            .map(|(k, v)| {
                let timestamp = match v.confirmation_time {
                    ConfirmationTime::Confirmed { height: _, time } => Some(time), // confirmed timestamp
                    ConfirmationTime::Unconfirmed { .. } => None, // unconfirmed timestamp
                };
                IndexItem { timestamp, key: k }
            })
            .collect::<Vec<_>>();
        activity_index.extend(transaction_details);

        // add the channel closures to the activity index
        let closures = self
            .storage
            .scan::<ChannelClosure>(CHANNEL_CLOSURE_PREFIX, None)?
            .into_iter()
            .map(|(k, v)| IndexItem {
                timestamp: Some(v.timestamp),
                key: k,
            })
            .collect::<Vec<_>>();
        activity_index.extend(closures);

        // add inbound invoices to the activity index
        let inbound = self
            .storage
            .scan::<PaymentInfo>(PAYMENT_INBOUND_PREFIX_KEY, None)?
            .into_iter()
            .filter(|(_, p)| matches!(p.status, HTLCStatus::Succeeded | HTLCStatus::InFlight))
            .map(|(k, v)| IndexItem {
                timestamp: Some(v.last_update),
                key: k,
            })
            .collect::<Vec<_>>();

        let outbound = self
            .storage
            .scan::<PaymentInfo>(PAYMENT_OUTBOUND_PREFIX_KEY, None)?
            .into_iter()
            .filter(|(_, p)| matches!(p.status, HTLCStatus::Succeeded | HTLCStatus::InFlight))
            .map(|(k, v)| IndexItem {
                timestamp: Some(v.last_update),
                key: k,
            })
            .collect::<Vec<_>>();

        activity_index.extend(inbound);
        activity_index.extend(outbound);

        // add the activity index to the storage
        {
            let index = self.storage.activity_index();
            let mut read = index.try_write()?;
            read.extend(activity_index);
        }
        log_trace!(logger, "finished populating activity index");

        log_trace!(logger, "creating price cache");
        let price_cache = self
            .storage
            .get_bitcoin_price_cache()?
            .into_iter()
            .map(|(k, v)| (k, (v, Duration::from_secs(0))))
            .collect();
        log_trace!(logger, "finished creating price cache");

        log_trace!(logger, "creating mutiny wallet");
        let mw = MutinyWallet {
            xprivkey: self.xprivkey,
            config,
            storage: self.storage,
            node_manager,
            lnurl_client,
            // esplora,
            auth,
            stop,
            logger: logger.clone(),
            network,
            skip_hodl_invoices: self.skip_hodl_invoices,
            safe_mode: self.safe_mode,
            bitcoin_price_cache: Arc::new(Mutex::new(price_cache)),
        };
        log_trace!(logger, "finished creating mutiny wallet");
        // if we are in safe mode, don't create any nodes or
        // start any nostr services
        if self.safe_mode {
            return Ok(mw);
        }

        // if we don't have any nodes, create one
        log_trace!(logger, "listing nodes");
        if mw.node_manager.list_nodes().await?.is_empty() {
            log_trace!(logger, "going to create first node");
            let nm = mw.node_manager.clone();
            // spawn in background, this can take a while and we don't want to block
            utils::spawn(async move {
                if let Err(e) = nm.new_node().await {
                    log_error!(nm.logger, "Failed to create first node: {e}");
                }
            })
        };
        log_trace!(logger, "finished listing nodes");

        log_info!(
            mw.logger,
            "Final setup took {}ms",
            start.elapsed().as_millis()
        );

        Ok(mw)
    }
}

/// MutinyWallet is the main entry point for the library.
/// It contains the NodeManager, which is the main interface to manage the
/// bitcoin and the lightning functionality.
#[derive(Clone)]
pub struct MutinyWallet<S: MutinyStorage> {
    xprivkey: ExtendedPrivKey,
    config: MutinyWalletConfig,
    pub(crate) storage: S,
    pub node_manager: Arc<NodeManager<S>>,
    lnurl_client: Arc<LnUrlClient>,
    auth: AuthManager,
    // esplora: Arc<AsyncClient>,
    pub stop: Arc<AtomicBool>,
    pub logger: Arc<MutinyLogger>,
    network: Network,
    skip_hodl_invoices: bool,
    safe_mode: bool,
    bitcoin_price_cache: Arc<Mutex<HashMap<String, (f32, Duration)>>>,
}

impl<S: MutinyStorage> MutinyWallet<S> {
    /// Starts up all the nodes again.
    /// Not needed after [NodeManager]'s `new()` function.
    pub async fn start(&mut self) -> Result<(), MutinyError> {
        log_trace!(self.logger, "calling start");

        self.storage.start().await?;

        let mut nm_builder = NodeManagerBuilder::new(self.xprivkey, self.storage.clone())
            .with_config(self.config.clone());
        nm_builder.with_logger(self.logger.clone());

        // when we restart, gen a new session id
        self.node_manager = Arc::new(nm_builder.build().await?);
        NodeManager::start_sync(self.node_manager.clone());

        log_trace!(self.logger, "finished calling start");
        Ok(())
    }

    /// Pays a lightning invoice from a federation (preferred) or node.
    /// An amount should only be provided if the invoice does not have an amount.
    /// Amountless invoices cannot be paid by a federation.
    /// The amount should be in satoshis.
    pub async fn pay_invoice(
        &self,
        inv: &Bolt11Invoice,
        amt_sats: Option<u64>,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        log_trace!(self.logger, "calling pay_invoice");

        if inv.network() != self.network {
            return Err(MutinyError::IncorrectNetwork);
        }

        // check invoice is expired
        if inv.would_expire(utils::now()) {
            return Err(MutinyError::InvoiceExpired);
        }

        // Check the amount specified in the invoice, we need one to make the payment
        let _send_msat = inv
            .amount_milli_satoshis()
            .or(amt_sats.map(|x| x * 1_000))
            .ok_or(MutinyError::InvoiceInvalid)?;

        // set labels now, need to set it before in case the payment times out
        self.storage
            .set_invoice_labels(inv.clone(), labels.clone())?;

        // If any balance at all, then fallback to node manager for payment.
        // Take the error from the node manager as the priority.
        let res = if self
            .node_manager
            .nodes
            .read()
            .await
            .iter()
            .flat_map(|(_, n)| n.channel_manager.list_channels())
            .map(|c| c.balance_msat)
            .sum::<u64>()
            > 0
        {
            let res = self
                .node_manager
                .pay_invoice(None, inv, amt_sats, labels)
                .await?;

            Ok(res)
        } else {
            Err(MutinyError::InsufficientBalance)
        };
        log_trace!(self.logger, "finished calling pay_invoice");

        res
    }

    /// Estimates the lightning fee for a transaction. Amount is either from the invoice
    /// if one is available or a passed in amount (priority). It will try to predict either
    /// sending the payment through a federation or through lightning, depending on balances.
    /// The amount and fee is in satoshis.
    /// Returns None if it has no good way to calculate fee.
    pub async fn estimate_ln_fee(
        &self,
        inv: Option<&Bolt11Invoice>,
        amt_sats: Option<u64>,
    ) -> Result<Option<u64>, MutinyError> {
        log_trace!(self.logger, "calling estimate_ln_fee");

        let amt = amt_sats
            .or(inv
                .and_then(|i| i.amount_milli_satoshis())
                .map(|a| a / 1_000))
            .ok_or(MutinyError::BadAmountError)?;

        // check balances first
        let total_balances = self.get_balance().await?;

        if total_balances.lightning > amt {
            // TODO try something to try to get lightning fee
            return Ok(None);
        }

        Err(MutinyError::InsufficientBalance)
    }

    /// Creates a BIP 21 invoice. This creates a new address and a lightning invoice.
    /// The lightning invoice may return errors related to the LSP. Check the error and
    /// fallback to `get_new_address` and warn the user that Lightning is not available.
    ///
    /// Errors that might be returned include:
    ///
    /// - [`MutinyError::LspGenericError`]: This is returned for various reasons, including if a
    ///   request to the LSP server fails for any reason, or if the server returns
    ///   a status other than 500 that can't be parsed into a `ProposalResponse`.
    ///
    /// - [`MutinyError::LspFundingError`]: Returned if the LSP server returns an error with
    ///   a status of 500, indicating an "Internal Server Error", and a message
    ///   stating "Cannot fund new channel at this time". This means that the LSP cannot support
    ///   a new channel at this time.
    ///
    /// - [`MutinyError::LspAmountTooHighError`]: Returned if the LSP server returns an error with
    ///   a status of 500, indicating an "Internal Server Error", and a message stating "Invoice
    ///   amount is too high". This means that the LSP cannot support the amount that the user
    ///   requested. The user should request a smaller amount from the LSP.
    ///
    /// - [`MutinyError::LspConnectionError`]: Returned if the LSP server returns an error with
    ///   a status of 500, indicating an "Internal Server Error", and a message that starts with
    ///   "Failed to connect to peer". This means that the LSP is not connected to our node.
    ///
    /// If the server returns a status of 500 with a different error message,
    /// a [`MutinyError::LspGenericError`] is returned.
    pub async fn create_bip21(
        &self,
        amount: Option<u64>,
        labels: Vec<String>,
    ) -> Result<MutinyBip21RawMaterials, MutinyError> {
        log_trace!(self.logger, "calling create_bip21");

        let invoice = if self.safe_mode || amount.is_none() {
            None
        } else {
            Some(
                self.create_lightning_invoice(amount.expect("just checked"), labels.clone())
                    .await?
                    .bolt11
                    .ok_or(MutinyError::InvoiceCreationFailed)?,
            )
        };

        let Ok(address) = self.create_address(labels.clone()).await else {
            return Err(MutinyError::WalletOperationFailed);
        };
        log_trace!(self.logger, "finished calling create_bip21");

        Ok(MutinyBip21RawMaterials {
            address,
            invoice,
            btc_amount: amount.map(|amount| bitcoin::Amount::from_sat(amount).to_btc().to_string()),
            labels,
        })
    }

    pub async fn send_to_address(
        &self,
        send_to: Address,
        amount: u64,
        labels: Vec<String>,
        fee_rate: Option<f32>,
    ) -> Result<Txid, MutinyError> {
        log_trace!(self.logger, "calling send_to_address");

        // If any balance at all, then fallback to node manager for payment.
        // Take the error from the node manager as the priority.
        let b = self.node_manager.get_balance().await?;
        let res = if b.confirmed + b.unconfirmed > 0 {
            let res = self
                .node_manager
                .send_to_address(send_to, amount, labels, fee_rate)
                .await?;
            Ok(res)
        } else {
            Err(MutinyError::InsufficientBalance)
        };
        log_trace!(self.logger, "finished calling send_to_address");

        res
    }

    /// Estimates the onchain fee for a transaction sending to the given address.
    /// The amount is in satoshis and the fee rate is in sat/vbyte.
    pub async fn estimate_tx_fee(
        &self,
        destination_address: Address,
        amount: u64,
        fee_rate: Option<f32>,
    ) -> Result<u64, MutinyError> {
        log_trace!(self.logger, "calling estimate_tx_fee");

        if amount < DUST_LIMIT {
            return Err(MutinyError::WalletOperationFailed);
        }

        let b = self.node_manager.get_balance().await?;
        let res = if b.confirmed + b.unconfirmed > 0 {
            let res = self
                .node_manager
                .estimate_tx_fee(destination_address, amount, fee_rate)?;

            Ok(res)
        } else {
            Err(MutinyError::InsufficientBalance)
        };
        log_trace!(self.logger, "finished calling estimate_tx_fee");

        res
    }

    /// Sweeps all the funds from the wallet to the given address.
    /// The fee rate is in sat/vbyte.
    ///
    /// If a fee rate is not provided, one will be used from the fee estimator.
    pub async fn sweep_wallet(
        &self,
        send_to: Address,
        labels: Vec<String>,
        fee_rate: Option<f32>,
    ) -> Result<Txid, MutinyError> {
        log_trace!(self.logger, "calling sweep_wallet");

        let b = self.node_manager.get_balance().await?;
        let res = if b.confirmed + b.unconfirmed > 0 {
            let res = self
                .node_manager
                .sweep_wallet(send_to.clone(), labels, fee_rate)
                .await?;

            Ok(res)
        } else {
            log_error!(self.logger, "node manager doesn't have a balance");
            Err(MutinyError::InsufficientBalance)
        };
        log_trace!(self.logger, "finished calling sweep_wallet");

        res
    }

    pub async fn create_address(
        &self,
        labels: Vec<String>,
    ) -> Result<bitcoin::Address, MutinyError> {
        log_trace!(self.logger, "calling create_address");

        // Fallback to node_manager address creation
        let Ok(addr) = self.node_manager.get_new_address(labels.clone()) else {
            return Err(MutinyError::WalletOperationFailed);
        };

        log_trace!(self.logger, "finished calling create_address");
        Ok(addr)
    }

    async fn create_lightning_invoice(
        &self,
        amount: u64,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        log_trace!(self.logger, "calling create_lightning_invoice");

        let (inv, _fee) = self.node_manager.create_invoice(amount, labels).await?;

        log_trace!(self.logger, "finished calling create_lightning_invoice");
        Ok(inv)
    }

    /// Gets the current balance of the wallet.
    /// This includes both on-chain, lightning funds, and federations.
    ///
    /// This will not include any funds in an unconfirmed lightning channel.
    pub async fn get_balance(&self) -> Result<MutinyBalance, MutinyError> {
        log_trace!(self.logger, "calling get_balance");

        let ln_balance = self.node_manager.get_balance().await?;

        Ok(MutinyBalance::new(ln_balance))
    }

    fn get_invoice_internal(
        &self,
        key: &str,
        inbound: bool,
        labels_map: &HashMap<Bolt11Invoice, Vec<String>>,
    ) -> Result<Option<MutinyInvoice>, MutinyError> {
        if let Some(info) = self.storage.get_data::<PaymentInfo>(key)? {
            let labels = match info.bolt11.clone() {
                None => vec![],
                Some(i) => labels_map.get(&i).cloned().unwrap_or_default(),
            };
            let prefix = match inbound {
                true => PAYMENT_INBOUND_PREFIX_KEY,
                false => PAYMENT_OUTBOUND_PREFIX_KEY,
            };
            let payment_hash_str = get_payment_hash_from_key(key, prefix);
            let hash: [u8; 32] = FromHex::from_hex(payment_hash_str)?;

            return MutinyInvoice::from(info, PaymentHash(hash), inbound, labels).map(Some);
        };

        Ok(None)
    }

    /// Get the sorted activity list for lightning payments, channels, and txs.
    pub fn get_activity(
        &self,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<Vec<ActivityItem>, MutinyError> {
        log_trace!(self.logger, "calling get_activity");

        let index = {
            let index = self.storage.activity_index();
            let vec = index.try_read()?.clone().into_iter().collect_vec();

            let (start, end) = match (offset, limit) {
                (None, None) => (0, vec.len()),
                (Some(offset), Some(limit)) => {
                    let end = offset.saturating_add(limit).min(vec.len());
                    (offset, end)
                }
                (Some(offset), None) => (offset, vec.len()),
                (None, Some(limit)) => (0, limit),
            };

            // handle out of bounds
            let start = start.min(vec.len());
            let end = end.min(vec.len());

            // handle start > end
            if start > end {
                return Ok(vec![]);
            }

            vec[start..end].to_vec()
        };

        let labels_map = self.storage.get_invoice_labels()?;

        let mut activities = Vec::with_capacity(index.len());
        for item in index {
            if item.key.starts_with(PAYMENT_INBOUND_PREFIX_KEY) {
                if let Some(mutiny_invoice) =
                    self.get_invoice_internal(&item.key, true, &labels_map)?
                {
                    activities.push(ActivityItem::Lightning(Box::new(mutiny_invoice)));
                }
            } else if item.key.starts_with(PAYMENT_OUTBOUND_PREFIX_KEY) {
                if let Some(mutiny_invoice) =
                    self.get_invoice_internal(&item.key, false, &labels_map)?
                {
                    activities.push(ActivityItem::Lightning(Box::new(mutiny_invoice)));
                }
            } else if item.key.starts_with(CHANNEL_CLOSURE_PREFIX) {
                if let Some(mut closure) = self.storage.get_data::<ChannelClosure>(&item.key)? {
                    if closure.user_channel_id.is_none() {
                        // convert keys to u128
                        let user_channel_id_str = item
                            .key
                            .trim_start_matches(CHANNEL_CLOSURE_PREFIX)
                            .splitn(2, '_') // Channel closures have `_{node_id}` at the end
                            .collect::<Vec<&str>>()[0];
                        let user_channel_id: [u8; 16] = FromHex::from_hex(user_channel_id_str)?;
                        closure.user_channel_id = Some(user_channel_id);
                    }
                    activities.push(ActivityItem::ChannelClosed(closure));
                }
            } else if item.key.starts_with(ONCHAIN_PREFIX) {
                // convert keys to txid
                let txid_str = item.key.trim_start_matches(ONCHAIN_PREFIX);
                let txid: Txid = Txid::from_str(txid_str)?;
                if let Some(tx_details) = self.node_manager.get_transaction(txid)? {
                    // make sure it is a relevant transaction
                    if tx_details.sent != 0 || tx_details.received != 0 {
                        activities.push(ActivityItem::OnChain(tx_details));
                    }
                }
            } else if item.key.starts_with(TRANSACTION_DETAILS_PREFIX_KEY) {
                // convert keys to internal transaction id
                let internal_id_str = item.key.trim_start_matches(TRANSACTION_DETAILS_PREFIX_KEY);
                let internal_id: Txid = Txid::from_str(internal_id_str)?;
                if let Some(tx_details) =
                    get_transaction_details(&self.storage, internal_id, &self.logger)
                {
                    // make sure it is a relevant transaction
                    if tx_details.sent != 0 || tx_details.received != 0 {
                        activities.push(ActivityItem::OnChain(tx_details));
                    }
                }
            }
        }
        log_trace!(self.logger, "finished calling get_activity");

        Ok(activities)
    }

    pub fn get_transaction(&self, txid: Txid) -> Result<Option<TransactionDetails>, MutinyError> {
        log_trace!(self.logger, "calling get_transaction");

        // check our local cache/state for fedimint first
        let res = match get_transaction_details(&self.storage, txid, &self.logger) {
            Some(t) => Ok(Some(t)),
            None => {
                // fall back to node manager
                self.node_manager.get_transaction(txid)
            }
        };
        log_trace!(self.logger, "finished calling get_transaction");

        res
    }

    /// Returns all the lightning activity for a given label
    pub async fn get_label_activity(
        &self,
        label: &String,
    ) -> Result<Vec<ActivityItem>, MutinyError> {
        log_trace!(self.logger, "calling get_label_activity");

        let Some(label_item) = self.node_manager.get_label(label)? else {
            return Ok(Vec::new());
        };

        // get all the payment hashes for this label
        let payment_hashes: HashSet<sha256::Hash> = label_item
            .invoices
            .into_iter()
            .map(|i| *i.payment_hash())
            .collect();

        let index = self.storage.activity_index();
        let index = index.try_read()?.clone().into_iter().collect_vec();

        let labels_map = self.storage.get_invoice_labels()?;

        let mut activities = Vec::with_capacity(index.len());
        for item in index {
            if item.key.starts_with(PAYMENT_INBOUND_PREFIX_KEY) {
                let payment_hash_str =
                    get_payment_hash_from_key(&item.key, PAYMENT_INBOUND_PREFIX_KEY);
                let hash = sha256::Hash::from_str(payment_hash_str)?;

                if payment_hashes.contains(&hash) {
                    if let Some(mutiny_invoice) =
                        self.get_invoice_internal(&item.key, true, &labels_map)?
                    {
                        activities.push(ActivityItem::Lightning(Box::new(mutiny_invoice)));
                    }
                }
            } else if item.key.starts_with(PAYMENT_OUTBOUND_PREFIX_KEY) {
                let payment_hash_str =
                    get_payment_hash_from_key(&item.key, PAYMENT_OUTBOUND_PREFIX_KEY);
                let hash = sha256::Hash::from_str(payment_hash_str)?;

                if payment_hashes.contains(&hash) {
                    if let Some(mutiny_invoice) =
                        self.get_invoice_internal(&item.key, false, &labels_map)?
                    {
                        activities.push(ActivityItem::Lightning(Box::new(mutiny_invoice)));
                    }
                }
            }
        }
        log_trace!(self.logger, "finished calling get_label_activity");

        Ok(activities)
    }

    pub fn list_invoices(&self) -> Result<Vec<MutinyInvoice>, MutinyError> {
        log_trace!(self.logger, "calling list_invoices");

        let mut inbound_invoices = self.list_payment_info_from_persisters(true)?;
        let mut outbound_invoices = self.list_payment_info_from_persisters(false)?;
        inbound_invoices.append(&mut outbound_invoices);
        log_trace!(self.logger, "finished calling list_invoices");

        Ok(inbound_invoices)
    }

    fn list_payment_info_from_persisters(
        &self,
        inbound: bool,
    ) -> Result<Vec<MutinyInvoice>, MutinyError> {
        let now = utils::now();
        let labels_map = self.storage.get_invoice_labels()?;

        Ok(list_payment_info(&self.storage, inbound)?
            .into_iter()
            .filter_map(|(h, i)| {
                let labels = match i.bolt11.clone() {
                    None => vec![],
                    Some(i) => labels_map.get(&i).cloned().unwrap_or_default(),
                };
                let mutiny_invoice = MutinyInvoice::from(i.clone(), h, inbound, labels).ok();

                // filter out expired invoices
                mutiny_invoice.filter(|invoice| {
                    !invoice.bolt11.as_ref().is_some_and(|b| b.would_expire(now))
                        || matches!(invoice.status, HTLCStatus::Succeeded | HTLCStatus::InFlight)
                })
            })
            .collect())
    }

    /// Gets an invoice.
    /// This includes sent and received invoices.
    pub async fn get_invoice(&self, invoice: &Bolt11Invoice) -> Result<MutinyInvoice, MutinyError> {
        log_trace!(self.logger, "calling get_invoice");

        let res = self.get_invoice_by_hash(invoice.payment_hash()).await;
        log_trace!(self.logger, "finished calling get_invoice");

        res
    }

    /// Looks up an invoice by hash.
    /// This includes sent and received invoices.
    pub async fn get_invoice_by_hash(
        &self,
        hash: &sha256::Hash,
    ) -> Result<MutinyInvoice, MutinyError> {
        log_trace!(self.logger, "calling get_invoice_by_hash");

        let res = get_invoice_by_hash(hash, &self.storage, &self.logger);
        log_trace!(self.logger, "finished calling get_invoice_by_hash");

        res
    }

    /// Stops all of the nodes and background processes.
    /// Returns after node has been stopped.
    pub async fn stop(&self) -> Result<(), MutinyError> {
        log_trace!(self.logger, "calling stop");

        self.stop.store(true, Ordering::Relaxed);

        self.node_manager.stop().await?;

        // stop the indexeddb object to close db connection
        if self.storage.connected().unwrap_or(false) {
            log_debug!(self.logger, "stopping storage");
            self.storage.stop();
            log_debug!(self.logger, "stopped storage");
        }

        log_trace!(self.logger, "finished calling stop");
        Ok(())
    }

    pub async fn change_password(
        &mut self,
        old: Option<String>,
        new: Option<String>,
    ) -> Result<(), MutinyError> {
        log_trace!(self.logger, "calling change_password");

        // check if old password is correct
        if old != self.storage.password().map(|s| s.to_owned()) {
            return Err(MutinyError::IncorrectPassword);
        }

        if old == new {
            return Err(MutinyError::SamePassword);
        }

        log_info!(self.logger, "Changing password");

        self.stop().await?;

        self.storage.start().await?;

        self.storage.change_password_and_rewrite_storage(
            old.filter(|s| !s.is_empty()),
            new.filter(|s| !s.is_empty()),
        )?;

        // There's not a good way to check that all the indexeddb
        // data is saved in the background. This should get better
        // once we have async saving, but for now just make sure
        // the user has saved their seed already.
        sleep(5_000).await;

        log_trace!(self.logger, "finished calling change_password");
        Ok(())
    }

    /// Resets BDK's keychain tracker. This will require a re-sync of the blockchain.
    ///
    /// This can be useful if you get stuck in a bad state.
    pub async fn reset_onchain_tracker(&mut self) -> Result<(), MutinyError> {
        log_trace!(self.logger, "calling reset_onchain_tracker");

        self.node_manager.reset_onchain_tracker().await?;
        // sleep for 250ms to give time for the storage to write
        utils::sleep(250).await;

        self.stop().await?;

        // sleep for 250ms to give time for the node manager to stop
        utils::sleep(250).await;

        self.start().await?;

        self.node_manager
            .wallet
            .full_sync(FULL_SYNC_STOP_GAP)
            .await?;

        log_trace!(self.logger, "finished calling reset_onchain_tracker");
        Ok(())
    }

    /// Deletes all the storage
    pub async fn delete_all(&self) -> Result<(), MutinyError> {
        log_trace!(self.logger, "calling delete_all");

        self.storage.delete_all().await?;
        log_trace!(self.logger, "finished calling delete_all");

        Ok(())
    }

    /// Restores the mnemonic after deleting the previous state.
    ///
    /// Backup the state beforehand. Does not restore lightning data.
    /// Should refresh or restart afterwards. Wallet should be stopped.
    pub async fn restore_mnemonic(mut storage: S, m: Mnemonic) -> Result<(), MutinyError> {
        // Delete our storage but insert some device specific data
        let device_id = storage.get_device_id()?;
        let logs: Option<Vec<String>> = storage.get_data(LOGGING_KEY)?;
        storage.stop();
        S::clear().await?;
        storage.start().await?;
        storage.insert_mnemonic(m)?;
        storage.set_data(NEED_FULL_SYNC_KEY.to_string(), true, None)?;
        storage.set_data(DEVICE_ID_KEY.to_string(), device_id, None)?;
        storage.set_data(LOGGING_KEY.to_string(), logs, None)?;

        Ok(())
    }

    /// Decodes a lightning invoice into useful information.
    /// Will return an error if the invoice is for a different network.
    pub fn decode_invoice(
        &self,
        invoice: Bolt11Invoice,
        network: Option<Network>,
    ) -> Result<MutinyInvoice, MutinyError> {
        log_trace!(self.logger, "calling decode_invoice");

        if invoice.network() != network.unwrap_or(self.network) {
            return Err(MutinyError::IncorrectNetwork);
        }

        let res = invoice.into();
        log_trace!(self.logger, "finished calling decode_invoice");

        Ok(res)
    }

    /// Calls upon a LNURL to get the parameters for it.
    /// This contains what kind of LNURL it is (pay, withdrawal, auth, etc).
    // todo revamp LnUrlParams to be well designed
    pub async fn decode_lnurl(&self, lnurl: LnUrl) -> Result<LnUrlParams, MutinyError> {
        log_trace!(self.logger, "calling decode_lnurl");

        // handle LNURL-AUTH
        if lnurl.is_lnurl_auth() {
            return Ok(LnUrlParams {
                max: 0,
                min: 0,
                tag: "login".to_string(),
            });
        }

        let response = self.lnurl_client.make_request(&lnurl.url).await?;

        let params = match response {
            LnUrlResponse::LnUrlPayResponse(pay) => LnUrlParams {
                max: pay.max_sendable,
                min: pay.min_sendable,
                tag: "payRequest".to_string(),
            },
            LnUrlResponse::LnUrlChannelResponse(_chan) => LnUrlParams {
                max: 0,
                min: 0,
                tag: "channelRequest".to_string(),
            },
            LnUrlResponse::LnUrlWithdrawResponse(withdraw) => LnUrlParams {
                max: withdraw.max_withdrawable,
                min: withdraw.min_withdrawable.unwrap_or(0),
                tag: "withdrawRequest".to_string(),
            },
        };

        log_trace!(self.logger, "finished calling decode_lnurl");
        Ok(params)
    }

    /// Calls upon a LNURL and pays it.
    /// This will fail if the LNURL is not a LNURL pay.
    pub async fn lnurl_pay(
        &self,
        lnurl: &LnUrl,
        amount_sats: u64,
        mut labels: Vec<String>,
        comment: Option<String>,
        privacy_level: PrivacyLevel,
    ) -> Result<MutinyInvoice, MutinyError> {
        log_trace!(self.logger, "calling lnurl_pay");

        let response = self.lnurl_client.make_request(&lnurl.url).await?;

        let res = match response {
            LnUrlResponse::LnUrlPayResponse(pay) => {
                let msats = amount_sats * 1000;

                let invoice = self
                    .lnurl_client
                    .get_invoice(&pay, msats, None, comment.as_deref())
                    .await?;

                let invoice = Bolt11Invoice::from_str(invoice.invoice())?;

                if invoice
                    .amount_milli_satoshis()
                    .is_some_and(|amt| msats == amt)
                {
                    // If we don't have any labels, see if this matches a contact
                    if labels.is_empty() {
                        if let Some(label) = self.storage.get_contact_for_lnurl(lnurl)? {
                            labels.insert(0, label)
                        }
                    }

                    let mut inv = self.pay_invoice(&invoice, None, labels).await?;
                    // save privacy level to storage, can skip if its the default privacy level
                    if privacy_level != PrivacyLevel::default() {
                        inv.privacy_level = privacy_level;
                        let hash = inv.payment_hash.into_32();
                        log_debug!(
                            self.logger,
                            "Saving updated payment: {} {}",
                            hash.to_lower_hex_string(),
                            inv.last_updated
                        );
                        persist_payment_info(&self.storage, &hash, &inv.clone().into(), false)?;
                    }
                    Ok(inv)
                } else {
                    log_error!(self.logger, "LNURL return invoice with incorrect amount");
                    Err(MutinyError::LnUrlFailure)
                }
            }
            LnUrlResponse::LnUrlWithdrawResponse(_) => Err(MutinyError::IncorrectLnUrlFunction),
            LnUrlResponse::LnUrlChannelResponse(_) => Err(MutinyError::IncorrectLnUrlFunction),
        };
        log_trace!(self.logger, "finished calling lnurl_pay");

        res
    }

    /// Calls upon a LNURL and withdraws from it.
    /// This will fail if the LNURL is not a LNURL withdrawal.
    pub async fn lnurl_withdraw(
        &self,
        lnurl: &LnUrl,
        amount_sats: u64,
    ) -> Result<bool, MutinyError> {
        log_trace!(self.logger, "calling lnurl_withdraw");

        let response = self.lnurl_client.make_request(&lnurl.url).await?;

        let res = match response {
            LnUrlResponse::LnUrlPayResponse(_) => Err(MutinyError::IncorrectLnUrlFunction),
            LnUrlResponse::LnUrlChannelResponse(_) => Err(MutinyError::IncorrectLnUrlFunction),
            LnUrlResponse::LnUrlWithdrawResponse(withdraw) => {
                // fixme: do we need to use this description?
                let _description = withdraw.default_description.clone();
                let mutiny_invoice = self
                    .create_invoice(amount_sats, vec!["LNURL Withdrawal".to_string()])
                    .await?;
                let invoice_str = mutiny_invoice.bolt11.expect("Invoice should have bolt11");
                let res = self
                    .lnurl_client
                    .do_withdrawal(&withdraw, &invoice_str.to_string())
                    .await?;
                match res {
                    Response::Ok { .. } => Ok(true),
                    Response::Error { .. } => Ok(false),
                }
            }
        };
        log_trace!(self.logger, "finished calling lnurl_withdraw");

        res
    }

    /// Authenticate with a LNURL-auth
    pub async fn lnurl_auth(&self, lnurl: LnUrl) -> Result<(), MutinyError> {
        log_trace!(self.logger, "calling lnurl_auth");

        let res = make_lnurl_auth_connection(
            self.auth.clone(),
            self.lnurl_client.clone(),
            lnurl,
            self.logger.clone(),
        )
        .await;
        log_trace!(self.logger, "finished calling lnurl_auth");

        res
    }

    pub fn is_safe_mode(&self) -> bool {
        self.safe_mode
    }

    // FIXME
    pub async fn check_available_lnurl_name(&self, _name: String) -> Result<bool, MutinyError> {
        Err(MutinyError::NotFound)
    }

    pub async fn reserve_lnurl_name(&self, _name: String) -> Result<(), MutinyError> {
        // log_trace!(self.logger, "calling reserve_lnurl_name");

        // let res = if let Some(hermes_client) = self.hermes_client.clone() {
        //     Ok(hermes_client.reserve_name(name).await?)
        // } else {
        //     Err(MutinyError::NotFound)
        // };
        // log_trace!(self.logger, "calling reserve_lnurl_name");

        // res
        Err(MutinyError::NotFound)
    }

    pub async fn check_lnurl_name(&self) -> Result<Option<String>, MutinyError> {
        // log_trace!(self.logger, "calling check_lnurl_name");

        // let res = if let Some(hermes_client) = self.hermes_client.as_ref() {
        //     hermes_client.check_username().await
        // } else {
        //     Err(MutinyError::NotFound)
        // };
        // log_trace!(self.logger, "finished calling check_lnurl_name");

        // res
        Err(MutinyError::NotFound)
    }

    /// Gets the current bitcoin price in USD.
    pub async fn get_bitcoin_price(&self, fiat: Option<String>) -> Result<f32, MutinyError> {
        log_trace!(self.logger, "calling get_bitcoin_price");

        let now = crate::utils::now();
        let fiat = fiat.unwrap_or("usd".to_string());

        let cache_result = {
            let cache = self.bitcoin_price_cache.lock().await;
            cache.get(&fiat).cloned()
        };

        let res = match cache_result {
            Some((price, timestamp)) if timestamp == Duration::from_secs(0) => {
                // Cache is from previous run, return it but fetch a new price in the background
                let cache = self.bitcoin_price_cache.clone();
                let storage = self.storage.clone();
                let logger = self.logger.clone();
                spawn(async move {
                    if let Err(e) =
                        Self::fetch_and_cache_price(fiat, now, cache, storage, logger.clone()).await
                    {
                        log_warn!(logger, "failed to fetch bitcoin price: {e:?}");
                    }
                });
                Ok(price)
            }
            Some((price, timestamp))
                if timestamp + Duration::from_secs(BITCOIN_PRICE_CACHE_SEC) > now =>
            {
                // Cache is not expired
                Ok(price)
            }
            _ => {
                // Cache is either expired, empty, or doesn't have the desired fiat value
                Self::fetch_and_cache_price(
                    fiat,
                    now,
                    self.bitcoin_price_cache.clone(),
                    self.storage.clone(),
                    self.logger.clone(),
                )
                .await
            }
        };
        log_trace!(self.logger, "finished calling get_bitcoin_price");

        res
    }

    async fn fetch_and_cache_price(
        fiat: String,
        now: Duration,
        bitcoin_price_cache: Arc<Mutex<HashMap<String, (f32, Duration)>>>,
        storage: S,
        logger: Arc<MutinyLogger>,
    ) -> Result<f32, MutinyError> {
        match Self::fetch_bitcoin_price(&fiat).await {
            Ok(new_price) => {
                let mut cache = bitcoin_price_cache.lock().await;
                let cache_entry = (new_price, now);
                cache.insert(fiat.clone(), cache_entry);

                // save to storage in the background
                let cache_clone = cache.clone();
                spawn(async move {
                    let cache = cache_clone
                        .into_iter()
                        .map(|(k, (price, _))| (k, price))
                        .collect();

                    if let Err(e) = storage.insert_bitcoin_price_cache(cache) {
                        log_error!(logger, "failed to save bitcoin price cache: {e:?}");
                    }
                });

                Ok(new_price)
            }
            Err(e) => {
                // If fetching price fails, return the cached price (if any)
                let cache = bitcoin_price_cache.lock().await;
                if let Some((price, _)) = cache.get(&fiat) {
                    log_warn!(logger, "price api failed, returning cached price");
                    Ok(*price)
                } else {
                    // If there is no cached price, return the error
                    log_error!(logger, "no cached price and price api failed for {fiat}");
                    Err(e)
                }
            }
        }
    }

    async fn fetch_bitcoin_price(fiat: &str) -> Result<f32, MutinyError> {
        let api_url = format!("https://price.mutinywallet.com/price/{fiat}");

        let client = reqwest::Client::builder()
            .build()
            .map_err(|_| MutinyError::BitcoinPriceError)?;

        let request = client
            .get(api_url)
            .build()
            .map_err(|_| MutinyError::BitcoinPriceError)?;

        let resp: reqwest::Response = utils::fetch_with_timeout(&client, request).await?;

        let response: BitcoinPriceResponse = resp
            .error_for_status()
            .map_err(|_| MutinyError::BitcoinPriceError)?
            .json()
            .await
            .map_err(|_| MutinyError::BitcoinPriceError)?;

        Ok(response.price)
    }

    /// Returns the network of the wallet.
    pub fn get_network(&self) -> Network {
        self.network
    }
}

impl<S: MutinyStorage> InvoiceHandler for MutinyWallet<S> {
    fn logger(&self) -> &MutinyLogger {
        self.logger.as_ref()
    }

    fn skip_hodl_invoices(&self) -> bool {
        self.skip_hodl_invoices
    }

    fn get_network(&self) -> Network {
        self.network
    }

    async fn get_best_block(&self) -> Result<BestBlock, MutinyError> {
        let node = self.node_manager.get_node_by_key_or_first(None).await?;
        Ok(node.channel_manager.current_best_block())
    }

    async fn lookup_payment(&self, payment_hash: &[u8; 32]) -> Option<MutinyInvoice> {
        self.get_invoice_by_hash(&sha256::Hash::from_byte_array(*payment_hash))
            .await
            .ok()
    }

    async fn pay_invoice(
        &self,
        invoice: &Bolt11Invoice,
        amt_sats: Option<u64>,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        self.pay_invoice(invoice, amt_sats, labels).await
    }

    async fn create_invoice(
        &self,
        amount: u64,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        self.create_lightning_invoice(amount, labels).await
    }
}

//     esplora: Arc<AsyncClient>,
//     stop: Arc<AtomicBool>,

//             esplora.clone(),
//             c.network,
//             stop.clone(),
//             logger.clone(),
//             safe_mode,
//         )

//         esplora,
//         network,
//         stop.clone(),
//         logger.clone(),
//         safe_mode,
//     )

#[derive(Deserialize, Clone, Copy, Debug)]
struct BitcoinPriceResponse {
    pub price: f32,
}

// // max amount that can be spent through a gateway
// fn max_spendable_amount(current_balance_sat: u64, routing_fees: &GatewayFees) -> Option<u64> {
//     let current_balance_msat = current_balance_sat as f64 * 1_000.0;

//     // proportional fee on the current balance
//     let base_and_prop_fee_msat = calc_routing_fee_msat(current_balance_msat, routing_fees);

//     // The max balance considering the maximum possible proportional fee.
//     // This gives us a baseline to start checking the fees from. In the case that the fee is 1%
//     // The real maximum balance will be somewhere between our current balance and 99% of our
//     // balance.
//     let initial_max = current_balance_msat - base_and_prop_fee_msat;

//     // if the fee would make the amount go negative, then there is not a possible amount to spend
//     if initial_max <= 0.0 {
//         return None;
//     }

//     // if the initial balance and initial maximum is basically the same, then that's it
//     // this is basically only ever the case if there's not really any fee involved
//     if current_balance_msat - initial_max < 1.0 {
//         return Some((initial_max / 1_000.0).floor() as u64);
//     }

//     // keep trying until we hit our balance or find the max amount
//     let mut new_max = initial_max;
//     while new_max < current_balance_msat {
//         // we increment by one and check the fees for it
//         let new_check = new_max + 1.0;

//         // check the new spendable balance amount plus base fees plus new proportional fee
//         let new_amt = new_check + calc_routing_fee_msat(new_check, routing_fees);
//         if current_balance_msat - new_amt <= 0.0 {
//             // since we are incrementing from a minimum spendable amount,
//             // if we overshot our total balance then the last max is the highest
//             return Some((new_max / 1_000.0).floor() as u64);
//         }

//         // this is the new spendable maximum
//         new_max += 1.0;
//     }

//     Some((new_max / 1_000.0).floor() as u64)
// }

// fn calc_routing_fee_msat(amt_msat: f64, routing_fees: &GatewayFees) -> f64 {
//     let prop_fee_msat = (amt_msat * routing_fees.proportional_millionths as f64) / 1_000_000.0;
//     routing_fees.base_msat as f64 + prop_fee_msat
// }

// #[cfg(test)]
// fn max_routing_fee_amount() {
//     let initial_budget = 1;
//     let routing_fees = GatewayFees {
//         base_msat: 10_000,
//         proportional_millionths: 0,
//     };
//     assert_eq!(None, max_spendable_amount(initial_budget, &routing_fees));

//     // only a percentage fee
//     let initial_budget = 100;
//     let routing_fees = GatewayFees {
//         base_msat: 0,
//         proportional_millionths: 0,
//     };
//     assert_eq!(
//         Some(100),
//         max_spendable_amount(initial_budget, &routing_fees)
//     );

//     let initial_budget = 100;
//     let routing_fees = GatewayFees {
//         base_msat: 0,
//         proportional_millionths: 10_000,
//     };
//     assert_eq!(
//         Some(99),
//         max_spendable_amount(initial_budget, &routing_fees)
//     );

//     let initial_budget = 100;
//     let routing_fees = GatewayFees {
//         base_msat: 0,
//         proportional_millionths: 100_000,
//     };
//     assert_eq!(
//         Some(90),
//         max_spendable_amount(initial_budget, &routing_fees)
//     );

//     let initial_budget = 101_000;
//     let routing_fees = GatewayFees {
//         base_msat: 0,
//         proportional_millionths: 100_000,
//     };
//     assert_eq!(
//         Some(91_818),
//         max_spendable_amount(initial_budget, &routing_fees)
//     );

//     let initial_budget = 101;
//     let routing_fees = GatewayFees {
//         base_msat: 0,
//         proportional_millionths: 100_000,
//     };
//     assert_eq!(
//         Some(91),
//         max_spendable_amount(initial_budget, &routing_fees)
//     );

//     // same tests but with a base fee
//     let initial_budget = 100;
//     let routing_fees = GatewayFees {
//         base_msat: 1_000,
//         proportional_millionths: 0,
//     };
//     assert_eq!(
//         Some(99),
//         max_spendable_amount(initial_budget, &routing_fees)
//     );

//     let initial_budget = 100;
//     let routing_fees = GatewayFees {
//         base_msat: 1_000,
//         proportional_millionths: 10_000,
//     };
//     assert_eq!(
//         Some(98),
//         max_spendable_amount(initial_budget, &routing_fees)
//     );

//     let initial_budget = 100;
//     let routing_fees = GatewayFees {
//         base_msat: 1_000,
//         proportional_millionths: 100_000,
//     };
//     assert_eq!(
//         Some(89),
//         max_spendable_amount(initial_budget, &routing_fees)
//     );

//     let initial_budget = 101;
//     let routing_fees = GatewayFees {
//         base_msat: 1_000,
//         proportional_millionths: 100_000,
//     };
//     assert_eq!(
//         Some(90),
//         max_spendable_amount(initial_budget, &routing_fees)
//     );
// }

// #[cfg(test)]
// #[cfg(not(target_arch = "wasm32"))]
// mod tests {
//     use super::*;

// }

#[cfg(test)]
#[cfg(target_arch = "wasm32")]
mod tests {
    use crate::storage::{
        payment_key, persist_payment_info, IndexItem, MemoryStorage, MutinyStorage, ONCHAIN_PREFIX,
        PAYMENT_OUTBOUND_PREFIX_KEY,
    };
    use crate::{
        encrypt::encryption_key_from_pass, generate_seed, nodemanager::NodeManager, MutinyWallet,
        MutinyWalletBuilder, MutinyWalletConfigBuilder,
    };
    use crate::{
        event::{HTLCStatus, MillisatAmount, PaymentInfo},
        TransactionDetails,
    };
    use crate::{ldkstorage::CHANNEL_CLOSURE_PREFIX, storage::persist_transaction_details};
    use crate::{nodemanager::ChannelClosure, storage::TRANSACTION_DETAILS_PREFIX_KEY};
    use bdk_chain::{BlockId, ConfirmationTime};
    use bitcoin::bip32::ExtendedPrivKey;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::PublicKey;
    use bitcoin::{absolute::LockTime, Txid};
    use bitcoin::{BlockHash, Network, Transaction, TxOut};
    use hex_conservative::DisplayHex;
    use itertools::Itertools;
    use std::str::FromStr;

    use crate::test_utils::*;

    use crate::utils::{now, sleep};
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn create_mutiny_wallet() {
        let test_name = "create_mutiny_wallet";
        log!("{}", test_name);

        let mnemonic = generate_seed(12).unwrap();
        let network = Network::Regtest;
        let xpriv = ExtendedPrivKey::new_master(network, &mnemonic.to_seed("")).unwrap();

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher), None);
        assert!(!NodeManager::has_node_manager(storage.clone()));
        let config = MutinyWalletConfigBuilder::new(xpriv)
            .with_network(network)
            .build();
        let mw = MutinyWalletBuilder::new(xpriv, storage.clone())
            .with_config(config)
            .build()
            .await
            .expect("mutiny wallet should initialize");
        mw.storage.insert_mnemonic(mnemonic).unwrap();
        assert!(NodeManager::has_node_manager(storage));
    }

    #[test]
    async fn restart_mutiny_wallet() {
        let test_name = "restart_mutiny_wallet";
        log!("{}", test_name);
        let network = Network::Regtest;
        let xpriv = ExtendedPrivKey::new_master(network, &[0; 32]).unwrap();

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher), None);
        assert!(!NodeManager::has_node_manager(storage.clone()));
        let config = MutinyWalletConfigBuilder::new(xpriv)
            .with_network(network)
            .build();
        let mut mw = MutinyWalletBuilder::new(xpriv, storage.clone())
            .with_config(config)
            .build()
            .await
            .expect("mutiny wallet should initialize");

        let first_seed = mw.node_manager.xprivkey;

        assert!(mw.stop().await.is_ok());
        assert!(mw.start().await.is_ok());
        assert_eq!(first_seed, mw.node_manager.xprivkey);
    }

    #[test]
    async fn restart_mutiny_wallet_with_nodes() {
        let test_name = "restart_mutiny_wallet_with_nodes";
        log!("{}", test_name);

        let network = Network::Regtest;
        let xpriv = ExtendedPrivKey::new_master(network, &[0; 32]).unwrap();

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher), None);

        assert!(!NodeManager::has_node_manager(storage.clone()));
        let config = MutinyWalletConfigBuilder::new(xpriv)
            .with_network(network)
            .build();
        let mut mw = MutinyWalletBuilder::new(xpriv, storage.clone())
            .with_config(config)
            .build()
            .await
            .expect("mutiny wallet should initialize");

        // let storage persist
        sleep(1000).await;

        assert_eq!(mw.node_manager.list_nodes().await.unwrap().len(), 1);

        assert!(mw.node_manager.new_node().await.is_ok());
        // let storage persist
        sleep(1000).await;

        assert_eq!(mw.node_manager.list_nodes().await.unwrap().len(), 2);

        assert!(mw.stop().await.is_ok());
        assert!(mw.start().await.is_ok());
        assert_eq!(mw.node_manager.list_nodes().await.unwrap().len(), 2);
    }

    #[test]
    async fn restore_mutiny_mnemonic() {
        let test_name = "restore_mutiny_mnemonic";
        log!("{}", test_name);
        let mnemonic = generate_seed(12).unwrap();
        let network = Network::Regtest;
        let xpriv = ExtendedPrivKey::new_master(network, &mnemonic.to_seed("")).unwrap();

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher), None);
        assert!(!NodeManager::has_node_manager(storage.clone()));
        let config = MutinyWalletConfigBuilder::new(xpriv)
            .with_network(network)
            .build();
        let mw = MutinyWalletBuilder::new(xpriv, storage.clone())
            .with_config(config)
            .build()
            .await
            .expect("mutiny wallet should initialize");
        let seed = mw.node_manager.xprivkey;
        assert!(!seed.private_key.secret_bytes().is_empty());

        // create a second mw and make sure it has a different seed
        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage2 = MemoryStorage::new(Some(pass), Some(cipher), None);
        assert!(!NodeManager::has_node_manager(storage2.clone()));
        let xpriv2 = ExtendedPrivKey::new_master(network, &[0; 32]).unwrap();
        let config2 = MutinyWalletConfigBuilder::new(xpriv2)
            .with_network(network)
            .build();
        let mw2 = MutinyWalletBuilder::new(xpriv2, storage2.clone())
            .with_config(config2)
            .build()
            .await
            .expect("mutiny wallet should initialize");
        let seed2 = mw2.node_manager.xprivkey;
        assert_ne!(seed, seed2);

        // now restore the first seed into the 2nd mutiny node
        mw2.stop().await.expect("should stop");
        drop(mw2);

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage3 = MemoryStorage::new(Some(pass), Some(cipher), None);

        MutinyWallet::restore_mnemonic(storage3.clone(), mnemonic.clone())
            .await
            .expect("mutiny wallet should restore");

        let new_mnemonic = storage3.get_mnemonic().unwrap().unwrap();
        let new_xpriv = ExtendedPrivKey::new_master(network, &new_mnemonic.to_seed("")).unwrap();
        let config3 = MutinyWalletConfigBuilder::new(new_xpriv)
            .with_network(network)
            .build();
        let mw3 = MutinyWalletBuilder::new(new_xpriv, storage3.clone())
            .with_config(config3)
            .build()
            .await
            .expect("mutiny wallet should initialize");
        let restored_seed = mw3.node_manager.xprivkey;
        assert_eq!(seed, restored_seed);
    }

    #[test]
    async fn create_mutiny_wallet_safe_mode() {
        let test_name = "create_mutiny_wallet";
        log!("{}", test_name);

        let mnemonic = generate_seed(12).unwrap();
        let network = Network::Regtest;
        let xpriv = ExtendedPrivKey::new_master(network, &mnemonic.to_seed("")).unwrap();

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher), None);
        assert!(!NodeManager::has_node_manager(storage.clone()));
        let mut config_builder = MutinyWalletConfigBuilder::new(xpriv).with_network(network);
        config_builder.with_safe_mode();
        let config = config_builder.build();
        let mw = MutinyWalletBuilder::new(xpriv, storage.clone())
            .with_config(config)
            .build()
            .await
            .expect("mutiny wallet should initialize");
        mw.storage.insert_mnemonic(mnemonic).unwrap();
        assert!(NodeManager::has_node_manager(storage));

        let bip21 = mw.create_bip21(None, vec![]).await.unwrap();
        assert!(bip21.invoice.is_none());

        let new_node = mw.node_manager.new_node().await;
        assert!(new_node.is_err());
    }

    #[test]
    async fn test_sort_index_item() {
        let storage = MemoryStorage::new(None, None, None);
        let seed = generate_seed(12).expect("Failed to gen seed");
        let network = Network::Regtest;
        let xpriv = ExtendedPrivKey::new_master(network, &seed.to_seed("")).unwrap();
        let c = MutinyWalletConfigBuilder::new(xpriv)
            .with_network(network)
            .build();
        let mw = MutinyWalletBuilder::new(xpriv, storage.clone())
            .with_config(c)
            .build()
            .await
            .expect("mutiny wallet should initialize");

        loop {
            if !mw.node_manager.list_nodes().await.unwrap().is_empty() {
                break;
            }
            sleep(100).await;
        }

        let node = mw
            .node_manager
            .get_node_by_key_or_first(None)
            .await
            .unwrap();

        let closure: ChannelClosure = ChannelClosure {
            user_channel_id: None,
            channel_id: None,
            node_id: None,
            reason: "".to_string(),
            timestamp: 1686258926,
        };
        let closure_chan_id: u128 = 6969;
        node.persister
            .persist_channel_closure(closure_chan_id, closure.clone())
            .unwrap();

        let address = mw.node_manager.get_new_address(vec![]).unwrap();
        let output = TxOut {
            value: 10_000,
            script_pubkey: address.script_pubkey(),
        };
        let tx1 = Transaction {
            version: 1,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![output.clone()],
        };
        mw.node_manager
            .wallet
            .insert_tx(
                tx1.clone(),
                ConfirmationTime::Unconfirmed { last_seen: 0 },
                None,
            )
            .await
            .unwrap();

        let tx2 = Transaction {
            version: 2, // tx2 has different version than tx1 so they have different txids
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![output],
        };
        mw.node_manager
            .wallet
            .insert_tx(
                tx2.clone(),
                ConfirmationTime::Confirmed {
                    height: 1,
                    time: 1234,
                },
                Some(BlockId {
                    height: 1,
                    hash: BlockHash::all_zeros(),
                }),
            )
            .await
            .unwrap();

        let pubkey = PublicKey::from_str(
            "02465ed5be53d04fde66c9418ff14a5f2267723810176c9212b722e542dc1afb1b",
        )
        .unwrap();

        let payment_hash1: [u8; 32] =
            FromHex::from_hex("55ecf9169a6fa07e8ba181fdddf5b0bcc7860176659fa22a7cca9da2a359a33b")
                .unwrap();
        let invoice1 = PaymentInfo {
            bolt11: None,
            preimage: None,
            payee_pubkey: Some(pubkey),
            status: HTLCStatus::Succeeded,
            amt_msat: MillisatAmount(Some(100 * 1_000)),
            last_update: 1681781585,
            secret: None,
            fee_paid_msat: None,
            privacy_level: Default::default(),
        };
        persist_payment_info(&storage, &payment_hash1, &invoice1, false).unwrap();

        let payment_hash2: [u8; 32] =
            FromHex::from_hex("661ab24752eb99fc9c90236ffe348b1f8b9da5b9c00601c711d53589d98e7919")
                .unwrap();
        let invoice2 = PaymentInfo {
            bolt11: None,
            preimage: None,
            secret: None,
            payee_pubkey: Some(pubkey),
            amt_msat: MillisatAmount(Some(100 * 1_000)),
            last_update: 1781781585,
            status: HTLCStatus::Succeeded,
            fee_paid_msat: None,
            privacy_level: Default::default(),
        };
        persist_payment_info(&storage, &payment_hash2, &invoice2, false).unwrap();

        let payment_hash3: [u8; 32] =
            FromHex::from_hex("ab98fb003849d440b49346c213bdae018468b9f2dbd731726f0aaf581fda4ad1")
                .unwrap();
        let invoice3 = PaymentInfo {
            bolt11: None,
            preimage: None,
            payee_pubkey: Some(pubkey),
            amt_msat: MillisatAmount(Some(101 * 1_000)),
            status: HTLCStatus::InFlight,
            last_update: 1581781585,
            secret: None,
            fee_paid_msat: None,
            privacy_level: Default::default(),
        };
        persist_payment_info(&storage, &payment_hash3, &invoice3, false).unwrap();

        let payment_hash4: [u8; 32] =
            FromHex::from_hex("3287bdd9c82dbb91acdffcb103b1235c74060c01b9d22b4a62184bff290e1e7e")
                .unwrap();
        let mut invoice4 = PaymentInfo {
            bolt11: None,
            preimage: None,
            payee_pubkey: Some(pubkey),
            amt_msat: MillisatAmount(Some(102 * 1_000)),
            status: HTLCStatus::InFlight,
            fee_paid_msat: None,
            last_update: 1581781585,
            secret: None,
            privacy_level: Default::default(),
        };
        persist_payment_info(&storage, &payment_hash4, &invoice4, false).unwrap();

        let transaction_details1 = TransactionDetails {
            transaction: None,
            txid: Some(Txid::all_zeros()),
            internal_id: Txid::all_zeros(),
            received: 0,
            sent: 10_000,
            fee: Some(100),
            confirmation_time: ConfirmationTime::Unconfirmed {
                last_seen: now().as_secs(),
            },
            labels: vec![],
        };
        persist_transaction_details(&storage, &transaction_details1).unwrap();

        let vec = {
            let index = storage.activity_index();
            let vec = index.read().unwrap().clone().into_iter().collect_vec();
            vec
        };

        let expected = vec![
            IndexItem {
                timestamp: None,
                key: format!("{ONCHAIN_PREFIX}{}", tx1.txid()),
            },
            IndexItem {
                timestamp: None,
                key: format!(
                    "{PAYMENT_OUTBOUND_PREFIX_KEY}{}",
                    payment_hash4.to_lower_hex_string()
                ),
            },
            IndexItem {
                timestamp: None,
                key: format!(
                    "{PAYMENT_OUTBOUND_PREFIX_KEY}{}",
                    payment_hash3.to_lower_hex_string()
                ),
            },
            IndexItem {
                timestamp: None,
                key: format!(
                    "{TRANSACTION_DETAILS_PREFIX_KEY}{}",
                    transaction_details1.internal_id
                ),
            },
            IndexItem {
                timestamp: Some(invoice2.last_update),
                key: format!(
                    "{PAYMENT_OUTBOUND_PREFIX_KEY}{}",
                    payment_hash2.to_lower_hex_string()
                ),
            },
            IndexItem {
                timestamp: Some(closure.timestamp),
                key: format!(
                    "{CHANNEL_CLOSURE_PREFIX}{}_{}",
                    closure_chan_id.to_be_bytes().to_lower_hex_string(),
                    node.uuid
                ),
            },
            IndexItem {
                timestamp: Some(invoice1.last_update),
                key: format!(
                    "{PAYMENT_OUTBOUND_PREFIX_KEY}{}",
                    payment_hash1.to_lower_hex_string()
                ),
            },
            IndexItem {
                timestamp: Some(1234),
                key: format!("{ONCHAIN_PREFIX}{}", tx2.txid()),
            },
        ];

        assert_eq!(vec.len(), expected.len()); // make sure im not dumb
        assert_eq!(vec, expected);

        let activity = mw.get_activity(None, None).unwrap();
        assert_eq!(activity.len(), expected.len());

        let with_limit = mw.get_activity(Some(3), None).unwrap();
        assert_eq!(with_limit.len(), 3);

        let with_offset = mw.get_activity(None, Some(3)).unwrap();
        assert_eq!(with_offset.len(), activity.len() - 3);

        let with_both = mw.get_activity(Some(3), Some(3)).unwrap();
        assert_eq!(with_limit.len(), 3);
        assert_ne!(with_both, with_limit);

        // check we handle out of bounds errors
        let with_limit_oob = mw.get_activity(Some(usize::MAX), None).unwrap();
        assert_eq!(with_limit_oob.len(), expected.len());
        let with_offset_oob = mw.get_activity(None, Some(usize::MAX)).unwrap();
        assert!(with_offset_oob.is_empty());
        let with_offset_oob = mw.get_activity(None, Some(expected.len())).unwrap();
        assert!(with_offset_oob.is_empty());
        let with_both_oob = mw.get_activity(Some(usize::MAX), Some(usize::MAX)).unwrap();
        assert!(with_both_oob.is_empty());

        // update an inflight payment and make sure it isn't duplicated
        invoice4.last_update = now().as_secs();
        invoice4.status = HTLCStatus::Succeeded;
        persist_payment_info(&storage, &payment_hash4, &invoice4, false).unwrap();

        let vec = {
            let index = storage.activity_index();
            let vec = index.read().unwrap().clone().into_iter().collect_vec();
            vec
        };

        let item = vec
            .iter()
            .find(|i| i.key == payment_key(false, &payment_hash4));
        assert!(item.is_some_and(|i| i.timestamp == Some(invoice4.last_update))); // make sure timestamp got updated
        assert_eq!(vec.len(), expected.len()); // make sure no duplicates
    }
}
