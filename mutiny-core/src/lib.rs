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
pub mod federation;
mod fees;
mod gossip;
mod key;
mod keymanager;
pub mod labels;
mod ldkstorage;
pub mod lnurlauth;
pub mod logging;
mod lsp;
mod messagehandler;
mod networking;
mod node;
pub mod nodemanager;
pub mod nostr;
mod onchain;
mod peermanager;
pub mod scorer;
pub mod storage;
mod subscription;
pub mod utils;
pub mod vss;

#[cfg(test)]
mod test_utils;

pub use crate::gossip::{GOSSIP_SYNC_TIME_KEY, NETWORK_GRAPH_KEY, PROB_SCORER_KEY};
pub use crate::keymanager::generate_seed;
pub use crate::ldkstorage::{CHANNEL_MANAGER_KEY, MONITORS_PREFIX_KEY};
use crate::{auth::MutinyAuthClient, logging::MutinyLogger};
use crate::{error::MutinyError, nostr::ReservedProfile};
use crate::{
    event::{HTLCStatus, MillisatAmount, PaymentInfo},
    onchain::FULL_SYNC_STOP_GAP,
};
use crate::{
    federation::GatewayFees,
    storage::{
        list_payment_info, MutinyStorage, DEVICE_ID_KEY, EXPECTED_NETWORK_KEY, NEED_FULL_SYNC_KEY,
    },
};
use crate::{
    federation::{FederationClient, FederationIdentity, FederationIndex, FederationStorage},
    labels::{get_contact_key, Contact, LabelStorage},
    nodemanager::NodeBalance,
};
use crate::{
    lnurlauth::make_lnurl_auth_connection,
    nodemanager::{ChannelClosure, MutinyBip21RawMaterials, TransactionDetails},
};
use crate::{lnurlauth::AuthManager, nostr::MUTINY_PLUS_SUBSCRIPTION_LABEL};
use crate::{logging::LOGGING_KEY, nodemanager::NodeManagerBuilder};
use crate::{nodemanager::NodeManager, nostr::ProfileType};
use crate::{
    nostr::nwc::{BudgetPeriod, BudgetedSpendingConditions, NwcProfileTag, SpendingConditions},
    subscription::MutinySubscriptionClient,
};
use crate::{nostr::NostrManager, utils::sleep};
use ::nostr::nips::nip57;
use ::nostr::prelude::ZapRequestData;
use ::nostr::{Event, EventId, JsonUtil, Kind, Metadata};
use async_lock::RwLock;
use bdk_chain::ConfirmationTime;
use bip39::Mnemonic;
use bitcoin::bip32::ExtendedPrivKey;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{hashes::sha256, Network};
use fedimint_core::{api::InviteCode, config::FederationId};
use futures::{pin_mut, select, FutureExt};
use futures_util::join;
use hex_conservative::{DisplayHex, FromHex};
#[cfg(target_arch = "wasm32")]
use instant::Instant;
use lightning::ln::PaymentHash;
use lightning::util::logger::Logger;
use lightning::{log_debug, log_error, log_info, log_trace, log_warn};
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription};
use lnurl::{lnurl::LnUrl, AsyncClient as LnUrlClient, LnUrlResponse, Response};
use nostr_sdk::{Client, RelayPoolNotification};
use reqwest::multipart::{Form, Part};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;
use std::{collections::HashMap, sync::atomic::AtomicBool};
use std::{str::FromStr, sync::atomic::Ordering};
use uuid::Uuid;

use crate::labels::LabelItem;
use crate::nostr::NostrKeySource;
use crate::storage::SUBSCRIPTION_TIMESTAMP;
use crate::utils::parse_profile_metadata;
#[cfg(test)]
use mockall::{automock, predicate::*};

const DEFAULT_PAYMENT_TIMEOUT: u64 = 30;
const MAX_FEDERATION_INVOICE_AMT: u64 = 200_000;
const SWAP_LABEL: &str = "SWAP";

#[cfg_attr(test, automock)]
pub trait InvoiceHandler {
    fn logger(&self) -> &MutinyLogger;
    fn skip_hodl_invoices(&self) -> bool;
    async fn get_outbound_payment_status(&self, payment_hash: &[u8; 32]) -> Option<HTLCStatus>;
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

/// Plan is a subscription plan for Mutiny+
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Plan {
    /// The ID of the internal plan.
    /// Used for subscribing to specific one.
    pub id: u8,

    /// The amount in sats for the plan.
    pub amount_sat: u64,
}

#[derive(Copy, Clone)]
pub struct MutinyBalance {
    pub confirmed: u64,
    pub unconfirmed: u64,
    pub lightning: u64,
    pub federation: u64,
    pub force_close: u64,
}

impl MutinyBalance {
    fn new(ln_balance: NodeBalance, federation_balance: u64) -> Self {
        Self {
            confirmed: ln_balance.confirmed,
            unconfirmed: ln_balance.unconfirmed,
            lightning: ln_balance.lightning,
            federation: federation_balance,
            force_close: ln_balance.force_close,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct FederationBalance {
    pub identity: FederationIdentity,
    pub balance: u64,
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct FederationBalances {
    pub balances: Vec<FederationBalance>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ActivityItem {
    OnChain(TransactionDetails),
    Lightning(Box<MutinyInvoice>),
    ChannelClosed(ChannelClosure),
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
    pub fees_paid: Option<u64>,
    pub inbound: bool,
    pub labels: Vec<String>,
    pub last_updated: u64,
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
    xprivkey: ExtendedPrivKey,
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
    primal_url: Option<String>,
    do_not_connect_peers: bool,
    skip_device_lock: bool,
    pub safe_mode: bool,
    skip_hodl_invoices: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DirectMessage {
    pub from: ::nostr::PublicKey,
    pub to: ::nostr::PublicKey,
    pub message: String,
    pub date: u64,
    pub event_id: EventId,
}

impl PartialOrd for DirectMessage {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DirectMessage {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // order by date, then the message, the keys
        self.date
            .cmp(&other.date)
            .then_with(|| self.message.cmp(&other.message))
            .then_with(|| self.from.cmp(&other.from))
            .then_with(|| self.to.cmp(&other.to))
    }
}

impl MutinyWalletConfigBuilder {
    pub fn new(xprivkey: ExtendedPrivKey) -> MutinyWalletConfigBuilder {
        MutinyWalletConfigBuilder {
            xprivkey,
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
            primal_url: None,
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

    pub fn with_primal_url(&mut self, primal_url: String) {
        self.primal_url = Some(primal_url);
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
            xprivkey: self.xprivkey,
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
            primal_url: self.primal_url,
            do_not_connect_peers: self.do_not_connect_peers,
            skip_device_lock: self.skip_device_lock,
            safe_mode: self.safe_mode,
            skip_hodl_invoices: self.skip_hodl_invoices,
        }
    }
}

#[derive(Clone)]
pub struct MutinyWalletConfig {
    xprivkey: ExtendedPrivKey,
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
    primal_url: Option<String>,
    do_not_connect_peers: bool,
    skip_device_lock: bool,
    pub safe_mode: bool,
    skip_hodl_invoices: bool,
}

pub struct MutinyWalletBuilder<S: MutinyStorage> {
    xprivkey: ExtendedPrivKey,
    nostr_key_source: NostrKeySource,
    storage: S,
    config: Option<MutinyWalletConfig>,
    session_id: Option<String>,
    network: Option<Network>,
    auth_client: Option<Arc<MutinyAuthClient>>,
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
            nostr_key_source: NostrKeySource::Derived,
            config: None,
            session_id: None,
            network: None,
            auth_client: None,
            subscription_url: None,
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

    pub fn with_nostr_key_source(&mut self, key_source: NostrKeySource) {
        self.nostr_key_source = key_source;
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

        let start = Instant::now();

        let mut nm_builder = NodeManagerBuilder::new(self.xprivkey, self.storage.clone())
            .with_config(config.clone());
        nm_builder.with_stop(stop.clone());
        nm_builder.with_logger(logger.clone());
        let node_manager = Arc::new(nm_builder.build().await?);

        log_trace!(
            logger,
            "NodeManager started, took: {}ms",
            start.elapsed().as_millis()
        );

        // start syncing node manager
        NodeManager::start_sync(node_manager.clone());

        // create nostr manager
        let nostr = Arc::new(NostrManager::from_mnemonic(
            self.xprivkey,
            self.nostr_key_source,
            self.storage.clone(),
            logger.clone(),
            stop.clone(),
        )?);

        // connect to relays when not in tests
        #[cfg(not(test))]
        nostr.connect().await?;

        // create federation module if any exist
        let federation_storage = self.storage.get_federations()?;
        let federations = if !federation_storage.federations.is_empty() {
            let start = Instant::now();
            log_trace!(logger, "Building Federations");
            let result =
                create_federations(federation_storage.clone(), &config, &self.storage, &logger)
                    .await?;
            log_debug!(
                logger,
                "Federations started, took: {}ms",
                start.elapsed().as_millis()
            );
            result
        } else {
            Arc::new(RwLock::new(HashMap::new()))
        };

        if !self.skip_hodl_invoices {
            log_warn!(
                logger,
                "Starting with HODL invoices enabled. This is not recommended!"
            );
        }

        let start = Instant::now();

        let lnurl_client = Arc::new(
            lnurl::Builder::default()
                .build_async()
                .expect("failed to make lnurl client"),
        );

        let (subscription_client, auth) = if let Some(auth_client) = self.auth_client.clone() {
            if let Some(subscription_url) = self.subscription_url {
                let auth = auth_client.auth.clone();
                let s = Arc::new(MutinySubscriptionClient::new(
                    auth_client,
                    subscription_url,
                    logger.clone(),
                ));
                (Some(s), auth)
            } else {
                (None, auth_client.auth.clone())
            }
        } else {
            let auth_manager = AuthManager::new(self.xprivkey)?;
            (None, auth_manager)
        };

        let mw = MutinyWallet {
            xprivkey: self.xprivkey,
            config,
            storage: self.storage,
            node_manager,
            nostr,
            federation_storage: Arc::new(RwLock::new(federation_storage)),
            federations,
            lnurl_client,
            subscription_client,
            auth,
            stop,
            logger,
            network,
            skip_hodl_invoices: self.skip_hodl_invoices,
            safe_mode: self.safe_mode,
        };

        // if we are in safe mode, don't create any nodes or
        // start any nostr services
        if self.safe_mode {
            return Ok(mw);
        }

        // if we don't have any nodes, create one
        if mw.node_manager.list_nodes().await?.is_empty() {
            let nm = mw.node_manager.clone();
            // spawn in background, this can take a while and we don't want to block
            utils::spawn(async move {
                if let Err(e) = nm.new_node().await {
                    log_error!(nm.logger, "Failed to create first node: {e}");
                }
            })
        };

        // start the nostr background process
        mw.start_nostr().await;

        // start the federation background processor
        mw.start_fedimint_background_checker().await;

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
    pub nostr: Arc<NostrManager<S>>,
    pub federation_storage: Arc<RwLock<FederationStorage>>,
    pub(crate) federations: Arc<RwLock<HashMap<FederationId, Arc<FederationClient<S>>>>>,
    lnurl_client: Arc<LnUrlClient>,
    auth: AuthManager,
    subscription_client: Option<Arc<MutinySubscriptionClient>>,
    pub stop: Arc<AtomicBool>,
    pub logger: Arc<MutinyLogger>,
    network: Network,
    skip_hodl_invoices: bool,
    safe_mode: bool,
}

impl<S: MutinyStorage> MutinyWallet<S> {
    /// Starts up all the nodes again.
    /// Not needed after [NodeManager]'s `new()` function.
    pub async fn start(&mut self) -> Result<(), MutinyError> {
        self.storage.start().await?;

        let mut nm_builder = NodeManagerBuilder::new(self.xprivkey, self.storage.clone())
            .with_config(self.config.clone());
        nm_builder.with_stop(self.stop.clone());
        nm_builder.with_logger(self.logger.clone());

        // when we restart, gen a new session id
        self.node_manager = Arc::new(nm_builder.build().await?);
        NodeManager::start_sync(self.node_manager.clone());

        Ok(())
    }

    /// Starts a background process that will watch for nostr events
    pub(crate) async fn start_nostr(&self) {
        let nostr = self.nostr.clone();
        let logger = self.logger.clone();
        let stop = self.stop.clone();
        let self_clone = self.clone();
        utils::spawn(async move {
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                };

                // if we have no filters, then wait 10 seconds and see if we do again
                let mut last_filters = nostr.get_filters().unwrap_or_default();
                if last_filters.is_empty() {
                    utils::sleep(10_000).await;
                    continue;
                }

                // clear in-active profiles, we used to have disabled and archived profiles
                // but now we just delete profiles
                if let Err(e) = nostr.remove_inactive_profiles() {
                    log_warn!(logger, "Failed to clear in-active NWC profiles: {e}");
                }

                // if a single-use profile's payment was successful in the background,
                // we can safely clear it now
                if let Err(e) = nostr
                    .clear_successful_single_use_profiles(&self_clone)
                    .await
                {
                    log_warn!(logger, "Failed to clear in-active NWC profiles: {e}");
                }

                if let Err(e) = nostr.clear_expired_nwc_invoices().await {
                    log_warn!(logger, "Failed to clear expired NWC invoices: {e}");
                }

                let client = Client::new(nostr.primary_key.clone());

                client
                    .add_relays(nostr.get_relays())
                    .await
                    .expect("Failed to add relays");
                client.connect().await;

                client.subscribe(last_filters.clone()).await;

                // handle NWC requests
                let mut notifications = client.notifications();

                let mut next_filter_check = crate::utils::now().as_secs() + 5;
                loop {
                    let read_fut = notifications.recv().fuse();
                    let delay_fut = Box::pin(utils::sleep(1_000)).fuse();

                    // Determine the time for filter check.
                    // Since delay runs every second, needs to allow for filter check to run too
                    let current_time = crate::utils::now().as_secs();
                    let time_until_next_filter_check =
                        (next_filter_check.saturating_sub(current_time)) * 1_000;
                    let filter_check_fut = Box::pin(utils::sleep(
                        time_until_next_filter_check.try_into().unwrap(),
                    ))
                    .fuse();

                    pin_mut!(read_fut, delay_fut, filter_check_fut);
                    select! {
                        notification = read_fut => {
                            match notification {
                                Ok(RelayPoolNotification::Event { event, .. }) => {
                                    if event.verify().is_ok() {
                                        match event.kind {
                                            Kind::WalletConnectRequest => {
                                                match nostr.handle_nwc_request(event, &self_clone).await {
                                                    Ok(Some(event)) => {
                                                        if let Err(e) = client.send_event(event).await {
                                                            log_warn!(logger, "Error sending NWC event: {e}");
                                                        }
                                                    }
                                                    Ok(None) => {} // no response
                                                    Err(e) => {
                                                        log_error!(logger, "Error handling NWC request: {e}");
                                                    }
                                                }
                                            }
                                            Kind::EncryptedDirectMessage => {
                                                if let Err(e) = nostr.handle_direct_message(event, &self_clone).await {
                                                        log_error!(logger, "Error handling dm: {e}");
                                                }
                                            }
                                            kind => log_warn!(logger, "Received unexpected note of kind {kind}")
                                        }
                                    }
                                },
                                Ok(RelayPoolNotification::Message { .. }) => {}, // ignore messages
                                Ok(RelayPoolNotification::Shutdown) => break, // if we disconnect, we restart to reconnect
                                Ok(RelayPoolNotification::Stop) => {}, // Currently unused
                                Ok(RelayPoolNotification::RelayStatus { .. }) => {}, // Currently unused
                                Err(_) => break, // if we are erroring we should reconnect
                            }
                        }
                        _ = delay_fut => {
                            if stop.load(Ordering::Relaxed) {
                                break;
                            }
                        }
                        _ = filter_check_fut => {
                            // Check if the filters have changed
                            if let Ok(current_filters) = nostr.get_filters() {
                                if !utils::compare_filters_vec(&current_filters, &last_filters) {
                                    log_debug!(logger, "subscribing to new nwc filters");
                                    client.subscribe(current_filters.clone()).await;
                                    last_filters = current_filters;
                                }
                            }
                            // Set the time for the next filter check
                            next_filter_check = crate::utils::now().as_secs() + 5;
                        }
                    }
                }

                if let Err(e) = client.disconnect().await {
                    log_warn!(logger, "Error disconnecting from relays: {e}");
                }
            }
        });
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
        if inv.network() != self.network {
            return Err(MutinyError::IncorrectNetwork);
        }

        // check invoice is expired
        if inv.would_expire(utils::now()) {
            return Err(MutinyError::InvoiceExpired);
        }

        // Check the amount specified in the invoice, we need one to make the payment
        let send_msat = inv
            .amount_milli_satoshis()
            .or(amt_sats.map(|x| x * 1_000))
            .ok_or(MutinyError::InvoiceInvalid)?;

        // set labels now, need to set it before in case the payment times out
        self.storage
            .set_invoice_labels(inv.clone(), labels.clone())?;

        // Try each federation first
        let federation_ids = self.list_federation_ids().await?;
        let mut last_federation_error = None;
        for federation_id in federation_ids {
            if let Some(fedimint_client) = self.federations.read().await.get(&federation_id) {
                // Check if the federation has enough balance
                let balance = fedimint_client.get_balance().await?;
                if balance >= send_msat / 1_000 {
                    // Try to pay the invoice using the federation
                    let payment_result = fedimint_client
                        .pay_invoice(inv.clone(), labels.clone())
                        .await;
                    match payment_result {
                        Ok(r) => {
                            return Ok(r);
                        }
                        Err(e) => match e {
                            MutinyError::PaymentTimeout => return Err(e),
                            MutinyError::RoutingFailed => {
                                log_debug!(
                                    self.logger,
                                    "could not make payment through federation: {e}"
                                );
                                last_federation_error = Some(e);
                                continue;
                            }
                            _ => {
                                log_warn!(self.logger, "unhandled error: {e}");
                                last_federation_error = Some(e);
                            }
                        },
                    }
                }
                // If payment fails or invoice amount is None or balance is not sufficient, continue to next federation
            }
            // If federation client is not found, continue to next federation
        }

        // If any balance at all, then fallback to node manager for payment.
        // Take the error from the node manager as the priority.
        if self
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
            self.node_manager
                .pay_invoice(None, inv, amt_sats, labels)
                .await
        } else {
            Err(last_federation_error.unwrap_or(MutinyError::InsufficientBalance))
        }
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
        let amt = amt_sats
            .or(inv.and_then(|i| i.amount_milli_satoshis()))
            .ok_or(MutinyError::BadAmountError)?;

        // check balances first
        let total_balances = self.get_balance().await?;
        if total_balances.federation > amt {
            let federation_ids = self.list_federation_ids().await?;
            for federation_id in federation_ids {
                // Check if the federation has enough balance
                if let Some(fedimint_client) = self.federations.read().await.get(&federation_id) {
                    let current_balance = fedimint_client.get_balance().await?;
                    log_info!(
                        self.logger,
                        "current fedimint client balance: {}",
                        current_balance
                    );

                    let fees = fedimint_client.gateway_fee().await?;
                    let max_spendable = max_spendable_amount(current_balance, &fees)
                        .map_or(Err(MutinyError::InsufficientBalance), Ok)?;

                    if max_spendable >= amt {
                        let prop_fee_msat =
                            (amt as f64 * 1_000.0 * fees.proportional_millionths as f64)
                                / 1_000_000.0;

                        let total_fee = fees.base_msat as f64 + prop_fee_msat;
                        return Ok(Some((total_fee / 1_000.0).floor() as u64));
                    }
                }
            }
        }

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

        let Ok(address) = self.node_manager.get_new_address(labels.clone()) else {
            return Err(MutinyError::WalletOperationFailed);
        };

        Ok(MutinyBip21RawMaterials {
            address,
            invoice,
            btc_amount: amount.map(|amount| bitcoin::Amount::from_sat(amount).to_btc().to_string()),
            labels,
        })
    }

    pub async fn sweep_federation_balance(
        &self,
        amount: Option<u64>,
    ) -> Result<FedimintSweepResult, MutinyError> {
        // TODO support more than one federation
        let federation_ids = self.list_federation_ids().await?;
        if federation_ids.is_empty() {
            return Err(MutinyError::NotFound);
        }
        let federation_id = &federation_ids[0];
        let federation_lock = self.federations.read().await;
        let fedimint_client = federation_lock
            .get(federation_id)
            .ok_or(MutinyError::NotFound)?;

        let labels = vec![SWAP_LABEL.to_string()];

        // if the user provided amount, this is easy
        if let Some(amt) = amount {
            let (inv, fee) = self
                .node_manager
                .create_invoice(amt, labels.clone())
                .await?;

            let bolt_11 = inv.bolt11.expect("create inv had one job");
            self.storage
                .set_invoice_labels(bolt_11.clone(), labels.clone())?;
            let pay_res = fedimint_client.pay_invoice(bolt_11, labels).await?;
            let total_fees_paid = pay_res.fees_paid.unwrap_or(0) + fee;

            return Ok(FedimintSweepResult {
                amount: amt,
                fees: Some(total_fees_paid),
            });
        }

        // If no amount, figure out the amount to send over
        let current_balance = fedimint_client.get_balance().await?;
        log_debug!(
            self.logger,
            "current fedimint client balance: {}",
            current_balance
        );

        let fees = fedimint_client.gateway_fee().await?;
        // FIXME: this is still producing off by one. check round down
        let amt = max_spendable_amount(current_balance, &fees)
            .map_or(Err(MutinyError::InsufficientBalance), Ok)?;
        log_debug!(self.logger, "max spendable: {}", amt);

        // try to get an invoice for this exact amount
        let (inv, fee) = self
            .node_manager
            .create_invoice(amt, labels.clone())
            .await?;

        // check if we can afford that invoice
        let inv_amt = inv.amount_sats.ok_or(MutinyError::BadAmountError)?;
        let first_invoice_amount = if inv_amt > amt {
            log_debug!(self.logger, "adjusting amount to swap to: {}", amt);
            inv_amt - (inv_amt - amt)
        } else {
            inv_amt
        };

        // if invoice amount changed, create a new invoice
        let (inv_to_pay, fee) = if first_invoice_amount != inv_amt {
            self.node_manager
                .create_invoice(first_invoice_amount, labels.clone())
                .await?
        } else {
            (inv.clone(), fee)
        };

        log_debug!(self.logger, "attempting payment from fedimint client");
        let bolt_11 = inv_to_pay.bolt11.expect("create inv had one job");
        self.storage
            .set_invoice_labels(bolt_11.clone(), labels.clone())?;
        let first_invoice_res = fedimint_client.pay_invoice(bolt_11, labels).await?;

        let remaining_balance = fedimint_client.get_balance().await?;
        if remaining_balance > 0 {
            // there was a remainder when there shouldn't have been
            // for now just log this, it is probably just a millisat/1 sat difference
            log_warn!(
                self.logger,
                "remaining fedimint balance: {}",
                remaining_balance
            );
        }

        let total_fees = first_invoice_res.fees_paid.unwrap_or(0) + fee;
        Ok(FedimintSweepResult {
            amount: current_balance - total_fees,
            fees: Some(total_fees),
        })
    }

    /// Estimate the fee before trying to sweep from federation
    pub async fn estimate_sweep_federation_fee(
        &self,
        amount: Option<u64>,
    ) -> Result<Option<u64>, MutinyError> {
        if let Some(0) = amount {
            return Ok(None);
        }

        // TODO support more than one federation
        let federation_ids = self.list_federation_ids().await?;
        if federation_ids.is_empty() {
            return Err(MutinyError::NotFound);
        }

        let federation_id = &federation_ids[0];
        let federation_lock = self.federations.read().await;
        let fedimint_client = federation_lock
            .get(federation_id)
            .ok_or(MutinyError::NotFound)?;
        let fees = fedimint_client.gateway_fee().await?;

        let (lsp_fee, federation_fee) = {
            if let Some(amt) = amount {
                // if the user provided amount, this is easy
                (
                    self.node_manager.get_lsp_fee(amt).await?,
                    (calc_routing_fee_msat(amt as f64 * 1_000.0, &fees) / 1_000.0).floor() as u64,
                )
            } else {
                // If no amount, figure out the amount to send over
                let current_balance = fedimint_client.get_balance().await?;
                log_debug!(
                    self.logger,
                    "current fedimint client balance: {}",
                    current_balance
                );

                let amt = max_spendable_amount(current_balance, &fees)
                    .map_or(Err(MutinyError::InsufficientBalance), Ok)?;
                log_debug!(self.logger, "max spendable: {}", amt);

                // try to get an invoice for this exact amount
                (
                    self.node_manager.get_lsp_fee(amt).await?,
                    current_balance - amt,
                )
            }
        };

        Ok(Some(lsp_fee + federation_fee))
    }

    async fn create_lightning_invoice(
        &self,
        amount: u64,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        // Attempt to create federation invoice if available and below max amount
        let federation_ids = self.list_federation_ids().await?;
        if !federation_ids.is_empty() && amount <= MAX_FEDERATION_INVOICE_AMT {
            let federation_id = &federation_ids[0];
            let fedimint_client = self.federations.read().await.get(federation_id).cloned();

            if let Some(client) = fedimint_client {
                if let Ok(inv) = client.get_invoice(amount, labels.clone()).await {
                    self.storage
                        .set_invoice_labels(inv.bolt11.clone().expect("just created"), labels)?;
                    return Ok(inv);
                }
            }
        }

        // Fallback to node_manager invoice creation if no federation invoice created
        let (inv, _fee) = self.node_manager.create_invoice(amount, labels).await?;

        Ok(inv)
    }

    /// Gets the current balance of the wallet.
    /// This includes both on-chain, lightning funds, and federations.
    ///
    /// This will not include any funds in an unconfirmed lightning channel.
    pub async fn get_balance(&self) -> Result<MutinyBalance, MutinyError> {
        let ln_balance = self.node_manager.get_balance().await?;
        let federation_balance = self.get_total_federation_balance().await?;

        Ok(MutinyBalance::new(ln_balance, federation_balance))
    }

    /// Get the sorted activity list for lightning payments, channels, and txs.
    pub async fn get_activity(&self) -> Result<Vec<ActivityItem>, MutinyError> {
        // Get activity for lightning invoices
        let lightning = self
            .list_invoices()
            .map_err(|e| {
                log_warn!(self.logger, "Failed to get lightning activity: {e}");
                e
            })
            .unwrap_or_default();

        // Get activities from node manager
        let (closures, onchain) = self.node_manager.get_activity().await?;

        let mut activities = Vec::with_capacity(lightning.len() + onchain.len() + closures.len());
        for ln in lightning {
            // Only show paid and in-flight invoices
            match ln.status {
                HTLCStatus::Succeeded | HTLCStatus::InFlight => {
                    activities.push(ActivityItem::Lightning(Box::new(ln)));
                }
                HTLCStatus::Pending | HTLCStatus::Failed => {}
            }
        }
        for on in onchain {
            activities.push(ActivityItem::OnChain(on));
        }
        for chan in closures {
            activities.push(ActivityItem::ChannelClosed(chan));
        }

        // Sort all activities, newest first
        activities.sort_by(|a, b| b.cmp(a));

        Ok(activities)
    }

    pub fn list_invoices(&self) -> Result<Vec<MutinyInvoice>, MutinyError> {
        let mut inbound_invoices = self.list_payment_info_from_persisters(true)?;
        let mut outbound_invoices = self.list_payment_info_from_persisters(false)?;
        inbound_invoices.append(&mut outbound_invoices);
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
        self.get_invoice_by_hash(invoice.payment_hash()).await
    }

    /// Looks up an invoice by hash.
    /// This includes sent and received invoices.
    pub async fn get_invoice_by_hash(
        &self,
        hash: &sha256::Hash,
    ) -> Result<MutinyInvoice, MutinyError> {
        // First, try to find the invoice in the node manager
        if let Ok(invoice) = self.node_manager.get_invoice_by_hash(hash).await {
            return Ok(invoice);
        }

        // If not found in node manager, search in federations
        let federations = self.federations.read().await;
        for (_fed_id, federation) in federations.iter() {
            if let Ok(invoice) = federation.get_invoice_by_hash(hash).await {
                return Ok(invoice);
            }
        }

        Err(MutinyError::NotFound)
    }

    /// Checks whether or not the user is subscribed to Mutiny+.
    /// Submits a NWC string to keep the subscription active if not expired.
    ///
    /// Returns None if there's no subscription at all.
    /// Returns Some(u64) for their unix expiration timestamp, which may be in the
    /// past or in the future, depending on whether or not it is currently active.
    pub async fn check_subscribed(&self) -> Result<Option<u64>, MutinyError> {
        if let Some(ref subscription_client) = self.subscription_client {
            let now = utils::now().as_secs();
            match self.storage.get_data::<u64>(SUBSCRIPTION_TIMESTAMP) {
                Ok(Some(timestamp)) if timestamp > now => {
                    // if we have a timestamp and it is in the future, we are subscribed
                    // make sure we have a NWC profile, this needs to be done in case
                    // the subscription was created outside the app.
                    self.ensure_mutiny_nwc_profile(subscription_client, true)
                        .await?;
                    Ok(Some(timestamp))
                }
                _ => {
                    // if we don't have a timestamp or it is in the past, check with the server
                    let time = subscription_client.check_subscribed().await?;
                    // if we are subscribed, save the timestamp
                    if let Some(time) = time.filter(|t| *t > now) {
                        self.storage
                            .set_data(SUBSCRIPTION_TIMESTAMP.to_string(), time, None)?;
                    }
                    Ok(time)
                }
            }
        } else {
            Ok(None)
        }
    }

    /// Gets the subscription plans for Mutiny+ subscriptions
    pub async fn get_subscription_plans(&self) -> Result<Vec<Plan>, MutinyError> {
        if let Some(subscription_client) = self.subscription_client.clone() {
            Ok(subscription_client.get_plans().await?)
        } else {
            Ok(vec![])
        }
    }

    /// Subscribes to a Mutiny+ plan with a specific plan id.
    ///
    /// Returns a lightning invoice so that the plan can be paid for to start it.
    pub async fn subscribe_to_plan(&self, id: u8) -> Result<MutinyInvoice, MutinyError> {
        if let Some(subscription_client) = self.subscription_client.clone() {
            Ok(Bolt11Invoice::from_str(&subscription_client.subscribe_to_plan(id).await?)?.into())
        } else {
            Err(MutinyError::SubscriptionClientNotConfigured)
        }
    }

    /// Pay the subscription invoice. This will post a NWC automatically afterwards.
    pub async fn pay_subscription_invoice(
        &self,
        inv: &Bolt11Invoice,
        autopay: bool,
    ) -> Result<(), MutinyError> {
        if let Some(subscription_client) = self.subscription_client.as_ref() {
            // TODO if this times out, we should make the next part happen in EventManager
            self.pay_invoice(inv, None, vec![MUTINY_PLUS_SUBSCRIPTION_LABEL.to_string()])
                .await?;

            // now submit the NWC string if never created before
            self.ensure_mutiny_nwc_profile(subscription_client, autopay)
                .await?;

            Ok(())
        } else {
            Err(MutinyError::SubscriptionClientNotConfigured)
        }
    }

    async fn ensure_mutiny_nwc_profile(
        &self,
        subscription_client: &MutinySubscriptionClient,
        autopay: bool,
    ) -> Result<(), MutinyError> {
        let nwc_profiles = self.nostr.profiles();
        let reserved_profile_index = ReservedProfile::MutinySubscription.info().1;
        let profile_opt = nwc_profiles
            .iter()
            .find(|profile| profile.index == reserved_profile_index);

        match profile_opt {
            None => {
                // profile with the reserved index does not exist, create a new one
                let nwc = if autopay {
                    self.nostr
                        .create_new_nwc_profile(
                            ProfileType::Reserved(ReservedProfile::MutinySubscription),
                            SpendingConditions::Budget(BudgetedSpendingConditions {
                                budget: 21_000,
                                single_max: None,
                                payments: vec![],
                                period: BudgetPeriod::Month,
                            }),
                            NwcProfileTag::Subscription,
                        )
                        .await?
                        .nwc_uri
                } else {
                    self.nostr
                        .create_new_nwc_profile(
                            ProfileType::Reserved(ReservedProfile::MutinySubscription),
                            SpendingConditions::RequireApproval,
                            NwcProfileTag::Subscription,
                        )
                        .await?
                        .nwc_uri
                };

                if let Some(nwc) = nwc {
                    // only should have to submit the NWC if never created locally before
                    subscription_client.submit_nwc(nwc).await?;
                }
            }
            Some(profile) => {
                if profile.tag != NwcProfileTag::Subscription {
                    let mut nwc = profile.clone();
                    nwc.tag = NwcProfileTag::Subscription;
                    self.nostr.edit_nwc_profile(nwc)?;
                }
            }
        }

        // check if we have a contact, if not create one
        match self.storage.get_contact(MUTINY_PLUS_SUBSCRIPTION_LABEL)? {
            Some(_) => {}
            None => {
                let key = get_contact_key(MUTINY_PLUS_SUBSCRIPTION_LABEL);
                let contact = Contact {
                    name: MUTINY_PLUS_SUBSCRIPTION_LABEL.to_string(),
                    npub: None,
                    ln_address: None,
                    lnurl: None,
                    image_url: Some("https://void.cat/d/CZPXhnwjqRhULSjPJ3sXTE.webp".to_string()),
                    last_used: utils::now().as_secs(),
                };
                self.storage.set_data(key, contact, None)?;
            }
        }

        Ok(())
    }

    /// Uploads a profile pic to nostr.build and returns the uploaded file's URL
    pub async fn upload_profile_pic(&self, image_bytes: Vec<u8>) -> Result<String, MutinyError> {
        let client = reqwest::Client::new();

        let form = Form::new().part("fileToUpload", Part::bytes(image_bytes));
        let res: NostrBuildResult = client
            .post("https://nostr.build/api/v2/upload/profile")
            .multipart(form)
            .send()
            .await
            .map_err(|_| MutinyError::NostrError)?
            .json()
            .await
            .map_err(|_| MutinyError::NostrError)?;

        if res.status != "success" {
            log_error!(
                self.logger,
                "Error uploading profile picture: {}",
                res.message
            );
            return Err(MutinyError::NostrError);
        }

        // get url from response body
        if let Some(value) = res.data.first() {
            return value
                .get("url")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or(MutinyError::NostrError);
        }

        Err(MutinyError::NostrError)
    }

    /// Makes a request to the primal api
    async fn primal_request(
        client: &reqwest::Client,
        url: &str,
        body: Value,
    ) -> Result<Vec<Value>, MutinyError> {
        client
            .post(url)
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|_| MutinyError::NostrError)?
            .json()
            .await
            .map_err(|_| MutinyError::NostrError)
    }

    /// Syncs all of our nostr data from the configured primal instance
    pub async fn sync_nostr(&self) -> Result<(), MutinyError> {
        let contacts_fut = self.sync_nostr_contacts(self.nostr.public_key);
        let profile_fut = self.sync_nostr_profile();

        // join futures and handle result
        let (contacts_res, profile_res) = join!(contacts_fut, profile_fut);
        contacts_res?;
        profile_res?;

        Ok(())
    }

    /// Fetches our latest nostr profile from primal and saves to storage
    async fn sync_nostr_profile(&self) -> Result<(), MutinyError> {
        let url = self
            .config
            .primal_url
            .as_deref()
            .unwrap_or("https://primal-cache.mutinywallet.com/api");
        let client = reqwest::Client::new();

        let body = json!(["user_profile", { "pubkey": self.nostr.public_key } ]);
        let data: Vec<Value> = Self::primal_request(&client, url, body).await?;

        if let Some(json) = data.first().cloned() {
            let event: Event = serde_json::from_value(json).map_err(|_| MutinyError::NostrError)?;
            if event.kind != Kind::Metadata {
                return Ok(());
            }

            let metadata: Metadata =
                serde_json::from_str(&event.content).map_err(|_| MutinyError::NostrError)?;
            self.storage.set_nostr_profile(metadata)?;
        }

        Ok(())
    }

    /// Get contacts from the given npub and sync them to the wallet
    pub async fn sync_nostr_contacts(&self, npub: ::nostr::PublicKey) -> Result<(), MutinyError> {
        let url = self
            .config
            .primal_url
            .as_deref()
            .unwrap_or("https://primal-cache.mutinywallet.com/api");
        let client = reqwest::Client::new();

        let body = json!(["contact_list", { "pubkey": npub } ]);
        let data: Vec<Value> = Self::primal_request(&client, url, body).await?;
        let mut metadata = parse_profile_metadata(data);

        let contacts = self.storage.get_contacts()?;

        // get contacts that weren't in our npub contacts list
        let missing_pks: Vec<String> = contacts
            .iter()
            .filter_map(|(_, c)| {
                if c.npub.is_some_and(|n| metadata.get(&n).is_none()) {
                    c.npub.map(|n| n.to_hex())
                } else {
                    None
                }
            })
            .collect();

        if !missing_pks.is_empty() {
            let body = json!(["user_infos", {"pubkeys": missing_pks }]);
            let data: Vec<Value> = Self::primal_request(&client, url, body).await?;
            let missing_metadata = parse_profile_metadata(data);
            metadata.extend(missing_metadata);
        }

        let mut updated_contacts: Vec<(String, Value)> =
            Vec::with_capacity(contacts.len() + metadata.len());

        for (id, contact) in contacts {
            if let Some(npub) = contact.npub {
                if let Some(meta) = metadata.get(&npub) {
                    let updated = contact.update_with_metadata(meta.clone());
                    metadata.remove(&npub);
                    updated_contacts.push((get_contact_key(id), serde_json::to_value(updated)?));
                }
            }
        }

        for (npub, meta) in metadata {
            let contact = Contact::create_from_metadata(npub, meta);

            if contact.name.is_empty() {
                log_debug!(
                    self.logger,
                    "Skipping creating contact with no name: {npub}"
                );
                continue;
            }

            // generate a uuid, this will be the "label" that we use to store the contact
            let id = Uuid::new_v4().to_string();
            let key = get_contact_key(&id);
            updated_contacts.push((key, serde_json::to_value(contact)?));

            let key = labels::get_label_item_key(&id);
            let label_item = LabelItem::default();
            updated_contacts.push((key, serde_json::to_value(label_item)?));
        }

        self.storage.set(updated_contacts)?;

        Ok(())
    }

    /// Get dm conversation between us and given npub
    /// Returns a vector of messages sorted by newest first
    pub async fn get_dm_conversation(
        &self,
        npub: ::nostr::PublicKey,
        limit: u64,
        until: Option<u64>,
        since: Option<u64>,
    ) -> Result<Vec<DirectMessage>, MutinyError> {
        let url = self
            .config
            .primal_url
            .as_deref()
            .unwrap_or("https://primal-cache.mutinywallet.com/api");
        let client = reqwest::Client::new();

        // api is a little weird, has sender and receiver but still gives full conversation
        let sender = npub.to_hex();
        let receiver = self.nostr.public_key.to_hex();
        let body = match (until, since) {
            (Some(until), Some(since)) => {
                json!(["get_directmsgs", { "sender": sender, "receiver": receiver, "limit": limit, "until": until, "since": since }])
            }
            (None, Some(since)) => {
                json!(["get_directmsgs", { "sender": sender, "receiver": receiver, "limit": limit, "since": since }])
            }
            (Some(until), None) => {
                json!(["get_directmsgs", { "sender": sender, "receiver": receiver, "limit": limit, "until": until }])
            }
            (None, None) => {
                json!(["get_directmsgs", { "sender": sender, "receiver": receiver, "limit": limit, "since": 0 }])
            }
        };
        let data: Vec<Value> = Self::primal_request(&client, url, body).await?;

        let mut messages = Vec::with_capacity(data.len());
        for d in data {
            let event = Event::from_value(d)
                .ok()
                .filter(|e| e.kind == Kind::EncryptedDirectMessage);

            if let Some(event) = event {
                // verify signature
                if event.verify().is_err() {
                    continue;
                }

                let message = self.nostr.decrypt_dm(npub, &event.content).await?;

                let to = if event.pubkey == npub {
                    self.nostr.public_key
                } else {
                    npub
                };
                let dm = DirectMessage {
                    from: event.pubkey,
                    to,
                    message,
                    date: event.created_at.as_u64(),
                    event_id: event.id,
                };
                messages.push(dm);
            }
        }

        // sort messages, newest first
        messages.sort_by(|a, b| b.cmp(a));

        Ok(messages)
    }

    /// Stops all of the nodes and background processes.
    /// Returns after node has been stopped.
    pub async fn stop(&self) -> Result<(), MutinyError> {
        self.node_manager.stop().await
    }

    pub async fn change_password(
        &mut self,
        old: Option<String>,
        new: Option<String>,
    ) -> Result<(), MutinyError> {
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

        Ok(())
    }

    /// Resets BDK's keychain tracker. This will require a re-sync of the blockchain.
    ///
    /// This can be useful if you get stuck in a bad state.
    pub async fn reset_onchain_tracker(&mut self) -> Result<(), MutinyError> {
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

        Ok(())
    }

    /// Deletes all the storage
    pub async fn delete_all(&self) -> Result<(), MutinyError> {
        self.storage.delete_all().await?;
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
        if invoice.network() != network.unwrap_or(self.network) {
            return Err(MutinyError::IncorrectNetwork);
        }

        Ok(invoice.into())
    }

    /// Adds a new federation based on its federation code
    pub async fn new_federation(
        &mut self,
        federation_code: InviteCode,
    ) -> Result<FederationIdentity, MutinyError> {
        create_new_federation(
            self.xprivkey,
            self.storage.clone(),
            self.network,
            self.logger.clone(),
            self.federation_storage.clone(),
            self.federations.clone(),
            federation_code,
        )
        .await
    }

    /// Lists the federation id's of the federation clients in the manager.
    pub async fn list_federations(&self) -> Result<Vec<FederationIdentity>, MutinyError> {
        let federations = self.federations.read().await;
        let mut federation_identities = Vec::new();
        for f in federations.iter() {
            let i = f.1.get_mutiny_federation_identity().await;
            federation_identities.push(i);
        }
        Ok(federation_identities)
    }

    /// Lists the federation id's of the federation clients in the manager.
    pub async fn list_federation_ids(&self) -> Result<Vec<FederationId>, MutinyError> {
        let federations = self.federations.read().await;
        let federation_identities = federations
            .iter()
            .map(|(_, n)| n.fedimint_client.federation_id())
            .collect();
        Ok(federation_identities)
    }

    /// Removes a federation by removing it from the user's federation list.
    pub async fn remove_federation(&self, federation_id: FederationId) -> Result<(), MutinyError> {
        let mut federations_guard = self.federations.write().await;

        if let Some(fedimint_client) = federations_guard.get(&federation_id) {
            let uuid = &fedimint_client.uuid;

            let mut federation_storage_guard = self.federation_storage.write().await;

            if federation_storage_guard.federations.contains_key(uuid) {
                federation_storage_guard.federations.remove(uuid);
                federation_storage_guard.version += 1;
                self.storage
                    .insert_federations(federation_storage_guard.clone())
                    .await?;
                // TODO in the future, delete user's fedimint storage too
                // for now keep it in case they restore the federation again
                // fedimint_client.delete_fedimint_storage().await?;
                federations_guard.remove(&federation_id);
            } else {
                return Err(MutinyError::NotFound);
            }
        } else {
            return Err(MutinyError::NotFound);
        }

        Ok(())
    }

    pub async fn recover_federation_backups(&self) -> Result<(), MutinyError> {
        let federation_ids = self.list_federation_ids().await?;

        let federations = self.federations.read().await;
        for fed_id in federation_ids {
            federations
                .get(&fed_id)
                .ok_or(MutinyError::NotFound)?
                .recover_backup()
                .await?;

            log_info!(self.logger, "Scanned federation backups: {}", fed_id);
        }

        Ok(())
    }

    pub async fn get_total_federation_balance(&self) -> Result<u64, MutinyError> {
        let federation_ids = self.list_federation_ids().await?;
        let mut total_balance = 0;

        let federations = self.federations.read().await;
        for fed_id in federation_ids {
            let balance = federations
                .get(&fed_id)
                .ok_or(MutinyError::NotFound)?
                .get_balance()
                .await?;

            total_balance += balance;
        }

        Ok(total_balance)
    }

    pub async fn get_federation_balances(&self) -> Result<FederationBalances, MutinyError> {
        let federation_lock = self.federations.read().await;

        let federation_ids = self.list_federation_ids().await?;
        let mut balances = Vec::with_capacity(federation_ids.len());
        for fed_id in federation_ids {
            let fedimint_client = federation_lock.get(&fed_id).ok_or(MutinyError::NotFound)?;

            let balance = fedimint_client.get_balance().await?;
            let identity = fedimint_client.get_mutiny_federation_identity().await;

            balances.push(FederationBalance { identity, balance });
        }

        Ok(FederationBalances { balances })
    }

    /// Starts a background process that will check pending fedimint operations
    pub(crate) async fn start_fedimint_background_checker(&self) {
        let logger = self.logger.clone();
        let stop = self.stop.clone();
        let self_clone = self.clone();
        utils::spawn(async move {
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                };

                sleep(1000).await;
                let federation_lock = self_clone.federations.read().await;

                match self_clone.list_federation_ids().await {
                    Ok(federation_ids) => {
                        for fed_id in federation_ids {
                            match federation_lock.get(&fed_id) {
                                Some(fedimint_client) => {
                                    let _ = fedimint_client.check_activity().await.map_err(|e| {
                                        log_error!(logger, "error checking activity: {e}")
                                    });
                                }
                                None => {
                                    log_error!(
                                        logger,
                                        "could not get a federation from the lock: {}",
                                        fed_id
                                    )
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log_error!(logger, "could not list federations: {e}")
                    }
                }
            }
        });
    }

    /// Calls upon a LNURL to get the parameters for it.
    /// This contains what kind of LNURL it is (pay, withdrawal, auth, etc).
    // todo revamp LnUrlParams to be well designed
    pub async fn decode_lnurl(&self, lnurl: LnUrl) -> Result<LnUrlParams, MutinyError> {
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

        Ok(params)
    }

    /// Calls upon a LNURL and pays it.
    /// This will fail if the LNURL is not a LNURL pay.
    pub async fn lnurl_pay(
        &self,
        lnurl: &LnUrl,
        amount_sats: u64,
        zap_npub: Option<::nostr::PublicKey>,
        mut labels: Vec<String>,
        comment: Option<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        let response = self.lnurl_client.make_request(&lnurl.url).await?;

        match response {
            LnUrlResponse::LnUrlPayResponse(pay) => {
                let msats = amount_sats * 1000;

                // if user's npub is given, do an anon zap
                let (zap_request, comment) = match zap_npub {
                    Some(zap_npub) => {
                        let data = ZapRequestData {
                            public_key: zap_npub,
                            relays: vec![
                                "wss://relay.mutinywallet.com".into(),
                                "wss://relay.primal.net".into(),
                            ],
                            message: comment.unwrap_or_default(),
                            amount: Some(msats),
                            lnurl: Some(lnurl.encode()),
                            event_id: None,
                            event_coordinate: None,
                        };
                        let event = nip57::anonymous_zap_request(data)?;

                        (Some(event.as_json()), None)
                    }
                    None => (None, comment.filter(|c| !c.is_empty())),
                };

                let invoice = self
                    .lnurl_client
                    .get_invoice(&pay, msats, zap_request, comment.as_deref())
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

                    self.pay_invoice(&invoice, None, labels).await
                } else {
                    log_error!(self.logger, "LNURL return invoice with incorrect amount");
                    Err(MutinyError::LnUrlFailure)
                }
            }
            LnUrlResponse::LnUrlWithdrawResponse(_) => Err(MutinyError::IncorrectLnUrlFunction),
            LnUrlResponse::LnUrlChannelResponse(_) => Err(MutinyError::IncorrectLnUrlFunction),
        }
    }

    /// Calls upon a LNURL and withdraws from it.
    /// This will fail if the LNURL is not a LNURL withdrawal.
    pub async fn lnurl_withdraw(
        &self,
        lnurl: &LnUrl,
        amount_sats: u64,
    ) -> Result<bool, MutinyError> {
        let response = self.lnurl_client.make_request(&lnurl.url).await?;

        match response {
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
        }
    }

    /// Authenticate with a LNURL-auth
    pub async fn lnurl_auth(&self, lnurl: LnUrl) -> Result<(), MutinyError> {
        make_lnurl_auth_connection(
            self.auth.clone(),
            self.lnurl_client.clone(),
            lnurl,
            self.logger.clone(),
        )
        .await
    }

    pub fn is_safe_mode(&self) -> bool {
        self.safe_mode
    }
}

impl<S: MutinyStorage> InvoiceHandler for MutinyWallet<S> {
    fn logger(&self) -> &MutinyLogger {
        self.logger.as_ref()
    }

    fn skip_hodl_invoices(&self) -> bool {
        self.skip_hodl_invoices
    }

    async fn get_outbound_payment_status(&self, payment_hash: &[u8; 32]) -> Option<HTLCStatus> {
        self.get_invoice_by_hash(&sha256::Hash::from_byte_array(*payment_hash))
            .await
            .ok()
            .map(|p| p.status)
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

async fn create_federations<S: MutinyStorage>(
    federation_storage: FederationStorage,
    c: &MutinyWalletConfig,
    storage: &S,
    logger: &Arc<MutinyLogger>,
) -> Result<Arc<RwLock<HashMap<FederationId, Arc<FederationClient<S>>>>>, MutinyError> {
    let mut federation_map = HashMap::with_capacity(federation_storage.federations.len());
    for (uuid, federation_index) in federation_storage.federations {
        let federation = FederationClient::new(
            uuid,
            federation_index.federation_code,
            c.xprivkey,
            storage,
            c.network,
            logger.clone(),
        )
        .await?;

        let id = federation.fedimint_client.federation_id();

        federation_map.insert(id, Arc::new(federation));
    }
    let federations = Arc::new(RwLock::new(federation_map));
    Ok(federations)
}

// This will create a new federation and returns the Federation ID of the client created.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_new_federation<S: MutinyStorage>(
    xprivkey: ExtendedPrivKey,
    storage: S,
    network: Network,
    logger: Arc<MutinyLogger>,
    federation_storage: Arc<RwLock<FederationStorage>>,
    federations: Arc<RwLock<HashMap<FederationId, Arc<FederationClient<S>>>>>,
    federation_code: InviteCode,
) -> Result<FederationIdentity, MutinyError> {
    // Begin with a mutex lock so that nothing else can
    // save or alter the federation list while it is about to
    // be saved.
    let mut federation_mutex = federation_storage.write().await;

    // Check if the federation already exists
    if federation_mutex
        .federations
        .values()
        .any(|federation| federation.federation_code == federation_code)
    {
        return Err(MutinyError::InvalidArgumentsError);
    }

    // Create and save a new federation
    let next_federation_uuid = Uuid::new_v4().to_string();
    let next_federation = FederationIndex {
        federation_code: federation_code.clone(),
    };

    federation_mutex
        .federations
        .insert(next_federation_uuid.clone(), next_federation.clone());
    federation_mutex.version += 1;
    storage.insert_federations(federation_mutex.clone()).await?;

    // now create the federation process and init it
    let new_federation = FederationClient::new(
        next_federation_uuid.clone(),
        federation_code,
        xprivkey,
        &storage,
        network,
        logger.clone(),
    )
    .await?;

    let federation_id = new_federation.fedimint_client.federation_id();
    let federation_name = new_federation.fedimint_client.get_meta("federation_name");
    let federation_expiry_timestamp = new_federation
        .fedimint_client
        .get_meta("federation_expiry_timestamp");
    let welcome_message = new_federation.fedimint_client.get_meta("welcome_message");
    let gateway_fees = new_federation.gateway_fee().await.ok();

    federations
        .write()
        .await
        .insert(federation_id, Arc::new(new_federation));

    Ok(FederationIdentity {
        uuid: next_federation_uuid.clone(),
        federation_id,
        federation_name,
        federation_expiry_timestamp,
        welcome_message,
        gateway_fees,
    })
}

#[derive(Deserialize)]
struct NostrBuildResult {
    status: String,
    message: String,
    data: Vec<Value>,
}

// max amount that can be spent through a gateway
fn max_spendable_amount(current_balance_sat: u64, routing_fees: &GatewayFees) -> Option<u64> {
    let current_balance_msat = current_balance_sat as f64 * 1_000.0;

    // proportional fee on the current balance
    let base_and_prop_fee_msat = calc_routing_fee_msat(current_balance_msat, routing_fees);

    // The max balance considering the maximum possible proportional fee.
    // This gives us a baseline to start checking the fees from. In the case that the fee is 1%
    // The real maximum balance will be somewhere between our current balance and 99% of our
    // balance.
    let initial_max = current_balance_msat - base_and_prop_fee_msat;

    // if the fee would make the amount go negative, then there is not a possible amount to spend
    if initial_max <= 0.0 {
        return None;
    }

    // if the initial balance and initial maximum is basically the same, then that's it
    // this is basically only ever the case if there's not really any fee involved
    if current_balance_msat - initial_max < 1.0 {
        return Some((initial_max / 1_000.0).floor() as u64);
    }

    // keep trying until we hit our balance or find the max amount
    let mut new_max = initial_max;
    while new_max < current_balance_msat {
        // we increment by one and check the fees for it
        let new_check = new_max + 1.0;

        // check the new spendable balance amount plus base fees plus new proportional fee
        let new_amt = new_check + calc_routing_fee_msat(new_check, routing_fees);
        if current_balance_msat - new_amt <= 0.0 {
            // since we are incrementing from a minimum spendable amount,
            // if we overshot our total balance then the last max is the highest
            return Some((new_max / 1_000.0).floor() as u64);
        }

        // this is the new spendable maximum
        new_max += 1.0;
    }

    Some((new_max / 1_000.0).floor() as u64)
}

fn calc_routing_fee_msat(amt_msat: f64, routing_fees: &GatewayFees) -> f64 {
    let prop_fee_msat = (amt_msat * routing_fees.proportional_millionths as f64) / 1_000_000.0;
    routing_fees.base_msat as f64 + prop_fee_msat
}

#[cfg(test)]
fn max_routing_fee_amount() {
    let initial_budget = 1;
    let routing_fees = GatewayFees {
        base_msat: 10_000,
        proportional_millionths: 0,
    };
    assert_eq!(None, max_spendable_amount(initial_budget, &routing_fees));

    // only a percentage fee
    let initial_budget = 100;
    let routing_fees = GatewayFees {
        base_msat: 0,
        proportional_millionths: 0,
    };
    assert_eq!(
        Some(100),
        max_spendable_amount(initial_budget, &routing_fees)
    );

    let initial_budget = 100;
    let routing_fees = GatewayFees {
        base_msat: 0,
        proportional_millionths: 10_000,
    };
    assert_eq!(
        Some(99),
        max_spendable_amount(initial_budget, &routing_fees)
    );

    let initial_budget = 100;
    let routing_fees = GatewayFees {
        base_msat: 0,
        proportional_millionths: 100_000,
    };
    assert_eq!(
        Some(90),
        max_spendable_amount(initial_budget, &routing_fees)
    );

    let initial_budget = 101_000;
    let routing_fees = GatewayFees {
        base_msat: 0,
        proportional_millionths: 100_000,
    };
    assert_eq!(
        Some(91_818),
        max_spendable_amount(initial_budget, &routing_fees)
    );

    let initial_budget = 101;
    let routing_fees = GatewayFees {
        base_msat: 0,
        proportional_millionths: 100_000,
    };
    assert_eq!(
        Some(91),
        max_spendable_amount(initial_budget, &routing_fees)
    );

    // same tests but with a base fee
    let initial_budget = 100;
    let routing_fees = GatewayFees {
        base_msat: 1_000,
        proportional_millionths: 0,
    };
    assert_eq!(
        Some(99),
        max_spendable_amount(initial_budget, &routing_fees)
    );

    let initial_budget = 100;
    let routing_fees = GatewayFees {
        base_msat: 1_000,
        proportional_millionths: 10_000,
    };
    assert_eq!(
        Some(98),
        max_spendable_amount(initial_budget, &routing_fees)
    );

    let initial_budget = 100;
    let routing_fees = GatewayFees {
        base_msat: 1_000,
        proportional_millionths: 100_000,
    };
    assert_eq!(
        Some(89),
        max_spendable_amount(initial_budget, &routing_fees)
    );

    let initial_budget = 101;
    let routing_fees = GatewayFees {
        base_msat: 1_000,
        proportional_millionths: 100_000,
    };
    assert_eq!(
        Some(90),
        max_spendable_amount(initial_budget, &routing_fees)
    );
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn test_max_routing_fee_amount() {
        max_routing_fee_amount();
    }
}

#[cfg(test)]
#[cfg(target_arch = "wasm32")]
mod tests {
    use crate::{
        encrypt::encryption_key_from_pass, generate_seed, max_routing_fee_amount,
        nodemanager::NodeManager, MutinyWallet, MutinyWalletBuilder, MutinyWalletConfigBuilder,
    };
    use bitcoin::bip32::ExtendedPrivKey;
    use bitcoin::Network;

    use crate::test_utils::*;

    use crate::labels::{Contact, LabelStorage};
    use crate::nostr::NostrKeySource;
    use crate::storage::{MemoryStorage, MutinyStorage};
    use crate::utils::{parse_npub, sleep};
    use nostr::Keys;
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
    async fn sync_nostr_contacts() {
        let npub =
            parse_npub("npub18s7md9ytv8r240jmag5j037huupk5jnsk94adykeaxtvc6lyftesuw5ydl").unwrap();
        let ben =
            parse_npub("npub1u8lnhlw5usp3t9vmpz60ejpyt649z33hu82wc2hpv6m5xdqmuxhs46turz").unwrap();
        let tony =
            parse_npub("npub1t0nyg64g5vwprva52wlcmt7fkdr07v5dr7s35raq9g0xgc0k4xcsedjgqv").unwrap();

        // create wallet
        let mnemonic = generate_seed(12).unwrap();
        let network = Network::Regtest;
        let xpriv = ExtendedPrivKey::new_master(network, &mnemonic.to_seed("")).unwrap();
        let storage = MemoryStorage::new(None, None, None);
        let config = MutinyWalletConfigBuilder::new(xpriv)
            .with_network(network)
            .build();
        let mw = MutinyWalletBuilder::new(xpriv, storage.clone())
            .with_config(config)
            .build()
            .await
            .expect("mutiny wallet should initialize");

        // sync contacts
        mw.sync_nostr_contacts(npub).await.expect("synced contacts");

        // first sync should yield just ben's contact
        let contacts = mw
            .storage
            .get_contacts()
            .unwrap()
            .into_values()
            .collect::<Vec<_>>();
        assert_eq!(contacts.len(), 1);
        let contact = contacts.first().unwrap();
        assert_eq!(contact.npub, Some(ben));
        assert!(contact.image_url.is_some());
        assert!(contact.ln_address.is_some());
        assert!(!contact.name.is_empty());

        // add tony as a contact with incomplete info
        let incorrect_name = "incorrect name".to_string();
        let new_contact = Contact {
            name: incorrect_name.clone(),
            npub: Some(tony),
            ..Default::default()
        };
        let id = mw.storage.create_new_contact(new_contact).unwrap();

        // sync contacts again, tony's contact should be correct
        mw.sync_nostr_contacts(npub).await.expect("synced contacts");

        let contacts = mw.storage.get_contacts().unwrap();
        assert_eq!(contacts.len(), 2);
        let contact = contacts.get(&id).unwrap();
        assert_eq!(contact.npub, Some(tony));
        assert!(contact.image_url.is_some());
        assert!(contact.ln_address.is_some());
        assert_ne!(contact.name, incorrect_name);
    }

    #[test]
    async fn get_dm_conversation_test() {
        // test nsec I made and sent dms to
        let nsec =
            Keys::parse("nsec1w2cy7vmq8urw9ae6wjaujrmztndad7e65hja52zk0c9x4yxgk0xsfuqk6s").unwrap();
        let npub =
            parse_npub("npub18s7md9ytv8r240jmag5j037huupk5jnsk94adykeaxtvc6lyftesuw5ydl").unwrap();

        // create wallet
        let mnemonic = generate_seed(12).unwrap();
        let network = Network::Regtest;
        let xpriv = ExtendedPrivKey::new_master(network, &mnemonic.to_seed("")).unwrap();
        let storage = MemoryStorage::new(None, None, None);
        let config = MutinyWalletConfigBuilder::new(xpriv)
            .with_network(network)
            .build();
        let mut mw = MutinyWalletBuilder::new(xpriv, storage.clone()).with_config(config);
        mw.with_nostr_key_source(NostrKeySource::Imported(nsec));
        let mw = mw.build().await.expect("mutiny wallet should initialize");

        // get messages
        let limit = 5;
        let messages = mw
            .get_dm_conversation(npub, limit, None, None)
            .await
            .unwrap();

        assert_eq!(messages.len(), 5);

        for x in &messages {
            log!("{}", x.message);
        }

        // get next messages
        let limit = 2;
        let util = messages.iter().min_by_key(|m| m.date).unwrap().date - 1;
        let next = mw
            .get_dm_conversation(npub, limit, Some(util), None)
            .await
            .unwrap();

        for x in next.iter() {
            log!("{}", x.message);
        }

        // check that we got different messages
        assert_eq!(next.len(), 2);
        assert!(next.iter().all(|m| !messages.contains(m)));

        // test check for future messages, should be empty
        let since = messages.iter().max_by_key(|m| m.date).unwrap().date + 1;
        let future_msgs = mw
            .get_dm_conversation(npub, limit, None, Some(since))
            .await
            .unwrap();

        assert!(future_msgs.is_empty());
    }

    #[test]
    fn test_max_routing_fee_amount() {
        max_routing_fee_amount();
    }
}
