use crate::lnurlauth::AuthManager;
use crate::logging::LOGGING_KEY;
use crate::multiesplora::MultiEsploraClient;
use crate::redshift::{RedshiftManager, RedshiftStatus, RedshiftStorage};
use crate::storage::{MutinyStorage, DEVICE_ID_KEY, KEYCHAIN_STORE_KEY, NEED_FULL_SYNC_KEY};
use crate::utils::{sleep, spawn};
use crate::MutinyWalletConfig;
use crate::{
    chain::MutinyChain,
    error::MutinyError,
    esplora::EsploraSyncClient,
    fees::MutinyFeeEstimator,
    gossip,
    gossip::{fetch_updated_gossip, get_rgs_url},
    logging::MutinyLogger,
    lspclient::LspClient,
    node::{Node, PubkeyConnectionInfo, RapidGossipSync},
    onchain::get_esplora_url,
    onchain::OnChainWallet,
    utils,
};
use crate::{
    event::{HTLCStatus, PaymentInfo},
    lnurlauth::make_lnurl_auth_connection,
};
use crate::{gossip::*, scorer::HubPreferentialScorer};
use crate::{labels::LabelStorage, subscription::MutinySubscriptionClient};
use anyhow::anyhow;
use bdk::chain::{BlockId, ConfirmationTime};
use bdk::{wallet::AddressIndex, LocalUtxo};
use bitcoin::blockdata::script;
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{rand, PublicKey};
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::{Address, Network, OutPoint, Transaction, Txid};
use core::time::Duration;
use esplora_client::Builder;
use futures::{future::join_all, lock::Mutex};
use lightning::chain::Confirm;
use lightning::events::ClosureReason;
use lightning::ln::channelmanager::{ChannelDetails, PhantomRouteHints};
use lightning::ln::script::ShutdownScript;
use lightning::ln::{ChannelId, PaymentHash};
use lightning::routing::gossip::NodeId;
use lightning::sign::{NodeSigner, Recipient};
use lightning::util::logger::*;
use lightning::{log_debug, log_error, log_info, log_warn};
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription};
use lnurl::lnurl::LnUrl;
use lnurl::{AsyncClient as LnUrlClient, LnUrlResponse, Response};
use nostr::key::XOnlyPublicKey;
use nostr::{EventBuilder, Keys, Kind, Tag, TagKind};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{collections::HashMap, ops::Deref, sync::Arc};
use uuid::Uuid;

const BITCOIN_PRICE_CACHE_SEC: u64 = 300;
pub const DEVICE_LOCK_INTERVAL_SECS: u64 = 30;

// This is the NodeStorage object saved to the DB
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct NodeStorage {
    pub nodes: HashMap<String, NodeIndex>,
    #[serde(default)]
    pub version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LspConfig {
    VoltageFlow(String),
}

fn deserialize_lsp_config<'de, D>(deserializer: D) -> Result<Option<LspConfig>, D::Error>
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

// This is the NodeIndex reference that is saved to the DB
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Default)]
pub struct NodeIndex {
    pub child_index: u32,
    #[serde(deserialize_with = "deserialize_lsp_config")]
    pub lsp: Option<LspConfig>,
    pub archived: Option<bool>,
}

impl NodeIndex {
    pub fn is_archived(&self) -> bool {
        self.archived.unwrap_or(false)
    }
}

// This is the NodeIdentity that refer to a specific node
// Used for public facing identification.
pub struct NodeIdentity {
    pub uuid: String,
    pub pubkey: PublicKey,
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct MutinyBip21RawMaterials {
    pub address: Address,
    pub invoice: Option<Bolt11Invoice>,
    pub btc_amount: Option<String>,
    pub labels: Vec<String>,
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
                if a.is_empty() {
                    None
                } else {
                    Some(a.to_string())
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
                    preimage: i.preimage.map(|p| p.to_hex()),
                    fees_paid: i.fee_paid_msat.map(|f| f / 1_000),
                    ..invoice.into()
                })
            }
            None => {
                let amount_sats: Option<u64> = i.amt_msat.0.map(|s| s / 1_000);
                let fees_paid = i.fee_paid_msat.map(|f| f / 1_000);
                let preimage = i.preimage.map(|p| p.to_hex());
                let payment_hash = sha256::Hash::from_inner(payment_hash.0);
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

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct MutinyPeer {
    pub pubkey: PublicKey,
    pub connection_string: Option<String>,
    pub alias: Option<String>,
    pub color: Option<String>,
    pub label: Option<String>,
    pub is_connected: bool,
}

impl PartialOrd for MutinyPeer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MutinyPeer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.is_connected
            .cmp(&other.is_connected)
            .then_with(|| self.alias.cmp(&other.alias))
            .then_with(|| self.pubkey.cmp(&other.pubkey))
            .then_with(|| self.connection_string.cmp(&other.connection_string))
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct MutinyChannel {
    pub user_chan_id: String,
    pub balance: u64,
    pub size: u64,
    pub reserve: u64,
    pub outpoint: Option<OutPoint>,
    pub peer: PublicKey,
    pub confirmations_required: Option<u32>,
    pub confirmations: u32,
    pub is_outbound: bool,
    pub is_usable: bool,
}

impl From<&ChannelDetails> for MutinyChannel {
    fn from(c: &ChannelDetails) -> Self {
        MutinyChannel {
            user_chan_id: c.user_channel_id.to_hex(),
            balance: c.outbound_capacity_msat / 1_000,
            size: c.channel_value_satoshis,
            reserve: c.unspendable_punishment_reserve.unwrap_or(0),
            outpoint: c.funding_txo.map(|f| f.into_bitcoin_outpoint()),
            peer: c.counterparty.node_id,
            confirmations_required: c.confirmations_required,
            confirmations: c.confirmations.unwrap_or(0),
            is_outbound: c.is_outbound,
            is_usable: c.is_usable,
        }
    }
}

/// A wallet transaction
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TransactionDetails {
    /// Optional transaction
    pub transaction: Option<Transaction>,
    /// Transaction id
    pub txid: Txid,
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

impl From<bdk::TransactionDetails> for TransactionDetails {
    fn from(t: bdk::TransactionDetails) -> Self {
        TransactionDetails {
            transaction: t.transaction,
            txid: t.txid,
            received: t.received,
            sent: t.sent,
            fee: t.fee,
            confirmation_time: t.confirmation_time,
            labels: vec![],
        }
    }
}

/// Information about a channel that was closed.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChannelClosure {
    pub user_channel_id: Option<[u8; 16]>,
    pub channel_id: Option<[u8; 32]>,
    pub node_id: Option<PublicKey>,
    pub reason: String,
    pub timestamp: u64,
}

impl ChannelClosure {
    pub fn new(
        user_channel_id: u128,
        channel_id: ChannelId,
        node_id: Option<PublicKey>,
        reason: ClosureReason,
    ) -> Self {
        Self {
            user_channel_id: Some(user_channel_id.to_be_bytes()),
            channel_id: Some(channel_id.0),
            node_id,
            reason: reason.to_string(),
            timestamp: utils::now().as_secs(),
        }
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

pub struct MutinyBalance {
    pub confirmed: u64,
    pub unconfirmed: u64,
    pub lightning: u64,
    pub force_close: u64,
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

/// The [NodeManager] is the main entry point for interacting with the Mutiny Wallet.
/// It is responsible for managing the on-chain wallet and the lightning nodes.
///
/// It can be used to create a new wallet, or to load an existing wallet.
///
/// It can be configured to use all different custom backend services, or to use the default
/// services provided by Mutiny.
pub struct NodeManager<S: MutinyStorage> {
    pub(crate) stop: Arc<AtomicBool>,
    pub(crate) xprivkey: ExtendedPrivKey,
    network: Network,
    #[cfg(target_arch = "wasm32")]
    websocket_proxy_addr: String,
    user_rgs_url: Option<String>,
    esplora: Arc<MultiEsploraClient>,
    pub(crate) wallet: Arc<OnChainWallet<S>>,
    gossip_sync: Arc<RapidGossipSync>,
    scorer: Arc<utils::Mutex<HubPreferentialScorer>>,
    chain: Arc<MutinyChain<S>>,
    fee_estimator: Arc<MutinyFeeEstimator<S>>,
    pub(crate) storage: S,
    pub(crate) node_storage: Mutex<NodeStorage>,
    pub(crate) nodes: Arc<Mutex<HashMap<PublicKey, Arc<Node<S>>>>>,
    auth: AuthManager,
    lnurl_client: Arc<LnUrlClient>,
    pub(crate) lsp_clients: Vec<LspClient>,
    pub(crate) subscription_client: Option<Arc<MutinySubscriptionClient>>,
    pub(crate) logger: Arc<MutinyLogger>,
    bitcoin_price_cache: Arc<Mutex<HashMap<String, (f32, Duration)>>>,
    do_not_connect_peers: bool,
    skip_hodl_invoices: bool,
    pub safe_mode: bool,
}

impl<S: MutinyStorage> NodeManager<S> {
    /// Returns if there is a saved wallet in storage.
    /// This is checked by seeing if a mnemonic seed exists in storage.
    pub fn has_node_manager(storage: S) -> bool {
        storage.get_mnemonic().is_ok_and(|x| x.is_some())
    }

    /// Creates a new [NodeManager] with the given parameters.
    /// The mnemonic seed is read from storage, unless one is provided.
    /// If no mnemonic is provided, a new one is generated and stored.
    pub async fn new(
        c: MutinyWalletConfig,
        storage: S,
        session_id: Option<String>,
    ) -> Result<NodeManager<S>, MutinyError> {
        let stop = Arc::new(AtomicBool::new(false));

        #[cfg(target_arch = "wasm32")]
        let websocket_proxy_addr = c
            .websocket_proxy_addr
            .unwrap_or_else(|| String::from("wss://p.mutinywallet.com"));

        let logger = Arc::new(MutinyLogger::with_writer(
            stop.clone(),
            storage.clone(),
            session_id,
        ));

        // Need to prevent other devices from running at the same time
        if !c.skip_device_lock {
            if let Some(lock) = storage.get_device_lock()? {
                log_info!(logger, "Current device lock: {lock:?}");
            }
            storage.set_device_lock().await?;
        }

        let storage_clone = storage.clone();
        let logger_clone = logger.clone();
        let stop_clone = stop.clone();
        utils::spawn(async move {
            loop {
                if stop_clone.load(Ordering::Relaxed) {
                    break;
                }
                sleep((DEVICE_LOCK_INTERVAL_SECS * 1_000) as i32).await;
                if let Err(e) = storage_clone.set_device_lock().await {
                    log_error!(logger_clone, "Error setting device lock: {e}");
                }
            }
        });

        let esplora_server_url = get_esplora_url(c.network, c.user_esplora_url);
        let esplora_clients = {
            // esplora_server_url is a space separated list of urls
            let urls = esplora_server_url.split(' ').collect::<Vec<_>>();
            let mut clients = Vec::with_capacity(urls.len());
            for url in urls {
                let client = Builder::new(url).build_async()?;
                clients.push(Arc::new(client));
            }
            clients
        };
        let esplora = MultiEsploraClient::new(esplora_clients);
        let tx_sync = Arc::new(EsploraSyncClient::from_client(
            esplora.clone(),
            logger.clone(),
        ));

        let esplora = Arc::new(esplora);
        let fee_estimator = Arc::new(MutinyFeeEstimator::new(
            storage.clone(),
            esplora.clone(),
            logger.clone(),
        ));

        let wallet = Arc::new(OnChainWallet::new(
            c.xprivkey,
            storage.clone(),
            c.network,
            esplora.clone(),
            fee_estimator.clone(),
            stop.clone(),
            logger.clone(),
        )?);

        let chain = Arc::new(MutinyChain::new(tx_sync, wallet.clone(), logger.clone()));

        let (gossip_sync, scorer) = get_gossip_sync(
            &storage,
            c.scorer_url,
            c.auth_client.clone(),
            c.network,
            logger.clone(),
        )
        .await?;

        let scorer = Arc::new(utils::Mutex::new(scorer));

        let gossip_sync = Arc::new(gossip_sync);

        // load lsp clients, if any
        let lsp_clients: Vec<LspClient> = match c.lsp_url.clone() {
            // check if string is some and not an empty string
            // and safe_mode is not enabled
            Some(lsp_urls) if !lsp_urls.is_empty() && !c.safe_mode => {
                let urls: Vec<&str> = lsp_urls.split(',').collect();

                let futs = urls.into_iter().map(|url| LspClient::new(url.trim()));

                let results = futures::future::join_all(futs).await;

                results
                    .into_iter()
                    .flat_map(|res| match res {
                        Ok(client) => Some(client),
                        Err(e) => {
                            log_warn!(logger, "Error starting up lsp client: {e}");
                            None
                        }
                    })
                    .collect()
            }
            _ => Vec::new(),
        };

        let node_storage = storage.get_nodes()?;

        let nodes = if c.safe_mode {
            // If safe mode is enabled, we don't start any nodes
            log_warn!(logger, "Safe mode enabled, not starting any nodes");
            Arc::new(Mutex::new(HashMap::new()))
        } else {
            // Remove the archived nodes, we don't need to start them up.
            let unarchived_nodes = node_storage
                .clone()
                .nodes
                .into_iter()
                .filter(|(_, n)| !n.is_archived());

            let mut nodes_map = HashMap::new();

            for node_item in unarchived_nodes {
                let node = Node::new(
                    node_item.0,
                    &node_item.1,
                    c.xprivkey,
                    storage.clone(),
                    gossip_sync.clone(),
                    scorer.clone(),
                    chain.clone(),
                    fee_estimator.clone(),
                    wallet.clone(),
                    c.network,
                    &esplora,
                    &lsp_clients,
                    logger.clone(),
                    c.do_not_connect_peers,
                    false,
                    c.skip_hodl_invoices,
                    #[cfg(target_arch = "wasm32")]
                    websocket_proxy_addr.clone(),
                )
                .await?;

                let id = node
                    .keys_manager
                    .get_node_id(Recipient::Node)
                    .expect("Failed to get node id");

                nodes_map.insert(id, Arc::new(node));
            }

            // when we create the nodes we set the LSP if one is missing
            // we need to save it to local storage after startup in case
            // a LSP was set.
            let updated_nodes: HashMap<String, NodeIndex> = nodes_map
                .values()
                .map(|n| (n._uuid.clone(), n.node_index()))
                .collect();

            log_info!(logger, "inserting updated nodes");

            storage.insert_nodes(NodeStorage {
                nodes: updated_nodes,
                version: node_storage.version + 1,
            })?;

            log_info!(logger, "inserted updated nodes");

            Arc::new(Mutex::new(nodes_map))
        };

        let lnurl_client = Arc::new(
            lnurl::Builder::default()
                .build_async()
                .expect("failed to make lnurl client"),
        );

        let (subscription_client, auth) = if let Some(auth_client) = c.auth_client {
            if let Some(subscription_url) = c.subscription_url {
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
            let auth_manager = AuthManager::new(c.xprivkey)?;
            (None, auth_manager)
        };

        let price_cache = storage
            .get_bitcoin_price_cache()?
            .into_iter()
            .map(|(k, v)| (k, (v, Duration::from_secs(0))))
            .collect();

        let nm = NodeManager {
            stop,
            xprivkey: c.xprivkey,
            network: c.network,
            wallet,
            gossip_sync,
            scorer,
            chain,
            fee_estimator,
            storage,
            node_storage: Mutex::new(node_storage),
            nodes,
            #[cfg(target_arch = "wasm32")]
            websocket_proxy_addr,
            user_rgs_url: c.user_rgs_url,
            esplora,
            auth,
            lnurl_client,
            lsp_clients,
            subscription_client,
            logger,
            bitcoin_price_cache: Arc::new(Mutex::new(price_cache)),
            do_not_connect_peers: c.do_not_connect_peers,
            safe_mode: c.safe_mode,
            skip_hodl_invoices: c.skip_hodl_invoices,
        };

        Ok(nm)
    }

    /// Returns the node with the given pubkey
    pub(crate) async fn get_node(&self, pk: &PublicKey) -> Result<Arc<Node<S>>, MutinyError> {
        let nodes = self.nodes.lock().await;
        let node = nodes.get(pk).ok_or(MutinyError::NotFound)?;
        Ok(node.clone())
    }

    /// Stops all of the nodes and background processes.
    /// Returns after node has been stopped.
    pub async fn stop(&self) -> Result<(), MutinyError> {
        self.stop.swap(true, Ordering::Relaxed);
        let mut nodes = self.nodes.lock().await;
        let node_futures = nodes.iter().map(|(_, n)| async {
            match n.stop().await {
                Ok(_) => {
                    log_debug!(self.logger, "stopped node: {}", n.pubkey.to_hex())
                }
                Err(e) => {
                    log_error!(
                        self.logger,
                        "failed to stop node {}: {e}",
                        n.pubkey.to_hex()
                    )
                }
            }
        });
        log_debug!(self.logger, "stopping all nodes");
        join_all(node_futures).await;
        nodes.clear();
        log_debug!(self.logger, "stopped all nodes");

        // stop the indexeddb object to close db connection
        if self.storage.connected().unwrap_or(false) {
            log_debug!(self.logger, "stopping storage");
            self.storage.stop();
            log_debug!(self.logger, "stopped storage");
        }

        Ok(())
    }

    /// Starts a background tasks to poll redshifts until they are ready and then start attempting payments.
    ///
    /// This function will first find redshifts that are in the [RedshiftStatus::AttemptingPayments] state and start attempting payments
    /// and redshifts that are in the [RedshiftStatus::ClosingChannels] state and finish closing channels.
    /// This is done in case the node manager was shutdown while attempting payments or closing channels.
    pub(crate) fn start_redshifts(nm: Arc<NodeManager<S>>) {
        // find AttemptingPayments redshifts and restart attempting payments
        // find ClosingChannels redshifts and restart closing channels
        // use unwrap_or_default() to handle errors
        let all = nm.storage.get_redshifts().unwrap_or_default();
        for redshift in all {
            match redshift.status {
                RedshiftStatus::AttemptingPayments => {
                    // start attempting payments
                    let nm_clone = nm.clone();
                    utils::spawn(async move {
                        if let Err(e) = nm_clone.attempt_payments(redshift).await {
                            log_error!(nm_clone.logger, "Error attempting redshift payments: {e}");
                        }
                    });
                }
                RedshiftStatus::ClosingChannels => {
                    // finish closing channels
                    let nm_clone = nm.clone();
                    utils::spawn(async move {
                        if let Err(e) = nm_clone.close_channels(redshift).await {
                            log_error!(nm_clone.logger, "Error closing redshift channels: {e}");
                        }
                    });
                }
                _ => {} // ignore other statuses
            }
        }

        utils::spawn(async move {
            loop {
                if nm.stop.load(Ordering::Relaxed) {
                    break;
                }
                // find redshifts with channels ready
                // use unwrap_or_default() to handle errors
                let all = nm.storage.get_redshifts().unwrap_or_default();
                for mut redshift in all {
                    if redshift.status == RedshiftStatus::ChannelOpened {
                        // update status
                        redshift.status = RedshiftStatus::AttemptingPayments;
                        if let Err(e) = nm.storage.persist_redshift(redshift.clone()) {
                            log_error!(nm.logger, "Error persisting redshift status update: {e}");
                        }

                        // start attempting payments
                        let payment_nm = nm.clone();
                        utils::spawn(async move {
                            if let Err(e) = payment_nm.attempt_payments(redshift).await {
                                log_error!(
                                    payment_nm.logger,
                                    "Error attempting redshift payments: {e}"
                                );
                            }
                        });
                    }
                }

                // sleep 10 seconds
                sleep(10_000).await;
            }
        });
    }

    /// Creates a background process that will sync the wallet with the blockchain.
    /// This will also update the fee estimates every 10 minutes.
    pub fn start_sync(nm: Arc<NodeManager<S>>) {
        // If we are stopped, don't sync
        if nm.stop.load(Ordering::Relaxed) {
            return;
        }

        utils::spawn(async move {
            let mut synced = false;
            loop {
                // If we are stopped, don't sync
                if nm.stop.load(Ordering::Relaxed) {
                    return;
                }

                if !synced {
                    if let Err(e) = nm.sync_rgs().await {
                        log_error!(nm.logger, "Failed to sync RGS: {e}");
                    } else {
                        log_info!(nm.logger, "RGS Synced!");
                    }
                }

                // we don't need to re-sync fees every time
                // just do it every 10 minutes
                if let Err(e) = nm.fee_estimator.update_fee_estimates_if_necessary().await {
                    log_error!(nm.logger, "Failed to update fee estimates: {e}");
                } else {
                    log_info!(nm.logger, "Updated fee estimates!");
                }

                if let Err(e) = nm.sync().await {
                    log_error!(nm.logger, "Failed to sync: {e}");
                } else if !synced {
                    // if this is the first sync, set the done_first_sync flag
                    let _ = nm.storage.set_done_first_sync();
                    synced = true;
                }

                // sleep for 1 minute, checking graceful shutdown check each 1s.
                for _ in 0..60 {
                    if nm.stop.load(Ordering::Relaxed) {
                        return;
                    }
                    sleep(1_000).await;
                }
            }
        });
    }

    /// Broadcast a transaction to the network.
    /// The transaction is broadcast through the configured esplora server.
    pub async fn broadcast_transaction(&self, tx: Transaction) -> Result<(), MutinyError> {
        self.wallet.broadcast_transaction(tx).await
    }

    /// Returns the network of the wallet.
    pub fn get_network(&self) -> Network {
        self.network
    }

    /// Gets a new bitcoin address from the wallet.
    /// Will generate a new address on every call.
    ///
    /// It is recommended to create a new address for every transaction.
    pub fn get_new_address(&self, labels: Vec<String>) -> Result<Address, MutinyError> {
        if let Ok(mut wallet) = self.wallet.wallet.try_write() {
            let address = wallet.get_address(AddressIndex::New).address;
            self.set_address_labels(address.clone(), labels)?;
            return Ok(address);
        }

        log_error!(self.logger, "Could not get wallet lock to get new address");
        Err(MutinyError::WalletOperationFailed)
    }

    /// Gets the current balance of the on-chain wallet.
    pub fn get_wallet_balance(&self) -> Result<u64, MutinyError> {
        if let Ok(wallet) = self.wallet.wallet.try_read() {
            return Ok(wallet.get_balance().total());
        }

        log_error!(
            self.logger,
            "Could not get wallet lock to get wallet balance"
        );
        Err(MutinyError::WalletOperationFailed)
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
        // If we are in safe mode, we don't create invoices
        let invoice = if self.safe_mode {
            None
        } else {
            let inv = self.create_invoice(amount, labels.clone()).await?;
            Some(inv.bolt11.ok_or(MutinyError::WalletOperationFailed)?)
        };

        let Ok(address) = self.get_new_address(labels.clone()) else {
            return Err(MutinyError::WalletOperationFailed);
        };

        Ok(MutinyBip21RawMaterials {
            address,
            invoice,
            btc_amount: amount.map(|amount| bitcoin::Amount::from_sat(amount).to_btc().to_string()),
            labels,
        })
    }

    /// Sends an on-chain transaction to the given address.
    /// The amount is in satoshis and the fee rate is in sat/vbyte.
    ///
    /// If a fee rate is not provided, one will be used from the fee estimator.
    pub async fn send_to_address(
        &self,
        send_to: Address,
        amount: u64,
        labels: Vec<String>,
        fee_rate: Option<f32>,
    ) -> Result<Txid, MutinyError> {
        if !send_to.is_valid_for_network(self.network) {
            return Err(MutinyError::IncorrectNetwork(send_to.network));
        }

        self.wallet.send(send_to, amount, labels, fee_rate).await
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
        if !send_to.is_valid_for_network(self.network) {
            return Err(MutinyError::IncorrectNetwork(send_to.network));
        }

        self.wallet.sweep(send_to, labels, fee_rate).await
    }

    /// Estimates the onchain fee for a transaction sending to the given address.
    /// The amount is in satoshis and the fee rate is in sat/vbyte.
    pub fn estimate_tx_fee(
        &self,
        destination_address: Address,
        amount: u64,
        fee_rate: Option<f32>,
    ) -> Result<u64, MutinyError> {
        self.wallet
            .estimate_tx_fee(destination_address.script_pubkey(), amount, fee_rate)
    }

    /// Estimates the onchain fee for a transaction sweep our on-chain balance
    /// to the given address.
    ///
    /// The fee rate is in sat/vbyte.
    pub fn estimate_sweep_tx_fee(
        &self,
        destination_address: Address,
        fee_rate: Option<f32>,
    ) -> Result<u64, MutinyError> {
        self.wallet
            .estimate_sweep_tx_fee(destination_address.script_pubkey(), fee_rate)
    }

    /// Estimates the onchain fee for a opening a lightning channel.
    /// The amount is in satoshis and the fee rate is in sat/vbyte.
    pub fn estimate_channel_open_fee(
        &self,
        amount: u64,
        fee_rate: Option<f32>,
    ) -> Result<u64, MutinyError> {
        // Dummy p2wsh script for the channel output
        let script = script::Builder::new()
            .push_int(0)
            .push_slice(&[0; 32])
            .into_script();
        self.wallet.estimate_tx_fee(script, amount, fee_rate)
    }

    /// Estimates the onchain fee for sweeping our on-chain balance to open a lightning channel.
    /// The fee rate is in sat/vbyte.
    pub fn estimate_sweep_channel_open_fee(
        &self,
        fee_rate: Option<f32>,
    ) -> Result<u64, MutinyError> {
        // Dummy p2wsh script for the channel output
        let script = script::Builder::new()
            .push_int(0)
            .push_slice(&[0; 32])
            .into_script();
        self.wallet.estimate_sweep_tx_fee(script, fee_rate)
    }

    /// Checks if the given address has any transactions.
    /// If it does, it returns the details of the first transaction.
    ///
    /// This should be used to check if a payment has been made to an address.
    pub async fn check_address(
        &self,
        address: &Address,
    ) -> Result<Option<TransactionDetails>, MutinyError> {
        if !address.is_valid_for_network(self.network) {
            return Err(MutinyError::IncorrectNetwork(address.network));
        }

        let script = address.payload.script_pubkey();
        let txs = self.esplora.scripthash_txs(&script, None).await?;

        let details_opt = txs.first().map(|tx| {
            let received: u64 = tx
                .vout
                .iter()
                .filter(|v| v.scriptpubkey == script)
                .map(|v| v.value)
                .sum();

            let confirmation_time = tx
                .confirmation_time()
                .map(|c| ConfirmationTime::Confirmed {
                    height: c.height,
                    time: c.timestamp,
                })
                .unwrap_or(ConfirmationTime::Unconfirmed {
                    last_seen: utils::now().as_secs(),
                });

            let address_labels = self.get_address_labels().unwrap_or_default();
            let labels = address_labels
                .get(&address.to_string())
                .cloned()
                .unwrap_or_default();

            let details = TransactionDetails {
                transaction: Some(tx.to_tx()),
                txid: tx.txid,
                received,
                sent: 0,
                fee: None,
                confirmation_time,
                labels,
            };

            let block_id = match tx.status.block_hash {
                Some(hash) => {
                    let height = tx
                        .status
                        .block_height
                        .expect("block height must be present");
                    Some(BlockId { hash, height })
                }
                None => None,
            };

            (details, block_id)
        });

        // if we found a tx we should try to import it into the wallet
        if let Some((details, block_id)) = details_opt.clone() {
            let wallet = self.wallet.clone();
            utils::spawn(async move {
                let tx = details.transaction.expect("tx must be present");
                wallet
                    .insert_tx(tx, details.confirmation_time, block_id)
                    .await
                    .expect("failed to insert tx");
            });
        }

        Ok(details_opt.map(|(d, _)| d))
    }

    /// Returns all the on-chain and lightning activity from the wallet.
    pub async fn get_activity(&self) -> Result<Vec<ActivityItem>, MutinyError> {
        // todo add contacts to the activity
        let (lightning, closures) =
            futures_util::join!(self.list_invoices(), self.list_channel_closures());
        let lightning = lightning
            .map_err(|e| {
                log_warn!(self.logger, "Failed to get lightning activity: {e}");
                e
            })
            .unwrap_or_default();
        let closures = closures
            .map_err(|e| {
                log_warn!(self.logger, "Failed to get channel closures: {e}");
                e
            })
            .unwrap_or_default();
        let onchain = self
            .list_onchain()
            .map_err(|e| {
                log_warn!(self.logger, "Failed to get bdk history: {e}");
                e
            })
            .unwrap_or_default();

        let mut activity = Vec::with_capacity(lightning.len() + onchain.len() + closures.len());
        for ln in lightning {
            // Only show paid and in-flight invoices
            match ln.status {
                HTLCStatus::Succeeded | HTLCStatus::InFlight => {
                    activity.push(ActivityItem::Lightning(Box::new(ln)));
                }
                HTLCStatus::Pending | HTLCStatus::Failed => {}
            }
        }
        for on in onchain {
            activity.push(ActivityItem::OnChain(on));
        }
        for chan in closures {
            activity.push(ActivityItem::ChannelClosed(chan));
        }

        // Newest first
        activity.sort_by(|a, b| b.cmp(a));

        Ok(activity)
    }

    /// Returns all the on-chain and lightning activity for a given label
    pub async fn get_label_activity(
        &self,
        label: &String,
    ) -> Result<Vec<ActivityItem>, MutinyError> {
        let Some(label_item) = self.get_label(label)? else {
            return Ok(Vec::new());
        };

        let mut activity = vec![];
        for inv in label_item.invoices.iter() {
            let ln = self.get_invoice(inv).await?;
            // Only show paid and in-flight invoices
            match ln.status {
                HTLCStatus::Succeeded | HTLCStatus::InFlight => {
                    activity.push(ActivityItem::Lightning(Box::new(ln)));
                }
                HTLCStatus::Pending | HTLCStatus::Failed => {}
            }
        }
        let onchain = self
            .list_onchain()
            .map_err(|e| {
                log_warn!(self.logger, "Failed to get bdk history: {e}");
                e
            })
            .unwrap_or_default();

        for on in onchain {
            if on.labels.contains(label) {
                activity.push(ActivityItem::OnChain(on));
            }
        }

        // Newest first
        activity.sort_by(|a, b| b.cmp(a));

        Ok(activity)
    }

    /// Adds labels to the TransactionDetails based on the address labels.
    /// This will panic if the TransactionDetails does not have a transaction.
    /// Make sure you flag `include_raw` when calling `list_transactions` to
    /// ensure that the transaction is included.
    fn add_onchain_labels(
        &self,
        address_labels: &HashMap<String, Vec<String>>,
        tx: bdk::TransactionDetails,
    ) -> TransactionDetails {
        // find the first output address that has a label
        let labels = tx
            .transaction
            .clone()
            .unwrap() // safe because we call with list_transactions(true)
            .output
            .iter()
            .find_map(|o| {
                if let Ok(addr) = Address::from_script(&o.script_pubkey, self.network) {
                    address_labels.get(&addr.to_string()).cloned()
                } else {
                    None
                }
            })
            .unwrap_or_default();

        TransactionDetails {
            labels,
            ..tx.into()
        }
    }

    /// Lists all the on-chain transactions in the wallet.
    /// These are sorted by confirmation time.
    pub fn list_onchain(&self) -> Result<Vec<TransactionDetails>, MutinyError> {
        let mut txs = self.wallet.list_transactions(true)?;
        txs.sort();
        let address_labels = self.get_address_labels()?;
        let txs = txs
            .into_iter()
            .map(|tx| self.add_onchain_labels(&address_labels, tx))
            .collect();

        Ok(txs)
    }

    /// Gets the details of a specific on-chain transaction.
    pub fn get_transaction(&self, txid: Txid) -> Result<Option<TransactionDetails>, MutinyError> {
        match self.wallet.get_transaction(txid, true)? {
            Some(tx) => {
                let address_labels = self.get_address_labels()?;
                let tx_details = self.add_onchain_labels(&address_labels, tx);
                Ok(Some(tx_details))
            }
            None => Ok(None),
        }
    }

    /// Gets the current balance of the wallet.
    /// This includes both on-chain and lightning funds.
    ///
    /// This will not include any funds in an unconfirmed lightning channel.
    pub async fn get_balance(&self) -> Result<MutinyBalance, MutinyError> {
        let onchain = if let Ok(wallet) = self.wallet.wallet.try_read() {
            wallet.get_balance()
        } else {
            log_error!(self.logger, "Could not get wallet lock to get balance");
            return Err(MutinyError::WalletOperationFailed);
        };

        let nodes = self.nodes.lock().await;
        let lightning_msats: u64 = nodes
            .iter()
            .flat_map(|(_, n)| n.channel_manager.list_channels())
            .map(|c| c.balance_msat)
            .sum();

        // get the amount in limbo from force closes
        let force_close: u64 = nodes
            .iter()
            .flat_map(|(_, n)| {
                let channels = n.channel_manager.list_channels();
                let ignored_channels: Vec<&ChannelDetails> = channels.iter().collect();
                n.chain_monitor.get_claimable_balances(&ignored_channels)
            })
            // need to filter out pending mutual closes, these are counted in the on-chain balance
            // comment out for now until https://github.com/lightningdevkit/rust-lightning/issues/2738
            // .filter(|b| {
            //     !matches!(
            //         b,
            //         Balance::ClaimableOnChannelClose { .. }
            //             | Balance::ClaimableAwaitingConfirmations { .. }
            //     )
            // })
            .map(|bal| bal.claimable_amount_satoshis())
            .sum();

        Ok(MutinyBalance {
            confirmed: onchain.confirmed + onchain.trusted_pending,
            unconfirmed: onchain.untrusted_pending + onchain.immature,
            lightning: lightning_msats / 1_000,
            force_close,
        })
    }

    /// Lists all the UTXOs in the wallet.
    pub fn list_utxos(&self) -> Result<Vec<LocalUtxo>, MutinyError> {
        self.wallet.list_utxos()
    }

    /// Syncs the lightning wallet with the blockchain.
    /// This will update the wallet with any lightning channels
    /// that have been opened or closed.
    ///
    /// This should be called before syncing the on-chain wallet
    /// to ensure that new on-chain transactions are picked up.
    async fn sync_ldk(&self) -> Result<(), MutinyError> {
        let nodes = self.nodes.lock().await;

        // Lock all the nodes so we can sync them, make sure we keep the locks
        // in scope so they don't get dropped and unlocked.
        let futs = nodes
            .iter()
            .map(|(_, node)| node.sync_lock.lock())
            .collect::<Vec<_>>();
        let _locks = join_all(futs).await;

        let confirmables: Vec<&(dyn Confirm)> = nodes
            .iter()
            .flat_map(|(_, node)| {
                let vec: Vec<&(dyn Confirm)> =
                    vec![node.channel_manager.deref(), node.chain_monitor.deref()];
                vec
            })
            .collect();

        self.chain
            .tx_sync
            .sync(confirmables)
            .await
            .map_err(|_e| MutinyError::ChainAccessFailed)?;

        Ok(())
    }

    /// Syncs the rapid gossip sync data.
    /// Will be skipped if in safe mode.
    async fn sync_rgs(&self) -> Result<(), MutinyError> {
        // Skip syncing RGS if we are in safe mode.
        if self.safe_mode {
            log_info!(self.logger, "Skipping rgs sync in safe mode");
        } else {
            let last_rgs_sync_timestamp = self
                .gossip_sync
                .network_graph()
                .get_last_rapid_gossip_sync_timestamp();

            if let Some(rgs_url) = get_rgs_url(
                self.network,
                self.user_rgs_url.as_deref(),
                last_rgs_sync_timestamp,
            ) {
                log_info!(self.logger, "RGS URL: {rgs_url}");

                let now = utils::now().as_secs();
                fetch_updated_gossip(
                    rgs_url,
                    now,
                    last_rgs_sync_timestamp.unwrap_or_default(),
                    &self.gossip_sync,
                    &self.storage,
                    &self.logger,
                )
                .await?;
            }
        }

        Ok(())
    }

    /// Syncs the on-chain wallet and lightning wallet.
    /// This will update the on-chain wallet with any new
    /// transactions and update the lightning wallet with
    /// any channels that have been opened or closed.
    async fn sync(&self) -> Result<(), MutinyError> {
        // If we are stopped, don't sync
        if self.stop.load(Ordering::Relaxed) {
            return Ok(());
        }

        // Sync ldk first because it may broadcast transactions
        // to addresses that are in our bdk wallet. This way
        // they are found on this iteration of syncing instead
        // of the next one.
        // Skip if we are in safe mode.
        if self.safe_mode {
            log_info!(self.logger, "Skipping ldk sync in safe mode");
        } else if let Err(e) = self.sync_ldk().await {
            log_error!(self.logger, "Failed to sync ldk: {e}");
            return Err(e);
        }

        // sync bdk wallet
        match self.wallet.sync().await {
            Ok(()) => Ok(log_info!(self.logger, "We are synced!")),
            Err(e) => {
                log_error!(self.logger, "Failed to sync on-chain wallet: {e}");
                Err(e)
            }
        }
    }

    /// Gets a fee estimate for a very low priority transaction.
    /// Value is in sat/vbyte.
    pub fn estimate_fee_low(&self) -> u32 {
        self.fee_estimator.get_low_fee_rate() / 250
    }

    /// Gets a fee estimate for an average priority transaction.
    /// Value is in sat/vbyte.
    pub fn estimate_fee_normal(&self) -> u32 {
        self.fee_estimator.get_normal_fee_rate() / 250
    }

    /// Gets a fee estimate for an high priority transaction.
    /// Value is in sat/vbyte.
    pub fn estimate_fee_high(&self) -> u32 {
        self.fee_estimator.get_high_fee_rate() / 250
    }

    /// Creates a new lightning node and adds it to the manager.
    pub async fn new_node(&self) -> Result<NodeIdentity, MutinyError> {
        if self.safe_mode {
            return Err(MutinyError::NotRunning);
        }

        create_new_node_from_node_manager(self).await
    }

    /// Archives a node so it will not be started up next time the node manager is created.
    ///
    /// If the node has any active channels it will fail to archive
    #[allow(dead_code)]
    pub(crate) async fn archive_node(&self, pubkey: PublicKey) -> Result<(), MutinyError> {
        if let Some(node) = self.nodes.lock().await.get(&pubkey) {
            // disallow archiving nodes with active channels or
            // claimable on-chain funds, so we don't lose funds
            if node.channel_manager.list_channels().is_empty()
                && node.chain_monitor.get_claimable_balances(&[]).is_empty()
            {
                self.archive_node_by_uuid(node._uuid.clone()).await
            } else {
                Err(anyhow!("Node has active channels, cannot archive").into())
            }
        } else {
            Err(anyhow!("Could not find node to archive").into())
        }
    }

    /// Archives a node so it will not be started up next time the node manager is created.
    ///
    /// If the node has any active channels it will fail to archive
    #[allow(dead_code)]
    pub(crate) async fn archive_node_by_uuid(&self, node_uuid: String) -> Result<(), MutinyError> {
        let mut node_storage = self.node_storage.lock().await;

        match node_storage.nodes.get(&node_uuid).map(|n| n.to_owned()) {
            None => Err(anyhow!("Could not find node to archive").into()),
            Some(mut node) => {
                node.archived = Some(true);
                let prev = node_storage.nodes.insert(node_uuid, node);

                // Check that we did override the previous node index
                debug_assert!(prev.is_some());

                Ok(())
            }
        }
    }

    /// Lists the pubkeys of the lightning node in the manager.
    pub async fn list_nodes(&self) -> Result<Vec<PublicKey>, MutinyError> {
        let nodes = self.nodes.lock().await;
        let peers = nodes.iter().map(|(_, n)| n.pubkey).collect();
        Ok(peers)
    }

    /// Attempts to connect to a peer from the selected node.
    pub async fn connect_to_peer(
        &self,
        self_node_pubkey: &PublicKey,
        connection_string: &str,
        label: Option<String>,
    ) -> Result<(), MutinyError> {
        if let Some(node) = self.nodes.lock().await.get(self_node_pubkey) {
            let connect_info = PubkeyConnectionInfo::new(connection_string)?;
            let label_opt = label.filter(|s| !s.is_empty()); // filter out empty strings
            let res = node.connect_peer(connect_info, label_opt).await;
            match res {
                Ok(_) => {
                    log_info!(self.logger, "connected to peer: {connection_string}");
                    return Ok(());
                }
                Err(e) => {
                    log_error!(
                        self.logger,
                        "could not connect to peer: {connection_string} - {e}"
                    );
                    return Err(e);
                }
            };
        }

        log_error!(
            self.logger,
            "could not find internal node {self_node_pubkey}"
        );
        Err(MutinyError::NotFound)
    }

    /// Disconnects from a peer from the selected node.
    pub async fn disconnect_peer(
        &self,
        self_node_pubkey: &PublicKey,
        peer: PublicKey,
    ) -> Result<(), MutinyError> {
        if let Some(node) = self.nodes.lock().await.get(self_node_pubkey) {
            node.disconnect_peer(peer);
            Ok(())
        } else {
            log_error!(
                self.logger,
                "could not find internal node {self_node_pubkey}"
            );
            Err(MutinyError::NotFound)
        }
    }

    /// Deletes a peer from the selected node.
    /// This will make it so that the node will not attempt to
    /// reconnect to the peer.
    pub async fn delete_peer(
        &self,
        self_node_pubkey: &PublicKey,
        peer: &NodeId,
    ) -> Result<(), MutinyError> {
        if let Some(node) = self.nodes.lock().await.get(self_node_pubkey) {
            gossip::delete_peer_info(&self.storage, &node._uuid, peer)?;
            Ok(())
        } else {
            log_error!(
                self.logger,
                "could not find internal node {self_node_pubkey}"
            );
            Err(MutinyError::NotFound)
        }
    }

    /// Sets the label of a peer from the selected node.
    pub fn label_peer(&self, node_id: &NodeId, label: Option<String>) -> Result<(), MutinyError> {
        gossip::set_peer_label(&self.storage, node_id, label)?;
        Ok(())
    }

    // all values in sats

    /// Creates a lightning invoice. The amount should be in satoshis.
    /// If no amount is provided, the invoice will be created with no amount.
    /// If no description is provided, the invoice will be created with no description.
    ///
    /// If the manager has more than one node it will create a phantom invoice.
    /// If there is only one node it will create an invoice just for that node.
    pub async fn create_invoice(
        &self,
        amount: Option<u64>,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        let nodes = self.nodes.lock().await;
        let use_phantom = nodes.len() > 1 && self.lsp_clients.is_empty();
        if nodes.len() == 0 {
            return Err(MutinyError::InvoiceCreationFailed);
        }
        let route_hints: Option<Vec<PhantomRouteHints>> = if use_phantom {
            Some(
                nodes
                    .iter()
                    .map(|(_, n)| n.get_phantom_route_hint())
                    .collect(),
            )
        } else {
            None
        };

        // just create a normal invoice from the first node
        let first_node = if let Some(node) = nodes.values().next() {
            node
        } else {
            return Err(MutinyError::WalletOperationFailed);
        };
        let invoice = first_node
            .create_invoice(amount, labels, route_hints)
            .await?;

        Ok(invoice.into())
    }

    /// Pays a lightning invoice from the selected node.
    /// An amount should only be provided if the invoice does not have an amount.
    /// The amount should be in satoshis.
    pub async fn pay_invoice(
        &self,
        from_node: &PublicKey,
        invoice: &Bolt11Invoice,
        amt_sats: Option<u64>,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        if invoice.network() != self.network {
            return Err(MutinyError::IncorrectNetwork(invoice.network()));
        }

        let node = self.get_node(from_node).await?;
        node.pay_invoice_with_timeout(invoice, amt_sats, None, labels)
            .await
    }

    /// Sends a spontaneous payment to a node from the selected node.
    /// The amount should be in satoshis.
    pub async fn keysend(
        &self,
        from_node: &PublicKey,
        to_node: PublicKey,
        amt_sats: u64,
        message: Option<String>,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        let node = self.get_node(from_node).await?;
        log_debug!(self.logger, "Keysending to {to_node}");
        node.keysend_with_timeout(to_node, amt_sats, message, labels, None)
            .await
    }

    /// Decodes a lightning invoice into useful information.
    /// Will return an error if the invoice is for a different network.
    pub async fn decode_invoice(
        &self,
        invoice: Bolt11Invoice,
        network: Option<Network>,
    ) -> Result<MutinyInvoice, MutinyError> {
        if invoice.network() != network.unwrap_or(self.network) {
            return Err(MutinyError::IncorrectNetwork(invoice.network()));
        }

        Ok(invoice.into())
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
        from_node: &PublicKey,
        lnurl: &LnUrl,
        amount_sats: u64,
        zap_npub: Option<XOnlyPublicKey>,
        mut labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        let response = self.lnurl_client.make_request(&lnurl.url).await?;

        match response {
            LnUrlResponse::LnUrlPayResponse(pay) => {
                let msats = amount_sats * 1000;

                // if user's npub is given, do an anon zap
                let zap_request = match zap_npub {
                    Some(zap_npub) => {
                        let tags = vec![
                            Tag::PubKey(zap_npub, None),
                            Tag::Amount(msats),
                            Tag::Lnurl(lnurl.to_string()),
                            Tag::Relays(vec!["wss://nostr.mutinywallet.com".into()]),
                            Tag::Generic(TagKind::Custom("anon".to_string()), vec![]),
                        ];
                        EventBuilder::new(Kind::ZapRequest, "", &tags)
                            .to_event(&Keys::generate())
                            .ok()
                            .map(|z| z.as_json())
                    }
                    None => None,
                };

                let invoice = self
                    .lnurl_client
                    .get_invoice(&pay, msats, zap_request, None)
                    .await?;

                let invoice = Bolt11Invoice::from_str(invoice.invoice())?;

                if invoice
                    .amount_milli_satoshis()
                    .is_some_and(|amt| msats == amt)
                {
                    // If we have a contact for this lnurl, add it to the labels as the first
                    if let Some(label) = self.get_contact_for_lnurl(lnurl)? {
                        if !labels.contains(&label) {
                            labels.insert(0, label)
                        }
                    }

                    self.pay_invoice(from_node, &invoice, None, labels).await
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
                    .create_invoice(Some(amount_sats), vec!["LNURL Withdrawal".to_string()])
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

    /// Gets an invoice from the node manager.
    /// This includes sent and received invoices.
    pub async fn get_invoice(&self, invoice: &Bolt11Invoice) -> Result<MutinyInvoice, MutinyError> {
        let nodes = self.nodes.lock().await;
        let inv_opt: Option<MutinyInvoice> =
            nodes.iter().find_map(|(_, n)| n.get_invoice(invoice).ok());
        match inv_opt {
            Some(i) => Ok(i),
            None => Err(MutinyError::NotFound),
        }
    }

    /// Gets an invoice from the node manager.
    /// This includes sent and received invoices.
    pub async fn get_invoice_by_hash(
        &self,
        hash: &sha256::Hash,
    ) -> Result<MutinyInvoice, MutinyError> {
        let nodes = self.nodes.lock().await;
        for (_, node) in nodes.iter() {
            if let Ok(inv) = node.get_invoice_by_hash(hash) {
                return Ok(inv);
            }
        }

        Err(MutinyError::NotFound)
    }

    /// Gets an invoice from the node manager.
    /// This includes sent and received invoices.
    pub async fn list_invoices(&self) -> Result<Vec<MutinyInvoice>, MutinyError> {
        let mut invoices: Vec<MutinyInvoice> = vec![];
        let nodes = self.nodes.lock().await;
        for (_, node) in nodes.iter() {
            if let Ok(mut invs) = node.list_invoices() {
                invoices.append(&mut invs)
            }
        }
        Ok(invoices)
    }

    pub async fn get_channel_closure(
        &self,
        user_channel_id: u128,
    ) -> Result<ChannelClosure, MutinyError> {
        let nodes = self.nodes.lock().await;
        for (_, node) in nodes.iter() {
            if let Ok(Some(closure)) = node.get_channel_closure(user_channel_id) {
                return Ok(closure);
            }
        }

        Err(MutinyError::NotFound)
    }

    pub async fn list_channel_closures(&self) -> Result<Vec<ChannelClosure>, MutinyError> {
        let mut channels: Vec<ChannelClosure> = vec![];
        let nodes = self.nodes.lock().await;
        for (_, node) in nodes.iter() {
            if let Ok(mut invs) = node.get_channel_closures() {
                channels.append(&mut invs)
            }
        }
        Ok(channels)
    }

    /// Opens a channel from our selected node to the given pubkey.
    /// The amount is in satoshis.
    ///
    /// The node must be online and have a connection to the peer.
    /// The wallet much have enough funds to open the channel.
    pub async fn open_channel(
        &self,
        from_node: &PublicKey,
        to_pubkey: Option<PublicKey>,
        amount: u64,
        fee_rate: Option<f32>,
        user_channel_id: Option<u128>,
    ) -> Result<MutinyChannel, MutinyError> {
        let node = self.get_node(from_node).await?;

        let to_pubkey = match to_pubkey {
            Some(pubkey) => pubkey,
            None => {
                node.lsp_client
                    .as_ref()
                    .ok_or(MutinyError::PubkeyInvalid)?
                    .pubkey
            }
        };

        let outpoint = node
            .open_channel_with_timeout(to_pubkey, amount, fee_rate, user_channel_id, 60)
            .await?;

        let all_channels = node.channel_manager.list_channels();
        let found_channel = all_channels
            .iter()
            .find(|chan| chan.funding_txo.map(|a| a.into_bitcoin_outpoint()) == Some(outpoint));

        match found_channel {
            Some(channel) => Ok(channel.into()),
            None => Err(MutinyError::ChannelCreationFailed), // what should we do here?
        }
    }

    /// Opens a channel from our selected node to the given pubkey.
    /// It will spend the given utxos in full to fund the channel.
    ///
    /// The node must be online and have a connection to the peer.
    /// The UTXOs must all exist in the wallet.
    pub async fn sweep_utxos_to_channel(
        &self,
        user_chan_id: Option<u128>,
        from_node: &PublicKey,
        utxos: &[OutPoint],
        to_pubkey: Option<PublicKey>,
    ) -> Result<MutinyChannel, MutinyError> {
        let node = self.get_node(from_node).await?;

        let to_pubkey = match to_pubkey {
            Some(pubkey) => pubkey,
            None => {
                node.lsp_client
                    .as_ref()
                    .ok_or(MutinyError::PubkeyInvalid)?
                    .pubkey
            }
        };

        let outpoint = node
            .sweep_utxos_to_channel_with_timeout(user_chan_id, utxos, to_pubkey, 60)
            .await?;

        let all_channels = node.channel_manager.list_channels();
        let found_channel = all_channels
            .iter()
            .find(|chan| chan.funding_txo.map(|a| a.into_bitcoin_outpoint()) == Some(outpoint));

        match found_channel {
            Some(channel) => Ok(channel.into()),
            None => Err(MutinyError::ChannelCreationFailed), // what should we do here?
        }
    }

    /// Opens a channel from our selected node to the given pubkey.
    /// It will spend the all the on-chain utxo in full to fund the channel.
    ///
    /// The node must be online and have a connection to the peer.
    pub async fn sweep_all_to_channel(
        &self,
        user_chan_id: Option<u128>,
        from_node: &PublicKey,
        to_pubkey: Option<PublicKey>,
    ) -> Result<MutinyChannel, MutinyError> {
        let utxos = self
            .list_utxos()?
            .iter()
            .map(|u| u.outpoint)
            .collect::<Vec<_>>();

        self.sweep_utxos_to_channel(user_chan_id, from_node, &utxos, to_pubkey)
            .await
    }

    /// Closes a channel with the given outpoint.
    ///
    /// If force is true, the channel will be force closed.
    ///
    /// If abandon is true, the channel will be abandoned.
    /// This will force close without broadcasting the latest transaction.
    /// This should only be used if the channel will never actually be opened.
    ///
    /// If both force and abandon are true, an error will be returned.
    pub async fn close_channel(
        &self,
        outpoint: &OutPoint,
        address: Option<Address>,
        force: bool,
        abandon: bool,
    ) -> Result<(), MutinyError> {
        if force && abandon {
            return Err(MutinyError::ChannelClosingFailed);
        }

        let nodes = self.nodes.lock().await;
        let channel_opt: Option<(Arc<Node<S>>, ChannelDetails)> =
            nodes.iter().find_map(|(_, n)| {
                n.channel_manager
                    .list_channels()
                    .iter()
                    .find(|c| c.funding_txo.map(|f| f.into_bitcoin_outpoint()) == Some(*outpoint))
                    .map(|c| (n.clone(), c.clone()))
            });

        match channel_opt {
            Some((node, channel)) => {
                if force {
                    node.channel_manager
                        .force_close_broadcasting_latest_txn(
                            &channel.channel_id,
                            &channel.counterparty.node_id,
                        )
                        .map_err(|e| {
                            log_error!(
                                self.logger,
                                "had an error force closing channel {} with node {} : {e:?}",
                                &channel.channel_id.to_hex(),
                                &channel.counterparty.node_id.to_hex()
                            );
                            MutinyError::ChannelClosingFailed
                        })?;
                } else if abandon {
                    node.channel_manager
                        .force_close_without_broadcasting_txn(
                            &channel.channel_id,
                            &channel.counterparty.node_id,
                        )
                        .map_err(|e| {
                            log_error!(
                                self.logger,
                                "had an error abandoning closing channel {} with node {} : {e:?}",
                                &channel.channel_id.to_hex(),
                                &channel.counterparty.node_id.to_hex()
                            );
                            MutinyError::ChannelClosingFailed
                        })?;
                } else {
                    // convert address to ShutdownScript
                    let shutdown_script = if let Some(addr) = address {
                        Some(ShutdownScript::try_from(addr.script_pubkey())?)
                    } else {
                        None
                    };

                    // ldk uses background fee rate for closing channels which can be very slow
                    // so we use normal fee rate instead
                    let fee_rate = self.wallet.fees.get_normal_fee_rate();

                    node.channel_manager
                        .close_channel_with_feerate_and_script(
                            &channel.channel_id,
                            &channel.counterparty.node_id,
                            Some(fee_rate),
                            shutdown_script,
                        )
                        .map_err(|e| {
                            log_error!(
                                self.logger,
                                "had an error closing channel {} with node {} : {e:?}",
                                &channel.channel_id.to_hex(),
                                &channel.counterparty.node_id.to_hex()
                            );
                            MutinyError::ChannelClosingFailed
                        })?;
                }

                Ok(())
            }
            None => {
                log_error!(
                    self.logger,
                    "Channel not found with this transaction: {outpoint}",
                );
                Err(MutinyError::NotFound)
            }
        }
    }

    /// Lists all the channels for all the nodes in the node manager.
    pub async fn list_channels(&self) -> Result<Vec<MutinyChannel>, MutinyError> {
        let nodes = self.nodes.lock().await;
        let channels: Vec<ChannelDetails> = nodes
            .iter()
            .flat_map(|(_, n)| n.channel_manager.list_channels())
            .collect();

        let mutiny_channels: Vec<MutinyChannel> =
            channels.iter().map(MutinyChannel::from).collect();

        Ok(mutiny_channels)
    }

    /// Lists all the peers for all the nodes in the node manager.
    pub async fn list_peers(&self) -> Result<Vec<MutinyPeer>, MutinyError> {
        let peer_data = gossip::get_all_peers(&self.storage)?;

        // get peers saved in storage
        let mut storage_peers: Vec<MutinyPeer> = peer_data
            .iter()
            .map(|(node_id, metadata)| MutinyPeer {
                // node id should be safe here
                pubkey: PublicKey::from_slice(node_id.as_slice()).expect("Invalid pubkey"),
                connection_string: metadata.connection_string.clone(),
                alias: metadata.alias.clone(),
                color: metadata.color.clone(),
                label: metadata.label.clone(),
                is_connected: false,
            })
            .collect();

        let nodes = self.nodes.lock().await;

        // get peers we are connected to
        let connected_peers: Vec<PublicKey> = nodes
            .iter()
            .flat_map(|(_, n)| n.peer_manager.get_peer_node_ids())
            .collect();

        // correctly set is_connected
        for peer in &mut storage_peers {
            if connected_peers.contains(&peer.pubkey) {
                peer.is_connected = true;
            }
        }

        // add any connected peers that weren't in our storage,
        // likely new or inbound connections
        let mut missing: Vec<MutinyPeer> = Vec::new();
        for peer in connected_peers {
            if !storage_peers.iter().any(|p| p.pubkey == peer) {
                let new = MutinyPeer {
                    pubkey: peer,
                    connection_string: None,
                    alias: None,
                    color: None,
                    label: None,
                    is_connected: true,
                };
                missing.push(new);
            }
        }

        storage_peers.append(&mut missing);
        storage_peers.sort();

        Ok(storage_peers)
    }

    /// Checks whether or not the user is subscribed to Mutiny+.
    ///
    /// Returns None if there's no subscription at all.
    /// Returns Some(u64) for their unix expiration timestamp, which may be in the
    /// past or in the future, depending on whether or not it is currently active.
    pub(crate) async fn check_subscribed(&self) -> Result<Option<u64>, MutinyError> {
        if let Some(subscription_client) = self.subscription_client.clone() {
            Ok(subscription_client.check_subscribed().await?)
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

    /// Gets the current bitcoin price in USD.
    pub async fn get_bitcoin_price(&self, fiat: Option<String>) -> Result<f32, MutinyError> {
        let now = crate::utils::now();
        let fiat = fiat.unwrap_or("usd".to_string());

        let cache_result = {
            let cache = self.bitcoin_price_cache.lock().await;
            cache.get(&fiat).cloned()
        };

        match cache_result {
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
        }
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
        let api_url = format!(
            "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies={}",
            fiat
        );

        let client = Client::builder()
            .build()
            .map_err(|_| MutinyError::BitcoinPriceError)?;

        let request = client
            .get(api_url)
            .build()
            .map_err(|_| MutinyError::BitcoinPriceError)?;

        let resp: reqwest::Response = utils::fetch_with_timeout(&client, request).await?;

        let response: CoingeckoResponse = resp
            .error_for_status()
            .map_err(|_| MutinyError::BitcoinPriceError)?
            .json()
            .await
            .map_err(|_| MutinyError::BitcoinPriceError)?;

        if let Some(price) = response.bitcoin.get(fiat) {
            Ok(*price)
        } else {
            Err(MutinyError::BitcoinPriceError)
        }
    }

    /// Retrieves the logs from storage.
    pub fn get_logs(
        storage: S,
        logger: Arc<MutinyLogger>,
    ) -> Result<Option<Vec<String>>, MutinyError> {
        logger.get_logs(&storage)
    }

    /// Resets the scorer and network graph. This can be useful if you get stuck in a bad state.
    pub async fn reset_router(&self) -> Result<(), MutinyError> {
        // if we're not connected to the db, start it up
        let needs_db_connection = !self.storage.clone().connected().unwrap_or(true);
        if needs_db_connection {
            self.storage.clone().start().await?;
        }

        // delete all the keys we use to store routing data
        self.storage
            .delete(&[GOSSIP_SYNC_TIME_KEY, NETWORK_GRAPH_KEY, PROB_SCORER_KEY])?;

        // shut back down after reading if it was already closed
        if needs_db_connection {
            self.storage.clone().stop();
        }

        Ok(())
    }

    /// Resets BDK's keychain tracker. This will require a re-sync of the blockchain.
    ///
    /// This can be useful if you get stuck in a bad state.
    pub async fn reset_onchain_tracker(&self) -> Result<(), MutinyError> {
        // if we're not connected to the db, start it up
        let needs_db_connection = !self.storage.clone().connected().unwrap_or(true);
        if needs_db_connection {
            self.storage.clone().start().await?;
        }

        // delete the bdk keychain store
        self.storage.delete(&[KEYCHAIN_STORE_KEY])?;
        self.storage.set_data(NEED_FULL_SYNC_KEY, true, None)?;

        // shut back down after reading if it was already closed
        if needs_db_connection {
            self.storage.clone().stop();
        }

        Ok(())
    }

    /// Exports the current state of the node manager to a json object.
    pub async fn export_json(storage: S) -> Result<Value, MutinyError> {
        let needs_db_connection = !storage.clone().connected().unwrap_or(true);
        if needs_db_connection {
            storage.clone().start().await?;
        }

        // get all the data from storage, scanning with prefix "" will get all keys
        let map = storage.scan("", None)?;
        let serde_map = serde_json::map::Map::from_iter(map.into_iter().filter(|(k, _)| {
            // filter out logs and network graph
            // these are really big and not needed for export
            // filter out device id so a new one is generated
            !matches!(
                k.as_str(),
                LOGGING_KEY | NETWORK_GRAPH_KEY | PROB_SCORER_KEY | DEVICE_ID_KEY
            )
        }));

        // shut back down after reading if it was already closed
        if needs_db_connection {
            storage.clone().stop();
        }

        Ok(Value::Object(serde_map))
    }
}

#[derive(Deserialize, Clone, Debug)]
struct CoingeckoResponse {
    pub bitcoin: HashMap<String, f32>,
}

// This will create a new node with a node manager and return the PublicKey of the node created.
pub(crate) async fn create_new_node_from_node_manager<S: MutinyStorage>(
    node_manager: &NodeManager<S>,
) -> Result<NodeIdentity, MutinyError> {
    // Begin with a mutex lock so that nothing else can
    // save or alter the node list while it is about to
    // be saved.
    let mut node_mutex = node_manager.node_storage.lock().await;

    // Get the current nodes and their bip32 indices
    // so that we can create another node with the next.
    // Always get it from our storage, the node_mutex is
    // mostly for read only and locking.
    let mut existing_nodes = node_manager.storage.get_nodes()?;
    let next_node_index = match existing_nodes
        .nodes
        .iter()
        .max_by_key(|(_, v)| v.child_index)
    {
        None => 0,
        Some((_, v)) => v.child_index + 1,
    };

    // Create and save a new node using the next child index
    let next_node_uuid = Uuid::new_v4().to_string();

    let lsp = if node_manager.lsp_clients.is_empty() {
        log_info!(
            node_manager.logger,
            "no lsp saved and no lsp clients available"
        );
        None
    } else {
        log_info!(node_manager.logger, "no lsp saved, picking random one");
        // If we don't have an lsp saved we should pick a random
        // one from our client list and save it for next time
        let rand = rand::random::<usize>() % node_manager.lsp_clients.len();
        Some(LspConfig::VoltageFlow(
            node_manager.lsp_clients[rand].url.clone(),
        ))
    };

    let next_node = NodeIndex {
        child_index: next_node_index,
        lsp,
        archived: Some(false),
    };

    existing_nodes.version += 1;
    existing_nodes
        .nodes
        .insert(next_node_uuid.clone(), next_node.clone());

    node_manager.storage.insert_nodes(existing_nodes.clone())?;
    node_mutex.nodes = existing_nodes.nodes.clone();

    // now create the node process and init it
    let new_node_res = Node::new(
        next_node_uuid.clone(),
        &next_node,
        node_manager.xprivkey,
        node_manager.storage.clone(),
        node_manager.gossip_sync.clone(),
        node_manager.scorer.clone(),
        node_manager.chain.clone(),
        node_manager.fee_estimator.clone(),
        node_manager.wallet.clone(),
        node_manager.network,
        &node_manager.esplora,
        &node_manager.lsp_clients,
        node_manager.logger.clone(),
        node_manager.do_not_connect_peers,
        false,
        node_manager.skip_hodl_invoices,
        #[cfg(target_arch = "wasm32")]
        node_manager.websocket_proxy_addr.clone(),
    )
    .await;

    let new_node = match new_node_res {
        Ok(new_node) => new_node,
        Err(e) => return Err(e),
    };

    let node_pubkey = new_node.pubkey;
    node_manager
        .nodes
        .clone()
        .lock()
        .await
        .insert(node_pubkey, Arc::new(new_node));

    Ok(NodeIdentity {
        uuid: next_node_uuid.clone(),
        pubkey: node_pubkey,
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        encrypt::encryption_key_from_pass,
        nodemanager::{
            ActivityItem, ChannelClosure, MutinyInvoice, NodeManager, TransactionDetails,
        },
    };
    use crate::{keymanager::generate_seed, MutinyWalletConfig};
    use bdk::chain::ConfirmationTime;
    use bitcoin::hashes::hex::{FromHex, ToHex};
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::PublicKey;
    use bitcoin::util::bip32::ExtendedPrivKey;
    use bitcoin::{Network, PackedLockTime, Transaction, TxOut, Txid};
    use lightning::ln::PaymentHash;
    use lightning_invoice::Bolt11Invoice;
    use std::collections::HashMap;
    use std::str::FromStr;

    use crate::test_utils::*;

    use crate::event::{HTLCStatus, MillisatAmount, PaymentInfo};
    use crate::nodemanager::{LspConfig, NodeIndex, NodeStorage};
    use crate::storage::{MemoryStorage, MutinyStorage};
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    const BOLT_11: &str = "lntbs1m1pjrmuu3pp52hk0j956d7s8azaps87amadshnrcvqtkvk06y2nue2w69g6e5vasdqqcqzpgxqyz5vqsp5wu3py6257pa3yzarw0et2200c08r5fu6k3u94yfwmlnc8skdkc9s9qyyssqc783940p82c64qq9pu3xczt4tdxzex9wpjn54486y866aayft2cxxusl9eags4cs3kcmuqdrvhvs0gudpj5r2a6awu4wcq29crpesjcqhdju55";

    #[test]
    async fn create_node_manager() {
        let test_name = "create_node_manager";
        log!("{}", test_name);
        let seed = generate_seed(12).unwrap();
        let xpriv = ExtendedPrivKey::new_master(Network::Regtest, &seed.to_seed("")).unwrap();

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher), None);

        assert!(!NodeManager::has_node_manager(storage.clone()));
        let c = MutinyWalletConfig::new(
            xpriv,
            #[cfg(target_arch = "wasm32")]
            None,
            Network::Regtest,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            true,
        );
        NodeManager::new(c, storage.clone(), None)
            .await
            .expect("node manager should initialize");
        storage.insert_mnemonic(seed).unwrap();
        assert!(NodeManager::has_node_manager(storage));
    }

    #[test]
    async fn created_new_nodes() {
        let test_name = "created_new_nodes";
        log!("{}", test_name);

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher), None);
        let seed = generate_seed(12).expect("Failed to gen seed");
        let xpriv = ExtendedPrivKey::new_master(Network::Regtest, &seed.to_seed("")).unwrap();
        let c = MutinyWalletConfig::new(
            xpriv,
            #[cfg(target_arch = "wasm32")]
            None,
            Network::Regtest,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            true,
        );
        let nm = NodeManager::new(c, storage, None)
            .await
            .expect("node manager should initialize");

        {
            let node_identity = nm.new_node().await.expect("should create new node");
            let node_storage = nm.node_storage.lock().await;
            assert_ne!("", node_identity.uuid);
            assert_ne!("", node_identity.pubkey.to_string());
            assert_eq!(1, node_storage.nodes.len());

            let retrieved_node = node_storage.nodes.get(&node_identity.uuid).unwrap();
            assert_eq!(0, retrieved_node.child_index);
        }

        {
            let node_identity = nm.new_node().await.expect("node manager should initialize");
            let node_storage = nm.node_storage.lock().await;

            assert_ne!("", node_identity.uuid);
            assert_ne!("", node_identity.pubkey.to_string());
            assert_eq!(2, node_storage.nodes.len());

            let retrieved_node = node_storage.nodes.get(&node_identity.uuid).unwrap();
            assert_eq!(1, retrieved_node.child_index);
        }
    }

    #[test]
    async fn safe_mode_tests() {
        let test_name = "safe_mode_tests";
        log!("{}", test_name);

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher), None);
        let seed = generate_seed(12).expect("Failed to gen seed");
        let xpriv = ExtendedPrivKey::new_master(Network::Regtest, &seed.to_seed("")).unwrap();
        let c = MutinyWalletConfig::new(
            xpriv,
            #[cfg(target_arch = "wasm32")]
            None,
            Network::Regtest,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            true,
        );
        let c = c.with_safe_mode();

        let nm = NodeManager::new(c, storage, None)
            .await
            .expect("node manager should initialize");

        let bip21 = nm.create_bip21(None, vec![]).await.unwrap();
        assert!(bip21.invoice.is_none());

        let new_node = nm.new_node().await;
        assert!(new_node.is_err());
    }

    #[test]
    async fn created_label_transaction() {
        let test_name = "created_new_nodes";
        log!("{}", test_name);

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher), None);
        let seed = generate_seed(12).expect("Failed to gen seed");
        let xpriv = ExtendedPrivKey::new_master(Network::Regtest, &seed.to_seed("")).unwrap();
        let c = MutinyWalletConfig::new(
            xpriv,
            #[cfg(target_arch = "wasm32")]
            None,
            Network::Signet,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            true,
        );
        let nm = NodeManager::new(c, storage, None)
            .await
            .expect("node manager should initialize");

        let labels = vec![String::from("label1"), String::from("label2")];

        let address = nm
            .get_new_address(labels.clone())
            .expect("should create new address");

        let fake_tx = Transaction {
            version: 2,
            lock_time: PackedLockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: 1_000_000,
                script_pubkey: address.script_pubkey(),
            }],
        };

        // insert fake tx into wallet
        {
            let mut wallet = nm.wallet.wallet.try_write().unwrap();
            wallet
                .insert_tx(
                    fake_tx.clone(),
                    ConfirmationTime::Unconfirmed { last_seen: 0 },
                )
                .unwrap();
            wallet.commit().unwrap();
        }

        let txs = nm.list_onchain().expect("should list onchain txs");
        let tx_opt = nm
            .get_transaction(fake_tx.txid())
            .expect("should get transaction");

        assert_eq!(txs.len(), 1);
        let tx = &txs[0];
        assert_eq!(tx.txid, fake_tx.txid());
        assert_eq!(tx.labels, labels);

        assert!(tx_opt.is_some());
        let tx = tx_opt.unwrap();
        assert_eq!(tx.txid, fake_tx.txid());
        assert_eq!(tx.labels, labels);
    }

    #[test]
    fn test_bolt11_payment_info_into_mutiny_invoice() {
        let preimage: [u8; 32] =
            FromHex::from_hex("7600f5a9ad72452dea7ad86dabbc9cb46be96a1a2fcd961e041d066b38d93008")
                .unwrap();
        let secret: [u8; 32] =
            FromHex::from_hex("7722126954f07b120ba373f2b529efc3ce3a279ab4785a912edfe783c2cdb60b")
                .unwrap();

        let payment_hash = sha256::Hash::from_hex(
            "55ecf9169a6fa07e8ba181fdddf5b0bcc7860176659fa22a7cca9da2a359a33b",
        )
        .unwrap();

        let invoice = Bolt11Invoice::from_str(BOLT_11).unwrap();

        let labels = vec!["label1".to_string(), "label2".to_string()];

        let payment_info = PaymentInfo {
            preimage: Some(preimage),
            secret: Some(secret),
            status: HTLCStatus::Succeeded,
            amt_msat: MillisatAmount(Some(100_000_000)),
            fee_paid_msat: None,
            bolt11: Some(invoice.clone()),
            payee_pubkey: None,
            last_update: 1681781585,
        };

        let expected: MutinyInvoice = MutinyInvoice {
            bolt11: Some(invoice),
            description: None,
            payment_hash,
            preimage: Some(preimage.to_hex()),
            payee_pubkey: None,
            amount_sats: Some(100_000),
            expire: 1681781649 + 86400,
            status: HTLCStatus::Succeeded,
            fees_paid: None,
            inbound: true,
            labels: labels.clone(),
            last_updated: 1681781585,
        };

        let actual = MutinyInvoice::from(
            payment_info,
            PaymentHash(payment_hash.into_inner()),
            true,
            labels,
        )
        .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_keysend_payment_info_into_mutiny_invoice() {
        let preimage: [u8; 32] =
            FromHex::from_hex("7600f5a9ad72452dea7ad86dabbc9cb46be96a1a2fcd961e041d066b38d93008")
                .unwrap();

        let payment_hash = sha256::Hash::from_hex(
            "55ecf9169a6fa07e8ba181fdddf5b0bcc7860176659fa22a7cca9da2a359a33b",
        )
        .unwrap();

        let pubkey = PublicKey::from_str(
            "02465ed5be53d04fde66c9418ff14a5f2267723810176c9212b722e542dc1afb1b",
        )
        .unwrap();

        let payment_info = PaymentInfo {
            preimage: Some(preimage),
            secret: None,
            status: HTLCStatus::Succeeded,
            amt_msat: MillisatAmount(Some(100_000)),
            fee_paid_msat: Some(1_000),
            bolt11: None,
            payee_pubkey: Some(pubkey),
            last_update: 1681781585,
        };

        let expected: MutinyInvoice = MutinyInvoice {
            bolt11: None,
            description: None,
            payment_hash,
            preimage: Some(preimage.to_hex()),
            payee_pubkey: Some(pubkey),
            amount_sats: Some(100),
            expire: 1681781585,
            status: HTLCStatus::Succeeded,
            fees_paid: Some(1),
            inbound: false,
            labels: vec![],
            last_updated: 1681781585,
        };

        let actual = MutinyInvoice::from(
            payment_info,
            PaymentHash(payment_hash.into_inner()),
            false,
            vec![],
        )
        .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_serialize_node_storage() {
        let old: NodeStorage = serde_json::from_str("{\"nodes\":{\"93ca1ee3-d5f1-42ed-8bd9-042b298c70dc\":{\"archived\":false,\"child_index\":0,\"lsp\":\"https://signet-lsp.mutinywallet.com\"}},\"version\":11}").unwrap();
        let node = NodeIndex {
            child_index: 0,
            lsp: Some(LspConfig::VoltageFlow(
                "https://signet-lsp.mutinywallet.com".to_string(),
            )),
            archived: Some(false),
        };
        let mut nodes = HashMap::new();
        nodes.insert("93ca1ee3-d5f1-42ed-8bd9-042b298c70dc".to_string(), node);
        let expected = NodeStorage { nodes, version: 11 };

        assert_eq!(old, expected);

        let serialized = serde_json::to_string(&expected).unwrap();
        let deserialized: NodeStorage = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, expected);
    }

    #[test]
    fn test_sort_activity_item() {
        let preimage: [u8; 32] =
            FromHex::from_hex("7600f5a9ad72452dea7ad86dabbc9cb46be96a1a2fcd961e041d066b38d93008")
                .unwrap();

        let payment_hash = sha256::Hash::from_hex(
            "55ecf9169a6fa07e8ba181fdddf5b0bcc7860176659fa22a7cca9da2a359a33b",
        )
        .unwrap();

        let pubkey = PublicKey::from_str(
            "02465ed5be53d04fde66c9418ff14a5f2267723810176c9212b722e542dc1afb1b",
        )
        .unwrap();

        let closure: ChannelClosure = ChannelClosure {
            user_channel_id: None,
            channel_id: None,
            node_id: None,
            reason: "".to_string(),
            timestamp: 1686258926,
        };

        let tx1: TransactionDetails = TransactionDetails {
            transaction: None,
            txid: Txid::all_zeros(),
            received: 0,
            sent: 0,
            fee: None,
            confirmation_time: ConfirmationTime::Unconfirmed { last_seen: 0_u64 },
            labels: vec![],
        };

        let tx2: TransactionDetails = TransactionDetails {
            transaction: None,
            txid: Txid::all_zeros(),
            received: 0,
            sent: 0,
            fee: None,
            confirmation_time: ConfirmationTime::Confirmed {
                height: 1,
                time: 1234,
            },
            labels: vec![],
        };

        let invoice1: MutinyInvoice = MutinyInvoice {
            bolt11: None,
            description: None,
            payment_hash,
            preimage: Some(preimage.to_hex()),
            payee_pubkey: Some(pubkey),
            amount_sats: Some(100),
            expire: 1681781585,
            status: HTLCStatus::Succeeded,
            fees_paid: Some(1),
            inbound: false,
            labels: vec![],
            last_updated: 1681781585,
        };

        let invoice2: MutinyInvoice = MutinyInvoice {
            bolt11: None,
            description: None,
            payment_hash,
            preimage: Some(preimage.to_hex()),
            payee_pubkey: Some(pubkey),
            amount_sats: Some(100),
            expire: 1681781585,
            status: HTLCStatus::Succeeded,
            fees_paid: Some(1),
            inbound: false,
            labels: vec![],
            last_updated: 1781781585,
        };

        let invoice3: MutinyInvoice = MutinyInvoice {
            bolt11: None,
            description: None,
            payment_hash,
            preimage: None,
            payee_pubkey: Some(pubkey),
            amount_sats: Some(101),
            expire: 1581781585,
            status: HTLCStatus::InFlight,
            fees_paid: None,
            inbound: false,
            labels: vec![],
            last_updated: 1581781585,
        };

        let invoice4: MutinyInvoice = MutinyInvoice {
            bolt11: None,
            description: None,
            payment_hash,
            preimage: None,
            payee_pubkey: Some(pubkey),
            amount_sats: Some(102),
            expire: 1581781585,
            status: HTLCStatus::InFlight,
            fees_paid: None,
            inbound: false,
            labels: vec![],
            last_updated: 1581781585,
        };

        let invoice5: MutinyInvoice = MutinyInvoice {
            bolt11: None,
            description: Some("difference".to_string()),
            payment_hash,
            preimage: Some(preimage.to_hex()),
            payee_pubkey: Some(pubkey),
            amount_sats: Some(100),
            expire: 1681781585,
            status: HTLCStatus::Succeeded,
            fees_paid: Some(1),
            inbound: false,
            labels: vec![],
            last_updated: 1781781585,
        };

        let mut vec = vec![
            ActivityItem::OnChain(tx1.clone()),
            ActivityItem::OnChain(tx2.clone()),
            ActivityItem::Lightning(Box::new(invoice1.clone())),
            ActivityItem::Lightning(Box::new(invoice2.clone())),
            ActivityItem::Lightning(Box::new(invoice3.clone())),
            ActivityItem::Lightning(Box::new(invoice4.clone())),
            ActivityItem::Lightning(Box::new(invoice5.clone())),
            ActivityItem::ChannelClosed(closure.clone()),
        ];
        vec.sort();

        assert_eq!(
            vec,
            vec![
                ActivityItem::OnChain(tx2),
                ActivityItem::Lightning(Box::new(invoice1)),
                ActivityItem::ChannelClosed(closure),
                ActivityItem::Lightning(Box::new(invoice5)),
                ActivityItem::Lightning(Box::new(invoice2)),
                ActivityItem::OnChain(tx1),
                ActivityItem::Lightning(Box::new(invoice3)),
                ActivityItem::Lightning(Box::new(invoice4)),
            ]
        );
    }
}
