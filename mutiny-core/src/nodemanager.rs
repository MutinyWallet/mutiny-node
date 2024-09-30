use crate::labels::LabelStorage;
use crate::ldkstorage::CHANNEL_CLOSURE_PREFIX;
use crate::logging::LOGGING_KEY;
use crate::lsp::voltage;
use crate::utils::{sleep, spawn};
use crate::MutinyInvoice;
use crate::MutinyWalletConfig;
use crate::{auth::MutinyAuthClient, TransactionDetails};
use crate::{
    chain::MutinyChain,
    error::MutinyError,
    fees::MutinyFeeEstimator,
    gossip,
    gossip::{fetch_updated_gossip, get_rgs_url},
    logging::MutinyLogger,
    lsp::{deserialize_lsp_config, Lsp, LspConfig},
    node::{Node, PubkeyConnectionInfo, RapidGossipSync},
    onchain::get_esplora_url,
    onchain::OnChainWallet,
    utils,
};
use crate::{gossip::*, scorer::HubPreferentialScorer};
use crate::{
    node::NodeBuilder,
    storage::{MutinyStorage, DEVICE_ID_KEY, KEYCHAIN_STORE_KEY, NEED_FULL_SYNC_KEY},
};
use anyhow::anyhow;
use async_lock::RwLock;
use bdk::chain::{BlockId, ConfirmationTime};
use bdk::{wallet::AddressIndex, LocalOutput};
use bitcoin::address::NetworkUnchecked;
use bitcoin::bip32::ExtendedPrivKey;
use bitcoin::blockdata::script;
use bitcoin::hashes::hex::FromHex;

use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, Network, OutPoint, Transaction, Txid};
use esplora_client::{AsyncClient, Builder};
use futures::future::join_all;
use hex_conservative::DisplayHex;
use lightning::chain::Confirm;
use lightning::events::ClosureReason;
use lightning::ln::channelmanager::{ChannelDetails, PhantomRouteHints};
use lightning::ln::script::ShutdownScript;
use lightning::ln::ChannelId;
use lightning::routing::gossip::NodeId;
use lightning::sign::{NodeSigner, Recipient};
use lightning::util::logger::*;
use lightning::{log_debug, log_error, log_info, log_trace, log_warn};
use lightning_invoice::Bolt11Invoice;
use lightning_transaction_sync::EsploraSyncClient;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::max;

use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;
use std::{collections::HashMap, ops::Deref, sync::Arc};
use url::Url;
#[cfg(target_arch = "wasm32")]
use web_time::Instant;

// This is the NodeStorage object saved to the DB
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct NodeStorage {
    pub nodes: HashMap<String, NodeIndex>,
    #[serde(default)]
    pub version: u32,
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

#[derive(Serialize, Clone, Eq, PartialEq)]
pub struct MutinyBip21RawMaterials {
    pub address: Address,
    pub invoice: Option<Bolt11Invoice>,
    pub btc_amount: Option<String>,
    pub labels: Vec<String>,
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
    pub inbound: u64,
    pub outpoint: Option<OutPoint>,
    pub peer: PublicKey,
    pub confirmations_required: Option<u32>,
    pub confirmations: u32,
    pub is_outbound: bool,
    pub is_usable: bool,
    pub is_anchor: bool,
}

impl From<&ChannelDetails> for MutinyChannel {
    fn from(c: &ChannelDetails) -> Self {
        let size = c.channel_value_satoshis;
        let balance = c.next_outbound_htlc_limit_msat / 1_000;
        let inbound = c.inbound_capacity_msat / 1_000;

        // Don't calculate reserve, just make it what we didn't
        // account for in balance and inbound
        let reserve = size - (balance + inbound);

        let is_anchor = c
            .channel_type
            .as_ref()
            .map(|t| t.supports_anchors_zero_fee_htlc_tx())
            .unwrap_or(false);

        MutinyChannel {
            user_chan_id: c.user_channel_id.to_be_bytes().to_lower_hex_string(),
            balance,
            size,
            reserve,
            inbound,
            outpoint: c.funding_txo.map(|f| f.into_bitcoin_outpoint()),
            peer: c.counterparty.node_id,
            confirmations_required: c.confirmations_required,
            confirmations: c.confirmations.unwrap_or(0),
            is_outbound: c.is_outbound,
            is_usable: c.is_usable,
            is_anchor,
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

    pub(crate) fn set_user_channel_id_from_key(&mut self, key: &str) -> Result<(), MutinyError> {
        if self.user_channel_id.is_some() {
            return Ok(());
        }

        // convert keys to u128
        let user_channel_id_str = key
            .trim_start_matches(CHANNEL_CLOSURE_PREFIX)
            .splitn(2, '_') // Channel closures have `_{node_id}` at the end
            .collect::<Vec<&str>>()[0];
        let user_channel_id: [u8; 16] = FromHex::from_hex(user_channel_id_str)?;
        self.user_channel_id = Some(user_channel_id);

        Ok(())
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

pub struct NodeBalance {
    pub confirmed: u64,
    pub unconfirmed: u64,
    pub lightning: u64,
    pub force_close: u64,
}

pub struct NodeManagerBuilder<S: MutinyStorage> {
    xprivkey: ExtendedPrivKey,
    storage: S,
    esplora: Option<Arc<AsyncClient>>,
    config: Option<MutinyWalletConfig>,
    stop: Option<Arc<AtomicBool>>,
    logger: Option<Arc<MutinyLogger>>,
}

impl<S: MutinyStorage> NodeManagerBuilder<S> {
    pub fn new(xprivkey: ExtendedPrivKey, storage: S) -> NodeManagerBuilder<S> {
        NodeManagerBuilder::<S> {
            xprivkey,
            storage,
            esplora: None,
            config: None,
            stop: None,
            logger: None,
        }
    }

    pub fn with_config(mut self, config: MutinyWalletConfig) -> NodeManagerBuilder<S> {
        self.config = Some(config);
        self
    }

    pub fn with_stop(&mut self, stop: Arc<AtomicBool>) {
        self.stop = Some(stop);
    }

    pub fn with_esplora(&mut self, esplora: Arc<AsyncClient>) {
        self.esplora = Some(esplora);
    }

    pub fn with_logger(&mut self, logger: Arc<MutinyLogger>) {
        self.logger = Some(logger);
    }

    /// Creates a new [NodeManager] with the given parameters.
    /// The mnemonic seed is read from storage, unless one is provided.
    /// If no mnemonic is provided, a new one is generated and stored.
    pub async fn build(self) -> Result<NodeManager<S>, MutinyError> {
        // config is required
        let c = self
            .config
            .map_or_else(|| Err(MutinyError::InvalidArgumentsError), Ok)?;
        let logger = self.logger.unwrap_or(Arc::new(MutinyLogger::default()));
        let stop = self.stop.unwrap_or(Arc::new(AtomicBool::new(false)));
        let esplora = if let Some(e) = self.esplora {
            e
        } else {
            let esplora_server_url = get_esplora_url(c.network, c.user_esplora_url);
            let esplora = Builder::new(&esplora_server_url).build_async()?;
            Arc::new(esplora)
        };

        #[cfg(target_arch = "wasm32")]
        let websocket_proxy_addr = c
            .websocket_proxy_addr
            .unwrap_or_else(|| String::from("wss://p.mutinywallet.com"));

        let start = Instant::now();
        log_info!(logger, "Building node manager components");

        log_trace!(logger, "creating tx sync client");
        let tx_sync = Arc::new(EsploraSyncClient::from_client(
            esplora.as_ref().clone(),
            logger.clone(),
        ));
        log_trace!(logger, "finished creating tx sync client");

        log_trace!(logger, "creating fee estimator");
        let fee_estimator = Arc::new(MutinyFeeEstimator::new(
            self.storage.clone(),
            esplora.clone(),
            logger.clone(),
        ));
        log_trace!(logger, "finished creating fee estimator");

        log_trace!(logger, "creating on chain wallet");
        let wallet = Arc::new(OnChainWallet::new(
            self.xprivkey,
            self.storage.clone(),
            c.network,
            esplora.clone(),
            fee_estimator.clone(),
            stop.clone(),
            logger.clone(),
        )?);
        log_trace!(logger, "finished creating on chain wallet");

        log_trace!(logger, "creating chain");
        let chain = Arc::new(MutinyChain::new(tx_sync, wallet.clone(), logger.clone()));
        log_trace!(logger, "finished creating chain");

        log_trace!(logger, "creating gossip sync");
        let (gossip_sync, scorer) =
            get_gossip_sync(&self.storage, c.network, logger.clone()).await?;
        log_trace!(logger, "finished creating gossip sync");

        log_trace!(logger, "creating scorer");
        let scorer = Arc::new(utils::Mutex::new(scorer));
        log_trace!(logger, "finished creating scorer");

        let gossip_sync = Arc::new(gossip_sync);

        log_trace!(logger, "creating lsp config");
        let lsp_config = if c.safe_mode {
            None
        } else {
            create_lsp_config(c.lsp_url, c.lsp_connection_string, c.lsp_token).unwrap_or_else(
                |_| {
                    log_warn!(
                        logger,
                        "Failed to create lsp config, falling back to no LSP configured"
                    );
                    None
                },
            )
        };
        log_trace!(logger, "finished creating lsp config");

        log_trace!(logger, "getting nodes from storage");
        let node_storage = self.storage.get_nodes()?;
        log_trace!(logger, "finished getting nodes from storage");

        log_trace!(
            logger,
            "Node manager Components built: took {}ms",
            start.elapsed().as_millis()
        );

        let has_done_initial_ldk_sync = Arc::new(AtomicBool::new(false));

        let nodes = if c.safe_mode {
            // If safe mode is enabled, we don't start any nodes
            log_warn!(logger, "Safe mode enabled, not starting any nodes");
            Arc::new(RwLock::new(HashMap::new()))
        } else {
            log_trace!(logger, "going through nodes");

            // Remove the archived nodes, we don't need to start them up.
            let unarchived_nodes = node_storage
                .clone()
                .nodes
                .into_iter()
                .filter(|(_, n)| !n.is_archived());

            let start = Instant::now();
            log_debug!(logger, "Building nodes");

            let mut nodes_map = HashMap::new();

            for node_item in unarchived_nodes {
                let mut node_builder = NodeBuilder::new(self.xprivkey, self.storage.clone())
                    .with_uuid(node_item.0)
                    .with_node_index(node_item.1)
                    .with_gossip_sync(gossip_sync.clone())
                    .with_scorer(scorer.clone())
                    .with_chain(chain.clone())
                    .with_fee_estimator(fee_estimator.clone())
                    .with_wallet(wallet.clone())
                    .with_esplora(esplora.clone())
                    .with_initial_sync(has_done_initial_ldk_sync.clone())
                    .with_network(c.network);
                node_builder.with_logger(logger.clone());

                #[cfg(target_arch = "wasm32")]
                node_builder.with_websocket_proxy_addr(websocket_proxy_addr.clone());

                if let Some(l) = lsp_config.clone() {
                    node_builder.with_lsp_config(l);
                }
                if c.do_not_connect_peers {
                    node_builder.do_not_connect_peers();
                }

                let node = node_builder.build().await?;

                let id = node
                    .keys_manager
                    .get_node_id(Recipient::Node)
                    .expect("Failed to get node id");

                nodes_map.insert(id, Arc::new(node));
            }
            log_trace!(
                logger,
                "Nodes built: took {}ms",
                start.elapsed().as_millis()
            );

            // when we create the nodes we set the LSP if one is missing
            // we need to save it to local storage after startup in case
            // a LSP was set.
            let mut updated_nodes: HashMap<String, NodeIndex> =
                HashMap::with_capacity(nodes_map.len());
            for n in nodes_map.values() {
                updated_nodes.insert(n.uuid.clone(), n.node_index().await);
            }

            // insert updated nodes in background, isn't a huge deal if this fails,
            // it is only for updating the LSP config
            log_info!(logger, "inserting updated nodes");
            let version = node_storage.version + 1;
            let storage = self.storage.clone();
            let logger_clone = logger.clone();
            spawn(async move {
                let start = Instant::now();
                if let Err(e) = storage
                    .insert_nodes(&NodeStorage {
                        nodes: updated_nodes,
                        version,
                    })
                    .await
                {
                    log_error!(logger_clone, "Failed to insert updated nodes: {e}");
                } else {
                    log_info!(
                        logger_clone,
                        "inserted updated nodes, took {}ms",
                        start.elapsed().as_millis()
                    );
                }
            });

            Arc::new(RwLock::new(nodes_map))
        };

        let nm = NodeManager {
            stop,
            xprivkey: self.xprivkey,
            network: c.network,
            wallet,
            gossip_sync,
            scorer,
            chain,
            fee_estimator,
            storage: self.storage,
            node_storage: RwLock::new(node_storage),
            nodes,
            #[cfg(target_arch = "wasm32")]
            websocket_proxy_addr,
            user_rgs_url: c.user_rgs_url,
            scorer_url: c.scorer_url,
            auth_client: c.auth_client,
            esplora,
            lsp_config,
            logger,
            do_not_connect_peers: c.do_not_connect_peers,
            safe_mode: c.safe_mode,
            has_done_initial_ldk_sync,
        };

        Ok(nm)
    }
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
    scorer_url: Option<String>,
    auth_client: Option<Arc<MutinyAuthClient>>,
    esplora: Arc<AsyncClient>,
    pub(crate) wallet: Arc<OnChainWallet<S>>,
    gossip_sync: Arc<RapidGossipSync>,
    scorer: Arc<utils::Mutex<HubPreferentialScorer>>,
    chain: Arc<MutinyChain<S>>,
    fee_estimator: Arc<MutinyFeeEstimator<S>>,
    pub(crate) storage: S,
    pub(crate) node_storage: RwLock<NodeStorage>,
    pub(crate) nodes: Arc<RwLock<HashMap<PublicKey, Arc<Node<S>>>>>,
    pub(crate) lsp_config: Option<LspConfig>,
    pub(crate) logger: Arc<MutinyLogger>,
    do_not_connect_peers: bool,
    pub safe_mode: bool,
    /// If we've completed an initial sync this instance
    pub(crate) has_done_initial_ldk_sync: Arc<AtomicBool>,
}

impl<S: MutinyStorage> NodeManager<S> {
    /// Returns if there is a saved wallet in storage.
    /// This is checked by seeing if a mnemonic seed exists in storage.
    pub fn has_node_manager(storage: S) -> bool {
        storage.get_mnemonic().is_ok_and(|x| x.is_some())
    }

    // New function to get a node by PublicKey or return the first node
    pub(crate) async fn get_node_by_key_or_first(
        &self,
        pk: Option<&PublicKey>,
    ) -> Result<Arc<Node<S>>, MutinyError> {
        log_trace!(self.logger, "calling get_node_by_key_or_first");

        let nodes = self.nodes.read().await;
        let node = match pk {
            Some(pubkey) => nodes.get(pubkey),
            None => nodes.iter().next().map(|(_, node)| node),
        };
        let res = node.cloned().ok_or(MutinyError::NotFound);
        log_trace!(self.logger, "finished calling get_node_by_key_or_first");

        res
    }

    /// Stops all of the nodes and background processes.
    /// Returns after node has been stopped.
    pub async fn stop(&self) -> Result<(), MutinyError> {
        log_trace!(self.logger, "calling stop");

        self.stop.swap(true, Ordering::Relaxed);
        let mut nodes = self.nodes.write().await;
        let node_futures = nodes.iter().map(|(_, n)| async {
            match n.stop().await {
                Ok(_) => {
                    log_debug!(self.logger, "stopped node: {}", n.pubkey)
                }
                Err(e) => {
                    log_error!(self.logger, "failed to stop node {}: {e}", n.pubkey)
                }
            }
        });
        log_debug!(self.logger, "stopping all nodes");
        join_all(node_futures).await;
        nodes.clear();
        log_debug!(self.logger, "finished calling stop");

        Ok(())
    }

    /// Creates a background process that will sync the wallet with the blockchain.
    /// This will also update the fee estimates every 10 minutes.
    pub fn start_sync(nm: Arc<NodeManager<S>>) {
        log_trace!(nm.logger, "calling start_sync");

        // sync every second on regtest, this makes testing easier
        let sync_interval_secs = match nm.network {
            Network::Bitcoin | Network::Testnet | Network::Signet => 60,
            Network::Regtest => 1,
            net => unreachable!("Unknown network: {net}"),
        };
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

                    if let Err(e) = nm.sync_scorer().await {
                        log_error!(nm.logger, "Failed to sync scorer: {e}");
                    } else {
                        log_info!(nm.logger, "Scorer Synced!");
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

                // wait for next sync round, checking graceful shutdown check each second.
                for _ in 0..sync_interval_secs {
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
        log_trace!(self.logger, "calling broadcast_transaction");
        let res = self.wallet.broadcast_transaction(tx).await;
        log_trace!(self.logger, "finished calling broadcast_transaction");

        res
    }

    /// Returns the network of the wallet.
    pub fn get_network(&self) -> Network {
        self.network
    }

    /// Gets a new bitcoin address from the wallet.
    /// Will generate the last unused address in our bdk wallet.
    pub fn get_new_address(&self, labels: Vec<String>) -> Result<Address, MutinyError> {
        log_trace!(self.logger, "calling get_new_address");

        if let Ok(mut wallet) = self.wallet.wallet.try_write() {
            let address = wallet.try_get_address(AddressIndex::LastUnused)?.address;
            self.set_address_labels(address.clone(), labels)?;
            log_trace!(self.logger, "finished calling get_new_address");

            return Ok(address);
        }

        log_error!(self.logger, "Could not get wallet lock to get new address");
        Err(MutinyError::WalletOperationFailed)
    }

    /// Gets the current balance of the on-chain wallet.
    pub fn get_wallet_balance(&self) -> Result<u64, MutinyError> {
        log_trace!(self.logger, "calling get_wallet_balance");

        if let Ok(wallet) = self.wallet.wallet.try_read() {
            log_trace!(self.logger, "finished calling get_wallet_balance");
            return Ok(wallet.get_balance().total());
        }

        log_error!(
            self.logger,
            "Could not get wallet lock to get wallet balance"
        );
        Err(MutinyError::WalletOperationFailed)
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
        log_trace!(self.logger, "calling send_to_address");
        let res = self.wallet.send(send_to, amount, labels, fee_rate).await;
        log_trace!(self.logger, "finished calling send_to_address");

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
        let res = self.wallet.sweep(send_to, labels, fee_rate).await;
        log_trace!(self.logger, "calling sweep_wallet");

        res
    }

    /// Estimates the onchain fee for a transaction sending to the given address.
    /// The amount is in satoshis and the fee rate is in sat/vbyte.
    pub(crate) fn estimate_tx_fee(
        &self,
        destination_address: Address,
        amount: u64,
        fee_rate: Option<f32>,
    ) -> Result<u64, MutinyError> {
        log_trace!(self.logger, "calling estimate_tx_fee");
        let res =
            self.wallet
                .estimate_tx_fee(destination_address.script_pubkey(), amount, fee_rate);
        log_trace!(self.logger, "calling estimate_tx_fee");

        res
    }

    // /// Estimates the onchain fee for a transaction sweep our on-chain balance
    // /// to the given address.
    // ///
    // /// The fee rate is in sat/vbyte.
    // pub(crate) fn estimate_sweep_tx_fee(
    //     &self,
    //     destination_address: Address,
    //     fee_rate: Option<f32>,
    // ) -> Result<u64, MutinyError> {
    //     self.wallet
    //         .estimate_sweep_tx_fee(destination_address.script_pubkey(), fee_rate)
    // }

    /// Estimates the onchain fee for a opening a lightning channel.
    /// The amount is in satoshis and the fee rate is in sat/vbyte.
    pub fn estimate_channel_open_fee(
        &self,
        amount: u64,
        fee_rate: Option<f32>,
    ) -> Result<u64, MutinyError> {
        log_trace!(self.logger, "calling estimate_channel_open_fee");

        // Dummy p2wsh script for the channel output
        let script = script::Builder::new()
            .push_int(0)
            .push_slice([0; 32])
            .into_script();
        let res = self.wallet.estimate_tx_fee(script, amount, fee_rate);
        log_trace!(self.logger, "calling estimate_channel_open_fee");

        res
    }

    /// Estimates the onchain fee for sweeping our on-chain balance to open a lightning channel.
    /// The fee rate is in sat/vbyte.
    pub fn estimate_sweep_channel_open_fee(
        &self,
        fee_rate: Option<f32>,
    ) -> Result<u64, MutinyError> {
        log_trace!(self.logger, "calling estimate_sweep_channel_open_fee");

        // Dummy p2wsh script for the channel output
        let script = script::Builder::new()
            .push_int(0)
            .push_slice([0; 32])
            .into_script();
        let res = self.wallet.estimate_sweep_tx_fee(script, fee_rate);
        log_trace!(self.logger, "calling estimate_sweep_channel_open_fee");

        res
    }

    /// Bumps the given transaction by replacing the given tx with a transaction at
    /// the new given fee rate in sats/vbyte
    pub async fn bump_fee(&self, txid: Txid, new_fee_rate: f32) -> Result<Txid, MutinyError> {
        log_trace!(self.logger, "calling bump_fee");

        // check that this is not a funding tx for any channels,
        // bumping those can cause loss of funds
        let channels = self.list_channels().await?;
        if channels
            .iter()
            .any(|c| c.outpoint.is_some_and(|t| t.txid == txid))
        {
            return Err(MutinyError::ChannelCreationFailed);
        }

        let res = self.wallet.bump_fee(txid, new_fee_rate).await;
        log_trace!(self.logger, "finished calling bump_fee");

        res
    }

    /// Checks if the given address has any transactions.
    /// If it does, it returns the details of the first transaction.
    ///
    /// This should be used to check if a payment has been made to an address.
    pub async fn check_address(
        &self,
        address: Address<NetworkUnchecked>,
    ) -> Result<Option<TransactionDetails>, MutinyError> {
        log_trace!(self.logger, "calling check_address");

        let address = address.require_network(self.network)?;

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
                txid: Some(tx.txid),
                internal_id: tx.txid,
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

        log_trace!(self.logger, "finished calling check_address");
        Ok(details_opt.map(|(d, _)| d))
    }

    /// Adds labels to the TransactionDetails based on the address labels.
    /// This will panic if the TransactionDetails does not have a transaction.
    /// Make sure you flag `include_raw` when calling `list_transactions` to
    /// ensure that the transaction is included.
    fn add_onchain_labels(
        &self,
        address_labels: &HashMap<String, Vec<String>>,
        mut tx: TransactionDetails,
    ) -> TransactionDetails {
        // find the first output address that has a label
        tx.labels = tx
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

        tx
    }

    /// Lists all the on-chain transactions in the wallet.
    /// These are sorted by confirmation time.
    pub fn list_onchain(&self) -> Result<Vec<TransactionDetails>, MutinyError> {
        log_trace!(self.logger, "calling list_onchain");

        let mut txs = self.wallet.list_transactions(true)?;
        txs.sort();
        let address_labels = self.get_address_labels()?;
        let txs = txs
            .into_iter()
            .map(|tx| self.add_onchain_labels(&address_labels, tx))
            .collect();

        log_trace!(self.logger, "finished calling list_onchain");
        Ok(txs)
    }

    /// Gets the details of a specific on-chain transaction.
    pub fn get_transaction(&self, txid: Txid) -> Result<Option<TransactionDetails>, MutinyError> {
        log_trace!(self.logger, "calling get_transaction");

        let res = match self.wallet.get_transaction(txid)? {
            Some(tx) => {
                let address_labels = self.get_address_labels()?;
                let tx_details = self.add_onchain_labels(&address_labels, tx);
                Ok(Some(tx_details))
            }
            None => Ok(None),
        };
        log_trace!(self.logger, "finished calling get_transaction");

        res
    }

    /// Gets the current balance of the wallet.
    /// This includes both on-chain and lightning funds.
    ///
    /// This will not include any funds in an unconfirmed lightning channel.
    pub(crate) async fn get_balance(&self) -> Result<NodeBalance, MutinyError> {
        log_trace!(self.logger, "calling get_balance");

        let onchain = if let Ok(wallet) = self.wallet.wallet.try_read() {
            wallet.get_balance()
        } else {
            log_error!(self.logger, "Could not get wallet lock to get balance");
            return Err(MutinyError::WalletOperationFailed);
        };

        let nodes = self.nodes.read().await;
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

        log_trace!(self.logger, "finished calling get_balance");

        Ok(NodeBalance {
            confirmed: onchain.confirmed + onchain.trusted_pending,
            unconfirmed: onchain.untrusted_pending + onchain.immature,
            lightning: lightning_msats / 1_000,
            force_close,
        })
    }

    /// Lists all the UTXOs in the wallet.
    pub fn list_utxos(&self) -> Result<Vec<LocalOutput>, MutinyError> {
        log_trace!(self.logger, "calling list_utxos");
        let res = self.wallet.list_utxos();
        log_trace!(self.logger, "calling list_utxos");

        res
    }

    /// Syncs the lightning wallet with the blockchain.
    /// This will update the wallet with any lightning channels
    /// that have been opened or closed.
    ///
    /// This should be called before syncing the on-chain wallet
    /// to ensure that new on-chain transactions are picked up.
    async fn sync_ldk(&self) -> Result<(), MutinyError> {
        log_trace!(self.logger, "calling sync_ldk");

        // get nodes hashmap, immediately drop lock because sync can take a while
        let nodes = {
            let nodes = self.nodes.read().await;
            nodes.deref().clone()
        };

        // Lock all the nodes so we can sync them, make sure we keep the locks
        // in scope so they don't get dropped and unlocked.
        let futs = nodes
            .values()
            .map(|node| node.sync_lock.lock())
            .collect::<Vec<_>>();
        let _locks = join_all(futs).await;

        let confirmables: Vec<&(dyn Confirm + Send + Sync)> = nodes
            .iter()
            .flat_map(|(_, node)| {
                let vec: Vec<&(dyn Confirm + Send + Sync)> =
                    vec![node.channel_manager.deref(), node.chain_monitor.deref()];
                vec
            })
            .collect();

        self.chain
            .tx_sync
            .sync(confirmables)
            .await
            .map_err(|_e| MutinyError::ChainAccessFailed)?;

        log_trace!(self.logger, "finished calling sync_ldk");
        Ok(())
    }

    /// Syncs the rapid gossip sync data.
    /// Will be skipped if in safe mode.
    async fn sync_rgs(&self) -> Result<(), MutinyError> {
        log_trace!(self.logger, "calling sync_rgs");

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

        log_trace!(self.logger, "finished calling sync_rgs");
        Ok(())
    }

    /// Downloads the latest score data from the server and replaces the current scorer.
    /// Will be skipped if in safe mode.
    async fn sync_scorer(&self) -> Result<(), MutinyError> {
        log_trace!(self.logger, "calling sync_scorer");

        // Skip syncing scorer if we are in safe mode.
        if self.safe_mode {
            log_info!(self.logger, "Skipping scorer sync in safe mode");
            return Ok(());
        }

        if let (Some(auth), Some(url)) = (self.auth_client.as_ref(), self.scorer_url.as_deref()) {
            let scorer = get_remote_scorer(
                auth,
                url,
                self.gossip_sync.network_graph().clone(),
                self.logger.clone(),
            )
            .await
            .map_err(|e| {
                log_error!(self.logger, "Failed to sync scorer: {e}");
                e
            })?;

            // Replace the current scorer with the new one
            let mut lock = self
                .scorer
                .try_lock()
                .map_err(|_| MutinyError::WalletSyncError)?;
            *lock = scorer;
        }

        log_trace!(self.logger, "finished calling sync_scorer");
        Ok(())
    }

    /// Syncs the on-chain wallet and lightning wallet.
    /// This will update the on-chain wallet with any new
    /// transactions and update the lightning wallet with
    /// any channels that have been opened or closed.
    async fn sync(&self) -> Result<(), MutinyError> {
        log_trace!(self.logger, "calling sync");

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

        // set has synced to true
        self.has_done_initial_ldk_sync.swap(true, Ordering::SeqCst);

        // sync bdk wallet
        let res = match self.wallet.sync().await {
            Ok(()) => Ok(log_info!(self.logger, "We are synced!")),
            Err(e) => {
                log_error!(self.logger, "Failed to sync on-chain wallet: {e}");
                Err(e)
            }
        };
        log_trace!(self.logger, "finished calling sync");

        res
    }

    /// Gets a fee estimate for a very low priority transaction.
    /// Value is in sat/vbyte.
    pub fn estimate_fee_low(&self) -> u32 {
        log_trace!(self.logger, "calling estimate_fee_low");
        let res = max(self.fee_estimator.get_low_fee_rate() / 250, 1);
        log_trace!(self.logger, "finished calling estimate_fee_low");

        res
    }

    /// Gets a fee estimate for an average priority transaction.
    /// Value is in sat/vbyte.
    pub fn estimate_fee_normal(&self) -> u32 {
        log_trace!(self.logger, "calling estimate_fee_normal");
        let res = max(self.fee_estimator.get_normal_fee_rate() / 250, 1);
        log_trace!(self.logger, "finished calling estimate_fee_normal");

        res
    }

    /// Gets a fee estimate for an high priority transaction.
    /// Value is in sat/vbyte.
    pub fn estimate_fee_high(&self) -> u32 {
        log_trace!(self.logger, "calling estimate_fee_high");
        let res = max(self.fee_estimator.get_high_fee_rate() / 250, 1);
        log_trace!(self.logger, "finished calling estimate_fee_high");

        res
    }

    /// Creates a new lightning node and adds it to the manager.
    pub async fn new_node(&self) -> Result<NodeIdentity, MutinyError> {
        log_trace!(self.logger, "calling new_node");
        if self.safe_mode {
            return Err(MutinyError::NotRunning);
        }

        let res = create_new_node_from_node_manager(self).await;
        log_trace!(self.logger, "finished calling new_node");

        res
    }

    /// Archives a node so it will not be started up next time the node manager is created.
    ///
    /// If the node has any active channels it will fail to archive
    #[allow(dead_code)]
    pub(crate) async fn archive_node(&self, pubkey: PublicKey) -> Result<(), MutinyError> {
        if let Some(node) = self.nodes.read().await.get(&pubkey) {
            // disallow archiving nodes with active channels or
            // claimable on-chain funds, so we don't lose funds
            if node.channel_manager.list_channels().is_empty()
                && node.chain_monitor.get_claimable_balances(&[]).is_empty()
            {
                self.archive_node_by_uuid(node.uuid.clone()).await
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
        let mut node_storage = self.node_storage.write().await;

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
        log_trace!(self.logger, "calling list_nodes");

        let nodes = self.nodes.read().await;
        let peers = nodes.iter().map(|(_, n)| n.pubkey).collect();

        log_trace!(self.logger, "finished calling list_nodes");
        Ok(peers)
    }

    pub async fn get_configured_lsp(&self) -> Result<Option<LspConfig>, MutinyError> {
        let node = self.get_node_by_key_or_first(None).await?;
        Ok(node.node_index().await.lsp)
    }

    /// Changes all the node's LSPs to the given config. If any of the nodes have an active channel with the
    /// current LSP, it will fail to change the LSP.
    ///
    /// Requires a restart of the node manager to take effect.
    pub async fn change_lsp(&self, mut lsp_config: Option<LspConfig>) -> Result<(), MutinyError> {
        log_trace!(self.logger, "calling change_lsp");

        // if we are in safe mode we don't load the lightning state so we can't know if it is safe to change the LSP.
        if self.safe_mode {
            return Err(MutinyError::NotRunning);
        }

        // check if any nodes have active channels with the current LSP
        // if they do, we can't change the LSP
        let nodes = self.nodes.read().await;
        for node in nodes.values() {
            if let Some(ref lsp) = node.lsp_client {
                if !node
                    .channel_manager
                    .list_channels_with_counterparty(&lsp.get_lsp_pubkey().await)
                    .is_empty()
                {
                    return Err(MutinyError::LspGenericError);
                }
            }
        }
        drop(nodes);

        // verify that the LSP config is valid
        match lsp_config.as_mut() {
            Some(LspConfig::VoltageFlow(config)) => {
                let http_client = Client::new();

                // try to connect to the LSP, update the config if successful
                let (pk, str) = voltage::LspClient::fetch_connection_info(
                    &http_client,
                    &config.url,
                    &self.logger,
                )
                .await?;
                config.pubkey = Some(pk);
                config.connection_string = Some(str);
            }
            Some(LspConfig::Lsps(config)) => {
                // make sure a valid connection string was provided
                PubkeyConnectionInfo::new(&config.connection_string)?;
            }
            None => {} // Nothing to verify
        }

        // edit node storage
        let mut node_storage = self.node_storage.write().await;
        node_storage.nodes.iter_mut().for_each(|(_, n)| {
            n.lsp = lsp_config.clone();
        });
        node_storage.version += 1; // update version for VSS

        // save updated lsp to storage
        self.storage.insert_nodes(&node_storage).await?;
        log_trace!(self.logger, "finished calling change_lsp");

        Ok(())
    }

    /// Attempts to connect to a peer using either a specified node or the first available node.
    pub async fn connect_to_peer(
        &self,
        self_node_pubkey: Option<&PublicKey>,
        connection_string: &str,
        label: Option<String>,
    ) -> Result<(), MutinyError> {
        log_trace!(self.logger, "calling connect_to_peer");

        let node = self.get_node_by_key_or_first(self_node_pubkey).await?;
        let connect_info = PubkeyConnectionInfo::new(connection_string)?;
        let label_opt = label.filter(|s| !s.is_empty()); // filter out empty strings
        let res = node.connect_peer(connect_info, label_opt).await;

        log_trace!(self.logger, "finished calling connect_to_peer");
        match res {
            Ok(_) => {
                log_info!(self.logger, "Connected to peer: {connection_string}");
                Ok(())
            }
            Err(e) => {
                log_error!(
                    self.logger,
                    "Could not connect to peer: {connection_string} - {e}"
                );
                Err(e)
            }
        }
    }

    /// Disconnects from a peer using either a specified node or the first available node.
    pub async fn disconnect_peer(
        &self,
        self_node_pubkey: Option<&PublicKey>,
        peer: PublicKey,
    ) -> Result<(), MutinyError> {
        log_trace!(self.logger, "calling disconnect_peer");

        let node = self.get_node_by_key_or_first(self_node_pubkey).await?;
        node.disconnect_peer(peer);
        log_trace!(self.logger, "finished calling disconnect_peer");

        Ok(())
    }

    /// Deletes a peer from either a specified node or the first available node.
    /// This will prevent the node from attempting to reconnect to the peer.
    pub async fn delete_peer(
        &self,
        self_node_pubkey: Option<&PublicKey>,
        peer: &NodeId,
    ) -> Result<(), MutinyError> {
        log_trace!(self.logger, "calling delete_peer");

        let node = self.get_node_by_key_or_first(self_node_pubkey).await?;
        gossip::delete_peer_info(&self.storage, &node.uuid, peer)?;
        log_trace!(self.logger, "finished calling delete_peer");

        Ok(())
    }

    /// Sets the label of a peer from the selected node.
    pub fn label_peer(&self, node_id: &NodeId, label: Option<String>) -> Result<(), MutinyError> {
        log_trace!(self.logger, "calling label_peer");
        gossip::set_peer_label(&self.storage, node_id, label)?;
        log_trace!(self.logger, "finished calling label_peer");

        Ok(())
    }

    // all values in sats

    /// Creates a lightning invoice. The amount should be in satoshis.
    /// If no description is provided, the invoice will be created with no description.
    ///
    /// If the manager has more than one node it will create a phantom invoice.
    /// If there is only one node it will create an invoice just for that node.
    pub async fn create_invoice(
        &self,
        amount: u64,
        labels: Vec<String>,
    ) -> Result<(MutinyInvoice, u64), MutinyError> {
        log_trace!(self.logger, "calling create_invoice");

        let nodes = self.nodes.read().await;
        let use_phantom = nodes.len() > 1 && self.lsp_config.is_none();
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
            .create_invoice(amount, route_hints, labels)
            .await?;
        log_trace!(self.logger, "finished calling create_invoice");

        Ok((invoice.0.into(), invoice.1))
    }

    /// Gets the LSP fee for receiving an invoice down the first node that exists.
    /// This could include the fee if a channel open is necessary. Otherwise the fee
    /// will be low or non-existant.
    pub async fn get_lsp_fee(&self, amount: u64) -> Result<u64, MutinyError> {
        log_trace!(self.logger, "calling get_lsp_fee");

        let node = self.get_node_by_key_or_first(None).await?;
        let res = node.get_lsp_fee(amount).await;

        log_trace!(self.logger, "finished calling get_lsp_fee");

        res
    }

    /// Pays a lightning invoice from either a specified node or the first available node.
    /// An amount should only be provided if the invoice does not have an amount.
    /// The amount should be in satoshis.
    pub(crate) async fn pay_invoice(
        &self,
        self_node_pubkey: Option<&PublicKey>,
        invoice: &Bolt11Invoice,
        amt_sats: Option<u64>,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        log_trace!(self.logger, "calling pay_invoice");

        let node = self.get_node_by_key_or_first(self_node_pubkey).await?;
        let res = node
            .pay_invoice_with_timeout(invoice, amt_sats, None, labels)
            .await;
        log_trace!(self.logger, "finished calling pay_invoice");

        res
    }

    /// Sends a spontaneous payment to a node from either a specified node or the first available node.
    /// The amount should be in satoshis.
    pub async fn keysend(
        &self,
        self_node_pubkey: Option<&PublicKey>,
        to_node: PublicKey,
        amt_sats: u64,
        message: Option<String>,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        log_trace!(self.logger, "calling keysend");

        let node = self.get_node_by_key_or_first(self_node_pubkey).await?;
        log_debug!(self.logger, "Keysending to {to_node}");
        let res = node
            .keysend_with_timeout(to_node, amt_sats, message, labels, None)
            .await;
        log_trace!(self.logger, "finished calling keysend");

        res
    }

    pub async fn get_channel_closure(
        &self,
        user_channel_id: u128,
    ) -> Result<ChannelClosure, MutinyError> {
        log_trace!(self.logger, "calling get_channel_closure");

        let nodes = self.nodes.read().await;
        for (_, node) in nodes.iter() {
            if let Ok(Some(closure)) = node.get_channel_closure(user_channel_id) {
                log_trace!(self.logger, "finished calling get_channel_closure");
                return Ok(closure);
            }
        }

        log_trace!(self.logger, "finished calling get_channel_closure");
        Err(MutinyError::NotFound)
    }

    pub async fn list_channel_closures(&self) -> Result<Vec<ChannelClosure>, MutinyError> {
        log_trace!(self.logger, "calling list_channel_closures");

        let mut channels: Vec<ChannelClosure> = vec![];
        let nodes = self.nodes.read().await;
        for (_, node) in nodes.iter() {
            if let Ok(mut invs) = node.get_channel_closures() {
                channels.append(&mut invs)
            }
        }

        log_trace!(self.logger, "finished calling list_channel_closures");
        Ok(channels)
    }

    /// Opens a channel from either a specified node or the first available node to the given pubkey.
    /// The amount is in satoshis.
    ///
    /// The node must be online and have a connection to the peer.
    /// The wallet must have enough funds to open the channel.
    pub async fn open_channel(
        &self,
        self_node_pubkey: Option<&PublicKey>,
        to_pubkey: Option<PublicKey>,
        amount: u64,
        fee_rate: Option<f32>,
        user_channel_id: Option<u128>,
    ) -> Result<MutinyChannel, MutinyError> {
        log_trace!(self.logger, "calling open_channel");

        let node = self.get_node_by_key_or_first(self_node_pubkey).await?;
        let to_pubkey = match to_pubkey {
            Some(pubkey) => pubkey,
            None => {
                node.lsp_client
                    .as_ref()
                    .ok_or(MutinyError::PubkeyInvalid)?
                    .get_lsp_pubkey()
                    .await
            }
        };

        let outpoint = node
            .open_channel_with_timeout(to_pubkey, amount, fee_rate, user_channel_id, 60)
            .await?;

        let all_channels = node.channel_manager.list_channels();
        let found_channel = all_channels
            .iter()
            .find(|chan| chan.funding_txo.map(|a| a.into_bitcoin_outpoint()) == Some(outpoint));

        log_trace!(self.logger, "finished calling open_channel");
        match found_channel {
            Some(channel) => Ok(channel.into()),
            None => Err(MutinyError::ChannelCreationFailed),
        }
    }

    /// Opens a channel from either a specified node or the first available node to the given pubkey.
    /// It will spend the given utxos in full to fund the channel.
    ///
    /// The node must be online and have a connection to the peer.
    /// The UTXOs must all exist in the wallet.
    pub async fn sweep_utxos_to_channel(
        &self,
        utxos: &[OutPoint],
        to_pubkey: Option<PublicKey>,
    ) -> Result<MutinyChannel, MutinyError> {
        log_trace!(self.logger, "calling sweep_utxos_to_channel");

        let node = self.get_node_by_key_or_first(None).await?;
        let to_pubkey = match to_pubkey {
            Some(pubkey) => pubkey,
            None => {
                node.lsp_client
                    .as_ref()
                    .ok_or(MutinyError::PubkeyInvalid)?
                    .get_lsp_pubkey()
                    .await
            }
        };

        let outpoint = node
            .sweep_utxos_to_channel_with_timeout(None, utxos, to_pubkey, 60)
            .await?;

        let all_channels = node.channel_manager.list_channels();
        let found_channel = all_channels
            .iter()
            .find(|chan| chan.funding_txo.map(|a| a.into_bitcoin_outpoint()) == Some(outpoint));

        log_trace!(self.logger, "finished calling sweep_utxos_to_channel");
        match found_channel {
            Some(channel) => Ok(channel.into()),
            None => Err(MutinyError::ChannelCreationFailed),
        }
    }

    /// Opens a channel from our selected node to the given pubkey.
    /// It will spend the all the on-chain utxo in full to fund the channel.
    ///
    /// The node must be online and have a connection to the peer.
    pub async fn sweep_all_to_channel(
        &self,
        to_pubkey: Option<PublicKey>,
    ) -> Result<MutinyChannel, MutinyError> {
        log_trace!(self.logger, "calling sweep_all_to_channel");

        let utxos = self
            .list_utxos()?
            .iter()
            .map(|u| u.outpoint)
            .collect::<Vec<_>>();

        let res = self.sweep_utxos_to_channel(&utxos, to_pubkey).await;
        log_trace!(self.logger, "finished calling sweep_all_to_channel");

        res
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
        log_trace!(self.logger, "calling close_channel");

        if force && abandon {
            return Err(MutinyError::ChannelClosingFailed);
        }

        let nodes = self.nodes.read().await;
        let channel_opt: Option<(Arc<Node<S>>, ChannelDetails)> =
            nodes.iter().find_map(|(_, n)| {
                n.channel_manager
                    .list_channels()
                    .iter()
                    .find(|c| c.funding_txo.map(|f| f.into_bitcoin_outpoint()) == Some(*outpoint))
                    .map(|c| (n.clone(), c.clone()))
            });

        let res = match channel_opt {
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
                                &channel.channel_id,
                                &channel.counterparty.node_id
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
                                &channel.channel_id,
                                &channel.counterparty.node_id
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
                                &channel.channel_id,
                                &channel.counterparty.node_id
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
        };
        log_trace!(self.logger, "finished calling close_channel");

        res
    }

    /// Lists all the channels for all the nodes in the node manager.
    pub async fn list_channels(&self) -> Result<Vec<MutinyChannel>, MutinyError> {
        log_trace!(self.logger, "calling list_channels");

        let nodes = self.nodes.read().await;
        let channels: Vec<ChannelDetails> = nodes
            .iter()
            .flat_map(|(_, n)| n.channel_manager.list_channels())
            .collect();

        let mutiny_channels: Vec<MutinyChannel> =
            channels.iter().map(MutinyChannel::from).collect();

        log_trace!(self.logger, "finished calling list_channels");
        Ok(mutiny_channels)
    }

    /// Lists all the peers for all the nodes in the node manager.
    pub async fn list_peers(&self) -> Result<Vec<MutinyPeer>, MutinyError> {
        log_trace!(self.logger, "calling list_peers");

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

        let nodes = self.nodes.read().await;

        // get peers we are connected to
        let connected_peers: Vec<PublicKey> = nodes
            .iter()
            .flat_map(|(_, n)| n.peer_manager.get_peer_node_ids().into_iter().map(|x| x.0))
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

        log_trace!(self.logger, "finished calling list_peers");
        Ok(storage_peers)
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
        log_trace!(self.logger, "calling reset_router");

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

        log_trace!(self.logger, "finished calling reset_router");
        Ok(())
    }

    /// Resets BDK's keychain tracker. This will require a re-sync of the blockchain.
    ///
    /// This can be useful if you get stuck in a bad state.
    pub async fn reset_onchain_tracker(&self) -> Result<(), MutinyError> {
        log_trace!(self.logger, "calling reset_onchain_tracker");

        // if we're not connected to the db, start it up
        let needs_db_connection = !self.storage.clone().connected().unwrap_or(true);
        if needs_db_connection {
            self.storage.clone().start().await?;
        }

        // delete the bdk keychain store
        self.storage.delete(&[KEYCHAIN_STORE_KEY])?;
        self.storage
            .set_data(NEED_FULL_SYNC_KEY.to_string(), true, None)?;

        // shut back down after reading if it was already closed
        if needs_db_connection {
            self.storage.clone().stop();
        }

        log_trace!(self.logger, "finished calling reset_onchain_tracker");
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

// This will create a new node with a node manager and return the PublicKey of the node created.
pub(crate) async fn create_new_node_from_node_manager<S: MutinyStorage>(
    node_manager: &NodeManager<S>,
) -> Result<NodeIdentity, MutinyError> {
    // Begin with a mutex lock so that nothing else can
    // save or alter the node list while it is about to
    // be saved.
    let mut node_mutex = node_manager.node_storage.write().await;

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

    let lsp = node_manager.lsp_config.clone();

    let next_node = NodeIndex {
        child_index: next_node_index,
        lsp,
        archived: Some(false),
    };

    let mut node_builder = NodeBuilder::new(node_manager.xprivkey, node_manager.storage.clone())
        .with_node_index(next_node.clone())
        .with_gossip_sync(node_manager.gossip_sync.clone())
        .with_scorer(node_manager.scorer.clone())
        .with_chain(node_manager.chain.clone())
        .with_fee_estimator(node_manager.fee_estimator.clone())
        .with_wallet(node_manager.wallet.clone())
        .with_esplora(node_manager.esplora.clone())
        .with_network(node_manager.network)
        .with_initial_sync(node_manager.has_done_initial_ldk_sync.clone());
    node_builder.with_logger(node_manager.logger.clone());

    #[cfg(target_arch = "wasm32")]
    node_builder.with_websocket_proxy_addr(node_manager.websocket_proxy_addr.clone());

    if let Some(l) = node_manager.lsp_config.clone() {
        node_builder.with_lsp_config(l);
    }
    if node_manager.do_not_connect_peers {
        node_builder.do_not_connect_peers();
    }

    let new_node = node_builder.build().await?;
    let node_pubkey = new_node.pubkey;
    let next_node_uuid = new_node.uuid.clone();

    existing_nodes.version += 1;
    existing_nodes
        .nodes
        .insert(next_node_uuid.clone(), next_node);
    node_manager.storage.insert_nodes(&existing_nodes).await?;
    node_mutex.nodes = existing_nodes.nodes.clone();

    let mut nodes = node_manager.nodes.write().await;
    nodes.insert(node_pubkey, Arc::new(new_node));

    Ok(NodeIdentity {
        uuid: next_node_uuid,
        pubkey: node_pubkey,
    })
}

/// Turn parameterized LSP options into a [`LspConfig`].
pub fn create_lsp_config(
    lsp_url: Option<String>,
    lsp_connection_string: Option<String>,
    lsp_token: Option<String>,
) -> Result<Option<LspConfig>, MutinyError> {
    match (lsp_url.clone(), lsp_connection_string.clone()) {
        (Some(lsp_url), None) => {
            let trimmed = lsp_url.trim().to_string();
            if !trimmed.is_empty() {
                // make sure url is valid
                if Url::parse(&trimmed).is_err() {
                    return Err(MutinyError::InvalidArgumentsError);
                }

                Ok(Some(LspConfig::new_voltage_flow(trimmed)))
            } else {
                Ok(None)
            }
        }
        (None, Some(lsp_connection_string)) => {
            if !lsp_connection_string.is_empty() {
                Ok(Some(LspConfig::new_lsps(lsp_connection_string, lsp_token)))
            } else {
                Ok(None)
            }
        }
        (Some(_), Some(_)) => Err(MutinyError::InvalidArgumentsError),
        (None, None) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        encrypt::encryption_key_from_pass,
        nodemanager::{ChannelClosure, MutinyInvoice, NodeManager, TransactionDetails},
        ActivityItem, MutinyWalletConfigBuilder, PrivacyLevel,
    };
    use crate::{keymanager::generate_seed, nodemanager::NodeManagerBuilder};
    use bdk::chain::ConfirmationTime;
    use bitcoin::bip32::ExtendedPrivKey;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::{PublicKey, ThirtyTwoByteHash};
    use bitcoin::{absolute, Network, Transaction, TxOut, Txid};
    use hex_conservative::DisplayHex;
    use lightning::ln::PaymentHash;
    use lightning_invoice::Bolt11Invoice;
    use std::collections::HashMap;
    use std::str::FromStr;

    use crate::test_utils::*;

    use crate::event::{HTLCStatus, MillisatAmount, PaymentInfo};
    use crate::lsp::voltage::VoltageConfig;
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
        let network = Network::Regtest;
        let xpriv = ExtendedPrivKey::new_master(network, &seed.to_seed("")).unwrap();

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher), None);

        assert!(!NodeManager::has_node_manager(storage.clone()));
        let c = MutinyWalletConfigBuilder::new(xpriv)
            .with_network(network)
            .build();
        NodeManagerBuilder::new(xpriv, storage.clone())
            .with_config(c)
            .build()
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
        let network = Network::Regtest;
        let xpriv = ExtendedPrivKey::new_master(network, &seed.to_seed("")).unwrap();
        let c = MutinyWalletConfigBuilder::new(xpriv)
            .with_network(network)
            .build();
        let nm = NodeManagerBuilder::new(xpriv, storage.clone())
            .with_config(c)
            .build()
            .await
            .expect("node manager should initialize");

        {
            let node_identity = nm.new_node().await.expect("should create new node");
            let node_storage = nm.node_storage.read().await;
            assert_ne!("", node_identity.uuid);
            assert_ne!("", node_identity.pubkey.to_string());
            assert_eq!(1, node_storage.nodes.len());

            let retrieved_node = node_storage.nodes.get(&node_identity.uuid).unwrap();
            assert_eq!(0, retrieved_node.child_index);
        }

        {
            let node_identity = nm.new_node().await.expect("node manager should initialize");
            let node_storage = nm.node_storage.read().await;

            assert_ne!("", node_identity.uuid);
            assert_ne!("", node_identity.pubkey.to_string());
            assert_eq!(2, node_storage.nodes.len());

            let retrieved_node = node_storage.nodes.get(&node_identity.uuid).unwrap();
            assert_eq!(1, retrieved_node.child_index);
        }
    }

    #[test]
    async fn created_label_transaction() {
        let test_name = "created_new_nodes";
        log!("{}", test_name);

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher), None);
        let seed = generate_seed(12).expect("Failed to gen seed");
        let network = Network::Regtest;
        let xpriv = ExtendedPrivKey::new_master(network, &seed.to_seed("")).unwrap();
        let c = MutinyWalletConfigBuilder::new(xpriv)
            .with_network(network)
            .build();
        let nm = NodeManagerBuilder::new(xpriv, storage.clone())
            .with_config(c)
            .build()
            .await
            .expect("node manager should initialize");

        let labels = vec![String::from("label1"), String::from("label2")];

        let address = nm
            .get_new_address(labels.clone())
            .expect("should create new address");

        let fake_tx = Transaction {
            version: 2,
            lock_time: absolute::LockTime::ZERO,
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
        assert_eq!(tx.txid, Some(fake_tx.txid()));
        assert_eq!(tx.labels, labels);

        assert!(tx_opt.is_some());
        let tx = tx_opt.unwrap();
        assert_eq!(tx.txid, Some(fake_tx.txid()));
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

        let payment_hash = sha256::Hash::from_str(
            "55ecf9169a6fa07e8ba181fdddf5b0bcc7860176659fa22a7cca9da2a359a33b",
        )
        .unwrap();

        let invoice = Bolt11Invoice::from_str(BOLT_11).unwrap();

        let labels = vec!["label1".to_string(), "label2".to_string()];

        let payment_info = PaymentInfo {
            preimage: Some(preimage),
            secret: Some(secret),
            status: HTLCStatus::Succeeded,
            privacy_level: PrivacyLevel::Anonymous,
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
            preimage: Some(preimage.to_lower_hex_string()),
            payee_pubkey: None,
            amount_sats: Some(100_000),
            expire: 1681781649 + 86400,
            status: HTLCStatus::Succeeded,
            privacy_level: PrivacyLevel::Anonymous,
            fees_paid: None,
            inbound: true,
            labels: labels.clone(),
            last_updated: 1681781585,
        };

        let actual = MutinyInvoice::from(
            payment_info,
            PaymentHash(payment_hash.into_32()),
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

        let payment_hash = sha256::Hash::from_str(
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
            privacy_level: PrivacyLevel::Anonymous,
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
            preimage: Some(preimage.to_lower_hex_string()),
            payee_pubkey: Some(pubkey),
            amount_sats: Some(100),
            expire: 1681781585,
            status: HTLCStatus::Succeeded,
            privacy_level: PrivacyLevel::Anonymous,
            fees_paid: Some(1),
            inbound: false,
            labels: vec![],
            last_updated: 1681781585,
        };

        let actual = MutinyInvoice::from(
            payment_info,
            PaymentHash(payment_hash.into_32()),
            false,
            vec![],
        )
        .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_serialize_node_storage() {
        let old1: NodeStorage = serde_json::from_str("{\"nodes\":{\"93ca1ee3-d5f1-42ed-8bd9-042b298c70dc\":{\"archived\":false,\"child_index\":0,\"lsp\":\"https://signet-lsp.mutinywallet.com\"}},\"version\":11}").unwrap();
        let old2: NodeStorage = serde_json::from_str("{\"nodes\":{\"93ca1ee3-d5f1-42ed-8bd9-042b298c70dc\":{\"archived\":false,\"child_index\":0,\"lsp\":{\"VoltageFlow\":\"https://signet-lsp.mutinywallet.com\"}}},\"version\":11}").unwrap();
        let node = NodeIndex {
            child_index: 0,
            lsp: Some(LspConfig::VoltageFlow(VoltageConfig {
                url: "https://signet-lsp.mutinywallet.com".to_string(),
                pubkey: None,
                connection_string: None,
            })),
            archived: Some(false),
        };
        let mut nodes = HashMap::new();
        nodes.insert("93ca1ee3-d5f1-42ed-8bd9-042b298c70dc".to_string(), node);
        let expected = NodeStorage { nodes, version: 11 };

        assert_eq!(old1, expected);
        assert_eq!(old2, expected);

        let serialized = serde_json::to_string(&expected).unwrap();
        let deserialized: NodeStorage = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, expected);
    }

    #[test]
    fn test_sort_activity_item() {
        let preimage: [u8; 32] =
            FromHex::from_hex("7600f5a9ad72452dea7ad86dabbc9cb46be96a1a2fcd961e041d066b38d93008")
                .unwrap();

        let payment_hash = sha256::Hash::from_str(
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
            txid: Some(Txid::all_zeros()),
            internal_id: Txid::all_zeros(),
            received: 0,
            sent: 0,
            fee: None,
            confirmation_time: ConfirmationTime::Unconfirmed { last_seen: 0_u64 },
            labels: vec![],
        };

        let tx2: TransactionDetails = TransactionDetails {
            transaction: None,
            txid: Some(Txid::all_zeros()),
            internal_id: Txid::all_zeros(),
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
            preimage: Some(preimage.to_lower_hex_string()),
            payee_pubkey: Some(pubkey),
            amount_sats: Some(100),
            expire: 1681781585,
            status: HTLCStatus::Succeeded,
            privacy_level: PrivacyLevel::NotAvailable,
            fees_paid: Some(1),
            inbound: false,
            labels: vec![],
            last_updated: 1681781585,
        };

        let invoice2: MutinyInvoice = MutinyInvoice {
            bolt11: None,
            description: None,
            payment_hash,
            preimage: Some(preimage.to_lower_hex_string()),
            payee_pubkey: Some(pubkey),
            amount_sats: Some(100),
            expire: 1681781585,
            status: HTLCStatus::Succeeded,
            privacy_level: PrivacyLevel::NotAvailable,
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
            privacy_level: PrivacyLevel::NotAvailable,
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
            privacy_level: PrivacyLevel::NotAvailable,
            fees_paid: None,
            inbound: false,
            labels: vec![],
            last_updated: 1581781585,
        };

        let invoice5: MutinyInvoice = MutinyInvoice {
            bolt11: None,
            description: Some("difference".to_string()),
            payment_hash,
            preimage: Some(preimage.to_lower_hex_string()),
            payee_pubkey: Some(pubkey),
            amount_sats: Some(100),
            expire: 1681781585,
            status: HTLCStatus::Succeeded,
            privacy_level: PrivacyLevel::NotAvailable,
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
