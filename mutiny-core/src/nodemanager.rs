use anyhow::anyhow;
use std::cmp::Ordering;
use std::{collections::HashMap, ops::Deref, sync::Arc};

use crate::auth::{AuthManager, AuthProfile};
use crate::event::{HTLCStatus, PaymentInfo};
use crate::indexed_db::MutinyStorage;
use crate::{
    chain::MutinyChain,
    error::MutinyError,
    esplora::EsploraSyncClient,
    fees::MutinyFeeEstimator,
    gossip, keymanager,
    logging::MutinyLogger,
    lspclient::LspClient,
    node::{Node, ProbScorer, PubkeyConnectionInfo, RapidGossipSync},
    utils,
    wallet::get_esplora_url,
    wallet::MutinyWallet,
};
use bdk::chain::{BlockId, ConfirmationTime};
use bdk::{wallet::AddressIndex, LocalUtxo, TransactionDetails};
use bdk_esplora::esplora_client::AsyncClient;
use bip39::Mnemonic;
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{rand, PublicKey};
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::{Address, Network, OutPoint, Transaction, Txid};
use futures::lock::Mutex;
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use lightning::chain::keysinterface::{NodeSigner, Recipient};
use lightning::chain::Confirm;
use lightning::ln::channelmanager::{ChannelDetails, PhantomRouteHints};
use lightning::ln::PaymentHash;
use lightning::routing::gossip::NodeId;
use lightning_invoice::{Invoice, InvoiceDescription};
use lnurl::lnurl::LnUrl;
use lnurl::{AsyncClient as LnUrlClient, LnUrlResponse, Response};
use log::{debug, error, info, warn};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;
use wasm_bindgen_futures::spawn_local;

pub struct NodeManager {
    mnemonic: Mnemonic,
    network: Network,
    websocket_proxy_addr: String,
    esplora: Arc<AsyncClient>,
    wallet: Arc<MutinyWallet>,
    gossip_sync: Arc<RapidGossipSync>,
    scorer: Arc<utils::Mutex<ProbScorer>>,
    chain: Arc<MutinyChain>,
    fee_estimator: Arc<MutinyFeeEstimator>,
    storage: MutinyStorage,
    node_storage: Mutex<NodeStorage>,
    pub(crate) nodes: Arc<Mutex<HashMap<PublicKey, Arc<Node>>>>,
    auth: AuthManager,
    lnurl_client: LnUrlClient,
    lsp_clients: Vec<LspClient>,
}

// This is the NodeStorage object saved to the DB
#[derive(Serialize, Deserialize, Clone, Default)]
pub(crate) struct NodeStorage {
    pub nodes: HashMap<String, NodeIndex>,
}

// This is the NodeIndex reference that is saved to the DB
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct NodeIndex {
    pub child_index: u32,
    pub lsp: Option<String>,
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
    pub invoice: Invoice,
    pub btc_amount: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct MutinyInvoice {
    pub bolt11: Option<Invoice>,
    pub description: Option<String>,
    pub payment_hash: sha256::Hash,
    pub preimage: Option<String>,
    pub payee_pubkey: Option<PublicKey>,
    pub amount_sats: Option<u64>,
    pub expire: u64,
    pub paid: bool,
    pub fees_paid: Option<u64>,
    pub is_send: bool,
    pub last_updated: u64,
}

impl From<Invoice> for MutinyInvoice {
    fn from(value: Invoice) -> Self {
        let description = match value.description() {
            InvoiceDescription::Direct(a) => {
                if a.is_empty() {
                    None
                } else {
                    Some(a.to_string())
                }
            }
            InvoiceDescription::Hash(_) => None,
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
            paid: false,
            fees_paid: None,
            is_send: false, // todo this could be bad
            last_updated: timestamp,
        }
    }
}

impl MutinyInvoice {
    pub(crate) fn from(
        i: PaymentInfo,
        payment_hash: PaymentHash,
        inbound: bool,
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
                let mut mutiny_invoice: MutinyInvoice = invoice.into();
                mutiny_invoice.is_send = !inbound;
                mutiny_invoice.last_updated = i.last_update;
                mutiny_invoice.paid = i.status == HTLCStatus::Succeeded;
                mutiny_invoice.amount_sats = amount_sats;
                mutiny_invoice.preimage = i.preimage.map(|p| p.to_hex());
                mutiny_invoice.fees_paid = i.fee_paid_msat.map(|f| f / 1_000);
                mutiny_invoice.payee_pubkey = i.payee_pubkey;
                Ok(mutiny_invoice)
            }
            None => {
                let paid = i.status == HTLCStatus::Succeeded;
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
                    paid,
                    fees_paid,
                    is_send: !inbound,
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
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MutinyPeer {
    fn cmp(&self, other: &Self) -> Ordering {
        self.is_connected
            .cmp(&other.is_connected)
            .then_with(|| self.alias.cmp(&other.alias))
            .then_with(|| self.pubkey.cmp(&other.pubkey))
            .then_with(|| self.connection_string.cmp(&other.connection_string))
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct MutinyChannel {
    pub balance: u64,
    pub size: u64,
    pub reserve: u64,
    pub outpoint: Option<OutPoint>,
    pub peer: PublicKey,
    pub confirmed: bool,
}

impl From<&ChannelDetails> for MutinyChannel {
    fn from(c: &ChannelDetails) -> Self {
        MutinyChannel {
            balance: c.outbound_capacity_msat / 1_000,
            size: c.channel_value_satoshis,
            reserve: c.unspendable_punishment_reserve.unwrap_or(0),
            outpoint: c.funding_txo.map(|f| f.into_bitcoin_outpoint()),
            peer: c.counterparty.node_id,
            confirmed: c.is_channel_ready, // fixme not exactly correct
        }
    }
}

pub struct MutinyBalance {
    pub confirmed: u64,
    pub unconfirmed: u64,
    pub lightning: u64,
}

pub struct LnUrlParams {
    pub max: u64,
    pub min: u64,
    pub tag: String,
}

/// The [NodeManager] is the main entry point for interacting with the Mutiny Wallet.
/// It is responsible for managing the on-chain wallet and the lightning nodes.
///
/// It can be used to create a new wallet, or to load an existing wallet.
///
/// It can be configured to use all different custom backend services, or to use the default
/// services provided by Mutiny.
impl NodeManager {
    /// Returns if there is a saved wallet in storage.
    /// This is checked by seeing if a mnemonic seed exists in storage.
    pub async fn has_node_manager() -> bool {
        MutinyStorage::has_mnemonic().await.unwrap_or(false)
    }

    /// Creates a new [NodeManager] with the given parameters.
    /// The mnemonic seed is read from storage, unless one is provided.
    /// If no mnemonic is provided, a new one is generated and stored.
    pub async fn new(
        password: String,
        mnemonic: Option<Mnemonic>,
        websocket_proxy_addr: Option<String>,
        network: Option<Network>,
        user_esplora_url: Option<String>,
        user_rgs_url: Option<String>,
        lsp_url: Option<String>,
    ) -> Result<NodeManager, MutinyError> {
        let websocket_proxy_addr =
            websocket_proxy_addr.unwrap_or_else(|| String::from("wss://p.mutinywallet.com"));

        // todo we should eventually have default mainnet
        let network: Network = network.unwrap_or(Network::Testnet);

        let storage = MutinyStorage::new(password.clone()).await?;

        let mnemonic = match mnemonic {
            Some(seed) => storage.insert_mnemonic(seed).await?,
            None => match storage.get_mnemonic().await {
                Ok(mnemonic) => mnemonic,
                Err(_) => {
                    let seed = keymanager::generate_seed(12)?;
                    storage.insert_mnemonic(seed).await?
                }
            },
        };

        let logger = Arc::new(MutinyLogger::default());

        let esplora_server_url = get_esplora_url(network, user_esplora_url);
        let tx_sync = Arc::new(EsploraSyncClient::new(esplora_server_url, logger.clone()));

        let esplora = Arc::new(tx_sync.client().clone());
        let fee_estimator = Arc::new(MutinyFeeEstimator::new(storage.clone(), esplora.clone()));

        let wallet = Arc::new(MutinyWallet::new(
            &mnemonic,
            storage.clone(),
            network,
            esplora.clone(),
            fee_estimator.clone(),
        )?);

        let chain = Arc::new(MutinyChain::new(tx_sync));

        // We don't need to actually sync gossip in tests unless we need to test gossip
        #[cfg(test)]
        let (gossip_sync, scorer) =
            gossip::get_dummy_gossip(user_rgs_url.clone(), network, logger.clone());

        #[cfg(not(test))]
        let (gossip_sync, scorer) =
            gossip::get_gossip_sync(user_rgs_url, network, logger.clone()).await?;

        let scorer = Arc::new(utils::Mutex::new(scorer));

        let gossip_sync = Arc::new(gossip_sync);

        // load lsp clients, if any
        let lsp_clients: Vec<LspClient> = match lsp_url.clone() {
            // check if string is some and not an empty string
            Some(lsp_urls) if !lsp_urls.is_empty() => {
                let urls: Vec<&str> = lsp_urls.split(',').collect();

                let futs = urls.into_iter().map(|url| LspClient::new(url.trim()));

                let results = futures::future::join_all(futs).await;

                results
                    .into_iter()
                    .flat_map(|res| match res {
                        Ok(client) => Some(client),
                        Err(e) => {
                            warn!("Error starting up lsp client: {e}");
                            None
                        }
                    })
                    .collect()
            }
            _ => Vec::new(),
        };

        let node_storage = storage.get_nodes()?;

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
                &mnemonic,
                storage.clone(),
                gossip_sync.clone(),
                scorer.clone(),
                chain.clone(),
                fee_estimator.clone(),
                wallet.clone(),
                network,
                websocket_proxy_addr.clone(),
                esplora.clone(),
                &lsp_clients,
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

        info!("inserting updated nodes");

        storage.insert_nodes(NodeStorage {
            nodes: updated_nodes,
        })?;

        info!("inserted updated nodes");

        let seed = mnemonic.to_seed("");
        let xprivkey = ExtendedPrivKey::new_master(network, &seed)?;
        let auth = AuthManager::new(xprivkey, storage.clone())?;

        // Create default profile if it doesn't exist
        auth.create_init()?;

        let lnurl_client = lnurl::Builder::default()
            .build_async()
            .expect("failed to make lnurl client");

        Ok(NodeManager {
            mnemonic,
            network,
            wallet,
            gossip_sync,
            scorer,
            chain,
            fee_estimator,
            storage,
            node_storage: Mutex::new(node_storage),
            nodes: Arc::new(Mutex::new(nodes_map)),
            websocket_proxy_addr,
            esplora,
            auth,
            lnurl_client,
            lsp_clients,
        })
    }

    /// Broadcast a transaction to the network.
    /// The transaction is broadcast through the configured esplora server.
    pub fn broadcast_transaction(&self, tx: &Transaction) -> Result<(), MutinyError> {
        self.chain.broadcast_transaction(tx);
        Ok(())
    }

    /// Returns the mnemonic seed phrase for the wallet.
    pub fn show_seed(&self) -> Mnemonic {
        self.mnemonic.clone()
    }

    /// Returns the network of the wallet.
    pub fn get_network(&self) -> Network {
        self.network
    }

    /// Gets a new bitcoin address from the wallet.
    /// Will generate a new address on every call.
    ///
    /// It is recommended to create a new address for every transaction.
    pub fn get_new_address(&self) -> Result<Address, MutinyError> {
        let mut wallet = self.wallet.wallet.try_write()?;

        Ok(wallet.get_address(AddressIndex::New).address)
    }

    /// Gets the current balance of the on-chain wallet.
    pub fn get_wallet_balance(&self) -> Result<u64, MutinyError> {
        let wallet = self.wallet.wallet.try_read()?;

        Ok(wallet.get_balance().total())
    }

    /// Creates a BIP 21 invoice. This creates a new address and a lightning invoice.
    pub async fn create_bip21(
        &self,
        amount: Option<u64>,
        description: Option<String>,
    ) -> Result<MutinyBip21RawMaterials, MutinyError> {
        let Ok(address) = self.get_new_address() else {
            return Err(MutinyError::WalletOperationFailed);
        };

        let invoice = self.create_invoice(amount, description.clone()).await?;

        let Some(bolt11) = invoice.bolt11 else {
            return Err(MutinyError::WalletOperationFailed);
        };

        Ok(MutinyBip21RawMaterials {
            address,
            invoice: bolt11,
            btc_amount: amount.map(|amount| bitcoin::Amount::from_sat(amount).to_btc().to_string()),
            description: invoice.description,
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
        fee_rate: Option<f32>,
    ) -> Result<Txid, MutinyError> {
        if !send_to.is_valid_for_network(self.network) {
            return Err(MutinyError::IncorrectNetwork(send_to.network));
        }

        self.wallet.send(send_to, amount, fee_rate).await
    }

    /// Sweeps all the funds from the wallet to the given address.
    /// The fee rate is in sat/vbyte.
    ///
    /// If a fee rate is not provided, one will be used from the fee estimator.
    pub async fn sweep_wallet(
        &self,
        send_to: Address,
        fee_rate: Option<f32>,
    ) -> Result<Txid, MutinyError> {
        if !send_to.is_valid_for_network(self.network) {
            return Err(MutinyError::IncorrectNetwork(send_to.network));
        }

        self.wallet.sweep(send_to, fee_rate).await
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
                .unwrap_or(ConfirmationTime::Unconfirmed);

            let details = TransactionDetails {
                transaction: Some(tx.to_tx()),
                txid: tx.txid,
                received,
                sent: 0,
                fee: None,
                confirmation_time,
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
            spawn_local(async move {
                let tx = details.transaction.expect("tx must be present");
                wallet
                    .insert_tx(tx, details.confirmation_time, block_id)
                    .await
                    .expect("failed to insert tx");
            });
        }

        Ok(details_opt.map(|(d, _)| d))
    }

    /// Lists all the on-chain transactions in the wallet.
    /// These are sorted by confirmation time.
    pub fn list_onchain(&self) -> Result<Vec<TransactionDetails>, MutinyError> {
        let mut txs = self.wallet.list_transactions(false)?;
        txs.sort();

        Ok(txs)
    }

    /// Gets the details of a specific on-chain transaction.
    pub fn get_transaction(&self, txid: Txid) -> Result<Option<TransactionDetails>, MutinyError> {
        self.wallet.get_transaction(txid, false)
    }

    /// Gets the current balance of the wallet.
    /// This includes both on-chain and lightning funds.
    ///
    /// This will not include any funds in an unconfirmed lightning channel.
    pub async fn get_balance(&self) -> Result<MutinyBalance, MutinyError> {
        let onchain = self.wallet.wallet.try_read()?.get_balance();

        let nodes = self.nodes.lock().await;
        let lightning_msats: u64 = nodes
            .iter()
            .flat_map(|(_, n)| n.channel_manager.list_usable_channels())
            .map(|c| c.outbound_capacity_msat)
            .sum();

        Ok(MutinyBalance {
            confirmed: onchain.confirmed + onchain.trusted_pending,
            unconfirmed: onchain.untrusted_pending + onchain.immature,
            lightning: lightning_msats / 1000,
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

    /// Syncs the on-chain wallet and lightning wallet.
    /// This will update the on-chain wallet with any new
    /// transactions and update the lightning wallet with
    /// any channels that have been opened or closed.
    ///
    /// This also updates the fee estimates.
    pub async fn sync(&self) -> Result<(), MutinyError> {
        // update fee estimates before sync in case we need to
        // broadcast a transaction
        self.fee_estimator.update_fee_estimates().await?;
        info!("Updated cached fees!");

        // Sync ldk first because it may broadcast transactions
        // to addresses that are in our bdk wallet. This way
        // they are found on this iteration of syncing instead
        // of the next one.
        self.sync_ldk().await?;

        // sync bdk wallet
        match self.wallet.sync().await {
            Ok(()) => Ok(info!("We are synced!")),
            Err(e) => Err(e),
        }
    }

    /// Gets a fee estimate for an average priority transaction.
    /// Value is in sat/vbyte.
    pub fn estimate_fee_normal(&self) -> u32 {
        self.fee_estimator
            .get_est_sat_per_1000_weight(ConfirmationTarget::Normal)
    }

    /// Gets a fee estimate for an high priority transaction.
    /// Value is in sat/vbyte.
    pub fn estimate_fee_high(&self) -> u32 {
        self.fee_estimator
            .get_est_sat_per_1000_weight(ConfirmationTarget::HighPriority)
    }

    /// Creates a new lightning node and adds it to the manager.
    pub async fn new_node(&self) -> Result<NodeIdentity, MutinyError> {
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
                    info!("connected to peer: {connection_string}");
                    return Ok(());
                }
                Err(e) => {
                    error!("could not connect to peer: {connection_string} - {e}");
                    return Err(e);
                }
            };
        }

        error!("could not find internal node {self_node_pubkey}");
        Err(MutinyError::WalletOperationFailed)
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
            error!("could not find internal node {self_node_pubkey}");
            Err(MutinyError::WalletOperationFailed)
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
            gossip::delete_peer_info(&node._uuid, peer).await?;
            Ok(())
        } else {
            error!("could not find internal node {self_node_pubkey}");
            Err(MutinyError::WalletOperationFailed)
        }
    }

    /// Sets the label of a peer from the selected node.
    pub async fn label_peer(
        &self,
        node_id: &NodeId,
        label: Option<String>,
    ) -> Result<(), MutinyError> {
        gossip::set_peer_label(node_id, label).await?;
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
        description: Option<String>,
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
            .create_invoice(amount, description, route_hints)
            .await?;

        Ok(invoice.into())
    }

    /// Pays a lightning invoice from the selected node.
    /// An amount should only be provided if the invoice does not have an amount.
    /// The amount should be in satoshis.
    pub async fn pay_invoice(
        &self,
        from_node: &PublicKey,
        invoice: &Invoice,
        amt_sats: Option<u64>,
    ) -> Result<MutinyInvoice, MutinyError> {
        if invoice.network() != self.network {
            return Err(MutinyError::IncorrectNetwork(invoice.network()));
        }

        let nodes = self.nodes.lock().await;
        let node = nodes.get(from_node).unwrap();
        node.pay_invoice_with_timeout(invoice, amt_sats, None).await
    }

    /// Sends a spontaneous payment to a node from the selected node.
    /// The amount should be in satoshis.
    pub async fn keysend(
        &self,
        from_node: &PublicKey,
        to_node: PublicKey,
        amt_sats: u64,
    ) -> Result<MutinyInvoice, MutinyError> {
        let nodes = self.nodes.lock().await;
        debug!("Keysending to {to_node}");
        let node = nodes.get(from_node).unwrap();
        node.keysend_with_timeout(to_node, amt_sats, None).await
    }

    /// Decodes a lightning invoice into useful information.
    /// Will return an error if the invoice is for a different network.
    pub async fn decode_invoice(&self, invoice: Invoice) -> Result<MutinyInvoice, MutinyError> {
        if invoice.network() != self.network {
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
    ) -> Result<MutinyInvoice, MutinyError> {
        let response = self.lnurl_client.make_request(&lnurl.url).await?;

        match response {
            LnUrlResponse::LnUrlPayResponse(pay) => {
                let msats = amount_sats * 1000;
                let invoice = self.lnurl_client.get_invoice(&pay, msats).await?;

                self.pay_invoice(from_node, &invoice.invoice(), None).await
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
                let description = withdraw.default_description.clone();
                let mutiny_invoice = self
                    .create_invoice(Some(amount_sats), Some(description))
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

    /// Creates a new LNURL-auth profile.
    pub fn create_lnurl_auth_profile(&self, name: String) -> Result<u32, MutinyError> {
        self.auth.add_profile(name)
    }

    /// Gets all the LNURL-auth profiles.
    pub fn get_lnurl_auth_profiles(&self) -> Result<Vec<AuthProfile>, MutinyError> {
        self.auth.get_profiles()
    }

    /// Authenticates with a LNURL-auth for the given profile.
    pub async fn lnurl_auth(&self, profile_index: usize, lnurl: LnUrl) -> Result<(), MutinyError> {
        let url = Url::parse(&lnurl.url)?;
        let query_pairs: HashMap<String, String> = url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        let k1 = query_pairs.get("k1").ok_or(MutinyError::LnUrlFailure)?;
        let k1: [u8; 32] = FromHex::from_hex(k1).map_err(|_| MutinyError::LnUrlFailure)?;
        let (sig, key) = self.auth.sign(profile_index, url.clone(), &k1)?;

        let response = self.lnurl_client.lnurl_auth(lnurl, sig, key).await?;
        match response {
            Response::Ok { .. } => {
                // don't fail if we just can't save the service
                if let Err(e) = self.auth.add_used_service(profile_index, url) {
                    error!("Failed to save used lnurl auth service: {e}");
                }

                Ok(())
            }
            Response::Error { .. } => Err(MutinyError::LnUrlFailure),
        }
    }

    /// Gets an invoice from the node manager.
    /// This includes sent and received invoices.
    pub async fn get_invoice(&self, invoice: &Invoice) -> Result<MutinyInvoice, MutinyError> {
        let nodes = self.nodes.lock().await;
        let inv_opt: Option<MutinyInvoice> =
            nodes.iter().find_map(|(_, n)| n.get_invoice(invoice).ok());
        match inv_opt {
            Some(i) => Ok(i),
            None => Err(MutinyError::InvoiceInvalid),
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
            if let Ok(invs) = node.list_invoices() {
                let inv_opt: Option<MutinyInvoice> =
                    invs.into_iter().find(|i| i.payment_hash == *hash);
                if let Some(i) = inv_opt {
                    return Ok(i);
                }
            }
        }
        Err(MutinyError::InvoiceInvalid)
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

    /// Opens a channel from our selected node to the given pubkey.
    /// The amount is in satoshis.
    ///
    /// The node must be online and have a connection to the peer.
    /// The wallet much have enough funds to open the channel.
    pub async fn open_channel(
        &self,
        from_node: &PublicKey,
        to_pubkey: PublicKey,
        amount: u64,
    ) -> Result<MutinyChannel, MutinyError> {
        let nodes = self.nodes.lock().await;
        let node = nodes.get(from_node).unwrap();

        let chan_id = node.open_channel(to_pubkey, amount).await?;

        let all_channels = node.channel_manager.list_channels();
        let found_channel = all_channels.iter().find(|chan| chan.channel_id == chan_id);

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
        from_node: &PublicKey,
        utxos: &[OutPoint],
        to_pubkey: PublicKey,
    ) -> Result<MutinyChannel, MutinyError> {
        let nodes = self.nodes.lock().await;
        let node = nodes.get(from_node).unwrap();

        let chan_id = node.sweep_utxos_to_channel(utxos, to_pubkey).await?;

        let all_channels = node.channel_manager.list_channels();
        let found_channel = all_channels.iter().find(|chan| chan.channel_id == chan_id);

        match found_channel {
            Some(channel) => Ok(channel.into()),
            None => Err(MutinyError::ChannelCreationFailed), // what should we do here?
        }
    }

    /// Closes a channel with the given outpoint.
    pub async fn close_channel(&self, outpoint: &OutPoint) -> Result<(), MutinyError> {
        let nodes = self.nodes.lock().await;
        let channel_opt: Option<(Arc<Node>, ChannelDetails)> = nodes.iter().find_map(|(_, n)| {
            n.channel_manager
                .list_channels()
                .iter()
                .find(|c| c.funding_txo.map(|f| f.into_bitcoin_outpoint()) == Some(*outpoint))
                .map(|c| (n.clone(), c.clone()))
        });

        match channel_opt {
            Some((node, channel)) => {
                node.channel_manager
                    .close_channel(&channel.channel_id, &channel.counterparty.node_id)
                    .map_err(|e| {
                        error!(
                            "had an error closing channel {} with node {} : {e:?}",
                            &channel.channel_id.to_hex(),
                            &channel.counterparty.node_id.to_hex()
                        );
                        MutinyError::ChannelClosingFailed
                    })?;

                Ok(())
            }
            None => {
                error!(
                    "Channel not found with this transaction: {}",
                    outpoint.to_string()
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
        let peer_data = gossip::get_all_peers().await?;

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
        for mut peer in &mut storage_peers {
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

    /// Gets the current bitcoin price in USD.
    pub async fn get_bitcoin_price(&self) -> Result<f32, MutinyError> {
        let client = Client::builder().build().unwrap();

        let resp = client
            .get("https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd")
            .send()
            .await
            .map_err(|_| MutinyError::BitcoinPriceError)?;

        let response: CoingeckoResponse = resp
            .error_for_status()
            .map_err(|_| MutinyError::BitcoinPriceError)?
            .json()
            .await
            .map_err(|_| MutinyError::BitcoinPriceError)?;

        Ok(response.bitcoin.usd)
    }

    /// Exports the current state of the node manager to a json object.
    pub async fn export_json(&self) -> Result<serde_json::Value, MutinyError> {
        let map = MutinyStorage::read_all(&self.storage.indexed_db, &self.storage.password).await?;
        let serde_map = serde_json::map::Map::from_iter(map.into_iter());
        Ok(serde_json::Value::Object(serde_map))
    }

    /// Restore a node manager from a json object.
    pub async fn import_json(json: serde_json::Value) -> Result<(), MutinyError> {
        MutinyStorage::import(json).await?;
        Ok(())
    }

    /// Converts a bitcoin amount in BTC to satoshis.
    pub fn convert_btc_to_sats(btc: f64) -> Result<u64, MutinyError> {
        // rust bitcoin doesn't like extra precision in the float
        // so we round to the nearest satoshi
        // explained here: https://stackoverflow.com/questions/28655362/how-does-one-round-a-floating-point-number-to-a-specified-number-of-digits
        let truncated = 10i32.pow(8) as f64;
        let btc = (btc * truncated).round() / truncated;
        if let Ok(amount) = bitcoin::Amount::from_btc(btc) {
            Ok(amount.to_sat())
        } else {
            Err(MutinyError::BadAmountError)
        }
    }

    /// Converts a satoshi amount to BTC.
    pub fn convert_sats_to_btc(sats: u64) -> f64 {
        bitcoin::Amount::from_sat(sats).to_btc()
    }
}

#[derive(Deserialize, Clone, Copy, Debug)]
struct CoingeckoResponse {
    pub bitcoin: CoingeckoPrice,
}

#[derive(Deserialize, Clone, Copy, Debug)]
struct CoingeckoPrice {
    pub usd: f32,
}

// This will create a new node with a node manager and return the PublicKey of the node created.
pub(crate) async fn create_new_node_from_node_manager(
    node_manager: &NodeManager,
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
        info!("no lsp saved and no lsp clients available");
        None
    } else {
        info!("no lsp saved, picking random one");
        // If we don't have an lsp saved we should pick a random
        // one from our client list and save it for next time
        let rand = rand::random::<usize>() % node_manager.lsp_clients.len();
        Some(node_manager.lsp_clients[rand].url.clone())
    };

    let next_node = NodeIndex {
        child_index: next_node_index,
        lsp,
        archived: Some(false),
    };

    existing_nodes
        .nodes
        .insert(next_node_uuid.clone(), next_node.clone());

    node_manager.storage.insert_nodes(existing_nodes.clone())?;
    node_mutex.nodes = existing_nodes.nodes.clone();

    // now create the node process and init it
    let new_node = match Node::new(
        next_node_uuid.clone(),
        &next_node,
        &node_manager.mnemonic,
        node_manager.storage.clone(),
        node_manager.gossip_sync.clone(),
        node_manager.scorer.clone(),
        node_manager.chain.clone(),
        node_manager.fee_estimator.clone(),
        node_manager.wallet.clone(),
        node_manager.network,
        node_manager.websocket_proxy_addr.clone(),
        node_manager.esplora.clone(),
        &node_manager.lsp_clients,
    )
    .await
    {
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
    use crate::keymanager::generate_seed;
    use crate::nodemanager::{MutinyInvoice, NodeManager};
    use bitcoin::hashes::hex::{FromHex, ToHex};
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::PublicKey;
    use bitcoin::Network;
    use lightning::ln::PaymentHash;
    use lightning_invoice::Invoice;
    use std::str::FromStr;

    use crate::test_utils::*;

    use crate::event::{HTLCStatus, MillisatAmount, PaymentInfo};
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    const BOLT_11: &str = "lntbs1m1pjrmuu3pp52hk0j956d7s8azaps87amadshnrcvqtkvk06y2nue2w69g6e5vasdqqcqzpgxqyz5vqsp5wu3py6257pa3yzarw0et2200c08r5fu6k3u94yfwmlnc8skdkc9s9qyyssqc783940p82c64qq9pu3xczt4tdxzex9wpjn54486y866aayft2cxxusl9eags4cs3kcmuqdrvhvs0gudpj5r2a6awu4wcq29crpesjcqhdju55";

    #[test]
    async fn create_node_manager() {
        log!("creating node manager!");

        assert!(!NodeManager::has_node_manager().await);
        NodeManager::new(
            "password".to_string(),
            None,
            None,
            Some(Network::Testnet),
            None,
            None,
            None,
        )
        .await
        .expect("node manager should initialize");
        assert!(NodeManager::has_node_manager().await);

        cleanup_wallet_test().await;
    }

    #[test]
    async fn correctly_show_seed() {
        log!("showing seed");

        let seed = generate_seed(12).expect("Failed to gen seed");
        let nm = NodeManager::new(
            "password".to_string(),
            Some(seed.clone()),
            None,
            Some(Network::Testnet),
            None,
            None,
            None,
        )
        .await
        .unwrap();

        assert!(NodeManager::has_node_manager().await);
        assert_eq!(seed, nm.show_seed());

        cleanup_wallet_test().await;
    }

    #[test]
    async fn created_new_nodes() {
        log!("creating new nodes");

        let seed = generate_seed(12).expect("Failed to gen seed");
        let nm = NodeManager::new(
            "password".to_string(),
            Some(seed),
            None,
            Some(Network::Testnet),
            None,
            None,
            None,
        )
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

        cleanup_wallet_test().await;
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

        let invoice = Invoice::from_str(BOLT_11).unwrap();

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
            paid: true,
            fees_paid: None,
            is_send: false,
            last_updated: 1681781585,
        };

        let actual =
            MutinyInvoice::from(payment_info, PaymentHash(payment_hash.into_inner()), true)
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
            paid: true,
            fees_paid: Some(1),
            is_send: true,
            last_updated: 1681781585,
        };

        let actual =
            MutinyInvoice::from(payment_info, PaymentHash(payment_hash.into_inner()), false)
                .unwrap();

        assert_eq!(actual, expected);
    }
}
