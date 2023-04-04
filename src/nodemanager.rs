use bdk::blockchain::EsploraBlockchain;
use bdk::{BlockTime, TransactionDetails};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::ops::Deref;
use std::{str::FromStr, sync::Arc};

use crate::chain::MutinyChain;
use crate::error::*;
use crate::esplora::EsploraSyncClient;
use crate::logging::MutinyLogger;
use crate::node::{Node, PubkeyConnectionInfo, RapidGossipSync};
use crate::utils::currency_from_network;
use crate::wallet::get_esplora_url;
use crate::{gossip, keymanager};
use crate::{localstorage::MutinyBrowserStorage, utils::set_panic_hook, wallet::MutinyWallet};
use bdk::wallet::AddressIndex;
use bip39::Mnemonic;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::{Address, Network, OutPoint, PublicKey, Transaction, Txid};
use futures::lock::Mutex;
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use lightning::chain::keysinterface::{NodeSigner, Recipient};
use lightning::chain::Confirm;
use lightning::ln::channelmanager::{ChannelDetails, PhantomRouteHints};
use lightning_invoice::{Invoice, InvoiceDescription};
// use lnurl::lnurl::LnUrl;
// use lnurl::{AsyncClient as LnUrlClient, LnUrlResponse, Response};
use crate::fees::MutinyFeeEstimator;
use log::{debug, error, info};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct NodeManager {
    mnemonic: Mnemonic,
    network: Network,
    websocket_proxy_addr: String,
    esplora: Arc<EsploraBlockchain>,
    wallet: Arc<MutinyWallet>,
    gossip_sync: Arc<RapidGossipSync>,
    chain: Arc<MutinyChain>,
    fee_estimator: Arc<MutinyFeeEstimator>,
    storage: MutinyBrowserStorage,
    node_storage: Mutex<NodeStorage>,
    nodes: Arc<Mutex<HashMap<String, Arc<Node>>>>,
    // lnurl_client: LnUrlClient,
}

// This is the NodeStorage object saved to the DB
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct NodeStorage {
    pub nodes: HashMap<String, NodeIndex>,
}

// This is the NodeIndex reference that is saved to the DB
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct NodeIndex {
    pub uuid: String,
    pub child_index: u32,
}

// This is the NodeIdentity that refer to a specific node
// Used for public facing identification.
#[wasm_bindgen]
pub struct NodeIdentity {
    uuid: String,
    pubkey: String,
}

#[wasm_bindgen]
impl NodeIdentity {
    #[wasm_bindgen(getter)]
    pub fn uuid(&self) -> String {
        self.uuid.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn pubkey(&self) -> String {
        self.pubkey.clone()
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
#[wasm_bindgen]
pub struct MutinyInvoice {
    bolt11: Option<String>,
    description: Option<String>,
    payment_hash: String,
    preimage: Option<String>,
    payee_pubkey: Option<String>,
    pub amount_sats: Option<u64>,
    pub expire: u64,
    pub paid: bool,
    pub fees_paid: Option<u64>,
    pub is_send: bool,
}

pub(crate) struct MutinyInvoiceParams {
    pub bolt11: Option<String>,
    pub description: Option<String>,
    pub payment_hash: String,
    pub preimage: Option<String>,
    pub payee_pubkey: Option<String>,
    pub amount_sats: Option<u64>,
    pub expire: u64,
    pub paid: bool,
    pub fees_paid: Option<u64>,
    pub is_send: bool,
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
#[wasm_bindgen]
pub struct MutinyBip21RawMaterials {
    address: String,
    invoice: String,
    btc_amount: Option<String>,
    description: Option<String>,
}

#[wasm_bindgen]
impl MutinyBip21RawMaterials {
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
    pub fn description(&self) -> Option<String> {
        self.description.clone()
    }
}

impl MutinyInvoice {
    pub(crate) fn new(p: MutinyInvoiceParams) -> Self {
        MutinyInvoice {
            bolt11: p.bolt11,
            description: p.description,
            payment_hash: p.payment_hash,
            preimage: p.preimage,
            payee_pubkey: p.payee_pubkey,
            amount_sats: p.amount_sats,
            expire: p.expire,
            paid: p.paid,
            fees_paid: p.fees_paid,
            is_send: p.is_send,
        }
    }
}

#[wasm_bindgen]
impl MutinyInvoice {
    #[wasm_bindgen(getter)]
    pub fn bolt11(&self) -> Option<String> {
        self.bolt11.clone()
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
}

impl From<Invoice> for MutinyInvoice {
    fn from(value: Invoice) -> Self {
        let description = match value.description() {
            InvoiceDescription::Direct(a) => Some(a.to_string()),
            InvoiceDescription::Hash(_) => None,
        };

        let timestamp = value.duration_since_epoch().as_secs();
        let expiry = timestamp + value.expiry_time().as_secs();

        MutinyInvoice {
            bolt11: Some(value.to_string()),
            description,
            payment_hash: value.payment_hash().to_owned().to_hex(),
            preimage: None,
            payee_pubkey: value.payee_pub_key().map(|p| p.to_hex()),
            amount_sats: value.amount_milli_satoshis().map(|m| m / 1000),
            expire: expiry,
            paid: false,
            fees_paid: None,
            is_send: false, // todo this could be bad
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
#[wasm_bindgen]
pub struct MutinyPeer {
    pubkey: secp256k1::PublicKey,
    connection_string: String,
    pub is_connected: bool,
}

#[wasm_bindgen]
impl MutinyPeer {
    #[wasm_bindgen(getter)]
    pub fn pubkey(&self) -> String {
        self.pubkey.to_hex()
    }

    #[wasm_bindgen(getter)]
    pub fn connection_string(&self) -> String {
        self.connection_string.clone()
    }
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
            .then_with(|| self.pubkey.cmp(&other.pubkey))
            .then_with(|| self.connection_string.cmp(&other.connection_string))
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
    pub confirmed: bool,
}

#[wasm_bindgen]
impl MutinyChannel {
    #[wasm_bindgen(getter)]
    pub fn outpoint(&self) -> Option<String> {
        self.outpoint.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn peer(&self) -> String {
        self.peer.clone()
    }
}

impl From<&ChannelDetails> for MutinyChannel {
    fn from(c: &ChannelDetails) -> Self {
        MutinyChannel {
            balance: c.outbound_capacity_msat / 1_000,
            size: c.channel_value_satoshis,
            reserve: c.unspendable_punishment_reserve.unwrap_or(0),
            outpoint: c.funding_txo.map(|f| f.into_bitcoin_outpoint().to_string()),
            peer: c.counterparty.node_id.to_hex(),
            confirmed: c.is_channel_ready, // fixme not exactly correct
        }
    }
}

#[wasm_bindgen]
pub struct MutinyBalance {
    pub confirmed: u64,
    pub unconfirmed: u64,
    pub lightning: u64,
}

#[wasm_bindgen]
pub struct LnUrlParams {
    pub max: u64,
    pub min: u64,
    tag: String,
}

#[wasm_bindgen]
impl LnUrlParams {
    #[wasm_bindgen(getter)]
    pub fn tag(&self) -> String {
        self.tag.clone()
    }
}

#[wasm_bindgen]
impl NodeManager {
    #[wasm_bindgen]
    pub fn has_node_manager() -> bool {
        MutinyBrowserStorage::has_mnemonic()
    }

    #[wasm_bindgen(constructor)]
    pub async fn new(
        password: String,
        mnemonic: Option<String>,
        websocket_proxy_addr: Option<String>,
        network_str: Option<String>,
        user_esplora_url: Option<String>,
        user_rgs_url: Option<String>,
    ) -> Result<NodeManager, MutinyJsError> {
        set_panic_hook();

        let websocket_proxy_addr =
            websocket_proxy_addr.unwrap_or_else(|| String::from("wss://p.mutinywallet.com"));

        let network: Network = network_str
            .unwrap_or_else(|| String::from("testnet"))
            .parse()
            .expect("invalid network");

        let storage = MutinyBrowserStorage::new(password);

        let mnemonic = match mnemonic {
            Some(m) => {
                debug!("{}", &m);
                let seed = match Mnemonic::from_str(String::as_str(&m)) {
                    Ok(seed) => seed,
                    Err(e) => {
                        error!("{}", e);
                        return Err(MutinyError::InvalidMnemonic.into());
                    }
                };
                storage.insert_mnemonic(seed)
            }
            None => match storage.get_mnemonic() {
                Ok(mnemonic) => mnemonic,
                Err(_) => {
                    let seed = keymanager::generate_seed(12)?;
                    storage.insert_mnemonic(seed)
                }
            },
        };

        let logger = Arc::new(MutinyLogger::default());

        let esplora_server_url = get_esplora_url(network, user_esplora_url);
        let tx_sync = Arc::new(EsploraSyncClient::new(esplora_server_url, logger.clone()));

        let esplora = Arc::new(EsploraBlockchain::from_client(tx_sync.client().clone(), 5));
        let wallet = Arc::new(MutinyWallet::new(
            mnemonic.clone(),
            storage.clone(),
            network,
            esplora.clone(),
        ));

        let chain = Arc::new(MutinyChain::new(tx_sync));

        // We don't need to actually sync gossip in tests unless we need to test gossip
        #[cfg(test)]
        let gossip_sync = Arc::new(gossip::get_dummy_gossip(
            user_rgs_url.clone(),
            network,
            logger.clone(),
        ));

        #[cfg(not(test))]
        let gossip_sync =
            Arc::new(gossip::get_gossip_sync(user_rgs_url, network, logger.clone()).await?);

        let fee_estimator = Arc::new(MutinyFeeEstimator::default());

        let node_storage = match MutinyBrowserStorage::get_nodes() {
            Ok(node_storage) => node_storage,
            Err(e) => {
                return Err(MutinyError::ReadError { source: e }.into());
            }
        };

        let mut nodes_map = HashMap::new();

        for node_item in node_storage.clone().nodes {
            let node = Node::new(
                node_item.1,
                mnemonic.clone(),
                storage.clone(),
                gossip_sync.clone(),
                chain.clone(),
                fee_estimator.clone(),
                wallet.clone(),
                network,
                websocket_proxy_addr.clone(),
                esplora.clone(),
            )
            .await?;

            let id = node
                .keys_manager
                .get_node_id(Recipient::Node)
                .expect("Failed to get node id");

            nodes_map.insert(id.to_hex(), Arc::new(node));
        }

        // let lnurl_client = lnurl::Builder::default().build_async().unwrap();

        Ok(NodeManager {
            mnemonic,
            network,
            wallet,
            gossip_sync,
            chain,
            fee_estimator,
            storage,
            node_storage: Mutex::new(node_storage),
            nodes: Arc::new(Mutex::new(nodes_map)),
            websocket_proxy_addr,
            esplora,
            // lnurl_client,
        })
    }

    #[wasm_bindgen]
    pub fn broadcast_transaction(&self, str: String) -> Result<(), MutinyJsError> {
        let tx_bytes = match Vec::from_hex(str.as_str()) {
            Ok(tx_bytes) => tx_bytes,
            Err(_) => return Err(MutinyError::WalletOperationFailed.into()),
        };
        let tx: Transaction = match deserialize(&tx_bytes) {
            Ok(tx) => tx,
            Err(_) => return Err(MutinyError::WalletOperationFailed.into()),
        };

        self.chain.broadcast_transaction(&tx);
        Ok(())
    }

    #[wasm_bindgen]
    pub fn show_seed(&self) -> String {
        self.mnemonic.to_string()
    }

    #[wasm_bindgen]
    pub fn get_network(&self) -> String {
        self.network.to_string()
    }

    #[wasm_bindgen]
    pub async fn get_new_address(&self) -> Result<String, MutinyJsError> {
        match self
            .wallet
            .wallet
            .lock()
            .await
            .get_address(AddressIndex::New)
        {
            Ok(addr) => Ok(addr.address.to_string()),
            Err(_) => Err(MutinyError::WalletOperationFailed.into()),
        }
    }

    #[wasm_bindgen]
    pub async fn get_wallet_balance(&self) -> Result<u64, MutinyJsError> {
        match self.wallet.wallet.lock().await.get_balance() {
            Ok(balance) => Ok(balance.get_total()),
            Err(_) => Err(MutinyJsError::WalletOperationFailed),
        }
    }

    #[wasm_bindgen]
    pub async fn create_bip21(
        &self,
        amount: Option<u64>,
        description: Option<String>,
    ) -> Result<MutinyBip21RawMaterials, MutinyJsError> {
        let Ok(address) = self.get_new_address().await else {
            return Err(MutinyError::WalletOperationFailed.into());
        };

        // TODO if there's no description should be something random I guess
        let Ok(invoice) = self.create_invoice(amount, description.clone().unwrap_or_else(|| "".into())).await else {
            return Err(MutinyError::WalletOperationFailed.into());
        };

        let Some(bolt11) = invoice.bolt11 else {
            return Err(MutinyError::WalletOperationFailed.into());
        };

        Ok(MutinyBip21RawMaterials {
            address,
            invoice: bolt11,
            btc_amount: amount.map(|amount| bitcoin::Amount::from_sat(amount).to_btc().to_string()),
            description,
        })
    }

    #[wasm_bindgen]
    pub async fn send_to_address(
        &self,
        destination_address: String,
        amount: u64,
        fee_rate: Option<f32>,
    ) -> Result<String, MutinyJsError> {
        let send_to = Address::from_str(&destination_address)?;

        if send_to.network != self.network {
            return Err(MutinyJsError::IncorrectNetwork);
        }

        match self.wallet.send(send_to, amount, fee_rate).await {
            Ok(txid) => Ok(txid.to_owned().to_string()),
            Err(e) => Err(e.into()),
        }
    }

    #[wasm_bindgen]
    pub async fn sweep_wallet(
        &self,
        destination_address: String,
        fee_rate: Option<f32>,
    ) -> Result<String, MutinyJsError> {
        let send_to = Address::from_str(&destination_address)?;

        if send_to.network != self.network {
            return Err(MutinyJsError::IncorrectNetwork);
        }

        match self.wallet.sweep(send_to, fee_rate).await {
            Ok(txid) => Ok(txid.to_owned().to_string()),
            Err(e) => Err(e.into()),
        }
    }

    #[wasm_bindgen]
    pub async fn check_address(
        &self,
        address: String,
    ) -> Result<JsValue /* Option<TransactionDetails> */, MutinyJsError> {
        let address = Address::from_str(address.as_str())?;

        if address.network != self.network {
            return Err(MutinyJsError::IncorrectNetwork);
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

            let confirmation_time = tx.confirmation_time().map(|c| BlockTime {
                height: c.height,
                timestamp: c.timestamp,
            });

            TransactionDetails {
                transaction: Some(tx.to_tx()),
                txid: tx.txid,
                received,
                sent: 0,
                fee: None,
                confirmation_time,
            }
        });

        Ok(serde_wasm_bindgen::to_value(&details_opt)?)
    }

    #[wasm_bindgen]
    pub async fn list_onchain(&self) -> Result<JsValue, MutinyJsError> {
        let mut txs = self.wallet.list_transactions(false).await?;
        txs.sort();

        Ok(serde_wasm_bindgen::to_value(&txs)?)
    }

    #[wasm_bindgen]
    pub async fn get_transaction(&self, txid: String) -> Result<JsValue, MutinyJsError> {
        let txid = Txid::from_str(txid.as_str())?;
        let txs = self.wallet.get_transaction(txid, false).await?;

        Ok(serde_wasm_bindgen::to_value(&txs)?)
    }

    #[wasm_bindgen]
    pub async fn get_balance(&self) -> Result<MutinyBalance, MutinyJsError> {
        match self.wallet.wallet.lock().await.get_balance() {
            Ok(onchain) => {
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
            Err(_) => Err(MutinyJsError::WalletOperationFailed),
        }
    }

    #[wasm_bindgen]
    pub async fn list_utxos(&self) -> Result<JsValue, MutinyJsError> {
        let utxos = self.wallet.list_utxos().await?;

        Ok(serde_wasm_bindgen::to_value(&utxos)?)
    }

    async fn sync_ldk(&self) -> Result<(), MutinyError> {
        // TODO
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

    #[wasm_bindgen]
    pub async fn sync(&self) -> Result<(), MutinyJsError> {
        // Sync ldk first because it may broadcast transactions
        // to addresses that are in our bdk wallet. This way
        // they are found on this iteration of syncing instead
        // of the next one.
        self.sync_ldk().await?;

        // sync bdk wallet
        match self.wallet.sync().await {
            Ok(()) => Ok(info!("We are synced!")),
            Err(e) => Err(e.into()),
        }
    }

    #[wasm_bindgen]
    pub fn estimate_fee_normal(&self) -> u32 {
        self.fee_estimator
            .get_est_sat_per_1000_weight(ConfirmationTarget::Normal)
    }

    #[wasm_bindgen]
    pub fn estimate_fee_high(&self) -> u32 {
        self.fee_estimator
            .get_est_sat_per_1000_weight(ConfirmationTarget::HighPriority)
    }

    #[wasm_bindgen]
    pub async fn new_node(&self) -> Result<NodeIdentity, MutinyJsError> {
        match create_new_node_from_node_manager(self).await {
            Ok(node_identity) => Ok(node_identity),
            Err(e) => Err(e.into()),
        }
    }

    #[wasm_bindgen]
    pub async fn list_nodes(&self) -> Result<JsValue /* Vec<String> */, MutinyJsError> {
        let nodes = self.nodes.lock().await;
        let peers: Vec<String> = nodes.iter().map(|(_, n)| n.pubkey.to_hex()).collect();

        Ok(serde_wasm_bindgen::to_value(&peers)?)
    }

    #[wasm_bindgen]
    pub async fn connect_to_peer(
        &self,
        self_node_pubkey: String,
        connection_string: String,
    ) -> Result<(), MutinyJsError> {
        if let Some(node) = self.nodes.lock().await.get(&self_node_pubkey) {
            let connect_info = PubkeyConnectionInfo::new(connection_string.clone())?;
            let res = node.connect_peer(connect_info).await;
            match res {
                Ok(_) => {
                    info!("connected to peer: {connection_string}");
                    return Ok(());
                }
                Err(e) => {
                    error!("could not connect to peer: {connection_string} - {e}");
                    return Err(e.into());
                }
            };
        }

        error!("could not find internal node {self_node_pubkey}");
        Err(MutinyError::WalletOperationFailed.into())
    }

    #[wasm_bindgen]
    pub async fn disconnect_peer(
        &self,
        self_node_pubkey: String,
        peer: String,
    ) -> Result<(), MutinyJsError> {
        if let Some(node) = self.nodes.lock().await.get(&self_node_pubkey) {
            let node_id = match PublicKey::from_str(peer.as_str()) {
                Ok(node_id) => Ok(node_id.inner),
                Err(_) => Err(MutinyJsError::PubkeyInvalid),
            }?;
            node.disconnect_peer(node_id);
            Ok(())
        } else {
            error!("could not find internal node {self_node_pubkey}");
            Err(MutinyError::WalletOperationFailed.into())
        }
    }

    #[wasm_bindgen]
    pub async fn delete_peer(
        &self,
        self_node_pubkey: String,
        peer: String,
    ) -> Result<(), MutinyJsError> {
        if let Some(node) = self.nodes.lock().await.get(&self_node_pubkey) {
            node.persister.delete_peer_connection_info(peer);
            Ok(())
        } else {
            error!("could not find internal node {self_node_pubkey}");
            Err(MutinyError::WalletOperationFailed.into())
        }
    }

    // all values in sats

    #[wasm_bindgen]
    pub async fn create_invoice(
        &self,
        amount: Option<u64>,
        description: String,
    ) -> Result<MutinyInvoice, MutinyJsError> {
        let nodes = self.nodes.lock().await;
        let use_phantom = nodes.len() > 1;
        if nodes.len() == 0 {
            return Err(MutinyJsError::InvoiceCreationFailed);
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
            return Err(MutinyJsError::WalletOperationFailed);
        };
        let invoice = first_node.create_invoice(amount, description, route_hints)?;

        Ok(invoice.into())
    }

    #[wasm_bindgen]
    pub async fn pay_invoice(
        &self,
        from_node: String,
        invoice_str: String,
        amt_sats: Option<u64>,
    ) -> Result<MutinyInvoice, MutinyJsError> {
        let invoice = Invoice::from_str(&invoice_str)?;

        if invoice.currency() != currency_from_network(self.network) {
            return Err(MutinyJsError::IncorrectNetwork);
        }

        let nodes = self.nodes.lock().await;
        let node = nodes.get(from_node.as_str()).unwrap();
        node.pay_invoice(invoice, amt_sats).map_err(|e| e.into())
    }

    #[wasm_bindgen]
    pub async fn keysend(
        &self,
        from_node: String,
        to_node: String,
        amt_sats: u64,
    ) -> Result<MutinyInvoice, MutinyJsError> {
        let nodes = self.nodes.lock().await;
        debug!("Keysending to {to_node}");
        let node = nodes.get(from_node.as_str()).unwrap();

        let node_id = match PublicKey::from_str(to_node.as_str()) {
            Ok(node_id) => Ok(node_id.inner),
            Err(_) => Err(MutinyJsError::PubkeyInvalid),
        }?;

        node.keysend(node_id, amt_sats).map_err(|e| e.into())
    }

    #[wasm_bindgen]
    pub async fn decode_invoice(&self, invoice: String) -> Result<MutinyInvoice, MutinyJsError> {
        let invoice = Invoice::from_str(&invoice)?;

        if invoice.currency() != currency_from_network(self.network) {
            return Err(MutinyJsError::IncorrectNetwork);
        }

        Ok(invoice.into())
    }
    //
    // #[wasm_bindgen]
    // pub async fn decode_lnurl(&self, lnurl: String) -> Result<LnUrlParams, MutinyJsError> {
    //     let lnurl = LnUrl::from_str(&lnurl)?;
    //
    //     let response = self.lnurl_client.make_request(&lnurl.url).await?;
    //
    //     let params = match response {
    //         LnUrlResponse::LnUrlPayResponse(pay) => LnUrlParams {
    //             max: pay.max_sendable,
    //             min: pay.min_sendable,
    //             tag: "payRequest".to_string(),
    //         },
    //         LnUrlResponse::LnUrlChannelResponse(_chan) => LnUrlParams {
    //             max: 0,
    //             min: 0,
    //             tag: "channelRequest".to_string(),
    //         },
    //         LnUrlResponse::LnUrlWithdrawResponse(withdraw) => LnUrlParams {
    //             max: withdraw.max_withdrawable,
    //             min: withdraw.min_withdrawable.unwrap_or(0),
    //             tag: "withdrawRequest".to_string(),
    //         },
    //     };
    //
    //     Ok(params)
    // }
    //
    // #[wasm_bindgen]
    // pub async fn lnurl_pay(
    //     &self,
    //     from_node: String,
    //     lnurl: String,
    //     amount_sats: u64,
    // ) -> Result<MutinyInvoice, MutinyJsError> {
    //     let lnurl = LnUrl::from_str(&lnurl)?;
    //
    //     let response = self.lnurl_client.make_request(&lnurl.url).await?;
    //
    //     match response {
    //         LnUrlResponse::LnUrlPayResponse(pay) => {
    //             let msats = amount_sats * 1000;
    //             let invoice = self.lnurl_client.get_invoice(&pay, msats).await?;
    //
    //             self.pay_invoice(from_node, invoice.invoice().to_string(), None)
    //                 .await
    //         }
    //         LnUrlResponse::LnUrlWithdrawResponse(_) => Err(MutinyJsError::IncorrectLnUrlFunction),
    //         LnUrlResponse::LnUrlChannelResponse(_) => Err(MutinyJsError::IncorrectLnUrlFunction),
    //     }
    // }
    //
    // #[wasm_bindgen]
    // pub async fn lnurl_withdraw(
    //     &self,
    //     lnurl: String,
    //     amount_sats: u64,
    // ) -> Result<bool, MutinyJsError> {
    //     let lnurl = LnUrl::from_str(&lnurl)?;
    //
    //     let response = self.lnurl_client.make_request(&lnurl.url).await?;
    //
    //     match response {
    //         LnUrlResponse::LnUrlPayResponse(_) => Err(MutinyJsError::IncorrectLnUrlFunction),
    //         LnUrlResponse::LnUrlChannelResponse(_) => Err(MutinyJsError::IncorrectLnUrlFunction),
    //         LnUrlResponse::LnUrlWithdrawResponse(withdraw) => {
    //             let description = withdraw.default_description.clone();
    //             let mutiny_invoice = self.create_invoice(Some(amount_sats), description).await?;
    //             let invoice_str = mutiny_invoice.bolt11.expect("Invoice should have bolt11");
    //             let res = self
    //                 .lnurl_client
    //                 .do_withdrawal(&withdraw, &invoice_str)
    //                 .await?;
    //             match res {
    //                 Response::Ok { .. } => Ok(true),
    //                 Response::Error { .. } => Ok(false),
    //             }
    //         }
    //     }
    // }

    #[wasm_bindgen]
    pub async fn get_invoice(&self, invoice: String) -> Result<MutinyInvoice, MutinyJsError> {
        let invoice = Invoice::from_str(&invoice)?;
        let nodes = self.nodes.lock().await;
        let inv_opt: Option<MutinyInvoice> = nodes
            .iter()
            .find_map(|(_, n)| n.get_invoice(invoice.clone()).ok());
        match inv_opt {
            Some(i) => Ok(i),
            None => Err(MutinyJsError::InvoiceInvalid),
        }
    }

    #[wasm_bindgen]
    pub async fn get_invoice_by_hash(&self, hash: String) -> Result<MutinyInvoice, MutinyJsError> {
        let nodes = self.nodes.lock().await;
        for (_, node) in nodes.iter() {
            if let Ok(invs) = node.list_invoices() {
                let inv_opt: Option<MutinyInvoice> =
                    invs.into_iter().find(|i| i.payment_hash() == hash);
                if let Some(i) = inv_opt {
                    return Ok(i);
                }
            }
        }
        Err(MutinyJsError::InvoiceInvalid)
    }

    #[wasm_bindgen]
    pub async fn list_invoices(&self) -> Result<JsValue /* Vec<MutinyInvoice> */, MutinyJsError> {
        let mut invoices: Vec<MutinyInvoice> = vec![];
        let nodes = self.nodes.lock().await;
        for (_, node) in nodes.iter() {
            if let Ok(mut invs) = node.list_invoices() {
                invoices.append(&mut invs)
            }
        }
        Ok(serde_wasm_bindgen::to_value(&invoices)?)
    }

    #[wasm_bindgen]
    pub async fn open_channel(
        &self,
        from_node: String,
        to_pubkey: String,
        amount: u64,
    ) -> Result<MutinyChannel, MutinyJsError> {
        let nodes = self.nodes.lock().await;
        let node = nodes.get(from_node.as_str()).unwrap();

        let node_id = match PublicKey::from_str(to_pubkey.as_str()) {
            Ok(node_id) => Ok(node_id.inner),
            Err(_) => Err(MutinyJsError::PubkeyInvalid),
        }?;

        let chan_id = node.open_channel(node_id, amount).await?;

        let all_channels = node.channel_manager.list_channels();
        let found_channel = all_channels.iter().find(|chan| chan.channel_id == chan_id);

        match found_channel {
            Some(channel) => Ok(channel.into()),
            None => Err(MutinyJsError::ChannelCreationFailed), // what should we do here?
        }
    }

    #[wasm_bindgen]
    pub async fn close_channel(&self, outpoint: String) -> Result<(), MutinyJsError> {
        let outpoint: OutPoint =
            OutPoint::from_str(outpoint.as_str()).expect("Failed to parse outpoint");
        let nodes = self.nodes.lock().await;
        let channel_opt: Option<(Arc<Node>, ChannelDetails)> = nodes.iter().find_map(|(_, n)| {
            n.channel_manager
                .list_channels()
                .iter()
                .find(|c| c.funding_txo.map(|f| f.into_bitcoin_outpoint()) == Some(outpoint))
                .map(|c| (n.clone(), c.clone()))
        });

        match channel_opt {
            Some((node, channel)) => {
                node.channel_manager
                    .close_channel(&channel.channel_id, &channel.counterparty.node_id)
                    .map_err(|_| MutinyJsError::ChannelClosingFailed)?;

                Ok(())
            }
            None => Err(MutinyJsError::ChannelClosingFailed),
        }
    }

    #[wasm_bindgen]
    pub async fn list_channels(&self) -> Result<JsValue, MutinyJsError> {
        let nodes = self.nodes.lock().await;
        let channels: Vec<ChannelDetails> = nodes
            .iter()
            .flat_map(|(_, n)| n.channel_manager.list_channels())
            .collect();

        let mutiny_channels: Vec<MutinyChannel> =
            channels.iter().map(MutinyChannel::from).collect();

        Ok(serde_wasm_bindgen::to_value(&mutiny_channels)?)
    }

    #[wasm_bindgen]
    pub async fn list_peers(&self) -> Result<JsValue /* Vec<MutinyPeer> */, MutinyJsError> {
        let nodes = self.nodes.lock().await;

        // get peers saved in storage
        let mut storage_peers: Vec<MutinyPeer> = nodes
            .iter()
            .flat_map(|(_, n)| n.persister.list_peer_connection_info())
            .map(|(pubkey, connection_string)| MutinyPeer {
                pubkey,
                connection_string,
                is_connected: false,
            })
            .collect();

        // get peers we are connected to
        let connected_peers: Vec<secp256k1::PublicKey> = nodes
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
                    connection_string: "unknown".to_string(),
                    is_connected: true,
                };
                missing.push(new);
            }
        }

        storage_peers.append(&mut missing);
        storage_peers.sort();

        Ok(serde_wasm_bindgen::to_value(&storage_peers)?)
    }

    #[wasm_bindgen]
    pub async fn get_bitcoin_price(&self) -> Result<f32, MutinyJsError> {
        let client = Client::builder().build().unwrap();

        let resp = client
            .get("https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd")
            .send()
            .await?;

        let response: CoingeckoResponse = resp.error_for_status()?.json().await?;

        Ok(response.bitcoin.usd)
    }

    #[wasm_bindgen]
    pub fn convert_btc_to_sats(btc: f64) -> Result<u64, MutinyJsError> {
        // rust bitcoin doesn't like extra precision in the float
        // so we round to the nearest satoshi
        // explained here: https://stackoverflow.com/questions/28655362/how-does-one-round-a-floating-point-number-to-a-specified-number-of-digits
        let truncated = 10i32.pow(8) as f64;
        let btc = (btc * truncated).round() / truncated;
        if let Ok(amount) = bitcoin::Amount::from_btc(btc) {
            Ok(amount.to_sat())
        } else {
            Err(MutinyJsError::BadAmountError)
        }
    }

    #[wasm_bindgen]
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
    let mut existing_nodes = match MutinyBrowserStorage::get_nodes() {
        Ok(existing_nodes) => existing_nodes,
        Err(e) => return Err(MutinyError::ReadError { source: e }),
    };
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
    let next_node = NodeIndex {
        uuid: next_node_uuid.clone(),
        child_index: next_node_index,
    };

    existing_nodes
        .nodes
        .insert(next_node_uuid.clone(), next_node.clone());

    MutinyBrowserStorage::insert_nodes(existing_nodes.clone())?;
    node_mutex.nodes = existing_nodes.nodes.clone();

    // now create the node process and init it
    let new_node = match Node::new(
        next_node.clone(),
        node_manager.mnemonic.clone(),
        node_manager.storage.clone(),
        node_manager.gossip_sync.clone(),
        node_manager.chain.clone(),
        node_manager.fee_estimator.clone(),
        node_manager.wallet.clone(),
        node_manager.network,
        node_manager.websocket_proxy_addr.clone(),
        node_manager.esplora.clone(),
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
        .insert(node_pubkey.to_string(), Arc::new(new_node));

    Ok(NodeIdentity {
        uuid: next_node.uuid.clone(),
        pubkey: node_pubkey.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use crate::keymanager::generate_seed;
    use crate::nodemanager::NodeManager;

    use crate::test::*;

    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn create_node_manager() {
        log!("creating node manager!");

        assert!(!NodeManager::has_node_manager());
        NodeManager::new(
            "password".to_string(),
            None,
            None,
            Some("testnet".to_owned()),
            None,
            None,
        )
        .await
        .expect("node manager should initialize");
        assert!(NodeManager::has_node_manager());

        cleanup_test();
    }

    #[test]
    async fn correctly_show_seed() {
        log!("showing seed");

        let seed = generate_seed(12).expect("Failed to gen seed");
        let nm = NodeManager::new(
            "password".to_string(),
            Some(seed.to_string()),
            None,
            Some("testnet".to_owned()),
            None,
            None,
        )
        .await
        .unwrap();

        assert!(NodeManager::has_node_manager());
        assert_eq!(seed.to_string(), nm.show_seed());

        cleanup_test();
    }

    #[test]
    async fn created_new_nodes() {
        log!("creating new nodes");

        let seed = generate_seed(12).expect("Failed to gen seed");
        let nm = NodeManager::new(
            "password".to_string(),
            Some(seed.to_string()),
            None,
            Some("testnet".to_owned()),
            None,
            None,
        )
        .await
        .expect("node manager should initialize");

        {
            let node_identity = nm.new_node().await.expect("should create new node");
            let node_storage = nm.node_storage.lock().await;
            assert_ne!("", node_identity.uuid);
            assert_ne!("", node_identity.pubkey);
            assert_eq!(1, node_storage.nodes.len());

            let retrieved_node = node_storage.nodes.get(&node_identity.uuid).unwrap();
            assert_eq!(0, retrieved_node.child_index);
        }

        {
            let node_identity = nm.new_node().await.expect("node manager should initialize");
            let node_storage = nm.node_storage.lock().await;

            assert_ne!("", node_identity.uuid);
            assert_ne!("", node_identity.pubkey);
            assert_eq!(2, node_storage.nodes.len());

            let retrieved_node = node_storage.nodes.get(&node_identity.uuid).unwrap();
            assert_eq!(1, retrieved_node.child_index);
        }

        cleanup_test();
    }
}
