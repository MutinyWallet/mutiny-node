use std::collections::HashMap;
use std::ops::Deref;
use std::{str::FromStr, sync::Arc};

use crate::chain::MutinyChain;
use crate::error::{MutinyError, MutinyJsError, MutinyStorageError};
use crate::keymanager;
use crate::node::Node;
use crate::{localstorage::MutinyBrowserStorage, utils::set_panic_hook, wallet::MutinyWallet};
use bdk::wallet::AddressIndex;
use bip39::Mnemonic;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::{Network, Transaction};
use futures::lock::Mutex;
use lightning::chain::chaininterface::BroadcasterInterface;
use lightning::chain::Confirm;
use lightning_invoice::{Invoice, InvoiceDescription};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct NodeManager {
    mnemonic: Mnemonic,
    network: Network,
    wallet: Arc<MutinyWallet>,
    chain: Arc<MutinyChain>,
    storage: MutinyBrowserStorage,
    node_storage: Mutex<NodeStorage>,
    nodes: Arc<Mutex<HashMap<String, Arc<Node>>>>,
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
    bolt11: String,
    description: Option<String>,
    payment_hash: String,
    preimage: Option<String>,
    pub amount_sats: Option<u64>,
    pub expire: Option<u64>,
    pub paid: bool,
    pub fees_paid: u64,
    pub is_send: bool,
}

#[wasm_bindgen]
impl MutinyInvoice {
    #[wasm_bindgen(getter)]
    pub fn bolt11(&self) -> String {
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
}

impl From<Invoice> for MutinyInvoice {
    fn from(value: Invoice) -> Self {
        let description = match value.description() {
            InvoiceDescription::Direct(a) => Some(a.to_string()),
            InvoiceDescription::Hash(_) => None,
        };

        MutinyInvoice {
            bolt11: value.to_string(),
            description,
            payment_hash: value.payment_hash().to_owned().to_hex(),
            preimage: None,
            amount_sats: value.amount_milli_satoshis().map(|m| m / 1000),
            expire: None, // todo
            paid: false,
            fees_paid: 0,
            is_send: false, // todo this could be bad
        }
    }
}

#[wasm_bindgen]
pub struct MutinyChannel {
    pub balance: u64,
    pub size: u64,
    outpoint: String,
    peer: String,
    pub confirmed: bool,
}

#[wasm_bindgen]
impl MutinyChannel {
    #[wasm_bindgen(getter)]
    pub fn outpoint(&self) -> String {
        self.outpoint.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn peer(&self) -> String {
        self.peer.clone()
    }
}

#[wasm_bindgen]
pub struct MutinyBalance {
    pub confirmed: u64,
    pub unconfirmed: u64,
    pub lightning: u64,
}

#[wasm_bindgen]
impl NodeManager {
    #[wasm_bindgen]
    pub fn has_node_manager() -> bool {
        MutinyBrowserStorage::has_mnemonic()
    }

    #[wasm_bindgen(constructor)]
    pub fn new(password: String, mnemonic: Option<String>) -> Result<NodeManager, MutinyJsError> {
        set_panic_hook();

        // TODO get network from frontend
        let network = Network::Testnet;

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

        let wallet = Arc::new(MutinyWallet::new(
            mnemonic.clone(),
            storage.clone(),
            network,
        ));

        let chain = Arc::new(MutinyChain::new(wallet.clone()));

        let node_storage = match MutinyBrowserStorage::get_nodes() {
            Ok(node_storage) => node_storage,
            Err(e) => {
                return Err(MutinyError::ReadError {
                    source: MutinyStorageError::Other(e.into()),
                }
                .into());
            }
        };

        Ok(NodeManager {
            mnemonic,
            network,
            wallet,
            chain,
            storage,
            node_storage: Mutex::new(node_storage),
            nodes: Arc::new(Mutex::new(HashMap::new())), // TODO init the nodes
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
    pub async fn send_to_address(
        &self,
        destination_address: String,
        amount: u64,
        fee_rate: Option<f32>,
    ) -> Result<String, MutinyJsError> {
        match self
            .wallet
            .send(destination_address, amount, fee_rate)
            .await
        {
            Ok(txid) => Ok(txid.to_owned().to_string()),
            Err(e) => Err(e.into()),
        }
    }

    #[wasm_bindgen]
    pub async fn check_address(
        &self,
        _address: String,
    ) -> Result<JsValue /* TransactionDetails */, MutinyJsError> {
        todo!()
    }

    #[wasm_bindgen]
    pub async fn list_onchain(&self) -> Result<JsValue, MutinyJsError> {
        let txs = self.wallet.list_transactions(false).await?;

        Ok(serde_wasm_bindgen::to_value(&txs)?)
    }

    #[wasm_bindgen]
    pub async fn get_balance(&self) -> Result<MutinyBalance, MutinyJsError> {
        match self.wallet.wallet.lock().await.get_balance() {
            Ok(onchain) => {
                let balance = MutinyBalance {
                    confirmed: onchain.confirmed,
                    unconfirmed: onchain.untrusted_pending + onchain.trusted_pending,
                    lightning: 0,
                };
                Ok(balance)
            }
            Err(_) => Err(MutinyJsError::WalletOperationFailed),
        }
    }

    #[wasm_bindgen]
    pub async fn list_utxos(&self) -> Result<JsValue, MutinyJsError> {
        let utxos = self.wallet.list_utxos().await?;

        Ok(serde_wasm_bindgen::to_value(&utxos)?)
    }

    #[wasm_bindgen]
    pub async fn sync(&self) -> Result<(), MutinyJsError> {
        // sync bdk wallet
        match self.wallet.sync().await {
            Ok(()) => {
                // sync ldk wallet
                let nodes = self.nodes.lock().await;

                let confirmables: Vec<&(dyn Confirm + Sync)> = nodes
                    .iter()
                    .flat_map(|(_, node)| {
                        let vec: Vec<&(dyn Confirm + Sync)> =
                            vec![node.channel_manager.deref(), node.chain_monitor.deref()];
                        vec
                    })
                    .collect();

                self.chain.sync(confirmables).await?;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    #[wasm_bindgen]
    pub async fn new_node(&self) -> Result<NodeIdentity, MutinyJsError> {
        match create_new_node_from_node_manager(self).await {
            Ok(node_identity) => Ok(node_identity),
            Err(e) => Err(e.into()),
        }
    }

    #[wasm_bindgen]
    pub async fn connect_to_peer(
        &self,
        self_node_pubkey: String,
        websocket_proxy_addr: String,
        connection_string: String,
    ) -> Result<(), MutinyJsError> {
        if let Some(node) = self.nodes.lock().await.get(&self_node_pubkey) {
            let res = node
                .connect_peer(websocket_proxy_addr, connection_string.clone())
                .await;
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

    // all values in sats

    #[wasm_bindgen]
    pub async fn create_invoice(
        &self,
        _amount: u64,
        _description: String,
    ) -> Result<MutinyInvoice, MutinyJsError> {
        todo!()
    }

    #[wasm_bindgen]
    pub async fn pay_invoice(&self, _invoice: String) -> Result<MutinyInvoice, MutinyJsError> {
        todo!()
    }

    #[wasm_bindgen]
    pub async fn decode_invoice(&self, _invoice: String) -> Result<MutinyInvoice, MutinyJsError> {
        todo!()
    }

    #[wasm_bindgen]
    pub async fn get_invoice(&self, _invoice: String) -> Result<MutinyInvoice, MutinyJsError> {
        todo!()
    }

    #[wasm_bindgen]
    pub async fn get_invoice_by_hash(&self, _hash: String) -> Result<MutinyInvoice, MutinyJsError> {
        todo!()
    }

    #[wasm_bindgen]
    pub async fn list_invoices(
        &self,
        _invoice: String,
    ) -> Result<JsValue /* Vec<MutinyInvoice> */, MutinyJsError> {
        todo!()
    }

    #[wasm_bindgen]
    pub async fn open_channel(
        &self,
        _pubkey: String,
        _host: Option<String>,
        _port: Option<u16>,
        _amount: u64,
        _fee_rate: Option<u16>,
    ) -> Result<MutinyChannel, MutinyJsError> {
        todo!()
    }

    #[wasm_bindgen]
    pub async fn close_channel(&self, _outpoint: JsValue) -> Result<JsValue, MutinyJsError> {
        todo!()
    }

    #[wasm_bindgen]
    pub async fn list_channels(&self) -> Result<MutinyChannel, MutinyJsError> {
        todo!()
    }

    #[wasm_bindgen]
    pub async fn list_peers(&self) -> Result<JsValue /* Vec<String> */, MutinyJsError> {
        todo!()
    }

    #[wasm_bindgen]
    pub async fn list_ln_txs(&self) -> Result<JsValue /* Vec<MutinyInvoice> */, MutinyJsError> {
        todo!()
    }
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
        node_manager.chain.clone(),
        node_manager.network,
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
        .insert(node_pubkey.clone().to_string(), Arc::new(new_node));

    Ok(NodeIdentity {
        uuid: next_node.uuid.clone(),
        pubkey: node_pubkey.clone().to_string(),
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
    fn create_node_manager() {
        log!("creating node manager!");

        assert!(!NodeManager::has_node_manager());
        NodeManager::new("password".to_string(), None).expect("node manager should initialize");
        assert!(NodeManager::has_node_manager());

        cleanup_test();
    }

    #[test]
    fn correctly_show_seed() {
        log!("showing seed");

        let seed = generate_seed(12).expect("Failed to gen seed");
        let nm = NodeManager::new("password".to_string(), Some(seed.to_string())).unwrap();

        assert!(NodeManager::has_node_manager());
        assert_eq!(seed.to_string(), nm.show_seed());

        cleanup_test();
    }

    #[test]
    async fn created_new_nodes() {
        log!("creating new nodes");

        let seed = generate_seed(12).expect("Failed to gen seed");
        let nm = NodeManager::new("password".to_string(), Some(seed.to_string()))
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
