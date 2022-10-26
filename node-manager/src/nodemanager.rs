use std::collections::HashMap;
use std::{str::FromStr, sync::Arc};

use bdk::wallet::AddressIndex;
use bip39::Mnemonic;
use bitcoin::secp256k1::PublicKey;
use bitcoin::Network;
use futures::{lock::Mutex, stream::SplitSink, SinkExt, StreamExt};
use gloo_net::websocket::{futures::WebSocket, Message};
use log::{debug, info};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::{
    localstorage::MutinyBrowserStorage, seedgen, utils::set_panic_hook, wallet::MutinyWallet,
};

#[wasm_bindgen]
pub struct NodeManager {
    mnemonic: Mnemonic,
    storage: MutinyBrowserStorage,
    wallet: MutinyWallet,
    node_storage: Mutex<NodeStorage>,
    ws_write: Arc<Mutex<SplitSink<WebSocket, Message>>>,
    counter: usize,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct NodeStorage {
    pub nodes: HashMap<String, NodeIndex>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct NodeIndex {
    pub id: String,
    pub pubkey: PublicKey,
    pub child_index: u32,
}

#[wasm_bindgen]
impl NodeManager {
    #[wasm_bindgen]
    pub fn has_node_manager() -> bool {
        MutinyBrowserStorage::has_mnemonic()
    }

    #[wasm_bindgen(constructor)]
    pub fn new(mnemonic: Option<String>) -> NodeManager {
        set_panic_hook();

        let storage = MutinyBrowserStorage::new();

        let mnemonic = match mnemonic {
            Some(m) => {
                let seed = Mnemonic::from_str(String::as_str(&m))
                    .expect("could not parse specified mnemonic");
                storage.insert_mnemonic(seed)
            }
            None => storage.get_mnemonic().unwrap_or_else(|_| {
                let seed = seedgen::generate_seed();
                storage.insert_mnemonic(seed)
            }),
        };

        let wallet = MutinyWallet::new(mnemonic.clone(), storage.clone(), Network::Testnet);

        let ws = WebSocket::open("wss://ws.postman-echo.com/raw").unwrap();
        let (write, mut read) = ws.split();

        spawn_local(async move {
            while let Some(msg) = read.next().await {
                info!("1. {:?}", msg)
            }
            debug!("WebSocket Closed")
        });

        let node_storage = MutinyBrowserStorage::get_nodes().expect("could not retrieve node keys");

        NodeManager {
            mnemonic,
            storage,
            wallet,
            node_storage: Mutex::new(node_storage),
            ws_write: Arc::new(Mutex::new(write)),
            counter: 0,
        }
    }

    #[wasm_bindgen]
    pub fn show_seed(&self) -> String {
        self.mnemonic.to_string()
    }

    #[wasm_bindgen]
    pub async fn get_new_address(&self) -> String {
        self.wallet
            .wallet
            .lock()
            .await
            .get_address(AddressIndex::New)
            .unwrap()
            .address
            .to_string()
    }

    #[wasm_bindgen]
    pub async fn get_wallet_balance(&self) -> u64 {
        self.wallet
            .wallet
            .lock()
            .await
            .get_balance()
            .unwrap()
            .get_total()
    }

    #[wasm_bindgen]
    pub async fn sync(&self) {
        self.wallet.sync().await.expect("Wallet failed to sync")
    }

    #[wasm_bindgen]
    pub async fn new_node(&self) -> String {
        create_new_node_from_node_manager(self).await.to_string()
    }

    #[wasm_bindgen]
    pub fn test_ws(&mut self) {
        let write = self.ws_write.clone();
        let count = self.counter;
        spawn_local(async move {
            write
                .clone()
                .lock()
                .await
                .send(Message::Text(format!("Test number {}", count)))
                .await
                .unwrap();
        });
        self.counter += 1;
    }
}

// This will create a new node with a node manager and return the PublicKey of the node created.
pub(crate) async fn create_new_node_from_node_manager(node_manager: &NodeManager) -> PublicKey {
    // Begin with a mutex lock so that nothing else can
    // save or alter the node list while it is about to
    // be saved.
    let mut node_mutex = node_manager.node_storage.lock().await;

    // Get the current nodes and their bip32 indices
    // so that we can create another node with the next.
    // Always get it from our storage, the node_mutex is
    // mostly for read only and locking.
    let mut existing_nodes = MutinyBrowserStorage::get_nodes().expect("could not retrieve nodes");
    let next_node_index = match existing_nodes
        .nodes
        .iter()
        .max_by_key(|(_, v)| v.child_index)
    {
        None => 0,
        Some((_, v)) => v.child_index + 1,
    };

    // Get the pubkey of this node before we save it
    let pubkey = seedgen::derive_pubkey_child(node_manager.mnemonic.clone(), next_node_index);

    // Create and save a new node using the next child index
    let next_node = NodeIndex {
        id: Uuid::new_v4().to_string(),
        pubkey,
        child_index: next_node_index,
    };
    existing_nodes
        .nodes
        .insert(pubkey.to_string(), next_node.clone());
    MutinyBrowserStorage::insert_nodes(existing_nodes.clone()).expect("could not insert nodes");
    node_mutex.nodes = existing_nodes.nodes.clone();
    pubkey
}

#[cfg(test)]
mod tests {
    use crate::nodemanager::NodeManager;
    use crate::seedgen::generate_seed;

    use crate::test::*;

    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    fn create_node_manager() {
        log!("creating node manager!");

        assert!(!NodeManager::has_node_manager());
        NodeManager::new(None);
        assert!(NodeManager::has_node_manager());

        cleanup_test();
    }

    #[test]
    fn correctly_show_seed() {
        log!("showing seed");

        let seed = generate_seed();
        let nm = NodeManager::new(Some(seed.to_string()));

        assert!(NodeManager::has_node_manager());
        assert_eq!(seed.to_string(), nm.show_seed());

        cleanup_test();
    }

    #[test]
    async fn created_new_nodes() {
        log!("creating new nodes");

        let seed = generate_seed();
        let nm = NodeManager::new(Some(seed.to_string()));

        {
            let node_pubkey = nm.new_node().await;
            let node_storage = nm.node_storage.lock().await;
            assert_ne!("", node_pubkey);
            assert_eq!(1, node_storage.nodes.len());

            let retrieved_node = node_storage.nodes.get(&node_pubkey.to_string()).unwrap();
            assert_eq!(node_pubkey, retrieved_node.pubkey.to_string());
            assert_eq!(0, retrieved_node.child_index);
        }

        {
            let node_pubkey = nm.new_node().await;
            let node_storage = nm.node_storage.lock().await;

            assert_ne!("", node_pubkey);
            assert_eq!(2, node_storage.nodes.len());

            let retrieved_node = node_storage.nodes.get(&node_pubkey.to_string()).unwrap();
            assert_eq!(node_pubkey, retrieved_node.pubkey.to_string());
            assert_eq!(1, retrieved_node.child_index);
        }

        cleanup_test();
    }
}
