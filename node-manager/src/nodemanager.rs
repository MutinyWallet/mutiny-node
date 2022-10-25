use std::{str::FromStr, sync::Arc};

use bdk::wallet::AddressIndex;
use bip32::XPrv;
use bip39::Mnemonic;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::Network;
use futures::{lock::Mutex, stream::SplitSink, SinkExt, StreamExt};
use gloo_net::websocket::{futures::WebSocket, Message};
use lightning::chain::keysinterface::{KeysInterface, KeysManager, Recipient};
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
    wallet: MutinyWallet,
    ws_write: Arc<Mutex<SplitSink<WebSocket, Message>>>,
    counter: usize,
}

#[derive(Serialize, Deserialize)]
pub struct NodeKeys {
    pub node_keys: Vec<NodeKey>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct NodeKey {
    pub id: String,
    pub pubkey: String,
    pub child_index: i32,
}

#[wasm_bindgen]
impl NodeManager {
    #[wasm_bindgen]
    pub fn has_node_manager() -> bool {
        let res = MutinyBrowserStorage::get_mnemonic();
        res.is_ok()
    }

    #[wasm_bindgen(constructor)]
    pub fn new(mnemonic: Option<String>) -> NodeManager {
        set_panic_hook();

        let mnemonic = match mnemonic {
            Some(m) => {
                let seed = Mnemonic::from_str(String::as_str(&m))
                    .expect("could not parse specified mnemonic");
                MutinyBrowserStorage::insert_mnemonic(seed)
            }
            None => MutinyBrowserStorage::get_mnemonic().unwrap_or_else(|_| {
                let seed = seedgen::generate_seed();
                MutinyBrowserStorage::insert_mnemonic(seed)
            }),
        };

        let wallet = MutinyWallet::new(mnemonic.clone(), Network::Testnet);

        let ws = WebSocket::open("wss://ws.postman-echo.com/raw").unwrap();
        let (write, mut read) = ws.split();

        spawn_local(async move {
            while let Some(msg) = read.next().await {
                info!("1. {:?}", msg)
            }
            debug!("WebSocket Closed")
        });

        NodeManager {
            mnemonic,
            wallet,
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

    pub fn new_node(&self) -> String {
        // Get the current nodes and their bip32 indices
        // so that we can create another node with the next.
        // TODO mutex lock this call
        let mut existing_node_keys =
            MutinyBrowserStorage::get_node_keys().expect("could not retrieve node keys");
        let next_node_index = match existing_node_keys
            .node_keys
            .iter()
            .max_by_key(|n| n.child_index)
        {
            None => 1,
            Some(n) => n.child_index,
        };

        // Get the pubkey of this node before we save it
        // TODO too many unwraps here
        let xpriv = XPrv::new(&self.mnemonic.to_seed(""))
            .unwrap()
            .derive_child(bip32::ChildNumber::new(next_node_index as u32, true).unwrap())
            .unwrap();
        let current_time = instant::now();
        let keys_manager = Arc::new(KeysManager::new(
            &xpriv.to_bytes(),
            (current_time / 1000.0).round() as u64,
            (current_time * 1000.0).round() as u32,
        ));
        let mut secp_ctx = Secp256k1::new();
        let keys_manager_clone = keys_manager.clone();
        secp_ctx.seeded_randomize(&keys_manager_clone.get_secure_random_bytes());
        let our_network_key = keys_manager_clone
            .get_node_secret(Recipient::Node)
            .expect("cannot parse node secret");
        let pubkey = PublicKey::from_secret_key(&secp_ctx, &our_network_key).to_string();

        // Create and save a new node using the next child index
        let next_node = NodeKey {
            id: Uuid::new_v4().to_string(),
            pubkey,
            child_index: next_node_index,
        };
        existing_node_keys.node_keys.push(next_node.clone());
        MutinyBrowserStorage::insert_node_keys(existing_node_keys)
            .expect("could not insert node keys");
        return next_node.id;
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

#[cfg(test)]
mod tests {
    use crate::nodemanager::NodeManager;
    use crate::seedgen::generate_seed;

    use crate::test::*;

    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    macro_rules! log {
        ( $( $t:tt )* ) => {
            web_sys::console::log_1(&format!( $( $t )* ).into());
        }
    }

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
}
