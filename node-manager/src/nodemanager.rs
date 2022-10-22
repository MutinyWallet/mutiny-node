use bip39::Mnemonic;
use futures::{lock::Mutex, stream::SplitSink, SinkExt, StreamExt};
use gloo_net::websocket::{futures::WebSocket, Message};
use log::{debug, info};
use std::{str::FromStr, sync::Arc};
use gloo_storage::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::{seedgen, utils::set_panic_hook};

#[wasm_bindgen]
pub struct NodeManager {
    mnemonic: Mnemonic,
    ws_write: Arc<Mutex<SplitSink<WebSocket, Message>>>,
    counter: usize,
}

#[wasm_bindgen]
impl NodeManager {
    fn insert_mnemonic(mnemonic: Mnemonic) -> Mnemonic {
        LocalStorage::set("mnemonic", mnemonic.clone().to_string())
            .expect("Failed to write to storage");
        mnemonic
    }

    #[wasm_bindgen]
    pub fn has_node_manager() -> bool {
        let res: Result<String> = LocalStorage::get("mnemonic");
        res.is_ok()
    }

    #[wasm_bindgen(constructor)]
    pub fn new(mnemonic: Option<String>) -> NodeManager {
        set_panic_hook();

        let mnemonic = match mnemonic {
            Some(m) => {
                let seed =
                    Mnemonic::from_str(String::as_str(&m)).expect("could not parse specified mnemonic");
                NodeManager::insert_mnemonic(seed)
            }
            None => {
                let res: Result<String> = LocalStorage::get("mnemonic");
                match res {
                    Ok(str) => Mnemonic::from_str(&str)
                        .expect("could not parse specified mnemonic"),
                    Err(_) => {
                        // does not exist, need to generate
                        let seed = seedgen::generate_seed();

                        NodeManager::insert_mnemonic(seed)
                    }
                }
            }
        };

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
            ws_write: Arc::new(Mutex::new(write)),
            counter: 0,
        }
    }

    #[wasm_bindgen]
    pub fn show_seed(&self) -> String {
        return self.mnemonic.to_string();
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
    use gloo_storage::{LocalStorage, Storage};
    use crate::nodemanager::NodeManager;
    use crate::seedgen::generate_seed;

    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    fn cleanup_test() -> () {
        LocalStorage::delete("mnemonic");
    }

    #[test]
    fn create_node_manager() {
        assert!(!NodeManager::has_node_manager());
        NodeManager::new(None);
        assert!(NodeManager::has_node_manager());

        cleanup_test();
    }

    #[test]
    fn correctly_show_seed() {
        let seed = generate_seed();
        let nm = NodeManager::new(Some(seed.to_string()));

        assert!(NodeManager::has_node_manager());
        assert_eq!(seed.to_string(), nm.show_seed());

        cleanup_test();
    }
}
