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
