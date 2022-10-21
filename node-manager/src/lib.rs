#![allow(non_snake_case, non_upper_case_globals)]
// wasm_bindgen uses improper casing and it needs to be turned off:
// https://github.com/rustwasm/wasm-bindgen/issues/2882

mod nodemanager;
mod seedgen;
mod utils;

use cfg_if::cfg_if;
use futures::{SinkExt, StreamExt};
use gloo_net::websocket::{futures::WebSocket, Message};
use log::{debug, info, Level};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

cfg_if! {
    if #[cfg(feature = "wee_alloc")] {
        extern crate wee_alloc;
        #[global_allocator]
        static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
    }
}

#[wasm_bindgen(start)]
pub async fn main_js() -> Result<(), JsValue> {
    wasm_logger::init(wasm_logger::Config::new(Level::Debug).message_on_new_line());

    debug!("Main function begins");

    let ws = WebSocket::open("wss://ws.postman-echo.com/raw").unwrap();
    let (mut write, mut read) = ws.split();

    spawn_local(async move {
        while let Some(msg) = read.next().await {
            info!("1. {:?}", msg)
        }
        debug!("WebSocket Closed")
    });

    spawn_local(async move {
        write
            .send(Message::Text(String::from("Test from main")))
            .await
            .unwrap();
    });

    debug!("Main function ends");

    Ok(())
}
