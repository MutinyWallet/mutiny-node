#![feature(io_error_other)]
#![allow(non_snake_case, non_upper_case_globals)]
// wasm_bindgen uses improper casing and it needs to be turned off:
// https://github.com/rustwasm/wasm-bindgen/issues/2882

mod background;
mod bdkstorage;
mod chain;
mod dlc;
mod dlcstorage;
mod encrypt;
mod error;
mod event;
mod invoice;
mod keymanager;
mod ldkstorage;
mod localstorage;
mod logging;
mod node;
mod nodemanager;
mod tcpproxy;
mod utils;
mod wallet;

use cfg_if::cfg_if;
use log::{debug, Level};
use wasm_bindgen::prelude::*;

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
    debug!("Main function begins and ends");
    Ok(())
}

#[cfg(test)]
mod test {
    use gloo_storage::{LocalStorage, Storage};

    macro_rules! log {
        ( $( $t:tt )* ) => {
            web_sys::console::log_1(&format!( $( $t )* ).into());
        }
    }
    pub(crate) use log;

    pub(crate) fn cleanup_test() {
        LocalStorage::clear();
    }
}
