// wasm_bindgen uses improper casing and it needs to be turned off:
// https://github.com/rustwasm/wasm-bindgen/issues/2882
// wasm is also considered "extra_unused_type_parameters"
#![allow(
    incomplete_features,
    non_snake_case,
    non_upper_case_globals,
    clippy::extra_unused_type_parameters
)]
#![feature(io_error_other)]
#![feature(async_fn_in_trait)]
// background file is mostly an LDK copy paste
#![allow(clippy::all)]
mod background;

mod bdkstorage;
mod chain;
mod encrypt;
mod error;
mod esplora;
mod event;
mod fees;
mod keymanager;
mod ldkstorage;
mod localstorage;
mod logging;
mod node;
mod nodemanager;
mod peermanager;
mod proxy;
mod socket;
mod utils;
mod wallet;

use log::{debug, Level};
use wasm_bindgen::prelude::*;

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
