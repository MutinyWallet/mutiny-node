#![allow(non_snake_case, non_upper_case_globals)]
// wasm_bindgen uses improper casing and it needs to be turned off:
// https://github.com/rustwasm/wasm-bindgen/issues/2882

extern crate cfg_if;
extern crate wasm_bindgen;

mod seedgen;
mod utils;

use bip39::Mnemonic;
use cfg_if::cfg_if;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

cfg_if! {
    if #[cfg(feature = "wee_alloc")] {
        extern crate wee_alloc;
        #[global_allocator]
        static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
    }
}

#[wasm_bindgen]
pub struct NodeManager {
    mnemonic: Mnemonic,
}

#[wasm_bindgen]
impl NodeManager {
    #[wasm_bindgen(constructor)]
    pub fn new(mnemonic: Option<String>) -> NodeManager {
        utils::set_panic_hook();

        let mnemonic = if let Some(m) = mnemonic {
            Mnemonic::from_str(String::as_str(&m)).expect("could not parse specified mnemonic")
        } else {
            seedgen::generate_seed()
        };

        NodeManager { mnemonic }
    }

    #[wasm_bindgen]
    pub fn show_seed(&self) -> String {
        return self.mnemonic.to_string();
    }
}
