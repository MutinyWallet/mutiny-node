use bip39::Mnemonic;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

use crate::{seedgen, utils::set_panic_hook};

#[wasm_bindgen]
pub struct NodeManager {
    mnemonic: Mnemonic,
}

#[wasm_bindgen]
impl NodeManager {
    #[wasm_bindgen(constructor)]
    pub fn new(mnemonic: Option<String>) -> NodeManager {
        set_panic_hook();

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
