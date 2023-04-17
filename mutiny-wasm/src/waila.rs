use std::str::FromStr;
use wasm_bindgen::prelude::*;

#[derive(Debug)]
#[wasm_bindgen]
pub struct PaymentParams {
    string: String,
    params: bitcoin_waila::PaymentParams<'static>,
}

#[wasm_bindgen]
impl PaymentParams {
    #[wasm_bindgen(constructor)]
    pub fn from_string(string: String) -> Result<PaymentParams, JsValue> {
        let params = bitcoin_waila::PaymentParams::from_str(&string).map_err(|_| JsValue::NULL)?;
        Ok(PaymentParams { string, params })
    }

    #[wasm_bindgen(getter)]
    pub fn string(&self) -> String {
        self.string.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn memo(&self) -> Option<String> {
        self.params.memo()
    }

    #[wasm_bindgen(getter)]
    pub fn network(&self) -> Option<String> {
        self.params.network().map(|n| n.to_string())
    }

    #[wasm_bindgen(getter)]
    pub fn amount_sats(&self) -> Option<u64> {
        self.params.amount().map(|amount| amount.to_sat())
    }

    #[wasm_bindgen(getter)]
    pub fn amount_msats(&self) -> Option<u64> {
        self.params.amount_msats()
    }

    #[wasm_bindgen(getter)]
    pub fn address(&self) -> Option<String> {
        self.params.address().map(|addr| addr.to_string())
    }

    #[wasm_bindgen(getter)]
    pub fn invoice(&self) -> Option<String> {
        self.params.invoice().map(|invoice| invoice.to_string())
    }

    #[wasm_bindgen(getter)]
    pub fn node_pubkey(&self) -> Option<String> {
        self.params.node_pubkey().map(|pubkey| pubkey.to_string())
    }

    #[wasm_bindgen(getter)]
    pub fn lnurl(&self) -> Option<String> {
        self.params.lnurl().map(|lnurl| lnurl.to_string())
    }
}
