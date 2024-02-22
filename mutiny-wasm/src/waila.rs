use bitcoin::Network;
use nostr::prelude::ToBech32;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone)]
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

    #[wasm_bindgen]
    pub fn valid_for_network(&self, network: String) -> Option<bool> {
        let network = Network::from_str(&network).ok()?;
        self.params.valid_for_network(network)
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
    pub fn offer(&self) -> Option<String> {
        self.params.offer().map(|offer| offer.to_string())
    }

    #[wasm_bindgen(getter)]
    pub fn refund(&self) -> Option<String> {
        self.params.refund().map(|refund| refund.to_string())
    }

    #[wasm_bindgen(getter)]
    pub fn node_pubkey(&self) -> Option<String> {
        self.params.node_pubkey().map(|pubkey| pubkey.to_string())
    }

    #[wasm_bindgen(getter)]
    pub fn lnurl(&self) -> Option<String> {
        self.params.lnurl().map(|lnurl| lnurl.to_string())
    }

    #[wasm_bindgen(getter)]
    pub fn lightning_address(&self) -> Option<String> {
        self.params.lightning_address().map(|addr| addr.to_string())
    }

    #[wasm_bindgen(getter)]
    pub fn is_lnurl_auth(&self) -> bool {
        self.params.is_lnurl_auth()
    }

    #[wasm_bindgen(getter)]
    pub fn nostr_pubkey(&self) -> Option<String> {
        self.params
            .nostr_pubkey()
            .and_then(|key| key.to_bech32().ok())
    }

    #[wasm_bindgen(getter)]
    pub fn fedimint_invite_code(&self) -> Option<String> {
        self.params.fedimint_invite_code()
    }

    #[wasm_bindgen(getter)]
    pub fn nostr_wallet_auth(&self) -> Option<String> {
        self.params.nostr_wallet_auth().map(|u| u.to_string())
    }

    #[wasm_bindgen(getter)]
    pub fn cashu_token(&self) -> Option<String> {
        self.params.cashu_token().and_then(|t| t.serialize().ok())
    }

    #[wasm_bindgen(getter)]
    pub fn fedimint_oob_notes(&self) -> Option<String> {
        self.params.fedimint_oob_notes().map(|t| t.to_string())
    }

    #[wasm_bindgen(getter)]
    pub fn payjoin_endpoint(&self) -> Option<String> {
        self.params.payjoin_endpoint().map(|n| n.to_string())
    }

    #[wasm_bindgen(getter)]
    pub fn disable_output_substitution(&self) -> Option<bool> {
        self.params.disable_output_substitution()
    }

    #[wasm_bindgen(getter)]
    pub fn payjoin_supported(&self) -> bool {
        self.params.payjoin_endpoint().is_some()
    }
}
