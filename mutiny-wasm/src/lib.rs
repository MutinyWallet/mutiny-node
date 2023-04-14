// wasm_bindgen uses improper casing and it needs to be turned off:
// https://github.com/rustwasm/wasm-bindgen/issues/2882
// wasm is also considered "extra_unused_type_parameters"
#![allow(
    non_snake_case,
    non_upper_case_globals,
    clippy::extra_unused_type_parameters
)]

extern crate mutiny_core;

mod error;
mod models;
mod utils;

use crate::error::MutinyJsError;
use crate::models::*;
use mutiny_core::nodemanager;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct NodeManager {
    inner: nodemanager::NodeManager,
}

#[wasm_bindgen]
impl NodeManager {
    #[wasm_bindgen(constructor)]
    pub async fn new(
        password: String,
        mnemonic: Option<String>,
        websocket_proxy_addr: Option<String>,
        network_str: Option<String>,
        user_esplora_url: Option<String>,
        user_rgs_url: Option<String>,
        lsp_url: Option<String>,
    ) -> Result<NodeManager, MutinyJsError> {
        crate::utils::set_panic_hook();

        let inner = nodemanager::NodeManager::new(
            password,
            mnemonic,
            websocket_proxy_addr,
            network_str,
            user_esplora_url,
            user_rgs_url,
            lsp_url,
        )
        .await?;
        Ok(NodeManager { inner })
    }

    #[wasm_bindgen]
    pub fn has_node_manager() -> bool {
        nodemanager::NodeManager::has_node_manager()
    }

    #[wasm_bindgen]
    pub fn broadcast_transaction(&self, str: String) -> Result<(), MutinyJsError> {
        Ok(self.inner.broadcast_transaction(str)?)
    }

    #[wasm_bindgen]
    pub fn show_seed(&self) -> String {
        self.inner.show_seed()
    }

    #[wasm_bindgen]
    pub fn get_network(&self) -> String {
        self.inner.get_network()
    }

    #[wasm_bindgen]
    pub async fn get_new_address(&self) -> Result<String, MutinyJsError> {
        Ok(self.inner.get_new_address().await?)
    }

    #[wasm_bindgen]
    pub async fn get_wallet_balance(&self) -> Result<u64, MutinyJsError> {
        Ok(self.inner.get_wallet_balance().await?)
    }

    #[wasm_bindgen]
    pub async fn create_bip21(
        &self,
        amount: Option<u64>,
        description: Option<String>,
    ) -> Result<MutinyBip21RawMaterials, MutinyJsError> {
        Ok(self.inner.create_bip21(amount, description).await?.into())
    }

    #[wasm_bindgen]
    pub async fn send_to_address(
        &self,
        destination_address: String,
        amount: u64,
        fee_rate: Option<f32>,
    ) -> Result<String, MutinyJsError> {
        Ok(self
            .inner
            .send_to_address(destination_address, amount, fee_rate)
            .await?
            .to_string())
    }

    #[wasm_bindgen]
    pub async fn sweep_wallet(
        &self,
        destination_address: String,
        fee_rate: Option<f32>,
    ) -> Result<String, MutinyJsError> {
        Ok(self
            .inner
            .sweep_wallet(destination_address, fee_rate)
            .await?
            .to_string())
    }

    #[wasm_bindgen]
    pub async fn check_address(
        &self,
        address: String,
    ) -> Result<JsValue /* Option<TransactionDetails> */, MutinyJsError> {
        Ok(serde_wasm_bindgen::to_value(
            &self.inner.check_address(address).await?,
        )?)
    }

    #[wasm_bindgen]
    pub async fn list_onchain(
        &self,
    ) -> Result<JsValue /* Vec<TransactionDetails> */, MutinyJsError> {
        Ok(serde_wasm_bindgen::to_value(
            &self.inner.list_onchain().await?,
        )?)
    }

    #[wasm_bindgen]
    pub async fn get_transaction(
        &self,
        txid: String,
    ) -> Result<JsValue /* Option<TransactionDetails> */, MutinyJsError> {
        Ok(serde_wasm_bindgen::to_value(
            &self.inner.get_transaction(txid).await?,
        )?)
    }

    #[wasm_bindgen]
    pub async fn get_balance(&self) -> Result<MutinyBalance, MutinyJsError> {
        Ok(self.inner.get_balance().await?.into())
    }

    #[wasm_bindgen]
    pub async fn list_utxos(&self) -> Result<JsValue, MutinyJsError> {
        Ok(serde_wasm_bindgen::to_value(
            &self.inner.list_utxos().await?,
        )?)
    }

    #[wasm_bindgen]
    pub async fn sync(&self) -> Result<(), MutinyJsError> {
        Ok(self.inner.sync().await?)
    }

    #[wasm_bindgen]
    pub fn estimate_fee_normal(&self) -> u32 {
        self.inner.estimate_fee_normal()
    }

    #[wasm_bindgen]
    pub fn estimate_fee_high(&self) -> u32 {
        self.inner.estimate_fee_high()
    }

    #[wasm_bindgen]
    pub async fn new_node(&self) -> Result<NodeIdentity, MutinyJsError> {
        Ok(self.inner.new_node().await?.into())
    }

    #[wasm_bindgen]
    pub async fn list_nodes(&self) -> Result<JsValue /* Vec<String> */, MutinyJsError> {
        Ok(serde_wasm_bindgen::to_value(
            &self.inner.list_nodes().await?,
        )?)
    }

    #[wasm_bindgen]
    pub async fn connect_to_peer(
        &self,
        self_node_pubkey: String,
        connection_string: String,
    ) -> Result<(), MutinyJsError> {
        Ok(self
            .inner
            .connect_to_peer(self_node_pubkey, connection_string)
            .await?)
    }

    #[wasm_bindgen]
    pub async fn disconnect_peer(
        &self,
        self_node_pubkey: String,
        peer: String,
    ) -> Result<(), MutinyJsError> {
        Ok(self.inner.disconnect_peer(self_node_pubkey, peer).await?)
    }

    #[wasm_bindgen]
    pub async fn delete_peer(
        &self,
        self_node_pubkey: String,
        peer: String,
    ) -> Result<(), MutinyJsError> {
        Ok(self.inner.delete_peer(self_node_pubkey, peer).await?)
    }

    #[wasm_bindgen]
    pub async fn create_invoice(
        &self,
        amount: Option<u64>,
        description: String,
    ) -> Result<MutinyInvoice, MutinyJsError> {
        Ok(self.inner.create_invoice(amount, description).await?.into())
    }

    #[wasm_bindgen]
    pub async fn pay_invoice(
        &self,
        from_node: String,
        invoice_str: String,
        amt_sats: Option<u64>,
    ) -> Result<MutinyInvoice, MutinyJsError> {
        Ok(self
            .inner
            .pay_invoice(from_node, invoice_str, amt_sats)
            .await?
            .into())
    }

    #[wasm_bindgen]
    pub async fn keysend(
        &self,
        from_node: String,
        to_node: String,
        amt_sats: u64,
    ) -> Result<MutinyInvoice, MutinyJsError> {
        Ok(self
            .inner
            .keysend(from_node, to_node, amt_sats)
            .await?
            .into())
    }

    #[wasm_bindgen]
    pub async fn decode_invoice(&self, invoice: String) -> Result<MutinyInvoice, MutinyJsError> {
        Ok(self.inner.decode_invoice(invoice).await?.into())
    }

    #[wasm_bindgen]
    pub async fn decode_lnurl(&self, lnurl: String) -> Result<LnUrlParams, MutinyJsError> {
        Ok(self.inner.decode_lnurl(lnurl).await?.into())
    }

    #[wasm_bindgen]
    pub async fn lnurl_pay(
        &self,
        from_node: String,
        lnurl: String,
        amount_sats: u64,
    ) -> Result<MutinyInvoice, MutinyJsError> {
        Ok(self
            .inner
            .lnurl_pay(from_node, lnurl, amount_sats)
            .await?
            .into())
    }

    #[wasm_bindgen]
    pub async fn lnurl_withdraw(
        &self,
        lnurl: String,
        amount_sats: u64,
    ) -> Result<bool, MutinyJsError> {
        Ok(self.inner.lnurl_withdraw(lnurl, amount_sats).await?)
    }

    #[wasm_bindgen]
    pub async fn get_invoice(&self, invoice: String) -> Result<MutinyInvoice, MutinyJsError> {
        Ok(self.inner.get_invoice(invoice).await?.into())
    }

    #[wasm_bindgen]
    pub async fn get_invoice_by_hash(&self, hash: String) -> Result<MutinyInvoice, MutinyJsError> {
        Ok(self.inner.get_invoice_by_hash(hash).await?.into())
    }

    #[wasm_bindgen]
    pub async fn list_invoices(&self) -> Result<JsValue /* Vec<MutinyInvoice> */, MutinyJsError> {
        Ok(serde_wasm_bindgen::to_value(
            &self.inner.list_invoices().await?,
        )?)
    }

    #[wasm_bindgen]
    pub async fn open_channel(
        &self,
        from_node: String,
        to_pubkey: String,
        amount: u64,
    ) -> Result<MutinyChannel, MutinyJsError> {
        Ok(self
            .inner
            .open_channel(from_node, to_pubkey, amount)
            .await?
            .into())
    }

    #[wasm_bindgen]
    pub async fn close_channel(&self, outpoint: String) -> Result<(), MutinyJsError> {
        Ok(self.inner.close_channel(outpoint).await?)
    }

    #[wasm_bindgen]
    pub async fn list_channels(&self) -> Result<JsValue /* Vec<MutinyChannel> */, MutinyJsError> {
        Ok(serde_wasm_bindgen::to_value(
            &self.inner.list_channels().await?,
        )?)
    }

    #[wasm_bindgen]
    pub async fn list_peers(&self) -> Result<JsValue /* Vec<MutinyPeer> */, MutinyJsError> {
        Ok(serde_wasm_bindgen::to_value(
            &self.inner.list_peers().await?,
        )?)
    }

    #[wasm_bindgen]
    pub async fn get_bitcoin_price(&self) -> Result<f32, MutinyJsError> {
        Ok(self.inner.get_bitcoin_price().await?)
    }

    #[wasm_bindgen]
    pub fn convert_btc_to_sats(&self, btc: f64) -> Result<u64, MutinyJsError> {
        Ok(mutiny_core::nodemanager::NodeManager::convert_btc_to_sats(
            btc,
        )?)
    }

    #[wasm_bindgen]
    pub fn convert_sats_to_btc(&self, sats: u64) -> f64 {
        mutiny_core::nodemanager::NodeManager::convert_sats_to_btc(sats)
    }
}

#[cfg(test)]
mod tests {
    use crate::NodeManager;

    use crate::utils::test::*;

    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn create_node_manager() {
        log!("creating node manager!");

        assert!(!NodeManager::has_node_manager());
        NodeManager::new(
            "password".to_string(),
            None,
            None,
            Some("testnet".to_owned()),
            None,
            None,
            None,
        )
        .await
        .expect("node manager should initialize");
        assert!(NodeManager::has_node_manager());

        cleanup_test();
    }

    #[test]
    async fn correctly_show_seed() {
        log!("showing seed");

        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy).unwrap();
        let seed = bip39::Mnemonic::from_entropy(&entropy).unwrap();

        let nm = NodeManager::new(
            "password".to_string(),
            Some(seed.to_string()),
            None,
            Some("testnet".to_owned()),
            None,
            None,
            None,
        )
        .await
        .unwrap();

        assert!(NodeManager::has_node_manager());
        assert_eq!(seed.to_string(), nm.show_seed());

        cleanup_test();
    }

    #[test]
    async fn created_new_nodes() {
        log!("creating new nodes");

        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy).unwrap();
        let seed = bip39::Mnemonic::from_entropy(&entropy).unwrap();

        let nm = NodeManager::new(
            "password".to_string(),
            Some(seed.to_string()),
            None,
            Some("testnet".to_owned()),
            None,
            None,
            None,
        )
        .await
        .expect("node manager should initialize");

        let node_identity = nm.new_node().await.expect("should create new node");
        assert_ne!("", node_identity.uuid());
        assert_ne!("", node_identity.pubkey());

        let node_identity = nm.new_node().await.expect("node manager should initialize");

        assert_ne!("", node_identity.uuid());
        assert_ne!("", node_identity.pubkey());

        cleanup_test();
    }
}
