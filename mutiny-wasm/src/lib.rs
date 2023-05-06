// wasm is considered "extra_unused_type_parameters"
#![allow(clippy::extra_unused_type_parameters)]

extern crate mutiny_core;

mod error;
mod models;
mod utils;

use crate::error::MutinyJsError;
use crate::models::*;
use bip39::Mnemonic;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::sha256;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, Network, OutPoint, Transaction, Txid};
use gloo_utils::format::JsValueSerdeExt;
use lightning::routing::gossip::NodeId;
use lightning_invoice::Invoice;
use lnurl::lnurl::LnUrl;
use mutiny_core::nodemanager;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct MutinyWallet {
    inner: mutiny_core::MutinyWallet,
}

/// The [MutinyWallet] is the main entry point for interacting with the Mutiny Wallet.
/// It is responsible for managing the on-chain wallet and the lightning nodes.
///
/// It can be used to create a new wallet, or to load an existing wallet.
///
/// It can be configured to use all different custom backend services, or to use the default
/// services provided by Mutiny.
#[wasm_bindgen]
impl MutinyWallet {
    /// Creates a new [MutinyWallet] with the given parameters.
    /// The mnemonic seed is read from storage, unless one is provided.
    /// If no mnemonic is provided, a new one is generated and stored.
    #[wasm_bindgen(constructor)]
    pub async fn new(
        password: String,
        mnemonic_str: Option<String>,
        websocket_proxy_addr: Option<String>,
        network_str: Option<String>,
        user_esplora_url: Option<String>,
        user_rgs_url: Option<String>,
        lsp_url: Option<String>,
    ) -> Result<MutinyWallet, MutinyJsError> {
        utils::set_panic_hook();

        let network: Option<Network> = network_str.map(|s| s.parse().expect("Invalid network"));

        let mnemonic = match mnemonic_str {
            Some(m) => Some(Mnemonic::from_str(&m).map_err(|_| MutinyJsError::InvalidMnemonic)?),
            None => None,
        };

        let inner = mutiny_core::MutinyWallet::new(
            password,
            mnemonic,
            websocket_proxy_addr,
            network,
            user_esplora_url,
            user_rgs_url,
            lsp_url,
        )
        .await?;
        Ok(MutinyWallet { inner })
    }

    /// Returns if there is a saved wallet in storage.
    /// This is checked by seeing if a mnemonic seed exists in storage.
    #[wasm_bindgen]
    pub async fn has_node_manager() -> bool {
        nodemanager::NodeManager::has_node_manager().await
    }

    /// Starts up all the nodes again.
    /// Not needed after [NodeManager]'s `new()` function.
    #[wasm_bindgen]
    pub async fn start(&mut self) -> Result<(), MutinyJsError> {
        Ok(self.inner.start().await?)
    }

    /// Stops all of the nodes and background processes.
    /// Returns after node has been stopped.
    #[wasm_bindgen]
    pub async fn stop(&self) -> Result<(), MutinyJsError> {
        Ok(self.inner.node_manager.stop().await?)
    }

    /// Broadcast a transaction to the network.
    /// The transaction is broadcast through the configured esplora server.
    #[wasm_bindgen]
    pub fn broadcast_transaction(&self, str: String) -> Result<(), MutinyJsError> {
        let tx_bytes =
            Vec::from_hex(str.as_str()).map_err(|_| MutinyJsError::WalletOperationFailed)?;
        let tx: Transaction =
            deserialize(&tx_bytes).map_err(|_| MutinyJsError::WalletOperationFailed)?;
        Ok(self.inner.node_manager.broadcast_transaction(&tx)?)
    }

    /// Returns the mnemonic seed phrase for the wallet.
    #[wasm_bindgen]
    pub fn show_seed(&self) -> String {
        self.inner.node_manager.show_seed().to_string()
    }

    /// Returns the network of the wallet.
    #[wasm_bindgen]
    pub fn get_network(&self) -> String {
        self.inner.node_manager.get_network().to_string()
    }

    /// Gets a new bitcoin address from the wallet.
    /// Will generate a new address on every call.
    ///
    /// It is recommended to create a new address for every transaction.
    #[wasm_bindgen]
    pub fn get_new_address(&self) -> Result<String, MutinyJsError> {
        Ok(self.inner.node_manager.get_new_address()?.to_string())
    }

    /// Gets the current balance of the on-chain wallet.
    #[wasm_bindgen]
    pub fn get_wallet_balance(&self) -> Result<u64, MutinyJsError> {
        Ok(self.inner.node_manager.get_wallet_balance()?)
    }

    /// Creates a BIP 21 invoice. This creates a new address and a lightning invoice.
    #[wasm_bindgen]
    pub async fn create_bip21(
        &self,
        amount: Option<u64>,
        description: Option<String>,
    ) -> Result<MutinyBip21RawMaterials, MutinyJsError> {
        Ok(self
            .inner
            .node_manager
            .create_bip21(amount, description)
            .await?
            .into())
    }

    /// Sends an on-chain transaction to the given address.
    /// The amount is in satoshis and the fee rate is in sat/vbyte.
    ///
    /// If a fee rate is not provided, one will be used from the fee estimator.
    #[wasm_bindgen]
    pub async fn send_to_address(
        &self,
        destination_address: String,
        amount: u64,
        fee_rate: Option<f32>,
    ) -> Result<String, MutinyJsError> {
        let send_to = Address::from_str(&destination_address)?;
        Ok(self
            .inner
            .node_manager
            .send_to_address(send_to, amount, fee_rate)
            .await?
            .to_string())
    }

    /// Sweeps all the funds from the wallet to the given address.
    /// The fee rate is in sat/vbyte.
    ///
    /// If a fee rate is not provided, one will be used from the fee estimator.
    #[wasm_bindgen]
    pub async fn sweep_wallet(
        &self,
        destination_address: String,
        fee_rate: Option<f32>,
    ) -> Result<String, MutinyJsError> {
        let send_to = Address::from_str(&destination_address)?;
        Ok(self
            .inner
            .node_manager
            .sweep_wallet(send_to, fee_rate)
            .await?
            .to_string())
    }

    /// Checks if the given address has any transactions.
    /// If it does, it returns the details of the first transaction.
    ///
    /// This should be used to check if a payment has been made to an address.
    #[wasm_bindgen]
    pub async fn check_address(
        &self,
        address: String,
    ) -> Result<JsValue /* Option<TransactionDetails> */, MutinyJsError> {
        let address = Address::from_str(&address)?;
        Ok(JsValue::from_serde(
            &self.inner.node_manager.check_address(&address).await?,
        )?)
    }

    /// Lists all the on-chain transactions in the wallet.
    /// These are sorted by confirmation time.
    #[wasm_bindgen]
    pub fn list_onchain(&self) -> Result<JsValue /* Vec<TransactionDetails> */, MutinyJsError> {
        Ok(JsValue::from_serde(
            &self.inner.node_manager.list_onchain()?,
        )?)
    }

    /// Gets the details of a specific on-chain transaction.
    #[wasm_bindgen]
    pub fn get_transaction(
        &self,
        txid: String,
    ) -> Result<JsValue /* Option<TransactionDetails> */, MutinyJsError> {
        let txid = Txid::from_str(&txid)?;
        Ok(JsValue::from_serde(
            &self.inner.node_manager.get_transaction(txid)?,
        )?)
    }

    /// Gets the current balance of the wallet.
    /// This includes both on-chain and lightning funds.
    ///
    /// This will not include any funds in an unconfirmed lightning channel.
    #[wasm_bindgen]
    pub async fn get_balance(&self) -> Result<MutinyBalance, MutinyJsError> {
        Ok(self.inner.node_manager.get_balance().await?.into())
    }

    /// Lists all the UTXOs in the wallet.
    #[wasm_bindgen]
    pub fn list_utxos(&self) -> Result<JsValue, MutinyJsError> {
        Ok(JsValue::from_serde(&self.inner.node_manager.list_utxos()?)?)
    }

    /// Syncs the on-chain wallet and lightning wallet.
    /// This will update the on-chain wallet with any new
    /// transactions and update the lightning wallet with
    /// any channels that have been opened or closed.
    ///
    /// This also updates the fee estimates.
    #[wasm_bindgen]
    pub async fn sync(&self) -> Result<(), MutinyJsError> {
        Ok(self.inner.node_manager.sync().await?)
    }

    /// Gets a fee estimate for an average priority transaction.
    /// Value is in sat/vbyte.
    #[wasm_bindgen]
    pub fn estimate_fee_normal(&self) -> u32 {
        self.inner.node_manager.estimate_fee_normal()
    }

    /// Gets a fee estimate for an high priority transaction.
    /// Value is in sat/vbyte.
    #[wasm_bindgen]
    pub fn estimate_fee_high(&self) -> u32 {
        self.inner.node_manager.estimate_fee_high()
    }

    /// Creates a new lightning node and adds it to the manager.
    #[wasm_bindgen]
    pub async fn new_node(&self) -> Result<NodeIdentity, MutinyJsError> {
        Ok(self.inner.node_manager.new_node().await?.into())
    }

    /// Lists the pubkeys of the lightning node in the manager.
    #[wasm_bindgen]
    pub async fn list_nodes(&self) -> Result<JsValue /* Vec<String> */, MutinyJsError> {
        Ok(JsValue::from_serde(
            &self.inner.node_manager.list_nodes().await?,
        )?)
    }

    /// Attempts to connect to a peer from the selected node.
    #[wasm_bindgen]
    pub async fn connect_to_peer(
        &self,
        self_node_pubkey: String,
        connection_string: String,
        label: Option<String>,
    ) -> Result<(), MutinyJsError> {
        let self_node_pubkey = PublicKey::from_str(&self_node_pubkey)?;
        Ok(self
            .inner
            .node_manager
            .connect_to_peer(&self_node_pubkey, &connection_string, label)
            .await?)
    }

    /// Disconnects from a peer from the selected node.
    #[wasm_bindgen]
    pub async fn disconnect_peer(
        &self,
        self_node_pubkey: String,
        peer: String,
    ) -> Result<(), MutinyJsError> {
        let self_node_pubkey = PublicKey::from_str(&self_node_pubkey)?;
        let peer = PublicKey::from_str(&peer)?;
        Ok(self
            .inner
            .node_manager
            .disconnect_peer(&self_node_pubkey, peer)
            .await?)
    }

    /// Deletes a peer from the selected node.
    /// This will make it so that the node will not attempt to
    /// reconnect to the peer.
    #[wasm_bindgen]
    pub async fn delete_peer(
        &self,
        self_node_pubkey: String,
        peer: String,
    ) -> Result<(), MutinyJsError> {
        let self_node_pubkey = PublicKey::from_str(&self_node_pubkey)?;
        let peer = NodeId::from_str(&peer)?;
        Ok(self
            .inner
            .node_manager
            .delete_peer(&self_node_pubkey, &peer)
            .await?)
    }

    /// Sets the label of a peer from the selected node.
    #[wasm_bindgen]
    pub async fn label_peer(
        &self,
        node_id: String,
        label: Option<String>,
    ) -> Result<(), MutinyJsError> {
        let node_id = NodeId::from_str(&node_id)?;
        self.inner.node_manager.label_peer(&node_id, label).await?;
        Ok(())
    }

    /// Creates a lightning invoice. The amount should be in satoshis.
    /// If no amount is provided, the invoice will be created with no amount.
    /// If no description is provided, the invoice will be created with no description.
    ///
    /// If the manager has more than one node it will create a phantom invoice.
    /// If there is only one node it will create an invoice just for that node.
    #[wasm_bindgen]
    pub async fn create_invoice(
        &self,
        amount: Option<u64>,
        description: Option<String>,
    ) -> Result<MutinyInvoice, MutinyJsError> {
        Ok(self
            .inner
            .node_manager
            .create_invoice(amount, description)
            .await?
            .into())
    }

    /// Pays a lightning invoice from the selected node.
    /// An amount should only be provided if the invoice does not have an amount.
    /// The amount should be in satoshis.
    #[wasm_bindgen]
    pub async fn pay_invoice(
        &self,
        from_node: String,
        invoice_str: String,
        amt_sats: Option<u64>,
    ) -> Result<MutinyInvoice, MutinyJsError> {
        let from_node = PublicKey::from_str(&from_node)?;
        let invoice = Invoice::from_str(&invoice_str)?;
        Ok(self
            .inner
            .node_manager
            .pay_invoice(&from_node, &invoice, amt_sats)
            .await?
            .into())
    }

    /// Sends a spontaneous payment to a node from the selected node.
    /// The amount should be in satoshis.
    #[wasm_bindgen]
    pub async fn keysend(
        &self,
        from_node: String,
        to_node: String,
        amt_sats: u64,
    ) -> Result<MutinyInvoice, MutinyJsError> {
        let from_node = PublicKey::from_str(&from_node)?;
        let to_node = PublicKey::from_str(&to_node)?;
        Ok(self
            .inner
            .node_manager
            .keysend(&from_node, to_node, amt_sats)
            .await?
            .into())
    }

    /// Decodes a lightning invoice into useful information.
    /// Will return an error if the invoice is for a different network.
    #[wasm_bindgen]
    pub async fn decode_invoice(&self, invoice: String) -> Result<MutinyInvoice, MutinyJsError> {
        let invoice = Invoice::from_str(&invoice)?;
        Ok(self
            .inner
            .node_manager
            .decode_invoice(invoice)
            .await?
            .into())
    }

    /// Calls upon a LNURL to get the parameters for it.
    /// This contains what kind of LNURL it is (pay, withdrawal, auth, etc).
    #[wasm_bindgen]
    pub async fn decode_lnurl(&self, lnurl: String) -> Result<LnUrlParams, MutinyJsError> {
        let lnurl = LnUrl::from_str(&lnurl)?;
        Ok(self.inner.node_manager.decode_lnurl(lnurl).await?.into())
    }

    /// Calls upon a LNURL and pays it.
    /// This will fail if the LNURL is not a LNURL pay.
    #[wasm_bindgen]
    pub async fn lnurl_pay(
        &self,
        from_node: String,
        lnurl: String,
        amount_sats: u64,
    ) -> Result<MutinyInvoice, MutinyJsError> {
        let from_node = PublicKey::from_str(&from_node)?;
        let lnurl = LnUrl::from_str(&lnurl)?;
        Ok(self
            .inner
            .node_manager
            .lnurl_pay(&from_node, &lnurl, amount_sats)
            .await?
            .into())
    }

    /// Calls upon a LNURL and withdraws from it.
    /// This will fail if the LNURL is not a LNURL withdrawal.
    #[wasm_bindgen]
    pub async fn lnurl_withdraw(
        &self,
        lnurl: String,
        amount_sats: u64,
    ) -> Result<bool, MutinyJsError> {
        let lnurl = LnUrl::from_str(&lnurl)?;
        Ok(self
            .inner
            .node_manager
            .lnurl_withdraw(&lnurl, amount_sats)
            .await?)
    }

    /// Creates a new LNURL-auth profile.
    #[wasm_bindgen]
    pub fn create_lnurl_auth_profile(&self, name: String) -> Result<u32, MutinyJsError> {
        Ok(self.inner.node_manager.create_lnurl_auth_profile(name)?)
    }

    /// Gets all the LNURL-auth profiles.
    #[wasm_bindgen]
    pub fn get_lnurl_auth_profiles(&self) -> Result<JsValue /*<Vec<AuthProfile> */, MutinyJsError> {
        Ok(JsValue::from_serde(
            &self.inner.node_manager.get_lnurl_auth_profiles()?,
        )?)
    }

    /// Authenticates with a LNURL-auth for the given profile.
    #[wasm_bindgen]
    pub async fn lnurl_auth(
        &self,
        profile_index: usize,
        lnurl: String,
    ) -> Result<(), MutinyJsError> {
        let lnurl = LnUrl::from_str(&lnurl)?;
        Ok(self
            .inner
            .node_manager
            .lnurl_auth(profile_index, lnurl)
            .await?)
    }

    /// Gets an invoice from the node manager.
    /// This includes sent and received invoices.
    #[wasm_bindgen]
    pub async fn get_invoice(&self, invoice: String) -> Result<MutinyInvoice, MutinyJsError> {
        let invoice = Invoice::from_str(&invoice)?;
        Ok(self.inner.node_manager.get_invoice(&invoice).await?.into())
    }

    /// Gets an invoice from the node manager.
    /// This includes sent and received invoices.
    #[wasm_bindgen]
    pub async fn get_invoice_by_hash(&self, hash: String) -> Result<MutinyInvoice, MutinyJsError> {
        let hash: sha256::Hash = sha256::Hash::from_str(&hash)?;
        Ok(self
            .inner
            .node_manager
            .get_invoice_by_hash(&hash)
            .await?
            .into())
    }

    /// Gets an invoice from the node manager.
    /// This includes sent and received invoices.
    #[wasm_bindgen]
    pub async fn list_invoices(&self) -> Result<JsValue /* Vec<MutinyInvoice> */, MutinyJsError> {
        Ok(JsValue::from_serde(
            &self.inner.node_manager.list_invoices().await?,
        )?)
    }

    /// Opens a channel from our selected node to the given pubkey.
    /// The amount is in satoshis.
    ///
    /// The node must be online and have a connection to the peer.
    /// The wallet much have enough funds to open the channel.
    #[wasm_bindgen]
    pub async fn open_channel(
        &self,
        from_node: String,
        to_pubkey: String,
        amount: u64,
    ) -> Result<MutinyChannel, MutinyJsError> {
        let from_node = PublicKey::from_str(&from_node)?;
        let to_pubkey = PublicKey::from_str(&to_pubkey)?;
        Ok(self
            .inner
            .node_manager
            .open_channel(&from_node, to_pubkey, amount)
            .await?
            .into())
    }

    /// Closes a channel with the given outpoint.
    #[wasm_bindgen]
    pub async fn close_channel(&self, outpoint: String) -> Result<(), MutinyJsError> {
        let outpoint: OutPoint = OutPoint::from_str(outpoint.as_str()).expect("invalid outpoint");
        Ok(self.inner.node_manager.close_channel(&outpoint).await?)
    }

    /// Lists all the channels for all the nodes in the node manager.
    #[wasm_bindgen]
    pub async fn list_channels(&self) -> Result<JsValue /* Vec<MutinyChannel> */, MutinyJsError> {
        Ok(JsValue::from_serde(
            &self.inner.node_manager.list_channels().await?,
        )?)
    }

    /// Lists all the peers for all the nodes in the node manager.
    #[wasm_bindgen]
    pub async fn list_peers(&self) -> Result<JsValue /* Vec<MutinyPeer> */, MutinyJsError> {
        Ok(JsValue::from_serde(
            &self.inner.node_manager.list_peers().await?,
        )?)
    }

    /// Gets the current bitcoin price in USD.
    #[wasm_bindgen]
    pub async fn get_bitcoin_price(&self) -> Result<f32, MutinyJsError> {
        Ok(self.inner.node_manager.get_bitcoin_price().await?)
    }

    /// Exports the current state of the node manager to a json object.
    #[wasm_bindgen]
    pub async fn export_json(&self) -> Result<String, MutinyJsError> {
        let json = self.inner.node_manager.export_json().await?;
        Ok(serde_json::to_string(&json)?)
    }

    /// Restore a node manager from a json object.
    #[wasm_bindgen]
    pub async fn import_json(json: String) -> Result<(), MutinyJsError> {
        let json: serde_json::Value = serde_json::from_str(&json)?;
        nodemanager::NodeManager::import_json(json).await?;
        Ok(())
    }

    /// Converts a bitcoin amount in BTC to satoshis.
    #[wasm_bindgen]
    pub fn convert_btc_to_sats(btc: f64) -> Result<u64, MutinyJsError> {
        Ok(nodemanager::NodeManager::convert_btc_to_sats(btc)?)
    }

    /// Converts a satoshi amount to BTC.
    #[wasm_bindgen]
    pub fn convert_sats_to_btc(sats: u64) -> f64 {
        nodemanager::NodeManager::convert_sats_to_btc(sats)
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::test::*;
    use crate::MutinyWallet;
    use mutiny_core::test_utils::*;

    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn create_mutiny_wallet() {
        log!("creating mutiny wallet!");

        assert!(!MutinyWallet::has_node_manager().await);
        MutinyWallet::new(
            "password".to_string(),
            None,
            None,
            Some("testnet".to_owned()),
            None,
            None,
            None,
        )
        .await
        .expect("mutiny wallet should initialize");
        assert!(MutinyWallet::has_node_manager().await);

        cleanup_wallet_test().await;
    }

    #[test]
    async fn correctly_show_seed() {
        log!("showing seed");

        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy).unwrap();
        let seed = bip39::Mnemonic::from_entropy(&entropy).unwrap();

        let nm = MutinyWallet::new(
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

        assert!(MutinyWallet::has_node_manager().await);
        assert_eq!(seed.to_string(), nm.show_seed());

        cleanup_wallet_test().await;
    }

    #[test]
    async fn created_new_nodes() {
        log!("creating new nodes");

        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy).unwrap();
        let seed = bip39::Mnemonic::from_entropy(&entropy).unwrap();

        let nm = MutinyWallet::new(
            "password".to_string(),
            Some(seed.to_string()),
            None,
            Some("testnet".to_owned()),
            None,
            None,
            None,
        )
        .await
        .expect("mutiny wallet should initialize");

        let node_identity = nm.new_node().await.expect("should create new node");
        assert_ne!("", node_identity.uuid());
        assert_ne!("", node_identity.pubkey());

        let node_identity = nm
            .new_node()
            .await
            .expect("mutiny wallet should initialize");

        assert_ne!("", node_identity.uuid());
        assert_ne!("", node_identity.pubkey());

        cleanup_wallet_test().await;
    }
}
