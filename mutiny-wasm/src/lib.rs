// wasm is considered "extra_unused_type_parameters"
#![allow(
    incomplete_features,
    clippy::extra_unused_type_parameters,
    clippy::arc_with_non_send_sync
)]

extern crate mutiny_core;

pub mod error;
mod indexed_db;
mod models;
mod utils;

use crate::error::MutinyJsError;
use crate::indexed_db::IndexedDbStorage;
use crate::models::*;
use bip39::Mnemonic;
use bitcoin::bip32::Xpriv;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::sha256;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, Network, OutPoint, Txid};
use futures::lock::Mutex;
use gloo_utils::format::JsValueSerdeExt;

use lightning::{log_info, log_warn, routing::gossip::NodeId, util::logger::Logger};
use lightning_invoice::Bolt11Invoice;

use mutiny_core::storage::{DeviceLock, MutinyStorage, DEVICE_LOCK_KEY};
use mutiny_core::utils::{sleep, spawn};
use mutiny_core::vss::MutinyVssClient;
use mutiny_core::MutinyWalletBuilder;
use mutiny_core::{
    encrypt::encryption_key_from_pass, InvoiceHandler, MutinyWalletConfigBuilder, PrivacyLevel,
};
use mutiny_core::{
    labels::LabelStorage,
    nodemanager::{create_lsp_config, NodeManager},
};
use mutiny_core::{logging::MutinyLogger, lsp::LspConfig};

use std::str::FromStr;
use std::sync::Arc;
use wasm_bindgen::prelude::*;

static INITIALIZED: once_cell::sync::Lazy<Mutex<bool>> =
    once_cell::sync::Lazy::new(|| Mutex::new(false));

#[cfg(test)]
async fn uninit() {
    let mut init = INITIALIZED.lock().await;
    *init = false;
}

#[wasm_bindgen]
pub struct MutinyWallet {
    mnemonic: Mnemonic,
    inner: mutiny_core::MutinyWallet<IndexedDbStorage>,
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
    #[wasm_bindgen]
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        password: Option<String>,
        mnemonic_str: Option<String>,
        websocket_proxy_addr: Option<String>,
        network_str: Option<String>,
        user_esplora_url: Option<String>,
        user_rgs_url: Option<String>,
        lsp_url: Option<String>,
        lsp_connection_string: Option<String>,
        lsp_token: Option<String>,
        auth_url: Option<String>,
        subscription_url: Option<String>,
        storage_url: Option<String>,
        scorer_url: Option<String>,
        do_not_connect_peers: Option<bool>,
        skip_device_lock: Option<bool>,
        safe_mode: Option<bool>,
        skip_hodl_invoices: Option<bool>,
        nsec_override: Option<String>,
        nip_07_key: Option<String>,
        primal_url: Option<String>,
        blind_auth_url: Option<String>,
        hermes_url: Option<String>,
    ) -> Result<MutinyWallet, MutinyJsError> {
        let start = instant::Instant::now();
        // if both are set throw an error
        // todo default to nsec if both are for same key?
        if nsec_override.is_some() && nip_07_key.is_some() {
            return Err(MutinyJsError::InvalidArgumentsError);
        }

        utils::set_panic_hook();
        let mut init = INITIALIZED.lock().await;
        if *init {
            return Err(MutinyJsError::AlreadyRunning);
        } else {
            *init = true;
        }

        match Self::new_internal(
            password,
            mnemonic_str,
            websocket_proxy_addr,
            network_str,
            user_esplora_url,
            user_rgs_url,
            lsp_url,
            lsp_connection_string,
            lsp_token,
            auth_url,
            subscription_url,
            storage_url,
            scorer_url,
            do_not_connect_peers,
            skip_device_lock,
            safe_mode,
            skip_hodl_invoices,
            nsec_override,
            nip_07_key,
            primal_url,
            blind_auth_url,
            hermes_url,
        )
        .await
        {
            Ok(m) => {
                log_info!(
                    m.inner.logger,
                    "Wallet startup took {}ms",
                    start.elapsed().as_millis()
                );
                Ok(m)
            }
            Err(e) => {
                // mark uninitialized because we failed to startup
                *init = false;
                Err(e)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn new_internal(
        password: Option<String>,
        mnemonic_str: Option<String>,
        websocket_proxy_addr: Option<String>,
        network_str: Option<String>,
        user_esplora_url: Option<String>,
        user_rgs_url: Option<String>,
        lsp_url: Option<String>,
        lsp_connection_string: Option<String>,
        lsp_token: Option<String>,
        auth_url: Option<String>,
        subscription_url: Option<String>,
        storage_url: Option<String>,
        scorer_url: Option<String>,
        do_not_connect_peers: Option<bool>,
        skip_device_lock: Option<bool>,
        safe_mode: Option<bool>,
        skip_hodl_invoices: Option<bool>,
        _nsec_override: Option<String>,
        _nip_07_key: Option<String>,
        _primal_url: Option<String>,
        blind_auth_url: Option<String>,
        hermes_url: Option<String>,
    ) -> Result<MutinyWallet, MutinyJsError> {
        let safe_mode = safe_mode.unwrap_or(false);
        let logger = Arc::new(MutinyLogger::default());

        let cipher = password
            .as_ref()
            .filter(|p| !p.is_empty())
            .map(|p| encryption_key_from_pass(p))
            .transpose()?;

        let network: Network = network_str
            .map(|s| s.parse().expect("Invalid network"))
            .unwrap_or(Network::Bitcoin);

        let override_mnemonic = mnemonic_str.map(|s| Mnemonic::from_str(&s)).transpose()?;

        let mnemonic =
            IndexedDbStorage::get_mnemonic(override_mnemonic, password.as_deref(), cipher.clone())
                .await?;

        let seed = mnemonic.to_seed("");
        let xprivkey = Xpriv::new_master(network, &seed).unwrap();

        let vss_client = if safe_mode {
            None
        } else {
            let vss = storage_url.map(|url| {
                Arc::new(MutinyVssClient::new_unauthenticated(
                    url,
                    xprivkey.private_key,
                    logger.clone(),
                ))
            });

            vss
        };

        let storage = IndexedDbStorage::new(password, cipher, vss_client, logger.clone()).await?;

        let mut config_builder = MutinyWalletConfigBuilder::new(xprivkey).with_network(network);
        if let Some(w) = websocket_proxy_addr {
            config_builder.with_websocket_proxy_addr(w);
        }
        if let Some(url) = user_esplora_url {
            config_builder.with_user_esplora_url(url);
        }
        if let Some(url) = user_rgs_url {
            config_builder.with_user_rgs_url(url);
        }
        if let Some(url) = lsp_url {
            config_builder.with_lsp_url(url);
        }
        if let Some(url) = lsp_connection_string {
            config_builder.with_lsp_connection_string(url);
        }
        if let Some(url) = lsp_token {
            config_builder.with_lsp_token(url);
        }
        if let Some(url) = subscription_url {
            config_builder.with_subscription_url(url);
        }
        if let Some(url) = scorer_url {
            config_builder.with_scorer_url(url);
        }
        if let Some(url) = blind_auth_url {
            config_builder.with_blind_auth_url(url);
        }
        if let Some(url) = hermes_url {
            config_builder.with_hermes_url(url);
        }
        if let Some(true) = skip_device_lock {
            config_builder.with_skip_device_lock();
        }
        if let Some(false) = skip_hodl_invoices {
            config_builder.do_not_skip_hodl_invoices();
        }
        if let Some(true) = do_not_connect_peers {
            config_builder.do_not_connect_peers();
        }
        if safe_mode {
            config_builder.with_safe_mode();
        }
        let config = config_builder.build();

        let mut mw_builder = MutinyWalletBuilder::new(xprivkey, storage).with_config(config);
        mw_builder.with_session_id(logger.session_id.clone());
        let inner = mw_builder.build().await?;

        Ok(MutinyWallet { mnemonic, inner })
    }

    pub fn is_safe_mode(&self) -> bool {
        self.inner.is_safe_mode()
    }

    /// Returns if there is a saved wallet in storage.
    /// This is checked by seeing if a mnemonic seed exists in storage.
    #[wasm_bindgen]
    pub async fn has_node_manager() -> Result<bool, MutinyJsError> {
        Ok(IndexedDbStorage::has_mnemonic().await?)
    }

    /// Returns the number of remaining seconds until the device lock expires.
    #[wasm_bindgen]
    pub async fn get_device_lock_remaining_secs(
        password: Option<String>,
        auth_url: Option<String>,
        storage_url: Option<String>,
    ) -> Result<Option<u64>, MutinyJsError> {
        let logger = Arc::new(MutinyLogger::default());
        let cipher = password
            .as_ref()
            .filter(|p| !p.is_empty())
            .map(|p| encryption_key_from_pass(p))
            .transpose()?;
        let mnemonic =
            IndexedDbStorage::get_mnemonic(None, password.as_deref(), cipher.clone()).await?;

        let seed = mnemonic.to_seed("");
        // Network doesn't matter here, only for encoding
        let xprivkey = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();

        let vss_client = storage_url.map(|url| {
            Arc::new(MutinyVssClient::new_unauthenticated(
                url,
                xprivkey.private_key,
                logger.clone(),
            ))
        });

        if let Some(vss) = vss_client {
            let obj = vss.get_object(DEVICE_LOCK_KEY).await?;
            let lock = serde_json::from_value::<DeviceLock>(obj.value)?;

            return Ok(Some(lock.remaining_secs()));
        };

        Ok(None)
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

    /// Returns the mnemonic seed phrase for the wallet.
    #[wasm_bindgen]
    pub fn show_seed(&self) -> String {
        self.mnemonic.to_string()
    }

    /// Returns the network of the wallet.
    #[wasm_bindgen]
    pub fn get_network(&self) -> String {
        self.inner.get_network().to_string()
    }

    /// Gets a new bitcoin address from the wallet.
    /// Will generate a new address on every call.
    ///
    /// It is recommended to create a new address for every transaction.
    #[wasm_bindgen]
    pub async fn get_new_address(
        &self,
        labels: Vec<String>,
    ) -> Result<MutinyBip21RawMaterials, MutinyJsError> {
        let address = self.inner.create_address(labels.clone()).await?;
        Ok(MutinyBip21RawMaterials {
            address: address.to_string(),
            invoice: None,
            btc_amount: None,
            labels,
        })
    }

    /// Creates a BIP 21 invoice. This creates a new address and a lightning invoice.
    /// The lightning invoice may return errors related to the LSP. Check the error and
    /// fallback to `get_new_address` and warn the user that Lightning is not available.
    ///
    ///
    /// Errors that might be returned include:
    ///
    /// - [`MutinyJsError::LspGenericError`]: This is returned for various reasons, including if a
    ///   request to the LSP server fails for any reason, or if the server returns
    ///   a status other than 500 that can't be parsed into a `ProposalResponse`.
    ///
    /// - [`MutinyJsError::LspFundingError`]: Returned if the LSP server returns an error with
    ///   a status of 500, indicating an "Internal Server Error", and a message
    ///   stating "Cannot fund new channel at this time". This means that the LSP cannot support
    ///   a new channel at this time.
    ///
    /// - [`MutinyJsError::LspAmountTooHighError`]: Returned if the LSP server returns an error with
    ///   a status of 500, indicating an "Internal Server Error", and a message stating "Invoice
    ///   amount is too high". This means that the LSP cannot support the amount that the user
    ///   requested. The user should request a smaller amount from the LSP.
    ///
    /// - [`MutinyJsError::LspConnectionError`]: Returned if the LSP server returns an error with
    ///   a status of 500, indicating an "Internal Server Error", and a message that starts with
    ///   "Failed to connect to peer". This means that the LSP is not connected to our node.
    ///
    /// If the server returns a status of 500 with a different error message,
    /// a [`MutinyJsError::LspGenericError`] is returned.
    #[wasm_bindgen]
    pub async fn create_bip21(
        &self,
        amount: Option<u64>,
        labels: Vec<String>,
    ) -> Result<MutinyBip21RawMaterials, MutinyJsError> {
        Ok(self.inner.create_bip21(amount, labels).await?.into())
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
        labels: Vec<String>,
        fee_rate: Option<u64>,
    ) -> Result<String, MutinyJsError> {
        let send_to =
            Address::from_str(&destination_address)?.require_network(self.inner.get_network())?;
        Ok(self
            .inner
            .send_to_address(send_to, amount, labels, fee_rate)
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
        labels: Vec<String>,
        fee_rate: Option<u64>,
    ) -> Result<String, MutinyJsError> {
        let send_to =
            Address::from_str(&destination_address)?.require_network(self.inner.get_network())?;
        Ok(self
            .inner
            .sweep_wallet(send_to, labels, fee_rate)
            .await?
            .to_string())
    }

    /// Estimates the onchain fee for a transaction sending to the given address.
    /// The amount is in satoshis and the fee rate is in sat/vbyte.
    pub async fn estimate_tx_fee(
        &self,
        destination_address: String,
        amount: u64,
        fee_rate: Option<u64>,
    ) -> Result<u64, MutinyJsError> {
        let addr = Address::from_str(&destination_address)?.assume_checked();
        Ok(self.inner.estimate_tx_fee(addr, amount, fee_rate).await?)
    }

    /// Estimates the onchain fee for a opening a lightning channel.
    /// The amount is in satoshis and the fee rate is in sat/vbyte.
    pub fn estimate_channel_open_fee(
        &self,
        amount: u64,
        fee_rate: Option<u64>,
    ) -> Result<u64, MutinyJsError> {
        Ok(self
            .inner
            .node_manager
            .estimate_channel_open_fee(amount, fee_rate)?)
    }

    /// Estimates the onchain fee for sweeping our on-chain balance to open a lightning channel.
    /// The fee rate is in sat/vbyte.
    pub fn estimate_sweep_channel_open_fee(
        &self,
        fee_rate: Option<u64>,
    ) -> Result<u64, MutinyJsError> {
        Ok(self
            .inner
            .node_manager
            .estimate_sweep_channel_open_fee(fee_rate)?)
    }

    /// Estimates the lightning fee for a transaction. Amount is either from the invoice
    /// if one is available or a passed in amount (priority). It will try to predict either
    /// sending the payment through a federation or through lightning, depending on balances.
    /// The amount and fee is in satoshis.
    /// Returns None if it has no good way to calculate fee.
    pub async fn estimate_ln_fee(
        &self,
        invoice_str: Option<String>,
        amt_sats: Option<u64>,
    ) -> Result<Option<u64>, MutinyJsError> {
        let invoice = match invoice_str {
            Some(i) => Some(Bolt11Invoice::from_str(&i)?),
            None => None,
        };
        Ok(self
            .inner
            .estimate_ln_fee(invoice.as_ref(), amt_sats)
            .await?)
    }

    /// Bumps the given transaction by replacing the given tx with a transaction at
    /// the new given fee rate in sats/vbyte
    pub async fn bump_fee(&self, txid: String, fee_rate: u64) -> Result<String, MutinyJsError> {
        let txid = Txid::from_str(&txid)?;
        let result = self.inner.node_manager.bump_fee(txid, fee_rate).await?;

        Ok(result.to_string())
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
            &self.inner.node_manager.check_address(address).await?,
        )?)
    }

    /// Gets the details of a specific on-chain transaction.
    #[wasm_bindgen]
    pub fn get_transaction(
        &self,
        txid: String,
    ) -> Result<JsValue /* Option<TransactionDetails> */, MutinyJsError> {
        let txid = Txid::from_str(&txid)?;
        Ok(JsValue::from_serde(&self.inner.get_transaction(txid)?)?)
    }

    /// Gets the current balance of the wallet.
    /// This includes both on-chain and lightning funds.
    ///
    /// This will not include any funds in an unconfirmed lightning channel.
    #[wasm_bindgen]
    pub async fn get_balance(&self) -> Result<MutinyBalance, MutinyJsError> {
        Ok(self.inner.get_balance().await?.into())
    }

    /// Lists all the UTXOs in the wallet.
    #[wasm_bindgen]
    pub fn list_utxos(&self) -> Result<JsValue, MutinyJsError> {
        Ok(JsValue::from_serde(&self.inner.node_manager.list_utxos()?)?)
    }

    /// Gets a fee estimate for an low priority transaction.
    /// Value is in sat/vbyte.
    #[wasm_bindgen]
    pub fn estimate_fee_low(&self) -> u32 {
        self.inner.node_manager.estimate_fee_low()
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

    /// Changes all the node's LSPs to the given config. If any of the nodes have an active channel with the
    /// current LSP, it will fail to change the LSP.
    ///
    /// Requires a restart of the node manager to take effect.
    pub async fn change_lsp(
        &self,
        lsp_url: Option<String>,
        lsp_connection_string: Option<String>,
        lsp_token: Option<String>,
    ) -> Result<(), MutinyJsError> {
        let lsp_config = create_lsp_config(lsp_url, lsp_connection_string, lsp_token)?;

        self.inner.node_manager.change_lsp(lsp_config).await?;
        Ok(())
    }

    /// Returns the current LSP config
    pub async fn get_configured_lsp(&self) -> Result<JsValue, MutinyJsError> {
        match self.inner.node_manager.get_configured_lsp().await? {
            Some(LspConfig::VoltageFlow(config)) => Ok(JsValue::from_serde(&config)?),
            Some(LspConfig::Lsps(config)) => Ok(JsValue::from_serde(&config)?),
            None => Ok(JsValue::NULL),
        }
    }

    /// Attempts to connect to a peer from the selected node.
    #[wasm_bindgen]
    pub async fn connect_to_peer(
        &self,
        connection_string: String,
        label: Option<String>,
    ) -> Result<(), MutinyJsError> {
        Ok(self
            .inner
            .node_manager
            .connect_to_peer(None, &connection_string, label)
            .await?)
    }

    /// Disconnects from a peer from the selected node.
    #[wasm_bindgen]
    pub async fn disconnect_peer(&self, peer: String) -> Result<(), MutinyJsError> {
        let peer = PublicKey::from_str(&peer)?;
        Ok(self.inner.node_manager.disconnect_peer(None, peer).await?)
    }

    /// Deletes a peer from the selected node.
    /// This will make it so that the node will not attempt to
    /// reconnect to the peer.
    #[wasm_bindgen]
    pub async fn delete_peer(&self, peer: String) -> Result<(), MutinyJsError> {
        let peer = NodeId::from_str(&peer).map_err(|_| MutinyJsError::InvalidArgumentsError)?;
        Ok(self.inner.node_manager.delete_peer(None, &peer).await?)
    }

    /// Sets the label of a peer from the selected node.
    #[wasm_bindgen]
    pub fn label_peer(&self, node_id: String, label: Option<String>) -> Result<(), MutinyJsError> {
        let node_id =
            NodeId::from_str(&node_id).map_err(|_| MutinyJsError::InvalidArgumentsError)?;
        self.inner.node_manager.label_peer(&node_id, label)?;
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
        amount: u64,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyJsError> {
        Ok(self.inner.create_invoice(amount, labels).await?.into())
    }

    /// Pays a lightning invoice from the selected node.
    /// An amount should only be provided if the invoice does not have an amount.
    /// The amount should be in satoshis.
    #[wasm_bindgen]
    pub async fn pay_invoice(
        &self,
        invoice_str: String,
        amt_sats: Option<u64>,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyJsError> {
        let invoice = Bolt11Invoice::from_str(&invoice_str)?;
        Ok(self
            .inner
            .pay_invoice(&invoice, amt_sats, labels)
            .await?
            .into())
    }

    /// Sends a spontaneous payment to a node from the selected node.
    /// The amount should be in satoshis.
    #[wasm_bindgen]
    pub async fn keysend(
        &self,
        to_node: String,
        amt_sats: u64,
        message: Option<String>,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyJsError> {
        let to_node = PublicKey::from_str(&to_node)?;
        Ok(self
            .inner
            .node_manager
            .keysend(None, to_node, amt_sats, message, labels)
            .await?
            .into())
    }

    /// Decodes a lightning invoice into useful information.
    /// Will return an error if the invoice is for a different network.
    #[wasm_bindgen]
    pub async fn decode_invoice(
        &self,
        invoice: String,
        network: Option<String>,
    ) -> Result<MutinyInvoice, MutinyJsError> {
        let invoice = Bolt11Invoice::from_str(&invoice)?;
        let network = network
            .map(|n| Network::from_str(&n).map_err(|_| MutinyJsError::InvalidArgumentsError))
            .transpose()?;
        Ok(self.inner.decode_invoice(invoice, network)?.into())
    }

    /// Gets an invoice from the node manager.
    /// This includes sent and received invoices.
    #[wasm_bindgen]
    pub async fn get_invoice(&self, invoice: String) -> Result<MutinyInvoice, MutinyJsError> {
        let invoice = Bolt11Invoice::from_str(&invoice)?;
        Ok(self.inner.get_invoice(&invoice).await?.into())
    }

    /// Gets an invoice from the node manager.
    /// This includes sent and received invoices.
    #[wasm_bindgen]
    pub async fn get_invoice_by_hash(&self, hash: String) -> Result<MutinyInvoice, MutinyJsError> {
        let hash: sha256::Hash = sha256::Hash::from_str(&hash)?;
        Ok(self.inner.get_invoice_by_hash(&hash).await?.into())
    }

    /// Gets an invoice from the node manager.
    /// This includes sent and received invoices.
    #[wasm_bindgen]
    pub async fn list_invoices(&self) -> Result<JsValue /* Vec<MutinyInvoice> */, MutinyJsError> {
        Ok(JsValue::from_serde(&self.inner.list_invoices()?)?)
    }

    /// Gets an channel closure from the node manager.
    #[wasm_bindgen]
    pub async fn get_channel_closure(
        &self,
        user_channel_id: String,
    ) -> Result<ChannelClosure, MutinyJsError> {
        let user_channel_id: [u8; 16] = FromHex::from_hex(&user_channel_id)?;
        Ok(self
            .inner
            .node_manager
            .get_channel_closure(u128::from_be_bytes(user_channel_id))
            .await?
            .into())
    }

    /// Gets all channel closures from the node manager.
    ///
    /// The channel closures are sorted by the time they were closed.
    #[wasm_bindgen]
    pub async fn list_channel_closures(
        &self,
    ) -> Result<JsValue /* Vec<ChannelClosure> */, MutinyJsError> {
        let mut channel_closures = self.inner.node_manager.list_channel_closures().await?;
        channel_closures.sort();
        Ok(JsValue::from_serde(&channel_closures)?)
    }

    /// Opens a channel from our selected node to the given pubkey.
    /// The amount is in satoshis.
    ///
    /// The node must be online and have a connection to the peer.
    /// The wallet much have enough funds to open the channel.
    #[wasm_bindgen]
    pub async fn open_channel(
        &self,
        to_pubkey: Option<String>,
        amount: u64,
        fee_rate: Option<u64>,
    ) -> Result<MutinyChannel, MutinyJsError> {
        let to_pubkey = match to_pubkey {
            Some(pubkey_str) if !pubkey_str.trim().is_empty() => {
                Some(PublicKey::from_str(&pubkey_str)?)
            }
            _ => None,
        };

        Ok(self
            .inner
            .node_manager
            .open_channel(None, to_pubkey, amount, fee_rate, None)
            .await?
            .into())
    }

    /// Opens a channel from our selected node to the given pubkey.
    /// It will spend the all the on-chain utxo in full to fund the channel.
    ///
    /// The node must be online and have a connection to the peer.
    pub async fn sweep_all_to_channel(
        &self,
        to_pubkey: Option<String>,
    ) -> Result<MutinyChannel, MutinyJsError> {
        let to_pubkey = match to_pubkey {
            Some(pubkey_str) if !pubkey_str.trim().is_empty() => {
                Some(PublicKey::from_str(&pubkey_str)?)
            }
            _ => None,
        };

        Ok(self
            .inner
            .node_manager
            .sweep_all_to_channel(to_pubkey)
            .await?
            .into())
    }

    /// Closes a channel with the given outpoint.
    ///
    /// If force is true, the channel will be force closed.
    ///
    /// If abandon is true, the channel will be abandoned.
    /// This will force close without broadcasting the latest transaction.
    /// This should only be used if the channel will never actually be opened.
    ///
    /// If both force and abandon are true, an error will be returned.
    /// The address must match the network and the network: "bitcoin", "testnet", "signet", "regtest"
    #[wasm_bindgen]
    pub async fn close_channel(
        &self,
        outpoint: String,
        address: String,
        force: bool,
        abandon: bool,
        network: Option<String>,
    ) -> Result<(), MutinyJsError> {
        let outpoint: OutPoint =
            OutPoint::from_str(&outpoint).map_err(|_| MutinyJsError::InvalidArgumentsError)?;

        let network = if let Some(net) = network {
            Network::from_str(&net).map_err(|_| MutinyJsError::InvalidAddressNetworkError)?
        } else {
            Network::Bitcoin
        };
        let address =
            Address::from_str(&address).map_err(|_| MutinyJsError::InvalidAddressNetworkError)?;
        let address = address
            .require_network(network)
            .map_err(|_| MutinyJsError::InvalidAddressNetworkError)
            .ok();
        Ok(self
            .inner
            .node_manager
            .close_channel(&outpoint, address, force, abandon)
            .await?)
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

    pub fn get_address_labels(
        &self,
    ) -> Result<JsValue /* Map<Address, Vec<String>> */, MutinyJsError> {
        Ok(JsValue::from_serde(
            &self.inner.node_manager.get_address_labels()?,
        )?)
    }

    /// Set the labels for an address, replacing any existing labels
    /// If you want to do not want to replace any existing labels, use `get_address_labels` to get the existing labels,
    /// add the new labels, and then use `set_address_labels` to set the new labels
    pub fn set_address_labels(
        &self,
        address: String,
        labels: Vec<String>,
    ) -> Result<(), MutinyJsError> {
        let address = Address::from_str(&address)?.assume_checked();
        Ok(self
            .inner
            .node_manager
            .set_address_labels(address, labels)?)
    }

    pub fn get_invoice_labels(
        &self,
    ) -> Result<JsValue /* Map<Invoice, Vec<String>> */, MutinyJsError> {
        Ok(JsValue::from_serde(
            &self.inner.node_manager.get_invoice_labels()?,
        )?)
    }

    /// Set the labels for an invoice, replacing any existing labels
    /// If you want to do not want to replace any existing labels, use `get_invoice_labels` to get the existing labels,
    /// add the new labels, and then use `set_invoice_labels` to set the new labels
    pub fn set_invoice_labels(
        &self,
        invoice: String,
        labels: Vec<String>,
    ) -> Result<(), MutinyJsError> {
        let invoice = Bolt11Invoice::from_str(&invoice)?;
        Ok(self
            .inner
            .node_manager
            .set_invoice_labels(invoice, labels)?)
    }

    /// Gets the current bitcoin price in chosen Fiat.
    #[wasm_bindgen]
    pub async fn get_bitcoin_price(&self, fiat: Option<String>) -> Result<f32, MutinyJsError> {
        Ok(self.inner.get_bitcoin_price(fiat).await?)
    }

    /// Exports the current state of the node manager to a json object.
    #[wasm_bindgen]
    pub async fn get_logs() -> Result<JsValue /* Option<Vec<String>> */, MutinyJsError> {
        let logs = IndexedDbStorage::get_logs().await?;
        Ok(JsValue::from_serde(&logs)?)
    }

    /// Resets the scorer and network graph. This can be useful if you get stuck in a bad state.
    #[wasm_bindgen]
    pub async fn reset_router(&self) -> Result<(), MutinyJsError> {
        self.inner.node_manager.reset_router().await?;
        // Sleep to wait for indexed db to finish writing
        sleep(500).await;
        Ok(())
    }

    /// Resets BDK's keychain tracker. This will require a re-sync of the blockchain.
    ///
    /// This can be useful if you get stuck in a bad state.
    #[wasm_bindgen]
    pub async fn reset_onchain_tracker(&mut self) -> Result<(), MutinyJsError> {
        Ok(self.inner.reset_onchain_tracker().await?)
    }

    /// Exports the current state of the node manager to a json object.
    #[wasm_bindgen]
    pub async fn export_json(password: Option<String>) -> Result<String, MutinyJsError> {
        let logger = Arc::new(MutinyLogger::default());
        let cipher = password
            .as_ref()
            .filter(|p| !p.is_empty())
            .map(|p| encryption_key_from_pass(p))
            .transpose()?;
        // todo init vss
        let storage = IndexedDbStorage::new(password, cipher, None, logger).await?;
        if storage.get_mnemonic().is_err() {
            // if we get an error, then we have the wrong password
            return Err(MutinyJsError::IncorrectPassword);
        }
        let json = NodeManager::export_json(storage).await?;
        Ok(serde_json::to_string(&json)?)
    }

    /// Restore a node manager from a json object.
    #[wasm_bindgen]
    pub async fn import_json(json: String) -> Result<(), MutinyJsError> {
        let json: serde_json::Value = serde_json::from_str(&json)?;
        IndexedDbStorage::import(json).await?;
        Ok(())
    }

    /// Clears storage and deletes all data.
    ///
    /// All data in VSS persists but the device lock is cleared.
    #[wasm_bindgen]
    pub async fn delete_all(&self) -> Result<(), MutinyJsError> {
        self.inner.delete_all().await?;
        Ok(())
    }

    /// Restore's the mnemonic after deleting the previous state.
    ///
    /// Backup the state beforehand. Does not restore lightning data.
    /// Should refresh or restart afterwards. Wallet should be stopped.
    #[wasm_bindgen]
    pub async fn restore_mnemonic(
        m: String,
        password: Option<String>,
    ) -> Result<(), MutinyJsError> {
        let logger = Arc::new(MutinyLogger::default());
        let cipher = password
            .as_ref()
            .filter(|p| !p.is_empty())
            .map(|p| encryption_key_from_pass(p))
            .transpose()?;
        let storage = IndexedDbStorage::new(password, cipher, None, logger.clone()).await?;
        mutiny_core::MutinyWallet::<IndexedDbStorage>::restore_mnemonic(
            storage,
            Mnemonic::from_str(&m).map_err(|_| MutinyJsError::InvalidMnemonic)?,
        )
        .await?;
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn change_password(
        &mut self,
        old_password: Option<String>,
        new_password: Option<String>,
    ) -> Result<(), MutinyJsError> {
        let old_p = old_password.filter(|p| !p.is_empty());
        let new_p = new_password.filter(|p| !p.is_empty());
        self.inner.change_password(old_p, new_p).await?;
        Ok(())
    }

    /// Converts a bitcoin amount in BTC to satoshis.
    #[wasm_bindgen]
    pub fn convert_btc_to_sats(btc: f64) -> Result<u64, MutinyJsError> {
        // rust bitcoin doesn't like extra precision in the float
        // so we round to the nearest satoshi
        // explained here: https://stackoverflow.com/questions/28655362/how-does-one-round-a-floating-point-number-to-a-specified-number-of-digits
        let truncated = 10i32.pow(8) as f64;
        let btc = (btc * truncated).round() / truncated;
        if let Ok(amount) = bitcoin::Amount::from_btc(btc) {
            Ok(amount.to_sat())
        } else {
            Err(MutinyJsError::BadAmountError)
        }
    }

    /// Converts a satoshi amount to BTC.
    #[wasm_bindgen]
    pub fn convert_sats_to_btc(sats: u64) -> f64 {
        bitcoin::Amount::from_sat(sats).to_btc()
    }

    /// If the invoice is from a node that gives hodl invoices
    #[wasm_bindgen]
    pub async fn is_potential_hodl_invoice(invoice: String) -> Result<bool, MutinyJsError> {
        let invoice = Bolt11Invoice::from_str(&invoice)?;
        Ok(mutiny_core::utils::is_hodl_invoice(&invoice))
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::test::*;
    use crate::{uninit, MutinyWallet};

    use crate::error::MutinyJsError;
    use crate::indexed_db::IndexedDbStorage;
    use js_sys::Array;
    use mutiny_core::storage::MutinyStorage;
    use mutiny_core::utils::sleep;
    use wasm_bindgen::JsCast;
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn create_mutiny_wallet() {
        log!("creating mutiny wallet!");
        let password = Some("password".to_string());

        assert!(!MutinyWallet::has_node_manager().await.unwrap());
        MutinyWallet::new(
            password.clone(),
            None,
            None,
            Some("regtest".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("mutiny wallet should initialize");
        sleep(1_000).await;
        assert!(MutinyWallet::has_node_manager().await.unwrap());

        IndexedDbStorage::clear()
            .await
            .expect("failed to clear storage");
        uninit().await;
    }

    #[test]
    async fn fail_to_create_wallet_different_seed() {
        MutinyWallet::new(
            None,
            None,
            None,
            Some("regtest".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("mutiny wallet should initialize");
        sleep(1_000).await;
        assert!(MutinyWallet::has_node_manager().await.unwrap());
        uninit().await;

        let seed = mutiny_core::generate_seed(12).unwrap();
        let result = MutinyWallet::new(
            None,
            Some(seed.to_string()),
            None,
            Some("regtest".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await;

        match result {
            Err(MutinyJsError::InvalidMnemonic) => {}
            Err(e) => panic!("should have failed to create wallet with different seed {e:?}"),
            Ok(_) => panic!("should have failed to create wallet with different seed"),
        }

        IndexedDbStorage::clear()
            .await
            .expect("failed to clear storage");
        uninit().await;
    }

    #[test]
    async fn fail_to_create_2_mutiny_wallets() {
        log!("trying to create 2 mutiny wallets!");
        let password = Some("password".to_string());

        assert!(!MutinyWallet::has_node_manager().await.unwrap());
        MutinyWallet::new(
            password.clone(),
            None,
            None,
            Some("regtest".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("mutiny wallet should initialize");
        sleep(1_000).await;
        assert!(MutinyWallet::has_node_manager().await.unwrap());

        // try to create a second
        let result = MutinyWallet::new(
            password.clone(),
            None,
            None,
            Some("regtest".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await;

        if let Err(MutinyJsError::AlreadyRunning) = result {
            // this is the expected error
        } else {
            panic!("should have failed to create a second mutiny wallet");
        };

        IndexedDbStorage::clear()
            .await
            .expect("failed to clear storage");
        uninit().await;
    }

    #[test]
    async fn correctly_show_seed() {
        log!("showing seed");

        let seed = mutiny_core::generate_seed(12).unwrap();

        let password = Some("password".to_string());

        // make sure storage is empty
        IndexedDbStorage::clear()
            .await
            .expect("failed to clear storage");

        let nm = MutinyWallet::new(
            password.clone(),
            Some(seed.to_string()),
            None,
            Some("regtest".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        log!("checking nm");
        assert!(MutinyWallet::has_node_manager().await.unwrap());
        log!("checking seed");
        assert_eq!(seed.to_string(), nm.show_seed());

        IndexedDbStorage::clear()
            .await
            .expect("failed to clear storage");
        uninit().await;
    }

    #[test]
    async fn give_correct_err_with_wrong_password() {
        let seed = mutiny_core::generate_seed(12).unwrap();

        let password = Some("password".to_string());

        // make sure storage is empty
        IndexedDbStorage::clear()
            .await
            .expect("failed to clear storage");

        let nm = MutinyWallet::new(
            password.clone(),
            Some(seed.to_string()),
            None,
            Some("regtest".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        log!("checking nm");
        assert!(MutinyWallet::has_node_manager().await.unwrap());
        log!("checking seed");
        assert_eq!(seed.to_string(), nm.show_seed());
        nm.stop().await.unwrap();
        drop(nm);
        uninit().await;

        // create with incorrect password
        let result = MutinyWallet::new(
            None,
            Some(seed.to_string()),
            None,
            Some("regtest".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await;

        if !matches!(result, Err(MutinyJsError::IncorrectPassword)) {
            panic!("should have failed to create wallet with incorrect password");
        }

        IndexedDbStorage::clear()
            .await
            .expect("failed to clear storage");
        uninit().await;
    }

    #[test]
    async fn created_new_nodes() {
        log!("creating new nodes");

        let nm = MutinyWallet::new(
            Some("password".to_string()),
            None,
            None,
            Some("regtest".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
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

        IndexedDbStorage::clear()
            .await
            .expect("failed to clear storage");
        uninit().await;
    }

    fn js_to_option_vec_string(js_val: JsValue) -> Result<Option<Vec<String>>, JsValue> {
        if js_val.is_undefined() || js_val.is_null() {
            return Ok(None);
        }

        let js_array: Array = js_val
            .dyn_into()
            .map_err(|_| JsValue::from_str("Expected an array"))?;

        let vec_string: Result<Vec<String>, _> = (0..js_array.length())
            .map(|index| {
                js_array
                    .get(index)
                    .as_string()
                    .ok_or_else(|| JsValue::from_str("Expected an array of strings"))
            })
            .collect();

        vec_string.map(Some)
    }

    #[test]
    async fn test_get_logs_no_password() {
        log!("getting logs with no password");

        let nm = MutinyWallet::new(
            None,
            None,
            None,
            Some("regtest".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("mutiny wallet should initialize");

        // create the nodes so we have some extra data
        let node_identity = nm.new_node().await.expect("should create new node");
        assert_ne!("", node_identity.uuid());
        assert_ne!("", node_identity.pubkey());

        let node_identity = nm
            .new_node()
            .await
            .expect("mutiny wallet should initialize");

        assert_ne!("", node_identity.uuid());
        assert_ne!("", node_identity.pubkey());

        // sleep to make sure logs save
        sleep(6_000).await;
        let logs = MutinyWallet::get_logs().await.expect("should get logs");
        let parsed_logs = js_to_option_vec_string(logs).expect("should parse logs");
        assert!(parsed_logs.is_some());
        assert!(!parsed_logs.clone().unwrap().is_empty());
        assert_ne!("", parsed_logs.unwrap()[0]);

        IndexedDbStorage::clear()
            .await
            .expect("failed to clear storage");
        uninit().await;
    }

    #[test]
    async fn test_get_logs_with_password() {
        log!("getting logs with password");

        let password = Some("password".to_string());
        let nm = MutinyWallet::new(
            password.clone(),
            None,
            None,
            Some("regtest".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("mutiny wallet should initialize");

        // create the nodes so we have some extra data
        let node_identity = nm.new_node().await.expect("should create new node");
        assert_ne!("", node_identity.uuid());
        assert_ne!("", node_identity.pubkey());

        let node_identity = nm
            .new_node()
            .await
            .expect("mutiny wallet should initialize");

        assert_ne!("", node_identity.uuid());
        assert_ne!("", node_identity.pubkey());

        // sleep to make sure logs save
        sleep(6_000).await;
        let logs = MutinyWallet::get_logs().await.expect("should get logs");
        let parsed_logs = js_to_option_vec_string(logs).expect("should parse logs");
        assert!(parsed_logs.is_some());
        assert!(!parsed_logs.clone().unwrap().is_empty());
        assert_ne!("", parsed_logs.unwrap()[0]);

        IndexedDbStorage::clear()
            .await
            .expect("failed to clear storage");
        uninit().await;
    }
}
