#![crate_name = "mutiny_core"]
// wasm is considered "extra_unused_type_parameters"
#![allow(incomplete_features, clippy::extra_unused_type_parameters)]
#![feature(io_error_other)]
#![feature(async_fn_in_trait)]
// background file is mostly an LDK copy paste
mod background;

mod auth;
mod chain;
mod encrypt;
pub mod error;
pub mod esplora;
mod event;
mod fees;
mod gossip;
mod indexed_db;
mod keymanager;
mod ldkstorage;
mod logging;
mod lspclient;
mod node;
pub mod nodemanager;
mod onchain;
mod peermanager;
mod proxy;
mod redshift;
mod socket;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
mod utils;

use crate::error::MutinyError;
use crate::nodemanager::NodeManager;
pub use auth::AuthProfile;
use bip39::Mnemonic;
use bitcoin::Network;
use std::sync::Arc;

#[derive(Clone)]
/// MutinyWallet is the main entry point for the library.
/// It contains the NodeManager, which is the main interface to manage the
/// bitcoin and the lightning functionality.
pub struct MutinyWallet {
    pub node_manager: Arc<NodeManager>,
}

impl MutinyWallet {
    pub async fn new(
        password: String,
        mnemonic: Option<Mnemonic>,
        websocket_proxy_addr: Option<String>,
        network: Option<Network>,
        user_esplora_url: Option<String>,
        user_rgs_url: Option<String>,
        lsp_url: Option<String>,
    ) -> Result<MutinyWallet, MutinyError> {
        let node_manager = Arc::new(
            NodeManager::new(
                password,
                mnemonic,
                websocket_proxy_addr,
                network,
                user_esplora_url,
                user_rgs_url,
                lsp_url,
            )
            .await?,
        );

        Ok(Self { node_manager })
    }
}
