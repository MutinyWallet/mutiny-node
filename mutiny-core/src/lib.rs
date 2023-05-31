#![crate_name = "mutiny_core"]
// wasm is considered "extra_unused_type_parameters"
#![allow(
    incomplete_features,
    clippy::extra_unused_type_parameters,
    type_alias_bounds
)]
#![feature(io_error_other)]
#![feature(async_fn_in_trait)]
// background file is mostly an LDK copy paste
mod background;

mod auth;
mod chain;
pub mod encrypt;
pub mod error;
pub mod esplora;
mod event;
mod fees;
mod gossip;
mod keymanager;
pub mod labels;
mod ldkstorage;
pub mod logging;
mod lspclient;
mod node;
pub mod nodemanager;
mod nostr;
mod onchain;
mod peermanager;
mod proxy;
pub mod redshift;
mod socket;
pub mod storage;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
mod utils;

pub use crate::gossip::{GOSSIP_SYNC_TIME_KEY, NETWORK_GRAPH_KEY, PROB_SCORER_KEY};
pub use crate::keymanager::generate_seed;
pub use crate::ldkstorage::{CHANNEL_MANAGER_KEY, MONITORS_PREFIX_KEY};

use crate::error::MutinyError;
use crate::nodemanager::NodeManager;
use crate::nostr::NostrManager;
use crate::storage::MutinyStorage;
use ::nostr::Kind;
pub use auth::AuthProfile;
use bip39::Mnemonic;
use bitcoin::secp256k1::PublicKey;
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::Network;
use futures::{pin_mut, select, FutureExt};
use lightning::util::logger::Logger;
use lightning::{log_error, log_warn};
use nostr_sdk::{Client, RelayMessage, RelayPoolNotification};
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[derive(Clone)]
pub struct MutinyWalletConfig {
    mnemonic: Option<Mnemonic>,
    websocket_proxy_addr: Option<String>,
    network: Option<Network>,
    user_esplora_url: Option<String>,
    user_rgs_url: Option<String>,
    lsp_url: Option<String>,
}

impl MutinyWalletConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mnemonic: Option<Mnemonic>,
        websocket_proxy_addr: Option<String>,
        network: Option<Network>,
        user_esplora_url: Option<String>,
        user_rgs_url: Option<String>,
        lsp_url: Option<String>,
    ) -> Self {
        Self {
            mnemonic,
            websocket_proxy_addr,
            network,
            user_esplora_url,
            user_rgs_url,
            lsp_url,
        }
    }
}

#[derive(Clone)]
/// MutinyWallet is the main entry point for the library.
/// It contains the NodeManager, which is the main interface to manage the
/// bitcoin and the lightning functionality.
pub struct MutinyWallet<S: MutinyStorage> {
    config: MutinyWalletConfig,
    storage: S,
    pub node_manager: Arc<NodeManager<S>>,
    pub nostr: Arc<NostrManager>,
}

impl<S: MutinyStorage> MutinyWallet<S> {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        storage: S,
        mnemonic: Option<Mnemonic>,
        websocket_proxy_addr: Option<String>,
        network: Option<Network>,
        user_esplora_url: Option<String>,
        user_rgs_url: Option<String>,
        lsp_url: Option<String>,
    ) -> Result<MutinyWallet<S>, MutinyError> {
        let config = MutinyWalletConfig::new(
            mnemonic,
            websocket_proxy_addr,
            network,
            user_esplora_url,
            user_rgs_url,
            lsp_url,
        );

        let node_manager = Arc::new(NodeManager::new(config.clone(), storage.clone()).await?);

        NodeManager::start_sync(node_manager.clone());

        // create nostr manager
        let seed = node_manager.show_seed().to_seed("");
        let xprivkey = ExtendedPrivKey::new_master(node_manager.get_network(), &seed)?;
        let relays = vec!["wss://nostr.mutinywallet.com".to_string()]; // todo make configurable
        let nostr = Arc::new(NostrManager::from_mnemonic(xprivkey, relays)?);

        Ok(Self {
            config,
            storage,
            node_manager,
            nostr,
        })
    }

    /// Starts up all the nodes again.
    /// Not needed after [NodeManager]'s `new()` function.
    pub async fn start(&mut self) -> Result<(), MutinyError> {
        self.node_manager =
            Arc::new(NodeManager::new(self.config.clone(), self.storage.clone()).await?);
        NodeManager::start_sync(self.node_manager.clone());
        NodeManager::start_redshifts(self.node_manager.clone());
        Ok(())
    }

    /// Starts a background process that will watch for nostr wallet connect events
    pub async fn start_nostr_wallet_connect(&self, from_node: PublicKey) {
        let nostr = self.nostr.clone();
        let nm = self.node_manager.clone();
        utils::spawn(async move {
            let mut broadcasted_info = false;
            loop {
                if nm.stop.load(Ordering::Relaxed) {
                    break;
                };

                // check we have lightning channels ready
                if nm
                    .get_node(&from_node)
                    .await
                    .map(|n| n.channel_manager.list_usable_channels().is_empty())
                    .unwrap_or(true)
                {
                    utils::sleep(1_000).await;
                    continue;
                }

                let client = Client::new(&nostr.primary_key);
                client
                    .add_relays(nostr.relays.clone())
                    .await
                    .expect("Failed to add relays");
                client.connect().await;
                client.subscribe(vec![nostr.create_nwc_filter()]).await;

                // broadcast NWC info event
                // todo we only need to broadcast on creation
                if !broadcasted_info {
                    if let Ok(event) = nostr.create_nwc_info_event() {
                        if let Err(e) = client.send_event(event).await {
                            log_warn!(nm.logger, "Error sending NWC info event: {e}");
                        } else {
                            broadcasted_info = true;
                        }
                    }
                }

                // handle NWC requests
                let mut notifications = client.notifications();

                loop {
                    let read_fut = notifications.recv().fuse();
                    let delay_fut = Box::pin(utils::sleep(1_000)).fuse();
                    pin_mut!(read_fut);
                    pin_mut!(delay_fut);
                    select! {
                        notification = read_fut => {
                            match notification {
                                Ok(RelayPoolNotification::Event(_url, event)) => {
                                    if event.kind == Kind::WalletConnectRequest {
                                        match nostr.handle_nwc_request(event, &nm, &from_node).await {
                                            Ok(Some(event)) => {
                                                if let Err(e) = client.send_event(event).await {
                                                    log_warn!(nm.logger, "Error sending NWC event: {e}");
                                                }
                                            }
                                            Ok(None) => {} // no response
                                            Err(e) => {
                                                log_error!(nm.logger, "Error handling NWC request: {e}");
                                            }
                                        }
                                    }
                                }
                                Ok(RelayPoolNotification::Message(_url, RelayMessage::EndOfStoredEvents(_))) => {
                                    // after we process all events, sleep for 10 seconds
                                    // and then we will reconnect to the relay
                                    if let Err(e) = client.disconnect().await {
                                        log_warn!(nm.logger, "Error disconnecting from nostr relay: {e}");
                                    }
                                    // wait up to 10s, checking graceful shutdown check each 1s.
                                    for _ in 0..10 {
                                        if nm.stop.load(Ordering::Relaxed) {
                                            break;
                                        }
                                        utils::sleep(1_000).await;
                                    }
                                    break;
                                }
                                _ => {} // ignore
                            }
                        }
                        _ = delay_fut => {
                            if nm.stop.load(Ordering::Relaxed) {
                                break;
                            }
                        }
                    }
                }
            }
        });
    }

    /// Stops all of the nodes and background processes.
    /// Returns after node has been stopped.
    pub async fn stop(&self) -> Result<(), MutinyError> {
        // TODO stop redshift and NWC as well
        self.node_manager.stop().await
    }
}

#[cfg(test)]
mod tests {
    use crate::{nodemanager::NodeManager, MutinyWallet};
    use bitcoin::Network;

    use crate::test_utils::*;

    use crate::storage::MemoryStorage;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn create_mutiny_wallet() {
        let test_name = "create_mutiny_wallet";
        log!("{}", test_name);

        let storage = MemoryStorage::new(Some(uuid::Uuid::new_v4().to_string()));
        assert!(!NodeManager::has_node_manager(storage.clone()));
        MutinyWallet::new(
            storage.clone(),
            None,
            None,
            Some(Network::Regtest),
            None,
            None,
            None,
        )
        .await
        .expect("mutiny wallet should initialize");
        assert!(NodeManager::has_node_manager(storage));
    }

    #[test]
    async fn restart_mutiny_wallet() {
        let test_name = "restart_mutiny_wallet";
        log!("{}", test_name);

        let storage = MemoryStorage::new(Some(uuid::Uuid::new_v4().to_string()));
        assert!(!NodeManager::has_node_manager(storage.clone()));
        let mut mw = MutinyWallet::new(
            storage.clone(),
            None,
            None,
            Some(Network::Regtest),
            None,
            None,
            None,
        )
        .await
        .expect("mutiny wallet should initialize");
        assert!(NodeManager::has_node_manager(storage));

        let first_seed = mw.node_manager.show_seed();

        assert!(mw.stop().await.is_ok());
        assert!(mw.start().await.is_ok());
        assert_eq!(first_seed, mw.node_manager.show_seed());
    }

    #[test]
    async fn restart_mutiny_wallet_with_nodes() {
        let test_name = "restart_mutiny_wallet_with_nodes";
        log!("{}", test_name);

        let storage = MemoryStorage::new(Some(uuid::Uuid::new_v4().to_string()));

        assert!(!NodeManager::has_node_manager(storage.clone()));
        let mut mw = MutinyWallet::new(
            storage.clone(),
            None,
            None,
            Some(Network::Regtest),
            None,
            None,
            None,
        )
        .await
        .expect("mutiny wallet should initialize");
        assert!(NodeManager::has_node_manager(storage));

        assert!(mw.node_manager.list_nodes().await.unwrap().is_empty());
        assert!(mw.node_manager.new_node().await.is_ok());
        assert!(!mw.node_manager.list_nodes().await.unwrap().is_empty());

        assert!(mw.stop().await.is_ok());
        assert!(mw.start().await.is_ok());
        assert!(!mw.node_manager.list_nodes().await.unwrap().is_empty());
    }
}
