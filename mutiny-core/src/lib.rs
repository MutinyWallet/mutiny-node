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
mod lnurlauth;
pub mod logging;
mod lspclient;
mod networking;
mod node;
pub mod nodemanager;
pub mod nostr;
mod onchain;
mod peermanager;
pub mod redshift;
pub mod scb;
pub mod storage;
mod subscription;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
mod utils;

pub use crate::gossip::{GOSSIP_SYNC_TIME_KEY, NETWORK_GRAPH_KEY, PROB_SCORER_KEY};
pub use crate::keymanager::generate_seed;
pub use crate::ldkstorage::{CHANNEL_MANAGER_KEY, MONITORS_PREFIX_KEY};

use crate::storage::MutinyStorage;
use crate::{error::MutinyError, nostr::ReservedProfile};
use crate::{nodemanager::NodeManager, nostr::ProfileType};
use crate::{nostr::NostrManager, utils::sleep};
use ::nostr::Kind;
use bip39::Mnemonic;
use bitcoin::secp256k1::PublicKey;
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::Network;
use futures::{pin_mut, select, FutureExt};
use lightning::util::logger::Logger;
use lightning::{log_error, log_info, log_warn};
use lightning_invoice::Invoice;
use nostr_sdk::{Client, RelayPoolNotification};
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[derive(Clone)]
pub struct MutinyWalletConfig {
    mnemonic: Option<Mnemonic>,
    #[cfg(target_arch = "wasm32")]
    websocket_proxy_addr: Option<String>,
    network: Option<Network>,
    user_esplora_url: Option<String>,
    user_rgs_url: Option<String>,
    lsp_url: Option<String>,
    auth_url: Option<String>,
    subscription_url: Option<String>,
    do_not_connect_peers: bool,
}

impl MutinyWalletConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mnemonic: Option<Mnemonic>,
        #[cfg(target_arch = "wasm32")] websocket_proxy_addr: Option<String>,
        network: Option<Network>,
        user_esplora_url: Option<String>,
        user_rgs_url: Option<String>,
        lsp_url: Option<String>,
        auth_url: Option<String>,
        subscription_url: Option<String>,
    ) -> Self {
        Self {
            mnemonic,
            #[cfg(target_arch = "wasm32")]
            websocket_proxy_addr,
            network,
            user_esplora_url,
            user_rgs_url,
            lsp_url,
            auth_url,
            subscription_url,
            do_not_connect_peers: false,
        }
    }

    pub fn with_do_not_connect_peers(mut self) -> Self {
        self.do_not_connect_peers = true;
        self
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
    pub nostr: Arc<NostrManager<S>>,
}

impl<S: MutinyStorage> MutinyWallet<S> {
    pub async fn new(
        storage: S,
        config: MutinyWalletConfig,
    ) -> Result<MutinyWallet<S>, MutinyError> {
        let node_manager = Arc::new(NodeManager::new(config.clone(), storage.clone()).await?);

        // if we don't have any nodes, create one
        let first_node = {
            match node_manager.list_nodes().await?.pop() {
                Some(node) => node,
                None => node_manager.new_node().await?.pubkey,
            }
        };

        NodeManager::start_sync(node_manager.clone());

        // create nostr manager
        let seed = node_manager.show_seed().to_seed("");
        let xprivkey = ExtendedPrivKey::new_master(node_manager.get_network(), &seed)?;
        let nostr = Arc::new(NostrManager::from_mnemonic(xprivkey, storage.clone())?);

        let mw = Self {
            config,
            storage,
            node_manager,
            nostr,
        };

        // start the nostr wallet connect background process
        mw.start_nostr_wallet_connect(first_node).await;

        Ok(mw)
    }

    /// Starts up all the nodes again.
    /// Not needed after [NodeManager]'s `new()` function.
    pub async fn start(&mut self) -> Result<(), MutinyError> {
        self.storage.start().await?;
        self.node_manager =
            Arc::new(NodeManager::new(self.config.clone(), self.storage.clone()).await?);
        NodeManager::start_sync(self.node_manager.clone());
        NodeManager::start_redshifts(self.node_manager.clone());
        Ok(())
    }

    /// Starts a background process that will watch for nostr wallet connect events
    pub(crate) async fn start_nostr_wallet_connect(&self, from_node: PublicKey) {
        let nostr = self.nostr.clone();
        let nm = self.node_manager.clone();
        utils::spawn(async move {
            loop {
                if nm.stop.load(Ordering::Relaxed) {
                    break;
                };

                // if we have no relays, then there are no nwc profiles enabled
                // wait 10 seconds and see if we do again
                let relays = nostr.get_relays();
                if relays.is_empty() {
                    utils::sleep(10_000).await;
                    continue;
                }

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

                if let Err(e) = nostr.clear_expired_nwc_invoices() {
                    log_warn!(nm.logger, "Failed to clear expired NWC invoices: {e}");
                }

                let client = Client::new(&nostr.primary_key);

                #[cfg(target_arch = "wasm32")]
                let add_relay_res = client.add_relays(nostr.get_relays()).await;

                #[cfg(not(target_arch = "wasm32"))]
                let add_relay_res = client
                    .add_relays(nostr.get_relays().into_iter().map(|s| (s, None)).collect())
                    .await;

                add_relay_res.expect("Failed to add relays");
                client.connect().await;
                client.subscribe(nostr.get_nwc_filters()).await;

                // handle NWC requests
                let mut notifications = client.notifications();

                loop {
                    let read_fut = notifications.recv().fuse();
                    let delay_fut = Box::pin(utils::sleep(1_000)).fuse();
                    pin_mut!(read_fut);
                    pin_mut!(delay_fut);
                    select! {
                        notification = read_fut => {
                                if let Ok(RelayPoolNotification::Event(_url, event)) = notification {
                                    if event.kind == Kind::WalletConnectRequest && event.verify().is_ok() {
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

    /// Pay the subscription invoice. This will post a NWC automatically afterwards.
    pub async fn pay_subscription_invoice(&self, inv: &Invoice) -> Result<(), MutinyError> {
        if let Some(subscription_client) = self.node_manager.subscription_client.clone() {
            let nodes = self.node_manager.nodes.lock().await;
            let first_node_pubkey = if let Some(node) = nodes.values().next() {
                node.pubkey
            } else {
                return Err(MutinyError::WalletOperationFailed);
            };
            drop(nodes);

            // TODO if this times out, we should make the next part happen in EventManager
            self.node_manager
                .pay_invoice(
                    &first_node_pubkey,
                    inv,
                    None,
                    vec!["Mutiny+ Subscription".to_string()],
                )
                .await?;

            // now submit the NWC string
            let nwc_profiles = self.nostr.profiles();
            let reserved_profile_index = ReservedProfile::MutinySubscription.info().1;
            let profile_opt = nwc_profiles
                .iter()
                .find(|profile| profile.index == reserved_profile_index);

            let nwc_uri = match profile_opt {
                Some(profile) => {
                    // profile with the reserved index already exists, do something with it
                    profile.nwc_uri.clone()
                }
                None => {
                    // profile with the reserved index does not exist, create a new one
                    let profile = self
                        .nostr
                        .create_new_nwc_profile(
                            ProfileType::Reserved(ReservedProfile::MutinySubscription),
                            21_000,
                        )
                        .await?;
                    profile.nwc_uri
                }
            };

            subscription_client.submit_nwc(nwc_uri).await?;

            Ok(())
        } else {
            Err(MutinyError::SubscriptionClientNotConfigured)
        }
    }

    /// Stops all of the nodes and background processes.
    /// Returns after node has been stopped.
    pub async fn stop(&self) -> Result<(), MutinyError> {
        // TODO stop redshift and NWC as well
        self.node_manager.stop().await
    }

    pub async fn change_password(
        &mut self,
        old: Option<String>,
        new: Option<String>,
    ) -> Result<(), MutinyError> {
        // check if old password is correct
        if old != self.storage.password().map(|s| s.to_owned()) {
            return Err(MutinyError::IncorrectPassword);
        }

        log_info!(self.node_manager.logger, "Changing password");

        self.stop().await?;

        self.storage.start().await?;

        self.storage.change_password_and_rewrite_storage(
            old.filter(|s| !s.is_empty()),
            new.filter(|s| !s.is_empty()),
        )?;

        // There's not a good way to check that all the indexeddb
        // data is saved in the background. This should get better
        // once we have async saving, but for now just make sure
        // the user has saved their seed already.
        sleep(5_000).await;

        Ok(())
    }

    /// Resets BDK's keychain tracker. This will require a re-sync of the blockchain.
    ///
    /// This can be useful if you get stuck in a bad state.
    pub async fn reset_onchain_tracker(&mut self) -> Result<(), MutinyError> {
        self.node_manager.reset_onchain_tracker().await?;
        // sleep for 250ms to give time for the storage to write
        utils::sleep(250).await;

        self.stop().await?;

        // sleep for 250ms to give time for the node manager to stop
        utils::sleep(250).await;

        self.start().await?;

        Ok(())
    }

    /// Restores the mnemonic after deleting the previous state.
    ///
    /// Backup the state beforehand. Does not restore lightning data.
    /// Should refresh or restart afterwards. Wallet should be stopped.
    pub async fn restore_mnemonic(mut storage: S, m: Mnemonic) -> Result<(), MutinyError> {
        storage.stop();
        S::clear().await?;
        storage.start().await?;
        storage.insert_mnemonic(m)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        encrypt::encryption_key_from_pass, nodemanager::NodeManager, MutinyWallet,
        MutinyWalletConfig,
    };
    use bitcoin::Network;

    use crate::test_utils::*;

    use crate::storage::MemoryStorage;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn create_mutiny_wallet() {
        let test_name = "create_mutiny_wallet";
        log!("{}", test_name);

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher));
        assert!(!NodeManager::has_node_manager(storage.clone()));
        let config = MutinyWalletConfig::new(
            None,
            #[cfg(target_arch = "wasm32")]
            None,
            Some(Network::Regtest),
            None,
            None,
            None,
            None,
            None,
        );
        MutinyWallet::new(storage.clone(), config)
            .await
            .expect("mutiny wallet should initialize");
        assert!(NodeManager::has_node_manager(storage));
    }

    #[test]
    async fn restart_mutiny_wallet() {
        let test_name = "restart_mutiny_wallet";
        log!("{}", test_name);

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher));
        assert!(!NodeManager::has_node_manager(storage.clone()));
        let config = MutinyWalletConfig::new(
            None,
            #[cfg(target_arch = "wasm32")]
            None,
            Some(Network::Regtest),
            None,
            None,
            None,
            None,
            None,
        );
        let mut mw = MutinyWallet::new(storage.clone(), config)
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

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher));

        assert!(!NodeManager::has_node_manager(storage.clone()));
        let config = MutinyWalletConfig::new(
            None,
            #[cfg(target_arch = "wasm32")]
            None,
            Some(Network::Regtest),
            None,
            None,
            None,
            None,
            None,
        );
        let mut mw = MutinyWallet::new(storage.clone(), config)
            .await
            .expect("mutiny wallet should initialize");
        assert!(NodeManager::has_node_manager(storage));

        assert_eq!(mw.node_manager.list_nodes().await.unwrap().len(), 1);
        assert!(mw.node_manager.new_node().await.is_ok());
        assert_eq!(mw.node_manager.list_nodes().await.unwrap().len(), 2);

        assert!(mw.stop().await.is_ok());
        assert!(mw.start().await.is_ok());
        assert_eq!(mw.node_manager.list_nodes().await.unwrap().len(), 2);
    }

    #[test]
    async fn restore_mutiny_mnemonic() {
        let test_name = "restore_mutiny_mnemonic";
        log!("{}", test_name);

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher));
        assert!(!NodeManager::has_node_manager(storage.clone()));
        let config = MutinyWalletConfig::new(
            None,
            #[cfg(target_arch = "wasm32")]
            None,
            Some(Network::Regtest),
            None,
            None,
            None,
            None,
            None,
        );
        let mw = MutinyWallet::new(storage.clone(), config)
            .await
            .expect("mutiny wallet should initialize");
        let seed = mw.node_manager.show_seed();
        assert_ne!(seed.to_string(), "");

        // create a second mw and make sure it has a different seed
        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage2 = MemoryStorage::new(Some(pass), Some(cipher));
        assert!(!NodeManager::has_node_manager(storage2.clone()));
        let config2 = MutinyWalletConfig::new(
            None,
            #[cfg(target_arch = "wasm32")]
            None,
            Some(Network::Regtest),
            None,
            None,
            None,
            None,
            None,
        );
        let mw2 = MutinyWallet::new(storage2.clone(), config2.clone())
            .await
            .expect("mutiny wallet should initialize");
        let seed2 = mw2.node_manager.show_seed();
        assert_ne!(seed.to_string(), seed2.to_string());

        // now restore the first seed into the 2nd mutiny node
        mw2.stop().await.expect("should stop");
        drop(mw2);

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage3 = MemoryStorage::new(Some(pass), Some(cipher));
        MutinyWallet::restore_mnemonic(storage3.clone(), seed.clone())
            .await
            .expect("mutiny wallet should restore");

        let mw2 = MutinyWallet::new(storage3, config2)
            .await
            .expect("mutiny wallet should initialize");
        let restored_seed = mw2.node_manager.show_seed();
        assert_eq!(seed.to_string(), restored_seed.to_string());
    }
}
