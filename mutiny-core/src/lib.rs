#![crate_name = "mutiny_core"]
// wasm is considered "extra_unused_type_parameters"
#![allow(
    incomplete_features,
    clippy::extra_unused_type_parameters,
    clippy::arc_with_non_send_sync,
    type_alias_bounds
)]
#![feature(io_error_other)]
#![feature(async_fn_in_trait)]
// background file is mostly an LDK copy paste
mod background;

pub mod auth;
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
pub mod lnurlauth;
pub mod logging;
mod lspclient;
mod multiesplora;
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
pub mod vss;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
pub mod utils;

pub use crate::gossip::{GOSSIP_SYNC_TIME_KEY, NETWORK_GRAPH_KEY, PROB_SCORER_KEY};
pub use crate::keymanager::generate_seed;
pub use crate::ldkstorage::{CHANNEL_MANAGER_KEY, MONITORS_PREFIX_KEY};

use crate::auth::MutinyAuthClient;
use crate::labels::{Contact, LabelStorage};
use crate::nostr::nwc::{NwcProfileTag, SpendingConditions};
use crate::storage::{MutinyStorage, DEVICE_ID_KEY, NEED_FULL_SYNC_KEY};
use crate::{error::MutinyError, nostr::ReservedProfile};
use crate::{nodemanager::NodeManager, nostr::ProfileType};
use crate::{nostr::NostrManager, utils::sleep};
use ::nostr::key::XOnlyPublicKey;
use ::nostr::{Keys, Kind};
use bip39::Mnemonic;
use bitcoin::secp256k1::PublicKey;
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::Network;
use futures::{pin_mut, select, FutureExt};
use lightning::{log_debug, util::logger::Logger};
use lightning::{log_error, log_info, log_warn};
use lightning_invoice::Bolt11Invoice;
use nostr_sdk::{Client, Options, RelayPoolNotification};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct MutinyWalletConfig {
    xprivkey: ExtendedPrivKey,
    #[cfg(target_arch = "wasm32")]
    websocket_proxy_addr: Option<String>,
    network: Network,
    user_esplora_url: Option<String>,
    user_rgs_url: Option<String>,
    lsp_url: Option<String>,
    auth_client: Option<Arc<MutinyAuthClient>>,
    subscription_url: Option<String>,
    scorer_url: Option<String>,
    do_not_connect_peers: bool,
    skip_device_lock: bool,
    pub safe_mode: bool,
}

impl MutinyWalletConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        xprivkey: ExtendedPrivKey,
        #[cfg(target_arch = "wasm32")] websocket_proxy_addr: Option<String>,
        network: Network,
        user_esplora_url: Option<String>,
        user_rgs_url: Option<String>,
        lsp_url: Option<String>,
        auth_client: Option<Arc<MutinyAuthClient>>,
        subscription_url: Option<String>,
        scorer_url: Option<String>,
        skip_device_lock: bool,
    ) -> Self {
        Self {
            xprivkey,
            #[cfg(target_arch = "wasm32")]
            websocket_proxy_addr,
            network,
            user_esplora_url,
            user_rgs_url,
            scorer_url,
            lsp_url,
            auth_client,
            subscription_url,
            do_not_connect_peers: false,
            skip_device_lock,
            safe_mode: false,
        }
    }

    pub fn with_do_not_connect_peers(mut self) -> Self {
        self.do_not_connect_peers = true;
        self
    }

    pub fn with_safe_mode(mut self) -> Self {
        self.safe_mode = true;
        self.with_do_not_connect_peers()
    }
}

#[derive(Clone)]
/// MutinyWallet is the main entry point for the library.
/// It contains the NodeManager, which is the main interface to manage the
/// bitcoin and the lightning functionality.
pub struct MutinyWallet<S: MutinyStorage> {
    pub config: MutinyWalletConfig,
    pub storage: S,
    pub node_manager: Arc<NodeManager<S>>,
    pub nostr: Arc<NostrManager<S>>,
}

impl<S: MutinyStorage> MutinyWallet<S> {
    pub async fn new(
        storage: S,
        config: MutinyWalletConfig,
    ) -> Result<MutinyWallet<S>, MutinyError> {
        let node_manager = Arc::new(NodeManager::new(config.clone(), storage.clone()).await?);

        NodeManager::start_sync(node_manager.clone());

        // create nostr manager
        let nostr = Arc::new(NostrManager::from_mnemonic(
            node_manager.xprivkey,
            storage.clone(),
        )?);

        let mw = Self {
            config,
            storage,
            node_manager,
            nostr,
        };

        #[cfg(not(test))]
        {
            // if we need a full sync from a restore
            if mw.storage.get(NEED_FULL_SYNC_KEY)?.unwrap_or_default() {
                mw.node_manager.wallet.full_sync().await?;
                mw.storage.delete(&[NEED_FULL_SYNC_KEY])?;
            }
        }

        // if we are in safe mode, don't create any nodes or
        // start any nostr services
        if mw.config.safe_mode {
            return Ok(mw);
        }

        // if we don't have any nodes, create one
        let first_node = {
            match mw.node_manager.list_nodes().await?.pop() {
                Some(node) => node,
                None => mw.node_manager.new_node().await?.pubkey,
            }
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

        // Redshifts disabled in safe mode
        if !self.config.safe_mode {
            NodeManager::start_redshifts(self.node_manager.clone());
        }

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

                if let Err(e) = nostr.clear_expired_nwc_invoices().await {
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

                let mut last_filters = nostr.get_nwc_filters();
                client.subscribe(last_filters.clone()).await;

                // handle NWC requests
                let mut notifications = client.notifications();

                let mut next_filter_check = crate::utils::now().as_secs() + 5;
                loop {
                    let read_fut = notifications.recv().fuse();
                    let delay_fut = Box::pin(utils::sleep(1_000)).fuse();

                    // Determine the time for filter check.
                    // Since delay runs every second, needs to allow for filter check to run too
                    let current_time = crate::utils::now().as_secs();
                    let time_until_next_filter_check =
                        (next_filter_check.saturating_sub(current_time)) * 1_000;
                    let filter_check_fut = Box::pin(utils::sleep(
                        time_until_next_filter_check.try_into().unwrap(),
                    ))
                    .fuse();

                    pin_mut!(read_fut, delay_fut, filter_check_fut);
                    select! {
                        notification = read_fut => {
                            match notification {
                                Ok(RelayPoolNotification::Event(_url, event)) => {
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
                                },
                                Ok(RelayPoolNotification::Message(_, _)) => {}, // ignore messages
                                Ok(RelayPoolNotification::Shutdown) => break, // if we disconnect, we restart to reconnect
                                Ok(RelayPoolNotification::Stop) => {}, // Currently unused
                                Err(_) => break, // if we are erroring we should reconnect
                            }
                        }
                        _ = delay_fut => {
                            if nm.stop.load(Ordering::Relaxed) {
                                break;
                            }
                        }
                        _ = filter_check_fut => {
                            // Check if the filters have changed
                            let current_filters = nostr.get_nwc_filters();
                            if current_filters != last_filters {
                                log_debug!(nm.logger, "subscribing to new nwc filters");
                                client.subscribe(current_filters.clone()).await;
                                last_filters = current_filters;
                            }
                            // Set the time for the next filter check
                            next_filter_check = crate::utils::now().as_secs() + 5;
                        }
                    }
                }

                if let Err(e) = client.disconnect().await {
                    log_warn!(nm.logger, "Error disconnecting from relays: {e}");
                }
            }
        });
    }

    /// Checks whether or not the user is subscribed to Mutiny+.
    /// Submits a NWC string to keep the subscription active if not expired.
    ///
    /// Returns None if there's no subscription at all.
    /// Returns Some(u64) for their unix expiration timestamp, which may be in the
    /// past or in the future, depending on whether or not it is currently active.
    pub async fn check_subscribed(&self) -> Result<Option<u64>, MutinyError> {
        if let Some(subscription_client) = self.node_manager.subscription_client.clone() {
            let expired = self.node_manager.check_subscribed().await?;
            if let Some(expired_time) = expired {
                // if not expired, make sure nwc is created and submitted
                // account for 3 day grace period
                if expired_time + 86_400 * 3 > crate::utils::now().as_secs() {
                    // now submit the NWC string if never created before
                    self.ensure_mutiny_nwc_profile(subscription_client).await?;
                }
            }
            Ok(expired)
        } else {
            Err(MutinyError::SubscriptionClientNotConfigured)
        }
    }

    /// Pay the subscription invoice. This will post a NWC automatically afterwards.
    pub async fn pay_subscription_invoice(&self, inv: &Bolt11Invoice) -> Result<(), MutinyError> {
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

            // now submit the NWC string if never created before
            self.ensure_mutiny_nwc_profile(subscription_client).await?;

            Ok(())
        } else {
            Err(MutinyError::SubscriptionClientNotConfigured)
        }
    }

    async fn ensure_mutiny_nwc_profile(
        &self,
        subscription_client: Arc<subscription::MutinySubscriptionClient>,
    ) -> Result<(), MutinyError> {
        let nwc_profiles = self.nostr.profiles();
        let reserved_profile_index = ReservedProfile::MutinySubscription.info().1;
        let profile_opt = nwc_profiles
            .iter()
            .find(|profile| profile.index == reserved_profile_index);

        match profile_opt {
            None => {
                // profile with the reserved index does not exist, create a new one
                let profile = self
                    .nostr
                    .create_new_nwc_profile(
                        ProfileType::Reserved(ReservedProfile::MutinySubscription),
                        SpendingConditions::RequireApproval,
                        NwcProfileTag::Subscription,
                    )
                    .await?;
                // only should have to submit the NWC if never created locally before
                subscription_client.submit_nwc(profile.nwc_uri).await?;
            }
            Some(profile) => {
                if profile.tag != NwcProfileTag::Subscription {
                    let mut nwc = profile.clone();
                    nwc.tag = NwcProfileTag::Subscription;
                    self.nostr.edit_profile(nwc)?;
                }
            }
        }

        Ok(())
    }

    /// Get contacts from the given npub and sync them to the wallet
    pub async fn sync_nostr_contacts(
        &self,
        npub: XOnlyPublicKey,
        timeout: Option<Duration>,
    ) -> Result<(), MutinyError> {
        let keys = Keys::from_public_key(npub);
        let options = Options::new().req_filters_chunk_size(30);
        let client = Client::with_opts(&keys, options);

        #[cfg(target_arch = "wasm32")]
        client.add_relay("wss://relay.damus.io").await?;

        #[cfg(not(target_arch = "wasm32"))]
        client.add_relay("wss://relay.damus.io", None).await?;

        client.connect().await;

        let mut metadata = client.get_contact_list_metadata(timeout).await?;

        let contacts = self.storage.get_contacts()?;

        for (id, contact) in contacts {
            if let Some(npub) = contact.npub {
                // need to convert to nostr::XOnlyPublicKey
                let npub = XOnlyPublicKey::from_slice(&npub.serialize()).unwrap();
                if let Some(meta) = metadata.get(&npub) {
                    let updated = contact.update_with_metadata(meta.clone());
                    self.storage.edit_contact(id, updated)?;
                    metadata.remove(&npub);
                }
            }
        }

        for (npub, meta) in metadata {
            // need to convert from nostr::XOnlyPublicKey
            let npub = bitcoin::XOnlyPublicKey::from_slice(&npub.serialize()).unwrap();
            let contact = Contact::create_from_metadata(npub, meta);

            if contact.name.is_empty() {
                continue;
            }

            self.storage.create_new_contact(contact)?;
        }

        client.disconnect().await?;
        Ok(())
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

        if old == new {
            return Err(MutinyError::SamePassword);
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

        self.node_manager.wallet.full_sync().await?;

        Ok(())
    }

    /// Restores the mnemonic after deleting the previous state.
    ///
    /// Backup the state beforehand. Does not restore lightning data.
    /// Should refresh or restart afterwards. Wallet should be stopped.
    pub async fn restore_mnemonic(mut storage: S, m: Mnemonic) -> Result<(), MutinyError> {
        let device_id = storage.get_device_id()?;
        storage.stop();
        S::clear().await?;
        storage.start().await?;
        storage.insert_mnemonic(m)?;
        storage.set_data(NEED_FULL_SYNC_KEY, true, None)?;
        storage.set_data(DEVICE_ID_KEY, device_id, None)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{generate_seed, nodemanager::NodeManager, MutinyWallet, MutinyWalletConfig};
    use bitcoin::util::bip32::ExtendedPrivKey;
    use bitcoin::Network;

    use crate::test_utils::*;

    use crate::storage::{MemoryStorage, MutinyStorage};
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn create_mutiny_wallet() {
        let test_name = "create_mutiny_wallet";
        log!("{}", test_name);

        let mnemonic = generate_seed(12).unwrap();
        let xpriv = ExtendedPrivKey::new_master(Network::Regtest, &mnemonic.to_seed("")).unwrap();

        let pass = uuid::Uuid::new_v4().to_string();
        let storage = MemoryStorage::new(Some(pass), None).unwrap();
        assert!(!NodeManager::has_node_manager(storage.clone()));
        let config = MutinyWalletConfig::new(
            xpriv,
            #[cfg(target_arch = "wasm32")]
            None,
            Network::Regtest,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        let mw = MutinyWallet::new(storage.clone(), config)
            .await
            .expect("mutiny wallet should initialize");
        mw.storage.insert_mnemonic(mnemonic).unwrap();
        assert!(NodeManager::has_node_manager(storage));
    }

    #[test]
    async fn restart_mutiny_wallet() {
        let test_name = "restart_mutiny_wallet";
        log!("{}", test_name);
        let xpriv = ExtendedPrivKey::new_master(Network::Regtest, &[0; 32]).unwrap();

        let pass = uuid::Uuid::new_v4().to_string();
        let storage = MemoryStorage::new(Some(pass), None).unwrap();
        assert!(!NodeManager::has_node_manager(storage.clone()));
        let config = MutinyWalletConfig::new(
            xpriv,
            #[cfg(target_arch = "wasm32")]
            None,
            Network::Regtest,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        let mut mw = MutinyWallet::new(storage.clone(), config)
            .await
            .expect("mutiny wallet should initialize");

        let first_seed = mw.node_manager.xprivkey;

        assert!(mw.stop().await.is_ok());
        assert!(mw.start().await.is_ok());
        assert_eq!(first_seed, mw.node_manager.xprivkey);
    }

    #[test]
    async fn restart_mutiny_wallet_with_nodes() {
        let test_name = "restart_mutiny_wallet_with_nodes";
        log!("{}", test_name);

        let xpriv = ExtendedPrivKey::new_master(Network::Regtest, &[0; 32]).unwrap();

        let pass = uuid::Uuid::new_v4().to_string();
        let storage = MemoryStorage::new(Some(pass), None).unwrap();

        assert!(!NodeManager::has_node_manager(storage.clone()));
        let config = MutinyWalletConfig::new(
            xpriv,
            #[cfg(target_arch = "wasm32")]
            None,
            Network::Regtest,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        let mut mw = MutinyWallet::new(storage.clone(), config)
            .await
            .expect("mutiny wallet should initialize");

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
        let mnemonic = generate_seed(12).unwrap();
        let xpriv = ExtendedPrivKey::new_master(Network::Regtest, &mnemonic.to_seed("")).unwrap();

        let pass = uuid::Uuid::new_v4().to_string();
        let storage = MemoryStorage::new(Some(pass), None).unwrap();
        assert!(!NodeManager::has_node_manager(storage.clone()));
        let config = MutinyWalletConfig::new(
            xpriv,
            #[cfg(target_arch = "wasm32")]
            None,
            Network::Regtest,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        let mw = MutinyWallet::new(storage.clone(), config)
            .await
            .expect("mutiny wallet should initialize");
        let seed = mw.node_manager.xprivkey;
        assert!(!seed.private_key.is_empty());

        // create a second mw and make sure it has a different seed
        let pass = uuid::Uuid::new_v4().to_string();
        let storage2 = MemoryStorage::new(Some(pass), None).unwrap();
        assert!(!NodeManager::has_node_manager(storage2.clone()));
        let xpriv = ExtendedPrivKey::new_master(Network::Regtest, &[0; 32]).unwrap();
        let mut config2 = MutinyWalletConfig::new(
            xpriv,
            #[cfg(target_arch = "wasm32")]
            None,
            Network::Regtest,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        let mw2 = MutinyWallet::new(storage2.clone(), config2.clone())
            .await
            .expect("mutiny wallet should initialize");
        let seed2 = mw2.node_manager.xprivkey;
        assert_ne!(seed, seed2);

        // now restore the first seed into the 2nd mutiny node
        mw2.stop().await.expect("should stop");
        drop(mw2);

        let pass = uuid::Uuid::new_v4().to_string();
        let storage3 = MemoryStorage::new(Some(pass), None).unwrap();
        MutinyWallet::restore_mnemonic(storage3.clone(), mnemonic.clone())
            .await
            .expect("mutiny wallet should restore");

        config2.xprivkey = {
            let seed = storage3.get_mnemonic().unwrap().unwrap();
            ExtendedPrivKey::new_master(Network::Regtest, &seed.to_seed("")).unwrap()
        };
        let mw2 = MutinyWallet::new(storage3, config2)
            .await
            .expect("mutiny wallet should initialize");
        let restored_seed = mw2.node_manager.xprivkey;
        assert_eq!(seed, restored_seed);
    }
}
