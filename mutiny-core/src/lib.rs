#![crate_name = "mutiny_core"]
// wasm is considered "extra_unused_type_parameters"
#![allow(
    async_fn_in_trait,
    incomplete_features,
    clippy::extra_unused_type_parameters,
    clippy::arc_with_non_send_sync,
    type_alias_bounds
)]
extern crate core;

pub mod auth;
mod chain;
pub mod encrypt;
pub mod error;
mod event;
pub mod federation;
mod fees;
mod gossip;
mod key;
mod keymanager;
pub mod labels;
mod ldkstorage;
pub mod lnurlauth;
pub mod logging;
mod lsp;
mod messagehandler;
mod networking;
mod node;
pub mod nodemanager;
pub mod nostr;
mod onchain;
mod peermanager;
pub mod redshift;
pub mod scorer;
pub mod sql;
pub mod storage;
mod subscription;
pub mod utils;
pub mod vss;

#[cfg(test)]
mod test_utils;

pub use crate::event::HTLCStatus;
pub use crate::gossip::{GOSSIP_SYNC_TIME_KEY, NETWORK_GRAPH_KEY, PROB_SCORER_KEY};
pub use crate::keymanager::generate_seed;
pub use crate::ldkstorage::{CHANNEL_MANAGER_KEY, MONITORS_PREFIX_KEY};

use crate::logging::LOGGING_KEY;
use crate::nodemanager::{
    ChannelClosure, MutinyBip21RawMaterials, MutinyInvoice, TransactionDetails,
};
use crate::nostr::nwc::{
    BudgetPeriod, BudgetedSpendingConditions, NwcProfileTag, SpendingConditions,
};
use crate::nostr::MUTINY_PLUS_SUBSCRIPTION_LABEL;
use crate::storage::{MutinyStorage, DEVICE_ID_KEY, EXPECTED_NETWORK_KEY, NEED_FULL_SYNC_KEY};
use crate::{auth::MutinyAuthClient, logging::MutinyLogger};
use crate::{error::MutinyError, nostr::ReservedProfile};
use crate::{
    federation::{FederationClient, FederationIdentity, FederationIndex, FederationStorage},
    labels::{get_contact_key, Contact, LabelStorage},
    nodemanager::NodeBalance,
    sql::glue::GlueDB,
};
use crate::{nodemanager::NodeManager, nostr::ProfileType};
use crate::{nostr::NostrManager, utils::sleep};
use ::nostr::key::XOnlyPublicKey;
use ::nostr::{Event, Kind, Metadata};
use bdk_chain::ConfirmationTime;
use bip39::Mnemonic;
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::Network;
use bitcoin::{hashes::sha256, secp256k1::PublicKey};
use fedimint_core::{api::InviteCode, config::FederationId};
use futures::{pin_mut, select, FutureExt};
use futures_util::lock::Mutex;
use lightning::{log_debug, util::logger::Logger};
use lightning::{log_error, log_info, log_warn};
use lightning_invoice::Bolt11Invoice;
use nostr_sdk::{Client, RelayPoolNotification};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::{collections::HashMap, sync::atomic::AtomicBool};
use uuid::Uuid;

const DEFAULT_PAYMENT_TIMEOUT: u64 = 30;

#[derive(Copy, Clone)]
pub struct MutinyBalance {
    pub confirmed: u64,
    pub unconfirmed: u64,
    pub lightning: u64,
    pub federation: u64,
    pub force_close: u64,
}

impl MutinyBalance {
    fn new(ln_balance: NodeBalance, federation_balance: u64) -> Self {
        Self {
            confirmed: ln_balance.confirmed,
            unconfirmed: ln_balance.unconfirmed,
            lightning: ln_balance.lightning,
            federation: federation_balance,
            force_close: ln_balance.force_close,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct FederationBalance {
    pub identity: FederationIdentity,
    pub balance: u64,
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct FederationBalances {
    pub balances: Vec<FederationBalance>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ActivityItem {
    OnChain(TransactionDetails),
    Lightning(Box<MutinyInvoice>),
    ChannelClosed(ChannelClosure),
}

impl ActivityItem {
    pub fn last_updated(&self) -> Option<u64> {
        match self {
            ActivityItem::OnChain(t) => match t.confirmation_time {
                ConfirmationTime::Confirmed { time, .. } => Some(time),
                ConfirmationTime::Unconfirmed { .. } => None,
            },
            ActivityItem::Lightning(i) => match i.status {
                HTLCStatus::Succeeded => Some(i.last_updated),
                HTLCStatus::Failed => Some(i.last_updated),
                HTLCStatus::Pending | HTLCStatus::InFlight => None,
            },
            ActivityItem::ChannelClosed(c) => Some(c.timestamp),
        }
    }

    pub fn labels(&self) -> Vec<String> {
        match self {
            ActivityItem::OnChain(t) => t.labels.clone(),
            ActivityItem::Lightning(i) => i.labels.clone(),
            ActivityItem::ChannelClosed(_) => vec![],
        }
    }

    pub fn is_channel_open(&self) -> bool {
        match self {
            ActivityItem::OnChain(onchain) => {
                onchain.labels.iter().any(|l| l.contains("LN Channel:"))
            }
            ActivityItem::Lightning(_) => false,
            ActivityItem::ChannelClosed(_) => false,
        }
    }
}

impl PartialOrd for ActivityItem {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ActivityItem {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // We want None to be greater than Some because those are pending transactions
        // so those should be at the top of the list
        let sort = match (self.last_updated(), other.last_updated()) {
            (Some(self_time), Some(other_time)) => self_time.cmp(&other_time),
            (Some(_), None) => core::cmp::Ordering::Less,
            (None, Some(_)) => core::cmp::Ordering::Greater,
            (None, None) => {
                // if both are none, do lightning first
                match (self, other) {
                    (ActivityItem::Lightning(_), ActivityItem::OnChain(_)) => {
                        core::cmp::Ordering::Greater
                    }
                    (ActivityItem::OnChain(_), ActivityItem::Lightning(_)) => {
                        core::cmp::Ordering::Less
                    }
                    (ActivityItem::Lightning(l1), ActivityItem::Lightning(l2)) => {
                        // compare lightning by expire time
                        l1.expire.cmp(&l2.expire)
                    }
                    (ActivityItem::OnChain(o1), ActivityItem::OnChain(o2)) => {
                        // compare onchain by confirmation time (which will be last seen for unconfirmed)
                        o1.confirmation_time.cmp(&o2.confirmation_time)
                    }
                    _ => core::cmp::Ordering::Equal,
                }
            }
        };

        // if the sort is equal, sort by serialization so we have a stable sort
        sort.then_with(|| {
            serde_json::to_string(self)
                .unwrap()
                .cmp(&serde_json::to_string(other).unwrap())
        })
    }
}

#[derive(Clone)]
pub struct MutinyWalletConfig {
    xprivkey: ExtendedPrivKey,
    #[cfg(target_arch = "wasm32")]
    websocket_proxy_addr: Option<String>,
    network: Network,
    user_esplora_url: Option<String>,
    user_rgs_url: Option<String>,
    lsp_url: Option<String>,
    lsp_connection_string: Option<String>,
    lsp_token: Option<String>,
    auth_client: Option<Arc<MutinyAuthClient>>,
    subscription_url: Option<String>,
    scorer_url: Option<String>,
    do_not_connect_peers: bool,
    skip_device_lock: bool,
    pub safe_mode: bool,
    skip_hodl_invoices: bool,
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
        lsp_connection_string: Option<String>,
        lsp_token: Option<String>,
        auth_client: Option<Arc<MutinyAuthClient>>,
        subscription_url: Option<String>,
        scorer_url: Option<String>,
        skip_device_lock: bool,
        skip_hodl_invoices: bool,
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
            lsp_connection_string,
            lsp_token,
            auth_client,
            subscription_url,
            do_not_connect_peers: false,
            skip_device_lock,
            safe_mode: false,
            skip_hodl_invoices,
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
    glue_db: GlueDB,
    pub node_manager: Arc<NodeManager<S>>,
    pub nostr: Arc<NostrManager<S>>,
    pub federation_storage: Arc<Mutex<FederationStorage>>,
    pub(crate) federations: Arc<Mutex<HashMap<FederationId, Arc<FederationClient<S>>>>>,
    pub stop: Arc<AtomicBool>,
    pub logger: Arc<MutinyLogger>,
}

impl<S: MutinyStorage> MutinyWallet<S> {
    pub async fn new(
        storage: S,
        config: MutinyWalletConfig,
        session_id: Option<String>,
    ) -> Result<MutinyWallet<S>, MutinyError> {
        let expected_network = storage.get::<Network>(EXPECTED_NETWORK_KEY)?;
        match expected_network {
            Some(network) => {
                if network != config.network {
                    return Err(MutinyError::NetworkMismatch);
                }
            }
            None => storage.set_data(EXPECTED_NETWORK_KEY.to_string(), config.network, None)?,
        }

        let stop = Arc::new(AtomicBool::new(false));
        let logger = Arc::new(MutinyLogger::with_writer(
            stop.clone(),
            storage.clone(),
            session_id,
        ));
        let node_manager = Arc::new(
            NodeManager::new(
                config.clone(),
                storage.clone(),
                stop.clone(),
                logger.clone(),
            )
            .await?,
        );

        NodeManager::start_sync(node_manager.clone());

        // create nostr manager
        let nostr = Arc::new(NostrManager::from_mnemonic(
            node_manager.xprivkey,
            storage.clone(),
            node_manager.logger.clone(),
        )?);

        // create gluedb storage
        let glue_db = GlueDB::new(
            #[cfg(target_arch = "wasm32")]
            None,
            logger.clone(),
        )
        .await?;

        // create federation library
        let (federation_storage, federations) =
            create_federations(&storage, &config, glue_db.clone(), &logger, stop.clone()).await?;
        let federation_storage = Arc::new(Mutex::new(federation_storage));
        let federations = federations;

        if !config.skip_hodl_invoices {
            log_warn!(
                node_manager.logger,
                "Starting with HODL invoices enabled. This is not recommended!"
            );
        }

        let mw = Self {
            config,
            storage,
            glue_db,
            node_manager,
            nostr,
            federation_storage,
            federations,
            stop,
            logger,
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
        // when we restart, gen a new session id
        self.node_manager = Arc::new(
            NodeManager::new(
                self.config.clone(),
                self.storage.clone(),
                self.stop.clone(),
                self.logger.clone(),
            )
            .await?,
        );
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

                // clear in-active profiles, we used to have disabled and archived profiles
                // but now we just delete profiles
                if let Err(e) = nostr.remove_inactive_profiles() {
                    log_warn!(nm.logger, "Failed to clear in-active NWC profiles: {e}");
                }

                // if a single-use profile's payment was successful in the background,
                // we can safely clear it now
                let node = nm.get_node(&from_node).await.expect("failed to get node");
                if let Err(e) = nostr.clear_successful_single_use_profiles(&node) {
                    log_warn!(nm.logger, "Failed to clear in-active NWC profiles: {e}");
                }
                drop(node);

                if let Err(e) = nostr.clear_expired_nwc_invoices().await {
                    log_warn!(nm.logger, "Failed to clear expired NWC invoices: {e}");
                }

                // clear successful single-use profiles

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
                                Ok(RelayPoolNotification::RelayStatus { .. }) => {}, // Currently unused
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

    /// Pays a lightning invoice from a federation (preferred) or node.
    /// An amount should only be provided if the invoice does not have an amount.
    /// Amountless invoices cannot be paid by a federation.
    /// The amount should be in satoshis.
    pub async fn pay_invoice(
        &self,
        inv: &Bolt11Invoice,
        amt_sats: Option<u64>,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        if inv.network() != self.config.network {
            return Err(MutinyError::IncorrectNetwork(inv.network()));
        }

        // Check the amount specified in the invoice, we need one to make the payment
        let send_msat = inv
            .amount_milli_satoshis()
            .or(amt_sats.map(|x| x * 1_000))
            .ok_or(MutinyError::InvoiceInvalid)?;

        // Try each federation first
        let federation_ids = self.list_federations().await?;
        for federation_id in federation_ids {
            if let Some(fedimint_client) = self.federations.lock().await.get(&federation_id) {
                // Check if the federation has enough balance
                let balance = fedimint_client.get_balance().await?;
                if balance >= send_msat / 1_000 {
                    // Try to pay the invoice using the federation
                    let payment_result = fedimint_client.pay_invoice(inv.clone()).await;
                    match payment_result {
                        Ok(r) => return Ok(r),
                        Err(e) => match e {
                            MutinyError::PaymentTimeout => return Err(e),
                            MutinyError::RoutingFailed => {
                                log_debug!(
                                    self.logger,
                                    "could not make payment through federation: {e}"
                                );
                                continue;
                            }
                            _ => {
                                log_warn!(self.logger, "unhandled error: {e}")
                            }
                        },
                    }
                }
                // If payment fails or invoice amount is None or balance is not sufficient, continue to next federation
            }
            // If federation client is not found, continue to next federation
        }

        // If no federation could pay the invoice, fall back to using node_manager for payment
        self.node_manager
            .pay_invoice(None, inv, amt_sats, labels)
            .await
    }

    /// Creates a BIP 21 invoice. This creates a new address and a lightning invoice.
    /// The lightning invoice may return errors related to the LSP. Check the error and
    /// fallback to `get_new_address` and warn the user that Lightning is not available.
    ///
    /// Errors that might be returned include:
    ///
    /// - [`MutinyError::LspGenericError`]: This is returned for various reasons, including if a
    ///   request to the LSP server fails for any reason, or if the server returns
    ///   a status other than 500 that can't be parsed into a `ProposalResponse`.
    ///
    /// - [`MutinyError::LspFundingError`]: Returned if the LSP server returns an error with
    ///   a status of 500, indicating an "Internal Server Error", and a message
    ///   stating "Cannot fund new channel at this time". This means that the LSP cannot support
    ///   a new channel at this time.
    ///
    /// - [`MutinyError::LspAmountTooHighError`]: Returned if the LSP server returns an error with
    ///   a status of 500, indicating an "Internal Server Error", and a message stating "Invoice
    ///   amount is too high". This means that the LSP cannot support the amount that the user
    ///   requested. The user should request a smaller amount from the LSP.
    ///
    /// - [`MutinyError::LspConnectionError`]: Returned if the LSP server returns an error with
    ///   a status of 500, indicating an "Internal Server Error", and a message that starts with
    ///   "Failed to connect to peer". This means that the LSP is not connected to our node.
    ///
    /// If the server returns a status of 500 with a different error message,
    /// a [`MutinyError::LspGenericError`] is returned.
    pub async fn create_bip21(
        &self,
        amount: Option<u64>,
        labels: Vec<String>,
    ) -> Result<MutinyBip21RawMaterials, MutinyError> {
        let invoice = if self.config.safe_mode {
            None
        } else {
            // Check if a federation exists
            let federation_ids = self.list_federations().await?;
            if !federation_ids.is_empty() {
                // Use the first federation for simplicity
                let federation_id = &federation_ids[0];
                let fedimint_client = self.federations.lock().await.get(federation_id).cloned();

                match fedimint_client {
                    Some(client) => {
                        // Try to create an invoice using the federation
                        match client.get_invoice(amount.unwrap_or_default()).await {
                            Ok(inv) => Some(inv.bolt11.ok_or(MutinyError::WalletOperationFailed)?),
                            Err(_) => None, // Handle the error or fallback to node_manager invoice creation
                        }
                    }
                    None => None, // No federation client found, fallback to node_manager invoice creation
                }
            } else {
                // Fallback to node_manager invoice creation if no federation is found
                let inv = self
                    .node_manager
                    .create_invoice(amount, labels.clone())
                    .await?;
                Some(inv.bolt11.ok_or(MutinyError::WalletOperationFailed)?)
            }
        };

        let Ok(address) = self.node_manager.get_new_address(labels.clone()) else {
            return Err(MutinyError::WalletOperationFailed);
        };

        Ok(MutinyBip21RawMaterials {
            address,
            invoice,
            btc_amount: amount.map(|amount| bitcoin::Amount::from_sat(amount).to_btc().to_string()),
            labels,
        })
    }

    /// Gets the current balance of the wallet.
    /// This includes both on-chain, lightning funds, and federations.
    ///
    /// This will not include any funds in an unconfirmed lightning channel.
    pub async fn get_balance(&self) -> Result<MutinyBalance, MutinyError> {
        let ln_balance = self.node_manager.get_balance().await?;
        let federation_balance = self.get_total_federation_balance().await?;

        Ok(MutinyBalance::new(ln_balance, federation_balance))
    }

    /// Get the sorted activity list for lightning payments, channels, and txs.
    pub async fn get_activity(&self) -> Result<Vec<ActivityItem>, MutinyError> {
        // Get activities from node manager
        let mut activities = self.node_manager.get_activity().await?;

        // Directly iterate over federation clients to get their activities
        let federations = self.federations.lock().await;
        for (_fed_id, federation) in federations.iter() {
            let federation_activities = federation.get_activity().await?;
            activities.extend(federation_activities);
        }

        // Sort all activities, newest first
        activities.sort_by(|a, b| b.cmp(a));

        Ok(activities)
    }

    /// Gets an invoice.
    /// This includes sent and received invoices.
    pub async fn get_invoice(&self, invoice: &Bolt11Invoice) -> Result<MutinyInvoice, MutinyError> {
        self.get_invoice_by_hash(invoice.payment_hash()).await
    }

    /// Looks up an invoice by hash.
    /// This includes sent and received invoices.
    pub async fn get_invoice_by_hash(
        &self,
        hash: &sha256::Hash,
    ) -> Result<MutinyInvoice, MutinyError> {
        // First, try to find the invoice in the node manager
        if let Ok(invoice) = self.node_manager.get_invoice_by_hash(hash).await {
            return Ok(invoice);
        }

        // If not found in node manager, search in federations
        let federations = self.federations.lock().await;
        for (_fed_id, federation) in federations.iter() {
            if let Ok(invoice) = federation.get_invoice_by_hash(hash).await {
                return Ok(invoice);
            }
        }

        Err(MutinyError::NotFound)
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
                    self.ensure_mutiny_nwc_profile(subscription_client, false)
                        .await?;
                }
            }
            Ok(expired)
        } else {
            Err(MutinyError::SubscriptionClientNotConfigured)
        }
    }

    /// Pay the subscription invoice. This will post a NWC automatically afterwards.
    pub async fn pay_subscription_invoice(
        &self,
        inv: &Bolt11Invoice,
        autopay: bool,
    ) -> Result<(), MutinyError> {
        if let Some(subscription_client) = self.node_manager.subscription_client.clone() {
            // TODO if this times out, we should make the next part happen in EventManager
            self.node_manager
                .pay_invoice(
                    None,
                    inv,
                    None,
                    vec![MUTINY_PLUS_SUBSCRIPTION_LABEL.to_string()],
                )
                .await?;

            // now submit the NWC string if never created before
            self.ensure_mutiny_nwc_profile(subscription_client, autopay)
                .await?;

            Ok(())
        } else {
            Err(MutinyError::SubscriptionClientNotConfigured)
        }
    }

    async fn ensure_mutiny_nwc_profile(
        &self,
        subscription_client: Arc<subscription::MutinySubscriptionClient>,
        autopay: bool,
    ) -> Result<(), MutinyError> {
        let nwc_profiles = self.nostr.profiles();
        let reserved_profile_index = ReservedProfile::MutinySubscription.info().1;
        let profile_opt = nwc_profiles
            .iter()
            .find(|profile| profile.index == reserved_profile_index);

        match profile_opt {
            None => {
                // profile with the reserved index does not exist, create a new one
                let nwc = if autopay {
                    self.nostr
                        .create_new_nwc_profile(
                            ProfileType::Reserved(ReservedProfile::MutinySubscription),
                            SpendingConditions::Budget(BudgetedSpendingConditions {
                                budget: 21_000,
                                single_max: None,
                                payments: vec![],
                                period: BudgetPeriod::Month,
                            }),
                            NwcProfileTag::Subscription,
                        )
                        .await?
                        .nwc_uri
                } else {
                    self.nostr
                        .create_new_nwc_profile(
                            ProfileType::Reserved(ReservedProfile::MutinySubscription),
                            SpendingConditions::RequireApproval,
                            NwcProfileTag::Subscription,
                        )
                        .await?
                        .nwc_uri
                };

                if let Some(nwc) = nwc {
                    // only should have to submit the NWC if never created locally before
                    subscription_client.submit_nwc(nwc).await?;
                }
            }
            Some(profile) => {
                if profile.tag != NwcProfileTag::Subscription {
                    let mut nwc = profile.clone();
                    nwc.tag = NwcProfileTag::Subscription;
                    self.nostr.edit_profile(nwc)?;
                }
            }
        }

        // check if we have a contact, if not create one
        match self
            .node_manager
            .get_contact(MUTINY_PLUS_SUBSCRIPTION_LABEL)?
        {
            Some(_) => {}
            None => {
                let key = get_contact_key(MUTINY_PLUS_SUBSCRIPTION_LABEL);
                let contact = Contact {
                    name: MUTINY_PLUS_SUBSCRIPTION_LABEL.to_string(),
                    npub: None,
                    ln_address: None,
                    lnurl: None,
                    image_url: Some("https://void.cat/d/CZPXhnwjqRhULSjPJ3sXTE.webp".to_string()),
                    archived: None,
                    last_used: utils::now().as_secs(),
                };
                self.storage.set_data(key, contact, None)?;
            }
        }

        Ok(())
    }

    /// Get contacts from the given npub and sync them to the wallet
    pub async fn sync_nostr_contacts(
        &self,
        primal_url: Option<&str>,
        npub: XOnlyPublicKey,
    ) -> Result<(), MutinyError> {
        let body = json!(["contact_list", { "pubkey": npub } ]);

        let url = primal_url.unwrap_or("https://primal-cache.mutinywallet.com/api");
        let data: Vec<Value> = reqwest::Client::new()
            .post(url)
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|_| MutinyError::NostrError)?
            .json()
            .await
            .map_err(|_| MutinyError::NostrError)?;

        let mut metadata = data
            .into_iter()
            .filter_map(|v| {
                Event::from_value(v)
                    .ok()
                    .and_then(|e| Metadata::from_json(e.content).ok().map(|m| (e.pubkey, m)))
            })
            .collect::<HashMap<_, _>>();

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
                log_debug!(
                    self.node_manager.logger,
                    "Skipping creating contact with no name: {npub}"
                );
                continue;
            }

            self.storage.create_new_contact(contact)?;
        }

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
        let logs: Option<Vec<String>> = storage.get_data(LOGGING_KEY)?;
        storage.stop();
        S::clear().await?;
        storage.start().await?;
        storage.insert_mnemonic(m)?;
        storage.set_data(NEED_FULL_SYNC_KEY.to_string(), true, None)?;
        storage.set_data(DEVICE_ID_KEY.to_string(), device_id, None)?;
        storage.set_data(LOGGING_KEY.to_string(), logs, None)?;
        Ok(())
    }

    /// Decodes a lightning invoice into useful information.
    /// Will return an error if the invoice is for a different network.
    pub fn decode_invoice(
        &self,
        invoice: Bolt11Invoice,
        network: Option<Network>,
    ) -> Result<MutinyInvoice, MutinyError> {
        if invoice.network() != network.unwrap_or(self.config.network) {
            return Err(MutinyError::IncorrectNetwork(invoice.network()));
        }

        Ok(invoice.into())
    }

    /// Adds a new federation based on its federation code
    pub async fn new_federation(
        &self,
        federation_code: InviteCode,
    ) -> Result<FederationIdentity, MutinyError> {
        create_new_federation(
            self.config.xprivkey,
            self.storage.clone(),
            self.glue_db.clone(),
            self.config.network,
            self.logger.clone(),
            self.federation_storage.clone(),
            self.federations.clone(),
            federation_code,
            self.stop.clone(),
        )
        .await
    }

    /// Lists the federation id's of the federation clients in the manager.
    pub async fn list_federations(&self) -> Result<Vec<FederationId>, MutinyError> {
        let federations = self.federations.lock().await;
        let federation_ids = federations
            .iter()
            .map(|(_, n)| n.fedimint_client.federation_id())
            .collect();
        Ok(federation_ids)
    }

    /// Removes a federation by setting its archived status to true, based on the FederationId.
    pub async fn remove_federation(&self, federation_id: FederationId) -> Result<(), MutinyError> {
        let mut federations_guard = self.federations.lock().await;

        if let Some(fedimint_client) = federations_guard.get(&federation_id) {
            let uuid = &fedimint_client.uuid;

            let mut federation_storage_guard = self.federation_storage.lock().await;

            if federation_storage_guard.federations.contains_key(uuid) {
                federation_storage_guard.federations.remove(uuid);
                self.storage
                    .insert_federations(federation_storage_guard.clone())?;
                federations_guard.remove(&federation_id);
            } else {
                return Err(MutinyError::NotFound);
            }
        } else {
            return Err(MutinyError::NotFound);
        }

        Ok(())
    }

    pub async fn get_total_federation_balance(&self) -> Result<u64, MutinyError> {
        let federation_ids = self.list_federations().await?;
        let mut total_balance = 0;

        let federations = self.federations.lock().await;
        for fed_id in federation_ids {
            let balance = federations
                .get(&fed_id)
                .ok_or(MutinyError::NotFound)?
                .get_balance()
                .await?;

            total_balance += balance;
        }

        Ok(total_balance)
    }

    pub async fn get_federation_balances(&self) -> Result<FederationBalances, MutinyError> {
        let federation_lock = self.federations.lock().await;

        let federation_ids = self.list_federations().await?;
        let mut balances = Vec::with_capacity(federation_ids.len());
        for fed_id in federation_ids {
            let fedimint_client = federation_lock.get(&fed_id).ok_or(MutinyError::NotFound)?;

            let balance = fedimint_client.get_balance().await?;
            let identity = fedimint_client.get_mutiny_federation_identity().await;

            balances.push(FederationBalance { identity, balance });
        }

        Ok(FederationBalances { balances })
    }
}

async fn create_federations<S: MutinyStorage>(
    storage: &S,
    c: &MutinyWalletConfig,
    g: GlueDB,
    logger: &Arc<MutinyLogger>,
    stop: Arc<AtomicBool>,
) -> Result<
    (
        FederationStorage,
        Arc<Mutex<HashMap<FederationId, Arc<FederationClient<S>>>>>,
    ),
    MutinyError,
> {
    let federation_storage = storage.get_federations()?;
    let federations = federation_storage.clone().federations.into_iter();
    let mut federation_map = HashMap::new();
    for federation_item in federations {
        let federation = FederationClient::new(
            federation_item.0,
            &federation_item.1,
            federation_item.1.federation_code.clone(),
            c.xprivkey,
            storage.clone(),
            g.clone(),
            c.network,
            logger.clone(),
            stop.clone(),
        )
        .await?;

        let id = federation.fedimint_client.federation_id();

        federation_map.insert(id, Arc::new(federation));
    }
    let federations = Arc::new(Mutex::new(federation_map));
    Ok((federation_storage, federations))
}

// This will create a new federation and returns the Federation ID of the client created.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_new_federation<S: MutinyStorage>(
    xprivkey: ExtendedPrivKey,
    storage: S,
    g: GlueDB,
    network: Network,
    logger: Arc<MutinyLogger>,
    federation_storage: Arc<Mutex<FederationStorage>>,
    federations: Arc<Mutex<HashMap<FederationId, Arc<FederationClient<S>>>>>,
    federation_code: InviteCode,
    stop: Arc<AtomicBool>,
) -> Result<FederationIdentity, MutinyError> {
    // Begin with a mutex lock so that nothing else can
    // save or alter the federation list while it is about to
    // be saved.
    let mut federation_mutex = federation_storage.lock().await;

    // Get the current federations so that we can check if the new federation already exists
    let mut existing_federations = storage.get_federations()?;

    // Check if the federation already exists
    if existing_federations
        .federations
        .values()
        .any(|federation| federation.federation_code == federation_code)
    {
        return Err(MutinyError::InvalidArgumentsError);
    }

    // Create and save a new federation
    let next_federation_uuid = Uuid::new_v4().to_string();
    let next_federation = FederationIndex {
        federation_code: federation_code.clone(),
    };

    existing_federations.version += 1;
    existing_federations
        .federations
        .insert(next_federation_uuid.clone(), next_federation.clone());

    storage.insert_federations(existing_federations.clone())?;
    federation_mutex.federations = existing_federations.federations.clone();

    // now create the federation process and init it
    let new_federation = FederationClient::new(
        next_federation_uuid.clone(),
        &next_federation,
        federation_code,
        xprivkey,
        storage.clone(),
        g.clone(),
        network,
        logger.clone(),
        stop,
    )
    .await?;

    let federation_id = new_federation.fedimint_client.federation_id();
    federations
        .lock()
        .await
        .insert(federation_id, Arc::new(new_federation));

    Ok(FederationIdentity {
        uuid: next_federation_uuid.clone(),
        federation_id,
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        encrypt::encryption_key_from_pass, generate_seed, nodemanager::NodeManager, MutinyWallet,
        MutinyWalletConfig,
    };
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
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher), None);
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
            None,
            None,
            false,
            true,
        );
        let mw = MutinyWallet::new(storage.clone(), config, None)
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
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher), None);
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
            None,
            None,
            false,
            true,
        );
        let mut mw = MutinyWallet::new(storage.clone(), config, None)
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
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher), None);

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
            None,
            None,
            false,
            true,
        );
        let mut mw = MutinyWallet::new(storage.clone(), config, None)
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
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher), None);
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
            None,
            None,
            false,
            true,
        );
        let mw = MutinyWallet::new(storage.clone(), config, None)
            .await
            .expect("mutiny wallet should initialize");
        let seed = mw.node_manager.xprivkey;
        assert!(!seed.private_key.is_empty());

        // create a second mw and make sure it has a different seed
        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage2 = MemoryStorage::new(Some(pass), Some(cipher), None);
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
            None,
            None,
            false,
            true,
        );
        let mw2 = MutinyWallet::new(storage2.clone(), config2.clone(), None)
            .await
            .expect("mutiny wallet should initialize");
        let seed2 = mw2.node_manager.xprivkey;
        assert_ne!(seed, seed2);

        // now restore the first seed into the 2nd mutiny node
        mw2.stop().await.expect("should stop");
        drop(mw2);

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage3 = MemoryStorage::new(Some(pass), Some(cipher), None);
        MutinyWallet::restore_mnemonic(storage3.clone(), mnemonic.clone())
            .await
            .expect("mutiny wallet should restore");

        config2.xprivkey = {
            let seed = storage3.get_mnemonic().unwrap().unwrap();
            ExtendedPrivKey::new_master(Network::Regtest, &seed.to_seed("")).unwrap()
        };
        let mw2 = MutinyWallet::new(storage3, config2, None)
            .await
            .expect("mutiny wallet should initialize");
        let restored_seed = mw2.node_manager.xprivkey;
        assert_eq!(seed, restored_seed);
    }

    #[test]
    async fn create_mutiny_wallet_safe_mode() {
        let test_name = "create_mutiny_wallet";
        log!("{}", test_name);

        let mnemonic = generate_seed(12).unwrap();
        let xpriv = ExtendedPrivKey::new_master(Network::Regtest, &mnemonic.to_seed("")).unwrap();

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher), None);
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
            None,
            None,
            false,
            true,
        )
        .with_safe_mode();
        let mw = MutinyWallet::new(storage.clone(), config, None)
            .await
            .expect("mutiny wallet should initialize");
        mw.storage.insert_mnemonic(mnemonic).unwrap();
        assert!(NodeManager::has_node_manager(storage));

        let bip21 = mw.create_bip21(None, vec![]).await.unwrap();
        assert!(bip21.invoice.is_none());

        let new_node = mw.node_manager.new_node().await;
        assert!(new_node.is_err());
    }
}
