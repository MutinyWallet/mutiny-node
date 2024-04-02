use crate::labels::Contact;
use crate::logging::MutinyLogger;
use crate::nostr::nip49::{NIP49BudgetPeriod, NIP49URI};
use crate::nostr::nwc::{
    check_valid_nwc_invoice, BudgetPeriod, BudgetedSpendingConditions, NostrWalletConnect,
    NwcProfile, NwcProfileTag, PendingNwcInvoice, Profile, SingleUseSpendingConditions,
    SpendingConditions, PENDING_NWC_EVENTS_KEY,
};
use crate::nostr::primal::PrimalClient;
use crate::storage::{update_nostr_contact_list, MutinyStorage, NOSTR_CONTACT_LIST};
use crate::{error::MutinyError, utils::get_random_bip32_child_index};
use crate::{labels::LabelStorage, InvoiceHandler};
use crate::{utils, HTLCStatus};
use bitcoin::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Secp256k1, Signing};
use bitcoin::{hashes::hex::FromHex, secp256k1::ThirtyTwoByteHash, Network};
use fedimint_core::api::InviteCode;
use fedimint_core::config::FederationId;
use futures::{pin_mut, select, FutureExt};
use futures_util::lock::Mutex;
use lightning::util::logger::Logger;
use lightning::{log_debug, log_error, log_info, log_warn};
use lightning_invoice::Bolt11Invoice;
use lnurl::lnurl::LnUrl;
use nostr::nips::nip47::*;
use nostr::{
    nips::nip04::{decrypt, encrypt},
    Alphabet, Event, EventBuilder, EventId, Filter, JsonUtil, Keys, Kind, Metadata, SecretKey,
    SingleLetterTag, Tag, TagKind, Timestamp,
};
use nostr_sdk::{Client, NostrSigner, RelayPoolNotification};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{atomic::Ordering, Arc, RwLock};
use std::time::Duration;
use std::{str::FromStr, sync::atomic::AtomicBool};
use url::Url;

pub mod nip49;
pub mod nwc;
mod primal;

const PROFILE_ACCOUNT_INDEX: u32 = 0;
const NWC_ACCOUNT_INDEX: u32 = 1;
pub(crate) const SERVICE_ACCOUNT_INDEX: u32 = 2;

pub(crate) const HERMES_CHAIN_INDEX: u32 = 0;

const USER_NWC_PROFILE_START_INDEX: u32 = 1000;

/// The number of trusted users we query for mint recommendations
const NUM_TRUSTED_USERS: u32 = 1_000;

const NWC_STORAGE_KEY: &str = "nwc_profiles";

const DEFAULT_RELAY: &str = "wss://relay.mutinywallet.com";

/// Reserved profiles that are used internally.
/// Must not exceed `USER_NWC_PROFILE_START_INDEX`
pub enum ReservedProfile {
    MutinySubscription,
}

pub(crate) const MUTINY_PLUS_SUBSCRIPTION_LABEL: &str = "Mutiny+ Subscription";

impl ReservedProfile {
    pub fn info(&self) -> (&'static str, u32) {
        let (n, i) = match self {
            ReservedProfile::MutinySubscription => (MUTINY_PLUS_SUBSCRIPTION_LABEL, 0),
        };
        if i >= USER_NWC_PROFILE_START_INDEX {
            panic!("Must not exceed 1000 reserved indexes")
        };
        (n, i)
    }
}

pub enum ProfileType {
    Reserved(ReservedProfile),
    Normal { name: String },
}

#[derive(Debug, Clone)]
pub enum NostrKeySource {
    /// We derive the nostr key from our mutiny seed
    Derived,
    /// Import nsec from the user
    Imported(Keys),
    /// Get keys from NIP-07 extension
    #[cfg(target_arch = "wasm32")]
    Extension(nostr::PublicKey),
}

/// Manages Nostr keys and has different utilities for nostr specific things
#[derive(Clone)]
pub struct NostrManager<S: MutinyStorage> {
    /// Extended private key that is the root seed of the wallet
    xprivkey: ExtendedPrivKey,
    /// Primary key used for nostr, this will be used for signing events
    pub(crate) primary_key: NostrSigner,
    /// Primary key's public key
    pub public_key: nostr::PublicKey,
    /// Separate profiles for each nostr wallet connect string
    pub(crate) nwc: Arc<RwLock<Vec<NostrWalletConnect>>>,
    pub storage: S,
    /// Lock for pending nwc invoices
    pending_nwc_lock: Arc<Mutex<()>>,
    /// Lock for following and unfollowing npubs
    follow_lock: Arc<Mutex<()>>,
    /// Logger
    pub logger: Arc<MutinyLogger>,
    /// Atomic stop signal
    pub stop: Arc<AtomicBool>,
    /// Nostr client
    pub client: Client,
    /// Primal client
    pub primal_client: PrimalClient,
}

/// A fedimint we discovered on nostr
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrDiscoveredFedimint {
    /// Invite Code to join the federation
    pub invite_codes: Vec<InviteCode>,
    /// The federation id
    pub id: FederationId,
    /// Pubkey of the nostr event
    pub pubkey: Option<nostr::PublicKey>,
    /// Event id of the nostr event
    pub event_id: Option<EventId>,
    /// Date this fedimint was announced on nostr
    pub created_at: Option<u64>,
    /// Metadata about the fedimint
    pub metadata: Option<Metadata>,
    /// Contacts that recommend this fedimint
    pub recommendations: Vec<Contact>,
}

impl<S: MutinyStorage> NostrManager<S> {
    /// Connect to the nostr relays
    pub async fn connect(&self) -> Result<(), MutinyError> {
        self.client.add_relays(self.get_relays()).await?;
        self.client.connect().await;

        Ok(())
    }

    /// Export the primary key's secret key if available
    pub fn export_nsec(&self) -> Option<SecretKey> {
        match &self.primary_key {
            NostrSigner::Keys(keys) => keys.secret_key().ok().cloned(),
            #[cfg(target_arch = "wasm32")]
            NostrSigner::NIP07(_) => None,
        }
    }

    pub fn get_relays(&self) -> Vec<String> {
        let mut relays: Vec<String> = self
            .nwc
            .read()
            .unwrap()
            .iter()
            .filter(|x| x.profile.active())
            .map(|x| x.profile.relay.clone())
            .collect();

        // add relays to pull DMs from
        relays.push("wss://relay.primal.net".to_string());
        relays.push("wss://relay.damus.io".to_string());

        // add relays for default sending
        relays.push("wss://nostr.mutinywallet.com".to_string()); // blastr
        relays.push("wss://relay.mutinywallet.com".to_string()); // strfry

        // remove duplicates
        relays.sort();
        relays.dedup();

        relays
    }

    fn get_nwc_filters(&self) -> Result<Vec<Filter>, MutinyError> {
        // if we haven't synced before, use now and save to storage
        let time_stamp = match self.storage.get_nwc_sync_time()? {
            None => {
                let now = Timestamp::now();
                self.storage.set_nwc_sync_time(now.as_u64())?;
                now
            }
            Some(time) => Timestamp::from(time + 1), // add one so we get only new events
        };

        let vec = self
            .nwc
            .read()
            .unwrap()
            .iter()
            .filter(|x| x.profile.active())
            .map(|nwc| nwc.create_nwc_filter(time_stamp))
            .collect();

        Ok(vec)
    }

    /// Filters for getting DMs from our contacts
    fn get_dm_filter(&self) -> Result<Filter, MutinyError> {
        let contacts = self.storage.get_contacts()?;
        let last_sync_time = self.storage.get_dm_sync_time()?;
        let npubs: HashSet<nostr::PublicKey> =
            contacts.into_values().flat_map(|c| c.npub).collect();

        // if we haven't synced before, use now and save to storage
        let time_stamp = match last_sync_time {
            None => {
                let now = Timestamp::now();
                self.storage.set_dm_sync_time(now.as_u64())?;
                now
            }
            Some(time) => Timestamp::from(time + 1), // add one so we get only new events
        };

        let received_dm_filter = Filter::new()
            .kind(Kind::EncryptedDirectMessage)
            .authors(npubs)
            .pubkey(self.public_key)
            .since(time_stamp);

        Ok(received_dm_filter)
    }

    /// Filter for getting updates to our nostr contacts list
    fn get_contacts_list_filter(&self) -> Result<Filter, MutinyError> {
        let event = self.storage.get_data::<Event>(NOSTR_CONTACT_LIST)?;

        // listen for latest contact list events
        let time_stamp = match event {
            None => Timestamp::from(0),
            Some(event) => {
                if event.pubkey == self.public_key {
                    event.created_at + 1_i64 // add one so we get only new events
                } else {
                    Timestamp::from(0)
                }
            }
        };

        Ok(Filter::new()
            .kind(Kind::ContactList)
            .author(self.public_key)
            .since(time_stamp))
    }

    pub fn get_filters(&self) -> Result<Vec<Filter>, MutinyError> {
        let mut nwc = self.get_nwc_filters()?;
        let dm = self.get_dm_filter()?;
        let contacts_list = self.get_contacts_list_filter()?;
        nwc.extend([dm, contacts_list]);

        Ok(nwc)
    }

    /// Sets the user's nostr profile metadata
    pub async fn edit_profile(
        &self,
        name: Option<String>,
        img_url: Option<Url>,
        lnurl: Option<LnUrl>,
        nip05: Option<String>,
    ) -> Result<Metadata, MutinyError> {
        // pull latest profile from primal
        let current = match self.primal_client.get_user_profile(self.public_key).await {
            Ok(Some(meta)) => meta,
            Ok(None) => {
                log_warn!(self.logger, "No profile found for user, creating new");
                Metadata::default()
            }
            Err(e) => {
                // if we can't get the profile from primal, fall back to local
                // otherwise we can't create/edit profile if the primal server is down
                log_error!(
                    self.logger,
                    "Failed to get user profile from primal, falling back to local: {e}"
                );
                self.storage.get_nostr_profile()?.unwrap_or_default()
            }
        };

        let with_name = if let Some(name) = name {
            current.name(name)
        } else {
            current
        };
        let with_img = if let Some(img_url) = img_url {
            with_name.picture(img_url)
        } else {
            with_name
        };
        let with_lnurl = if let Some(lnurl) = lnurl {
            if let Some(ln_addr) = lnurl.lightning_address() {
                with_img.lud16(ln_addr.to_string())
            } else {
                with_img.lud06(lnurl.to_string())
            }
        } else {
            with_img
        };
        let with_nip05 = if let Some(nip05) = nip05 {
            with_lnurl.nip05(nip05)
        } else {
            with_lnurl
        };

        let event_id = self.client.set_metadata(&with_nip05).await?;
        log_info!(self.logger, "New kind 0: {event_id}");
        self.storage.set_nostr_profile(with_nip05.clone())?;

        Ok(with_nip05)
    }

    /// Sets the user's nostr profile metadata as deleted
    pub async fn delete_profile(&self) -> Result<Metadata, MutinyError> {
        let metadata = Metadata::default()
            .name("Deleted")
            .display_name("Deleted")
            .about("Deleted")
            .custom_field("deleted", true);

        let event_id = self.client.set_metadata(&metadata).await?;
        log_info!(self.logger, "New kind 0: {event_id}");
        self.storage.set_nostr_profile(metadata.clone())?;

        Ok(metadata)
    }

    pub fn get_profile(&self) -> Result<Metadata, MutinyError> {
        Ok(self.storage.get_nostr_profile()?.unwrap_or_default())
    }

    /// Follows the npub on nostr if we're not already following
    ///
    /// Returns true if we're now following, false if we were already following
    pub async fn follow_npub(&self, npub: nostr::PublicKey) -> Result<(), MutinyError> {
        let _lock = self.follow_lock.lock().await;
        let event = self.storage.get_data::<Event>(NOSTR_CONTACT_LIST)?;

        let builder = match event {
            Some(event) => {
                // if event is for a different key, we need to pull down latest
                let (mut tags, content) = if event.pubkey != self.public_key {
                    let (opt, _) = self
                        .primal_client
                        .get_nostr_contacts(self.public_key)
                        .await?;

                    // if key doesn't have a contact list, create a new one
                    match opt {
                        None => (vec![], String::new()),
                        Some(event) => {
                            let tags = event.tags.clone();
                            let content = event.content.clone();
                            (tags, content)
                        }
                    }
                } else {
                    (event.tags.clone(), event.content.clone())
                };

                // check if we're already following
                if tags.iter().any(|tag| {
                    matches!(tag, Tag::PublicKey { public_key, uppercase: false, .. } if *public_key == npub)
                }) {
                    return Ok(());
                }

                tags.push(Tag::public_key(npub));
                EventBuilder::new(Kind::ContactList, content, tags)
            }
            None => EventBuilder::new(Kind::ContactList, "", [Tag::public_key(npub)]),
        };

        let event = self.primary_key.sign_event_builder(builder).await?;
        let event_id = self.client.send_event(event.clone()).await?;

        update_nostr_contact_list(&self.storage, event)?;

        log_info!(
            self.logger,
            "Followed npub: {npub}, new contact list event: {event_id}"
        );

        Ok(())
    }

    /// Unfollows the npub on nostr if we're following them
    ///
    /// Returns true if we were following them before
    pub async fn unfollow_npub(&self, npub: nostr::PublicKey) -> Result<(), MutinyError> {
        let _lock = self.follow_lock.lock().await;
        let event = self.storage.get_data::<Event>(NOSTR_CONTACT_LIST)?;

        match event {
            None => Ok(()), // no follow list, nothing to unfollow
            Some(event) => {
                // if event is for a different key, we need to pull down latest
                let (mut tags, content) = if event.pubkey != self.public_key {
                    let (opt, _) = self
                        .primal_client
                        .get_nostr_contacts(self.public_key)
                        .await?;

                    // if key doesn't have a contact list, create a new one
                    match opt {
                        None => (vec![], String::new()),
                        Some(event) => {
                            let tags = event.tags.clone();
                            let content = event.content.clone();
                            (tags, content)
                        }
                    }
                } else {
                    (event.tags.clone(), event.content.clone())
                };

                tags.retain(|tag| {
                    !matches!(tag, Tag::PublicKey { public_key, uppercase: false, .. } if *public_key == npub)
                });

                // check if we actually removed a tag,
                // if not then we weren't following them
                if tags.len() == event.tags.len() {
                    return Ok(());
                }

                let builder = EventBuilder::new(Kind::ContactList, content, tags);
                let event = self.primary_key.sign_event_builder(builder).await?;
                let event_id = self.client.send_event(event.clone()).await?;

                update_nostr_contact_list(&self.storage, event)?;

                log_info!(
                    self.logger,
                    "Unfollowed npub: {npub}, new contact list event: {event_id}"
                );

                Ok(())
            }
        }
    }

    /// Gets the list of npubs we're following
    pub fn get_follow_list(&self) -> Result<HashSet<nostr::PublicKey>, MutinyError> {
        let event = self.storage.get_data::<Event>(NOSTR_CONTACT_LIST)?;

        match event {
            None => Ok(HashSet::new()),
            Some(event) => {
                let npubs = event
                    .into_iter_tags()
                    .filter_map(|tag| {
                        if let Tag::PublicKey {
                            public_key,
                            uppercase: false,
                            ..
                        } = tag
                        {
                            Some(public_key)
                        } else {
                            None
                        }
                    })
                    .collect();
                Ok(npubs)
            }
        }
    }

    pub fn get_nwc_uri(&self, index: u32) -> Result<Option<NostrWalletConnectURI>, MutinyError> {
        let opt = self
            .nwc
            .read()
            .unwrap()
            .iter()
            .find(|nwc| nwc.profile.index == index)
            .map(|nwc| nwc.get_nwc_uri());

        if let Some(uri) = opt {
            Ok(uri?)
        } else {
            Err(MutinyError::NotFound)
        }
    }

    pub fn profiles(&self) -> Vec<NwcProfile> {
        self.nwc
            .read()
            .unwrap()
            .iter()
            .filter(|x| x.profile.active())
            .map(|x| x.nwc_profile())
            .collect()
    }

    pub(crate) fn remove_inactive_profiles(&self) -> Result<(), MutinyError> {
        let mut profiles = self.nwc.write().unwrap();

        profiles.retain(|x| x.profile.active());

        // save to storage
        {
            let profiles = profiles
                .iter()
                .map(|x| x.profile.clone())
                .collect::<Vec<_>>();
            self.storage
                .set_data(NWC_STORAGE_KEY.to_string(), profiles, None)?;
        }

        Ok(())
    }

    /// Goes through all single use profiles and removes the successfully paid ones
    pub(crate) async fn clear_successful_single_use_profiles(
        &self,
        invoice_handler: &impl InvoiceHandler,
    ) -> Result<(), MutinyError> {
        // Go through all remaining Single Use NWC
        let indices_to_remove = {
            let profiles = self.nwc.write().unwrap();
            profiles
                .iter()
                .enumerate()
                .filter_map(|(index, x)| {
                    if let SpendingConditions::SingleUse(single_use) =
                        &x.profile.spending_conditions
                    {
                        if let Some(payment_hash) = &single_use.payment_hash {
                            match FromHex::from_hex(payment_hash) {
                                Ok(hash) => {
                                    let hash: [u8; 32] = hash;
                                    Some((index, hash))
                                }
                                Err(_) => None,
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        };

        // All futures to go check on the status of those single use NWC
        let futures: Vec<_> = indices_to_remove
            .into_iter()
            .map(|(index, hash)| async move {
                match invoice_handler
                    .lookup_payment(&hash)
                    .await
                    .map(|x| x.status)
                {
                    Some(HTLCStatus::Succeeded) => Some(index),
                    _ => None,
                }
            })
            .collect();

        let results = futures::future::join_all(futures).await;

        // Remove all of those NWC and then save
        {
            let mut profiles = self.nwc.write().unwrap();
            for index in results.into_iter().flatten().rev() {
                profiles.remove(index);
            }

            let profiles = profiles
                .iter()
                .map(|x| x.profile.clone())
                .collect::<Vec<_>>();
            self.storage
                .set_data(NWC_STORAGE_KEY.to_string(), profiles, None)?;
        }

        Ok(())
    }

    pub fn edit_nwc_profile(&self, profile: NwcProfile) -> Result<NwcProfile, MutinyError> {
        let mut profiles = self.nwc.write().unwrap();
        let index = profile.index;

        let nwc = profiles
            .iter_mut()
            .find(|nwc| nwc.profile.index == index)
            .ok_or(MutinyError::NotFound)?;

        nwc.profile = profile.profile();

        let nwc_profile = nwc.nwc_profile();

        // save to storage
        {
            let profiles = profiles
                .iter()
                .map(|x| x.profile.clone())
                .collect::<Vec<_>>();
            self.storage
                .set_data(NWC_STORAGE_KEY.to_string(), profiles, None)?;
        }

        Ok(nwc_profile)
    }

    pub fn set_nwc_profile_budget(
        &self,
        profile_index: u32,
        budget_sats: u64,
        budget_period: BudgetPeriod,
        single_max_sats: Option<u64>,
    ) -> Result<NwcProfile, MutinyError> {
        let mut profiles = self.nwc.write().unwrap();

        let nwc = profiles
            .iter_mut()
            .find(|nwc| nwc.profile.index == profile_index)
            .ok_or(MutinyError::NotFound)?;

        let payments = if let SpendingConditions::Budget(budget) = &nwc.profile.spending_conditions
        {
            budget.payments.clone()
        } else {
            vec![]
        };

        nwc.profile.spending_conditions = SpendingConditions::Budget(BudgetedSpendingConditions {
            budget: budget_sats,
            single_max: single_max_sats,
            payments,
            period: budget_period,
        });

        let nwc_profile = nwc.nwc_profile();

        // save to storage
        {
            let profiles = profiles
                .iter()
                .map(|x| x.profile.clone())
                .collect::<Vec<_>>();
            self.storage
                .set_data(NWC_STORAGE_KEY.to_string(), profiles, None)?;
        }

        Ok(nwc_profile)
    }

    pub fn get_nwc_profile(&self, index: u32) -> Result<NwcProfile, MutinyError> {
        let profiles = self.nwc.read().unwrap();

        let nwc = profiles
            .iter()
            .find(|nwc| nwc.profile.index == index)
            .ok_or(MutinyError::NotFound)?;

        Ok(nwc.nwc_profile())
    }

    pub(crate) fn nostr_wallet_auth(
        &self,
        profile_type: ProfileType,
        uri: NIP49URI,
        budget: Option<BudgetedSpendingConditions>,
        tag: NwcProfileTag,
        commands: Vec<Method>,
    ) -> Result<NwcProfile, MutinyError> {
        let spending_conditions = match uri.budget {
            None => match budget {
                None => SpendingConditions::RequireApproval,
                Some(budget) => SpendingConditions::Budget(budget),
            },
            Some(uri_budget) => {
                // make sure we don't have 2 budgets
                if budget.is_some() {
                    return Err(MutinyError::InvalidArgumentsError);
                }

                SpendingConditions::Budget(BudgetedSpendingConditions {
                    budget: uri_budget.amount,
                    single_max: None,
                    payments: vec![],
                    period: match uri_budget.time_period {
                        NIP49BudgetPeriod::Daily => BudgetPeriod::Day,
                        NIP49BudgetPeriod::Weekly => BudgetPeriod::Week,
                        NIP49BudgetPeriod::Monthly => BudgetPeriod::Month,
                        NIP49BudgetPeriod::Yearly => BudgetPeriod::Year,
                    },
                })
            }
        };

        let mut profiles = self.nwc.try_write()?;

        let (name, index, child_key_index) = get_next_nwc_index(profile_type, &profiles)?;

        let label = match uri.identity {
            Some(identity) => {
                let contacts = self.storage.get_contacts()?;
                contacts.into_iter().find_map(|(id, c)| {
                    if c.npub == Some(identity) {
                        Some(id)
                    } else {
                        None
                    }
                })
            }
            None => None,
        };

        let profile = Profile {
            name,
            index,
            client_key: Some(uri.public_key),
            child_key_index,
            relay: DEFAULT_RELAY.to_string(), // override with our relay
            enabled: None,
            archived: None,
            spending_conditions,
            commands: Some(commands),
            tag,
            label,
        };

        let nwc = NostrWalletConnect::new(&Secp256k1::new(), self.xprivkey, profile)?;

        profiles.push(nwc.clone());
        profiles.sort_by_key(|nwc| nwc.profile.index);

        // save to storage
        {
            let profiles = profiles
                .iter()
                .map(|x| x.profile.clone())
                .collect::<Vec<_>>();
            self.storage
                .set_data(NWC_STORAGE_KEY.to_string(), profiles, None)?;
        }

        Ok(nwc.nwc_profile())
    }

    /// Creates a new NWC profile and saves to storage
    pub(crate) fn create_new_nwc_profile_internal(
        &self,
        profile_type: ProfileType,
        spending_conditions: SpendingConditions,
        tag: NwcProfileTag,
        commands: Vec<Method>,
    ) -> Result<NwcProfile, MutinyError> {
        let mut profiles = self.nwc.try_write()?;

        let (name, index, child_key_index) = get_next_nwc_index(profile_type, &profiles)?;

        let profile = Profile {
            name,
            index,
            child_key_index,
            relay: DEFAULT_RELAY.to_string(),
            enabled: None,
            archived: None,
            spending_conditions,
            tag,
            client_key: None,
            label: None,
            commands: Some(commands),
        };
        let nwc = NostrWalletConnect::new(&Secp256k1::new(), self.xprivkey, profile)?;

        profiles.push(nwc.clone());
        profiles.sort_by_key(|nwc| nwc.profile.index);

        // save to storage
        {
            let profiles = profiles
                .iter()
                .map(|x| x.profile.clone())
                .collect::<Vec<_>>();
            self.storage
                .set_data(NWC_STORAGE_KEY.to_string(), profiles, None)?;
        }

        Ok(nwc.nwc_profile())
    }

    /// Creates a new NWC profile and saves to storage
    /// This will also broadcast the info event to the relay
    pub async fn create_new_nwc_profile(
        &self,
        profile_type: ProfileType,
        spending_conditions: SpendingConditions,
        tag: NwcProfileTag,
        commands: Vec<Method>,
    ) -> Result<NwcProfile, MutinyError> {
        let profile =
            self.create_new_nwc_profile_internal(profile_type, spending_conditions, tag, commands)?;
        // add relay if needed
        let needs_connect = self.client.add_relay(profile.relay.as_str()).await?;
        if needs_connect {
            self.client.connect_relay(profile.relay.as_str()).await?;
        }

        let info_event = self.nwc.read().unwrap().iter().find_map(|nwc| {
            if nwc.profile.index == profile.index {
                nwc.create_nwc_info_event().ok()
            } else {
                None
            }
        });

        if let Some(info_event) = info_event {
            self.client
                .send_event_to([profile.relay.as_str()], info_event)
                .await
                .map_err(|e| {
                    MutinyError::Other(anyhow::anyhow!("Failed to send info event: {e:?}"))
                })?;
        }

        Ok(profile)
    }

    pub async fn create_single_use_nwc(
        &self,
        name: String,
        amount_sats: u64,
    ) -> Result<NwcProfile, MutinyError> {
        let profile = ProfileType::Normal { name };

        let spending_conditions = SpendingConditions::SingleUse(SingleUseSpendingConditions {
            amount_sats,
            payment_hash: None,
        });
        self.create_new_nwc_profile(
            profile,
            spending_conditions,
            NwcProfileTag::Gift,
            vec![Method::PayInvoice], // gifting only needs pay invoice
        )
        .await
    }

    /// Approves a nostr wallet auth request.
    /// Creates a new NWC profile and saves to storage.
    /// This will also broadcast the info event to the relay.
    pub async fn approve_nostr_wallet_auth(
        &self,
        profile_type: ProfileType,
        uri: NIP49URI,
        budget: Option<BudgetedSpendingConditions>,
        tag: NwcProfileTag,
    ) -> Result<NwcProfile, MutinyError> {
        // for now approve all commands
        let mut commands = uri.required_commands.clone();
        commands.extend_from_slice(&uri.optional_commands);

        let secret = uri.secret.clone();
        let relay = uri.relay_url.clone();
        let profile = self.nostr_wallet_auth(profile_type, uri, budget, tag, commands.clone())?;

        let nwc = self.nwc.try_read()?.iter().find_map(|nwc| {
            if nwc.profile.index == profile.index {
                Some(nwc.clone())
            } else {
                None
            }
        });

        if let Some(nwc) = nwc {
            let client = Client::new(self.primary_key.clone());

            let mut relays = self.get_relays();
            relays.push(relay.to_string());
            relays.push(profile.relay.clone());
            client.add_relays(relays).await?;
            client.connect().await;

            if let Some(event) = nwc.create_auth_confirmation_event(relay, secret, commands)? {
                let id = client.send_event(event).await.map_err(|e| {
                    MutinyError::Other(anyhow::anyhow!(
                        "Failed to send nwa confirmation event: {e:?}"
                    ))
                })?;
                log_info!(self.logger, "Broadcast NWA confirmation event: {id}");
            }

            let info_event = nwc.create_nwc_info_event()?;
            let id = client.send_event(info_event).await.map_err(|e| {
                MutinyError::Other(anyhow::anyhow!("Failed to send info event: {e:?}"))
            })?;
            log_info!(self.logger, "Broadcast NWC info event: {id}");

            let _ = client.disconnect().await;
        } else {
            log_error!(self.logger, "Failed to create info & auth event");
            return Err(MutinyError::Other(anyhow::anyhow!(
                "Failed to create info & auth event"
            )));
        }

        Ok(profile)
    }

    /// Lists all pending NWC invoices
    pub fn get_pending_nwc_invoices(&self) -> Result<Vec<PendingNwcInvoice>, MutinyError> {
        Ok(self
            .storage
            .get_data(PENDING_NWC_EVENTS_KEY)?
            .unwrap_or_default())
    }

    fn find_nwc_data(
        &self,
        hash: &sha256::Hash,
    ) -> Result<(Option<NostrWalletConnect>, PendingNwcInvoice), MutinyError> {
        let pending: Vec<PendingNwcInvoice> = self
            .storage
            .get_data(PENDING_NWC_EVENTS_KEY)?
            .unwrap_or_default();

        let inv = pending
            .iter()
            .find(|x| x.invoice.payment_hash() == hash)
            .ok_or(MutinyError::NotFound)?;

        let nwc = inv
            .index
            .map(|index| {
                let profiles = self.nwc.read().unwrap();
                profiles
                    .iter()
                    .find(|x| x.profile.index == index)
                    .ok_or(MutinyError::NotFound)
                    .cloned()
            })
            .transpose()?;

        Ok((nwc, inv.to_owned()))
    }

    async fn broadcast_nwc_response(
        &self,
        resp: Response,
        nwc: NostrWalletConnect,
        inv: PendingNwcInvoice,
    ) -> Result<EventId, MutinyError> {
        let encrypted = encrypt(
            nwc.server_key.secret_key().unwrap(),
            &nwc.client_pubkey(),
            resp.as_json(),
        )
        .unwrap();

        let p_tag = Tag::public_key(inv.pubkey);
        let e_tag = Tag::event(inv.event_id);
        let tags = match inv.identifier {
            Some(id) => vec![p_tag, e_tag, Tag::Identifier(id)],
            None => vec![p_tag, e_tag],
        };

        let response = EventBuilder::new(Kind::WalletConnectResponse, encrypted, tags)
            .to_event(&nwc.server_key)
            .map_err(|e| MutinyError::Other(anyhow::anyhow!("Failed to create event: {e:?}")))?;

        let event_id = self
            .client
            .send_event_to([nwc.profile.relay.as_str()], response)
            .await
            .map_err(|e| MutinyError::Other(anyhow::anyhow!("Failed to send info event: {e:?}")))?;

        Ok(event_id)
    }

    /// Removes an invoice from the pending list
    pub(crate) async fn remove_pending_nwc_invoice(
        &self,
        hash: &sha256::Hash,
    ) -> Result<(), MutinyError> {
        // get lock for writing
        self.pending_nwc_lock.lock().await;

        let mut pending: Vec<PendingNwcInvoice> = self
            .storage
            .get_data(PENDING_NWC_EVENTS_KEY)?
            .unwrap_or_default();

        let original_len = pending.len();

        // remove from storage
        pending.retain(|x| x.invoice.payment_hash() != hash);

        // if we didn't remove anything, we don't need to save
        if original_len == pending.len() {
            return Ok(());
        }

        self.storage
            .set_data(PENDING_NWC_EVENTS_KEY.to_string(), pending, None)?;

        Ok(())
    }

    /// Approves an invoice and sends the payment
    pub async fn approve_invoice(
        &self,
        hash: sha256::Hash,
        invoice_handler: &impl InvoiceHandler,
    ) -> Result<Option<EventId>, MutinyError> {
        let (nwc, inv) = self.find_nwc_data(&hash)?;

        let event_id = match nwc {
            Some(nwc) => {
                let resp = nwc.pay_nwc_invoice(invoice_handler, &inv.invoice).await?;
                Some(self.broadcast_nwc_response(resp, nwc, inv).await?)
            }
            None => {
                // handle dm invoice

                // find contact, tag invoice with id
                let contacts = self.storage.get_contacts()?;
                let label = contacts
                    .into_iter()
                    .find(|(_, c)| c.npub == Some(inv.pubkey))
                    .map(|(id, _)| vec![id])
                    .unwrap_or_default();
                if let Err(e) = invoice_handler.pay_invoice(&inv.invoice, None, label).await {
                    log_error!(invoice_handler.logger(), "failed to pay invoice: {e}");
                    return Err(e);
                }

                None
            }
        };

        // remove from our pending list
        self.remove_pending_nwc_invoice(&hash).await?;

        Ok(event_id)
    }

    /// Removes an invoice from the pending list, will also remove expired invoices
    pub async fn deny_invoice(&self, hash: sha256::Hash) -> Result<(), MutinyError> {
        // need to tell relay to remove the invoice
        // doesn't work in test environment
        #[cfg(not(test))]
        {
            let resp = Response {
                result_type: Method::PayInvoice,
                error: Some(NIP47Error {
                    code: ErrorCode::Other,
                    message: "Rejected".to_string(),
                }),
                result: None,
            };
            let (nwc, inv) = self.find_nwc_data(&hash)?;
            if let Some(nwc) = nwc {
                self.broadcast_nwc_response(resp, nwc, inv).await?;
            }
        }

        // wait for lock
        self.pending_nwc_lock.lock().await;

        let mut invoices: Vec<PendingNwcInvoice> = self
            .storage
            .get_data(PENDING_NWC_EVENTS_KEY)?
            .unwrap_or_default();

        // remove expired invoices
        invoices.retain(|x| !x.is_expired());

        // remove the invoice
        invoices.retain(|x| x.invoice.payment_hash() != &hash);

        self.storage
            .set_data(PENDING_NWC_EVENTS_KEY.to_string(), invoices, None)?;

        Ok(())
    }

    /// Removes all invoices from the pending list
    pub async fn deny_all_pending_nwc(&self) -> Result<(), MutinyError> {
        // wait for lock
        self.pending_nwc_lock.lock().await;

        // need to tell relay to remove the invoice
        // doesn't work in test environment
        #[cfg(not(test))]
        {
            let invoices: Vec<PendingNwcInvoice> = self
                .storage
                .get_data(PENDING_NWC_EVENTS_KEY)?
                .unwrap_or_default();

            for invoice in invoices {
                let resp = Response {
                    result_type: Method::PayInvoice,
                    error: Some(NIP47Error {
                        code: ErrorCode::Other,
                        message: "Rejected".to_string(),
                    }),
                    result: None,
                };
                let (nwc, inv) = self.find_nwc_data(invoice.invoice.payment_hash())?;

                if let Some(nwc) = nwc {
                    let encrypted = encrypt(
                        nwc.server_key.secret_key().unwrap(),
                        &nwc.client_pubkey(),
                        resp.as_json(),
                    )
                    .unwrap();

                    let p_tag = Tag::public_key(inv.pubkey);
                    let e_tag = Tag::event(inv.event_id);
                    let response =
                        EventBuilder::new(Kind::WalletConnectResponse, encrypted, [p_tag, e_tag])
                            .to_event(&nwc.server_key)
                            .map_err(|e| {
                                MutinyError::Other(anyhow::anyhow!("Failed to create event: {e:?}"))
                            })?;

                    self.client.send_event(response).await.map_err(|e| {
                        MutinyError::Other(anyhow::anyhow!("Failed to send info event: {e:?}"))
                    })?;
                }
            }
        }

        // need to define the type here, otherwise it will be ambiguous
        let empty: Vec<PendingNwcInvoice> = vec![];
        self.storage
            .set_data(PENDING_NWC_EVENTS_KEY.to_string(), empty, None)?;

        Ok(())
    }

    /// Goes through all pending NWC invoices and removes invoices that are
    /// expired or have been paid
    pub async fn clear_invalid_nwc_invoices(
        &self,
        invoice_handler: &impl InvoiceHandler,
    ) -> Result<(), MutinyError> {
        self.pending_nwc_lock.lock().await;
        let invoices: Vec<PendingNwcInvoice> = self
            .storage
            .get_data(PENDING_NWC_EVENTS_KEY)?
            .unwrap_or_default();

        let mut new_invoices = Vec::with_capacity(invoices.len());

        for inv in invoices {
            // remove expired invoices
            if inv.is_expired() {
                continue;
            }

            // remove paid invoices
            if invoice_handler
                .lookup_payment(&inv.invoice.payment_hash().into_32())
                .await
                .is_some_and(|p| p.status == HTLCStatus::Succeeded)
            {
                continue;
            }

            // keep the invoice if it is still valid
            new_invoices.push(inv);
        }

        // sort and dedup
        new_invoices.sort();
        new_invoices.dedup();

        self.storage
            .set_data(PENDING_NWC_EVENTS_KEY.to_string(), new_invoices, None)?;

        Ok(())
    }

    /// Handles an encrypted direct message. If it is an invoice we add it to our pending
    /// invoice storage.
    pub async fn handle_direct_message(
        &self,
        event: Event,
        invoice_handler: &impl InvoiceHandler,
    ) -> anyhow::Result<()> {
        if event.kind != Kind::EncryptedDirectMessage {
            anyhow::bail!("Not a direct message");
        } else if event.pubkey == self.public_key {
            return Ok(()); // don't process our own messages
        }

        log_debug!(self.logger, "processing dm: {}", event.id);

        // update sync time
        self.storage.set_dm_sync_time(event.created_at.as_u64())?;

        let decrypted = self.decrypt_dm(event.pubkey, &event.content).await?;

        // handle it like a pay invoice NWC request, to see if it is valid
        let params = PayInvoiceRequestParams {
            id: None,
            invoice: decrypted,
            amount: None,
        };
        let invoice: Bolt11Invoice = match check_valid_nwc_invoice(&params, invoice_handler).await {
            Ok(Some(invoice)) => invoice,
            Ok(None) => return Ok(()),
            Err(msg) => {
                log_debug!(self.logger, "Not adding DM'd invoice: {msg}");
                return Ok(());
            }
        };

        self.save_pending_nwc_invoice(None, event.id, event.pubkey, invoice, None)
            .await?;

        Ok(())
    }

    pub(crate) async fn save_pending_nwc_invoice(
        &self,
        profile_index: Option<u32>,
        event_id: EventId,
        event_pk: nostr::PublicKey,
        invoice: Bolt11Invoice,
        identifier: Option<String>,
    ) -> anyhow::Result<()> {
        let pending = PendingNwcInvoice {
            index: profile_index,
            invoice,
            event_id,
            pubkey: event_pk,
            identifier,
        };
        self.pending_nwc_lock.lock().await;

        let mut current: Vec<PendingNwcInvoice> = self
            .storage
            .get_data(PENDING_NWC_EVENTS_KEY)?
            .unwrap_or_default();

        if !current.contains(&pending) {
            current.push(pending);

            self.storage
                .set_data(PENDING_NWC_EVENTS_KEY.to_string(), current, None)?;
        }

        Ok(())
    }

    pub async fn handle_nwc_request(
        &self,
        event: Event,
        invoice_handler: &impl InvoiceHandler,
    ) -> anyhow::Result<Option<Event>> {
        let nwc = {
            let vec = self.nwc.read().unwrap();
            vec.iter()
                .find(|nwc| nwc.client_pubkey() == event.pubkey)
                .cloned()
        };

        self.storage.set_nwc_sync_time(event.created_at.as_u64())?;

        if let Some(mut nwc) = nwc {
            let event = nwc.handle_nwc_request(event, invoice_handler, self).await?;
            Ok(event)
        } else {
            Ok(None)
        }
    }

    pub(crate) fn save_nwc_profile(&self, nwc: NostrWalletConnect) -> Result<(), MutinyError> {
        let mut vec = self.nwc.write().unwrap();

        // update the profile
        for item in vec.iter_mut() {
            if item.profile.index == nwc.profile.index {
                item.profile = nwc.profile;
                break;
            }
        }

        let profiles = vec.iter().map(|x| x.profile.clone()).collect::<Vec<_>>();

        self.storage
            .set_data(NWC_STORAGE_KEY.to_string(), profiles, None)?;

        Ok(())
    }

    pub fn delete_nwc_profile(&self, index: u32) -> Result<(), MutinyError> {
        let mut vec = self.nwc.write().unwrap();

        // update the profile
        vec.retain(|x| x.profile.index != index);

        let profiles = vec.iter().map(|x| x.profile.clone()).collect::<Vec<_>>();

        self.storage
            .set_data(NWC_STORAGE_KEY.to_string(), profiles, None)?;

        Ok(())
    }

    pub async fn claim_single_use_nwc(
        &self,
        amount_sats: u64,
        nwc_uri: &str,
        invoice_handler: &impl InvoiceHandler,
    ) -> Result<Option<NIP47Error>, MutinyError> {
        let nwc = NostrWalletConnectURI::from_str(nwc_uri)
            .map_err(|_| MutinyError::InvalidArgumentsError)?;
        let secret = Keys::new(nwc.secret.clone());
        let client = Client::new(&secret);

        client
            .add_relay(nwc.relay_url.as_str())
            .await
            .expect("Failed to add relays");
        client.connect().await;

        let invoice = invoice_handler
            .create_invoice(amount_sats, vec!["Gift".to_string()])
            .await?;
        // unwrap is safe, we just created it
        let bolt11 = invoice.bolt11.unwrap();

        let req = Request {
            method: Method::PayInvoice,
            params: RequestParams::PayInvoice(PayInvoiceRequestParams {
                id: None,
                invoice: bolt11.to_string(),
                amount: None,
            }),
        };
        let encrypted = encrypt(&nwc.secret, &nwc.public_key, req.as_json())?;
        let p_tag = Tag::public_key(nwc.public_key);
        let request_event =
            EventBuilder::new(Kind::WalletConnectRequest, encrypted, [p_tag]).to_event(&secret)?;

        let filter = Filter::new()
            .kind(Kind::WalletConnectResponse)
            .author(nwc.public_key)
            .pubkey(secret.public_key())
            .event(request_event.id);

        client.subscribe(vec![filter], None).await;

        client
            .send_event(request_event.clone())
            .await
            .map_err(|e| {
                MutinyError::Other(anyhow::anyhow!("Failed to send request event: {e:?}"))
            })?;

        let mut notifications = client.notifications();

        let start_time = utils::now();

        // every second, check for response event, invoice paid, or timeout
        loop {
            let now = utils::now();
            if now - start_time > Duration::from_secs(30) {
                client.disconnect().await?;
                return Err(MutinyError::PaymentTimeout);
            }

            // check if the invoice has been paid, if so, return, otherwise continue
            // checking for response event
            if let Some(inv) = invoice_handler
                .lookup_payment(&bolt11.payment_hash().into_32())
                .await
            {
                if inv.status == HTLCStatus::Succeeded {
                    break;
                }
            }

            let read_fut = notifications.recv().fuse();
            let delay_fut = Box::pin(utils::sleep(1_000)).fuse();

            pin_mut!(read_fut, delay_fut);
            select! {
                notification = read_fut => {
                    match notification {
                        Ok(RelayPoolNotification::Event { event, .. }) => {
                            let has_e_tag = event.tags.iter().any(|x| {
                                if let Tag::Event { event_id: id, .. } = x {
                                    *id == request_event.id
                                } else {
                                        false
                                }
                            });
                            if has_e_tag && event.kind == Kind::WalletConnectResponse && event.verify().is_ok() {
                                let decrypted = decrypt(&nwc.secret, &nwc.public_key, &event.content)?;
                                let resp: Response = serde_json::from_str(&decrypted)?;

                                if resp.result_type == Method::PayInvoice {
                                    client.disconnect().await?;

                                    match resp.result {
                                        Some(ResponseResult::PayInvoice(params)) => {
                                            let preimage: Vec<u8> = FromHex::from_hex(&params.preimage)?;
                                            if sha256::Hash::hash(&preimage) != invoice.payment_hash {
                                                log_warn!(self.logger, "Received payment preimage that does not represent the invoice hash");
                                            }
                                            return Ok(None);
                                        },
                                        Some(_) => unreachable!("Should not receive any other response type"),
                                        None => return Ok(resp.error),
                                    }
                                }
                            }
                        },
                        Ok(RelayPoolNotification::Message { .. }) => {}, // ignore messages
                        Ok(RelayPoolNotification::Stop) => {}, // ignore stops
                        Ok(RelayPoolNotification::RelayStatus { .. }) => {}, // ignore status updates
                        Ok(RelayPoolNotification::Shutdown) =>
                            return Err(MutinyError::ConnectionFailed),
                        Err(_) => return Err(MutinyError::ConnectionFailed),
                    }
                }
                _ = delay_fut => {
                    if self.stop.load(Ordering::Relaxed) {
                        client.disconnect().await?;
                        return Err(MutinyError::NotRunning);
                    }
                }
            }
        }

        client.disconnect().await?;

        Ok(None)
    }

    /// Decrypts a DM using the primary key
    pub async fn decrypt_dm(
        &self,
        pubkey: nostr::PublicKey,
        message: &str,
    ) -> Result<String, MutinyError> {
        // todo we should handle NIP-44 as well
        match &self.primary_key {
            NostrSigner::Keys(key) => {
                let secret = key.secret_key().expect("must have");
                let decrypted = decrypt(secret, &pubkey, message)?;
                Ok(decrypted)
            }
            #[cfg(target_arch = "wasm32")]
            NostrSigner::NIP07(nip07) => {
                let decrypted = nip07.nip04_decrypt(pubkey, message).await?;
                Ok(decrypted)
            }
        }
    }

    pub async fn send_dm(
        &self,
        pubkey: nostr::PublicKey,
        message: String,
    ) -> Result<EventId, MutinyError> {
        let event_id = self.client.send_direct_msg(pubkey, message, None).await?;
        Ok(event_id)
    }

    /// Creates a recommendation event for a federation
    pub async fn recommend_federation(
        &self,
        invite_code: &InviteCode,
        network: Network,
        review: Option<&str>,
    ) -> Result<EventId, MutinyError> {
        let kind = Kind::from(38000);

        // properly tag the event as a federation with the federation id
        let d_tag = Tag::Identifier(invite_code.federation_id().to_string());
        let k_tag = Tag::Generic(
            TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::K)),
            vec!["38173".to_string()],
        );

        // tag the network
        let n_tag = Tag::Generic(
            TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::N)),
            vec![network_to_string(network).to_string()],
        );

        // tag the federation invite code
        let invite_code_tag = Tag::Generic(
            TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::U)),
            vec![invite_code.to_string()],
        );

        // todo tag the federation announcement event, to do so we need to have the pubkey of the federation

        let builder = EventBuilder::new(
            kind,
            review.unwrap_or_default(),
            [d_tag, k_tag, invite_code_tag, n_tag],
        );

        // send the event
        Ok(self.client.send_event_builder(builder).await?)
    }

    /// Checks if we have recommended the given federation
    pub async fn has_recommended_federation(
        &self,
        federation_id: &FederationId,
    ) -> Result<bool, MutinyError> {
        let filter = Filter::new()
            .author(self.public_key)
            .identifier(federation_id.to_string())
            .limit(1);

        let events = self.client.get_events_of(vec![filter], None).await?;

        Ok(!events.is_empty())
    }

    /// Queries our relays for federation announcements
    pub async fn discover_federations(
        &self,
        network: Network,
    ) -> Result<Vec<NostrDiscoveredFedimint>, MutinyError> {
        // get contacts by npub
        let npubs: HashMap<nostr::PublicKey, Contact> = self
            .storage
            .get_contacts()?
            .into_iter()
            .filter_map(|(_, c)| c.npub.map(|npub| (npub, c)))
            .collect();

        // our contacts might not have recommendation events, so pull in trusted users as well
        let primal_trusted_users: HashMap<nostr::PublicKey, Contact> = match self
            .primal_client
            .get_trusted_users(NUM_TRUSTED_USERS)
            .await
        {
            Ok(trusted) => {
                trusted
                    .into_iter()
                    .flat_map(|user| {
                        // skip if we already have this contact
                        if npubs.contains_key(&user.pubkey) {
                            return None;
                        }
                        // create a dummy contact from the metadata if available
                        let dummy_contact = match user.metadata {
                            Some(metadata) => Contact::create_from_metadata(user.pubkey, metadata),
                            None => Contact {
                                npub: Some(user.pubkey),
                                ..Default::default()
                            },
                        };
                        Some((user.pubkey, dummy_contact))
                    })
                    .collect()
            }
            Err(e) => {
                // if we fail to get trusted users, log the error and continue
                // we don't want to fail the entire function because of this
                // we'll just have less recommendations
                log_error!(self.logger, "Failed to get trusted users: {e}");
                HashMap::new()
            }
        };

        let network_str = network_to_string(network);

        // filter for finding mint announcements
        let mints = Filter::new().kind(Kind::from(38173));
        // filter for finding federation recommendations from contacts
        let contacts_recommendations = Filter::new()
            .kind(Kind::from(38000))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::K), ["38173"])
            .authors(npubs.keys().copied());
        // filter for finding federation recommendations from trusted people
        let trusted_recommendations = Filter::new()
            .kind(Kind::from(38000))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::K), ["38173"])
            .authors(primal_trusted_users.keys().copied());
        // filter for finding federation recommendations from random people
        let recommendations = Filter::new()
            .kind(Kind::from(38000))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::K), ["38173"])
            .limit(NUM_TRUSTED_USERS as usize);

        // fetch events
        let events = self
            .client
            .get_events_of(
                vec![
                    mints,
                    contacts_recommendations,
                    trusted_recommendations,
                    recommendations,
                ],
                Some(Duration::from_secs(5)),
            )
            .await?;

        let mut mints: Vec<NostrDiscoveredFedimint> = events
            .iter()
            .filter_map(|event| {
                // only process federation announcements
                if event.kind != Kind::from(38173) {
                    return None;
                }

                let network_tag = event.tags.iter().find_map(|tag| {
                    if tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::N))
                    {
                        Some(tag.as_vec().get(1).cloned().unwrap_or_default())
                    } else {
                        None
                    }
                });

                // if the network tag is missing, we assume it is on mainnet
                let network_tag = network_tag
                    .as_deref()
                    .unwrap_or(network_to_string(Network::Bitcoin));
                // skip if the network doesn't match
                if network_tag != network_str {
                    return None;
                }

                let federation_id = event.tags.iter().find_map(|tag| {
                    if let Tag::Identifier(id) = tag {
                        FederationId::from_str(id).ok()
                    } else {
                        None
                    }
                })?;

                let invite_codes: Vec<InviteCode> = event
                    .tags
                    .iter()
                    .filter_map(|tag| parse_invite_code_from_tag(tag, &federation_id))
                    .collect();

                // if we have no invite codes left, skip
                if invite_codes.is_empty() {
                    None
                } else {
                    // try to parse the metadata if available, it's okay if it fails
                    // todo could lookup kind 0 of the federation to get the metadata as well
                    let metadata = serde_json::from_str(&event.content).ok();
                    Some(NostrDiscoveredFedimint {
                        invite_codes,
                        id: federation_id,
                        pubkey: Some(event.pubkey),
                        event_id: Some(event.id),
                        created_at: Some(event.created_at.as_u64()),
                        metadata,
                        recommendations: vec![], // we'll add these in the next step
                    })
                }
            })
            .collect();

        // remove duplicates by federation id, keep the one with the newest event
        mints.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        mints.dedup_by(|a, b| a.id == b.id);

        // add on contact recommendations to mints
        for event in events {
            // only process federation recommendations
            if event.kind != Kind::from(38000)
                || !event.tags.iter().any(|tag| {
                    tag.kind() == TagKind::Custom("k".to_string())
                        && tag.as_vec().get(1).is_some_and(|x| x == "38173")
                })
            {
                continue;
            }

            // try to get the contact from our npubs, otherwise use the primal trusted users
            let contact = match npubs.get(&event.pubkey) {
                Some(contact) => contact.clone(),
                None => match primal_trusted_users.get(&event.pubkey).cloned() {
                    Some(contact) => contact,
                    None => {
                        // if we don't have the contact, skip
                        // this could be a spam account that we shouldn't trust
                        continue;
                    }
                },
            };

            let network_tag = event.tags.iter().find_map(|tag| {
                if tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::N)) {
                    Some(tag.as_vec().get(1).cloned().unwrap_or_default())
                } else {
                    None
                }
            });

            // if the network tag is missing, we assume it is on mainnet
            let network_tag = network_tag
                .as_deref()
                .unwrap_or(network_to_string(Network::Bitcoin));
            // skip if the network doesn't match
            if network_tag != network_str {
                continue;
            }

            let federation_id = event.tags.iter().find_map(|tag| {
                if let Tag::Identifier(id) = tag {
                    FederationId::from_str(id).ok()
                } else {
                    None
                }
            });

            // if we don't have the federation id, skip
            let federation_id = match federation_id {
                Some(id) => id,
                None => continue,
            };

            let invite_codes = event
                .tags
                .iter()
                .filter_map(|tag| parse_invite_code_from_tag(tag, &federation_id))
                .collect::<Vec<_>>();

            // todo read `a` tag recommendations as well

            match mints.iter_mut().find(|m| m.id == federation_id) {
                Some(mint) => {
                    mint.recommendations.push(contact);
                }
                None => {
                    // if we don't have the mint announcement
                    // Add to list with the contact as the recommendation
                    // Only if we have invite codes
                    if !invite_codes.is_empty() {
                        let mint = NostrDiscoveredFedimint {
                            invite_codes,
                            id: federation_id,
                            pubkey: None,
                            event_id: None,
                            created_at: None,
                            metadata: None,
                            recommendations: vec![contact],
                        };
                        mints.push(mint);
                    }
                }
            }
        }

        // sort the recommendations by whether they are contacts or not and if they have an image
        for mint in mints.iter_mut() {
            mint.recommendations.sort_by(|a, b| {
                let a_is_contact = a
                    .npub
                    .map(|npub| npubs.contains_key(&npub))
                    .unwrap_or(false);
                let b_is_contact = b
                    .npub
                    .map(|npub| npubs.contains_key(&npub))
                    .unwrap_or(false);

                if a_is_contact && !b_is_contact {
                    std::cmp::Ordering::Less
                } else if !a_is_contact && b_is_contact {
                    std::cmp::Ordering::Greater
                } else {
                    let a_has_image = a.image_url.is_some();
                    let b_has_image = b.image_url.is_some();
                    if a_has_image && !b_has_image {
                        std::cmp::Ordering::Less
                    } else if !a_has_image && b_has_image {
                        std::cmp::Ordering::Greater
                    } else {
                        // finally sort by npub if all else is equal
                        a.npub.cmp(&b.npub)
                    }
                }
            });
            mint.recommendations.dedup_by(|a, b| a.npub == b.npub);
        }

        // sort mints by most recommended
        mints.sort_by(|a, b| b.recommendations.len().cmp(&a.recommendations.len()));

        Ok(mints)
    }

    /// Derives the client and server keys for Nostr Wallet Connect given a profile index
    /// The left key is the client key and the right key is the server key
    pub(crate) fn derive_nwc_keys<C: Signing>(
        context: &Secp256k1<C>,
        xprivkey: ExtendedPrivKey,
        profile_index: u32,
    ) -> Result<(Keys, Keys), MutinyError> {
        let client_key = derive_nostr_key(
            context,
            xprivkey,
            NWC_ACCOUNT_INDEX,
            Some(profile_index),
            Some(0),
        )?;
        let server_key = derive_nostr_key(
            context,
            xprivkey,
            NWC_ACCOUNT_INDEX,
            Some(profile_index),
            Some(1),
        )?;

        Ok((client_key, server_key))
    }

    /// Creates a new NostrManager
    pub fn from_mnemonic(
        xprivkey: ExtendedPrivKey,
        key_source: NostrKeySource,
        storage: S,
        primal_url: Option<String>,
        logger: Arc<MutinyLogger>,
        stop: Arc<AtomicBool>,
    ) -> Result<Self, MutinyError> {
        let context = Secp256k1::new();

        // use provided nsec, otherwise generate it from seed
        let (primary_key, public_key) = match key_source {
            NostrKeySource::Derived => {
                let keys = derive_nostr_key(&context, xprivkey, PROFILE_ACCOUNT_INDEX, None, None)?;
                let public_key = keys.public_key();
                let signer = NostrSigner::Keys(keys);
                (signer, public_key)
            }
            NostrKeySource::Imported(keys) => {
                let public_key = keys.public_key();
                let signer = NostrSigner::Keys(keys);
                (signer, public_key)
            }
            #[cfg(target_arch = "wasm32")]
            NostrKeySource::Extension(public_key) => {
                let nip07 = nostr::prelude::Nip07Signer::new()?;
                let signer = NostrSigner::NIP07(nip07);
                (signer, public_key)
            }
        };

        // get from storage
        let profiles: Vec<Profile> = storage.get_data(NWC_STORAGE_KEY)?.unwrap_or_default();

        // generate the wallet connect keys
        let nwc = profiles
            .into_iter()
            .map(|profile| NostrWalletConnect::new(&context, xprivkey, profile).unwrap())
            .collect();

        let client = Client::new(primary_key.clone());

        let primal_client = PrimalClient::new(
            primal_url.unwrap_or("https://primal-cache.mutinywallet.com/api".to_string()),
        );

        Ok(Self {
            xprivkey,
            primary_key,
            public_key,
            nwc: Arc::new(RwLock::new(nwc)),
            storage,
            pending_nwc_lock: Arc::new(Mutex::new(())),
            follow_lock: Arc::new(Mutex::new(())),
            primal_client,
            logger,
            stop,
            client,
        })
    }
}

pub fn derive_nostr_key<C: Signing>(
    context: &Secp256k1<C>,
    xprivkey: ExtendedPrivKey,
    account: u32,
    chain: Option<u32>,
    index: Option<u32>,
) -> Result<Keys, MutinyError> {
    let chain = match chain {
        Some(chain) => ChildNumber::from_hardened_idx(chain)?,
        None => ChildNumber::from_normal_idx(0)?,
    };

    let index = match index {
        Some(index) => ChildNumber::from_hardened_idx(index)?,
        None => ChildNumber::from_normal_idx(0)?,
    };

    let path = DerivationPath::from_str(&format!("m/44'/1237'/{account}'/{chain}/{index}"))?;
    let key = xprivkey.derive_priv(context, &path)?;
    Ok(Keys::new(key.private_key.into()))
}

fn get_next_nwc_index(
    profile_type: ProfileType,
    profiles: &[NostrWalletConnect],
) -> Result<(String, u32, Option<u32>), MutinyError> {
    let (name, index, child_key_index) = match profile_type {
        ProfileType::Reserved(reserved_profile) => {
            let (name, index) = reserved_profile.info();
            (name.to_string(), index, None)
        }
        // Ensure normal profiles start from 1000
        ProfileType::Normal { name } => {
            let next_index = profiles
                .iter()
                .filter(|&nwc| nwc.profile.index >= USER_NWC_PROFILE_START_INDEX)
                .max_by(|a, b| a.profile.index.cmp(&b.profile.index))
                .map(|nwc| nwc.profile.index + 1)
                .unwrap_or(USER_NWC_PROFILE_START_INDEX);

            debug_assert!(next_index >= USER_NWC_PROFILE_START_INDEX);

            (name, next_index, Some(get_random_bip32_child_index()))
        }
    };

    Ok((name, index, child_key_index))
}

fn network_to_string(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "mainnet",
        Network::Testnet => "testnet",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
        net => unreachable!("Unknown network {net}!"),
    }
}

fn parse_invite_code_from_tag(
    tag: &Tag,
    expected_federation_id: &FederationId,
) -> Option<InviteCode> {
    let code = if let Tag::AbsoluteURL(code) = tag {
        InviteCode::from_str(&code.to_string()).ok()
    } else {
        // tag might have `fedimint` element, try to parse that as well
        let vec = tag.as_vec();
        if vec.len() == 3 && vec[0] == "u" && vec[2] == "fedimint" {
            InviteCode::from_str(&vec[1]).ok()
        } else {
            None
        }
    };

    // remove any invite codes that point to different federation
    code.filter(|c| c.federation_id() == *expected_federation_id)
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod test {
    use super::*;
    use crate::storage::MemoryStorage;
    use crate::utils::now;
    use crate::MockInvoiceHandler;
    use bip39::Mnemonic;
    use bitcoin::bip32::ExtendedPrivKey;
    use bitcoin::Network;
    use futures::executor::block_on;
    use lightning::ln::PaymentSecret;
    use lightning_invoice::{Bolt11Invoice, Currency, InvoiceBuilder};
    use mockall::predicate::eq;
    use std::str::FromStr;

    const EXPIRED_INVOICE: &str = "lnbc923720n1pj9nr6zpp5xmvlq2u5253htn52mflh2e6gn7pk5ht0d4qyhc62fadytccxw7hqhp5l4s6qwh57a7cwr7zrcz706qx0qy4eykcpr8m8dwz08hqf362egfscqzzsxqzfvsp5pr7yjvcn4ggrf6fq090zey0yvf8nqvdh2kq7fue0s0gnm69evy6s9qyyssqjyq0fwjr22eeg08xvmz88307yqu8tqqdjpycmermks822fpqyxgshj8hvnl9mkh6srclnxx0uf4ugfq43d66ak3rrz4dqcqd23vxwpsqf7dmhm";

    fn create_nostr_manager() -> NostrManager<MemoryStorage> {
        let mnemonic = Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").expect("could not generate");

        let xprivkey =
            ExtendedPrivKey::new_master(Network::Bitcoin, &mnemonic.to_seed("")).unwrap();

        let storage = MemoryStorage::new(None, None, None);

        let logger = Arc::new(MutinyLogger::default());

        let stop = Arc::new(AtomicBool::new(false));

        NostrManager::from_mnemonic(
            xprivkey,
            NostrKeySource::Derived,
            storage,
            None,
            logger,
            stop,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_process_dm() {
        let nostr_manager = create_nostr_manager();

        let mut inv_handler = MockInvoiceHandler::new();
        inv_handler
            .expect_logger()
            .return_const(MutinyLogger::default());
        inv_handler.expect_skip_hodl_invoices().return_const(true);

        #[allow(irrefutable_let_patterns)] // need this because enum with single variant
        let nostr_keys = if let NostrSigner::Keys(ref keys) = nostr_manager.primary_key {
            keys.clone()
        } else {
            panic!("unexpected keys")
        };
        let user = Keys::generate();

        // make sure non-invoice is not added
        let dm = EventBuilder::encrypted_direct_msg(
            &user,
            nostr_manager.public_key,
            "not an invoice",
            None,
        )
        .unwrap()
        .to_event(&user)
        .unwrap();
        block_on(nostr_manager.handle_direct_message(dm, &inv_handler)).unwrap();
        let pending = nostr_manager.get_pending_nwc_invoices().unwrap();
        assert!(pending.is_empty());

        // make sure expired invoice is not added
        let dm = EventBuilder::encrypted_direct_msg(
            &user,
            nostr_manager.public_key,
            EXPIRED_INVOICE,
            None,
        )
        .unwrap()
        .to_event(&user)
        .unwrap();
        let pending = nostr_manager.get_pending_nwc_invoices().unwrap();
        assert!(pending.is_empty());
        block_on(nostr_manager.handle_direct_message(dm, &inv_handler)).unwrap();

        // create invoice
        let secp = Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[2; 32]).unwrap();
        let invoice = InvoiceBuilder::new(Currency::Regtest)
            .description("Dummy invoice".to_string())
            .duration_since_epoch(now())
            .payment_hash(sha256::Hash::all_zeros())
            .payment_secret(PaymentSecret([0; 32]))
            .min_final_cltv_expiry_delta(144)
            .amount_milli_satoshis(69_000)
            .build_signed(|hash| secp.sign_ecdsa_recoverable(hash, &sk))
            .unwrap();

        // add handling for mock
        inv_handler
            .expect_lookup_payment()
            .with(eq(invoice.payment_hash().into_32()))
            .returning(move |_| None);

        // make sure our own dms don't get added
        let dm = EventBuilder::encrypted_direct_msg(
            &nostr_keys,
            user.public_key(),
            invoice.to_string(),
            None,
        )
        .unwrap()
        .to_event(&nostr_keys)
        .unwrap();
        block_on(nostr_manager.handle_direct_message(dm, &inv_handler)).unwrap();
        let pending = nostr_manager.get_pending_nwc_invoices().unwrap();
        assert!(pending.is_empty());

        // valid invoice dm should be added
        let dm = EventBuilder::encrypted_direct_msg(
            &user,
            nostr_manager.public_key,
            invoice.to_string(),
            None,
        )
        .unwrap()
        .to_event(&user)
        .unwrap();
        block_on(nostr_manager.handle_direct_message(dm, &inv_handler)).unwrap();
        let pending = nostr_manager.get_pending_nwc_invoices().unwrap();
        assert!(!pending.is_empty())
    }

    #[tokio::test]
    async fn test_create_profile() {
        let nostr_manager = create_nostr_manager();

        let name = "test".to_string();

        let profile = nostr_manager
            .create_new_nwc_profile_internal(
                ProfileType::Normal { name: name.clone() },
                SpendingConditions::default(),
                Default::default(),
                vec![Method::PayInvoice],
            )
            .unwrap();

        assert_eq!(profile.name, name);
        assert_eq!(profile.index, 1000);
        assert!(profile.client_key.is_none());
        assert!(profile.nwc_uri.is_some());

        let nwc =
            NostrWalletConnect::new(&Secp256k1::new(), nostr_manager.xprivkey, profile.profile())
                .unwrap();

        assert!(nwc.client_key.secret_key().is_ok());

        let profiles = nostr_manager.profiles();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, name);
        assert_eq!(profiles[0].index, 1000);
        assert!(profiles[0].client_key.is_none());
        assert!(profiles[0].nwc_uri.is_some());

        let profiles: Vec<Profile> = nostr_manager
            .storage
            .get_data(NWC_STORAGE_KEY)
            .unwrap()
            .unwrap_or_default();

        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, name);
        assert_eq!(profiles[0].index, 1000);
    }

    #[tokio::test]
    async fn test_create_reserve_profile() {
        let nostr_manager = create_nostr_manager();

        let name = MUTINY_PLUS_SUBSCRIPTION_LABEL.to_string();

        let profile = nostr_manager
            .create_new_nwc_profile_internal(
                ProfileType::Reserved(ReservedProfile::MutinySubscription),
                SpendingConditions::default(),
                Default::default(),
                vec![Method::PayInvoice],
            )
            .unwrap();

        assert_eq!(profile.name, name);
        assert_eq!(profile.index, 0);
        assert!(profile.client_key.is_none());
        assert!(profile.nwc_uri.is_some());

        let profiles = nostr_manager.profiles();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, name);
        assert_eq!(profiles[0].index, 0);
        assert!(profiles[0].client_key.is_none());
        assert!(profiles[0].nwc_uri.is_some());

        let profiles: Vec<Profile> = nostr_manager
            .storage
            .get_data(NWC_STORAGE_KEY)
            .unwrap()
            .unwrap_or_default();

        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, name);
        assert_eq!(profiles[0].index, 0);

        // now create normal profile
        let name = "test".to_string();

        let profile = nostr_manager
            .create_new_nwc_profile_internal(
                ProfileType::Normal { name: name.clone() },
                SpendingConditions::default(),
                Default::default(),
                vec![Method::PayInvoice],
            )
            .unwrap();

        assert_eq!(profile.name, name);
        assert_eq!(profile.index, 1000);
        assert!(profile.child_key_index.is_some());

        // create a non child_key_index profile
        let non_child_key_index_profile = Profile {
            name,
            index: 1001,
            client_key: None,
            relay: DEFAULT_RELAY.to_string(),
            enabled: None,
            archived: None,
            child_key_index: None,
            spending_conditions: Default::default(),
            commands: None,
            tag: Default::default(),
            label: None,
        };
        let mut profiles = nostr_manager.nwc.write().unwrap();
        let nwc = NostrWalletConnect::new(
            &Secp256k1::new(),
            nostr_manager.xprivkey,
            non_child_key_index_profile,
        )
        .unwrap();
        let original_nwc_uri = nwc.get_nwc_uri().unwrap();
        profiles.push(nwc);
        profiles.sort_by_key(|nwc| nwc.profile.index);
        {
            let profiles = profiles
                .iter()
                .map(|x| x.profile.clone())
                .collect::<Vec<_>>();
            nostr_manager
                .storage
                .set_data(NWC_STORAGE_KEY.to_string(), profiles, None)
                .unwrap();
        }
        // now read it and make sure the NWC URI is still correct
        let profiles: Vec<Profile> = nostr_manager
            .storage
            .get_data(NWC_STORAGE_KEY)
            .unwrap()
            .unwrap_or_default();
        let mut new_profile = profiles[2].clone();
        let new_nwc = NostrWalletConnect::new(
            &Secp256k1::new(),
            nostr_manager.xprivkey,
            new_profile.clone(),
        )
        .unwrap();

        assert_eq!(new_profile.clone().index, 1001);
        assert!(new_profile.child_key_index.is_none());
        assert_eq!(original_nwc_uri, new_nwc.get_nwc_uri().unwrap());

        // if we change the index then it should change the private key/nwc
        new_profile.index = 1002;
        let changed_nwc = NostrWalletConnect::new(
            &Secp256k1::new(),
            nostr_manager.xprivkey,
            new_profile.clone(),
        )
        .unwrap();
        assert_ne!(original_nwc_uri, changed_nwc.get_nwc_uri().unwrap());
    }

    #[tokio::test]
    async fn test_create_nwa_profile() {
        let nostr_manager = create_nostr_manager();

        let name = "test nwa".to_string();

        let uri = NIP49URI::from_str("nostr+walletauth://6670c389b3c4797c410866fe0996074df5f7b3ae45b8fafeac91db5717f82ba2?relay=wss%3A%2F%2Frelay.damus.io%2F&secret=6889ab8537b5a400&required_commands=pay_invoice&identity=71bfa9cbf84110de617e959021b08c69524fcaa1033ffd062abd0ae2657ba24c").unwrap();

        let profile = nostr_manager
            .nostr_wallet_auth(
                ProfileType::Normal { name: name.clone() },
                uri.clone(),
                None,
                Default::default(),
                vec![Method::PayInvoice],
            )
            .unwrap();

        assert_eq!(profile.name, name);
        assert_eq!(profile.index, 1000);
        assert_eq!(profile.client_key, Some(uri.public_key));
        assert_eq!(
            profile.spending_conditions,
            SpendingConditions::RequireApproval
        );
        assert!(profile.nwc_uri.is_none());

        let nwc =
            NostrWalletConnect::new(&Secp256k1::new(), nostr_manager.xprivkey, profile.profile())
                .unwrap();

        assert_eq!(nwc.client_pubkey().to_string(), uri.public_key.to_string());
        assert!(nwc.client_key.secret_key().is_err());

        let profiles = nostr_manager.profiles();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, name);
        assert_eq!(profiles[0].index, 1000);
        assert_eq!(profiles[0].client_key, Some(uri.public_key));
        assert!(profiles[0].nwc_uri.is_none());

        let profiles: Vec<Profile> = nostr_manager
            .storage
            .get_data(NWC_STORAGE_KEY)
            .unwrap()
            .unwrap_or_default();

        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, name);
        assert_eq!(profiles[0].index, 1000);
        assert_eq!(profiles[0].client_key, Some(uri.public_key));
    }

    #[tokio::test]
    async fn test_edit_profile() {
        let nostr_manager = create_nostr_manager();

        let name = "test".to_string();

        let mut profile = nostr_manager
            .create_new_nwc_profile_internal(
                ProfileType::Normal { name: name.clone() },
                SpendingConditions::default(),
                Default::default(),
                vec![Method::PayInvoice],
            )
            .unwrap();

        assert_eq!(profile.name, name);
        assert_eq!(profile.index, 1000);
        assert_eq!(profile.relay.as_str(), DEFAULT_RELAY);

        profile.relay = "wss://relay.damus.io".to_string();

        nostr_manager.edit_nwc_profile(profile).unwrap();

        let profiles = nostr_manager.profiles();
        assert_eq!(profiles.len(), 1);
        // check this stuff is the same
        assert_eq!(profiles[0].name, name);
        assert_eq!(profiles[0].index, 1000);
        // check this is different
        assert_eq!(profiles[0].relay.as_str(), "wss://relay.damus.io");

        let profiles: Vec<Profile> = nostr_manager
            .storage
            .get_data(NWC_STORAGE_KEY)
            .unwrap()
            .unwrap_or_default();

        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, name);
        assert_eq!(profiles[0].index, 1000);
    }

    #[tokio::test]
    async fn test_delete_profile() {
        let nostr_manager = create_nostr_manager();

        let name = "test".to_string();

        let profile = nostr_manager
            .create_new_nwc_profile_internal(
                ProfileType::Normal { name: name.clone() },
                SpendingConditions::default(),
                Default::default(),
                vec![Method::PayInvoice],
            )
            .unwrap();

        assert_eq!(profile.name, name);
        assert_eq!(profile.index, 1000);
        assert_eq!(profile.relay.as_str(), DEFAULT_RELAY);

        nostr_manager.delete_nwc_profile(profile.index).unwrap();

        let profiles = nostr_manager.profiles();
        assert_eq!(profiles.len(), 0);

        let profiles: Vec<Profile> = nostr_manager
            .storage
            .get_data(NWC_STORAGE_KEY)
            .unwrap()
            .unwrap_or_default();

        assert_eq!(profiles.len(), 0);
    }

    #[tokio::test]
    async fn test_deny_invoice() {
        let nostr_manager = create_nostr_manager();

        let name = "test".to_string();

        let profile = nostr_manager
            .create_new_nwc_profile_internal(
                ProfileType::Normal { name },
                SpendingConditions::default(),
                Default::default(),
                vec![Method::PayInvoice],
            )
            .unwrap();

        let inv = PendingNwcInvoice {
			index: Some(profile.index),
			invoice: Bolt11Invoice::from_str("lnbc923720n1pj9nrefpp5pczykgk37af5388n8dzynljpkzs7sje4melqgazlwv9y3apay8jqhp5rd8saxz3juve3eejq7z5fjttxmpaq88d7l92xv34n4h3mq6kwq2qcqzzsxqzfvsp5z0jwpehkuz9f2kv96h62p8x30nku76aj8yddpcust7g8ad0tr52q9qyyssqfy622q25helv8cj8hyxqltws4rdwz0xx2hw0uh575mn7a76cp3q4jcptmtjkjs4a34dqqxn8uy70d0qlxqleezv4zp84uk30pp5q3nqq4c9gkz").unwrap(),
			event_id: EventId::from_slice(&[0; 32]).unwrap(),
			pubkey: nostr::PublicKey::from_str("552a9d06810f306bfc085cb1e1c26102554138a51fa3a7fdf98f5b03a945143a").unwrap(),
			identifier: None,
		};

        // add dummy to storage
        nostr_manager
            .storage
            .set_data(PENDING_NWC_EVENTS_KEY.to_string(), vec![inv.clone()], None)
            .unwrap();

        let pending = nostr_manager.get_pending_nwc_invoices().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].invoice, inv.invoice);

        block_on(nostr_manager.deny_invoice(inv.invoice.payment_hash().to_owned())).unwrap();

        let pending = nostr_manager.get_pending_nwc_invoices().unwrap();
        assert_eq!(pending.len(), 0);
    }
}
