use crate::logging::MutinyLogger;
use crate::nostr::nip49::{NIP49BudgetPeriod, NIP49URI};
use crate::nostr::nwc::{
    check_valid_nwc_invoice, BudgetPeriod, BudgetedSpendingConditions, NostrWalletConnect,
    NwcProfile, NwcProfileTag, PendingNwcInvoice, Profile, SingleUseSpendingConditions,
    SpendingConditions, PENDING_NWC_EVENTS_KEY,
};
use crate::storage::MutinyStorage;
use crate::{error::MutinyError, utils::get_random_bip32_child_index};
use crate::{labels::LabelStorage, InvoiceHandler};
use crate::{utils, HTLCStatus};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Secp256k1, Signing};
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey};
use bitcoin::{
    hashes::hex::{FromHex, ToHex},
    secp256k1::ThirtyTwoByteHash,
};
use futures::{pin_mut, select, FutureExt};
use futures_util::lock::Mutex;
use lightning::util::logger::Logger;
use lightning::{log_debug, log_error, log_warn};
use lightning_invoice::Bolt11Invoice;
use nostr::key::{SecretKey, XOnlyPublicKey};
use nostr::nips::nip47::*;
use nostr::prelude::{decrypt, encrypt};
use nostr::{Event, EventBuilder, EventId, Filter, JsonUtil, Keys, Kind, Tag, Timestamp};
use nostr_sdk::{Client, ClientSigner, RelayPoolNotification};
use std::collections::HashSet;
use std::sync::{atomic::Ordering, Arc, RwLock};
use std::time::Duration;
use std::{str::FromStr, sync::atomic::AtomicBool};

pub mod nip49;
pub mod nwc;

const PROFILE_ACCOUNT_INDEX: u32 = 0;
const NWC_ACCOUNT_INDEX: u32 = 1;

const USER_NWC_PROFILE_START_INDEX: u32 = 1000;

const NWC_STORAGE_KEY: &str = "nwc_profiles";

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
    Extension(XOnlyPublicKey),
}

/// Manages Nostr keys and has different utilities for nostr specific things
#[derive(Clone)]
pub struct NostrManager<S: MutinyStorage> {
    /// Extended private key that is the root seed of the wallet
    xprivkey: ExtendedPrivKey,
    /// Primary key used for nostr, this will be used for signing events
    pub(crate) primary_key: ClientSigner,
    /// Primary key's public key
    pub public_key: XOnlyPublicKey,
    /// Separate profiles for each nostr wallet connect string
    pub(crate) nwc: Arc<RwLock<Vec<NostrWalletConnect>>>,
    pub storage: S,
    /// Lock for pending nwc invoices
    pending_nwc_lock: Arc<Mutex<()>>,
    /// Logger
    pub logger: Arc<MutinyLogger>,
    /// Atomic stop signal
    pub stop: Arc<AtomicBool>,
    /// Nostr client
    pub client: Client,
}

impl<S: MutinyStorage> NostrManager<S> {
    /// Connect to the nostr relays
    pub async fn connect(&self) -> Result<(), MutinyError> {
        self.client.add_relays(self.get_relays()).await?;
        self.client.connect().await;

        Ok(())
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

        // add blastr for default sending
        relays.push("wss://nostr.mutinywallet.com".to_string());

        // remove duplicates
        relays.sort();
        relays.dedup();

        relays
    }

    fn get_nwc_filters(&self) -> Vec<Filter> {
        self.nwc
            .read()
            .unwrap()
            .iter()
            .filter(|x| x.profile.active())
            .map(|nwc| nwc.create_nwc_filter())
            .collect()
    }

    /// Filters for getting DMs from our contacts
    fn get_dm_filter(&self) -> Result<Filter, MutinyError> {
        let contacts = self.storage.get_contacts()?;
        let last_sync_time = self.storage.get_dm_sync_time()?;
        let npubs: HashSet<XOnlyPublicKey> = contacts.into_values().flat_map(|c| c.npub).collect();

        // if we haven't synced before, use now and save to storage
        let time_stamp = match last_sync_time {
            None => {
                let now = Timestamp::now();
                self.storage.set_dm_sync_time(now.as_u64())?;
                now
            }
            Some(time) => Timestamp::from(time),
        };

        let received_dm_filter = Filter::new()
            .kind(Kind::EncryptedDirectMessage)
            .authors(npubs)
            .pubkey(self.public_key)
            .since(time_stamp);

        Ok(received_dm_filter)
    }

    pub fn get_filters(&self) -> Result<Vec<Filter>, MutinyError> {
        let mut nwc = self.get_nwc_filters();
        let dm = self.get_dm_filter()?;
        nwc.push(dm);

        Ok(nwc)
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
                match invoice_handler.get_outbound_payment_status(&hash).await {
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

    pub fn edit_profile(&self, profile: NwcProfile) -> Result<NwcProfile, MutinyError> {
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

    pub fn get_profile(&self, index: u32) -> Result<NwcProfile, MutinyError> {
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
                    // compare by to_hex because of different types across rust-bitcoin versions
                    if c.npub.map(|x| x.to_hex()) == Some(identity.to_hex()) {
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
            relay: "wss://nostr.mutinywallet.com".to_string(), // override with our relay
            enabled: None,
            archived: None,
            spending_conditions,
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
    pub(crate) fn create_new_profile(
        &self,
        profile_type: ProfileType,
        spending_conditions: SpendingConditions,
        tag: NwcProfileTag,
    ) -> Result<NwcProfile, MutinyError> {
        let mut profiles = self.nwc.try_write()?;

        let (name, index, child_key_index) = get_next_nwc_index(profile_type, &profiles)?;

        let profile = Profile {
            name,
            index,
            child_key_index,
            relay: "wss://nostr.mutinywallet.com".to_string(),
            enabled: None,
            archived: None,
            spending_conditions,
            tag,
            client_key: None,
            label: None,
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
    ) -> Result<NwcProfile, MutinyError> {
        let profile = self.create_new_profile(profile_type, spending_conditions, tag)?;
        // add relay if needed
        self.client.add_relay(profile.relay.as_str()).await?;

        let info_event = self.nwc.read().unwrap().iter().find_map(|nwc| {
            if nwc.profile.index == profile.index {
                nwc.create_nwc_info_event().ok()
            } else {
                None
            }
        });

        if let Some(info_event) = info_event {
            self.client
                .send_event_to(profile.relay.as_str(), info_event)
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
        self.create_new_nwc_profile(profile, spending_conditions, NwcProfileTag::Gift)
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
        let relay = uri.relay_url.to_string();
        let profile = self.nostr_wallet_auth(profile_type, uri, budget, tag)?;

        let nwc = self.nwc.try_read()?.iter().find_map(|nwc| {
            if nwc.profile.index == profile.index {
                Some(nwc.clone())
            } else {
                None
            }
        });

        if let Some(nwc) = nwc {
            let client = Client::new(self.primary_key.clone());

            client
                .add_relays(vec![relay, profile.relay.to_string()])
                .await
                .expect("Failed to add relays");
            client.connect().await;

            if let Some(event) = nwc.create_auth_confirmation_event(secret, commands)? {
                client.send_event(event).await.map_err(|e| {
                    MutinyError::Other(anyhow::anyhow!("Failed to send info event: {e:?}"))
                })?;
            }

            let info_event = nwc.create_nwc_info_event()?;
            client.send_event(info_event).await.map_err(|e| {
                MutinyError::Other(anyhow::anyhow!("Failed to send info event: {e:?}"))
            })?;

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
            &nwc.server_key.secret_key().unwrap(),
            &nwc.client_pubkey(),
            resp.as_json(),
        )
        .unwrap();

        let p_tag = Tag::PublicKey {
            public_key: inv.pubkey,
            relay_url: None,
            alias: None,
            uppercase: false,
        };
        let e_tag = Tag::Event {
            event_id: inv.event_id,
            relay_url: None,
            marker: None,
        };
        let response = EventBuilder::new(Kind::WalletConnectResponse, encrypted, [p_tag, e_tag])
            .to_event(&nwc.server_key)
            .map_err(|e| MutinyError::Other(anyhow::anyhow!("Failed to create event: {e:?}")))?;

        let event_id = self
            .client
            .send_event_to(nwc.profile.relay.as_str(), response)
            .await
            .map_err(|e| MutinyError::Other(anyhow::anyhow!("Failed to send info event: {e:?}")))?;

        Ok(event_id)
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

        // get lock for writing
        self.pending_nwc_lock.lock().await;

        // get from storage again, in case it was updated
        let mut pending: Vec<PendingNwcInvoice> = self
            .storage
            .get_data(PENDING_NWC_EVENTS_KEY)?
            .unwrap_or_default();

        // remove from storage
        pending.retain(|x| x.invoice.payment_hash() != &hash);
        self.storage
            .set_data(PENDING_NWC_EVENTS_KEY.to_string(), pending, None)?;

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
                        &nwc.server_key.secret_key().unwrap(),
                        &nwc.client_pubkey(),
                        resp.as_json(),
                    )
                    .unwrap();

                    let p_tag = Tag::PublicKey {
                        public_key: inv.pubkey,
                        relay_url: None,
                        alias: None,
                        uppercase: false,
                    };
                    let e_tag = Tag::Event {
                        event_id: inv.event_id,
                        relay_url: None,
                        marker: None,
                    };
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

    /// Goes through all pending NWC invoices and removes the expired ones
    pub async fn clear_expired_nwc_invoices(&self) -> Result<(), MutinyError> {
        self.pending_nwc_lock.lock().await;
        let mut invoices: Vec<PendingNwcInvoice> = self
            .storage
            .get_data(PENDING_NWC_EVENTS_KEY)?
            .unwrap_or_default();

        // remove expired invoices
        invoices.retain(|x| !x.is_expired());

        // sort and dedup
        invoices.sort();
        invoices.dedup();

        self.storage
            .set_data(PENDING_NWC_EVENTS_KEY.to_string(), invoices, None)?;

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

        let invoice: Bolt11Invoice =
            match check_valid_nwc_invoice(&decrypted, invoice_handler).await {
                Ok(Some(invoice)) => invoice,
                Ok(None) => return Ok(()),
                Err(msg) => {
                    log_debug!(self.logger, "Not adding DM'd invoice: {msg}");
                    return Ok(());
                }
            };

        self.save_pending_nwc_invoice(None, event.id, event.pubkey, invoice)
            .await?;

        Ok(())
    }

    pub(crate) async fn save_pending_nwc_invoice(
        &self,
        profile_index: Option<u32>,
        event_id: EventId,
        event_pk: XOnlyPublicKey,
        invoice: Bolt11Invoice,
    ) -> anyhow::Result<()> {
        let pending = PendingNwcInvoice {
            index: profile_index,
            invoice,
            event_id,
            pubkey: event_pk,
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
        let secret = Keys::new(nwc.secret);
        let client = Client::new(&secret);

        client
            .add_relay(nwc.relay_url.as_str())
            .await
            .expect("Failed to add relays");
        client.connect().await;

        let invoice = invoice_handler
            .create_invoice(Some(amount_sats), vec!["Gift".to_string()])
            .await?;
        // unwrap is safe, we just created it
        let bolt11 = invoice.bolt11.unwrap();

        let req = Request {
            method: Method::PayInvoice,
            params: RequestParams::PayInvoice(PayInvoiceRequestParams {
                invoice: bolt11.to_string(),
            }),
        };
        let encrypted = encrypt(&nwc.secret, &nwc.public_key, req.as_json())?;
        let p_tag = Tag::PublicKey {
            public_key: nwc.public_key,
            relay_url: None,
            alias: None,
            uppercase: false,
        };
        let request_event =
            EventBuilder::new(Kind::WalletConnectRequest, encrypted, [p_tag]).to_event(&secret)?;

        let filter = Filter::new()
            .kind(Kind::WalletConnectResponse)
            .author(nwc.public_key)
            .pubkey(secret.public_key())
            .event(request_event.id);

        client.subscribe(vec![filter]).await;

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
            if let Some(status) = invoice_handler
                .get_outbound_payment_status(&bolt11.payment_hash().into_32())
                .await
            {
                if status == HTLCStatus::Succeeded {
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
        pubkey: XOnlyPublicKey,
        message: &str,
    ) -> Result<String, MutinyError> {
        // todo we should handle NIP-44 as well
        match &self.primary_key {
            ClientSigner::Keys(key) => {
                let secret = key.secret_key().expect("must have");
                let decrypted = decrypt(&secret, &pubkey, message)?;
                Ok(decrypted)
            }
            #[cfg(target_arch = "wasm32")]
            ClientSigner::NIP07(nip07) => {
                let decrypted = nip07.nip04_decrypt(pubkey, message).await?;
                Ok(decrypted)
            }
        }
    }

    /// Derives the client and server keys for Nostr Wallet Connect given a profile index
    /// The left key is the client key and the right key is the server key
    pub(crate) fn derive_nwc_keys<C: Signing>(
        context: &Secp256k1<C>,
        xprivkey: ExtendedPrivKey,
        profile_index: u32,
    ) -> Result<(Keys, Keys), MutinyError> {
        let client_key = Self::derive_nostr_key(
            context,
            xprivkey,
            NWC_ACCOUNT_INDEX,
            Some(profile_index),
            Some(0),
        )?;
        let server_key = Self::derive_nostr_key(
            context,
            xprivkey,
            NWC_ACCOUNT_INDEX,
            Some(profile_index),
            Some(1),
        )?;

        Ok((client_key, server_key))
    }

    fn derive_nostr_key<C: Signing>(
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

        // just converting to nostr secret key, unwrap is safe
        let secret_key = SecretKey::from_slice(&key.private_key.secret_bytes()).unwrap();
        Ok(Keys::new(secret_key))
    }

    /// Creates a new NostrManager
    pub fn from_mnemonic(
        xprivkey: ExtendedPrivKey,
        key_source: NostrKeySource,
        storage: S,
        logger: Arc<MutinyLogger>,
        stop: Arc<AtomicBool>,
    ) -> Result<Self, MutinyError> {
        let context = Secp256k1::new();

        // use provided nsec, otherwise generate it from seed
        let (primary_key, public_key) = match key_source {
            NostrKeySource::Derived => {
                let keys =
                    Self::derive_nostr_key(&context, xprivkey, PROFILE_ACCOUNT_INDEX, None, None)?;
                let public_key = keys.public_key();
                let signer = ClientSigner::Keys(keys);
                (signer, public_key)
            }
            NostrKeySource::Imported(keys) => {
                let public_key = keys.public_key();
                let signer = ClientSigner::Keys(keys);
                (signer, public_key)
            }
            #[cfg(target_arch = "wasm32")]
            NostrKeySource::Extension(public_key) => {
                let nip07 = nostr::prelude::Nip07Signer::new()?;
                let signer = ClientSigner::NIP07(nip07);
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

        Ok(Self {
            xprivkey,
            primary_key,
            public_key,
            nwc: Arc::new(RwLock::new(nwc)),
            storage,
            pending_nwc_lock: Arc::new(Mutex::new(())),
            logger,
            stop,
            client,
        })
    }
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

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod test {
    use super::*;
    use crate::storage::MemoryStorage;
    use crate::utils::now;
    use crate::MockInvoiceHandler;
    use bip39::Mnemonic;
    use bitcoin::util::bip32::ExtendedPrivKey;
    use bitcoin::Network;
    use futures::executor::block_on;
    use lightning::ln::PaymentSecret;
    use lightning_invoice::{Bolt11Invoice, Currency, InvoiceBuilder};
    use mockall::predicate::eq;
    use nostr::key::XOnlyPublicKey;
    use std::str::FromStr;

    const EXPIRED_INVOICE: &str = "lnbc923720n1pj9nr6zpp5xmvlq2u5253htn52mflh2e6gn7pk5ht0d4qyhc62fadytccxw7hqhp5l4s6qwh57a7cwr7zrcz706qx0qy4eykcpr8m8dwz08hqf362egfscqzzsxqzfvsp5pr7yjvcn4ggrf6fq090zey0yvf8nqvdh2kq7fue0s0gnm69evy6s9qyyssqjyq0fwjr22eeg08xvmz88307yqu8tqqdjpycmermks822fpqyxgshj8hvnl9mkh6srclnxx0uf4ugfq43d66ak3rrz4dqcqd23vxwpsqf7dmhm";

    fn create_nostr_manager() -> NostrManager<MemoryStorage> {
        let mnemonic = Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").expect("could not generate");

        let xprivkey =
            ExtendedPrivKey::new_master(Network::Bitcoin, &mnemonic.to_seed("")).unwrap();

        let storage = MemoryStorage::new(None, None, None);

        let logger = Arc::new(MutinyLogger::default());

        let stop = Arc::new(AtomicBool::new(false));

        NostrManager::from_mnemonic(xprivkey, NostrKeySource::Derived, storage, logger, stop)
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
        let nostr_keys = if let ClientSigner::Keys(ref keys) = nostr_manager.primary_key {
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
            .expect_get_outbound_payment_status()
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
            .create_new_profile(
                ProfileType::Normal { name: name.clone() },
                SpendingConditions::default(),
                Default::default(),
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
            .create_new_profile(
                ProfileType::Reserved(ReservedProfile::MutinySubscription),
                SpendingConditions::default(),
                Default::default(),
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
            .create_new_profile(
                ProfileType::Normal { name: name.clone() },
                SpendingConditions::default(),
                Default::default(),
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
            relay: "wss://nostr.mutinywallet.com".to_string(),
            enabled: None,
            archived: None,
            child_key_index: None,
            spending_conditions: Default::default(),
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
            .create_new_profile(
                ProfileType::Normal { name: name.clone() },
                SpendingConditions::default(),
                Default::default(),
            )
            .unwrap();

        assert_eq!(profile.name, name);
        assert_eq!(profile.index, 1000);
        assert_eq!(profile.relay.as_str(), "wss://nostr.mutinywallet.com");

        profile.relay = "wss://relay.damus.io".to_string();

        nostr_manager.edit_profile(profile).unwrap();

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
            .create_new_profile(
                ProfileType::Normal { name: name.clone() },
                SpendingConditions::default(),
                Default::default(),
            )
            .unwrap();

        assert_eq!(profile.name, name);
        assert_eq!(profile.index, 1000);
        assert_eq!(profile.relay.as_str(), "wss://nostr.mutinywallet.com");

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
            .create_new_profile(
                ProfileType::Normal { name },
                SpendingConditions::default(),
                Default::default(),
            )
            .unwrap();

        let inv = PendingNwcInvoice {
            index: Some(profile.index),
            invoice: Bolt11Invoice::from_str("lnbc923720n1pj9nrefpp5pczykgk37af5388n8dzynljpkzs7sje4melqgazlwv9y3apay8jqhp5rd8saxz3juve3eejq7z5fjttxmpaq88d7l92xv34n4h3mq6kwq2qcqzzsxqzfvsp5z0jwpehkuz9f2kv96h62p8x30nku76aj8yddpcust7g8ad0tr52q9qyyssqfy622q25helv8cj8hyxqltws4rdwz0xx2hw0uh575mn7a76cp3q4jcptmtjkjs4a34dqqxn8uy70d0qlxqleezv4zp84uk30pp5q3nqq4c9gkz").unwrap(),
            event_id: EventId::from_slice(&[0; 32]).unwrap(),
            pubkey: XOnlyPublicKey::from_str("552a9d06810f306bfc085cb1e1c26102554138a51fa3a7fdf98f5b03a945143a").unwrap(),
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
