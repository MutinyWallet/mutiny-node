use crate::error::MutinyError;
use crate::nodemanager::NodeManager;
use crate::nostr::nwc::{
    NostrWalletConnect, NwcProfile, PendingNwcInvoice, Profile, SingleUseSpendingConditions,
    SpendingConditions, PENDING_NWC_EVENTS_KEY,
};
use crate::storage::MutinyStorage;
use bitcoin::hashes::sha256;
use bitcoin::secp256k1::{PublicKey, Secp256k1, Signing};
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey};
use futures_util::lock::Mutex;
use nostr::key::SecretKey;
use nostr::nips::nip47::*;
use nostr::prelude::encrypt;
use nostr::{Event, EventBuilder, EventId, Filter, Keys, Kind, Tag};
use nostr_sdk::Client;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

pub mod nwc;

const NWC_ACCOUNT_INDEX: u32 = 1;
const USER_NWC_PROFILE_START_INDEX: u32 = 1000;

const NWC_STORAGE_KEY: &str = "nwc_profiles";

/// Reserved profiles that are used internally.
/// Must not exceed `USER_NWC_PROFILE_START_INDEX`
pub enum ReservedProfile {
    MutinySubscription,
}

impl ReservedProfile {
    pub fn info(&self) -> (&'static str, u32) {
        let (n, i) = match self {
            ReservedProfile::MutinySubscription => ("Mutiny+ Subscription", 0),
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

/// Manages Nostr keys and has different utilities for nostr specific things
#[derive(Clone)]
pub struct NostrManager<S: MutinyStorage> {
    /// Extended private key that is the root seed of the wallet
    xprivkey: ExtendedPrivKey,
    /// Primary key used for nostr, this will be used for signing events
    pub primary_key: Keys,
    /// Separate profiles for each nostr wallet connect string
    pub(crate) nwc: Arc<RwLock<Vec<NostrWalletConnect>>>,
    pub storage: S,
    /// Lock for pending nwc invoices
    pending_nwc_lock: Arc<Mutex<()>>,
}

impl<S: MutinyStorage> NostrManager<S> {
    pub fn get_relays(&self) -> Vec<String> {
        let mut relays: Vec<String> = self
            .nwc
            .read()
            .unwrap()
            .iter()
            .filter(|x| x.profile.enabled)
            .map(|x| x.profile.relay.clone())
            .collect();

        // remove duplicates
        relays.sort();
        relays.dedup();

        relays
    }

    pub fn get_nwc_filters(&self) -> Vec<Filter> {
        self.nwc
            .read()
            .unwrap()
            .iter()
            .filter(|x| x.profile.enabled)
            .map(|nwc| nwc.create_nwc_filter())
            .collect()
    }

    pub fn get_nwc_uri(&self, index: u32) -> Result<String, MutinyError> {
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
            .filter(|x| !x.profile.archived)
            .map(|x| x.nwc_profile())
            .collect()
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
            self.storage.set_data(NWC_STORAGE_KEY, profiles, None)?;
        }

        Ok(nwc_profile)
    }

    /// Creates a new NWC profile and saves to storage
    pub(crate) fn create_new_profile(
        &self,
        profile_type: ProfileType,
        spending_conditions: SpendingConditions,
    ) -> Result<NwcProfile, MutinyError> {
        let mut profiles = self.nwc.write().unwrap();

        let normal_profiles_count = profiles
            .iter()
            .filter(|&nwc| nwc.profile.index >= USER_NWC_PROFILE_START_INDEX)
            .count() as u32;

        let (name, index) = match profile_type {
            ProfileType::Reserved(reserved_profile) => {
                let (name, index) = reserved_profile.info();
                (name.to_string(), index)
            }
            // Ensure normal profiles start from 1000
            ProfileType::Normal { name } => {
                (name, normal_profiles_count + USER_NWC_PROFILE_START_INDEX)
            }
        };

        let profile = Profile {
            name,
            index,
            relay: "wss://nostr.mutinywallet.com".to_string(),
            enabled: true,
            archived: false,
            spending_conditions,
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
            self.storage.set_data(NWC_STORAGE_KEY, profiles, None)?;
        }

        Ok(nwc.nwc_profile())
    }

    /// Creates a new NWC profile and saves to storage
    /// This will also broadcast the info event to the relay
    pub async fn create_new_nwc_profile(
        &self,
        profile_type: ProfileType,
        spending_conditions: SpendingConditions,
    ) -> Result<NwcProfile, MutinyError> {
        let profile = self.create_new_profile(profile_type, spending_conditions)?;

        let info_event = self.nwc.read().unwrap().iter().find_map(|nwc| {
            if nwc.profile.index == profile.index {
                nwc.create_nwc_info_event().ok()
            } else {
                None
            }
        });

        if let Some(info_event) = info_event {
            let client = Client::new(&self.primary_key);

            #[cfg(target_arch = "wasm32")]
            let add_relay_res = client.add_relay(&profile.relay).await;

            #[cfg(not(target_arch = "wasm32"))]
            let add_relay_res = client.add_relay(&profile.relay, None).await;

            add_relay_res.expect("Failed to add relays");
            client.connect().await;

            client.send_event(info_event).await.map_err(|e| {
                MutinyError::Other(anyhow::anyhow!("Failed to send info event: {e:?}"))
            })?;

            let _ = client.disconnect().await;
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
            spent: false,
        });
        self.create_new_nwc_profile(profile, spending_conditions)
            .await
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
        hash: sha256::Hash,
    ) -> Result<(NostrWalletConnect, PendingNwcInvoice), MutinyError> {
        let pending: Vec<PendingNwcInvoice> = self
            .storage
            .get_data(PENDING_NWC_EVENTS_KEY)?
            .unwrap_or_default();

        let inv = pending
            .iter()
            .find(|x| x.invoice.payment_hash() == &hash)
            .ok_or(MutinyError::NotFound)?;

        let nwc = {
            let profiles = self.nwc.read().unwrap();
            profiles
                .iter()
                .find(|x| x.profile.index == inv.index)
                .ok_or(MutinyError::NotFound)?
                .clone()
        };

        Ok((nwc, inv.to_owned()))
    }

    async fn broadcast_nwc_response(
        &self,
        resp: Response,
        nwc: NostrWalletConnect,
        inv: PendingNwcInvoice,
    ) -> Result<EventId, MutinyError> {
        let client = Client::new(&self.primary_key);

        #[cfg(target_arch = "wasm32")]
        let add_relay_res = client.add_relay(&nwc.profile.relay).await;

        #[cfg(not(target_arch = "wasm32"))]
        let add_relay_res = client.add_relay(&nwc.profile.relay, None).await;

        add_relay_res.expect("Failed to add relays");
        client.connect().await;

        let encrypted = encrypt(
            &nwc.server_key.secret_key().unwrap(),
            &nwc.client_pubkey(),
            resp.as_json(),
        )
        .unwrap();

        let p_tag = Tag::PubKey(inv.pubkey, None);
        let e_tag = Tag::Event(inv.event_id, None, None);
        let response = EventBuilder::new(Kind::WalletConnectResponse, encrypted, &[p_tag, e_tag])
            .to_event(&nwc.server_key)
            .map_err(|e| MutinyError::Other(anyhow::anyhow!("Failed to create event: {e:?}")))?;

        let event_id = client
            .send_event(response)
            .await
            .map_err(|e| MutinyError::Other(anyhow::anyhow!("Failed to send info event: {e:?}")))?;

        let _ = client.disconnect().await;

        Ok(event_id)
    }

    /// Approves an invoice and sends the payment
    pub async fn approve_invoice(
        &self,
        hash: sha256::Hash,
        node_manager: &NodeManager<S>,
        from_node: &PublicKey,
    ) -> Result<EventId, MutinyError> {
        let (nwc, inv) = self.find_nwc_data(hash)?;

        let resp = nwc
            .pay_nwc_invoice(node_manager, from_node, &inv.invoice)
            .await?;

        let event_id = self.broadcast_nwc_response(resp, nwc, inv).await?;

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
            .set_data(PENDING_NWC_EVENTS_KEY, pending, None)?;

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
            let (nwc, inv) = self.find_nwc_data(hash)?;
            self.broadcast_nwc_response(resp, nwc, inv).await?;
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
            .set_data(PENDING_NWC_EVENTS_KEY, invoices, None)?;

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
            .set_data(PENDING_NWC_EVENTS_KEY, invoices, None)?;

        Ok(())
    }

    pub async fn handle_nwc_request(
        &self,
        event: Event,
        node_manager: &NodeManager<S>,
        from_node: &PublicKey,
    ) -> anyhow::Result<Option<Event>> {
        let nwc = {
            let vec = self.nwc.read().unwrap();
            vec.iter()
                .find(|nwc| nwc.client_pubkey() == event.pubkey)
                .cloned()
        };

        if let Some(mut nwc) = nwc {
            let (event, needs_save) = nwc
                .handle_nwc_request(
                    event,
                    node_manager,
                    from_node,
                    self.pending_nwc_lock.deref(),
                )
                .await?;

            // update the profile if needed
            if needs_save {
                let mut vec = self.nwc.write().unwrap();

                // update the profile
                for item in vec.iter_mut() {
                    if item.profile.index == nwc.profile.index {
                        item.profile = nwc.profile;
                        break;
                    }
                }

                let profiles = vec.iter().map(|x| x.profile.clone()).collect::<Vec<_>>();
                drop(vec); // drop the lock, no longer needed

                self.storage.set_data(NWC_STORAGE_KEY, profiles, None)?;
            }

            Ok(event)
        } else {
            Ok(None)
        }
    }

    pub async fn claim_single_use_nwc(
        &self,
        amount_sats: u64,
        nwc_uri: &str,
        node_manager: &NodeManager<S>,
    ) -> anyhow::Result<EventId> {
        let nwc = NostrWalletConnectURI::from_str(nwc_uri)?;
        let secret = Keys::new(nwc.secret);
        let client = Client::new(&secret);

        #[cfg(target_arch = "wasm32")]
        let add_relay_res = client.add_relay(nwc.relay_url.as_str()).await;

        #[cfg(not(target_arch = "wasm32"))]
        let add_relay_res = client.add_relay(nwc.relay_url.as_str(), None).await;

        add_relay_res.expect("Failed to add relays");
        client.connect().await;

        let invoice = node_manager
            .create_invoice(Some(amount_sats), vec!["Gift".to_string()])
            .await?;

        let req = Request {
            method: Method::PayInvoice,
            params: RequestParams {
                invoice: invoice.bolt11.unwrap().to_string(),
            },
        };
        let encrypted = encrypt(&nwc.secret, &nwc.public_key, req.as_json())?;
        let p_tag = Tag::PubKey(nwc.public_key, None);
        let request_event =
            EventBuilder::new(Kind::WalletConnectRequest, encrypted, &[p_tag]).to_event(&secret)?;

        client
            .send_event(request_event.clone())
            .await
            .map_err(|e| {
                MutinyError::Other(anyhow::anyhow!("Failed to send request event: {e:?}"))
            })?;

        client.disconnect().await?;

        Ok(request_event.id)
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
    pub fn from_mnemonic(xprivkey: ExtendedPrivKey, storage: S) -> Result<Self, MutinyError> {
        let context = Secp256k1::new();

        // generate the default primary key
        let primary_key = Self::derive_nostr_key(&context, xprivkey, 0, None, None)?;

        // get from storage
        let profiles: Vec<Profile> = storage.get_data(NWC_STORAGE_KEY)?.unwrap_or_default();

        // generate the wallet connect keys
        let nwc = profiles
            .into_iter()
            .map(|profile| NostrWalletConnect::new(&context, xprivkey, profile).unwrap())
            .collect();

        Ok(Self {
            xprivkey,
            primary_key,
            nwc: Arc::new(RwLock::new(nwc)),
            storage,
            pending_nwc_lock: Arc::new(Mutex::new(())),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::storage::MemoryStorage;
    use bip39::Mnemonic;
    use bitcoin::util::bip32::ExtendedPrivKey;
    use bitcoin::Network;
    use futures::executor::block_on;
    use lightning_invoice::Bolt11Invoice;
    use nostr::key::XOnlyPublicKey;
    use std::str::FromStr;

    fn create_nostr_manager() -> NostrManager<MemoryStorage> {
        let mnemonic = Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").expect("could not generate");

        let xprivkey =
            ExtendedPrivKey::new_master(Network::Bitcoin, &mnemonic.to_seed("")).unwrap();

        let storage = MemoryStorage::new(None, None, None);

        NostrManager::from_mnemonic(xprivkey, storage).unwrap()
    }

    #[test]
    fn test_create_profile() {
        let nostr_manager = create_nostr_manager();

        let name = "test".to_string();

        let profile = nostr_manager
            .create_new_profile(
                ProfileType::Normal { name: name.clone() },
                SpendingConditions::default(),
            )
            .unwrap();

        assert_eq!(profile.name, name);
        assert_eq!(profile.index, 1000);

        let profiles = nostr_manager.profiles();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, name);
        assert_eq!(profiles[0].index, 1000);

        let profiles: Vec<Profile> = nostr_manager
            .storage
            .get_data(NWC_STORAGE_KEY)
            .unwrap()
            .unwrap_or_default();

        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, name);
        assert_eq!(profiles[0].index, 1000);
    }

    #[test]
    fn test_create_reserve_profile() {
        let nostr_manager = create_nostr_manager();

        let name = "Mutiny+ Subscription".to_string();

        let profile = nostr_manager
            .create_new_profile(
                ProfileType::Reserved(ReservedProfile::MutinySubscription),
                SpendingConditions::default(),
            )
            .unwrap();

        assert_eq!(profile.name, name);
        assert_eq!(profile.index, 0);

        let profiles = nostr_manager.profiles();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, name);
        assert_eq!(profiles[0].index, 0);

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
            )
            .unwrap();

        assert_eq!(profile.name, name);
        assert_eq!(profile.index, 1000);
    }

    #[test]
    fn test_edit_profile() {
        let nostr_manager = create_nostr_manager();

        let name = "test".to_string();

        let mut profile = nostr_manager
            .create_new_profile(
                ProfileType::Normal { name: name.clone() },
                SpendingConditions::default(),
            )
            .unwrap();

        assert_eq!(profile.name, name);
        assert_eq!(profile.index, 1000);
        assert!(profile.enabled);

        profile.enabled = false;

        nostr_manager.edit_profile(profile).unwrap();

        let profiles = nostr_manager.profiles();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, name);
        assert_eq!(profiles[0].index, 1000);
        assert!(!profiles[0].enabled);

        let profiles: Vec<Profile> = nostr_manager
            .storage
            .get_data(NWC_STORAGE_KEY)
            .unwrap()
            .unwrap_or_default();

        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, name);
        assert_eq!(profiles[0].index, 1000);
        assert!(!profiles[0].enabled);
    }

    #[test]
    fn test_deny_invoice() {
        let nostr_manager = create_nostr_manager();

        let name = "test".to_string();

        let profile = nostr_manager
            .create_new_profile(ProfileType::Normal { name }, SpendingConditions::default())
            .unwrap();

        let inv = PendingNwcInvoice {
            index: profile.index,
            invoice: Bolt11Invoice::from_str("lnbc923720n1pj9nrefpp5pczykgk37af5388n8dzynljpkzs7sje4melqgazlwv9y3apay8jqhp5rd8saxz3juve3eejq7z5fjttxmpaq88d7l92xv34n4h3mq6kwq2qcqzzsxqzfvsp5z0jwpehkuz9f2kv96h62p8x30nku76aj8yddpcust7g8ad0tr52q9qyyssqfy622q25helv8cj8hyxqltws4rdwz0xx2hw0uh575mn7a76cp3q4jcptmtjkjs4a34dqqxn8uy70d0qlxqleezv4zp84uk30pp5q3nqq4c9gkz").unwrap(),
            event_id: EventId::from_slice(&[0; 32]).unwrap(),
            pubkey: XOnlyPublicKey::from_str("552a9d06810f306bfc085cb1e1c26102554138a51fa3a7fdf98f5b03a945143a").unwrap(),
        };

        // add dummy to storage
        nostr_manager
            .storage
            .set_data(PENDING_NWC_EVENTS_KEY, vec![inv.clone()], None)
            .unwrap();

        let pending = nostr_manager.get_pending_nwc_invoices().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].invoice, inv.invoice);

        block_on(nostr_manager.deny_invoice(inv.invoice.payment_hash().to_owned())).unwrap();

        let pending = nostr_manager.get_pending_nwc_invoices().unwrap();
        assert_eq!(pending.len(), 0);
    }
}
