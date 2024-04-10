use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use async_lock::RwLock;
use bitcoin::hashes::hex::FromHex;
use bitcoin::key::Parity;
use bitcoin::secp256k1::ThirtyTwoByteHash;
use bitcoin::{bip32::ExtendedPrivKey, secp256k1::Secp256k1};
use fedimint_core::config::FederationId;
use futures::{pin_mut, select, FutureExt};
use lightning::util::logger::Logger;
use lightning::{log_error, log_info, log_warn};
use lightning_invoice::Bolt11Invoice;
use nostr::prelude::decrypt_received_private_zap_message;
use nostr::secp256k1::SecretKey;
use nostr::{nips::nip04::decrypt, Event, JsonUtil, Keys, Tag, ToBech32};
use nostr::{Filter, Kind, Timestamp};
use nostr_sdk::{Client, RelayPoolNotification};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use tbs::unblind_signature;
use url::Url;

use crate::event::{HTLCStatus, MillisatAmount, PaymentInfo};
use crate::labels::LabelStorage;
use crate::storage::persist_payment_info;
use crate::{
    blindauth::{BlindAuthClient, SignedToken},
    error::MutinyError,
    federation::{FederationClient, FederationIdentity},
    logging::MutinyLogger,
    nostr::{derive_nostr_key, HERMES_CHAIN_INDEX, SERVICE_ACCOUNT_INDEX},
    storage::MutinyStorage,
    utils, PrivacyLevel,
};

const HERMES_SERVICE_ID: u32 = 1;
#[allow(dead_code)]
const HERMES_FREE_PLAN_ID: u32 = 1;
const HERMES_PAID_PLAN_ID: u32 = 2;

#[derive(Deserialize, Serialize)]
pub struct RegisterRequest {
    pub name: Option<String>,
    pub pubkey: String,
    pub federation_invite_code: String,
    pub msg: tbs::Message,
    pub sig: tbs::Signature,
}

#[derive(Deserialize, Serialize)]
pub struct RegisterResponse {
    pub name: String,
}

pub struct HermesClient<S: MutinyStorage> {
    pub(crate) dm_key: Keys,
    claim_key: SecretKey,
    pub public_key: nostr::PublicKey,
    pub client: Client,
    http_client: reqwest::Client,
    pub(crate) federations: Arc<RwLock<HashMap<FederationId, Arc<FederationClient<S>>>>>,
    blind_auth: Arc<BlindAuthClient<S>>,
    base_url: String,
    // bool represents whether or not it was successfully checked
    current_address: Arc<RwLock<(Option<String>, bool)>>,
    storage: S,
    pub logger: Arc<MutinyLogger>,
    pub stop: Arc<AtomicBool>,
}

impl<S: MutinyStorage> HermesClient<S> {
    pub async fn new(
        xprivkey: ExtendedPrivKey,
        base_url: String,
        federations: Arc<RwLock<HashMap<FederationId, Arc<FederationClient<S>>>>>,
        blind_auth: Arc<BlindAuthClient<S>>,
        storage: &S,
        logger: Arc<MutinyLogger>,
        stop: Arc<AtomicBool>,
    ) -> Result<Self, MutinyError> {
        let keys = derive_nostr_key(
            &Secp256k1::new(),
            xprivkey,
            SERVICE_ACCOUNT_INDEX,
            Some(HERMES_CHAIN_INDEX),
            None,
        )?;
        let public_key = keys.public_key();
        let client = Client::new(&keys);

        let relays: Vec<String> = vec![
            "wss://relay.primal.net".to_string(),
            "wss://relay.damus.io".to_string(),
            "wss://nostr.mutinywallet.com".to_string(),
            "wss://relay.mutinywallet.com".to_string(),
        ];
        client
            .add_relays(relays)
            .await
            .expect("Failed to add relays");

        // we use even parity on hermes side, need to check if we need to negate
        let sec = keys.secret_key().expect("must have");
        let claim_key = if sec.x_only_public_key(&Secp256k1::new()).1 == Parity::Even {
            sec.clone()
        } else {
            sec.negate().into()
        };

        Ok(Self {
            dm_key: keys,
            claim_key: *claim_key,
            public_key,
            client,
            http_client: reqwest::Client::new(),
            base_url,
            federations,
            blind_auth,
            current_address: Arc::new(RwLock::new((None, false))),
            storage: storage.clone(),
            logger,
            stop,
        })
    }

    /// Starts the hermes background checker
    /// This should only error if there's an initial unrecoverable error
    /// Otherwise it will loop in the background until a stop signal
    pub fn start(&self, profile_key: Option<Keys>) -> Result<(), MutinyError> {
        // if we haven't synced before, use now and save to storage
        let last_sync_time = self.storage.get_dm_sync_time(true)?;
        let time_stamp = match last_sync_time {
            None => {
                let now = Timestamp::from(0);
                self.storage.set_dm_sync_time(now.as_u64(), true)?;
                now
            }
            Some(time) => Timestamp::from(time + 1), // add one so we get only new events
        };

        // check to see if we currently have an address
        let logger_check_clone = self.logger.clone();
        let stop_check_clone = self.stop.clone();
        let http_client_check_clone = self.http_client.clone();
        let public_key_check_clone = self.public_key;
        let base_url_check_clone = self.base_url.clone();
        let current_address_check_clone = self.current_address.clone();
        utils::spawn(async move {
            loop {
                if stop_check_clone.load(Ordering::Relaxed) {
                    break;
                };

                match check_hermes_name_for_pubkey(
                    &http_client_check_clone,
                    &base_url_check_clone,
                    public_key_check_clone,
                )
                .await
                {
                    Ok(o) => {
                        let mut c = current_address_check_clone.write().await;
                        log_info!(logger_check_clone, "checked lightning address: {o:?}");
                        *c = (o, true);
                        break;
                    }
                    Err(e) => {
                        log_error!(logger_check_clone, "error checking lightning address: {e}");
                    }
                };

                utils::sleep(1_000).await;
            }
        });

        let logger = self.logger.clone();
        let stop = self.stop.clone();
        let client = self.client.clone();
        let public_key = self.public_key;
        let claim_key = self.claim_key;
        let storage = self.storage.clone();
        let dm_key = self.dm_key.clone();
        let federations = self.federations.clone();
        utils::spawn(async move {
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                };

                log_info!(logger, "Starting Hermes DM listener for key {public_key}");

                let received_dm_filter = Filter::new()
                    .kind(Kind::EncryptedDirectMessage)
                    .pubkey(public_key)
                    .since(time_stamp);

                client.connect().await;

                client.subscribe(vec![received_dm_filter], None).await;

                let mut notifications = client.notifications();

                loop {
                    let read_fut = notifications.recv().fuse();
                    let delay_fut = Box::pin(utils::sleep(1_000)).fuse();

                    pin_mut!(read_fut, delay_fut);
                    select! {
                        notification = read_fut => {
                            match notification {
                                Ok(RelayPoolNotification::Event { event, .. }) => {
                                    if event.verify().is_ok() {
                                        match event.kind {
                                            Kind::EncryptedDirectMessage => {
                                                match decrypt_ecash_notification(&dm_key, event.pubkey, &event.content) {
                                                    Ok(notification) => {
                                                        if let Err(e) = handle_ecash_notification(notification, event.created_at, &federations, &storage, &claim_key, profile_key.as_ref(), &logger).await {
                                                            log_error!(logger, "Error handling ecash notification: {e}");
                                                        }
                                                    },
                                                    Err(e) => {
                                                        log_error!(logger, "Error decrypting DM: {e}");
                                                    }
                                                }
                                            }
                                            kind => log_warn!(logger, "Received unexpected note of kind {kind}")
                                        }
                                    }
                                },
                                Ok(RelayPoolNotification::Message { .. }) => {}, // ignore messages
                                Ok(RelayPoolNotification::Shutdown) => break, // if we disconnect, we restart to reconnect
                                Ok(RelayPoolNotification::Stop) => {}, // Currently unused
                                Ok(RelayPoolNotification::RelayStatus { .. }) => {}, // Currently unused
                                Err(_) => break, // if we are erroring we should reconnect
                            }
                        }
                        _ = delay_fut => {
                            if stop.load(Ordering::Relaxed) {
                                break;
                            }
                        }
                    }
                }

                if let Err(e) = client.disconnect().await {
                    log_warn!(logger, "Error disconnecting from relays: {e}");
                }
            }
        });

        Ok(())
    }

    pub async fn check_available_name(&self, name: String) -> Result<bool, MutinyError> {
        check_name_request(&self.http_client, &self.base_url, name).await
    }

    pub async fn reserve_name(&self, name: String) -> Result<(), MutinyError> {
        // check that we have a name token available
        let available_tokens = self.blind_auth.available_tokens().await;
        let available_paid_token =
            match find_hermes_token(&available_tokens, HERMES_SERVICE_ID, HERMES_PAID_PLAN_ID) {
                Some(t) => t,
                None => {
                    log_error!(
                        self.logger,
                        "No available paid token for Hermes, current tokens: {}",
                        available_tokens.len()
                    );
                    return Err(MutinyError::NotFound);
                }
            };

        // check that we have a federation added and get it's id/invite code
        let federation_identity = match self.get_first_federation().await {
            Some(f) => f,
            None => return Err(MutinyError::FederationRequired),
        };

        // do the unblinding
        let (nonce, blinding_key) = self
            .blind_auth
            .get_unblinded_info_from_token(available_paid_token);
        let unblinded_sig = unblind_signature(blinding_key, available_paid_token.blind_sig);

        // send the register request
        let req = RegisterRequest {
            name: Some(name.clone()),
            pubkey: self.public_key.to_string(),
            federation_invite_code: federation_identity.invite_code.to_string(),
            msg: nonce.to_message(),
            sig: unblinded_sig,
        };
        register_name(&self.http_client.clone(), &self.base_url, req).await?;

        {
            let mut c = self.current_address.write().await;
            log_info!(
                self.logger,
                "registered lightning address: {}",
                name.clone()
            );
            *c = (Some(name), true);
        }

        // Mark the token as spent successfully
        self.blind_auth.used_token(available_paid_token).await?;

        Ok(())
    }

    pub async fn check_username(&self) -> Result<Option<String>, MutinyError> {
        match self.current_address.read().await.clone() {
            (None, false) => Err(MutinyError::ConnectionFailed),
            (Some(n), true) => Ok(Some(n)),
            (None, true) => Ok(None),
            _ => {
                unreachable!("can't have some and false")
            }
        }
    }

    async fn get_first_federation(&self) -> Option<FederationIdentity> {
        let federations = self.federations.read().await;
        match federations.iter().next() {
            Some((_, n)) => Some(n.get_mutiny_federation_identity().await),
            None => None,
        }
    }

    // TODO need a way to change the federation if the user's federation changes
}

fn find_hermes_token(
    tokens: &[SignedToken],
    service_id: u32,
    plan_id: u32,
) -> Option<&SignedToken> {
    tokens
        .iter()
        .find(|token| token.service_id == service_id && token.plan_id == plan_id)
}

async fn check_hermes_name_for_pubkey(
    http_client: &reqwest::Client,
    base_url: &str,
    pubkey: nostr::PublicKey,
) -> Result<Option<String>, MutinyError> {
    let url = Url::parse(&format!("{}/v1/check-pubkey/{pubkey}", base_url,))
        .map_err(|_| MutinyError::ConnectionFailed)?;
    let request = http_client.request(Method::GET, url);

    let res = utils::fetch_with_timeout(http_client, request.build().expect("should build req"))
        .await?
        .json::<Option<String>>()
        .await
        .map_err(|_| MutinyError::ConnectionFailed)?;

    Ok(res)
}

async fn check_name_request(
    http_client: &reqwest::Client,
    base_url: &str,
    name: String,
) -> Result<bool, MutinyError> {
    let url = Url::parse(&format!("{}/v1/check-username/{name}", base_url))
        .map_err(|_| MutinyError::ConnectionFailed)?;
    let request = http_client.request(Method::GET, url);

    let res = utils::fetch_with_timeout(http_client, request.build().expect("should build req"))
        .await?
        .json::<bool>()
        .await
        .map_err(|_| MutinyError::ConnectionFailed)?;

    Ok(res)
}

async fn register_name(
    http_client: &reqwest::Client,
    base_url: &str,
    req: RegisterRequest,
) -> Result<RegisterResponse, MutinyError> {
    let url = Url::parse(&format!("{}/v1/register", base_url))
        .map_err(|_| MutinyError::ConnectionFailed)?;
    let request = http_client.request(Method::POST, url).json(&req);

    let res = utils::fetch_with_timeout(http_client, request.build().expect("should build req"))
        .await?
        .json::<RegisterResponse>()
        .await
        .map_err(|_| MutinyError::ConnectionFailed)?;

    Ok(res)
}

/// Decrypts a DM using the primary key
fn decrypt_ecash_notification(
    dm_key: &Keys,
    pubkey: nostr::PublicKey,
    message: &str,
) -> Result<EcashNotification, MutinyError> {
    // decrypt the dm first
    let secret = dm_key.secret_key().expect("must have");
    let decrypted = decrypt(secret, &pubkey, message)?;
    // parse the dm into an ecash notification
    let notification = serde_json::from_str(&decrypted)?;
    Ok(notification)
}

/// What the hermes client expects to receive from a DM
#[derive(Debug, Clone, Deserialize, Serialize)]
struct EcashNotification {
    /// Amount of ecash received in msats
    pub amount: u64,
    /// Tweak we should use to claim the ecash
    pub tweak_index: u64,
    /// Federation id that the ecash is for
    pub federation_id: FederationId,
    /// The zap request that came along with this payment,
    /// useful for tagging the payment to a contact
    pub zap_request: Option<String>,
    /// The bolt11 invoice for the payment
    pub bolt11: Bolt11Invoice,
    /// The preimage for the bolt11 invoice
    pub preimage: String,
}

/// Attempts to claim the ecash, if successful, saves the payment info
async fn handle_ecash_notification<S: MutinyStorage>(
    notification: EcashNotification,
    created_at: Timestamp,
    federations: &RwLock<HashMap<FederationId, Arc<FederationClient<S>>>>,
    storage: &S,
    claim_key: &SecretKey,
    profile_key: Option<&Keys>,
    logger: &MutinyLogger,
) -> anyhow::Result<()> {
    log_info!(
        logger,
        "Received ecash notification for {} msats!",
        notification.amount
    );

    if let Some(federation) = federations.read().await.get(&notification.federation_id) {
        match federation
            .claim_external_receive(claim_key, vec![notification.tweak_index])
            .await
        {
            Ok(_) => {
                log_info!(
                    logger,
                    "Claimed external receive for {} msats!",
                    notification.amount
                );

                let (privacy_level, msg, npub) = match notification.zap_request {
                    None => (PrivacyLevel::NotAvailable, None, None),
                    Some(zap_req) => {
                        let zap_req = Event::from_json(zap_req)?;
                        // handle private/anon zaps
                        let anon = zap_req.iter_tags().find_map(|tag| {
                            if let Tag::Anon { msg } = tag {
                                if msg.is_some() {
                                    // an Anon tag with a message is a private zap
                                    // try to decrypt the message and use that as the message
                                    handle_private_zap(&zap_req, profile_key, logger)
                                } else {
                                    // an Anon tag with no message is an anonymous zap
                                    // the content of the zap is the message
                                    Some((
                                        PrivacyLevel::Anonymous,
                                        Some(zap_req.content.clone()),
                                        None,
                                    ))
                                }
                            } else {
                                None
                            }
                        });

                        // handled the anon tag, if there wasn't one, it is a public zap
                        anon.unwrap_or((
                            PrivacyLevel::Public,
                            Some(zap_req.content.clone()),
                            Some(zap_req.pubkey),
                        ))
                    }
                };

                // create activity item
                let payment_hash = notification.bolt11.payment_hash().into_32();
                let preimage = FromHex::from_hex(&notification.preimage).ok();
                let info = PaymentInfo {
                    preimage,
                    secret: Some(notification.bolt11.payment_secret().0),
                    status: HTLCStatus::Succeeded,
                    amt_msat: MillisatAmount(Some(notification.amount)),
                    fee_paid_msat: None,
                    payee_pubkey: Some(notification.bolt11.recover_payee_pub_key()),
                    bolt11: Some(notification.bolt11.clone()),
                    privacy_level,
                    // use the notification event's created_at as last update so we can properly sort by time
                    last_update: created_at.as_u64(),
                };
                persist_payment_info(storage, &payment_hash, &info, true)?;

                // tag the invoice if we can
                let mut tags = Vec::with_capacity(2);

                // try to tag by contact by npub, otherwise tag by pubkey
                if let Some(npub) = npub {
                    if let Some((id, _)) = storage.get_contact_for_npub(npub)? {
                        tags.push(id);
                    } else {
                        tags.push(npub.to_bech32().expect("must be valid"));
                    }
                }

                // add message tag if we have one
                if let Some(msg) = msg.filter(|m| !m.is_empty()) {
                    tags.push(msg);
                }

                // save the tags if we have any
                if !tags.is_empty() {
                    storage.set_invoice_labels(notification.bolt11, tags)?;
                }
            }
            Err(e) => log_error!(logger, "Error claiming external receive: {e}"),
        }
    } else {
        log_warn!(
            logger,
            "Received DM for unknown federation {}, discarding...",
            notification.federation_id
        );
    }

    // save the last sync time
    storage.set_dm_sync_time(created_at.as_u64(), true)?;

    Ok(())
}

fn handle_private_zap(
    zap_req: &Event,
    profile_key: Option<&Keys>,
    logger: &MutinyLogger,
) -> Option<(PrivacyLevel, Option<String>, Option<nostr::PublicKey>)> {
    let key = match profile_key {
        Some(k) => k.secret_key().ok()?,
        None => {
            log_error!(logger, "No primary key to decrypt private zap");
            return None;
        }
    };
    // try to decrypt the message
    match decrypt_received_private_zap_message(key, zap_req) {
        Ok(event) => Some((
            PrivacyLevel::Private,
            Some(event.content.clone()),
            Some(event.pubkey),
        )),
        Err(e) => {
            // if we can't decrypt, treat it like it's an anonymous zap
            log_error!(logger, "Error decrypting private zap: {e}");
            Some((PrivacyLevel::Anonymous, Some(zap_req.content.clone()), None))
        }
    }
}
