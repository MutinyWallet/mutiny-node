use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use async_lock::RwLock;
use bitcoin::{bip32::ExtendedPrivKey, secp256k1::Secp256k1};
use fedimint_core::config::FederationId;
use futures::{pin_mut, select, FutureExt};
use lightning::util::logger::Logger;
use lightning::{log_error, log_warn};
use nostr::{nips::nip04::decrypt, Keys};
use nostr::{Filter, Kind, Timestamp};
use nostr_sdk::{Client, NostrSigner, RelayPoolNotification};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use tbs::unblind_signature;
use url::Url;

use crate::{
    blindauth::{BlindAuthClient, SignedToken},
    error::MutinyError,
    federation::{FederationClient, FederationIdentity},
    logging::MutinyLogger,
    nostr::{derive_nostr_key, HERMES_CHAIN_INDEX, SERVICE_ACCOUNT_INDEX},
    storage::MutinyStorage,
    utils,
};

const HERMES_SERVICE_ID: u32 = 1;
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
    pub(crate) primary_key: Keys,
    pub public_key: nostr::PublicKey,
    pub client: Client,
    http_client: reqwest::Client,
    pub(crate) federations: Arc<RwLock<HashMap<FederationId, Arc<FederationClient<S>>>>>,
    blind_auth: BlindAuthClient<S>,
    base_url: String,
    storage: S,
    pub logger: Arc<MutinyLogger>,
    pub stop: Arc<AtomicBool>,
}

impl<S: MutinyStorage> HermesClient<S> {
    pub async fn new(
        xprivkey: ExtendedPrivKey,
        base_url: String,
        federations: Arc<RwLock<HashMap<FederationId, Arc<FederationClient<S>>>>>,
        blind_auth: BlindAuthClient<S>,
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

        // TODO need to store the fact that we have a LNURL or not...

        Ok(Self {
            primary_key: keys,
            public_key,
            client,
            http_client: reqwest::Client::new(),
            base_url,
            federations,
            blind_auth,
            storage: storage.clone(),
            logger,
            stop,
        })
    }

    pub fn start(&self) -> Result<(), MutinyError> {
        let logger = self.logger.clone();
        let stop = self.stop.clone();
        let client = self.client.clone();
        let public_key = self.public_key.clone();
        let storage = self.storage.clone();
        let primary_key = self.primary_key.clone();

        // if we haven't synced before, use now and save to storage
        // TODO FIXME this won't be very correct
        // I guess make a new dm sync time?
        let last_sync_time = storage.get_dm_sync_time()?;
        let time_stamp = match last_sync_time {
            None => {
                let now = Timestamp::now();
                storage.set_dm_sync_time(now.as_u64())?;
                now
            }
            Some(time) => Timestamp::from(time + 1), // add one so we get only new events
        };

        utils::spawn(async move {
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                };

                let received_dm_filter = Filter::new()
                    .kind(Kind::EncryptedDirectMessage)
                    .pubkey(public_key)
                    .since(time_stamp);

                client.connect().await;

                client.subscribe(vec![received_dm_filter]).await;

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
                                                match decrypt_dm(primary_key.clone(), public_key, &event.content).await {
                                                    Ok(_) => {
                                                        // TODO we need to parse and redeem ecash
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
                None => return Err(MutinyError::NotFound),
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
            name: Some(name),
            pubkey: self.public_key.to_string(),
            federation_invite_code: federation_identity.invite_code.to_string(),
            msg: nonce.to_message(),
            sig: unblinded_sig,
        };
        register_name(&self.http_client.clone(), &self.base_url, req).await?;

        Ok(())
    }

    pub async fn get_first_federation(&self) -> Option<FederationIdentity> {
        let federations = self.federations.read().await;
        match federations.iter().next() {
            Some((_, n)) => Some(n.get_mutiny_federation_identity().await),
            None => None,
        }
    }

    // TODO need a way to change the federation if the user's federation changes
}

fn find_hermes_token(
    tokens: &Vec<SignedToken>,
    service_id: u32,
    plan_id: u32,
) -> Option<&SignedToken> {
    tokens
        .iter()
        .find(|token| token.service_id == service_id && token.plan_id == plan_id)
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
pub async fn decrypt_dm(
    primary_key: Keys,
    pubkey: nostr::PublicKey,
    message: &str,
) -> Result<String, MutinyError> {
    let secret = primary_key.secret_key().expect("must have");
    let decrypted = decrypt(secret, &pubkey, message)?;
    Ok(decrypted)
}
