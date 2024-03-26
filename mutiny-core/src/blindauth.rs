use crate::{
    auth::MutinyAuthClient,
    error::MutinyError,
    key::{create_root_child_key, ChildKey},
    onchain::coin_type_from_network,
};
use crate::{logging::MutinyLogger, storage::MutinyStorage};
use async_lock::RwLock;
use bitcoin::{
    bip32::{ChildNumber, DerivationPath, ExtendedPrivKey},
    secp256k1::Secp256k1,
    Network,
};
use fedimint_client::derivable_secret::{ChildId, DerivableSecret};
use lightning::log_error;
use lightning::util::logger::Logger;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tbs::{blind_message, BlindedMessage, BlindedSignature, BlindingKey};
use url::Url;

const BLINDAUTH_CLIENT_NONCE: &[u8] = b"BlindAuth Client Salt";

/// The type of blinded message this is for
const SERVICE_REGISTRATION_CHILD_ID: ChildId = ChildId(0);

/// Child ID used to derive the spend key from a service plan's DerivableSecret
const SPEND_KEY_CHILD_ID: ChildId = ChildId(0);

/// Child ID used to derive the blinding key from a service plan's DerivableSecret
const BLINDING_KEY_CHILD_ID: ChildId = ChildId(1);

#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct TokenStorage {
    // (service_id, plan_id): number of times used
    pub map: HashMap<ServicePlanIndex, u32>,
    pub tokens: Vec<SignedToken>,
    pub version: u32,
}

impl TokenStorage {
    fn increment(&mut self, service_id: u32, plan_id: u32, token: SignedToken) {
        let value = self
            .map
            .entry(ServicePlanIndex {
                service_id,
                plan_id,
            })
            .or_insert(0);
        *value += 1;
        self.tokens.push(token);
        self.version += 1;
    }

    fn get_value(&self, service_id: u32, plan_id: u32) -> u32 {
        self.map
            .get(&ServicePlanIndex {
                service_id,
                plan_id,
            })
            .unwrap_or(&0)
            .to_owned()
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Hash)]
pub struct ServicePlanIndex {
    pub service_id: u32,
    pub plan_id: u32,
}

impl Serialize for ServicePlanIndex {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let string = format!("{}-{}", self.service_id, self.plan_id);
        serializer.serialize_str(&string)
    }
}

impl<'a> Deserialize<'a> for ServicePlanIndex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let uri = String::deserialize(deserializer)?;

        let parts: Vec<&str> = uri.split('-').collect();
        if parts.len() != 2 {
            return Err(serde::de::Error::custom("Invalid ServicePlanIndex"));
        }

        let service_id = parts[0].parse::<u32>().map_err(serde::de::Error::custom)?;
        let plan_id = parts[1].parse::<u32>().map_err(serde::de::Error::custom)?;
        Ok(ServicePlanIndex {
            service_id,
            plan_id,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct UnsignedToken {
    pub counter: u32,
    pub service_id: u32,
    pub plan_id: u32,
    pub blinded_message: BlindedMessage,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SignedToken {
    pub counter: u32,
    pub service_id: u32,
    pub plan_id: u32,
    pub blinded_message: BlindedMessage,
    pub blind_sig: BlindedSignature,
    pub spent: bool,
}

#[derive(Serialize, Deserialize)]
pub struct CheckServiceTokenResponse {
    pub tokens: Vec<ServicePlans>,
}

#[derive(Serialize, Deserialize)]
pub struct ServicePlans {
    pub service: Service,
    pub plan: Plan,
}

#[derive(Serialize, Deserialize)]
pub struct Service {
    pub id: u32,
    pub name: String,
}

#[derive(Serialize, Deserialize)]
pub struct Plan {
    pub id: u32,
    pub service_id: u32,
    pub name: String,
    pub allocation_count: u32,
    pub allocation_type: String,
    pub subscription_plan_reference: Option<i32>,
}

#[derive(Serialize, Deserialize)]
pub struct RedeemServiceTokenRequest {
    pub service_id: u32,
    pub plan_id: u32,
    pub blinded_message: BlindedMessage,
}

#[derive(Serialize, Deserialize)]
pub struct RedeemServiceTokenResponse {
    pub service_id: u32,
    pub plan_id: u32,
    pub blind_sig: BlindedSignature,
}

pub struct BlindAuthClient<S: MutinyStorage> {
    secret: DerivableSecret,
    auth_client: Arc<MutinyAuthClient>,
    base_url: String,
    storage: S,
    token_storage: Arc<RwLock<TokenStorage>>,
    pub logger: Arc<MutinyLogger>,
}

impl<S: MutinyStorage> BlindAuthClient<S> {
    pub fn new(
        xprivkey: ExtendedPrivKey,
        auth_client: Arc<MutinyAuthClient>,
        network: Network,
        base_url: String,
        storage: &S,
        logger: Arc<MutinyLogger>,
    ) -> Result<Self, MutinyError> {
        let token_storage = storage.get_token_storage()?;
        let secret = create_blind_auth_secret(xprivkey, network)?;

        Ok(Self {
            secret,
            auth_client,
            base_url,
            storage: storage.clone(),
            token_storage: Arc::new(RwLock::new(token_storage)),
            logger,
        })
    }

    pub async fn redeem_available_tokens(&self) -> Result<(), MutinyError> {
        // check to see what is available to the user
        let available_tokens = self.check_available_tokens().await?;

        // fetch available one by one
        for service in available_tokens.tokens {
            match self.retrieve_blinded_signature(service).await {
                Ok(_) => (),
                Err(e) => {
                    log_error!(self.logger, "could not redeem token: {e}");
                }
            };
        }

        Ok(())
    }

    async fn check_available_tokens(&self) -> Result<CheckServiceTokenResponse, MutinyError> {
        get_available_tokens(&self.auth_client, &self.base_url).await
    }

    async fn retrieve_blinded_signature(
        &self,
        service: ServicePlans,
    ) -> Result<SignedToken, MutinyError> {
        let service_id = service.service.id;
        let plan_id = service.plan.id;
        let mut token_storage_guard = self.token_storage.write().await;
        let next_counter = token_storage_guard.get_value(service_id, plan_id) + 1;

        // create the deterministic info to derive the token from
        let token_to_blind =
            derive_blind_token(&self.secret, service_id, plan_id, next_counter).await?;
        let token_req = RedeemServiceTokenRequest {
            service_id,
            plan_id,
            blinded_message: token_to_blind.blinded_message,
        };

        // request a blinded signature
        let token_resp =
            retrieve_blinded_signature(&self.auth_client, &self.base_url, token_req).await?;
        let signed_token = SignedToken {
            counter: token_to_blind.counter,
            service_id,
            plan_id,
            blinded_message: token_to_blind.blinded_message,
            blind_sig: token_resp.blind_sig,
            spent: false,
        };

        // store the complete blinded token info
        token_storage_guard.increment(service_id, plan_id, signed_token.clone());

        // FIXME what if storage fails remotely? Revert somehow?
        // It will at least be there locally
        // Maybe have an "issued" tokens call so we can see if we're caught up with the server?
        self.storage
            .insert_token_storage(token_storage_guard.clone())
            .await
            .map_err(|e| {
                log_error!(self.logger, "could not save token storage: {e:?}");
                e
            })?;

        Ok(signed_token)
    }

    pub async fn available_tokens(&self) -> Vec<SignedToken> {
        self.token_storage
            .read()
            .await
            .tokens
            .clone()
            .into_iter()
            .filter(|t| !t.spent)
            .collect::<Vec<SignedToken>>()
    }

    pub async fn used_token(&self, token: &SignedToken) -> Result<(), MutinyError> {
        // once a token has sufficiently been used, mark it as spent and save it back
        let mut token_storage_guard = self.token_storage.write().await;

        // find the token in the vector of tokens
        if let Some(index) = token_storage_guard.tokens.iter_mut().position(|t| {
            t.service_id == token.service_id
                && t.plan_id == token.plan_id
                && t.counter == token.counter
        }) {
            // mark the found token as spent
            token_storage_guard.tokens[index].spent = true;
            token_storage_guard.version += 1;

            // save the updated token storage back to the database or other persistent storage
            self.storage
                .insert_token_storage(token_storage_guard.clone())
                .await?;
        } else {
            return Err(MutinyError::NotFound);
        }

        Ok(())
    }

    pub fn get_unblinded_info_from_token(
        &self,
        token: &SignedToken,
    ) -> (fedimint_mint_client::Nonce, BlindingKey) {
        generate_nonce(&self.secret, token.service_id, token.plan_id, token.counter)
    }
}

async fn get_available_tokens(
    auth_client: &MutinyAuthClient,
    base_url: &str,
) -> Result<CheckServiceTokenResponse, MutinyError> {
    let url = Url::parse(&format!("{}/v1/check-tokens", base_url))
        .map_err(|_| MutinyError::ConnectionFailed)?;
    let res = auth_client
        .request(Method::GET, url, None)
        .await?
        .json::<CheckServiceTokenResponse>()
        .await
        .map_err(|_| MutinyError::ConnectionFailed)?;

    Ok(res)
}

async fn retrieve_blinded_signature(
    auth_client: &MutinyAuthClient,
    base_url: &str,
    req: RedeemServiceTokenRequest,
) -> Result<RedeemServiceTokenResponse, MutinyError> {
    let url = Url::parse(&format!("{}/v1/redeem-tokens", base_url))
        .map_err(|_| MutinyError::ConnectionFailed)?;
    let body = serde_json::to_value(req)?;
    let res = auth_client
        .request(Method::POST, url, Some(body))
        .await?
        .json::<RedeemServiceTokenResponse>()
        .await
        .map_err(|_| MutinyError::ConnectionFailed)?;

    Ok(res)
}

async fn derive_blind_token(
    secret: &DerivableSecret,
    service_id: u32,
    plan_id: u32,
    counter: u32,
) -> Result<UnsignedToken, MutinyError> {
    let (nonce, blinding_key) = generate_nonce(secret, service_id, plan_id, counter);
    let blinded_message = blind_message(nonce.to_message(), blinding_key);

    let unsigned_token = UnsignedToken {
        counter,
        service_id,
        plan_id,
        blinded_message,
    };

    Ok(unsigned_token)
}

fn generate_nonce(
    secret: &DerivableSecret,
    service_id: u32,
    plan_id: u32,
    counter: u32,
) -> (fedimint_mint_client::Nonce, BlindingKey) {
    let child_secret = secret
        .child_key(SERVICE_REGISTRATION_CHILD_ID)
        .child_key(ChildId(service_id.into()))
        .child_key(ChildId(plan_id.into()))
        .child_key(ChildId(counter.into()));

    let spend_key = child_secret
        .child_key(SPEND_KEY_CHILD_ID)
        .to_secp_key(fedimint_ln_common::bitcoin::secp256k1::SECP256K1);

    let nonce = fedimint_mint_client::Nonce(spend_key.public_key());

    let blinding_key = BlindingKey(
        child_secret
            .child_key(BLINDING_KEY_CHILD_ID)
            .to_bls12_381_key(),
    );
    (nonce, blinding_key)
}

// Creates the root derivation secret for the blind auth client:
// `m/2'/N'` where `N` is the network type.
//
// Each specific service+plan will have a derivation from there.
fn create_blind_auth_secret(
    xprivkey: ExtendedPrivKey,
    network: Network,
) -> Result<DerivableSecret, MutinyError> {
    let context = Secp256k1::new();

    let shared_key = create_root_child_key(&context, xprivkey, ChildKey::BlindAuth)?;
    let xpriv = shared_key.derive_priv(
        &context,
        &DerivationPath::from(vec![ChildNumber::from_hardened_idx(
            coin_type_from_network(network),
        )?]),
    )?;

    Ok(DerivableSecret::new_root(
        &xpriv.private_key.secret_bytes(),
        BLINDAUTH_CLIENT_NONCE,
    ))
}

#[cfg(test)]
mod test {
    use crate::blindauth::{ServicePlanIndex, SignedToken, TokenStorage};
    use tbs::{BlindedMessage, BlindedSignature};

    #[test]
    fn test_token_storage_serialization() {
        let mut map = std::collections::HashMap::new();
        map.insert(
            ServicePlanIndex {
                service_id: 1,
                plan_id: 1,
            },
            1,
        );

        let token = SignedToken {
            counter: 1,
            service_id: 1,
            plan_id: 1,
            blinded_message: BlindedMessage(Default::default()),
            blind_sig: BlindedSignature(Default::default()),
            spent: false,
        };

        let storage = TokenStorage {
            map,
            tokens: vec![token],
            version: 0,
        };

        let serialized = serde_json::to_string(&storage).unwrap();
        let deserialized: TokenStorage = serde_json::from_str(&serialized).unwrap();

        assert_eq!(storage, deserialized);

        // test backwards compatibility
        let string = "{\"map\":{\"1-1\":1},\"tokens\":[{\"counter\":1,\"service_id\":1,\"plan_id\":1,\"blinded_message\":\"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"blind_sig\":\"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"spent\":false}],\"version\":0}";
        let deserialized: TokenStorage = serde_json::from_str(string).unwrap();
        assert_eq!(storage, deserialized);
    }
}
