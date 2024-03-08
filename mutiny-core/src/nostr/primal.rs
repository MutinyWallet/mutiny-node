use crate::error::MutinyError;
use crate::utils::parse_profile_metadata;
use nostr::{Event, Kind, Metadata};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct PrimalClient {
    api_url: String,
    client: reqwest::Client,
}

impl PrimalClient {
    pub fn new(api_url: String) -> Self {
        Self {
            api_url,
            client: reqwest::Client::new(),
        }
    }

    /// Makes a request to the primal api
    async fn primal_request(&self, body: Value) -> Result<Vec<Value>, MutinyError> {
        self.client
            .post(&self.api_url)
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|_| MutinyError::NostrError)?
            .json()
            .await
            .map_err(|_| MutinyError::NostrError)
    }

    pub async fn get_user_profile(
        &self,
        npub: nostr::PublicKey,
    ) -> Result<Option<Metadata>, MutinyError> {
        let body = json!(["user_profile", { "pubkey": npub} ]);
        let data: Vec<Value> = self.primal_request(body).await?;

        if let Some(json) = data.first().cloned() {
            let event: Event = match serde_json::from_value(json) {
                Ok(event) => event,
                Err(_) => return Ok(None), // if it's not an event then we don't have a profile
            };
            if event.kind != Kind::Metadata {
                return Ok(None);
            }

            let metadata: Metadata =
                serde_json::from_str(&event.content).map_err(|_| MutinyError::NostrError)?;
            return Ok(Some(metadata));
        };

        Ok(None)
    }

    pub async fn get_user_profiles(
        &self,
        npubs: Vec<nostr::PublicKey>,
    ) -> Result<HashMap<nostr::PublicKey, Metadata>, MutinyError> {
        let body = json!(["user_infos", {"pubkeys": npubs }]);
        let data: Vec<Value> = self.primal_request(body).await?;
        Ok(parse_profile_metadata(data))
    }

    pub async fn get_nostr_contacts(
        &self,
        npub: nostr::PublicKey,
    ) -> Result<(Option<Event>, HashMap<nostr::PublicKey, Metadata>), MutinyError> {
        let body = json!(["contact_list", { "pubkey": npub } ]);
        let data: Vec<Value> = self.primal_request(body).await?;

        // contact list should be the first event, followed by metadata of the contacts
        let contact_list = match data.first().cloned() {
            Some(json) => serde_json::from_value::<Event>(json.clone())
                .ok()
                .filter(|e| e.kind == Kind::ContactList),
            None => return Ok((None, HashMap::new())), // if no data, return empty
        };

        Ok((contact_list, parse_profile_metadata(data)))
    }

    pub async fn get_dm_conversation(
        &self,
        npub1: nostr::PublicKey,
        npub2: nostr::PublicKey,
        limit: u64,
        until: Option<u64>,
        since: Option<u64>,
    ) -> Result<Vec<Event>, MutinyError> {
        // api is a little weird, has sender and receiver but still gives full conversation
        let sender = npub1.to_hex();
        let receiver = npub2.to_hex();
        let body = match (until, since) {
            (Some(until), Some(since)) => {
                json!(["get_directmsgs", { "sender": sender, "receiver": receiver, "limit": limit, "until": until, "since": since }])
            }
            (None, Some(since)) => {
                json!(["get_directmsgs", { "sender": sender, "receiver": receiver, "limit": limit, "since": since }])
            }
            (Some(until), None) => {
                json!(["get_directmsgs", { "sender": sender, "receiver": receiver, "limit": limit, "until": until }])
            }
            (None, None) => {
                json!(["get_directmsgs", { "sender": sender, "receiver": receiver, "limit": limit, "since": 0 }])
            }
        };
        let data: Vec<Value> = self.primal_request(body).await?;

        let mut messages = Vec::with_capacity(data.len());
        for d in data {
            let event = Event::from_value(d)
                .ok()
                .filter(|e| e.kind == Kind::EncryptedDirectMessage);
            if let Some(event) = event {
                messages.push(event);
            }
        }

        Ok(messages)
    }

    /// Returns a list of trusted users from primal with their trust rating
    pub async fn get_trusted_users(&self, limit: u32) -> Result<Vec<TrustedUser>, MutinyError> {
        let body = json!(["trusted_users", {"limit": limit }]);
        let data: Vec<Value> = self.primal_request(body).await?;

        if let Some(json) = data.first().cloned() {
            let event: PrimalEvent =
                serde_json::from_value(json).map_err(|_| MutinyError::NostrError)?;

            let mut trusted_users: Vec<TrustedUser> =
                serde_json::from_str(&event.content).map_err(|_| MutinyError::NostrError)?;

            // parse kind0 events
            let metadata: HashMap<nostr::PublicKey, Metadata> = data
                .into_iter()
                .filter_map(|d| {
                    Event::from_value(d.clone())
                        .ok()
                        .filter(|e| e.kind == Kind::Metadata)
                        .and_then(|e| {
                            serde_json::from_str(&e.content)
                                .ok()
                                .map(|m: Metadata| (e.pubkey, m))
                        })
                })
                .collect();

            // add metadata to trusted users
            for user in trusted_users.iter_mut() {
                if let Some(meta) = metadata.get(&user.pubkey) {
                    user.metadata = Some(meta.clone());
                }
            }

            return Ok(trusted_users);
        };

        Err(MutinyError::NostrError)
    }
}

/// Primal will return nostr "events" which are just kind numbers
/// and a string of content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrimalEvent {
    pub kind: Kind,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedUser {
    #[serde(rename = "pk")]
    pub pubkey: nostr::PublicKey,
    #[serde(rename = "tr")]
    pub trust_rating: f64,
    pub metadata: Option<Metadata>,
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod test {
    use super::*;
    use nostr::{Keys, PublicKey};
    use std::str::FromStr;

    #[tokio::test]
    async fn test_get_user_profile() {
        let client = PrimalClient::new("https://primal-cache.mutinywallet.com/api".to_string());

        // test getting Ben's profile
        let ben =
            PublicKey::from_str("npub1u8lnhlw5usp3t9vmpz60ejpyt649z33hu82wc2hpv6m5xdqmuxhs46turz")
                .unwrap();
        let profile = client.get_user_profile(ben).await.unwrap();
        assert!(profile.is_some());

        // test getting a non-existent npub
        let keys = Keys::generate();
        let profile = client.get_user_profile(keys.public_key()).await.unwrap();
        assert!(profile.is_none());
    }
}
