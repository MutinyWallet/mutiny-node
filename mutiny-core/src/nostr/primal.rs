use crate::error::MutinyError;
use crate::utils::parse_profile_metadata;
use nostr::{Event, Kind, Metadata};
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
    ) -> Result<HashMap<nostr::PublicKey, Metadata>, MutinyError> {
        let body = json!(["contact_list", { "pubkey": npub } ]);
        let data: Vec<Value> = self.primal_request(body).await?;
        Ok(parse_profile_metadata(data))
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
