use crate::error::MutinyError;
use crate::nodemanager::NodeManager;
use crate::nostr::NostrManager;
use crate::storage::MutinyStorage;
use anyhow::anyhow;
use bitcoin::secp256k1::{PublicKey, Secp256k1, Signing};
use bitcoin::util::bip32::ExtendedPrivKey;
use lightning::util::logger::Logger;
use lightning::{log_error, log_warn};
use lightning_invoice::Invoice;
use nostr::key::XOnlyPublicKey;
use nostr::nips::nip47::*;
use nostr::prelude::{decrypt, encrypt};
use nostr::{Event, EventBuilder, Filter, Keys, Kind, Tag};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct Profile {
    pub name: String,
    pub index: u32,
    /// Maximum amount of sats that can be sent in a single payment
    pub max_single_amt_sats: u64,
    pub relay: String,
    pub enabled: bool,
}

impl PartialOrd for Profile {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.index.partial_cmp(&other.index)
    }
}

#[derive(Clone)]
pub(crate) struct NostrWalletConnect {
    /// Client key used for Nostr Wallet Connect.
    /// Mutiny will never use this key but it will be given to the client
    /// in the connect URI.
    client_key: Keys,
    /// Server key used for Nostr Wallet Connect.
    /// The nostr client will use this key to encrypt messages to the wallet.
    /// Mutiny will use this key to decrypt messages from the nostr client.
    server_key: Keys,
    pub(crate) profile: Profile,
}

impl NostrWalletConnect {
    pub fn new<C: Signing>(
        context: &Secp256k1<C>,
        xprivkey: ExtendedPrivKey,
        profile: Profile,
    ) -> Result<NostrWalletConnect, MutinyError> {
        let (client_key, server_key) =
            NostrManager::<()>::derive_nwc_keys(context, xprivkey, profile.index)?;

        Ok(Self {
            client_key,
            server_key,
            profile,
        })
    }

    pub fn get_nwc_uri(&self) -> anyhow::Result<String> {
        let uri = NostrWalletConnectURI::new(
            self.server_key.public_key(),
            self.profile.relay.parse()?,
            Some(self.client_key.secret_key().unwrap()),
            None,
        )?;

        Ok(uri.to_string())
    }

    pub fn client_pubkey(&self) -> XOnlyPublicKey {
        self.client_key.public_key()
    }

    pub fn server_pubkey(&self) -> XOnlyPublicKey {
        self.server_key.public_key()
    }

    pub fn create_nwc_filter(&self) -> Filter {
        Filter::new()
            .kinds(vec![Kind::WalletConnectRequest])
            .author(self.client_pubkey().to_string())
            .pubkey(self.server_pubkey())
    }

    /// Create Nostr Wallet Connect Info event
    pub fn create_nwc_info_event(&self) -> anyhow::Result<Event> {
        let info = EventBuilder::new(Kind::WalletConnectInfo, "pay_invoice".to_string(), &[])
            .to_event(&self.server_key)?;
        Ok(info)
    }

    /// Handle a Nostr Wallet Connect request, returns a response event if one is needed
    pub async fn handle_nwc_request<S: MutinyStorage>(
        &self,
        event: Event,
        node_manager: &NodeManager<S>,
        from_node: &PublicKey,
    ) -> anyhow::Result<Option<Event>> {
        let client_pubkey = self.client_key.public_key();
        if self.profile.enabled
            && event.kind == Kind::WalletConnectRequest
            && event.pubkey == client_pubkey
        {
            let server_key = self.server_key.secret_key()?;

            let decrypted = decrypt(&server_key, &client_pubkey, &event.content)?;
            let req: Request = Request::from_json(decrypted)?;

            // only respond to pay invoice requests
            if req.method != Method::PayInvoice {
                return Ok(None);
            }

            let invoice = Invoice::from_str(&req.params.invoice)
                .map_err(|_| anyhow!("Failed to parse invoice"))?;
            let msats = invoice.amount_milli_satoshis().unwrap_or(0);

            // verify amount is under our limit
            let content = if msats <= self.profile.max_single_amt_sats * 1_000 {
                // todo we could get the author of the event we zapping and use that as the label
                let labels = vec![self.profile.name.clone()];
                match node_manager
                    .pay_invoice(from_node, &invoice, None, labels)
                    .await
                {
                    Ok(inv) => {
                        // preimage should be set after a successful payment
                        let preimage = inv.preimage.expect("preimage not set");
                        Response {
                            result_type: Method::PayInvoice,
                            error: None,
                            result: Some(ResponseResult { preimage }),
                        }
                    }
                    Err(e) => {
                        log_error!(node_manager.logger, "failed to pay invoice: {e}");
                        Response {
                            result_type: Method::PayInvoice,
                            error: Some(NIP47Error {
                                code: ErrorCode::InsufficantBalance,
                                message: format!("Failed to pay invoice: {e}"),
                            }),
                            result: None,
                        }
                    }
                }
            } else {
                log_warn!(
                    node_manager.logger,
                    "Invoice amount too high: {msats} msats"
                );

                Response {
                    result_type: Method::PayInvoice,
                    error: Some(NIP47Error {
                        code: ErrorCode::QuotaExceeded,
                        message: format!("Invoice amount too high: {msats} msats"),
                    }),
                    result: None,
                }
            };

            let encrypted = encrypt(&server_key, &client_pubkey, content.as_json())?;

            let p_tag = Tag::PubKey(event.pubkey, None);
            let e_tag = Tag::Event(event.id, None, None);
            let response =
                EventBuilder::new(Kind::WalletConnectResponse, encrypted, &[p_tag, e_tag])
                    .to_event(&self.server_key)?;

            return Ok(Some(response));
        }

        Ok(None)
    }

    pub fn nwc_profile(&self) -> NwcProfile {
        NwcProfile {
            name: self.profile.name.clone(),
            index: self.profile.index,
            max_single_amt_sats: self.profile.max_single_amt_sats,
            relay: self.profile.relay.clone(),
            enabled: self.profile.enabled,
            nwc_uri: self.get_nwc_uri().expect("failed to get nwc uri"),
        }
    }
}

/// Struct for externally exposing a nostr wallet connect profile
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NwcProfile {
    pub name: String,
    pub index: u32,
    /// Maximum amount of sats that can be sent in a single payment
    pub max_single_amt_sats: u64,
    pub relay: String,
    pub enabled: bool,
    pub nwc_uri: String,
}

impl NwcProfile {
    pub(crate) fn profile(&self) -> Profile {
        Profile {
            name: self.name.clone(),
            index: self.index,
            max_single_amt_sats: self.max_single_amt_sats,
            relay: self.relay.clone(),
            enabled: self.enabled,
        }
    }
}
