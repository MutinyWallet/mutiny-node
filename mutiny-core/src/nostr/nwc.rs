use crate::error::MutinyError;
use crate::nodemanager::NodeManager;
use crate::nostr::NostrManager;
use crate::storage::MutinyStorage;
use crate::utils;
use anyhow::anyhow;
use bitcoin::secp256k1::{PublicKey, Secp256k1, Signing};
use bitcoin::util::bip32::ExtendedPrivKey;
use futures_util::lock::Mutex;
use lightning::util::logger::Logger;
use lightning::{log_error, log_warn};
use lightning_invoice::Bolt11Invoice;
use nostr::key::XOnlyPublicKey;
use nostr::nips::nip47::*;
use nostr::prelude::{decrypt, encrypt};
use nostr::{Event, EventBuilder, EventId, Filter, Keys, Kind, Tag};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::str::FromStr;

pub(crate) const PENDING_NWC_EVENTS_KEY: &str = "pending_nwc_events";

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SingleUseSpendingConditions {
    pub spent: bool,
    pub amount_sats: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SpendingConditions {
    SingleUse(SingleUseSpendingConditions),
    /// Require approval before sending a payment
    RequireApproval,
}

impl Default for SpendingConditions {
    fn default() -> Self {
        Self::RequireApproval
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct Profile {
    pub name: String,
    pub index: u32,
    pub relay: String,
    pub enabled: bool,
    /// Require approval before sending a payment
    #[serde(default)]
    pub spending_conditions: SpendingConditions,
}

impl PartialOrd for Profile {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
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
    pub(crate) server_key: Keys,
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

    pub(crate) async fn pay_nwc_invoice<S: MutinyStorage>(
        &self,
        node_manager: &NodeManager<S>,
        from_node: &PublicKey,
        invoice: &Bolt11Invoice,
    ) -> Result<Response, MutinyError> {
        let labels = vec![self.profile.name.clone()];
        match node_manager
            .pay_invoice(from_node, invoice, None, labels)
            .await
        {
            Ok(inv) => {
                // preimage should be set after a successful payment
                let preimage = inv.preimage.expect("preimage not set");
                Ok(Response {
                    result_type: Method::PayInvoice,
                    error: None,
                    result: Some(ResponseResult { preimage }),
                })
            }
            Err(e) => {
                log_error!(node_manager.logger, "failed to pay invoice: {e}");
                Err(e)
            }
        }
    }

    /// Handle a Nostr Wallet Connect request
    ///
    /// Returns a response event if one is needed and if the profile needs to be saved to disk
    pub async fn handle_nwc_request<S: MutinyStorage>(
        &mut self,
        event: Event,
        node_manager: &NodeManager<S>,
        from_node: &PublicKey,
        pending_nwc_lock: &Mutex<()>,
    ) -> anyhow::Result<(Option<Event>, bool)> {
        let client_pubkey = self.client_key.public_key();
        let mut needs_save = false;
        if self.profile.enabled
            && event.kind == Kind::WalletConnectRequest
            && event.pubkey == client_pubkey
        {
            let server_key = self.server_key.secret_key()?;

            let decrypted = decrypt(&server_key, &client_pubkey, &event.content)?;
            let req: Request = Request::from_json(decrypted)?;

            // only respond to pay invoice requests
            if req.method != Method::PayInvoice {
                return Ok((None, needs_save));
            }

            let invoice = Bolt11Invoice::from_str(&req.params.invoice)
                .map_err(|_| anyhow!("Failed to parse invoice"))?;

            // if the invoice has expired, skip it
            if invoice.would_expire(utils::now()) {
                return Ok((None, needs_save));
            }

            // if the invoice has no amount, we cannot pay it
            if invoice.amount_milli_satoshis().is_none() {
                log_warn!(
                    node_manager.logger,
                    "NWC Invoice amount not set, cannot pay: {invoice}"
                );
                return Ok((None, needs_save));
            }

            // if we have already paid this invoice, skip it
            let node = node_manager.get_node(from_node).await?;
            if node.get_invoice(&invoice).is_ok_and(|i| i.paid) {
                return Ok((None, needs_save));
            }
            drop(node);

            // if we need approval, just save in the db for later
            match self.profile.spending_conditions.clone() {
                SpendingConditions::SingleUse(mut single_use) => {
                    // check if we have already spent
                    if single_use.spent {
                        return Ok((None, needs_save));
                    }

                    let msats = invoice.amount_milli_satoshis().unwrap();

                    // verify amount is under our limit
                    let content = if msats <= single_use.amount_sats * 1_000 {
                        match self
                            .pay_nwc_invoice(node_manager, from_node, &invoice)
                            .await
                        {
                            Ok(resp) => {
                                // mark as spent and disable profile
                                single_use.spent = true;
                                self.profile.spending_conditions =
                                    SpendingConditions::SingleUse(single_use);
                                self.profile.enabled = false;
                                needs_save = true;
                                resp
                            }
                            Err(e) => {
                                // todo handle timeout errors
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

                    return Ok((Some(response), needs_save));
                }
                SpendingConditions::RequireApproval => {
                    let pending = PendingNwcInvoice {
                        index: self.profile.index,
                        invoice,
                        event_id: event.id,
                        pubkey: event.pubkey,
                    };
                    pending_nwc_lock.lock().await;

                    let mut current: Vec<PendingNwcInvoice> = node_manager
                        .storage
                        .get_data(PENDING_NWC_EVENTS_KEY)?
                        .unwrap_or_default();

                    current.push(pending);

                    node_manager
                        .storage
                        .set_data(PENDING_NWC_EVENTS_KEY, current, None)?;

                    return Ok((None, needs_save));
                }
            }
        }

        Ok((None, needs_save))
    }

    pub fn nwc_profile(&self) -> NwcProfile {
        NwcProfile {
            name: self.profile.name.clone(),
            index: self.profile.index,
            relay: self.profile.relay.clone(),
            enabled: self.profile.enabled,
            nwc_uri: self.get_nwc_uri().expect("failed to get nwc uri"),
            spending_conditions: self.profile.spending_conditions.clone(),
        }
    }
}

/// Struct for externally exposing a nostr wallet connect profile
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NwcProfile {
    pub name: String,
    pub index: u32,
    pub relay: String,
    pub enabled: bool,
    pub nwc_uri: String,
    #[serde(default)]
    pub spending_conditions: SpendingConditions,
}

impl NwcProfile {
    pub(crate) fn profile(&self) -> Profile {
        Profile {
            name: self.name.clone(),
            index: self.index,
            relay: self.relay.clone(),
            enabled: self.enabled,
            spending_conditions: self.spending_conditions.clone(),
        }
    }
}

/// An invoice received over Nostr Wallet Connect that is pending approval or rejection
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PendingNwcInvoice {
    /// Index of the profile that received the invoice
    pub index: u32,
    /// The invoice that awaiting approval
    pub invoice: Bolt11Invoice,
    /// The nostr event id of the request
    pub event_id: EventId,
    /// The nostr pubkey of the request
    pub pubkey: XOnlyPublicKey,
}

impl PartialOrd for PendingNwcInvoice {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.invoice
            .to_string()
            .partial_cmp(&other.invoice.to_string())
    }
}

impl Ord for PendingNwcInvoice {
    fn cmp(&self, other: &Self) -> Ordering {
        self.invoice.to_string().cmp(&other.invoice.to_string())
    }
}

impl PendingNwcInvoice {
    pub fn is_expired(&self) -> bool {
        self.invoice.would_expire(utils::now())
    }
}
