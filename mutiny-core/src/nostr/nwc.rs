use crate::error::MutinyError;
use crate::event::HTLCStatus;
use crate::nostr::nip49::NIP49Confirmation;
use crate::nostr::NostrManager;
use crate::storage::MutinyStorage;
use crate::utils;
use crate::InvoiceHandler;
use anyhow::anyhow;
use bitcoin::bip32::ExtendedPrivKey;
use bitcoin::hashes::hex::FromHex;
use bitcoin::secp256k1::{Secp256k1, Signing, ThirtyTwoByteHash};
use chrono::{DateTime, Datelike, Duration, NaiveDateTime, Utc};
use core::fmt;
use hex_conservative::DisplayHex;
use itertools::Itertools;
use lightning::util::logger::Logger;
use lightning::{log_error, log_warn};
use lightning_invoice::Bolt11Invoice;
use nostr::nips::nip04::{decrypt, encrypt};
use nostr::nips::nip47::*;
use nostr::{Event, EventBuilder, EventId, Filter, JsonUtil, Keys, Kind, Tag, Timestamp};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::str::FromStr;

pub(crate) const PENDING_NWC_EVENTS_KEY: &str = "pending_nwc_events";

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SingleUseSpendingConditions {
    pub payment_hash: Option<String>,
    pub amount_sats: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TrackedPayment {
    /// Time in seconds since epoch
    pub time: u64,
    /// Amount in sats
    pub amt: u64,
    /// Payment hash
    pub hash: String,
}

/// When payments for a given payment expire
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BudgetPeriod {
    /// Resets daily at midnight UTC
    Day,
    /// Resets every week on sunday, midnight UTC
    Week,
    /// Resets every month on the first, midnight UTC
    Month,
    /// Resets every year on the January 1st, midnight UTC
    Year,
    /// Payments not older than the given number of seconds are counted
    Seconds(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BudgetedSpendingConditions {
    /// Amount in sats for the allotted budget period
    pub budget: u64,
    /// Max amount in sats for a single payment
    pub single_max: Option<u64>,
    /// Payment history
    pub payments: Vec<TrackedPayment>,
    /// Time period the budget is for
    pub period: BudgetPeriod,
}

impl BudgetedSpendingConditions {
    pub fn add_payment(&mut self, invoice: &Bolt11Invoice) {
        let time = utils::now().as_secs();
        let payment = TrackedPayment {
            time,
            amt: invoice.amount_milli_satoshis().unwrap_or_default() / 1_000,
            hash: invoice.payment_hash().into_32().to_lower_hex_string(),
        };

        self.payments.push(payment);
    }

    pub fn remove_payment(&mut self, invoice: &Bolt11Invoice) {
        let hex = invoice.payment_hash().into_32().to_lower_hex_string();
        self.payments.retain(|p| p.hash != hex);
    }

    fn clean_old_payments(&mut self, now: DateTime<Utc>) {
        let period_start = match self.period {
            BudgetPeriod::Day => now.date_naive().and_hms_opt(0, 0, 0).unwrap(),
            BudgetPeriod::Week => (now
                - Duration::days((now.weekday().num_days_from_sunday()) as i64))
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .unwrap(),
            BudgetPeriod::Month => now
                .date_naive()
                .with_day(1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
            BudgetPeriod::Year => NaiveDateTime::new(
                now.date_naive().with_ordinal(1).unwrap(),
                chrono::NaiveTime::from_hms_opt(0, 0, 0).unwrap(),
            ),
            BudgetPeriod::Seconds(secs) => now
                .checked_sub_signed(Duration::seconds(secs as i64))
                .unwrap()
                .naive_utc(),
        };

        self.payments
            .retain(|p| p.time > period_start.timestamp() as u64)
    }

    pub fn sum_payments(&mut self) -> u64 {
        let now = Utc::now();
        self.clean_old_payments(now);
        self.payments.iter().map(|p| p.amt).sum()
    }

    pub fn budget_remaining(&self) -> u64 {
        let mut clone = self.clone();
        self.budget.saturating_sub(clone.sum_payments())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SpendingConditions {
    SingleUse(SingleUseSpendingConditions),
    /// Require approval before sending a payment
    RequireApproval,
    Budget(BudgetedSpendingConditions),
}

impl Default for SpendingConditions {
    fn default() -> Self {
        Self::RequireApproval
    }
}

/// Type of Nostr Wallet Connect profile
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NwcProfileTag {
    Subscription,
    Gift,
    General,
}

impl Default for NwcProfileTag {
    fn default() -> Self {
        Self::General
    }
}

impl fmt::Display for NwcProfileTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Subscription => write!(f, "Subscription"),
            Self::Gift => write!(f, "Gift"),
            Self::General => write!(f, "General"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct Profile {
    pub name: String,
    pub index: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_key: Option<nostr::PublicKey>,
    pub relay: String,
    pub enabled: Option<bool>,
    /// Archived profiles will not be displayed
    pub archived: Option<bool>,
    /// Require approval before sending a payment
    #[serde(default)]
    pub spending_conditions: SpendingConditions,
    /// Allowed commands for this profile
    pub(crate) commands: Option<Vec<Method>>,
    /// index to use to derive nostr keys for child index
    /// set to Option so that we keep using `index` for reserved + existing
    #[serde(default)]
    pub child_key_index: Option<u32>,
    #[serde(default)]
    pub tag: NwcProfileTag,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl Profile {
    pub fn active(&self) -> bool {
        match (self.enabled, self.archived) {
            (Some(enabled), Some(archived)) => enabled && !archived,
            (Some(enabled), None) => enabled,
            (None, Some(archived)) => !archived,
            (None, None) => true,
        }
    }

    /// Returns the available commands for this profile
    pub fn available_commands(&self) -> &[Method] {
        // if None this is an old profile and we should only allow pay invoice
        match self.commands.as_ref() {
            None => &[Method::PayInvoice],
            Some(cmds) => cmds,
        }
    }
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
    pub(crate) client_key: Keys,
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
        let key_derivation_index = profile.child_key_index.unwrap_or(profile.index);

        let (derived_client_key, server_key) =
            NostrManager::<()>::derive_nwc_keys(context, xprivkey, key_derivation_index)?;

        // if the profile has a client key, we should use that instead of the derived one, that means
        // that the profile was created from NWA
        let client_key = match profile.client_key {
            Some(client_key) => Keys::from_public_key(client_key),
            None => derived_client_key,
        };

        Ok(Self {
            client_key,
            server_key,
            profile,
        })
    }

    pub fn get_nwc_uri(&self) -> anyhow::Result<Option<NostrWalletConnectURI>> {
        match self.client_key.secret_key().ok() {
            Some(sk) => Ok(Some(NostrWalletConnectURI::new(
                self.server_key.public_key(),
                self.profile.relay.parse()?,
                sk.clone(),
                None,
            ))),
            None => Ok(None),
        }
    }

    pub fn client_pubkey(&self) -> nostr::PublicKey {
        self.client_key.public_key()
    }

    pub fn server_pubkey(&self) -> nostr::PublicKey {
        self.server_key.public_key()
    }

    pub fn create_nwc_filter(&self, timestamp: Timestamp) -> Filter {
        Filter::new()
            .kinds(vec![Kind::WalletConnectRequest])
            .author(self.client_pubkey())
            .pubkey(self.server_pubkey())
            .since(timestamp)
    }

    /// Create Nostr Wallet Connect Info event
    pub fn create_nwc_info_event(&self) -> anyhow::Result<Event> {
        let commands = self
            .profile
            .available_commands()
            .iter()
            .map(|c| c.to_string())
            .join(" ");
        let info =
            EventBuilder::new(Kind::WalletConnectInfo, commands, []).to_event(&self.server_key)?;
        Ok(info)
    }

    /// Create Nostr Wallet Auth Confirmation event
    pub fn create_auth_confirmation_event(
        &self,
        secret: String,
        commands: Vec<Method>,
    ) -> anyhow::Result<Option<Event>> {
        // skip non-NWA profiles
        if self.profile.client_key.is_none() {
            return Ok(None);
        }

        let json = NIP49Confirmation {
            secret,
            commands,
            relay: Some(self.profile.relay.clone()),
        };
        let content = encrypt(
            self.server_key.secret_key()?,
            &self.client_pubkey(),
            serde_json::to_string(&json)?,
        )?;
        let d_tag = Tag::Identifier(self.client_pubkey().to_hex());
        let event = EventBuilder::new(Kind::ParameterizedReplaceable(33194), content, [d_tag])
            .to_event(&self.server_key)?;
        Ok(Some(event))
    }

    pub(crate) async fn pay_nwc_invoice(
        &self,
        node: &impl InvoiceHandler,
        invoice: &Bolt11Invoice,
    ) -> Result<Response, MutinyError> {
        let label = self
            .profile
            .label
            .clone()
            .unwrap_or(self.profile.name.clone());
        match node.pay_invoice(invoice, None, vec![label]).await {
            Ok(inv) => {
                // preimage should be set after a successful payment
                let preimage = inv.preimage.expect("preimage not set");
                Ok(Response {
                    result_type: Method::PayInvoice,
                    error: None,
                    result: Some(ResponseResult::PayInvoice(PayInvoiceResponseResult {
                        preimage,
                    })),
                })
            }
            Err(e) => {
                log_error!(node.logger(), "failed to pay invoice: {e}");
                Err(e)
            }
        }
    }

    async fn save_pending_nwc_invoice<S: MutinyStorage>(
        &self,
        nostr_manager: &NostrManager<S>,
        event_id: EventId,
        event_pk: nostr::PublicKey,
        invoice: Bolt11Invoice,
        identifier: Option<String>,
    ) -> anyhow::Result<()> {
        nostr_manager
            .save_pending_nwc_invoice(
                Some(self.profile.index),
                event_id,
                event_pk,
                invoice,
                identifier,
            )
            .await
    }

    fn get_skipped_error_event(
        &self,
        event: &Event,
        result_type: Method,
        error_code: ErrorCode,
        message: String,
    ) -> anyhow::Result<Event> {
        let server_key = self.server_key.secret_key()?;
        let client_pubkey = self.client_key.public_key();
        let content = Response {
            result_type,
            error: Some(NIP47Error {
                code: error_code,
                message,
            }),
            result: None,
        };

        let encrypted = encrypt(server_key, &client_pubkey, content.as_json())?;

        let p_tag = Tag::public_key(event.pubkey);
        let e_tag = Tag::event(event.id);
        let response = EventBuilder::new(Kind::WalletConnectResponse, encrypted, [p_tag, e_tag])
            .to_event(&self.server_key)?;

        Ok(response)
    }

    /// Handle a Nostr Wallet Connect request
    ///
    /// Returns a response event if one is needed
    pub async fn handle_nwc_request<S: MutinyStorage>(
        &mut self,
        event: Event,
        node: &impl InvoiceHandler,
        nostr_manager: &NostrManager<S>,
    ) -> anyhow::Result<Option<Event>> {
        let client_pubkey = self.client_key.public_key();
        let mut needs_save = false;
        let mut needs_delete = false;
        let mut result = None;
        if self.profile.active()
            && event.kind == Kind::WalletConnectRequest
            && event.pubkey == client_pubkey
        {
            let server_key = self.server_key.secret_key()?;

            let decrypted = decrypt(server_key, &client_pubkey, &event.content)?;
            let req: Request = match Request::from_json(decrypted) {
                Ok(req) => req,
                Err(e) => {
                    log_warn!(
                        nostr_manager.logger,
                        "Failed to parse request: {e}, skipping..."
                    );
                    return self
                        .get_skipped_error_event(
                            &event,
                            Method::PayInvoice, // most likely it's a pay invoice request
                            ErrorCode::NotImplemented,
                            "Failed to parse request.".to_string(),
                        )
                        .map(Some);
                }
            };

            // only respond to commands that are allowed by the profile
            if !self.profile.available_commands().contains(&req.method) {
                return self
                    .get_skipped_error_event(
                        &event,
                        req.method,
                        ErrorCode::NotImplemented,
                        "Command is not supported.".to_string(),
                    )
                    .map(Some);
            }

            result = match req.params {
                RequestParams::PayInvoice(params) => {
                    self.handle_pay_invoice_request(
                        event,
                        node,
                        nostr_manager,
                        params,
                        &mut needs_delete,
                        &mut needs_save,
                    )
                    .await?
                }
                _ => return Err(anyhow!("Invalid request params for {}", req.method)),
            };
        }

        if needs_delete {
            nostr_manager.delete_nwc_profile(self.profile.index)?;
        } else if needs_save {
            nostr_manager.save_nwc_profile(self.clone())?;
        }

        Ok(result)
    }

    async fn handle_pay_invoice_request<S: MutinyStorage>(
        &mut self,
        event: Event,
        node: &impl InvoiceHandler,
        nostr_manager: &NostrManager<S>,
        params: PayInvoiceRequestParams,
        needs_delete: &mut bool,
        needs_save: &mut bool,
    ) -> anyhow::Result<Option<Event>> {
        let invoice: Bolt11Invoice = match check_valid_nwc_invoice(&params, node).await {
            Ok(Some(invoice)) => invoice,
            Ok(None) => return Ok(None),
            Err(err_string) => {
                return self
                    .get_skipped_error_event(
                        &event,
                        Method::PayInvoice,
                        ErrorCode::Other,
                        err_string,
                    )
                    .map(Some);
            }
        };

        // if we need approval, just save in the db for later
        match self.profile.spending_conditions.clone() {
            SpendingConditions::SingleUse(mut single_use) => {
                let msats = invoice.amount_milli_satoshis().unwrap();

                // get the status of the previous payment attempt, if one exists
                let prev_status: Option<HTLCStatus> = match single_use.payment_hash {
                    Some(payment_hash) => {
                        let hash: [u8; 32] =
                            FromHex::from_hex(&payment_hash).expect("invalid hash");
                        node.get_outbound_payment_status(&hash).await
                    }
                    None => None,
                };

                // check if we have already spent
                let content = match prev_status {
                    Some(HTLCStatus::Succeeded) => {
                        *needs_delete = true;
                        Response {
                            result_type: Method::PayInvoice,
                            error: Some(NIP47Error {
                                code: ErrorCode::QuotaExceeded,
                                message: "Already Claimed".to_string(),
                            }),
                            result: None,
                        }
                    }
                    None | Some(HTLCStatus::Failed) => {
                        if msats <= single_use.amount_sats * 1_000 {
                            match self.pay_nwc_invoice(node, &invoice).await {
                                Ok(resp) => {
                                    // after it is spent, delete the profile
                                    // so that it cannot be used again
                                    *needs_delete = true;
                                    resp
                                }
                                Err(e) => {
                                    let mut code = ErrorCode::InsufficientBalance;
                                    if let MutinyError::PaymentTimeout = e {
                                        // if a payment times out, we should save the payment_hash
                                        // and track if the payment settles or not. If it does not
                                        // we can try again later.
                                        single_use.payment_hash = Some(
                                            invoice.payment_hash().into_32().to_lower_hex_string(),
                                        );
                                        self.profile.spending_conditions =
                                            SpendingConditions::SingleUse(single_use);
                                        *needs_save = true;

                                        log_error!(
                                            nostr_manager.logger,
                                            "Payment timeout, saving profile for later"
                                        );
                                        code = ErrorCode::Internal;
                                    } else {
                                        // for non-timeout errors, add to manual approval list
                                        self.save_pending_nwc_invoice(
                                            nostr_manager,
                                            event.id,
                                            event.pubkey,
                                            invoice,
                                            params.id.clone(),
                                        )
                                        .await?
                                    }
                                    Response {
                                        result_type: Method::PayInvoice,
                                        error: Some(NIP47Error {
                                            code,
                                            message: format!("Failed to pay invoice: {e}"),
                                        }),
                                        result: None,
                                    }
                                }
                            }
                        } else {
                            log_warn!(
                                nostr_manager.logger,
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
                        }
                    }
                    Some(HTLCStatus::Pending) | Some(HTLCStatus::InFlight) => {
                        log_warn!(
                            nostr_manager.logger,
                            "Previous NWC payment still in flight, cannot pay: {invoice}"
                        );

                        Response {
                            result_type: Method::PayInvoice,
                            error: Some(NIP47Error {
                                code: ErrorCode::RateLimited,
                                message: "Previous payment still in flight, cannot pay".to_string(),
                            }),
                            result: None,
                        }
                    }
                };

                let encrypted = encrypt(
                    self.server_key.secret_key()?,
                    &self.client_key.public_key(),
                    content.as_json(),
                )?;

                let p_tag = Tag::public_key(event.pubkey);
                let e_tag = Tag::event(event.id);
                let tags = match params.id {
                    Some(id) => vec![p_tag, e_tag, Tag::Identifier(id)],
                    None => vec![p_tag, e_tag],
                };

                let response = EventBuilder::new(Kind::WalletConnectResponse, encrypted, tags)
                    .to_event(&self.server_key)?;

                if *needs_delete {
                    nostr_manager.delete_nwc_profile(self.profile.index)?;
                } else if *needs_save {
                    nostr_manager.save_nwc_profile(self.clone())?;
                }

                Ok(Some(response))
            }
            SpendingConditions::RequireApproval => {
                self.save_pending_nwc_invoice(
                    nostr_manager,
                    event.id,
                    event.pubkey,
                    invoice,
                    params.id,
                )
                .await?;

                if *needs_save {
                    nostr_manager.save_nwc_profile(self.clone())?;
                }

                Ok(None)
            }
            SpendingConditions::Budget(mut budget) => {
                let sats = invoice.amount_milli_satoshis().unwrap() / 1_000;

                let budget_err = if budget.single_max.is_some_and(|max| sats > max) {
                    Some("Invoice amount too high.")
                } else if budget.sum_payments() + sats > budget.budget {
                    // budget might not actually be exceeded, we should verify that the payments
                    // all went through, and if not, remove them from the budget
                    let mut indices_to_remove = Vec::new();
                    for (index, p) in budget.payments.iter().enumerate() {
                        let hash: [u8; 32] = FromHex::from_hex(&p.hash)?;
                        indices_to_remove.push((index, hash));
                    }

                    let futures: Vec<_> = indices_to_remove
                        .iter()
                        .map(|(index, hash)| async move {
                            match node.get_outbound_payment_status(hash).await {
                                Some(HTLCStatus::Failed) => Some(*index),
                                _ => None,
                            }
                        })
                        .collect();

                    let results = futures::future::join_all(futures).await;

                    // Remove failed payments
                    for index in results.into_iter().flatten().rev() {
                        budget.payments.remove(index);
                    }

                    // update budget with removed payments
                    self.profile.spending_conditions = SpendingConditions::Budget(budget.clone());

                    // try again with cleaned budget
                    if budget.sum_payments() + sats > budget.budget {
                        Some("Budget exceeded.")
                    } else {
                        None
                    }
                } else {
                    None
                };

                let content = match budget_err {
                    Some(err) => {
                        log_warn!(nostr_manager.logger, "Attempted to exceed budget: {err}");
                        // add to manual approval list
                        self.save_pending_nwc_invoice(
                            nostr_manager,
                            event.id,
                            event.pubkey,
                            invoice,
                            params.id.clone(),
                        )
                        .await?;
                        Response {
                            result_type: Method::PayInvoice,
                            error: Some(NIP47Error {
                                code: ErrorCode::QuotaExceeded,
                                message: err.to_string(),
                            }),
                            result: None,
                        }
                    }
                    None => {
                        // add payment to budget
                        budget.add_payment(&invoice);
                        self.profile.spending_conditions =
                            SpendingConditions::Budget(budget.clone());
                        // persist budget before payment to protect against it not saving after
                        nostr_manager.save_nwc_profile(self.clone())?;

                        // attempt to pay invoice
                        match self.pay_nwc_invoice(node, &invoice).await {
                            Ok(resp) => resp,
                            Err(e) => {
                                // remove payment if it failed
                                match e {
                                    MutinyError::PaymentTimeout => {
                                        log_warn!(
                                            nostr_manager.logger,
                                            "Payment timeout, not removing payment from budget"
                                        );
                                    }
                                    MutinyError::NonUniquePaymentHash => {
                                        log_warn!(
                                            nostr_manager.logger,
                                            "Already paid invoice, removing payment from budget"
                                        );
                                        budget.remove_payment(&invoice);
                                        self.profile.spending_conditions =
                                            SpendingConditions::Budget(budget);

                                        nostr_manager.save_nwc_profile(self.clone())?;

                                        // don't save to pending list, we already paid it
                                        return Ok(None);
                                    }
                                    _ => {
                                        log_warn!(
                                                nostr_manager.logger,
                                                "Failed to pay invoice: {e}, removing payment from budget, adding to manual approval list"
                                            );

                                        budget.remove_payment(&invoice);
                                        self.profile.spending_conditions =
                                            SpendingConditions::Budget(budget.clone());

                                        nostr_manager.save_nwc_profile(self.clone())?;

                                        // for non-timeout errors, add to manual approval list
                                        self.save_pending_nwc_invoice(
                                            nostr_manager,
                                            event.id,
                                            event.pubkey,
                                            invoice,
                                            params.id.clone(),
                                        )
                                        .await?
                                    }
                                }

                                Response {
                                    result_type: Method::PayInvoice,
                                    error: Some(NIP47Error {
                                        code: ErrorCode::InsufficientBalance,
                                        message: format!("Failed to pay invoice: {e}"),
                                    }),
                                    result: None,
                                }
                            }
                        }
                    }
                };

                let encrypted = encrypt(
                    self.server_key.secret_key()?,
                    &self.client_key.public_key(),
                    content.as_json(),
                )?;

                let p_tag = Tag::public_key(event.pubkey);
                let e_tag = Tag::event(event.id);

                let tags = match params.id {
                    Some(id) => vec![p_tag, e_tag, Tag::Identifier(id)],
                    None => vec![p_tag, e_tag],
                };

                let response = EventBuilder::new(Kind::WalletConnectResponse, encrypted, tags)
                    .to_event(&self.server_key)?;

                Ok(Some(response))
            }
        }
    }

    pub fn nwc_profile(&self) -> NwcProfile {
        NwcProfile {
            name: self.profile.name.clone(),
            index: self.profile.index,
            client_key: self.profile.client_key,
            relay: self.profile.relay.clone(),
            enabled: self.profile.enabled,
            archived: self.profile.archived,
            nwc_uri: self
                .get_nwc_uri()
                .expect("failed to get nwc uri")
                .map(|uri| uri.to_string()),
            spending_conditions: self.profile.spending_conditions.clone(),
            commands: self.profile.commands.clone(),
            child_key_index: self.profile.child_key_index,
            tag: self.profile.tag,
            label: self.profile.label.clone(),
        }
    }
}

/// Struct for externally exposing a nostr wallet connect profile
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NwcProfile {
    pub name: String,
    pub index: u32,
    /// Public Key given in a Nostr Wallet Auth URI.
    /// This will only be defined for profiles created through Nostr Wallet Auth.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_key: Option<nostr::PublicKey>,
    pub relay: String,
    pub enabled: Option<bool>,
    pub archived: Option<bool>,
    /// Nostr Wallet Connect URI
    /// This will only be defined for profiles created manually.
    pub nwc_uri: Option<String>,
    #[serde(default)]
    pub spending_conditions: SpendingConditions,
    /// Allowed commands for this profile
    pub commands: Option<Vec<Method>>,
    #[serde(default)]
    pub child_key_index: Option<u32>,
    #[serde(default)]
    pub tag: NwcProfileTag,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl NwcProfile {
    pub(crate) fn profile(&self) -> Profile {
        Profile {
            name: self.name.clone(),
            index: self.index,
            client_key: self.client_key,
            relay: self.relay.clone(),
            archived: self.archived,
            enabled: self.enabled,
            spending_conditions: self.spending_conditions.clone(),
            commands: self.commands.clone(),
            child_key_index: self.child_key_index,
            tag: self.tag,
            label: self.label.clone(),
        }
    }
}

/// An invoice received over Nostr Wallet Connect that is pending approval or rejection
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PendingNwcInvoice {
    /// Index of the profile that received the invoice.
    /// None if invoice is from a DM
    pub index: Option<u32>,
    /// The invoice that awaiting approval
    pub invoice: Bolt11Invoice,
    /// The nostr event id of the request
    pub event_id: EventId,
    /// The nostr pubkey of the request
    /// If this is a DM, this is who sent us the request
    pub pubkey: nostr::PublicKey,
    /// `id` parameter given in the original request
    /// This is normally only given for MultiPayInvoice requests
    pub identifier: Option<String>,
}

impl PartialOrd for PendingNwcInvoice {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
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

/// Checks if it is a valid invoice
/// Return an error string if invalid
/// Otherwise returns an optional invoice that should be processed
pub(crate) async fn check_valid_nwc_invoice(
    params: &PayInvoiceRequestParams,
    invoice_handler: &impl InvoiceHandler,
) -> Result<Option<Bolt11Invoice>, String> {
    let invoice = match Bolt11Invoice::from_str(&params.invoice) {
        Ok(invoice) => invoice,
        Err(_) => return Err("Invalid invoice".to_string()),
    };

    // if the invoice has expired, skip it
    if invoice.would_expire(utils::now()) {
        return Err("Invoice expired".to_string());
    }

    // if the invoice has no amount, we cannot pay it
    if invoice.amount_milli_satoshis().is_none() {
        log_warn!(
            invoice_handler.logger(),
            "NWC Invoice amount not set, cannot pay: {invoice}"
        );

        if params.amount.is_none() {
            return Err("Invoice amount not set".to_string());
        }

        // TODO we cannot pay invoices with msat values so for now return an error
        return Err("Paying 0 amount invoices is not supported yet".to_string());
    }

    if invoice_handler.skip_hodl_invoices() {
        // Skip potential hodl invoices as they can cause force closes
        if utils::is_hodl_invoice(&invoice) {
            log_warn!(
                invoice_handler.logger(),
                "Received potential hodl invoice, skipping..."
            );
            return Err("Paying hodl invoices disabled".to_string());
        }
    }

    // if we have already paid or are attempting to pay this invoice, skip it
    if invoice_handler
        .get_outbound_payment_status(&invoice.payment_hash().into_32())
        .await
        .is_some_and(|status| matches!(status, HTLCStatus::Succeeded | HTLCStatus::InFlight))
    {
        return Ok(None);
    }

    Ok(Some(invoice))
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::Days;

    #[test]
    fn test_clean_old_payments_seconds() {
        let mut budget = BudgetedSpendingConditions {
            budget: 100,
            single_max: None,
            payments: vec![
                TrackedPayment {
                    time: 91,
                    amt: 10,
                    hash: "1".to_string(),
                },
                TrackedPayment {
                    time: 95,
                    amt: 20,
                    hash: "2".to_string(),
                },
                TrackedPayment {
                    time: 97,
                    amt: 30,
                    hash: "3".to_string(),
                },
            ],
            period: BudgetPeriod::Seconds(10),
        };

        let time = NaiveDateTime::from_timestamp_opt(100, 0).unwrap().and_utc();
        budget.clean_old_payments(time);
        assert_eq!(budget.payments.len(), 3);

        let time = time.checked_add_signed(Duration::seconds(2)).unwrap();
        budget.clean_old_payments(time);
        assert_eq!(budget.payments.len(), 2);

        let time = time.checked_add_signed(Duration::seconds(3)).unwrap();
        budget.clean_old_payments(time);
        assert_eq!(budget.payments.len(), 1);

        let time = time.checked_add_signed(Duration::seconds(10)).unwrap();
        budget.clean_old_payments(time);
        assert_eq!(budget.payments.len(), 0);
    }

    #[test]
    fn test_clean_old_days() {
        let zero = NaiveDateTime::default();
        let mut budget = BudgetedSpendingConditions {
            budget: 100,
            single_max: None,
            payments: vec![
                TrackedPayment {
                    time: zero.checked_add_days(Days::new(1)).unwrap().timestamp() as u64,
                    amt: 10,
                    hash: "1".to_string(),
                },
                TrackedPayment {
                    time: zero.checked_add_days(Days::new(5)).unwrap().timestamp() as u64,
                    amt: 20,
                    hash: "2".to_string(),
                },
                TrackedPayment {
                    time: zero.checked_add_days(Days::new(7)).unwrap().timestamp() as u64,
                    amt: 30,
                    hash: "3".to_string(),
                },
            ],
            period: BudgetPeriod::Day,
        };

        let time = NaiveDateTime::from_timestamp_opt(100, 0).unwrap().and_utc();
        budget.clean_old_payments(time);
        assert_eq!(budget.payments.len(), 3);

        let time = time.checked_add_signed(Duration::days(2)).unwrap();
        budget.clean_old_payments(time);
        assert_eq!(budget.payments.len(), 2);

        let time = time.checked_add_signed(Duration::days(3)).unwrap();
        budget.clean_old_payments(time);
        assert_eq!(budget.payments.len(), 1);

        let time = time.checked_add_signed(Duration::days(10)).unwrap();
        budget.clean_old_payments(time);
        assert_eq!(budget.payments.len(), 0);
    }

    #[test]
    fn test_clean_old_weeks() {
        let mut budget = BudgetedSpendingConditions {
            budget: 100,
            single_max: None,
            payments: vec![
                TrackedPayment {
                    time: NaiveDateTime::from_timestamp_opt(1691712000, 0)
                        .unwrap()
                        .timestamp() as u64, // 2023-8-11
                    amt: 10,
                    hash: "1".to_string(),
                },
                TrackedPayment {
                    time: NaiveDateTime::from_timestamp_opt(1692316800, 0)
                        .unwrap()
                        .timestamp() as u64, // 2023-8-18
                    amt: 20,
                    hash: "2".to_string(),
                },
                TrackedPayment {
                    time: NaiveDateTime::from_timestamp_opt(1692921600, 0)
                        .unwrap()
                        .timestamp() as u64, // 2023-8-25
                    amt: 30,
                    hash: "3".to_string(),
                },
            ],
            period: BudgetPeriod::Week,
        };

        // 2023-8-13
        let time = NaiveDateTime::from_timestamp_opt(1691798400, 0)
            .unwrap()
            .and_utc();
        budget.clean_old_payments(time);
        assert_eq!(budget.payments.len(), 3);

        // 2023-8-14
        let time = NaiveDateTime::from_timestamp_opt(1691971200, 0)
            .unwrap()
            .and_utc();
        budget.clean_old_payments(time);
        assert_eq!(budget.payments.len(), 2);

        // 2023-8-21
        let time = NaiveDateTime::from_timestamp_opt(1692576000, 0)
            .unwrap()
            .and_utc();
        budget.clean_old_payments(time);
        assert_eq!(budget.payments.len(), 1);

        // 2023-8-28
        let time = NaiveDateTime::from_timestamp_opt(1693180800, 0)
            .unwrap()
            .and_utc();
        budget.clean_old_payments(time);
        assert_eq!(budget.payments.len(), 0);
    }

    #[test]
    fn test_clean_old_month() {
        let mut budget = BudgetedSpendingConditions {
            budget: 100,
            single_max: None,
            payments: vec![
                TrackedPayment {
                    time: NaiveDateTime::from_timestamp_opt(1683763200, 0)
                        .unwrap()
                        .timestamp() as u64, // 2023-5-11
                    amt: 10,
                    hash: "1".to_string(),
                },
                TrackedPayment {
                    time: NaiveDateTime::from_timestamp_opt(1686441600, 0)
                        .unwrap()
                        .timestamp() as u64, // 2023-6-11
                    amt: 20,
                    hash: "2".to_string(),
                },
                TrackedPayment {
                    time: NaiveDateTime::from_timestamp_opt(1689033600, 0)
                        .unwrap()
                        .timestamp() as u64, // 2023-7-11
                    amt: 30,
                    hash: "3".to_string(),
                },
            ],
            period: BudgetPeriod::Month,
        };

        // 2023-5-29
        let time = NaiveDateTime::from_timestamp_opt(1685318400, 0)
            .unwrap()
            .and_utc();
        budget.clean_old_payments(time);
        assert_eq!(budget.payments.len(), 3);

        // 2023-6-29
        let time = NaiveDateTime::from_timestamp_opt(1687996800, 0)
            .unwrap()
            .and_utc();
        budget.clean_old_payments(time);
        assert_eq!(budget.payments.len(), 2);

        // 2023-7-29
        let time = NaiveDateTime::from_timestamp_opt(1690588800, 0)
            .unwrap()
            .and_utc();
        budget.clean_old_payments(time);
        assert_eq!(budget.payments.len(), 1);

        // 2023-8-1
        let time = NaiveDateTime::from_timestamp_opt(1690848000, 0)
            .unwrap()
            .and_utc();
        budget.clean_old_payments(time);
        assert_eq!(budget.payments.len(), 0);
    }

    #[test]
    fn test_clean_old_year() {
        let mut budget = BudgetedSpendingConditions {
            budget: 100,
            single_max: None,
            payments: vec![
                TrackedPayment {
                    time: NaiveDateTime::from_timestamp_opt(1620691200, 0)
                        .unwrap()
                        .timestamp() as u64, // 2021-5-11
                    amt: 10,
                    hash: "1".to_string(),
                },
                TrackedPayment {
                    time: NaiveDateTime::from_timestamp_opt(1654905600, 0)
                        .unwrap()
                        .timestamp() as u64, // 2022-6-11
                    amt: 20,
                    hash: "2".to_string(),
                },
                TrackedPayment {
                    time: NaiveDateTime::from_timestamp_opt(1689033600, 0)
                        .unwrap()
                        .timestamp() as u64, // 2023-7-11
                    amt: 30,
                    hash: "3".to_string(),
                },
            ],
            period: BudgetPeriod::Year,
        };

        // 2021-7-11
        let time = NaiveDateTime::from_timestamp_opt(1625961600, 0)
            .unwrap()
            .and_utc();
        budget.clean_old_payments(time);
        assert_eq!(budget.payments.len(), 3);

        // 2022-7-11
        let time = NaiveDateTime::from_timestamp_opt(1657497600, 0)
            .unwrap()
            .and_utc();
        budget.clean_old_payments(time);
        assert_eq!(budget.payments.len(), 2);

        // 2023-9-11
        let time = NaiveDateTime::from_timestamp_opt(1694390400, 0)
            .unwrap()
            .and_utc();
        budget.clean_old_payments(time);
        assert_eq!(budget.payments.len(), 1);

        // 2024-4-20
        let time = NaiveDateTime::from_timestamp_opt(1713571200, 0)
            .unwrap()
            .and_utc();
        budget.clean_old_payments(time);
        assert_eq!(budget.payments.len(), 0);
    }
}

#[cfg(test)]
#[cfg(target_arch = "wasm32")]
mod wasm_test {
    use super::*;
    use crate::logging::MutinyLogger;
    use crate::nostr::{NostrKeySource, ProfileType};
    use crate::storage::MemoryStorage;
    use crate::test_utils::{create_dummy_invoice, create_mutiny_wallet, create_nwc_request};
    use crate::MockInvoiceHandler;
    use crate::MutinyInvoice;
    use bitcoin::Network;
    use mockall::predicate::eq;
    use nostr::key::SecretKey;
    use serde_json::json;
    use std::sync::{atomic::AtomicBool, Arc};
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    const INVOICE: &str = "lnbc923720n1pj9nr6zpp5xmvlq2u5253htn52mflh2e6gn7pk5ht0d4qyhc62fadytccxw7hqhp5l4s6qwh57a7cwr7zrcz706qx0qy4eykcpr8m8dwz08hqf362egfscqzzsxqzfvsp5pr7yjvcn4ggrf6fq090zey0yvf8nqvdh2kq7fue0s0gnm69evy6s9qyyssqjyq0fwjr22eeg08xvmz88307yqu8tqqdjpycmermks822fpqyxgshj8hvnl9mkh6srclnxx0uf4ugfq43d66ak3rrz4dqcqd23vxwpsqf7dmhm";

    fn check_no_pending_invoices(storage: &MemoryStorage) {
        let pending: Vec<PendingNwcInvoice> = storage
            .get_data(PENDING_NWC_EVENTS_KEY)
            .unwrap()
            .unwrap_or_default();
        assert_eq!(pending.len(), 0);
    }

    fn check_nwc_error_response(event: Event, sk: &SecretKey, expected: NIP47Error) {
        assert_eq!(event.kind, Kind::WalletConnectResponse);
        let decrypted = decrypt(sk, &event.pubkey, &event.content).unwrap();
        let resp: Response = Response::from_json(decrypted).unwrap();
        let error = resp.error.unwrap();
        // need to compare json strings because the error code does not implement PartialEq
        assert_eq!(
            serde_json::to_string(&error.code).unwrap(),
            serde_json::to_string(&expected.code).unwrap()
        );
        assert_eq!(error.message, expected.message);
    }

    #[test]
    async fn test_allowed_hodl_invoice() {
        let storage = MemoryStorage::default();
        let mut mw = create_mutiny_wallet(storage.clone()).await;
        mw.skip_hodl_invoices = false; // allow hodl invoices

        let xprivkey = ExtendedPrivKey::new_master(Network::Regtest, &[0; 64]).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let nostr_manager = NostrManager::from_mnemonic(
            xprivkey,
            NostrKeySource::Derived,
            storage.clone(),
            None,
            mw.logger.clone(),
            stop,
        )
        .unwrap();

        let profile = nostr_manager
            .create_new_nwc_profile_internal(
                ProfileType::Normal {
                    name: "test".to_string(),
                },
                SpendingConditions::RequireApproval,
                NwcProfileTag::General,
                vec![Method::PayInvoice],
            )
            .unwrap();

        let secp = Secp256k1::new();
        let mut nwc = NostrWalletConnect::new(&secp, xprivkey, profile.profile()).unwrap();
        let uri = nwc.get_nwc_uri().unwrap().unwrap();

        // test hodl invoice
        let one =
            SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(); // one key
        let invoice = create_dummy_invoice(Some(10_000), Network::Regtest, Some(*one))
            .0
            .to_string();
        let event = create_nwc_request(&uri, invoice.clone());
        let result = nwc
            .handle_nwc_request(event.clone(), &mw, &nostr_manager)
            .await;
        assert_eq!(result.unwrap(), None);

        let pending: Vec<PendingNwcInvoice> = storage
            .get_data(PENDING_NWC_EVENTS_KEY)
            .unwrap()
            .unwrap_or_default();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].invoice.to_string(), invoice);
        assert_eq!(pending[0].event_id, event.id);
        assert_eq!(pending[0].index, Some(nwc.profile.index));
        assert_eq!(pending[0].pubkey, event.pubkey);
    }

    #[test]
    async fn test_process_nwc_event_require_approval() {
        let storage = MemoryStorage::default();
        let logger = Arc::new(MutinyLogger::default());
        let mut node = MockInvoiceHandler::new();
        node.expect_logger().return_const(MutinyLogger::default());
        storage.set_done_first_sync().unwrap();

        let xprivkey = ExtendedPrivKey::new_master(Network::Regtest, &[0; 64]).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let nostr_manager = NostrManager::from_mnemonic(
            xprivkey,
            NostrKeySource::Derived,
            storage.clone(),
            None,
            logger.clone(),
            stop,
        )
        .unwrap();

        let profile = nostr_manager
            .create_new_nwc_profile_internal(
                ProfileType::Normal {
                    name: "test".to_string(),
                },
                SpendingConditions::RequireApproval,
                NwcProfileTag::General,
                vec![Method::PayInvoice],
            )
            .unwrap();

        let secp = Secp256k1::new();
        let mut nwc = NostrWalletConnect::new(&secp, xprivkey, profile.profile()).unwrap();
        let uri = nwc.get_nwc_uri().unwrap().unwrap();

        // test wrong kind
        let event = {
            EventBuilder::new(Kind::TextNote, "", [])
                .to_event(&Keys::new(uri.secret.clone()))
                .unwrap()
        };
        let result = nwc.handle_nwc_request(event, &node, &nostr_manager).await;
        assert_eq!(result.unwrap(), None);
        check_no_pending_invoices(&storage);

        // test unknown command
        let event = {
            let req = json!({"method": "fake_command", "params": {}});

            let encrypted = encrypt(&uri.secret, &uri.public_key, req.to_string()).unwrap();
            let p_tag = Tag::PublicKey {
                public_key: uri.public_key,
                relay_url: None,
                alias: None,
                uppercase: false,
            };
            EventBuilder::new(Kind::WalletConnectRequest, encrypted, [p_tag])
                .to_event(&Keys::new(uri.secret.clone()))
                .unwrap()
        };
        let result = nwc.handle_nwc_request(event, &node, &nostr_manager).await;
        check_nwc_error_response(
            result.unwrap().unwrap(),
            &uri.secret,
            NIP47Error {
                code: ErrorCode::NotImplemented,
                message: "Failed to parse request.".to_string(),
            },
        );
        check_no_pending_invoices(&storage);

        // test unexpected command
        let event = {
            let req = Request {
                method: Method::GetBalance,
                params: RequestParams::GetBalance,
            };

            let encrypted = encrypt(&uri.secret, &uri.public_key, req.as_json()).unwrap();
            let p_tag = Tag::PublicKey {
                public_key: uri.public_key,
                relay_url: None,
                alias: None,
                uppercase: false,
            };
            EventBuilder::new(Kind::WalletConnectRequest, encrypted, [p_tag])
                .to_event(&Keys::new(uri.secret.clone()))
                .unwrap()
        };
        let result = nwc.handle_nwc_request(event, &node, &nostr_manager).await;
        check_nwc_error_response(
            result.unwrap().unwrap(),
            &uri.secret,
            NIP47Error {
                code: ErrorCode::NotImplemented,
                message: "Command is not supported.".to_string(),
            },
        );
        check_no_pending_invoices(&storage);

        // test invalid invoice
        let event = create_nwc_request(&uri, "invalid invoice".to_string());
        let result = nwc.handle_nwc_request(event, &node, &nostr_manager).await;
        check_nwc_error_response(
            result.unwrap().unwrap(),
            &uri.secret,
            NIP47Error {
                code: ErrorCode::Other,
                message: "Invalid invoice".to_string(),
            },
        );
        check_no_pending_invoices(&storage);

        // test expired invoice
        let event = create_nwc_request(&uri, INVOICE.to_string());
        let result = nwc.handle_nwc_request(event, &node, &nostr_manager).await;
        check_nwc_error_response(
            result.unwrap().unwrap(),
            &uri.secret,
            NIP47Error {
                code: ErrorCode::Other,
                message: "Invoice expired".to_string(),
            },
        );
        check_no_pending_invoices(&storage);

        // test amount-less invoice
        let (invoice, _) = create_dummy_invoice(None, Network::Regtest, None);
        let event = create_nwc_request(&uri, invoice.to_string());
        let result = nwc.handle_nwc_request(event, &node, &nostr_manager).await;
        check_nwc_error_response(
            result.unwrap().unwrap(),
            &uri.secret,
            NIP47Error {
                code: ErrorCode::Other,
                message: "Invoice amount not set".to_string(),
            },
        );
        check_no_pending_invoices(&storage);

        // test hodl invoice
        node.expect_skip_hodl_invoices().return_const(true);
        let one =
            SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(); // one key
        let invoice = create_dummy_invoice(Some(10_000), Network::Regtest, Some(*one))
            .0
            .to_string();
        let event = create_nwc_request(&uri, invoice);
        let result = nwc.handle_nwc_request(event, &node, &nostr_manager).await;
        check_nwc_error_response(
            result.unwrap().unwrap(),
            &uri.secret,
            NIP47Error {
                code: ErrorCode::Other,
                message: "Paying hodl invoices disabled".to_string(),
            },
        );
        check_no_pending_invoices(&storage);

        // test in-flight payment
        let (invoice, _) = create_dummy_invoice(Some(1_000), Network::Regtest, None);
        node.expect_get_outbound_payment_status()
            .with(eq(invoice.payment_hash().into_32()))
            .returning(move |_| Some(HTLCStatus::InFlight));
        let event = create_nwc_request(&uri, invoice.to_string());
        let result = nwc.handle_nwc_request(event, &node, &nostr_manager).await;
        assert_eq!(result.unwrap(), None);
        check_no_pending_invoices(&storage);

        // test completed payment
        let (invoice, _) = create_dummy_invoice(Some(1_000), Network::Regtest, None);
        node.expect_get_outbound_payment_status()
            .with(eq(invoice.payment_hash().into_32()))
            .returning(move |_| Some(HTLCStatus::Succeeded));
        let event = create_nwc_request(&uri, invoice.to_string());
        let result = nwc.handle_nwc_request(event, &node, &nostr_manager).await;
        assert_eq!(result.unwrap(), None);
        check_no_pending_invoices(&storage);

        // test it goes to pending
        let (invoice, _) = create_dummy_invoice(Some(1_000), Network::Regtest, None);
        node.expect_get_outbound_payment_status()
            .with(eq(invoice.payment_hash().into_32()))
            .returning(move |_| None);
        let event = create_nwc_request(&uri, invoice.to_string());
        let result = nwc
            .handle_nwc_request(event.clone(), &node, &nostr_manager)
            .await;
        assert_eq!(result.unwrap(), None);

        let pending: Vec<PendingNwcInvoice> = storage
            .get_data(PENDING_NWC_EVENTS_KEY)
            .unwrap()
            .unwrap_or_default();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].invoice, invoice);
        assert_eq!(pending[0].event_id, event.id);
        assert_eq!(pending[0].index, Some(nwc.profile.index));
        assert_eq!(pending[0].pubkey, event.pubkey);
    }

    #[test]
    async fn test_clear_expired_pending_invoices() {
        let storage = MemoryStorage::default();
        let xprivkey = ExtendedPrivKey::new_master(Network::Regtest, &[0; 64]).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let nostr_manager = NostrManager::from_mnemonic(
            xprivkey,
            NostrKeySource::Derived,
            storage.clone(),
            None,
            Arc::new(MutinyLogger::default()),
            stop,
        )
        .unwrap();

        // check we start with no pending invoices
        let pending = nostr_manager.get_pending_nwc_invoices().unwrap();
        assert_eq!(pending.len(), 0);

        // add an expired invoice
        let expired = PendingNwcInvoice {
            index: Some(0),
            invoice: Bolt11Invoice::from_str(INVOICE).unwrap(),
            event_id: EventId::all_zeros(),
            pubkey: nostr_manager.public_key,
            identifier: None,
        };
        // add an unexpired invoice
        let unexpired = PendingNwcInvoice {
            index: Some(0),
            invoice: create_dummy_invoice(Some(1_000), Network::Regtest, None).0,
            event_id: EventId::all_zeros(),
            pubkey: nostr_manager.public_key,
            identifier: None,
        };
        storage
            .set_data(
                PENDING_NWC_EVENTS_KEY.to_string(),
                vec![expired, unexpired.clone()],
                None,
            )
            .unwrap();
        // make sure we added them
        let pending = nostr_manager.get_pending_nwc_invoices().unwrap();
        assert_eq!(pending.len(), 2);

        // check that the expired invoice is cleared
        nostr_manager.clear_expired_nwc_invoices().await.unwrap();
        let pending = nostr_manager.get_pending_nwc_invoices().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0], unexpired);
    }

    #[test]
    async fn test_failed_process_nwc_event_budget() {
        let storage = MemoryStorage::default();
        let mw = create_mutiny_wallet(storage.clone()).await;

        let xprivkey = ExtendedPrivKey::new_master(Network::Regtest, &[0; 64]).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let nostr_manager = NostrManager::from_mnemonic(
            xprivkey,
            NostrKeySource::Derived,
            storage.clone(),
            None,
            mw.logger.clone(),
            stop,
        )
        .unwrap();

        let budget = 10_000;
        let profile = nostr_manager
            .create_new_nwc_profile_internal(
                ProfileType::Normal {
                    name: "test".to_string(),
                },
                SpendingConditions::Budget(BudgetedSpendingConditions {
                    budget,
                    single_max: None,
                    payments: vec![],
                    period: BudgetPeriod::Seconds(10),
                }),
                NwcProfileTag::General,
                vec![Method::PayInvoice],
            )
            .unwrap();

        let secp = Secp256k1::new();
        let mut nwc = NostrWalletConnect::new(&secp, xprivkey, profile.profile()).unwrap();
        let uri = nwc.get_nwc_uri().unwrap().unwrap();

        // test failed payment goes to pending, we have no channels so it will fail
        let (invoice, _) = create_dummy_invoice(Some(10), Network::Regtest, None);
        let event = create_nwc_request(&uri, invoice.to_string());
        let result = nwc
            .handle_nwc_request(event.clone(), &mw, &nostr_manager)
            .await;
        assert!(result.unwrap().is_some()); // should get a error response
        let pending = nostr_manager.get_pending_nwc_invoices().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].invoice, invoice);
        assert_eq!(pending[0].event_id, event.id);
        assert_eq!(pending[0].index, Some(nwc.profile.index));
        assert_eq!(pending[0].pubkey, event.pubkey);

        // clear pending
        nostr_manager.deny_all_pending_nwc().await.unwrap();

        // test over budget payment goes to pending
        let (invoice, _) = create_dummy_invoice(Some(budget + 1), Network::Regtest, None);
        let event = create_nwc_request(&uri, invoice.to_string());
        let result = nwc
            .handle_nwc_request(event.clone(), &mw, &nostr_manager)
            .await;
        assert!(result.unwrap().is_some()); // should get a error response
        let pending = nostr_manager.get_pending_nwc_invoices().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].invoice, invoice);
        assert_eq!(pending[0].event_id, event.id);
        assert_eq!(pending[0].index, Some(nwc.profile.index));
        assert_eq!(pending[0].pubkey, event.pubkey);
    }

    #[test]
    async fn test_process_nwc_event_budget() {
        let storage = MemoryStorage::default();
        let logger = Arc::new(MutinyLogger::default());
        let mut node = MockInvoiceHandler::new();

        let amount_msats = 5_000;

        let (invoice, preimage) = create_dummy_invoice(Some(amount_msats), Network::Regtest, None);

        node.expect_skip_hodl_invoices().once().returning(|| true);
        node.expect_logger().return_const(MutinyLogger::default());
        node.expect_get_outbound_payment_status().return_const(None);
        node.expect_pay_invoice()
            .once()
            .returning(move |inv, _, _| {
                let mut mutiny_invoice: MutinyInvoice = inv.clone().into();
                mutiny_invoice.preimage = Some(preimage.to_lower_hex_string());
                mutiny_invoice.status = HTLCStatus::Succeeded;
                mutiny_invoice.last_updated = utils::now().as_secs();
                mutiny_invoice.fees_paid = Some(0);
                Ok(mutiny_invoice)
            });

        let xprivkey = ExtendedPrivKey::new_master(Network::Regtest, &[0; 64]).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let nostr_manager = NostrManager::from_mnemonic(
            xprivkey,
            NostrKeySource::Derived,
            storage.clone(),
            None,
            logger,
            stop,
        )
        .unwrap();

        let budget = 10_000;
        let profile = nostr_manager
            .create_new_nwc_profile_internal(
                ProfileType::Normal {
                    name: "test".to_string(),
                },
                SpendingConditions::Budget(BudgetedSpendingConditions {
                    budget,
                    single_max: None,
                    payments: vec![],
                    period: BudgetPeriod::Seconds(10),
                }),
                NwcProfileTag::General,
                vec![Method::PayInvoice],
            )
            .unwrap();

        let secp = Secp256k1::new();
        let mut nwc = NostrWalletConnect::new(&secp, xprivkey, profile.profile()).unwrap();
        let uri = nwc.get_nwc_uri().unwrap().unwrap();

        // test successful payment
        let event = create_nwc_request(&uri, invoice.to_string());
        let result = nwc
            .handle_nwc_request(event.clone(), &node, &nostr_manager)
            .await;
        let event = result.unwrap().unwrap();
        let content = decrypt(&uri.secret, &event.pubkey, &event.content).unwrap();
        let response: Response = Response::from_json(content).unwrap();
        let pending = nostr_manager.get_pending_nwc_invoices().unwrap();
        assert!(pending.is_empty());
        assert_eq!(response.result_type, Method::PayInvoice);
        assert!(response.error.is_none());

        match response.result {
            Some(ResponseResult::PayInvoice(PayInvoiceResponseResult { preimage: pre })) => {
                assert_eq!(pre, preimage.to_lower_hex_string());
            }
            _ => panic!("wrong response"),
        }

        match nwc.profile.spending_conditions {
            SpendingConditions::Budget(budget) => {
                assert_eq!(budget.payments.len(), 1);
                assert_eq!(budget.payments[0].amt, amount_msats / 1_000);
                assert_eq!(
                    budget.payments[0].hash,
                    invoice.payment_hash().into_32().to_lower_hex_string()
                );
            }
            _ => panic!("wrong spending conditions"),
        }
    }
}
