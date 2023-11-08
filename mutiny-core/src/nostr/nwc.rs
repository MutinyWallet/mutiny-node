use crate::error::MutinyError;
use crate::event::HTLCStatus;
use crate::nodemanager::NodeManager;
use crate::nostr::NostrManager;
use crate::storage::MutinyStorage;
use crate::utils;
use anyhow::anyhow;
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::secp256k1::{PublicKey, Secp256k1, Signing};
use bitcoin::util::bip32::ExtendedPrivKey;
use chrono::{DateTime, Datelike, Duration, NaiveDateTime, Utc};
use core::fmt;
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
            hash: invoice.payment_hash().to_hex(),
        };

        self.payments.push(payment);
    }

    pub fn remove_payment(&mut self, invoice: &Bolt11Invoice) {
        self.payments
            .retain(|p| p.hash != invoice.payment_hash().to_hex());
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
    pub relay: String,
    pub enabled: Option<bool>,
    /// Archived profiles will not be displayed
    pub archived: Option<bool>,
    /// Require approval before sending a payment
    #[serde(default)]
    pub spending_conditions: SpendingConditions,
    /// index to use to derive nostr keys for child index
    /// set to Option so that we keep using `index` for reserved + existing
    #[serde(default)]
    pub child_key_index: Option<u32>,
    #[serde(default)]
    pub tag: NwcProfileTag,
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
        let key_derivation_index = if let Some(s) = profile.child_key_index {
            s
        } else {
            profile.index
        };
        let (client_key, server_key) =
            NostrManager::<()>::derive_nwc_keys(context, xprivkey, key_derivation_index)?;

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
            self.client_key.secret_key().unwrap(),
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
                    result: Some(ResponseResult::PayInvoice(PayInvoiceResponseResult {
                        preimage,
                    })),
                })
            }
            Err(e) => {
                log_error!(node_manager.logger, "failed to pay invoice: {e}");
                Err(e)
            }
        }
    }

    async fn save_pending_nwc_invoice<S: MutinyStorage>(
        &self,
        nostr_manager: &NostrManager<S>,
        event_id: EventId,
        event_pk: XOnlyPublicKey,
        invoice: Bolt11Invoice,
    ) -> anyhow::Result<()> {
        let pending = PendingNwcInvoice {
            index: self.profile.index,
            invoice,
            event_id,
            pubkey: event_pk,
        };
        nostr_manager.pending_nwc_lock.lock().await;

        let mut current: Vec<PendingNwcInvoice> = nostr_manager
            .storage
            .get_data(PENDING_NWC_EVENTS_KEY)?
            .unwrap_or_default();

        if !current.contains(&pending) {
            current.push(pending);

            nostr_manager
                .storage
                .set_data(PENDING_NWC_EVENTS_KEY, current, None)?;
        }

        Ok(())
    }

    /// Handle a Nostr Wallet Connect request
    ///
    /// Returns a response event if one is needed
    pub async fn handle_nwc_request<S: MutinyStorage>(
        &mut self,
        event: Event,
        node_manager: &NodeManager<S>,
        from_node: &PublicKey,
        nostr_manager: &NostrManager<S>,
    ) -> anyhow::Result<Option<Event>> {
        let client_pubkey = self.client_key.public_key();
        let mut needs_save = false;
        let mut needs_delete = false;
        if self.profile.active()
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

            let invoice = match req.params {
                RequestParams::PayInvoice(params) => Bolt11Invoice::from_str(&params.invoice)
                    .map_err(|_| anyhow!("Failed to parse invoice"))?,
                _ => return Err(anyhow!("Invalid request params for pay invoice")),
            };

            // if the invoice has expired, skip it
            if invoice.would_expire(utils::now()) {
                return Ok(None);
            }

            // if the invoice has no amount, we cannot pay it
            if invoice.amount_milli_satoshis().is_none() {
                log_warn!(
                    node_manager.logger,
                    "NWC Invoice amount not set, cannot pay: {invoice}"
                );
                return Ok(None);
            }

            // if we have already paid or are attempting to pay this invoice, skip it
            let node = node_manager.get_node(from_node).await?;
            if node
                .get_invoice(&invoice)
                .is_ok_and(|i| matches!(i.status, HTLCStatus::Succeeded | HTLCStatus::InFlight))
            {
                return Ok(None);
            }
            drop(node);

            // if we need approval, just save in the db for later
            match self.profile.spending_conditions.clone() {
                SpendingConditions::SingleUse(mut single_use) => {
                    let msats = invoice.amount_milli_satoshis().unwrap();

                    // get the status of the previous payment attempt, if one exists
                    let prev_status: Option<HTLCStatus> = match single_use.payment_hash {
                        Some(payment_hash) => {
                            let hash: [u8; 32] =
                                FromHex::from_hex(&payment_hash).expect("invalid hash");
                            let node = node_manager.get_node(from_node).await?;
                            node.persister
                                .read_payment_info(&hash, false, &nostr_manager.logger)
                                .map(|p| p.status)
                        }
                        None => None,
                    };

                    // check if we have already spent
                    let content = match prev_status {
                        Some(HTLCStatus::Succeeded) => {
                            needs_delete = true;
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
                                match self
                                    .pay_nwc_invoice(node_manager, from_node, &invoice)
                                    .await
                                {
                                    Ok(resp) => {
                                        // after it is spent, delete the profile
                                        // so that it cannot be used again
                                        needs_delete = true;
                                        resp
                                    }
                                    Err(e) => {
                                        let mut code = ErrorCode::InsufficientBalance;
                                        if let MutinyError::PaymentTimeout = e {
                                            // if a payment times out, we should save the payment_hash
                                            // and track if the payment settles or not. If it does not
                                            // we can try again later.
                                            single_use.payment_hash =
                                                Some(invoice.payment_hash().to_hex());
                                            self.profile.spending_conditions =
                                                SpendingConditions::SingleUse(single_use);
                                            needs_save = true;

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
                                    message: "Previous payment still in flight, cannot pay"
                                        .to_string(),
                                }),
                                result: None,
                            }
                        }
                    };

                    let encrypted = encrypt(&server_key, &client_pubkey, content.as_json())?;

                    let p_tag = Tag::PubKey(event.pubkey, None);
                    let e_tag = Tag::Event(event.id, None, None);
                    let response =
                        EventBuilder::new(Kind::WalletConnectResponse, encrypted, &[p_tag, e_tag])
                            .to_event(&self.server_key)?;

                    if needs_delete {
                        nostr_manager.delete_nwc_profile(self.profile.index)?;
                    } else if needs_save {
                        nostr_manager.save_nwc_profile(self.clone())?;
                    }

                    return Ok(Some(response));
                }
                SpendingConditions::RequireApproval => {
                    self.save_pending_nwc_invoice(nostr_manager, event.id, event.pubkey, invoice)
                        .await?;

                    if needs_save {
                        nostr_manager.save_nwc_profile(self.clone())?;
                    }

                    return Ok(None);
                }
                SpendingConditions::Budget(mut budget) => {
                    let sats = invoice.amount_milli_satoshis().unwrap() / 1_000;

                    let budget_err = if budget.single_max.is_some_and(|max| sats > max) {
                        Some("Invoice amount too high.")
                    } else if budget.sum_payments() + sats > budget.budget {
                        let node = node_manager.get_node(from_node).await?;
                        // budget might not actually be exceeded, we should verify that the payments
                        // all went through, and if not, remove them from the budget
                        budget.payments.retain(|p| {
                            let hash: [u8; 32] = FromHex::from_hex(&p.hash).unwrap();
                            match node.persister.read_payment_info(
                                &hash,
                                false,
                                &nostr_manager.logger,
                            ) {
                                Some(info) => info.status != HTLCStatus::Failed, // remove failed payments from budget
                                None => true, // if we can't find the payment, keep it to be safe
                            }
                        });

                        // update budget with removed payments
                        self.profile.spending_conditions =
                            SpendingConditions::Budget(budget.clone());

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
                            match self
                                .pay_nwc_invoice(node_manager, from_node, &invoice)
                                .await
                            {
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

                    let encrypted = encrypt(&server_key, &client_pubkey, content.as_json())?;

                    let p_tag = Tag::PubKey(event.pubkey, None);
                    let e_tag = Tag::Event(event.id, None, None);
                    let response =
                        EventBuilder::new(Kind::WalletConnectResponse, encrypted, &[p_tag, e_tag])
                            .to_event(&self.server_key)?;

                    return Ok(Some(response));
                }
            }
        }

        if needs_delete {
            nostr_manager.delete_nwc_profile(self.profile.index)?;
        } else if needs_save {
            nostr_manager.save_nwc_profile(self.clone())?;
        }

        Ok(None)
    }

    pub fn nwc_profile(&self) -> NwcProfile {
        NwcProfile {
            name: self.profile.name.clone(),
            index: self.profile.index,
            relay: self.profile.relay.clone(),
            enabled: self.profile.enabled,
            archived: self.profile.archived,
            nwc_uri: self.get_nwc_uri().expect("failed to get nwc uri"),
            spending_conditions: self.profile.spending_conditions.clone(),
            child_key_index: self.profile.child_key_index,
            tag: self.profile.tag,
        }
    }
}

/// Struct for externally exposing a nostr wallet connect profile
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NwcProfile {
    pub name: String,
    pub index: u32,
    pub relay: String,
    pub enabled: Option<bool>,
    pub archived: Option<bool>,
    pub nwc_uri: String,
    #[serde(default)]
    pub spending_conditions: SpendingConditions,
    #[serde(default)]
    pub child_key_index: Option<u32>,
    #[serde(default)]
    pub tag: NwcProfileTag,
}

impl NwcProfile {
    pub(crate) fn profile(&self) -> Profile {
        Profile {
            name: self.name.clone(),
            index: self.index,
            relay: self.relay.clone(),
            archived: self.archived,
            enabled: self.enabled,
            spending_conditions: self.spending_conditions.clone(),
            child_key_index: self.child_key_index,
            tag: self.tag,
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
