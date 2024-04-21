use crate::error::MutinyError;
use crate::event::HTLCStatus;
use crate::nostr::client::NostrClient;
use crate::nostr::nip49::NIP49Confirmation;
use crate::nostr::primal::PrimalApi;
use crate::nostr::{derive_nwc_keys, NostrManager};
use crate::storage::MutinyStorage;
use crate::{utils, MutinyInvoice};
use crate::{CustomTLV, InvoiceHandler};
use anyhow::anyhow;
use bitcoin::bip32::ExtendedPrivKey;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, Secp256k1, Signing, ThirtyTwoByteHash};
use bitcoin::Network;
use chrono::{DateTime, Datelike, Duration, NaiveDateTime, Utc};
use core::fmt;
use hex_conservative::DisplayHex;
use itertools::Itertools;
use lightning::ln::{PaymentHash, PaymentPreimage};
use lightning::util::logger::Logger;
use lightning::{log_error, log_warn};
use lightning_invoice::Bolt11Invoice;
use nostr::nips::nip04::{decrypt, encrypt};
use nostr::nips::nip47::*;
use nostr::{Event, EventBuilder, EventId, Filter, JsonUtil, Keys, Kind, Tag, Timestamp};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::str::FromStr;
use url::Url;

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
    pub fn add_payment(&mut self, payment: &mut TrackedPayment) {
        let time = utils::now().as_secs();
        payment.time = time;
        self.payments.push(payment.clone());
    }

    pub fn remove_payment(&mut self, payment: &TrackedPayment) {
        self.payments.retain(|p| p.hash != payment.hash);
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NwcResponse {
    SingleEvent(Event),
    MultiEvent(Vec<Event>),
}

struct PayInvoiceRequest {
    params: PayInvoiceRequestParams,
    is_multi_pay: bool,
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
            derive_nwc_keys(context, xprivkey, key_derivation_index)?;

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
        uri_relay: Url,
        secret: String,
        commands: Vec<Method>,
    ) -> anyhow::Result<Option<Event>> {
        // skip non-NWA profiles
        if self.profile.client_key.is_none() {
            return Ok(None);
        }

        // if the relay is the same as the profile, we don't need to send it
        let relay = if uri_relay == Url::parse(&self.profile.relay)? {
            None
        } else {
            Some(self.profile.relay.clone())
        };

        let json = NIP49Confirmation {
            secret,
            commands,
            relay,
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

    async fn save_pending_nwc_invoice<S: MutinyStorage, P: PrimalApi, C: NostrClient>(
        &self,
        nostr_manager: &NostrManager<S, P, C>,
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

    fn build_nwc_response_event(
        &self,
        event: Event,
        content: Response,
        id: Option<String>,
    ) -> anyhow::Result<Event> {
        let encrypted = encrypt(
            self.server_key.secret_key()?,
            &self.client_key.public_key(),
            content.as_json(),
        )?;

        let p_tag = Tag::public_key(event.pubkey);
        let e_tag = Tag::event(event.id);

        let tags = match id {
            Some(id) => vec![p_tag, e_tag, Tag::Identifier(id)],
            None => vec![p_tag, e_tag],
        };

        let response = EventBuilder::new(Kind::WalletConnectResponse, encrypted, tags)
            .to_event(&self.server_key)?;

        Ok(response)
    }

    /// Handle a Nostr Wallet Connect request
    ///
    /// Returns a response event if one is needed
    pub async fn handle_nwc_request<S: MutinyStorage, P: PrimalApi, C: NostrClient>(
        &mut self,
        event: Event,
        node: &impl InvoiceHandler,
        nostr_manager: &NostrManager<S, P, C>,
    ) -> anyhow::Result<Option<NwcResponse>> {
        let client_pubkey = self.client_key.public_key();
        let mut needs_save = false;
        let mut needs_delete = false;
        let mut result = None;
        if event.kind == Kind::WalletConnectRequest && event.pubkey == client_pubkey {
            let server_key = self.server_key.secret_key()?;

            let decrypted = decrypt(server_key, &client_pubkey, &event.content)?;
            let req: Request = match Request::from_json(decrypted) {
                Ok(req) => req,
                Err(e) => {
                    log_warn!(
                        nostr_manager.logger,
                        "Failed to parse request: {e}, skipping..."
                    );
                    let error_event = self.get_skipped_error_event(
                        &event,
                        Method::PayInvoice, // most likely it's a pay invoice request
                        ErrorCode::NotImplemented,
                        "Failed to parse request.".to_string(),
                    )?;
                    if let Err(e) = nostr_manager.client.send_event(error_event.clone()).await {
                        return Err(anyhow!("Error sending NWC event: {}", e));
                    }
                    return Ok(Some(NwcResponse::SingleEvent(error_event)));
                }
            };

            // only respond to commands sent to active profiles
            if !self.profile.active() {
                let error_event = self.get_skipped_error_event(
                    &event,
                    req.method,
                    ErrorCode::Other,
                    "Nostr profile inactive".to_string(),
                )?;
                if let Err(e) = nostr_manager.client.send_event(error_event.clone()).await {
                    return Err(anyhow!("Error sending NWC event: {}", e));
                }
                return Ok(Some(NwcResponse::SingleEvent(error_event)));
            }

            // only respond to commands that are allowed by the profile
            if !self.profile.available_commands().contains(&req.method) {
                let error_event = self.get_skipped_error_event(
                    &event,
                    req.method,
                    ErrorCode::NotImplemented,
                    "Command is not supported.".to_string(),
                )?;
                if let Err(e) = nostr_manager.client.send_event(error_event.clone()).await {
                    return Err(anyhow!("Error sending NWC event: {}", e));
                }
                return Ok(Some(NwcResponse::SingleEvent(error_event)));
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
                RequestParams::MakeInvoice(params) => {
                    self.handle_make_invoice_request(event, node, &nostr_manager.client, params)
                        .await?
                }
                RequestParams::LookupInvoice(params) => {
                    self.handle_lookup_invoice_request(event, node, &nostr_manager.client, params)
                        .await?
                }
                RequestParams::ListTransactions(params) => {
                    self.handle_list_transactions(event, node, &nostr_manager.client, params)
                        .await?
                }
                RequestParams::GetBalance => {
                    self.handle_get_balance_request(event, &nostr_manager.client)
                        .await?
                }
                RequestParams::GetInfo => {
                    self.handle_get_info_request(event, node, &nostr_manager.client)
                        .await?
                }
                RequestParams::MultiPayInvoice(params) => {
                    self.handle_multi_pay_invoice_request(
                        event,
                        node,
                        nostr_manager,
                        params,
                        &mut needs_delete,
                        &mut needs_save,
                    )
                    .await?
                }
                RequestParams::PayKeysend(params) => {
                    self.handle_pay_keysend_request(event, node, nostr_manager, params)
                        .await?
                }
                RequestParams::MultiPayKeysend(params) => {
                    self.handle_multi_pay_keysend_request(event, node, nostr_manager, params)
                        .await?
                }
            };
        }

        if needs_delete {
            nostr_manager.delete_nwc_profile(self.profile.index)?;
        } else if needs_save {
            nostr_manager.save_nwc_profile(self.clone())?;
        }

        Ok(result)
    }

    async fn handle_get_info_request(
        &self,
        event: Event,
        node: &impl InvoiceHandler,
        client: &impl NostrClient,
    ) -> anyhow::Result<Option<NwcResponse>> {
        let network = match node.get_network() {
            Network::Bitcoin => "mainnet",
            Network::Testnet => "testnet",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
            net => unreachable!("Unknown network: {net}"),
        };

        let block = node.get_best_block().await?;

        let content = Response {
            result_type: Method::GetInfo,
            error: None,
            result: Some(ResponseResult::GetInfo(GetInfoResponseResult {
                alias: "Mutiny".to_string(),
                color: "000000".to_string(),
                // give an arbitrary pubkey, no need to leak ours
                pubkey: "02cae09cf2c8842ace44068a5bf3117a494ebbf69a99e79712483c36f97cdb7b54"
                    .to_string(),
                network: network.to_string(),
                block_height: block.height(),
                block_hash: block.block_hash().to_string(),
                methods: self
                    .profile
                    .available_commands()
                    .iter()
                    .map(|c| c.to_string())
                    .collect(),
            })),
        };

        let response_event = self.build_nwc_response_event(event, content, None)?;
        if let Err(e) = client.send_event(response_event.clone()).await {
            return Err(anyhow!("Error sending NWC event: {}", e));
        }
        Ok(Some(NwcResponse::SingleEvent(response_event)))
    }

    async fn handle_get_balance_request(
        &mut self,
        event: Event,
        client: &impl NostrClient,
    ) -> anyhow::Result<Option<NwcResponse>> {
        // Just return our current budget amount, don't leak our actual wallet balance
        let balance_sats = match &self.profile.spending_conditions {
            SpendingConditions::SingleUse(single_use) => {
                // if this nwc is used, we have no balance remaining
                match single_use.payment_hash {
                    Some(_) => 0,
                    None => single_use.amount_sats,
                }
            }
            SpendingConditions::Budget(budget) => budget.budget_remaining(),
            SpendingConditions::RequireApproval => 0,
        };

        let content = Response {
            result_type: Method::GetBalance,
            error: None,
            result: Some(ResponseResult::GetBalance(GetBalanceResponseResult {
                balance: balance_sats * 1_000, // return in msats
            })),
        };

        let response_event = self.build_nwc_response_event(event, content, None)?;
        if let Err(e) = client.send_event(response_event.clone()).await {
            return Err(anyhow!("Error sending NWC event: {}", e));
        }
        Ok(Some(NwcResponse::SingleEvent(response_event)))
    }

    async fn handle_list_transactions(
        &mut self,
        event: Event,
        node: &impl InvoiceHandler,
        client: &impl NostrClient,
        params: ListTransactionsRequestParams,
    ) -> anyhow::Result<Option<NwcResponse>> {
        let label = self
            .profile
            .label
            .clone()
            .unwrap_or(self.profile.name.clone());
        let invoices = node.get_payments_by_label(&label).await?;

        let from = params.from.unwrap_or(0);
        let until = params.until.unwrap_or(utils::now().as_secs());
        let unpaid = params.unpaid.unwrap_or(false);

        let mut invoices: Vec<MutinyInvoice> = invoices
            .into_iter()
            .filter(|invoice| {
                let created_at = invoice
                    .bolt11
                    .as_ref()
                    .map(|b| b.duration_since_epoch().as_secs())
                    .unwrap_or(invoice.last_updated);

                if unpaid {
                    created_at > from && created_at < until
                } else {
                    created_at > from
                        && created_at < until
                        && invoice.status == HTLCStatus::Succeeded
                }
            })
            .collect();

        if params.transaction_type.is_some() {
            let incoming = params.transaction_type.unwrap() == TransactionType::Incoming;
            invoices.retain(|invoice| invoice.inbound == incoming);
        }

        let mut transactions = Vec::with_capacity(invoices.len());
        for invoice in invoices {
            let transaction: LookupInvoiceResponseResult = invoice.into();
            transactions.push(transaction);
        }
        // sort in descending order by creation time
        transactions.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        let offset = params.offset.map(|o| o as usize);
        let limit = params.limit.map(|l| l as usize);

        let (start, end) = match (offset, limit) {
            (None, None) => (0, transactions.len()),
            (Some(offset), Some(limit)) => {
                let end = offset.saturating_add(limit).min(transactions.len());
                (offset, end)
            }
            (Some(offset), None) => (offset, transactions.len()),
            (None, Some(limit)) => (0, limit),
        };

        // handle out of bounds
        let start = start.min(transactions.len());
        let end = end.min(transactions.len());

        // handle start > end
        if start > end {
            transactions = vec![];
        } else {
            transactions = transactions[start..end].to_vec();
        }

        let content = Response {
            result_type: Method::ListTransactions,
            error: None,
            result: Some(ResponseResult::ListTransactions(transactions)),
        };

        let response_event = self.build_nwc_response_event(event, content, None)?;
        if let Err(e) = client.send_event(response_event.clone()).await {
            return Err(anyhow!("Error sending NWC event: {}", e));
        }
        Ok(Some(NwcResponse::SingleEvent(response_event)))
    }

    async fn handle_make_invoice_request(
        &mut self,
        event: Event,
        node: &impl InvoiceHandler,
        client: &impl NostrClient,
        params: MakeInvoiceRequestParams,
    ) -> anyhow::Result<Option<NwcResponse>> {
        // FIXME currently we are ignoring the description and expiry params
        let amount_sats = params.amount / 1_000;

        let label = self
            .profile
            .label
            .clone()
            .unwrap_or(self.profile.name.clone());

        let response_event = match node.create_invoice(amount_sats, vec![label]).await {
            Err(e) => self.get_skipped_error_event(
                &event,
                Method::MakeInvoice,
                ErrorCode::Other,
                format!("Failed to create invoice: {:?}", e),
            )?,
            Ok(invoice) => {
                let bolt11 = invoice.bolt11.expect("just made");

                let content = Response {
                    result_type: Method::MakeInvoice,
                    error: None,
                    result: Some(ResponseResult::MakeInvoice(MakeInvoiceResponseResult {
                        invoice: bolt11.to_string(),
                        payment_hash: bolt11.payment_hash().to_string(),
                    })),
                };

                self.build_nwc_response_event(event, content, None)?
            }
        };

        if let Err(e) = client.send_event(response_event.clone()).await {
            return Err(anyhow!("Error sending NWC event: {}", e));
        }
        Ok(Some(NwcResponse::SingleEvent(response_event)))
    }

    async fn handle_lookup_invoice_request(
        &mut self,
        event: Event,
        node: &impl InvoiceHandler,
        client: &impl NostrClient,
        params: LookupInvoiceRequestParams,
    ) -> anyhow::Result<Option<NwcResponse>> {
        let invoice = match params.payment_hash {
            Some(payment_hash) => {
                let hash: [u8; 32] = FromHex::from_hex(&payment_hash)
                    .map_err(|e| anyhow!("Failed to parse payment_hash {payment_hash}: {e}"))?;
                node.lookup_payment(&hash).await
            }
            None => match params.bolt11 {
                Some(bolt11) => {
                    let invoice = Bolt11Invoice::from_str(&bolt11)?;
                    let hash = invoice.payment_hash().into_32();
                    node.lookup_payment(&hash).await
                }
                None => return Err(anyhow!("No payment_hash or bolt11 provided")),
            },
        };

        let content = match invoice {
            None => Response {
                result_type: Method::LookupInvoice,
                error: Some(NIP47Error {
                    code: ErrorCode::NotFound,
                    message: "Invoice not found".to_string(),
                }),
                result: None,
            },
            Some(invoice) => {
                let result: LookupInvoiceResponseResult = invoice.into();

                Response {
                    result_type: Method::LookupInvoice,
                    error: None,
                    result: Some(ResponseResult::LookupInvoice(result)),
                }
            }
        };

        let response_event = self.build_nwc_response_event(event, content, None)?;
        if let Err(e) = client.send_event(response_event.clone()).await {
            return Err(anyhow!("Error sending NWC event: {}", e));
        }
        Ok(Some(NwcResponse::SingleEvent(response_event)))
    }

    async fn check_payment_within_budget(
        &mut self,
        node: &impl InvoiceHandler,
        budget: &mut BudgetedSpendingConditions,
        payment_amount_sats: u64,
    ) -> Result<(), String> {
        if budget
            .single_max
            .is_some_and(|max| payment_amount_sats > max)
        {
            Err("Payment amount too high".to_string())
        } else if budget.sum_payments() + payment_amount_sats > budget.budget {
            // budget might not actually be exceeded, we should verify that the payments
            // all went through, and if not, remove them from the budget
            let mut indices_to_remove = Vec::new();
            for (index, p) in budget.payments.iter().enumerate() {
                let hash: [u8; 32] = match FromHex::from_hex(&p.hash) {
                    Ok(hash) => hash,
                    Err(e) => return Err(format!("invalid hash: {}", e)),
                };
                indices_to_remove.push((index, hash));
            }

            let futures: Vec<_> = indices_to_remove
                .iter()
                .map(|(index, hash)| async move {
                    match node.lookup_payment(hash).await.map(|i| i.status) {
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
            if budget.sum_payments() + payment_amount_sats > budget.budget {
                Err("Budget exceeded.".to_string())
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    async fn handle_nwc_invoice_payment<S: MutinyStorage, P: PrimalApi, C: NostrClient>(
        &mut self,
        event: Event,
        node: &impl InvoiceHandler,
        nostr_manager: &NostrManager<S, P, C>,
        request: PayInvoiceRequest,
        needs_delete: &mut bool,
        needs_save: &mut bool,
    ) -> anyhow::Result<Option<Event>> {
        let method = if request.is_multi_pay {
            Method::MultiPayInvoice
        } else {
            Method::PayInvoice
        };

        let invoice: Bolt11Invoice = match check_valid_nwc_invoice(&request.params, node).await {
            Ok(Some(invoice)) => invoice,
            Ok(None) => return Ok(None),
            Err(err_string) => {
                return self
                    .get_skipped_error_event(&event, method, ErrorCode::Other, err_string)
                    .map(Some);
            }
        };

        match self.profile.spending_conditions.clone() {
            SpendingConditions::SingleUse(mut single_use) => {
                let msats = invoice.amount_milli_satoshis().unwrap();

                // get the status of the previous payment attempt, if one exists
                let prev_status: Option<HTLCStatus> = match single_use.payment_hash {
                    Some(payment_hash) => {
                        let hash: [u8; 32] =
                            FromHex::from_hex(&payment_hash).expect("invalid hash");
                        node.lookup_payment(&hash).await.map(|i| i.status)
                    }
                    None => None,
                };

                // check if we have already spent
                let content = match prev_status {
                    Some(HTLCStatus::Succeeded) => {
                        *needs_delete = true;
                        Response {
                            result_type: method,
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
                                            request.params.id.clone(),
                                        )
                                        .await?
                                    }
                                    Response {
                                        result_type: method,
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
                                result_type: method,
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
                            result_type: method,
                            error: Some(NIP47Error {
                                code: ErrorCode::RateLimited,
                                message: "Previous payment still in flight, cannot pay".to_string(),
                            }),
                            result: None,
                        }
                    }
                };

                if *needs_delete {
                    nostr_manager.delete_nwc_profile(self.profile.index)?;
                } else if *needs_save {
                    nostr_manager.save_nwc_profile(self.clone())?;
                }

                let response_event =
                    self.build_nwc_response_event(event, content, request.params.id)?;
                Ok(Some(response_event))
            }
            // if we need approval, just save in the db for later
            SpendingConditions::RequireApproval => {
                self.save_pending_nwc_invoice(
                    nostr_manager,
                    event.id,
                    event.pubkey,
                    invoice,
                    request.params.id,
                )
                .await?;

                if *needs_save {
                    nostr_manager.save_nwc_profile(self.clone())?;
                }
                Ok(None)
            }
            SpendingConditions::Budget(mut budget) => {
                let sats = invoice.amount_milli_satoshis().unwrap() / 1_000;

                let content = match self
                    .check_payment_within_budget(node, &mut budget, sats)
                    .await
                {
                    Err(err) => {
                        log_warn!(nostr_manager.logger, "Attempted to exceed budget: {err}");
                        // add to manual approval list
                        self.save_pending_nwc_invoice(
                            nostr_manager,
                            event.id,
                            event.pubkey,
                            invoice,
                            request.params.id.clone(),
                        )
                        .await?;
                        Response {
                            result_type: method,
                            error: Some(NIP47Error {
                                code: ErrorCode::QuotaExceeded,
                                message: err,
                            }),
                            result: None,
                        }
                    }
                    Ok(_) => {
                        let mut payment = TrackedPayment {
                            time: utils::now().as_secs(),
                            amt: sats,
                            hash: invoice.payment_hash().to_string(),
                        };
                        // add payment to budget
                        budget.add_payment(&mut payment);
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
                                        budget.remove_payment(&payment);
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

                                        budget.remove_payment(&payment);
                                        self.profile.spending_conditions =
                                            SpendingConditions::Budget(budget.clone());

                                        nostr_manager.save_nwc_profile(self.clone())?;

                                        // for non-timeout errors, add to manual approval list
                                        self.save_pending_nwc_invoice(
                                            nostr_manager,
                                            event.id,
                                            event.pubkey,
                                            invoice,
                                            request.params.id.clone(),
                                        )
                                        .await?
                                    }
                                }

                                Response {
                                    result_type: method,
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

                let response_event =
                    self.build_nwc_response_event(event, content, request.params.id)?;
                Ok(Some(response_event))
            }
        }
    }

    async fn handle_pay_invoice_request<S: MutinyStorage, P: PrimalApi, C: NostrClient>(
        &mut self,
        event: Event,
        node: &impl InvoiceHandler,
        nostr_manager: &NostrManager<S, P, C>,
        params: PayInvoiceRequestParams,
        needs_delete: &mut bool,
        needs_save: &mut bool,
    ) -> anyhow::Result<Option<NwcResponse>> {
        let pay_invoice_request = PayInvoiceRequest {
            params,
            is_multi_pay: false,
        };

        match self
            .handle_nwc_invoice_payment(
                event.clone(),
                node,
                nostr_manager,
                pay_invoice_request,
                needs_delete,
                needs_save,
            )
            .await
        {
            Ok(Some(response_event)) => {
                if let Err(e) = nostr_manager
                    .client
                    .send_event(response_event.clone())
                    .await
                {
                    return Err(anyhow!("Error sending NWC event: {}", e));
                }
                Ok(Some(NwcResponse::SingleEvent(response_event)))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(anyhow!("error handling pay_invoice_request: {}", e)),
        }
    }

    async fn handle_multi_pay_invoice_request<S: MutinyStorage, P: PrimalApi, C: NostrClient>(
        &mut self,
        event: Event,
        node: &impl InvoiceHandler,
        nostr_manager: &NostrManager<S, P, C>,
        params: MultiPayInvoiceRequestParams,
        needs_delete: &mut bool,
        needs_save: &mut bool,
    ) -> anyhow::Result<Option<NwcResponse>> {
        let mut response_events: Vec<Event> = Vec::with_capacity(params.invoices.len());

        for param in params.invoices {
            let pay_invoice_request = PayInvoiceRequest {
                params: param,
                is_multi_pay: true,
            };
            match self
                .handle_nwc_invoice_payment(
                    event.clone(),
                    node,
                    nostr_manager,
                    pay_invoice_request,
                    needs_delete,
                    needs_save,
                )
                .await
            {
                Ok(Some(response_event)) => {
                    if let Err(e) = nostr_manager
                        .client
                        .send_event(response_event.clone())
                        .await
                    {
                        log_error!(
                            nostr_manager.logger,
                            "Error sending multi_pay_invoice nwc response event: {}",
                            e
                        )
                    } else {
                        response_events.push(response_event);
                    }
                }
                Ok(None) => continue,
                Err(e) => {
                    log_error!(
                        nostr_manager.logger,
                        "Error handling multi_pay_invoice request: {}",
                        e
                    )
                }
            }
        }

        if response_events.is_empty() {
            Ok(None)
        } else {
            Ok(Some(NwcResponse::MultiEvent(response_events)))
        }
    }

    async fn handle_nwc_keysend_payment<S: MutinyStorage, P: PrimalApi, C: NostrClient>(
        &mut self,
        event: Event,
        node: &impl InvoiceHandler,
        nostr_manager: &NostrManager<S, P, C>,
        params: PayKeysendRequestParams,
        is_multi_keysend: bool,
    ) -> anyhow::Result<Option<Event>> {
        let method = if is_multi_keysend {
            Method::MultiPayKeysend
        } else {
            Method::PayKeysend
        };

        match self.profile.spending_conditions.clone() {
            SpendingConditions::SingleUse(_) => {
                // ignore this case since keysend payment requests are not generated from mutiny gifts
                Ok(None)
            }
            SpendingConditions::RequireApproval => {
                // respond with error
                // only do keysend payments for budgeted profiles
                let content = Response {
                    result_type: method,
                    error: Some(NIP47Error {
                        code: ErrorCode::Unauthorized,
                        message: String::from("Keysend only supported for profiles with a budget"),
                    }),
                    result: None,
                };

                let response_event = self.build_nwc_response_event(event, content, params.id)?;
                Ok(Some(response_event))
            }
            SpendingConditions::Budget(mut budget) => {
                // generate deterministic preimage for keysend payment from event info
                let preimage = match params.preimage {
                    Some(preimage) => {
                        let preimage = preimage.into_bytes();
                        if preimage.len() != 32 {
                            return Err(anyhow!("invalid preimage in NWC keysend request event"));
                        }
                        let mut preimage_bytes = [0; 32];
                        preimage_bytes.copy_from_slice(&preimage);
                        PaymentPreimage(preimage_bytes)
                    }
                    None => {
                        let server_key = self.server_key.secret_key()?;
                        let mut input = event.id.to_string();
                        input.push_str(&server_key.to_string());
                        if let Some(ref id) = params.id {
                            input.push_str(id.as_str());
                        };
                        PaymentPreimage(Sha256::hash(input.as_bytes()).into_32())
                    }
                };
                let payment_hash = PaymentHash(Sha256::hash(&preimage.0).into_32());

                // skip if keysend payment has already been done or in-flight
                if let Some(payment) = node.lookup_payment(&payment_hash.0).await {
                    if payment.status == HTLCStatus::Succeeded
                        || payment.status == HTLCStatus::InFlight
                    {
                        log_warn!(nostr_manager.logger, "keysend payment already made");
                        return Ok(None);
                    }
                }

                let sats = params.amount / 1000;

                // now only try keysend payment if within budget
                // if it falls out of budget return, send error
                let content = match self
                    .check_payment_within_budget(node, &mut budget, sats)
                    .await
                {
                    Err(err) => {
                        log_warn!(nostr_manager.logger, "Attempted to exceed budget: {err}");
                        Response {
                            result_type: method,
                            error: Some(NIP47Error {
                                code: ErrorCode::QuotaExceeded,
                                message: err,
                            }),
                            result: None,
                        }
                    }
                    Ok(_) => {
                        let mut payment = TrackedPayment {
                            time: utils::now().as_secs(),
                            amt: sats,
                            hash: payment_hash.to_string(),
                        };
                        // add payment to budget
                        budget.add_payment(&mut payment);
                        self.profile.spending_conditions =
                            SpendingConditions::Budget(budget.clone());
                        // persist budget before payment to protect against it not saving after
                        nostr_manager.save_nwc_profile(self.clone())?;

                        let to_node_pubkey = PublicKey::from_str(params.pubkey.as_str())?;

                        let label = self
                            .profile
                            .label
                            .clone()
                            .unwrap_or(self.profile.name.clone());

                        let tlvs = params
                            .tlv_records
                            .into_iter()
                            .map(|record| CustomTLV {
                                tlv_type: record.tlv_type,
                                value: record.value,
                            })
                            .collect();

                        // attempt keysend payment now
                        match node
                            .keysend(to_node_pubkey, sats, tlvs, vec![label], Some(preimage.0))
                            .await
                        {
                            Ok(_) => Response {
                                result_type: method,
                                error: None,
                                result: Some(ResponseResult::PayKeysend(
                                    PayKeysendResponseResult {
                                        preimage: preimage.to_string(),
                                    },
                                )),
                            },
                            Err(e) => {
                                log_warn!(nostr_manager.logger, "Failed send keysend payment: {e}. Removing from payment budget");
                                budget.remove_payment(&payment);
                                self.profile.spending_conditions =
                                    SpendingConditions::Budget(budget.clone());
                                nostr_manager.save_nwc_profile(self.clone())?;

                                Response {
                                    result_type: method,
                                    error: Some(NIP47Error {
                                        code: ErrorCode::PaymentFailed,
                                        message: String::from("failed to send keysend payment"),
                                    }),
                                    result: None,
                                }
                            }
                        }
                    }
                };

                let response_event = self.build_nwc_response_event(event, content, params.id)?;
                Ok(Some(response_event))
            }
        }
    }

    async fn handle_pay_keysend_request<S: MutinyStorage, P: PrimalApi, C: NostrClient>(
        &mut self,
        event: Event,
        node: &impl InvoiceHandler,
        nostr_manager: &NostrManager<S, P, C>,
        params: PayKeysendRequestParams,
    ) -> anyhow::Result<Option<NwcResponse>> {
        match self
            .handle_nwc_keysend_payment(event, node, nostr_manager, params, false)
            .await
        {
            Ok(Some(response_event)) => {
                if let Err(e) = nostr_manager
                    .client
                    .send_event(response_event.clone())
                    .await
                {
                    return Err(anyhow!("Error sending NWC event: {}", e));
                }
                Ok(Some(NwcResponse::SingleEvent(response_event)))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(anyhow!("error handling pay_keysend request: {}", e)),
        }
    }

    async fn handle_multi_pay_keysend_request<S: MutinyStorage, P: PrimalApi, C: NostrClient>(
        &mut self,
        event: Event,
        node: &impl InvoiceHandler,
        nostr_manager: &NostrManager<S, P, C>,
        params: MultiPayKeysendRequestParams,
    ) -> anyhow::Result<Option<NwcResponse>> {
        let mut response_events: Vec<Event> = Vec::with_capacity(params.keysends.len());

        for param in params.keysends {
            match self
                .handle_nwc_keysend_payment(event.clone(), node, nostr_manager, param.clone(), true)
                .await
            {
                Ok(Some(response_event)) => {
                    if let Err(e) = nostr_manager
                        .client
                        .send_event(response_event.clone())
                        .await
                    {
                        log_error!(
                            nostr_manager.logger,
                            "error sending multi_pay_keysend nwc response event: {}",
                            e
                        )
                    } else {
                        response_events.push(response_event);
                    }
                }
                Ok(None) => continue,
                Err(e) => {
                    log_error!(
                        nostr_manager.logger,
                        "Error handling multi_pay_keysend request: {}",
                        e
                    )
                }
            }
        }

        if response_events.is_empty() {
            Ok(None)
        } else {
            Ok(Some(NwcResponse::MultiEvent(response_events)))
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
        .lookup_payment(&invoice.payment_hash().into_32())
        .await
        .map(|i| i.status)
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
    use crate::nostr::client::MockNostrClient;
    use crate::nostr::primal::MockPrimalApi;
    use crate::nostr::{NostrKeySource, ProfileType};
    use crate::storage::MemoryStorage;
    use crate::test_utils::{
        create_dummy_invoice, create_multi_invoice_nwc_request, create_mutiny_wallet,
        create_nwc_request, create_pay_keysend_nwc_request, sign_nwc_request,
    };
    use crate::utils::sleep;
    use crate::MockInvoiceHandler;
    use crate::MutinyInvoice;
    use bitcoin::{BlockHash, Network};
    use lightning::chain::BestBlock;
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

    fn get_mock_nostr_client() -> MockNostrClient {
        let mut nostr_client = MockNostrClient::new();
        nostr_client.expect_set_signer().return_const(());
        nostr_client
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
            MockPrimalApi::new(),
            get_mock_nostr_client(),
            mw.logger.clone(),
            stop,
        )
        .await
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
        let mut nostr_manager = NostrManager::from_mnemonic(
            xprivkey,
            NostrKeySource::Derived,
            storage.clone(),
            MockPrimalApi::new(),
            get_mock_nostr_client(),
            logger.clone(),
            stop,
        )
        .await
        .unwrap();

        let profile = nostr_manager
            .create_new_nwc_profile_internal(
                ProfileType::Normal {
                    name: "test".to_string(),
                },
                SpendingConditions::RequireApproval,
                NwcProfileTag::General,
                vec![Method::PayInvoice, Method::PayKeysend],
            )
            .unwrap();

        let event_id = EventId::all_zeros();
        nostr_manager
            .client
            .expect_send_event()
            .times(7)
            .returning(move |_| Ok(event_id));

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
        if let NwcResponse::SingleEvent(event) = result.unwrap().unwrap() {
            check_nwc_error_response(
                event,
                &uri.secret,
                NIP47Error {
                    code: ErrorCode::NotImplemented,
                    message: "Failed to parse request.".to_string(),
                },
            );
        }
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
        if let NwcResponse::SingleEvent(event) = result.unwrap().unwrap() {
            check_nwc_error_response(
                event,
                &uri.secret,
                NIP47Error {
                    code: ErrorCode::NotImplemented,
                    message: "Command is not supported.".to_string(),
                },
            );
        }
        check_no_pending_invoices(&storage);

        // test invalid invoice
        let event = create_nwc_request(&uri, "invalid invoice".to_string());
        let result = nwc.handle_nwc_request(event, &node, &nostr_manager).await;
        if let NwcResponse::SingleEvent(event) = result.unwrap().unwrap() {
            check_nwc_error_response(
                event,
                &uri.secret,
                NIP47Error {
                    code: ErrorCode::Other,
                    message: "Invalid invoice".to_string(),
                },
            );
        }
        check_no_pending_invoices(&storage);

        // test expired invoice
        let event = create_nwc_request(&uri, INVOICE.to_string());
        let result = nwc.handle_nwc_request(event, &node, &nostr_manager).await;
        if let NwcResponse::SingleEvent(event) = result.unwrap().unwrap() {
            check_nwc_error_response(
                event,
                &uri.secret,
                NIP47Error {
                    code: ErrorCode::Other,
                    message: "Invoice expired".to_string(),
                },
            );
        }
        check_no_pending_invoices(&storage);

        // test amount-less invoice
        let (invoice, _) = create_dummy_invoice(None, Network::Regtest, None);
        let event = create_nwc_request(&uri, invoice.to_string());
        let result = nwc.handle_nwc_request(event, &node, &nostr_manager).await;
        if let NwcResponse::SingleEvent(event) = result.unwrap().unwrap() {
            check_nwc_error_response(
                event,
                &uri.secret,
                NIP47Error {
                    code: ErrorCode::Other,
                    message: "Invoice amount not set".to_string(),
                },
            );
        }
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
        if let NwcResponse::SingleEvent(event) = result.unwrap().unwrap() {
            check_nwc_error_response(
                event,
                &uri.secret,
                NIP47Error {
                    code: ErrorCode::Other,
                    message: "Paying hodl invoices disabled".to_string(),
                },
            );
        }
        check_no_pending_invoices(&storage);

        // test in-flight payment
        let (invoice, _) = create_dummy_invoice(Some(1_000), Network::Regtest, None);
        node.expect_lookup_payment()
            .with(eq(invoice.payment_hash().into_32()))
            .returning(move |_| {
                Some(MutinyInvoice {
                    status: HTLCStatus::InFlight,
                    ..Default::default()
                })
            });
        let event = create_nwc_request(&uri, invoice.to_string());
        let result = nwc.handle_nwc_request(event, &node, &nostr_manager).await;
        assert_eq!(result.unwrap(), None);
        check_no_pending_invoices(&storage);

        // test completed payment
        let (invoice, _) = create_dummy_invoice(Some(1_000), Network::Regtest, None);
        node.expect_lookup_payment()
            .with(eq(invoice.payment_hash().into_32()))
            .returning(move |_| {
                Some(MutinyInvoice {
                    status: HTLCStatus::Succeeded,
                    ..Default::default()
                })
            });
        let event = create_nwc_request(&uri, invoice.to_string());
        let result = nwc.handle_nwc_request(event, &node, &nostr_manager).await;
        assert_eq!(result.unwrap(), None);
        check_no_pending_invoices(&storage);

        // test it goes to pending
        let (invoice, _) = create_dummy_invoice(Some(1_000), Network::Regtest, None);
        node.expect_lookup_payment()
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

        // test keysend payment - require approval
        let event = create_pay_keysend_nwc_request(&uri, 1_000, "dummy".to_string());
        let result = nwc.handle_nwc_request(event, &node, &nostr_manager).await;
        if let NwcResponse::SingleEvent(event) = result.unwrap().unwrap() {
            check_nwc_error_response(
                event,
                &uri.secret,
                NIP47Error {
                    code: ErrorCode::Unauthorized,
                    message: "Keysend only supported for profiles with a budget".to_string(),
                },
            );
        }
    }

    #[test]
    async fn test_clear_invalid_pending_invoices() {
        let storage = MemoryStorage::default();
        let xprivkey = ExtendedPrivKey::new_master(Network::Regtest, &[0; 64]).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let nostr_manager = NostrManager::from_mnemonic(
            xprivkey,
            NostrKeySource::Derived,
            storage.clone(),
            MockPrimalApi::new(),
            get_mock_nostr_client(),
            Arc::new(MutinyLogger::default()),
            stop,
        )
        .await
        .unwrap();

        // check we start with no pending invoices
        let pending = nostr_manager.get_pending_nwc_invoices().unwrap();
        assert_eq!(pending.len(), 0);

        // add an expired invoice
        let pubkey = nostr_manager.get_npub().await;
        let expired = PendingNwcInvoice {
            index: Some(0),
            invoice: Bolt11Invoice::from_str(INVOICE).unwrap(),
            event_id: EventId::all_zeros(),
            pubkey,
            identifier: None,
        };
        // add an unexpired invoice
        let dummy_invoice = create_dummy_invoice(Some(1_000), Network::Regtest, None).0;
        let unexpired = PendingNwcInvoice {
            index: Some(0),
            invoice: dummy_invoice.clone(),
            event_id: EventId::all_zeros(),
            pubkey,
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
        let mut node = MockInvoiceHandler::new();
        node.expect_lookup_payment().return_const(None);
        nostr_manager
            .clear_invalid_nwc_invoices(&node)
            .await
            .unwrap();
        let pending = nostr_manager.get_pending_nwc_invoices().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0], unexpired);

        let mut node = MockInvoiceHandler::new();
        node.expect_lookup_payment()
            .with(eq(dummy_invoice.payment_hash().into_32()))
            .returning(move |_| {
                Some(MutinyInvoice {
                    status: HTLCStatus::Succeeded,
                    ..Default::default()
                })
            });
        nostr_manager
            .clear_invalid_nwc_invoices(&node)
            .await
            .unwrap();
        let pending = nostr_manager.get_pending_nwc_invoices().unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    async fn test_failed_process_nwc_event_budget() {
        let storage = MemoryStorage::default();
        let mw = create_mutiny_wallet(storage.clone()).await;

        let xprivkey = ExtendedPrivKey::new_master(Network::Regtest, &[0; 64]).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let mut nostr_manager = NostrManager::from_mnemonic(
            xprivkey,
            NostrKeySource::Derived,
            storage.clone(),
            MockPrimalApi::new(),
            get_mock_nostr_client(),
            mw.logger.clone(),
            stop,
        )
        .await
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
                vec![
                    Method::PayInvoice,
                    Method::MultiPayInvoice,
                    Method::PayKeysend,
                ],
            )
            .unwrap();

        let secp = Secp256k1::new();
        let mut nwc = NostrWalletConnect::new(&secp, xprivkey, profile.profile()).unwrap();
        let uri = nwc.get_nwc_uri().unwrap().unwrap();

        let event_id = EventId::all_zeros();
        nostr_manager
            .client
            .expect_send_event()
            .times(5)
            .returning(move |_| Ok(event_id));

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

        // clear pending
        nostr_manager.deny_all_pending_nwc().await.unwrap();

        let mut node = MockInvoiceHandler::new();
        node.expect_skip_hodl_invoices().times(2).returning(|| true);
        node.expect_lookup_payment().return_const(None);

        let secp = Secp256k1::new();
        let mut nwc = NostrWalletConnect::new(&secp, xprivkey, profile.profile()).unwrap();
        let uri = nwc.get_nwc_uri().unwrap().unwrap();

        // test multi invoice over budget after 1st invoice. 2nd goes to pending
        let (invoice_1, preimage_1) = create_dummy_invoice(Some(8_000_000), Network::Regtest, None);
        let (invoice_2, _) = create_dummy_invoice(Some(4_000_000), Network::Regtest, None);
        let invoices = vec![invoice_1.to_string(), invoice_2.to_string()];
        node.expect_pay_invoice()
            .once()
            .returning(move |inv, _, _| {
                let mut mutiny_invoice: MutinyInvoice = inv.clone().into();
                mutiny_invoice.preimage = Some(preimage_1.to_lower_hex_string());
                mutiny_invoice.status = HTLCStatus::Succeeded;
                mutiny_invoice.last_updated = utils::now().as_secs();
                mutiny_invoice.fees_paid = Some(0);
                Ok(mutiny_invoice)
            });

        let event = create_multi_invoice_nwc_request(&uri, invoices);
        let result = nwc
            .handle_nwc_request(event.clone(), &node, &nostr_manager)
            .await;
        assert!(result.unwrap().is_some());
        let pending = nostr_manager.get_pending_nwc_invoices().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].invoice, invoice_2);
        assert_eq!(pending[0].event_id, event.id);
        assert_eq!(pending[0].index, Some(nwc.profile.index));
        assert_eq!(pending[0].pubkey, event.pubkey);

        // test keysend over budget responds quota exceeded
        let pk_bytes = &mut [0u8; 32];
        getrandom::getrandom(pk_bytes).unwrap();
        let pk_bytes = bitcoin::secp256k1::SecretKey::from_slice(pk_bytes).unwrap();
        let secp = Secp256k1::new();
        let pubkey = pk_bytes.public_key(&secp);

        let event = create_pay_keysend_nwc_request(&uri, budget * 1000 + 1_000, pubkey.to_string());
        let mut node = MockInvoiceHandler::new();
        node.expect_lookup_payment().return_const(None);
        let result = nwc.handle_nwc_request(event, &mw, &nostr_manager).await;
        if let NwcResponse::SingleEvent(event) = result.unwrap().unwrap() {
            check_nwc_error_response(
                event,
                &uri.secret,
                NIP47Error {
                    code: ErrorCode::QuotaExceeded,
                    message: "Budget exceeded.".to_string(),
                },
            );
        }
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
        node.expect_lookup_payment().return_const(None);
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
        let mut nostr_manager = NostrManager::from_mnemonic(
            xprivkey,
            NostrKeySource::Derived,
            storage.clone(),
            MockPrimalApi::new(),
            get_mock_nostr_client(),
            logger,
            stop,
        )
        .await
        .unwrap();

        let event_id = EventId::all_zeros();
        nostr_manager
            .client
            .expect_send_event()
            .times(2)
            .returning(move |_| Ok(event_id));

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
                vec![Method::PayInvoice, Method::PayKeysend],
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

        let event = if let NwcResponse::SingleEvent(nwc_event) = result.unwrap().unwrap() {
            nwc_event
        } else {
            panic!("invalid nwc response")
        };

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

        match nwc.profile.spending_conditions.clone() {
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

        // test successful keysend payment
        let pk_bytes = &mut [0u8; 32];
        getrandom::getrandom(pk_bytes).unwrap();
        let pk_bytes = bitcoin::secp256k1::SecretKey::from_slice(pk_bytes).unwrap();
        let secp = Secp256k1::new();
        let pubkey = pk_bytes.public_key(&secp);

        let keysend_amount_msat = 5_000;
        let event = create_pay_keysend_nwc_request(&uri, keysend_amount_msat, pubkey.to_string());
        let mut input = event.id.to_string();
        input.push_str(&nwc.server_key.secret_key().unwrap().to_string());
        let preimage = PaymentPreimage(Sha256::hash(input.as_bytes()).into_32());

        node.expect_keysend()
            .with(
                eq(pubkey),
                eq(keysend_amount_msat / 1000),
                eq(vec![]),
                eq(vec![profile.name]),
                eq(Some(preimage.0)),
            )
            .returning(move |_, _, _, _, _| {
                let payment_hash = Sha256::hash(&preimage.0);
                let payment_preimage = preimage.to_string();

                let mutiny_invoice = MutinyInvoice {
                    bolt11: None,
                    description: None,
                    payment_hash,
                    preimage: Some(payment_preimage),
                    payee_pubkey: Some(pubkey),
                    amount_sats: None,
                    expire: 0,
                    status: HTLCStatus::Succeeded,
                    privacy_level: Default::default(),
                    fees_paid: None,
                    inbound: false,
                    labels: vec![],
                    last_updated: 0,
                };
                Ok(mutiny_invoice)
            });

        let result = nwc
            .handle_nwc_request(event.clone(), &node, &nostr_manager)
            .await;

        let event = if let NwcResponse::SingleEvent(nwc_event) = result.unwrap().unwrap() {
            nwc_event
        } else {
            panic!("invalid nwc response")
        };

        let content = decrypt(&uri.secret, &event.pubkey, &event.content).unwrap();
        let response: Response = Response::from_json(content).unwrap();
        assert_eq!(response.result_type, Method::PayKeysend);
        assert!(response.error.is_none());

        match response.result {
            Some(ResponseResult::PayKeysend(PayKeysendResponseResult { preimage: pre })) => {
                assert_eq!(pre, preimage.0.to_lower_hex_string());
            }
            _ => panic!("wrong response"),
        }

        match nwc.profile.spending_conditions {
            SpendingConditions::Budget(budget) => {
                assert_eq!(budget.payments.len(), 2);
                assert_eq!(budget.payments[1].amt, keysend_amount_msat / 1_000);
            }
            _ => panic!("wrong spending conditions"),
        }
    }

    #[test]
    async fn test_get_balance_require_approval() {
        let storage = MemoryStorage::default();
        let mw = create_mutiny_wallet(storage.clone()).await;

        let xprivkey = ExtendedPrivKey::new_master(Network::Regtest, &[0; 64]).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let mut nostr_manager = NostrManager::from_mnemonic(
            xprivkey,
            NostrKeySource::Derived,
            storage.clone(),
            MockPrimalApi::new(),
            get_mock_nostr_client(),
            mw.logger.clone(),
            stop,
        )
        .await
        .unwrap();

        let profile = nostr_manager
            .create_new_nwc_profile_internal(
                ProfileType::Normal {
                    name: "test".to_string(),
                },
                SpendingConditions::RequireApproval,
                NwcProfileTag::General,
                vec![Method::GetBalance],
            )
            .unwrap();

        let secp = Secp256k1::new();
        let mut nwc = NostrWalletConnect::new(&secp, xprivkey, profile.profile()).unwrap();
        let uri = nwc.get_nwc_uri().unwrap().unwrap();

        // test get_balance

        let event = sign_nwc_request(&uri, Request::get_balance());
        let event_id = EventId::all_zeros();
        nostr_manager
            .client
            .expect_send_event()
            .once()
            .returning(move |_| Ok(event_id));
        let result = nwc
            .handle_nwc_request(event.clone(), &mw, &nostr_manager)
            .await;

        let event = if let NwcResponse::SingleEvent(nwc_event) = result.unwrap().unwrap() {
            nwc_event
        } else {
            panic!("invalid nwc response")
        };
        let content = decrypt(&uri.secret, &event.pubkey, &event.content).unwrap();
        let response: Response = Response::from_json(content).unwrap();
        let balance = response.to_get_balance().unwrap();
        assert_eq!(balance.balance, 0);
    }

    #[test]
    async fn test_get_balance_budget() {
        let storage = MemoryStorage::default();
        let mw = create_mutiny_wallet(storage.clone()).await;

        let xprivkey = ExtendedPrivKey::new_master(Network::Regtest, &[0; 64]).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let mut nostr_manager = NostrManager::from_mnemonic(
            xprivkey,
            NostrKeySource::Derived,
            storage.clone(),
            MockPrimalApi::new(),
            get_mock_nostr_client(),
            mw.logger.clone(),
            stop,
        )
        .await
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
                    period: BudgetPeriod::Day,
                }),
                NwcProfileTag::General,
                vec![Method::GetBalance],
            )
            .unwrap();

        let secp = Secp256k1::new();
        let mut nwc = NostrWalletConnect::new(&secp, xprivkey, profile.profile()).unwrap();
        let uri = nwc.get_nwc_uri().unwrap().unwrap();

        // test get_balance

        let event = sign_nwc_request(&uri, Request::get_balance());
        let event_id = EventId::all_zeros();
        nostr_manager
            .client
            .expect_send_event()
            .once()
            .returning(move |_| Ok(event_id));
        let result = nwc
            .handle_nwc_request(event.clone(), &mw, &nostr_manager)
            .await;

        let event = if let NwcResponse::SingleEvent(nwc_event) = result.unwrap().unwrap() {
            nwc_event
        } else {
            panic!("invalid nwc response")
        };
        let content = decrypt(&uri.secret, &event.pubkey, &event.content).unwrap();
        let response: Response = Response::from_json(content).unwrap();
        let balance = response.to_get_balance().unwrap();
        assert_eq!(balance.balance, budget * 1_000); // convert to msats
    }

    #[test]
    async fn test_get_balance_single_use() {
        let storage = MemoryStorage::default();
        let mw = create_mutiny_wallet(storage.clone()).await;

        let xprivkey = ExtendedPrivKey::new_master(Network::Regtest, &[0; 64]).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let mut nostr_manager = NostrManager::from_mnemonic(
            xprivkey,
            NostrKeySource::Derived,
            storage.clone(),
            MockPrimalApi::new(),
            get_mock_nostr_client(),
            mw.logger.clone(),
            stop,
        )
        .await
        .unwrap();

        let budget = 10_000;

        let profile = nostr_manager
            .create_new_nwc_profile_internal(
                ProfileType::Normal {
                    name: "test".to_string(),
                },
                SpendingConditions::SingleUse(SingleUseSpendingConditions {
                    payment_hash: None,
                    amount_sats: budget,
                }),
                NwcProfileTag::General,
                vec![Method::GetBalance],
            )
            .unwrap();

        let secp = Secp256k1::new();
        let mut nwc = NostrWalletConnect::new(&secp, xprivkey, profile.profile()).unwrap();
        let uri = nwc.get_nwc_uri().unwrap().unwrap();

        // test get_balance

        let event = sign_nwc_request(&uri, Request::get_balance());
        let event_id = EventId::all_zeros();
        nostr_manager
            .client
            .expect_send_event()
            .once()
            .returning(move |_| Ok(event_id));
        let result = nwc
            .handle_nwc_request(event.clone(), &mw, &nostr_manager)
            .await;

        let event = if let NwcResponse::SingleEvent(nwc_event) = result.unwrap().unwrap() {
            nwc_event
        } else {
            panic!("invalid nwc response")
        };
        let content = decrypt(&uri.secret, &event.pubkey, &event.content).unwrap();
        let response: Response = Response::from_json(content).unwrap();
        let balance = response.to_get_balance().unwrap();
        assert_eq!(balance.balance, budget * 1_000); // convert to msats
    }

    #[test]
    async fn test_get_info() {
        let storage = MemoryStorage::default();

        let xprivkey = ExtendedPrivKey::new_master(Network::Regtest, &[0; 64]).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let mut nostr_manager = NostrManager::from_mnemonic(
            xprivkey,
            NostrKeySource::Derived,
            storage.clone(),
            MockPrimalApi::new(),
            get_mock_nostr_client(),
            Arc::new(MutinyLogger::default()),
            stop,
        )
        .await
        .unwrap();

        let best_block = BestBlock::new(
            BlockHash::from_str("000000000000000000017dfbca2b8c975abcf0f86a6b19f38b3e4cafeabf56b0")
                .unwrap(),
            6969,
        );

        let mut node = MockInvoiceHandler::new();
        node.expect_logger().return_const(MutinyLogger::default());
        node.expect_get_network().return_const(Network::Regtest);
        node.expect_get_best_block()
            .returning(move || Ok(best_block));

        let profile = nostr_manager
            .create_new_nwc_profile_internal(
                ProfileType::Normal {
                    name: "test".to_string(),
                },
                SpendingConditions::RequireApproval,
                NwcProfileTag::General,
                vec![Method::GetInfo],
            )
            .unwrap();

        let secp = Secp256k1::new();
        let mut nwc = NostrWalletConnect::new(&secp, xprivkey, profile.profile()).unwrap();
        let uri = nwc.get_nwc_uri().unwrap().unwrap();

        // test get_info

        let event = sign_nwc_request(&uri, Request::get_info());
        let event_id = EventId::all_zeros();
        nostr_manager
            .client
            .expect_send_event()
            .once()
            .returning(move |_| Ok(event_id));
        let result = nwc
            .handle_nwc_request(event.clone(), &node, &nostr_manager)
            .await;

        let event = if let NwcResponse::SingleEvent(nwc_event) = result.unwrap().unwrap() {
            nwc_event
        } else {
            panic!("invalid nwc response")
        };
        let content = decrypt(&uri.secret, &event.pubkey, &event.content).unwrap();
        let response: Response = Response::from_json(content).unwrap();
        let info = response.to_get_info().unwrap();

        assert_eq!(info.network, "regtest");
        assert_eq!(
            info.block_hash,
            "000000000000000000017dfbca2b8c975abcf0f86a6b19f38b3e4cafeabf56b0"
        );
        assert_eq!(info.block_height, best_block.height());
        assert_eq!(info.methods, vec!["get_info"]);
    }

    #[test]
    async fn test_make_invoice() {
        let storage = MemoryStorage::default();

        let xprivkey = ExtendedPrivKey::new_master(Network::Regtest, &[0; 64]).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let mut nostr_manager = NostrManager::from_mnemonic(
            xprivkey,
            NostrKeySource::Derived,
            storage.clone(),
            MockPrimalApi::new(),
            get_mock_nostr_client(),
            Arc::new(MutinyLogger::default()),
            stop,
        )
        .await
        .unwrap();

        let amount = 69696969;
        let invoice = create_dummy_invoice(Some(amount), Network::Regtest, None).0;

        let mut node = MockInvoiceHandler::new();
        let mutiny_inv: MutinyInvoice = invoice.clone().into();
        node.expect_create_invoice()
            .return_once(|_, _| Ok(mutiny_inv));

        let profile = nostr_manager
            .create_new_nwc_profile_internal(
                ProfileType::Normal {
                    name: "test".to_string(),
                },
                SpendingConditions::RequireApproval,
                NwcProfileTag::General,
                vec![Method::MakeInvoice],
            )
            .unwrap();

        let secp = Secp256k1::new();
        let mut nwc = NostrWalletConnect::new(&secp, xprivkey, profile.profile()).unwrap();
        let uri = nwc.get_nwc_uri().unwrap().unwrap();

        // test make_invoice

        let event = sign_nwc_request(
            &uri,
            Request::make_invoice(MakeInvoiceRequestParams {
                amount,
                description: None,
                description_hash: None,
                expiry: None,
            }),
        );
        let event_id = EventId::all_zeros();
        nostr_manager
            .client
            .expect_send_event()
            .once()
            .returning(move |_| Ok(event_id));
        let result = nwc
            .handle_nwc_request(event.clone(), &node, &nostr_manager)
            .await;

        let event = if let NwcResponse::SingleEvent(nwc_event) = result.unwrap().unwrap() {
            nwc_event
        } else {
            panic!("invalid nwc response")
        };
        let content = decrypt(&uri.secret, &event.pubkey, &event.content).unwrap();
        let response: Response = Response::from_json(content).unwrap();
        let result = response.to_make_invoice().unwrap();

        assert_eq!(result.invoice, invoice.to_string());
        assert_eq!(
            result.payment_hash,
            invoice.payment_hash().into_32().to_lower_hex_string()
        );
    }

    #[test]
    async fn test_lookup_invoice() {
        let storage = MemoryStorage::default();

        let xprivkey = ExtendedPrivKey::new_master(Network::Regtest, &[0; 64]).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let mut nostr_manager = NostrManager::from_mnemonic(
            xprivkey,
            NostrKeySource::Derived,
            storage.clone(),
            MockPrimalApi::new(),
            get_mock_nostr_client(),
            Arc::new(MutinyLogger::default()),
            stop,
        )
        .await
        .unwrap();

        let mut node = MockInvoiceHandler::new();
        node.expect_lookup_payment().once().returning(|_| None);

        let profile = nostr_manager
            .create_new_nwc_profile_internal(
                ProfileType::Normal {
                    name: "test".to_string(),
                },
                SpendingConditions::RequireApproval,
                NwcProfileTag::General,
                vec![Method::LookupInvoice],
            )
            .unwrap();

        let event_id = EventId::all_zeros();
        nostr_manager
            .client
            .expect_send_event()
            .times(2)
            .returning(move |_| Ok(event_id));

        let secp = Secp256k1::new();
        let mut nwc = NostrWalletConnect::new(&secp, xprivkey, profile.profile()).unwrap();
        let uri = nwc.get_nwc_uri().unwrap().unwrap();

        // test lookup_invoice

        // test missing invoice
        let event = sign_nwc_request(
			&uri,
			Request::lookup_invoice(LookupInvoiceRequestParams {
				payment_hash: None,
				bolt11: Some("lntbs1m1pjrmuu3pp52hk0j956d7s8azaps87amadshnrcvqtkvk06y2nue2w69g6e5vasdqqcqzpgxqyz5vqsp5wu3py6257pa3yzarw0et2200c08r5fu6k3u94yfwmlnc8skdkc9s9qyyssqc783940p82c64qq9pu3xczt4tdxzex9wpjn54486y866aayft2cxxusl9eags4cs3kcmuqdrvhvs0gudpj5r2a6awu4wcq29crpesjcqhdju55".to_string()),
			}),
		);
        let result = nwc
            .handle_nwc_request(event.clone(), &node, &nostr_manager)
            .await;

        let event = if let NwcResponse::SingleEvent(nwc_event) = result.unwrap().unwrap() {
            nwc_event
        } else {
            panic!("invalid nwc response")
        };
        let content = decrypt(&uri.secret, &event.pubkey, &event.content).unwrap();
        let response: Response = Response::from_json(content).unwrap();
        let error = response.error.unwrap();
        assert_eq!(error.message, "Invoice not found");
        assert!(matches!(error.code, ErrorCode::NotFound));
        assert_eq!(response.result_type, Method::LookupInvoice);

        // test found invoice
        let invoice = create_dummy_invoice(Some(69696969), Network::Regtest, None).0;
        let mutiny_inv: MutinyInvoice = invoice.clone().into();
        node.expect_lookup_payment()
            .once()
            .returning(move |_| Some(mutiny_inv.clone()));

        let event = sign_nwc_request(
            &uri,
            Request::lookup_invoice(LookupInvoiceRequestParams {
                payment_hash: None,
                bolt11: Some(invoice.to_string()),
            }),
        );
        let result = nwc
            .handle_nwc_request(event.clone(), &node, &nostr_manager)
            .await;

        let event = if let NwcResponse::SingleEvent(nwc_event) = result.unwrap().unwrap() {
            nwc_event
        } else {
            panic!("invalid nwc response")
        };
        let content = decrypt(&uri.secret, &event.pubkey, &event.content).unwrap();
        let response: Response = Response::from_json(content).unwrap();
        let result = response.to_lookup_invoice().unwrap();

        assert_eq!(result.invoice, Some(invoice.to_string()));
        assert_eq!(result.transaction_type, Some(TransactionType::Incoming));
        assert_eq!(result.preimage, None);
        assert_ne!(result.created_at, 0); // make sure we properly set this

        // test invalid invoice
        let event = sign_nwc_request(
            &uri,
            Request::lookup_invoice(LookupInvoiceRequestParams {
                payment_hash: None,
                bolt11: Some("invalid invoice".to_string()),
            }),
        );
        let result = nwc
            .handle_nwc_request(event.clone(), &node, &nostr_manager)
            .await;
        assert!(result.is_err());

        // test invalid payment_hash
        let event = sign_nwc_request(
            &uri,
            Request::lookup_invoice(LookupInvoiceRequestParams {
                payment_hash: Some("invalid payment_hash".to_string()),
                bolt11: None,
            }),
        );
        let result = nwc
            .handle_nwc_request(event.clone(), &node, &nostr_manager)
            .await;
        assert!(result.is_err());
    }

    #[test]
    async fn test_list_transactions() {
        let storage = MemoryStorage::default();

        let xprivkey = ExtendedPrivKey::new_master(Network::Regtest, &[0; 64]).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let mut nostr_manager = NostrManager::from_mnemonic(
            xprivkey,
            NostrKeySource::Derived,
            storage.clone(),
            MockPrimalApi::new(),
            get_mock_nostr_client(),
            Arc::new(MutinyLogger::default()),
            stop,
        )
        .await
        .unwrap();

        let profile = nostr_manager
            .create_new_nwc_profile_internal(
                ProfileType::Normal {
                    name: "test".to_string(),
                },
                SpendingConditions::RequireApproval,
                NwcProfileTag::General,
                vec![Method::ListTransactions],
            )
            .unwrap();

        let event_id = EventId::all_zeros();
        nostr_manager
            .client
            .expect_send_event()
            .times(4)
            .returning(move |_| Ok(event_id));

        let secp = Secp256k1::new();
        let mut nwc = NostrWalletConnect::new(&secp, xprivkey, profile.profile()).unwrap();
        let uri = nwc.get_nwc_uri().unwrap().unwrap();

        let invoice_1: MutinyInvoice = create_dummy_invoice(Some(69696969), Network::Regtest, None)
            .0
            .clone()
            .into();
        sleep(1000).await;

        let invoice_2: MutinyInvoice = create_dummy_invoice(Some(42_000), Network::Regtest, None)
            .0
            .clone()
            .into();
        sleep(1000).await;

        let invoice_3: MutinyInvoice = create_dummy_invoice(Some(84_000), Network::Regtest, None)
            .0
            .clone()
            .into();
        sleep(1000).await;

        let mut invoice_4: MutinyInvoice =
            create_dummy_invoice(Some(21_000), Network::Regtest, None)
                .0
                .clone()
                .into();
        invoice_4.status = HTLCStatus::Succeeded;

        let invoices: Vec<MutinyInvoice> = vec![
            invoice_1.clone(),
            invoice_2.clone(),
            invoice_3.clone(),
            invoice_4.clone(),
        ];

        let mut node = MockInvoiceHandler::new();
        node.expect_get_payments_by_label()
            .times(4)
            .returning(move |_| Ok(invoices.clone()));

        // only paid ones
        let time = utils::now().as_secs() + 2000000;
        let event = sign_nwc_request(
            &uri,
            Request::list_transactions(ListTransactionsRequestParams {
                from: None,
                until: Some(time),
                limit: None,
                offset: None,
                unpaid: None,
                transaction_type: None,
            }),
        );

        let result = nwc
            .handle_nwc_request(event.clone(), &node, &nostr_manager)
            .await;

        let event = if let NwcResponse::SingleEvent(nwc_event) = result.unwrap().unwrap() {
            nwc_event
        } else {
            panic!("invalid nwc response")
        };
        let content = decrypt(&uri.secret, &event.pubkey, &event.content).unwrap();
        let response: Response = Response::from_json(content).unwrap();
        let result = response.to_list_transactions().unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].amount, 21_000);
        assert_eq!(
            result[0].invoice.clone().unwrap(),
            invoice_4.bolt11.unwrap().to_string()
        );

        // with limit
        let time = utils::now().as_secs() + 2000000;
        let event = sign_nwc_request(
            &uri,
            Request::list_transactions(ListTransactionsRequestParams {
                from: None,
                until: Some(time),
                limit: Some(2),
                offset: None,
                unpaid: Some(true),
                transaction_type: None,
            }),
        );

        let result = nwc
            .handle_nwc_request(event.clone(), &node, &nostr_manager)
            .await;

        let event = if let NwcResponse::SingleEvent(nwc_event) = result.unwrap().unwrap() {
            nwc_event
        } else {
            panic!("invalid nwc response")
        };
        let content = decrypt(&uri.secret, &event.pubkey, &event.content).unwrap();
        let response: Response = Response::from_json(content).unwrap();
        let result = response.to_list_transactions().unwrap();

        assert_eq!(result.len(), 2);

        // outgoing
        let time = utils::now().as_secs() + 2000000;
        let event = sign_nwc_request(
            &uri,
            Request::list_transactions(ListTransactionsRequestParams {
                from: None,
                until: Some(time),
                limit: None,
                offset: None,
                unpaid: None,
                transaction_type: Some(TransactionType::Outgoing),
            }),
        );

        let result = nwc
            .handle_nwc_request(event.clone(), &node, &nostr_manager)
            .await;

        let event = if let NwcResponse::SingleEvent(nwc_event) = result.unwrap().unwrap() {
            nwc_event
        } else {
            panic!("invalid nwc response")
        };
        let content = decrypt(&uri.secret, &event.pubkey, &event.content).unwrap();
        let response: Response = Response::from_json(content).unwrap();
        let result = response.to_list_transactions().unwrap();
        assert_eq!(result.len(), 0);

        // with limit and offset
        let time = utils::now().as_secs() + 2000000;
        let event = sign_nwc_request(
            &uri,
            Request::list_transactions(ListTransactionsRequestParams {
                from: None,
                until: Some(time),
                limit: Some(2),
                offset: Some(1),
                unpaid: Some(true),
                transaction_type: None,
            }),
        );

        let result = nwc
            .handle_nwc_request(event.clone(), &node, &nostr_manager)
            .await;

        let event = if let NwcResponse::SingleEvent(nwc_event) = result.unwrap().unwrap() {
            nwc_event
        } else {
            panic!("invalid nwc response")
        };
        let content = decrypt(&uri.secret, &event.pubkey, &event.content).unwrap();
        let response: Response = Response::from_json(content).unwrap();
        let result = response.to_list_transactions().unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].amount / 1_000, invoice_3.amount_sats.unwrap());
        assert_eq!(
            result[0].invoice.clone().unwrap(),
            invoice_3.bolt11.unwrap().to_string()
        );

        assert_eq!(result[1].amount / 1_000, invoice_2.amount_sats.unwrap());
        assert_eq!(
            result[1].invoice.clone().unwrap(),
            invoice_2.bolt11.unwrap().to_string()
        );
    }
}
