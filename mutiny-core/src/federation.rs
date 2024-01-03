use crate::{
    error::MutinyError,
    key::{create_root_child_key, ChildKey},
    logging::MutinyLogger,
    nodemanager::MutinyInvoice,
    onchain::coin_type_from_network,
    sql::{glue::GlueDB, ApplicationStore},
    utils::{self, sleep},
    ActivityItem, HTLCStatus, DEFAULT_PAYMENT_TIMEOUT,
};
use bip39::Mnemonic;
use bitcoin::{
    hashes::{hex::ToHex, sha256},
    secp256k1::Secp256k1,
    util::bip32::ExtendedPrivKey,
    util::bip32::{ChildNumber, DerivationPath},
    Network,
};
use fedimint_bip39::Bip39RootSecretStrategy;
use fedimint_client::{
    db::ChronologicalOperationLogKey,
    derivable_secret::DerivableSecret,
    get_config_from_db,
    oplog::{OperationLogEntry, UpdateStreamOrOutcome},
    secret::{get_default_client_secret, RootSecretStrategy},
    ClientArc, FederationInfo,
};
use fedimint_core::{
    api::InviteCode,
    config::FederationId,
    core::OperationId,
    module::CommonModuleInit,
    task::{MaybeSend, MaybeSync},
    Amount,
};
use fedimint_ln_client::{
    InternalPayState, LightningClientInit, LightningClientModule, LightningOperationMeta,
    LightningOperationMetaVariant, LnPayState, LnReceiveState,
};
use fedimint_ln_common::LightningCommonInit;
use fedimint_mint_client::MintClientInit;
use fedimint_wallet_client::WalletClientInit;
use futures::future::{self};
use futures_util::{pin_mut, StreamExt};
use lightning::{log_debug, log_error, log_info, log_trace, log_warn, util::logger::Logger};
use lightning_invoice::Bolt11Invoice;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{collections::HashMap, fmt::Debug, sync::Arc};

// The amount of time in milliseconds to wait for
// checking the status of a fedimint payment. This
// is to work around their stream status checking
// when wanting just the current status.
const FEDIMINT_STATUS_TIMEOUT_CHECK_MS: u64 = 30;

// The maximum amount of operations we try to pull
// from fedimint when we need to search through
// their internal list.
const FEDIMINT_OPERATIONS_LIST_MAX: usize = 100;

impl From<LnReceiveState> for HTLCStatus {
    fn from(state: LnReceiveState) -> Self {
        match state {
            LnReceiveState::Created => HTLCStatus::Pending,
            LnReceiveState::Claimed => HTLCStatus::Succeeded,
            LnReceiveState::WaitingForPayment { .. } => HTLCStatus::Pending,
            LnReceiveState::Canceled { .. } => HTLCStatus::Failed,
            LnReceiveState::Funded => HTLCStatus::InFlight,
            LnReceiveState::AwaitingFunds => HTLCStatus::InFlight,
        }
    }
}

impl From<InternalPayState> for HTLCStatus {
    fn from(state: InternalPayState) -> Self {
        match state {
            InternalPayState::Funding => HTLCStatus::InFlight,
            InternalPayState::Preimage(_) => HTLCStatus::Succeeded,
            InternalPayState::RefundSuccess { .. } => HTLCStatus::Failed,
            InternalPayState::RefundError { .. } => HTLCStatus::Failed,
            InternalPayState::FundingFailed { .. } => HTLCStatus::Failed,
            InternalPayState::UnexpectedError(_) => HTLCStatus::Failed,
        }
    }
}

impl From<LnPayState> for HTLCStatus {
    fn from(state: LnPayState) -> Self {
        match state {
            LnPayState::Created => HTLCStatus::Pending,
            LnPayState::Canceled => HTLCStatus::Failed,
            LnPayState::Funded => HTLCStatus::InFlight,
            LnPayState::WaitingForRefund { .. } => HTLCStatus::InFlight,
            LnPayState::AwaitingChange => HTLCStatus::InFlight,
            LnPayState::Success { .. } => HTLCStatus::Succeeded,
            LnPayState::Refunded { .. } => HTLCStatus::Failed,
            LnPayState::UnexpectedError { .. } => HTLCStatus::Failed,
        }
    }
}

// This is the FederationStorage object saved to the DB
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct FederationStorage {
    pub federations: HashMap<String, FederationIndex>,
    pub version: u32,
}

// This is the FederationIdentity that refer to a specific federation
// Used for public facing identification.
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct FederationIdentity {
    pub uuid: String,
    pub federation_id: FederationId,
    // https://github.com/fedimint/fedimint/tree/master/docs/meta_fields
    pub federation_name: Option<String>,
    pub federation_expiry_timestamp: Option<String>,
    pub welcome_message: Option<String>,
}

// This is the FederationIndex reference that is saved to the DB
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct FederationIndex {
    pub federation_code: InviteCode,
}

pub struct FedimintBalance {
    pub amount: u64,
}

pub(crate) struct FederationClient {
    pub(crate) uuid: String,
    pub(crate) fedimint_client: ClientArc,
    g: GlueDB,
    pub(crate) logger: Arc<MutinyLogger>,
}

impl FederationClient {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn new(
        uuid: String,
        federation_code: InviteCode,
        xprivkey: ExtendedPrivKey,
        g: GlueDB,
        network: Network,
        logger: Arc<MutinyLogger>,
    ) -> Result<Self, MutinyError> {
        log_info!(logger, "initializing a new federation client: {uuid}");

        let federation_info = FederationInfo::from_invite_code(federation_code.clone()).await?;

        let mut client_builder = fedimint_client::Client::builder();
        client_builder.with_module(WalletClientInit(None));
        client_builder.with_module(MintClientInit);
        client_builder.with_module(LightningClientInit);

        let db = g
            .new_fedimint_client_db(federation_info.federation_id().to_string())
            .await?
            .into();
        if get_config_from_db(&db).await.is_none() {
            client_builder.with_federation_info(federation_info.clone());
        }

        client_builder.with_database(db);
        client_builder.with_primary_module(1);

        let secret = create_federation_secret(xprivkey, network)?;

        let fedimint_client = client_builder
            .build(get_default_client_secret(
                &secret,
                &federation_info.federation_id(),
            ))
            .await?;

        log_debug!(logger, "Built fedimint client");
        Ok(FederationClient {
            uuid,
            fedimint_client,
            g,
            logger,
        })
    }

    pub(crate) async fn get_invoice(
        &self,
        amount: u64,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        let lightning_module = self
            .fedimint_client
            .get_first_module::<LightningClientModule>();
        let (_id, invoice) = lightning_module
            .create_bolt11_invoice(Amount::from_sats(amount), String::new(), None, ())
            .await?;

        // persist the invoice
        let mut stored_payment: MutinyInvoice = invoice.clone().into();
        stored_payment.inbound = true;
        stored_payment.labels = labels;

        log_trace!(self.logger, "Persiting payment");
        self.g.save_payment(stored_payment).await?;
        log_trace!(self.logger, "Persisted payment");

        Ok(invoice.into())
    }

    /// Get the balance of this federation client in sats
    pub(crate) async fn get_balance(&self) -> Result<u64, MutinyError> {
        Ok(self.fedimint_client.get_balance().await.msats / 1_000)
    }

    pub async fn get_activity(&self) -> Result<Vec<ActivityItem>, MutinyError> {
        log_trace!(self.logger, "Getting activity");
        let payments = self.g.list_payments().await?;

        let mut payments_map: HashMap<sha256::Hash, MutinyInvoice> = HashMap::new();
        let mut pending_invoices: Vec<&MutinyInvoice> = Vec::new();

        for payment in payments.iter() {
            payments_map.insert(payment.payment_hash, payment.clone());
            if matches!(payment.status, HTLCStatus::InFlight | HTLCStatus::Pending) {
                pending_invoices.push(payment);
            }
        }

        let operations = if !pending_invoices.is_empty() {
            log_trace!(self.logger, "pending invoices, going to list operations");
            self.fedimint_client
                .operation_log()
                .list_operations(FEDIMINT_OPERATIONS_LIST_MAX, None)
                .await
        } else {
            vec![]
        };

        let lightning_module = Arc::new(
            self.fedimint_client
                .get_first_module::<LightningClientModule>(),
        );

        let mut operation_map: HashMap<
            sha256::Hash,
            (ChronologicalOperationLogKey, OperationLogEntry),
        > = HashMap::new();
        log_trace!(
            self.logger,
            "About to go through {} operations",
            operations.len()
        );
        for (key, entry) in operations {
            if entry.operation_module_kind() == LightningCommonInit::KIND.as_str() {
                let lightning_meta: LightningOperationMeta = entry.meta();
                match lightning_meta.variant {
                    LightningOperationMetaVariant::Pay(pay_meta) => {
                        operation_map.insert(*pay_meta.invoice.payment_hash(), (key, entry));
                    }
                    LightningOperationMetaVariant::Receive { invoice, .. } => {
                        operation_map.insert(*invoice.payment_hash(), (key, entry));
                    }
                }
            }
        }

        log_trace!(
            self.logger,
            "Going through {} pending invoices to extract status",
            pending_invoices.len()
        );
        for invoice in pending_invoices {
            let hash = invoice.payment_hash;
            if let Some((key, entry)) = operation_map.get(&hash) {
                if let Some(updated_invoice) = extract_invoice_from_entry(
                    self.logger.clone(),
                    entry,
                    &hash,
                    key.operation_id,
                    &lightning_module,
                )
                .await
                {
                    self.maybe_update_after_checking_fedimint(updated_invoice.clone())
                        .await?;
                    payments_map.insert(hash, updated_invoice);
                }
            }
        }

        let updated_payments = payments_map.into_values().collect::<Vec<_>>();

        let activity_items = updated_payments
            .into_iter()
            .filter_map(|invoice| {
                if !invoice
                    .bolt11
                    .as_ref()
                    .is_some_and(|b| b.would_expire(utils::now()))
                    && matches!(invoice.status, HTLCStatus::Succeeded | HTLCStatus::InFlight)
                {
                    Some(ActivityItem::Lightning(Box::new(invoice)))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        Ok(activity_items)
    }

    async fn maybe_update_after_checking_fedimint(
        &self,
        updated_invoice: MutinyInvoice,
    ) -> Result<(), MutinyError> {
        if matches!(
            updated_invoice.status,
            HTLCStatus::Succeeded | HTLCStatus::Failed
        ) {
            log_debug!(self.logger, "Saving updated payment");
            self.g
                .update_payment_status(
                    &updated_invoice.payment_hash,
                    updated_invoice.status.clone(),
                )
                .await?;
            self.g
                .update_payment_fee(&updated_invoice.payment_hash, updated_invoice.fees_paid)
                .await?;
            self.g
                .update_payment_preimage(
                    &updated_invoice.payment_hash,
                    updated_invoice.preimage.clone(),
                )
                .await?;
        }
        Ok(())
    }

    pub async fn get_invoice_by_hash(
        &self,
        hash: &sha256::Hash,
    ) -> Result<MutinyInvoice, MutinyError> {
        log_trace!(self.logger, "get_invoice_by_hash");

        // Try to get the invoice from storage first
        let invoice = match self.g.get_payment(hash).await {
            Ok(i) => i,
            Err(e) => {
                log_error!(self.logger, "could not get invoice by hash: {e}");
                return Err(e);
            }
        };

        if let Some(invoice) = invoice {
            log_trace!(self.logger, "retrieved invoice by hash");

            if matches!(invoice.status, HTLCStatus::InFlight | HTLCStatus::Pending) {
                log_trace!(self.logger, "invoice still in flight, getting operations");
                // If the invoice is InFlight or Pending, check the operation log for updates
                let lightning_module = self
                    .fedimint_client
                    .get_first_module::<LightningClientModule>();

                let operations = self
                    .fedimint_client
                    .operation_log()
                    .list_operations(FEDIMINT_OPERATIONS_LIST_MAX, None)
                    .await;

                log_trace!(
                    self.logger,
                    "going to go through {} operations",
                    operations.len()
                );
                for (key, entry) in operations {
                    if entry.operation_module_kind() == LightningCommonInit::KIND.as_str() {
                        if let Some(updated_invoice) = extract_invoice_from_entry(
                            self.logger.clone(),
                            &entry,
                            hash,
                            key.operation_id,
                            &lightning_module,
                        )
                        .await
                        {
                            self.maybe_update_after_checking_fedimint(updated_invoice.clone())
                                .await?;
                            return Ok(updated_invoice);
                        }
                    } else {
                        log_warn!(
                            self.logger,
                            "Unsupported module: {}",
                            entry.operation_module_kind()
                        );
                    }
                }
            } else {
                // If the invoice is not InFlight or Pending, return it directly
                log_trace!(self.logger, "returning final invoice");
                return Ok(invoice);
            }
        }

        log_debug!(self.logger, "could not find invoice");
        Err(MutinyError::NotFound)
    }

    pub(crate) async fn pay_invoice(
        &self,
        invoice: Bolt11Invoice,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        // Save before sending
        let mut stored_payment: MutinyInvoice = invoice.clone().into();
        stored_payment.inbound = false;
        stored_payment.labels = labels;
        self.g.save_payment(stored_payment.clone()).await?;

        let lightning_module = self
            .fedimint_client
            .get_first_module::<LightningClientModule>();

        let outgoing_payment = lightning_module
            .pay_bolt11_invoice(invoice.clone(), ())
            .await?;

        // Subscribe and process outcome based on payment type
        let inv = match outgoing_payment.payment_type {
            fedimint_ln_client::PayType::Internal(pay_id) => {
                match lightning_module.subscribe_internal_pay(pay_id).await {
                    Ok(o) => {
                        process_outcome(
                            o,
                            process_pay_state_internal,
                            invoice.clone(),
                            true,
                            DEFAULT_PAYMENT_TIMEOUT * 1_000,
                            Arc::clone(&self.logger),
                        )
                        .await
                    }
                    Err(_) => invoice.clone().into(),
                }
            }
            fedimint_ln_client::PayType::Lightning(pay_id) => {
                match lightning_module.subscribe_ln_pay(pay_id).await {
                    Ok(o) => {
                        process_outcome(
                            o,
                            process_pay_state_ln,
                            invoice.clone(),
                            false,
                            DEFAULT_PAYMENT_TIMEOUT * 1_000,
                            Arc::clone(&self.logger),
                        )
                        .await
                    }
                    Err(_) => invoice.clone().into(),
                }
            }
        };

        self.maybe_update_after_checking_fedimint(inv.clone())
            .await?;

        match inv.status {
            HTLCStatus::Succeeded => Ok(inv),
            HTLCStatus::Failed => Err(MutinyError::RoutingFailed),
            HTLCStatus::Pending => Err(MutinyError::PaymentTimeout),
            HTLCStatus::InFlight => Err(MutinyError::PaymentTimeout),
        }
    }

    pub fn get_mutiny_federation_identity(&self) -> FederationIdentity {
        FederationIdentity {
            uuid: self.uuid.clone(),
            federation_id: self.fedimint_client.federation_id(),
            federation_name: self.fedimint_client.get_meta("federation_name"),
            federation_expiry_timestamp: self
                .fedimint_client
                .get_meta("federation_expiry_timestamp"),
            welcome_message: self.fedimint_client.get_meta("welcome_message"),
        }
    }
}

// A federation private key will be derived from
// `m/1'/N'` where `N` is the network type.
//
// Federation will derive further keys from there.
fn create_federation_secret(
    xprivkey: ExtendedPrivKey,
    network: Network,
) -> Result<DerivableSecret, MutinyError> {
    let context = Secp256k1::new();

    let shared_key = create_root_child_key(&context, xprivkey, ChildKey::FederationChildKey)?;
    let xpriv = shared_key.derive_priv(
        &context,
        &DerivationPath::from(vec![ChildNumber::from_hardened_idx(
            coin_type_from_network(network),
        )?]),
    )?;

    // now that we have a private key for our federation secret, turn that into a mnemonic so we
    // can derive it just like fedimint does in case we ever want to expose the mnemonic for
    // fedimint cross compatibility.
    let mnemonic = mnemonic_from_xpriv(xpriv)?;
    Ok(Bip39RootSecretStrategy::<12>::to_root_secret(&mnemonic))
}

pub(crate) fn mnemonic_from_xpriv(xpriv: ExtendedPrivKey) -> Result<Mnemonic, MutinyError> {
    let mnemonic = Mnemonic::from_entropy(&xpriv.private_key.secret_bytes())?;
    Ok(mnemonic)
}

async fn extract_invoice_from_entry(
    logger: Arc<MutinyLogger>,
    entry: &OperationLogEntry,
    hash: &sha256::Hash,
    operation_id: OperationId,
    lightning_module: &LightningClientModule,
) -> Option<MutinyInvoice> {
    let lightning_meta: LightningOperationMeta = entry.meta();

    match lightning_meta.variant {
        LightningOperationMetaVariant::Pay(pay_meta) => {
            if pay_meta.invoice.payment_hash() == hash {
                match lightning_module.subscribe_ln_pay(operation_id).await {
                    Ok(o) => Some(
                        process_outcome(
                            o,
                            process_pay_state_ln,
                            pay_meta.invoice,
                            false,
                            FEDIMINT_STATUS_TIMEOUT_CHECK_MS,
                            logger,
                        )
                        .await,
                    ),
                    Err(_) => Some(pay_meta.invoice.into()),
                }
            } else {
                None
            }
        }
        LightningOperationMetaVariant::Receive { invoice, .. } => {
            if invoice.payment_hash() == hash {
                match lightning_module.subscribe_ln_receive(operation_id).await {
                    Ok(o) => Some(
                        process_outcome(
                            o,
                            process_receive_state,
                            invoice,
                            true,
                            FEDIMINT_STATUS_TIMEOUT_CHECK_MS,
                            logger,
                        )
                        .await,
                    ),
                    Err(_) => Some(invoice.into()),
                }
            } else {
                None
            }
        }
    }
}

fn process_pay_state_internal(pay_state: InternalPayState) -> (HTLCStatus, Option<String>) {
    let status: HTLCStatus = pay_state.clone().into();

    let p = if let InternalPayState::Preimage(preimage) = pay_state {
        Some(preimage.0.to_hex())
    } else {
        None
    };

    (status, p)
}

fn process_pay_state_ln(pay_state: LnPayState) -> (HTLCStatus, Option<String>) {
    let status: HTLCStatus = pay_state.clone().into();

    let p = if let LnPayState::Success { ref preimage } = pay_state {
        Some(preimage.to_string())
    } else {
        None
    };

    (status, p)
}

fn process_receive_state(receive_state: LnReceiveState) -> (HTLCStatus, Option<String>) {
    let status: HTLCStatus = receive_state.into();
    (status, None)
}

async fn process_outcome<U, F>(
    stream_or_outcome: UpdateStreamOrOutcome<U>,
    process_fn: F,
    invoice: Bolt11Invoice,
    inbound: bool,
    timeout: u64,
    logger: Arc<MutinyLogger>,
) -> MutinyInvoice
where
    U: Into<HTLCStatus>
        + Clone
        + Serialize
        + DeserializeOwned
        + Debug
        + MaybeSend
        + MaybeSync
        + 'static,
    F: Fn(U) -> (HTLCStatus, Option<String>) + Copy,
{
    let mut invoice: MutinyInvoice = invoice.into();
    invoice.inbound = inbound;

    match stream_or_outcome {
        UpdateStreamOrOutcome::Outcome(outcome) => {
            invoice.status = outcome.into();
            log_trace!(logger, "Outcome received: {}", invoice.status);
        }
        UpdateStreamOrOutcome::UpdateStream(mut s) => {
            let timeout_future = sleep(timeout as i32);
            pin_mut!(timeout_future);

            log_trace!(logger, "start timeout stream futures");
            while let future::Either::Left((outcome_option, _)) =
                future::select(s.next(), &mut timeout_future).await
            {
                if let Some(outcome) = outcome_option {
                    log_trace!(logger, "Streamed Outcome received: {:?}", outcome);
                    let (status, preimage) = process_fn(outcome);
                    invoice.status = status;
                    invoice.preimage = preimage;

                    if matches!(invoice.status, HTLCStatus::Succeeded | HTLCStatus::Failed) {
                        log_trace!(logger, "Streamed Outcome final, returning");
                        break;
                    }
                } else {
                    log_debug!(
                        logger,
                        "Timeout reached, exiting loop for payment {}",
                        invoice.payment_hash
                    );
                    break;
                }
            }
            log_trace!(
                logger,
                "Done with stream outcome, status: {}",
                invoice.status
            );
        }
    }

    invoice
}

#[cfg(test)]
fn fedimint_seed_generation() {
    use crate::generate_seed;

    let mnemonic = generate_seed(12).unwrap();

    let xpriv_regtest =
        ExtendedPrivKey::new_master(Network::Regtest, &mnemonic.to_seed("")).unwrap();
    let fed_secret_regtest = create_federation_secret(xpriv_regtest, Network::Regtest).unwrap();

    // create mainnet to ensure different
    let xpriv_mainnet =
        ExtendedPrivKey::new_master(Network::Bitcoin, &mnemonic.to_seed("")).unwrap();
    let fed_secret_mainnet = create_federation_secret(xpriv_mainnet, Network::Bitcoin).unwrap();

    assert_ne!(
        fed_secret_regtest.to_chacha20_poly1305_key_raw(),
        fed_secret_mainnet.to_chacha20_poly1305_key_raw(),
    );
}

#[cfg(test)]
fn fedimint_mnemonic_generation() {
    use super::*;

    let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let root_mnemonic = Mnemonic::from_str(mnemonic_str).expect("could not generate");
    let xpriv = ExtendedPrivKey::new_master(Network::Regtest, &root_mnemonic.to_seed("")).unwrap();
    let context = Secp256k1::new();
    let child_key = create_root_child_key(&context, xpriv, ChildKey::FederationChildKey).unwrap();

    let child_mnemonic = mnemonic_from_xpriv(child_key).unwrap();
    assert_ne!(mnemonic_str, child_mnemonic.to_string());

    let expected_child_mnemonic = "discover lift vanish gas also begin elevator must easily front kiwi motor glow shy lady sound crash flat bulk tilt sick super daring polar";
    assert_eq!(expected_child_mnemonic, child_mnemonic.to_string());

    // Do it again with different mnemonic
    let mnemonic_str2 = "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always";
    let root_mnemonic2 = Mnemonic::from_str(mnemonic_str2).expect("could not generate");
    let xpriv2 =
        ExtendedPrivKey::new_master(Network::Regtest, &root_mnemonic2.to_seed("")).unwrap();
    let context2 = Secp256k1::new();
    let child_key2 =
        create_root_child_key(&context2, xpriv2, ChildKey::FederationChildKey).unwrap();

    let child_mnemonic2 = mnemonic_from_xpriv(child_key2).unwrap();
    assert_ne!(mnemonic_str2, child_mnemonic2.to_string());

    let expected_child_mnemonic2 = "jewel primary rice smile garage lucky bullet scheme crack vehicle real urban pen another squeeze rate sorry never afraid chief proof decline reveal history";
    assert_ne!(expected_child_mnemonic, expected_child_mnemonic2);
    assert_eq!(expected_child_mnemonic2, child_mnemonic2.to_string());
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn test_fedimint_seed_generation() {
        fedimint_seed_generation();
    }

    #[test]
    fn test_fedimint_mnemonic_generation() {
        fedimint_mnemonic_generation();
    }
}

#[cfg(test)]
#[cfg(target_arch = "wasm32")]
mod wasm_tests {
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    fn test_fedimint_seed_generation() {
        fedimint_seed_generation();
    }

    #[test]
    fn test_fedimint_mnemonic_generation() {
        fedimint_mnemonic_generation();
    }
}
