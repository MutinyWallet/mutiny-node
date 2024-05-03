use crate::utils::{
    convert_from_fedimint_invoice, convert_to_fedimint_invoice, fetch_with_timeout, now, spawn,
};
use crate::TransactionDetails;
use crate::{
    error::{MutinyError, MutinyStorageError},
    event::PaymentInfo,
    key::{create_root_child_key, ChildKey},
    logging::MutinyLogger,
    onchain::coin_type_from_network,
    storage::{
        get_transaction_details, list_payment_info, persist_payment_info,
        persist_transaction_details, MutinyStorage, VersionedValue, TRANSACTION_DETAILS_PREFIX_KEY,
    },
    utils::sleep,
    HTLCStatus, MutinyInvoice, DEFAULT_PAYMENT_TIMEOUT,
};
use async_lock::RwLock;
use async_trait::async_trait;
use bdk_chain::ConfirmationTime;
use bip39::Mnemonic;
use bitcoin::{
    address::NetworkUnchecked,
    bip32::{ChildNumber, DerivationPath, ExtendedPrivKey},
    hashes::Hash,
    secp256k1::{Secp256k1, SecretKey, ThirtyTwoByteHash},
    Address, Network, Txid,
};
use core::fmt;
use esplora_client::AsyncClient;
use fedimint_bip39::Bip39RootSecretStrategy;
use fedimint_client::{
    derivable_secret::DerivableSecret,
    oplog::{OperationLogEntry, UpdateStreamOrOutcome},
    secret::{get_default_client_secret, RootSecretStrategy},
    ClientHandleArc,
};
use fedimint_core::bitcoin_migration::bitcoin30_to_bitcoin29_address;
use fedimint_core::config::ClientConfig;
use fedimint_core::{
    api::InviteCode,
    config::FederationId,
    core::OperationId,
    module::CommonModuleInit,
    task::{MaybeSend, MaybeSync},
    Amount,
};
use fedimint_core::{
    db::{
        mem_impl::{MemDatabase, MemTransaction},
        IDatabaseTransactionOps, IDatabaseTransactionOpsCore, IRawDatabase,
        IRawDatabaseTransaction, PrefixStream,
    },
    BitcoinHash,
};
use fedimint_ln_client::{
    InternalPayState, LightningClientInit, LightningClientModule, LightningOperationMeta,
    LightningOperationMetaVariant, LnPayState, LnReceiveState,
};
use fedimint_ln_common::lightning_invoice::{Bolt11InvoiceDescription, Description, RoutingFees};
use fedimint_ln_common::{LightningCommonInit, LightningGateway};
use fedimint_mint_client::MintClientInit;
use fedimint_wallet_client::{
    WalletClientInit, WalletClientModule, WalletCommonInit, WalletOperationMeta, WithdrawState,
};
use futures::{select, FutureExt};
use futures_util::{pin_mut, StreamExt};
use hex_conservative::{DisplayHex, FromHex};
use lightning::{log_debug, log_error, log_info, log_trace, log_warn, util::logger::Logger};
use lightning_invoice::Bolt11Invoice;
use reqwest::Method;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::time::Duration;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    sync::{atomic::AtomicBool, Arc},
};
use std::{
    str::FromStr,
    sync::atomic::{AtomicU32, Ordering},
};
#[cfg(target_arch = "wasm32")]
use web_time::Instant;

// The maximum amount of operations we try to pull
// from fedimint when we need to search through
// their internal list.
const FEDIMINT_OPERATIONS_LIST_MAX: usize = 100;

// On chain peg in timeout
const PEG_IN_TIMEOUT_YEAR: Duration = Duration::from_secs(86400 * 365);

pub const FEDIMINTS_PREFIX_KEY: &str = "fedimints/";

// Default signet/mainnet federation gateway info
const SIGNET_GATEWAY: &str = "0256f5ef1d986e9abf559651b7167de28bfd954683cd0f14703be12d1421aedc55";
const MAINNET_GATEWAY: &str = "025b9f090d3daab012346701f27d1c220d6d290f6b498255cddc492c255532a09d";
const SIGNET_FEDERATION: &str = "c8d423964c7ad944d30f57359b6e5b260e211dcfdb945140e28d4df51fd572d2";
const MAINNET_FEDERATION: &str = "c36038cce5a97e3467f03336fa8e7e3410960b81d1865cda2a609f70a8f51efb";

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
    pub invite_code: InviteCode,
    // https://github.com/fedimint/fedimint/tree/master/docs/meta_fields
    pub federation_name: Option<String>,
    pub federation_expiry_timestamp: Option<String>,
    pub welcome_message: Option<String>,
    pub gateway_fees: Option<GatewayFees>,
    // undocumented parameters that fedi uses: https://meta.dev.fedibtc.com/meta.json
    pub default_currency: Option<String>,
    pub federation_icon_url: Option<String>,
    pub max_balance_msats: Option<u32>,
    pub max_invoice_msats: Option<u32>,
    pub meta_external_url: Option<String>,
    pub onchain_deposits_disabled: Option<bool>,
    pub preview_message: Option<String>,
    pub public: Option<bool>,
    pub tos_url: Option<String>,
    pub popup_end_timestamp: Option<u32>,
    pub popup_countdown_message: Option<String>,
    pub invite_codes_disabled: Option<bool>,
    pub stability_pool_disabled: Option<bool>,
    pub social_recovery_disabled: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
struct FederationMetaConfig {
    #[serde(flatten)]
    pub federations: std::collections::HashMap<String, FederationMeta>,
}

// This is the FederationUrlConfig that refer to a specific federation
// Normal config information that might exist from their URL.
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
pub struct FederationMeta {
    // https://github.com/fedimint/fedimint/tree/master/docs/meta_fields
    pub federation_name: Option<String>,
    pub federation_expiry_timestamp: Option<String>,
    pub welcome_message: Option<String>,
    pub gateway_fees: Option<GatewayFees>,
    // undocumented parameters that fedi uses: https://meta.dev.fedibtc.com/meta.json
    pub default_currency: Option<String>,
    pub federation_icon_url: Option<String>,
    pub max_balance_msats: Option<String>,
    pub max_invoice_msats: Option<String>,
    pub meta_external_url: Option<String>,
    pub onchain_deposits_disabled: Option<String>,
    pub preview_message: Option<String>,
    pub public: Option<String>,
    pub tos_url: Option<String>,
    pub popup_end_timestamp: Option<String>,
    pub popup_countdown_message: Option<String>,
    pub invite_codes_disabled: Option<String>,
    pub stability_pool_disabled: Option<String>,
    pub social_recovery_disabled: Option<String>,
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Site {
    pub id: Option<String>,
    pub url: Option<String>,
    pub title: Option<String>,
    pub image_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Default)]
pub struct GatewayFees {
    pub base_msat: u32,
    pub proportional_millionths: u32,
}

impl From<RoutingFees> for GatewayFees {
    fn from(val: RoutingFees) -> Self {
        GatewayFees {
            base_msat: val.base_msat,
            proportional_millionths: val.proportional_millionths,
        }
    }
}

// This is the FederationIndex reference that is saved to the DB
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct FederationIndex {
    pub federation_code: InviteCode,
}

pub struct FedimintBalance {
    pub amount: u64,
}

#[cfg_attr(test, mockall::automock)]
pub trait FedimintClient {
    async fn claim_external_receive(
        &self,
        secret_key: &SecretKey,
        tweaks: Vec<u64>,
    ) -> Result<(), MutinyError>;
}

pub(crate) struct FederationClient<S: MutinyStorage> {
    pub(crate) uuid: String,
    pub(crate) fedimint_client: ClientHandleArc,
    invite_code: InviteCode,
    storage: S,
    #[allow(dead_code)]
    fedimint_storage: FedimintStorage<S>,
    gateway: Arc<RwLock<Option<LightningGateway>>>,
    esplora: Arc<AsyncClient>,
    network: Network,
    stop: Arc<AtomicBool>,
    pub(crate) logger: Arc<MutinyLogger>,
}

impl<S: MutinyStorage> FederationClient<S> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn new(
        uuid: String,
        federation_code: InviteCode,
        xprivkey: ExtendedPrivKey,
        storage: S,
        esplora: Arc<AsyncClient>,
        network: Network,
        stop: Arc<AtomicBool>,
        logger: Arc<MutinyLogger>,
    ) -> Result<Self, MutinyError> {
        log_info!(logger, "initializing a new federation client: {uuid}");

        let federation_id = federation_code.federation_id();

        log_trace!(logger, "Building fedimint client db");
        let fedimint_storage =
            FedimintStorage::new(storage.clone(), federation_id.to_string(), logger.clone())
                .await?;
        let db = fedimint_storage.clone().into();

        let is_initialized = fedimint_client::Client::is_initialized(&db).await;

        let mut client_builder = fedimint_client::Client::builder(db);
        client_builder.with_module(WalletClientInit(None));
        client_builder.with_module(MintClientInit);
        client_builder.with_module(LightningClientInit);

        client_builder.with_primary_module(1);

        log_trace!(logger, "Building fedimint client db");
        let secret = create_federation_secret(xprivkey, network)?;

        let fedimint_client = if is_initialized {
            client_builder
                .open(get_default_client_secret(&secret, &federation_id))
                .await
                .map_err(|e| {
                    log_error!(logger, "Could not open federation client: {e}");
                    MutinyError::FederationConnectionFailed
                })?
        } else {
            let download = Instant::now();
            let config = ClientConfig::download_from_invite_code(&federation_code)
                .await
                .map_err(|e| {
                    log_error!(logger, "Could not download federation info: {e}");
                    e
                })?;
            log_trace!(
                logger,
                "Downloaded federation info in: {}ms",
                download.elapsed().as_millis()
            );

            client_builder
                .join(get_default_client_secret(&secret, &federation_id), config)
                .await
                .map_err(|e| {
                    log_error!(logger, "Could not join federation: {e}");
                    MutinyError::FederationConnectionFailed
                })?
        };
        let fedimint_client = Arc::new(fedimint_client);

        log_trace!(logger, "Retrieving fedimint wallet client module");

        // check federation is on expected network
        let wallet_client = fedimint_client.get_first_module::<WalletClientModule>();
        // compare magic bytes because different versions of rust-bitcoin
        if network.magic().to_bytes() != wallet_client.get_network().magic().to_le_bytes() {
            log_error!(
                logger,
                "Fedimint on different network {}, expected: {network}",
                wallet_client.get_network()
            );

            // try to delete the storage for this federation
            if let Err(e) = fedimint_storage.delete_store().await {
                log_error!(logger, "Could not delete fedimint storage: {e}");
            }

            return Err(MutinyError::NetworkMismatch);
        }

        let gateway = Arc::new(RwLock::new(None));

        // Set active gateway preference in background
        let client_clone = fedimint_client.clone();
        let gateway_clone = gateway.clone();
        let logger_clone = logger.clone();
        spawn(async move {
            let start = Instant::now();
            // get lock immediately to block other actions until gateway is set
            let mut gateway_lock = gateway_clone.write().await;
            let lightning_module = client_clone.get_first_module::<LightningClientModule>();

            match lightning_module.update_gateway_cache(true).await {
                Ok(_) => {
                    log_trace!(logger_clone, "Updated lightning gateway cache");
                }
                Err(e) => {
                    log_error!(
                        logger_clone,
                        "Could not update lightning gateway cache: {e}"
                    );
                }
            }

            let gateways = lightning_module.list_gateways().await;
            if let Some(a) = get_gateway_preference(gateways, federation_id) {
                log_info!(
                    logger_clone,
                    "Setting active gateway for federation {federation_id}: {a}"
                );

                let gateway = lightning_module.select_gateway(&a).await;
                *gateway_lock = gateway;
            }

            log_trace!(
                logger_clone,
                "Setting active gateway took: {}ms",
                start.elapsed().as_millis()
            );
        });

        log_debug!(logger, "Built fedimint client");

        let federation_client = FederationClient {
            uuid,
            fedimint_client,
            fedimint_storage,
            storage,
            logger,
            invite_code: federation_code,
            esplora,
            network,
            stop,
            gateway,
        };

        Ok(federation_client)
    }

    pub(crate) async fn process_previous_operations(&self) -> Result<(), MutinyError> {
        // look for our internal state pending transactions
        let mut pending_invoices: HashSet<[u8; 32]> = HashSet::new();

        pending_invoices.extend(
            list_payment_info(&self.storage, true)?
                .into_iter()
                .filter(|(_h, i)| matches!(i.status, HTLCStatus::InFlight | HTLCStatus::Pending))
                .map(|(h, _i)| h.0),
        );

        pending_invoices.extend(
            list_payment_info(&self.storage, false)?
                .into_iter()
                .filter(|(_h, i)| matches!(i.status, HTLCStatus::InFlight | HTLCStatus::Pending))
                .map(|(h, _i)| h.0),
        );

        // pending on chain operations
        let pending_wallet_txids = self
            .storage
            .scan::<TransactionDetails>(TRANSACTION_DETAILS_PREFIX_KEY, None)?
            .into_iter()
            .filter(|(_k, v)| match v.confirmation_time {
                ConfirmationTime::Unconfirmed { .. } => true, // return all unconfirmed transactions
                _ => false,                                   // skip confirmed transactions
            })
            .map(|(_h, i)| i.internal_id)
            .collect::<HashSet<Txid>>();

        // go through last 100 operations
        let operations = self
            .fedimint_client
            .operation_log()
            .list_operations(FEDIMINT_OPERATIONS_LIST_MAX, None)
            .await;

        // find all of the pending ones
        for (key, entry) in operations {
            let module_type = entry.operation_module_kind();
            if module_type == LightningCommonInit::KIND.as_str() {
                let lightning_meta: LightningOperationMeta = entry.meta();
                match lightning_meta.variant {
                    LightningOperationMetaVariant::Pay(pay_meta) => {
                        let hash = pay_meta.invoice.payment_hash().into_inner();
                        if pending_invoices.contains(&hash) {
                            self.subscribe_operation(entry, key.operation_id);
                        }
                    }
                    LightningOperationMetaVariant::Receive { invoice, .. } => {
                        let hash = invoice.payment_hash().into_inner();
                        if pending_invoices.contains(&hash) {
                            self.subscribe_operation(entry, key.operation_id);
                        }
                    }
                    LightningOperationMetaVariant::Claim { .. } => {}
                }
            } else if module_type == WalletCommonInit::KIND.as_str() {
                let internal_id = Txid::from_slice(&key.operation_id.0)
                    .map_err(|_| MutinyError::ChainAccessFailed)
                    .expect("should convert");

                if pending_wallet_txids.contains(&internal_id) {
                    self.subscribe_operation(entry, key.operation_id);
                }
            } else {
                log_warn!(self.logger, "Unknown module type: {module_type}")
            }
        }

        Ok(())
    }

    fn subscribe_operation(&self, entry: OperationLogEntry, operation_id: OperationId) {
        subscribe_operation_ext(
            entry,
            operation_id,
            self.fedimint_client.clone(),
            self.esplora.clone(),
            self.logger.clone(),
            self.stop.clone(),
            self.storage.clone(),
        );
    }

    pub(crate) async fn gateway_fee(&self) -> Result<GatewayFees, MutinyError> {
        let gateway = self.gateway.read().await;
        Ok(gateway.as_ref().map(|x| x.fees.into()).unwrap_or_default())
    }

    pub(crate) async fn get_invoice(
        &self,
        amount: u64,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        let inbound = true;

        let lightning_module = self
            .fedimint_client
            .get_first_module::<LightningClientModule>();

        let desc = Description::new(String::new()).expect("empty string is valid");
        let gateway = self.gateway.read().await;
        let (id, invoice, _) = lightning_module
            .create_bolt11_invoice(
                Amount::from_sats(amount),
                Bolt11InvoiceDescription::Direct(&desc),
                None,
                (),
                gateway.clone(),
            )
            .await?;
        let invoice = convert_from_fedimint_invoice(&invoice);

        // persist the invoice
        let mut stored_payment: MutinyInvoice = invoice.clone().into();
        stored_payment.inbound = inbound;
        stored_payment.labels = labels;

        log_trace!(self.logger, "Persisting payment");
        let hash = stored_payment.payment_hash.into_32();
        let payment_info = PaymentInfo::from(stored_payment);
        persist_payment_info(&self.storage, &hash, &payment_info, inbound)?;
        log_trace!(self.logger, "Persisted payment");

        // subscribe to updates for it
        let fedimint_client_clone = self.fedimint_client.clone();
        let logger_clone = self.logger.clone();
        let storage_clone = self.storage.clone();
        let esplora_clone = self.esplora.clone();
        let stop = self.stop.clone();
        spawn(async move {
            let operation = fedimint_client_clone
                .operation_log()
                .get_operation(id)
                .await
                .expect("just created it");

            subscribe_operation_ext(
                operation,
                id,
                fedimint_client_clone,
                esplora_clone,
                logger_clone,
                stop,
                storage_clone,
            );
        });

        Ok(invoice.into())
    }

    pub(crate) async fn get_new_address(
        &self,
        labels: Vec<String>,
    ) -> Result<Address, MutinyError> {
        let wallet_module = self
            .fedimint_client
            .get_first_module::<WalletClientModule>();

        let (op_id, address) = wallet_module
            .get_deposit_address(fedimint_core::time::now() + PEG_IN_TIMEOUT_YEAR, ())
            .await?;

        let internal_id = Txid::from_slice(&op_id.0).map_err(|_| MutinyError::ChainAccessFailed)?;

        // persist the data we can while we wait for the transaction to come from fedimint
        let pending_transaction_details = TransactionDetails {
            transaction: None,
            txid: None,
            internal_id,
            received: 0,
            sent: 0,
            fee: None,
            confirmation_time: ConfirmationTime::Unconfirmed {
                last_seen: now().as_secs(),
            },
            labels,
        };

        persist_transaction_details(&self.storage, &pending_transaction_details)?;

        // subscribe
        let operation = self
            .fedimint_client
            .operation_log()
            .get_operation(op_id)
            .await
            .expect("just created it");
        self.subscribe_operation(operation, op_id);

        Ok(Address::from_str(&address.to_string())
            .expect("should convert")
            .assume_checked())
    }

    /// Get the balance of this federation client in sats
    pub(crate) async fn get_balance(&self) -> Result<u64, MutinyError> {
        Ok(self.fedimint_client.get_balance().await.msats / 1_000)
    }

    fn maybe_update_after_checking_fedimint(
        &self,
        updated_invoice: MutinyInvoice,
    ) -> Result<(), MutinyError> {
        maybe_update_after_checking_fedimint(
            updated_invoice,
            self.logger.clone(),
            self.storage.clone(),
        )?;
        Ok(())
    }

    pub(crate) async fn pay_invoice(
        &self,
        invoice: Bolt11Invoice,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        let inbound = false;

        let lightning_module = self
            .fedimint_client
            .get_first_module::<LightningClientModule>();

        let fedimint_invoice = convert_to_fedimint_invoice(&invoice);
        let gateway = self.gateway.read().await;
        let outgoing_payment = lightning_module
            .pay_bolt11_invoice(gateway.clone(), fedimint_invoice, ())
            .await?;

        // Save after payment was initiated successfully
        let mut stored_payment: MutinyInvoice = invoice.clone().into();
        stored_payment.inbound = inbound;
        stored_payment.labels = labels;
        stored_payment.status = HTLCStatus::InFlight;
        let hash = stored_payment.payment_hash.into_32();
        let payment_info = PaymentInfo::from(stored_payment);
        persist_payment_info(&self.storage, &hash, &payment_info, inbound)?;

        // Subscribe and process outcome based on payment type
        let (mut inv, id) = match outgoing_payment.payment_type {
            fedimint_ln_client::PayType::Internal(pay_id) => {
                match lightning_module.subscribe_internal_pay(pay_id).await {
                    Ok(o) => {
                        let o = process_ln_outcome(
                            o,
                            process_pay_state_internal,
                            invoice.clone(),
                            inbound,
                            Some(DEFAULT_PAYMENT_TIMEOUT * 1_000),
                            self.stop.clone(),
                            Arc::clone(&self.logger),
                        )
                        .await;
                        (o, pay_id)
                    }
                    Err(_) => (invoice.clone().into(), pay_id),
                }
            }
            fedimint_ln_client::PayType::Lightning(pay_id) => {
                match lightning_module.subscribe_ln_pay(pay_id).await {
                    Ok(o) => {
                        let o = process_ln_outcome(
                            o,
                            process_pay_state_ln,
                            invoice.clone(),
                            inbound,
                            Some(DEFAULT_PAYMENT_TIMEOUT * 1_000),
                            self.stop.clone(),
                            Arc::clone(&self.logger),
                        )
                        .await;
                        (o, pay_id)
                    }
                    Err(_) => (invoice.clone().into(), pay_id),
                }
            }
        };
        inv.fees_paid = Some(sats_round_up(&outgoing_payment.fee));

        self.maybe_update_after_checking_fedimint(inv.clone())?;

        match inv.status {
            HTLCStatus::Succeeded => Ok(inv),
            HTLCStatus::Failed => Err(MutinyError::RoutingFailed),
            _ => {
                // keep streaming after timeout happens
                let fedimint_client_clone = self.fedimint_client.clone();
                let logger_clone = self.logger.clone();
                let storage_clone = self.storage.clone();
                let esplora_clone = self.esplora.clone();
                let stop = self.stop.clone();
                spawn(async move {
                    let operation = fedimint_client_clone
                        .operation_log()
                        .get_operation(id)
                        .await
                        .expect("just created it");

                    subscribe_operation_ext(
                        operation,
                        id,
                        fedimint_client_clone,
                        esplora_clone,
                        logger_clone,
                        stop,
                        storage_clone,
                    );
                });

                Err(MutinyError::PaymentTimeout)
            }
        }
    }

    /// Send on chain transaction
    pub(crate) async fn send_onchain(
        &self,
        send_to: bitcoin::Address<NetworkUnchecked>,
        amount: u64,
        labels: Vec<String>,
    ) -> Result<Txid, MutinyError> {
        let address = bitcoin30_to_bitcoin29_address(send_to.require_network(self.network)?);

        let btc_amount = fedimint_ln_common::bitcoin::Amount::from_sat(amount);

        let wallet_module = self
            .fedimint_client
            .get_first_module::<WalletClientModule>();

        let peg_out_fees = wallet_module
            .get_withdraw_fees(address.clone(), btc_amount)
            .await?;

        let op_id = wallet_module
            .withdraw(address, btc_amount, peg_out_fees, ())
            .await?;

        let internal_id = Txid::from_slice(&op_id.0).map_err(|_| MutinyError::ChainAccessFailed)?;

        let pending_transaction_details = TransactionDetails {
            transaction: None,
            txid: None,
            internal_id,
            received: 0,
            sent: amount,
            fee: Some(peg_out_fees.amount().to_sat()),
            confirmation_time: ConfirmationTime::Unconfirmed {
                last_seen: now().as_secs(),
            },
            labels,
        };

        persist_transaction_details(&self.storage, &pending_transaction_details)?;

        // subscribe
        let operation = self
            .fedimint_client
            .operation_log()
            .get_operation(op_id)
            .await
            .expect("just created it");

        // Subscribe for a little bit, just to hopefully get transaction id
        process_operation_until_timeout(
            self.logger.clone(),
            operation,
            op_id,
            self.fedimint_client.clone(),
            self.storage.clone(),
            self.esplora.clone(),
            Some(DEFAULT_PAYMENT_TIMEOUT * 1_000),
            self.stop.clone(),
        )
        .await;

        // now check the status of the payment from storage
        if let Some(t) = get_transaction_details(&self.storage, internal_id, &self.logger) {
            if t.txid.is_some() {
                return Ok(internal_id);
            }
        }

        // keep subscribing if txid wasn't retrieved, but then return timeout
        let operation = self
            .fedimint_client
            .operation_log()
            .get_operation(op_id)
            .await
            .expect("just created it");
        self.subscribe_operation(operation, op_id);

        Err(MutinyError::PaymentTimeout)
    }

    /// Someone received a payment on our behalf, we need to claim it
    pub async fn claim_external_receive(
        &self,
        secret_key: &SecretKey,
        tweaks: Vec<u64>,
    ) -> Result<(), MutinyError> {
        let lightning_module = self
            .fedimint_client
            .get_first_module::<LightningClientModule>();

        let key_pair = fedimint_ln_common::bitcoin::secp256k1::KeyPair::from_seckey_slice(
            fedimint_ln_common::bitcoin::secp256k1::SECP256K1,
            &secret_key.secret_bytes(),
        )
        .map_err(|_| MutinyError::InvalidArgumentsError)?;
        let operation_ids = lightning_module
            .scan_receive_for_user_tweaked(key_pair, tweaks, ())
            .await;

        if operation_ids.is_empty() {
            log_warn!(
                self.logger,
                "External receive not found, maybe already claimed?"
            );
            return Err(MutinyError::NotFound);
        }

        for operation_id in operation_ids {
            let mut updates = lightning_module
                .subscribe_ln_claim(operation_id)
                .await?
                .into_stream();

            while let Some(update) = updates.next().await {
                match update {
                    LnReceiveState::Claimed => {
                        log_info!(self.logger, "External receive claimed!");
                    }
                    LnReceiveState::Canceled { reason } => {
                        log_error!(self.logger, "External receive canceled: {reason}");
                        return Err(MutinyError::InvalidArgumentsError); // todo better error
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    pub async fn get_mutiny_federation_identity(&self) -> FederationIdentity {
        let gateway_fees = self.gateway_fee().await.ok();
        get_federation_identity(
            self.uuid.clone(),
            self.fedimint_client.clone(),
            self.invite_code.clone(),
            gateway_fees,
            self.logger.clone(),
        )
        .await
    }

    // delete_fedimint_storage is not suggested at the moment due to the lack of easy restores
    #[allow(dead_code)]
    pub async fn delete_fedimint_storage(&self) -> Result<(), MutinyError> {
        self.fedimint_storage.delete_store().await
    }
}

pub(crate) async fn get_federation_identity(
    uuid: String,
    fedimint_client: ClientHandleArc,
    invite_code: InviteCode,
    gateway_fees: Option<GatewayFees>,

    logger: Arc<MutinyLogger>,
) -> FederationIdentity {
    let federation_id = fedimint_client.federation_id();
    let meta_external_url = fedimint_client.get_meta("meta_external_url");
    let config = if let Some(ref url) = meta_external_url {
        log_info!(
            logger,
            "Getting config for {federation_id} from meta_external_url: {url}"
        );
        let http_client = reqwest::Client::new();
        let request = http_client.request(Method::GET, url);

        match fetch_with_timeout(&http_client, request.build().expect("should build req")).await {
            Ok(r) => match r.json::<FederationMetaConfig>().await {
                Ok(c) =>
                {
                    #[allow(clippy::map_clone)]
                    c.federations
                        .get(&federation_id.to_string())
                        .map(|f| f.clone())
                }
                Err(e) => {
                    log_error!(logger, "Error parsing meta config: {e}");
                    None
                }
            },
            Err(e) => {
                log_error!(logger, "Error fetching meta config: {e}");
                None
            }
        }
    } else {
        None
    };

    FederationIdentity {
        uuid: uuid.clone(),
        federation_id,
        invite_code: invite_code.clone(),
        federation_name: merge_values(
            fedimint_client.get_meta("federation_name").clone(),
            config.as_ref().and_then(|c| c.federation_name.clone()),
        ),
        federation_expiry_timestamp: merge_values(
            fedimint_client.get_meta("federation_expiry_timestamp"),
            config
                .as_ref()
                .and_then(|c| c.federation_expiry_timestamp.clone()),
        ),
        welcome_message: merge_values(
            fedimint_client.get_meta("welcome_message"),
            config.as_ref().and_then(|c| c.welcome_message.clone()),
        ),
        gateway_fees, // Already merged using helper function...
        default_currency: merge_values(
            fedimint_client.get_meta("default_currency"),
            config.as_ref().and_then(|c| c.default_currency.clone()),
        ),
        federation_icon_url: merge_values(
            fedimint_client.get_meta("federation_icon_url"),
            config.as_ref().and_then(|c| c.federation_icon_url.clone()),
        ),
        max_balance_msats: merge_values(
            fedimint_client
                .get_meta("max_balance_msats")
                .map(|v| v.parse().unwrap_or(0)),
            config
                .as_ref()
                .and_then(|c| c.max_balance_msats.clone().map(|v| v.parse().unwrap_or(0))),
        ),
        max_invoice_msats: merge_values(
            fedimint_client
                .get_meta("max_invoice_msats")
                .map(|v| v.parse().unwrap_or(0)),
            config
                .as_ref()
                .and_then(|c| c.max_invoice_msats.clone().map(|v| v.parse().unwrap_or(0))),
        ),
        meta_external_url, // Already set...
        onchain_deposits_disabled: merge_values(
            fedimint_client
                .get_meta("onchain_deposits_disabled")
                .map(|v| v.parse().unwrap_or(false)),
            config.as_ref().and_then(|c| {
                c.onchain_deposits_disabled
                    .clone()
                    .map(|v| v.parse().unwrap_or(false))
            }),
        ),
        preview_message: merge_values(
            fedimint_client.get_meta("preview_message"),
            config.as_ref().and_then(|c| c.preview_message.clone()),
        ),
        public: merge_values(
            fedimint_client
                .get_meta("public")
                .map(|v| v.parse().unwrap_or(false)),
            config
                .as_ref()
                .and_then(|c| c.public.clone().map(|v| v.parse().unwrap_or(false))),
        ),
        tos_url: merge_values(
            fedimint_client.get_meta("tos_url"),
            config.as_ref().and_then(|c| c.tos_url.clone()),
        ),
        popup_end_timestamp: merge_values(
            fedimint_client
                .get_meta("popup_end_timestamp")
                .map(|v| v.parse().unwrap_or(0)),
            config.as_ref().and_then(|c| {
                c.popup_end_timestamp
                    .clone()
                    .map(|v| v.parse().unwrap_or(0))
            }),
        ),
        popup_countdown_message: merge_values(
            fedimint_client
                .get_meta("popup_countdown_message")
                .map(|v| v.to_string()),
            config
                .as_ref()
                .and_then(|c| c.popup_countdown_message.clone()),
        ),
        invite_codes_disabled: merge_values(
            fedimint_client
                .get_meta("invite_codes_disabled")
                .map(|v| v.parse().unwrap_or(false)),
            config.as_ref().and_then(|c| {
                c.invite_codes_disabled
                    .clone()
                    .map(|v| v.parse().unwrap_or(false))
            }),
        ),
        stability_pool_disabled: merge_values(
            fedimint_client
                .get_meta("stability_pool_disabled")
                .map(|v| v.parse().unwrap_or(false)),
            config.as_ref().and_then(|c| {
                c.stability_pool_disabled
                    .clone()
                    .map(|v| v.parse().unwrap_or(false))
            }),
        ),
        social_recovery_disabled: merge_values(
            fedimint_client
                .get_meta("social_recovery_disabled")
                .map(|v| v.parse().unwrap_or(false)),
            config.as_ref().and_then(|c| {
                c.social_recovery_disabled
                    .clone()
                    .map(|v| v.parse().unwrap_or(false))
            }),
        ),
    }
}

fn merge_values<T>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        // If a has value return that; otherwise, use the one from b if available.
        (Some(val), _) => Some(val),
        (None, Some(val)) => Some(val),
        (None, None) => None,
    }
}

fn subscribe_operation_ext<S: MutinyStorage>(
    entry: OperationLogEntry,
    operation_id: OperationId,
    fedimint_client: ClientHandleArc,
    esplora: Arc<AsyncClient>,
    logger: Arc<MutinyLogger>,
    stop: Arc<AtomicBool>,
    storage: S,
) {
    spawn(async move {
        process_operation_until_timeout(
            logger.clone(),
            entry,
            operation_id,
            fedimint_client,
            storage,
            esplora,
            None,
            stop,
        )
        .await;
    });
}

fn maybe_update_after_checking_fedimint<S: MutinyStorage>(
    updated_invoice: MutinyInvoice,
    logger: Arc<MutinyLogger>,
    storage: S,
) -> Result<(), MutinyError> {
    match updated_invoice.status {
        HTLCStatus::Succeeded | HTLCStatus::Failed => {
            log_debug!(logger, "Saving updated payment");
            let hash = updated_invoice.payment_hash.into_32();
            let inbound = updated_invoice.inbound;
            let mut payment_info = PaymentInfo::from(updated_invoice);
            payment_info.last_update = now().as_secs();
            persist_payment_info(&storage, &hash, &payment_info, inbound)?;
        }
        HTLCStatus::Pending | HTLCStatus::InFlight => (),
    }

    Ok(())
}

impl<S: MutinyStorage> FedimintClient for FederationClient<S> {
    async fn claim_external_receive(
        &self,
        secret_key: &SecretKey,
        tweaks: Vec<u64>,
    ) -> Result<(), MutinyError> {
        self.claim_external_receive(secret_key, tweaks).await
    }
}

fn sats_round_up(amount: &Amount) -> u64 {
    Amount::from_msats(amount.msats + 999).sats_round_down()
}

// Get a preferred gateway from a federation
fn get_gateway_preference(
    gateways: Vec<fedimint_ln_common::LightningGatewayAnnouncement>,
    federation_id: FederationId,
) -> Option<fedimint_ln_common::bitcoin::secp256k1::PublicKey> {
    let mut active_choice: Option<fedimint_ln_common::bitcoin::secp256k1::PublicKey> = None;

    let signet_gateway_id =
        fedimint_ln_common::bitcoin::secp256k1::PublicKey::from_str(SIGNET_GATEWAY)
            .expect("should be valid pubkey");
    let mainnet_gateway_id =
        fedimint_ln_common::bitcoin::secp256k1::PublicKey::from_str(MAINNET_GATEWAY)
            .expect("should be valid pubkey");
    let signet_federation_id =
        FederationId::from_str(SIGNET_FEDERATION).expect("should be a valid federation id");
    let mainnet_federation_id =
        FederationId::from_str(MAINNET_FEDERATION).expect("should be a valid federation id");

    for g in gateways.iter() {
        let g_id = g.info.gateway_id;

        // if the gateway node ID matches what we expect for our signet/mainnet
        // these take the highest priority
        if (g_id == signet_gateway_id && federation_id == signet_federation_id)
            || (g_id == mainnet_gateway_id && federation_id == mainnet_federation_id)
        {
            return Some(g_id);
        }

        // if vetted, set up as current active choice
        if g.vetted {
            active_choice = Some(g_id);
            continue;
        }

        // if not vetted, make sure fee is high enough
        if active_choice.is_none() {
            let fees = g.info.fees;
            if fees.base_msat >= 1_000 && fees.proportional_millionths >= 100 {
                active_choice = Some(g_id);
                continue;
            }
        }
    }

    // fallback to any gateway if none fit our criteria
    if active_choice.is_none() {
        active_choice = gateways.first().map(|g| g.info.gateway_id);
    }

    active_choice
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

    let shared_key = create_root_child_key(&context, xprivkey, ChildKey::Federation)?;
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

// FIXME refactor
#[allow(clippy::too_many_arguments)]
async fn process_operation_until_timeout<S: MutinyStorage>(
    logger: Arc<MutinyLogger>,
    entry: OperationLogEntry,
    operation_id: OperationId,
    fedimint_client: ClientHandleArc,
    storage: S,
    esplora: Arc<AsyncClient>,
    timeout: Option<u64>,
    stop: Arc<AtomicBool>,
) {
    let module_type = entry.operation_module_kind();
    if module_type == LightningCommonInit::KIND.as_str() {
        let lightning_meta: LightningOperationMeta = entry.meta();

        let lightning_module =
            Arc::new(fedimint_client.get_first_module::<LightningClientModule>());

        let updated_invoice = match lightning_meta.variant {
            LightningOperationMetaVariant::Pay(pay_meta) => {
                let hash = pay_meta.invoice.payment_hash().into_inner();
                let invoice = convert_from_fedimint_invoice(&pay_meta.invoice);
                if invoice.payment_hash().into_32() == hash {
                    match lightning_module.subscribe_ln_pay(operation_id).await {
                        Ok(o) => Some(
                            process_ln_outcome(
                                o,
                                process_pay_state_ln,
                                invoice,
                                false,
                                timeout,
                                stop,
                                logger.clone(),
                            )
                            .await,
                        ),
                        Err(e) => {
                            log_error!(logger, "Error trying to process stream outcome: {e}");

                            // return the latest status of the invoice even if it fails
                            Some(invoice.into())
                        }
                    }
                } else {
                    None
                }
            }
            LightningOperationMetaVariant::Receive { invoice, .. } => {
                let hash = invoice.payment_hash().into_inner();
                let invoice = convert_from_fedimint_invoice(&invoice);
                if invoice.payment_hash().into_32() == hash {
                    match lightning_module.subscribe_ln_receive(operation_id).await {
                        Ok(o) => Some(
                            process_ln_outcome(
                                o,
                                process_receive_state,
                                invoice,
                                true,
                                timeout,
                                stop,
                                logger.clone(),
                            )
                            .await,
                        ),
                        Err(e) => {
                            log_error!(logger, "Error trying to process stream outcome: {e}");

                            // return the latest status of the invoice even if it fails
                            Some(invoice.into())
                        }
                    }
                } else {
                    None
                }
            }
            LightningOperationMetaVariant::Claim { .. } => None,
        };

        if let Some(updated_invoice) = updated_invoice {
            match maybe_update_after_checking_fedimint(
                updated_invoice.clone(),
                logger.clone(),
                storage,
            ) {
                Ok(_) => {
                    log_debug!(logger, "subscribed and updated federation operation")
                }
                Err(e) => {
                    log_error!(logger, "could not update federation operation: {e}")
                }
            }
        }
    } else if module_type == WalletCommonInit::KIND.as_str() {
        let wallet_meta: WalletOperationMeta = entry.meta();
        let wallet_module = Arc::new(fedimint_client.get_first_module::<WalletClientModule>());
        let internal_id = Txid::from_slice(&operation_id.0)
            .map_err(|_| MutinyError::ChainAccessFailed)
            .expect("should convert");
        let stored_transaction_details = get_transaction_details(&storage, internal_id, &logger);
        if stored_transaction_details.is_none() {
            log_warn!(logger, "could not find transaction details: {internal_id}")
        }

        match wallet_meta.variant {
            fedimint_wallet_client::WalletOperationMetaVariant::Deposit {
                address: _,
                expires_at: _,
            } => {
                match wallet_module.subscribe_deposit_updates(operation_id).await {
                    Ok(o) => {
                        process_onchain_deposit_outcome(
                            o,
                            stored_transaction_details,
                            operation_id,
                            storage,
                            timeout,
                            stop,
                            logger,
                        )
                        .await
                    }
                    Err(e) => {
                        log_error!(logger, "Error trying to process stream outcome: {e}");
                    }
                };
            }
            fedimint_wallet_client::WalletOperationMetaVariant::Withdraw {
                address: _,
                amount,
                fee,
                change: _,
            } => {
                match wallet_module.subscribe_withdraw_updates(operation_id).await {
                    Ok(o) => {
                        process_onchain_withdraw_outcome(
                            o,
                            stored_transaction_details,
                            amount,
                            fee.amount(),
                            operation_id,
                            storage,
                            esplora,
                            timeout,
                            stop,
                            logger,
                        )
                        .await
                    }
                    Err(e) => {
                        log_error!(logger, "Error trying to process stream outcome: {e}");
                    }
                };
            }
            fedimint_wallet_client::WalletOperationMetaVariant::RbfWithdraw { .. } => {
                // not supported yet
                unimplemented!("User RBF withdrawals not supported yet")
            }
        }
    } else {
        log_warn!(logger, "Unknown module type: {module_type}")
    }
}

fn process_pay_state_internal(pay_state: InternalPayState, invoice: &mut MutinyInvoice) {
    invoice.preimage = if let InternalPayState::Preimage(ref preimage) = pay_state {
        Some(preimage.0.to_lower_hex_string())
    } else {
        None
    };

    invoice.status = pay_state.into();
}

fn process_pay_state_ln(pay_state: LnPayState, invoice: &mut MutinyInvoice) {
    invoice.preimage = if let LnPayState::Success { ref preimage } = pay_state {
        Some(preimage.to_string())
    } else {
        None
    };

    invoice.status = pay_state.into();
}

fn process_receive_state(receive_state: LnReceiveState, invoice: &mut MutinyInvoice) {
    invoice.status = receive_state.into();
}

async fn process_ln_outcome<U, F>(
    stream_or_outcome: UpdateStreamOrOutcome<U>,
    process_fn: F,
    invoice: Bolt11Invoice,
    inbound: bool,
    timeout: Option<u64>,
    stop: Arc<AtomicBool>,
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
    F: Fn(U, &mut MutinyInvoice),
{
    let mut invoice: MutinyInvoice = invoice.into();
    invoice.inbound = inbound;

    match stream_or_outcome {
        UpdateStreamOrOutcome::Outcome(outcome) => {
            invoice.status = outcome.into();
            log_trace!(logger, "Outcome received: {}", invoice.status);
        }
        UpdateStreamOrOutcome::UpdateStream(mut s) => {
            // break out after sleep time or check stop signal
            log_trace!(logger, "start timeout stream futures");
            loop {
                let timeout_future = if let Some(t) = timeout {
                    sleep(t as i32)
                } else {
                    sleep(1_000_i32)
                };

                let mut stream_fut = Box::pin(s.next()).fuse();
                let delay_fut = Box::pin(timeout_future).fuse();
                pin_mut!(delay_fut);

                select! {
                    outcome_option = stream_fut => {
                        if let Some(outcome) = outcome_option {
                            log_trace!(logger, "Streamed Outcome received: {:?}", outcome);
                            process_fn(outcome, &mut invoice);

                            if matches!(invoice.status, HTLCStatus::Succeeded | HTLCStatus::Failed) {
                                log_trace!(logger, "Streamed Outcome final, returning");
                                break;
                            }
                        }
                    }
                    _ = delay_fut => {
                        if timeout.is_none() {
                            if stop.load(Ordering::Relaxed)  {
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

// FIXME: refactor
#[allow(clippy::too_many_arguments)]
async fn process_onchain_withdraw_outcome<S: MutinyStorage>(
    stream_or_outcome: UpdateStreamOrOutcome<fedimint_wallet_client::WithdrawState>,
    original_transaction_details: Option<TransactionDetails>,
    amount: fedimint_ln_common::bitcoin::Amount,
    fee: fedimint_ln_common::bitcoin::Amount,
    operation_id: OperationId,
    storage: S,
    esplora: Arc<AsyncClient>,
    timeout: Option<u64>,
    stop: Arc<AtomicBool>,
    logger: Arc<MutinyLogger>,
) {
    let labels = original_transaction_details
        .as_ref()
        .map(|o| o.labels.clone())
        .unwrap_or_default();

    match stream_or_outcome {
        UpdateStreamOrOutcome::Outcome(outcome) => {
            // TODO
            log_trace!(logger, "Outcome received: {:?}", outcome);
        }
        UpdateStreamOrOutcome::UpdateStream(mut s) => {
            // break out after sleep time or check stop signal
            log_trace!(logger, "start timeout stream futures");
            loop {
                let timeout_future = if let Some(t) = timeout {
                    sleep(t as i32)
                } else {
                    sleep(1_000_i32)
                };

                let mut stream_fut = Box::pin(s.next()).fuse();
                let delay_fut = Box::pin(timeout_future).fuse();
                pin_mut!(delay_fut);

                select! {
                    outcome_option = stream_fut => {
                        if let Some(outcome) = outcome_option {
                            // TODO refactor outcome parsing into seperate method
                            match outcome {
                                WithdrawState::Created => {
                                    // Nothing to do
                                    log_debug!(logger, "Waiting for withdraw");
                                },
                                WithdrawState::Succeeded(txid) => {
                                    log_info!(logger, "Withdraw successful: {txid}");

                                    let internal_id = Txid::from_slice(&operation_id.0).expect("should convert");
                                    let txid = Txid::from_slice(&txid).expect("should convert");
                                    let updated_transaction_details = TransactionDetails {
                                        transaction: None,
                                        txid: Some(txid),
                                        internal_id,
                                        received: 0,
                                        sent: amount.to_sat(),
                                        fee: Some(fee.to_sat()),
                                        confirmation_time: ConfirmationTime::Unconfirmed { last_seen: now().as_secs() },
                                        labels: labels.clone(),
                                    };

                                    match persist_transaction_details(&storage, &updated_transaction_details) {
                                        Ok(_) => {
                                            log_info!(logger, "Transaction updated");
                                        },
                                        Err(e) => {
                                            log_error!(logger, "Error updating transaction: {e}");
                                        },
                                    }

                                    // we need to get confirmations for this txid and update
                                    subscribe_onchain_confirmation_check(storage.clone(), esplora.clone(), txid, updated_transaction_details, stop, logger.clone()).await;

                                    break
                                },
                                WithdrawState::Failed(e) => {
                                    // TODO delete
                                    log_error!(logger, "Transaction failed: {e}");
                                    break;
                                },
                            }
                        }
                    }
                    _ = delay_fut => {
                        if timeout.is_none() {
                            if stop.load(Ordering::Relaxed)  {
                                break;
                            }
                        } else {
                            log_debug!(
                                logger,
                                "Timeout reached, exiting loop for on chain tx",
                            );
                            break;
                        }
                    }
                }
            }
            log_trace!(logger, "Done with stream outcome",);
        }
    }
}

async fn subscribe_onchain_confirmation_check<S: MutinyStorage>(
    storage: S,
    esplora: Arc<AsyncClient>,
    txid: Txid,
    mut transaction_details: TransactionDetails,
    stop: Arc<AtomicBool>,
    logger: Arc<MutinyLogger>,
) {
    spawn(async move {
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            };

            match esplora.get_tx_status(&txid).await {
                Ok(s) => {
                    if s.confirmed {
                        log_info!(logger, "Transaction confirmed");
                        transaction_details.confirmation_time = ConfirmationTime::Confirmed {
                            height: s.block_height.expect("confirmed"),
                            time: now().as_secs(),
                        };
                        match persist_transaction_details(&storage, &transaction_details) {
                            Ok(_) => {
                                log_info!(logger, "Transaction updated");
                                break;
                            }
                            Err(e) => {
                                log_error!(logger, "Error updating transaction: {e}");
                            }
                        }
                    }
                }
                Err(e) => {
                    log_error!(logger, "Error updating transaction: {e}");
                }
            }

            sleep(5_000).await;
        }
    });
}

async fn process_onchain_deposit_outcome<S: MutinyStorage>(
    stream_or_outcome: UpdateStreamOrOutcome<fedimint_wallet_client::DepositState>,
    original_transaction_details: Option<TransactionDetails>,
    operation_id: OperationId,
    storage: S,
    timeout: Option<u64>,
    stop: Arc<AtomicBool>,
    logger: Arc<MutinyLogger>,
) {
    let labels = original_transaction_details
        .as_ref()
        .map(|o| o.labels.clone())
        .unwrap_or_default();

    match stream_or_outcome {
        UpdateStreamOrOutcome::Outcome(outcome) => {
            // TODO
            log_trace!(logger, "Outcome received: {:?}", outcome);
        }
        UpdateStreamOrOutcome::UpdateStream(mut s) => {
            // break out after sleep time or check stop signal
            log_trace!(logger, "start timeout stream futures");
            loop {
                let timeout_future = if let Some(t) = timeout {
                    sleep(t as i32)
                } else {
                    sleep(1_000_i32)
                };

                let mut stream_fut = Box::pin(s.next()).fuse();
                let delay_fut = Box::pin(timeout_future).fuse();
                pin_mut!(delay_fut);

                select! {
                    outcome_option = stream_fut => {
                        if let Some(outcome) = outcome_option {
                            // TODO refactor outcome parsing into seperate method
                            match outcome {
                                fedimint_wallet_client::DepositState::WaitingForTransaction => {
                                    // Nothing to do
                                    log_debug!(logger, "Waiting for transaction");
                                }
                                fedimint_wallet_client::DepositState::WaitingForConfirmation(tx) => {
                                    // Pending state, update with info we have
                                    log_debug!(logger, "Waiting for confirmation");
                                    let txid = Txid::from_slice(&tx.btc_transaction.txid()).expect("should convert");
                                    let internal_id = Txid::from_slice(&operation_id.0).expect("should convert");
                                    let output = tx.btc_transaction.output[tx.out_idx as usize].clone();

                                    let updated_transaction_details = TransactionDetails {
                                        transaction: None,
                                        txid: Some(txid),
                                        internal_id,
                                        received: output.value,
                                        sent: 0,
                                        fee: None,
                                        confirmation_time: ConfirmationTime::Unconfirmed { last_seen: now().as_secs() },
                                        labels: labels.clone(),
                                    };

                                    match persist_transaction_details(&storage, &updated_transaction_details) {
                                        Ok(_) => {
                                            log_info!(logger, "Transaction updated");
                                        },
                                        Err(e) => {
                                            log_error!(logger, "Error updating transaction: {e}");
                                        },
                                    }
                                }
                                fedimint_wallet_client::DepositState::Confirmed(tx) => {
                                    // Pending state, update with info we have
                                    log_debug!(logger, "Transaction confirmed");
                                    let txid = Txid::from_slice(&tx.btc_transaction.txid()).expect("should convert");
                                    let internal_id = Txid::from_slice(&operation_id.0).expect("should convert");
                                    let output = tx.btc_transaction.output[tx.out_idx as usize].clone();

                                    let updated_transaction_details = TransactionDetails {
                                        transaction: None,
                                        txid: Some(txid),
                                        internal_id,
                                        received: output.value,
                                        sent: 0,
                                        fee: None,
                                        confirmation_time: ConfirmationTime::Confirmed { height: 0, time: now().as_secs() }, // FIXME: can't figure this out
                                        labels: labels.clone(),
                                    };

                                    match persist_transaction_details(&storage, &updated_transaction_details) {
                                        Ok(_) => {
                                            log_info!(logger, "Transaction updated");
                                        },
                                        Err(e) => {
                                            log_error!(logger, "Error updating transaction: {e}");
                                        },
                                    }
                                }
                                fedimint_wallet_client::DepositState::Claimed(_) => {
                                    // Nothing really to change from confirmed to claimed
                                    log_debug!(logger, "Transaction claimed");
                                    break;
                                }
                                fedimint_wallet_client::DepositState::Failed(e) => {
                                    // TODO delete
                                    log_error!(logger, "Transaction failed: {e}");
                                    break;
                                }
                            }
                        }
                    }
                    _ = delay_fut => {
                        if timeout.is_none() {
                            if stop.load(Ordering::Relaxed)  {
                                break;
                            }
                        } else {
                            log_debug!(
                                logger,
                                "Timeout reached, exiting loop for on chain tx",
                            );
                            break;
                        }
                    }
                }
            }
            log_trace!(logger, "Done with stream outcome",);
        }
    }
}

#[derive(Clone)]
pub struct FedimintStorage<S: MutinyStorage> {
    pub(crate) storage: S,
    fedimint_memory: Arc<MemDatabase>,
    federation_id: String,
    federation_version: Arc<AtomicU32>,
}

impl<S: MutinyStorage> fmt::Debug for FedimintStorage<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FedimintDB").finish()
    }
}

impl<S: MutinyStorage> FedimintStorage<S> {
    pub async fn new(
        storage: S,
        federation_id: String,
        logger: Arc<MutinyLogger>,
    ) -> Result<Self, MutinyError> {
        log_debug!(logger, "initializing fedimint storage");

        let fedimint_memory = MemDatabase::new();

        let key = key_id(&federation_id);

        let federation_version = match storage.get_data::<VersionedValue>(&key) {
            Ok(Some(versioned_value)) => {
                // get the value/version and load it into fedimint memory
                let hex: String = serde_json::from_value(versioned_value.value.clone())?;
                if !hex.is_empty() {
                    let bytes: Vec<u8> =
                        FromHex::from_hex(&hex).map_err(|e| MutinyError::ReadError {
                            source: MutinyStorageError::Other(anyhow::Error::new(e)),
                        })?;
                    let key_value_pairs: Vec<(Vec<u8>, Vec<u8>)> = bincode::deserialize(&bytes)
                        .map_err(|e| MutinyError::ReadError {
                            source: MutinyStorageError::Other(e.into()),
                        })?;

                    let mut mem_db_tx = fedimint_memory.begin_transaction().await;
                    for (key, value) in key_value_pairs {
                        mem_db_tx
                            .raw_insert_bytes(&key, &value)
                            .await
                            .map_err(|_| {
                                MutinyError::write_err(MutinyStorageError::IndexedDBError)
                            })?;
                    }
                    mem_db_tx
                        .commit_tx()
                        .await
                        .map_err(|_| MutinyError::write_err(MutinyStorageError::IndexedDBError))?;
                }
                versioned_value.version
            }
            Ok(None) => 0,
            Err(e) => {
                panic!("unparsable value in federation storage: {e}")
            }
        };

        log_debug!(logger, "done setting up FedimintDB for fedimint");

        Ok(Self {
            storage,
            federation_id,
            federation_version: Arc::new(federation_version.into()),
            fedimint_memory: Arc::new(fedimint_memory),
        })
    }

    pub async fn delete_store(&self) -> Result<(), MutinyError> {
        let mut mem_db_tx = self.begin_transaction().await;
        mem_db_tx.raw_remove_by_prefix(&[]).await?;
        mem_db_tx
            .commit_tx()
            .await
            .map_err(|_| MutinyError::write_err(MutinyStorageError::IndexedDBError))
    }
}

fn key_id(federation_id: &str) -> String {
    format!("{}{}", FEDIMINTS_PREFIX_KEY, federation_id)
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<S: MutinyStorage> IRawDatabase for FedimintStorage<S> {
    type Transaction<'a> = IndexedDBPseudoTransaction<'a, S>;

    async fn begin_transaction<'a>(&'a self) -> IndexedDBPseudoTransaction<S> {
        IndexedDBPseudoTransaction {
            storage: self.storage.clone(),
            federation_id: self.federation_id.clone(),
            federation_version: self.federation_version.clone(),
            mem: self.fedimint_memory.begin_transaction().await,
        }
    }
}

pub struct IndexedDBPseudoTransaction<'a, S: MutinyStorage> {
    pub(crate) storage: S,
    federation_version: Arc<AtomicU32>,
    federation_id: String,
    mem: MemTransaction<'a>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<'a, S: MutinyStorage> IRawDatabaseTransaction for IndexedDBPseudoTransaction<'a, S> {
    async fn commit_tx(mut self) -> anyhow::Result<()> {
        let key_value_pairs = self
            .mem
            .raw_find_by_prefix(&[])
            .await?
            .collect::<Vec<(Vec<u8>, Vec<u8>)>>()
            .await;
        self.mem.commit_tx().await?;

        let serialized_data = bincode::serialize(&key_value_pairs).map_err(anyhow::Error::new)?;
        let hex_serialized_data = serialized_data.to_lower_hex_string();

        let old = self.federation_version.fetch_add(1, Ordering::SeqCst);
        let version = old + 1;
        let value = VersionedValue {
            version,
            value: serde_json::to_value(hex_serialized_data).unwrap(),
        };
        self.storage
            .set_data_async_queue_remote(key_id(&self.federation_id), value, version)
            .await?;

        Ok(())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<'a, S: MutinyStorage> IDatabaseTransactionOpsCore for IndexedDBPseudoTransaction<'a, S> {
    async fn raw_insert_bytes(
        &mut self,
        key: &[u8],
        value: &[u8],
    ) -> anyhow::Result<Option<Vec<u8>>> {
        self.mem.raw_insert_bytes(key, value).await
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        self.mem.raw_get_bytes(key).await
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        self.mem.raw_remove_entry(key).await
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> anyhow::Result<PrefixStream<'_>> {
        self.mem.raw_find_by_prefix(key_prefix).await
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> anyhow::Result<()> {
        self.mem.raw_remove_by_prefix(key_prefix).await
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> anyhow::Result<PrefixStream<'_>> {
        self.mem
            .raw_find_by_prefix_sorted_descending(key_prefix)
            .await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<'a, S: MutinyStorage> IDatabaseTransactionOps for IndexedDBPseudoTransaction<'a, S> {
    async fn rollback_tx_to_savepoint(&mut self) -> anyhow::Result<()> {
        self.mem.rollback_tx_to_savepoint().await
    }

    async fn set_tx_savepoint(&mut self) -> anyhow::Result<()> {
        self.mem.set_tx_savepoint().await
    }
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
    let child_key = create_root_child_key(&context, xpriv, ChildKey::Federation).unwrap();

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
    let child_key2 = create_root_child_key(&context2, xpriv2, ChildKey::Federation).unwrap();

    let child_mnemonic2 = mnemonic_from_xpriv(child_key2).unwrap();
    assert_ne!(mnemonic_str2, child_mnemonic2.to_string());

    let expected_child_mnemonic2 = "jewel primary rice smile garage lucky bullet scheme crack vehicle real urban pen another squeeze rate sorry never afraid chief proof decline reveal history";
    assert_ne!(expected_child_mnemonic, expected_child_mnemonic2);
    assert_eq!(expected_child_mnemonic2, child_mnemonic2.to_string());
}

#[cfg(test)]
fn gateway_preference() {
    use fedimint_core::util::SafeUrl;
    use fedimint_ln_common::bitcoin::secp256k1::PublicKey;
    use fedimint_ln_common::LightningGatewayAnnouncement;

    use super::*;

    const RANDOM_KEY: &str = "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166";
    let random_key = PublicKey::from_str(RANDOM_KEY).unwrap();

    const VETTED_GATEWAY: &str =
        "02465ed5be53d04fde66c9418ff14a5f2267723810176c9212b722e542dc1afb1b";
    let vetted_gateway_pubkey = PublicKey::from_str(VETTED_GATEWAY).unwrap();

    const UNVETTED_GATEWAY_KEY_HIGH_FEE: &str =
        "0384526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f07";
    let unvetted_gateway_high_fee_pubkey =
        PublicKey::from_str(UNVETTED_GATEWAY_KEY_HIGH_FEE).unwrap();

    const UNVETTED_GATEWAY_KEY_LOW_FEE: &str =
        "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443";
    let unvetted_gateway_low_fee_pubkey =
        PublicKey::from_str(UNVETTED_GATEWAY_KEY_LOW_FEE).unwrap();

    let random_federation_id = FederationId::dummy();

    // Create some sample LightningGatewayAnnouncement structs to test with
    let signet_gateway = LightningGatewayAnnouncement {
        info: LightningGateway {
            mint_channel_id: 12345,
            gateway_redeem_key: PublicKey::from_str(SIGNET_GATEWAY).unwrap(),
            node_pub_key: random_key,
            lightning_alias: "Signet Gateway".to_string(),
            api: SafeUrl::parse("http://localhost:8080").unwrap(),
            route_hints: vec![],
            fees: RoutingFees {
                base_msat: 100,
                proportional_millionths: 10,
            },
            gateway_id: PublicKey::from_str(SIGNET_GATEWAY).unwrap(),
            supports_private_payments: true,
        },
        vetted: false,
        ttl: Duration::from_secs(3600),
    };

    let mainnet_gateway = LightningGatewayAnnouncement {
        info: LightningGateway {
            mint_channel_id: 12345,
            gateway_redeem_key: PublicKey::from_str(MAINNET_GATEWAY).unwrap(),
            node_pub_key: random_key,
            lightning_alias: "Mainnet Gateway".to_string(),
            api: SafeUrl::parse("http://localhost:8080").unwrap(),
            route_hints: vec![],
            fees: RoutingFees {
                base_msat: 100,
                proportional_millionths: 10,
            },
            gateway_id: PublicKey::from_str(MAINNET_GATEWAY).unwrap(),
            supports_private_payments: true,
        },
        vetted: false,
        ttl: Duration::from_secs(3600),
    };

    let vetted_gateway = LightningGatewayAnnouncement {
        info: LightningGateway {
            mint_channel_id: 12345,
            gateway_redeem_key: random_key,
            node_pub_key: vetted_gateway_pubkey,
            lightning_alias: "Vetted Gateway".to_string(),
            api: SafeUrl::parse("http://localhost:8080").unwrap(),
            route_hints: vec![],
            fees: RoutingFees {
                base_msat: 200,
                proportional_millionths: 20,
            },
            gateway_id: vetted_gateway_pubkey,
            supports_private_payments: true,
        },
        vetted: true,
        ttl: Duration::from_secs(3600),
    };

    let unvetted_gateway_high_fee = LightningGatewayAnnouncement {
        info: LightningGateway {
            mint_channel_id: 12345,
            gateway_redeem_key: random_key,
            node_pub_key: unvetted_gateway_high_fee_pubkey,
            lightning_alias: "Unvetted Gateway".to_string(),
            api: SafeUrl::parse("http://localhost:8080").unwrap(),
            route_hints: vec![],
            fees: RoutingFees {
                base_msat: 200,
                proportional_millionths: 20,
            },
            gateway_id: unvetted_gateway_high_fee_pubkey,
            supports_private_payments: true,
        },
        vetted: false,
        ttl: Duration::from_secs(3600),
    };

    let unvetted_gateway_low_fee = LightningGatewayAnnouncement {
        info: LightningGateway {
            mint_channel_id: 12345,
            gateway_redeem_key: random_key,
            node_pub_key: unvetted_gateway_low_fee_pubkey,
            lightning_alias: "Unvetted Gateway".to_string(),
            api: SafeUrl::parse("http://localhost:8080").unwrap(),
            route_hints: vec![],
            fees: RoutingFees {
                base_msat: 10,
                proportional_millionths: 1,
            },
            gateway_id: unvetted_gateway_low_fee_pubkey,
            supports_private_payments: true,
        },
        vetted: false,
        ttl: Duration::from_secs(3600),
    };

    let gateways = vec![
        signet_gateway.clone(),
        mainnet_gateway.clone(),
        vetted_gateway.clone(),
        unvetted_gateway_low_fee.clone(),
        unvetted_gateway_high_fee.clone(),
    ];

    // Test that the method returns a Gateway ID when given a matching federation ID and gateway ID
    let signet_federation_id = FederationId::from_str(SIGNET_FEDERATION).unwrap();
    assert_eq!(
        get_gateway_preference(gateways.clone(), signet_federation_id),
        Some(PublicKey::from_str(SIGNET_GATEWAY).unwrap())
    );

    let mainnet_federation_id = FederationId::from_str(MAINNET_FEDERATION).unwrap();
    assert_eq!(
        get_gateway_preference(gateways.clone(), mainnet_federation_id),
        Some(PublicKey::from_str(MAINNET_GATEWAY).unwrap())
    );

    // Test that the method returns the first vetted gateway if none of the gateways match the federation ID
    assert_eq!(
        get_gateway_preference(gateways, random_federation_id),
        Some(vetted_gateway_pubkey)
    );

    // Test that the method returns the first vetted gateway if none of the gateways match the federation ID
    let gateways = vec![
        unvetted_gateway_low_fee.clone(),
        unvetted_gateway_high_fee.clone(),
        vetted_gateway.clone(),
    ];
    assert_eq!(
        get_gateway_preference(gateways, random_federation_id),
        Some(vetted_gateway_pubkey)
    );

    // Test that the method returns the first when given a non-matching federation ID and gateway ID,
    // and no unvetted gateways with a high enough fee
    let gateways = vec![
        signet_gateway.clone(),
        mainnet_gateway,
        unvetted_gateway_low_fee,
    ];
    assert_eq!(
        get_gateway_preference(gateways, random_federation_id),
        Some(signet_gateway.info.gateway_id)
    );
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

    #[test]
    fn test_gateway_preference() {
        gateway_preference();
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

    #[test]
    fn test_gateway_preference() {
        gateway_preference();
    }
}
