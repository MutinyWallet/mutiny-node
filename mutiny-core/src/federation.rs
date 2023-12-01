use crate::{
    error::MutinyError,
    key::{create_root_child_key, ChildKey},
    logging::MutinyLogger,
    nodemanager::MutinyInvoice,
    onchain::coin_type_from_network,
    storage::MutinyStorage,
    HTLCStatus,
};
use bip39::Mnemonic;
use bitcoin::{secp256k1::Secp256k1, util::bip32::ExtendedPrivKey};
use bitcoin::{
    util::bip32::{ChildNumber, DerivationPath},
    Network,
};
use fedimint_bip39::Bip39RootSecretStrategy;
use fedimint_client::{
    derivable_secret::DerivableSecret,
    secret::{get_default_client_secret, RootSecretStrategy},
    ClientArc, FederationInfo,
};
use fedimint_core::{api::InviteCode, config::FederationId, db::mem_impl::MemDatabase, Amount};
use fedimint_ln_client::{
    InternalPayState, LightningClientInit, LightningClientModule, LnPayState, LnReceiveState,
};
use fedimint_mint_client::MintClientInit;
use fedimint_wallet_client::WalletClientInit;
use futures_util::StreamExt;
use lightning::util::logger::Logger;
use lightning::{log_debug, log_info};
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{atomic::AtomicBool, Arc, RwLock},
};

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
}

// This is the FederationIndex reference that is saved to the DB
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct FederationIndex {
    pub federation_code: InviteCode,
}

pub struct FedimintBalance {
    pub amount: u64,
}

// TODO remove
#[allow(dead_code)]
pub(crate) struct FederationClient<S: MutinyStorage> {
    pub(crate) uuid: String,
    pub(crate) federation_index: FederationIndex,
    pub(crate) federation_code: InviteCode,
    pub(crate) fedimint_client: ClientArc,
    stopped_components: Arc<RwLock<Vec<bool>>>,
    storage: S,
    network: Network,
    pub(crate) logger: Arc<MutinyLogger>,
    stop: Arc<AtomicBool>,
}

// TODO remove
#[allow(dead_code)]
impl<S: MutinyStorage> FederationClient<S> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn new(
        uuid: String,
        federation_index: &FederationIndex,
        federation_code: InviteCode,
        xprivkey: ExtendedPrivKey,
        storage: S,
        network: Network,
        logger: Arc<MutinyLogger>,
        stop: Arc<AtomicBool>,
    ) -> Result<Self, MutinyError> {
        log_info!(logger, "initializing a new federation client: {uuid}");

        // a list of components that need to be stopped and whether or not they are stopped
        // TODO remove this if we end up not needing to stop things
        let stopped_components = Arc::new(RwLock::new(vec![]));

        log_info!(logger, "Joining federation {}", federation_code);

        let federation_info = FederationInfo::from_invite_code(federation_code.clone()).await?;

        let mut client_builder = fedimint_client::Client::builder();
        client_builder.with_module(WalletClientInit(None));
        client_builder.with_module(MintClientInit);
        client_builder.with_module(LightningClientInit);
        client_builder.with_database(MemDatabase::new().into()); // TODO not in memory
        client_builder.with_primary_module(1);
        client_builder
            .with_federation_info(FederationInfo::from_invite_code(federation_code.clone()).await?);

        let secret = create_federation_secret(xprivkey, network)?;

        let fedimint_client = client_builder
            .build(get_default_client_secret(
                &secret,
                &federation_info.federation_id(),
            ))
            .await?;

        Ok(FederationClient {
            uuid,
            federation_index: federation_index.clone(),
            federation_code,
            fedimint_client,
            stopped_components,
            storage,
            network,
            logger,
            stop,
        })
    }

    pub(crate) async fn get_invoice(&self, amount: u64) -> Result<MutinyInvoice, MutinyError> {
        let lightning_module = self
            .fedimint_client
            .get_first_module::<LightningClientModule>();
        let (_id, invoice) = lightning_module
            .create_bolt11_invoice(Amount::from_sats(amount), String::new(), None, ())
            .await?;
        Ok(invoice.into())
    }

    /// Get the balance of this federation client in sats
    pub(crate) async fn get_balance(&self) -> Result<u64, MutinyError> {
        Ok(self.fedimint_client.get_balance().await.msats / 1_000)
    }

    pub(crate) async fn pay_invoice(
        &self,
        invoice: Bolt11Invoice,
    ) -> Result<MutinyInvoice, MutinyError> {
        let lightning_module = self
            .fedimint_client
            .get_first_module::<LightningClientModule>();
        let outgoing_payment = lightning_module
            .pay_bolt11_invoice(invoice.clone(), ())
            .await?;

        let mut inv: MutinyInvoice = invoice.clone().into();
        match outgoing_payment.payment_type {
            fedimint_ln_client::PayType::Internal(pay_id) => {
                // TODO merge the two as much as we can
                let pay_outcome = lightning_module
                    .subscribe_internal_pay(pay_id)
                    .await
                    .map_err(|_| MutinyError::ConnectionFailed)?;

                match pay_outcome {
                    fedimint_client::oplog::UpdateStreamOrOutcome::UpdateStream(mut s) => {
                        log_debug!(
                            self.logger,
                            "waiting for update stream on payment: {}",
                            pay_id
                        );
                        while let Some(outcome) = s.next().await {
                            log_info!(self.logger, "Outcome: {outcome:?}");
                            inv.status = outcome.into();

                            if matches!(inv.status, HTLCStatus::Failed | HTLCStatus::Succeeded) {
                                break;
                            }
                        }
                    }
                    fedimint_client::oplog::UpdateStreamOrOutcome::Outcome(o) => {
                        log_info!(self.logger, "Outcome: {o:?}");
                        inv.status = o.into();
                    }
                }
            }
            fedimint_ln_client::PayType::Lightning(pay_id) => {
                let pay_outcome = lightning_module
                    .subscribe_ln_pay(pay_id)
                    .await
                    .map_err(|_| MutinyError::ConnectionFailed)?;

                match pay_outcome {
                    fedimint_client::oplog::UpdateStreamOrOutcome::UpdateStream(mut s) => {
                        log_debug!(
                            self.logger,
                            "waiting for update stream on payment: {}",
                            pay_id
                        );
                        while let Some(outcome) = s.next().await {
                            log_info!(self.logger, "Outcome: {outcome:?}");
                            inv.status = outcome.into();

                            if matches!(inv.status, HTLCStatus::Failed | HTLCStatus::Succeeded) {
                                break;
                            }
                        }
                    }
                    fedimint_client::oplog::UpdateStreamOrOutcome::Outcome(o) => {
                        log_info!(self.logger, "Outcome: {o:?}");
                        inv.status = o.into();
                    }
                }
            }
        }

        Ok(inv)
    }

    pub async fn get_mutiny_federation_identity(&self) -> FederationIdentity {
        FederationIdentity {
            uuid: self.uuid.clone(),
            federation_id: self.fedimint_client.federation_id(),
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
    use std::str::FromStr;

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
