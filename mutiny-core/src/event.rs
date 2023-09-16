use crate::fees::MutinyFeeEstimator;
use crate::keymanager::PhantomKeysManager;
use crate::ldkstorage::{MutinyNodePersister, PhantomChannelManager};
use crate::logging::MutinyLogger;
use crate::node::BumpTxEventHandler;
use crate::nodemanager::ChannelClosure;
use crate::onchain::OnChainWallet;
use crate::redshift::RedshiftStorage;
use crate::storage::MutinyStorage;
use crate::utils::sleep;
use anyhow::anyhow;
use bitcoin::hashes::hex::ToHex;
use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::Secp256k1;
use core::fmt;
use lightning::events::{Event, PaymentPurpose};
use lightning::sign::SpendableOutputDescriptor;
use lightning::{
    chain::chaininterface::{ConfirmationTarget, FeeEstimator},
    log_debug, log_error, log_info, log_warn,
    util::errors::APIError,
    util::logger::Logger,
};
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PaymentInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preimage: Option<[u8; 32]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<[u8; 32]>,
    pub status: HTLCStatus,
    #[serde(skip_serializing_if = "MillisatAmount::is_none")]
    pub amt_msat: MillisatAmount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_paid_msat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bolt11: Option<Bolt11Invoice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payee_pubkey: Option<PublicKey>,
    pub last_update: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct MillisatAmount(pub Option<u64>);

impl MillisatAmount {
    pub fn is_none(&self) -> bool {
        self.0.is_none()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HTLCStatus {
    /// Our invoice has not been paid yet
    Pending,
    /// We are currently trying to pay an invoice
    InFlight,
    /// An invoice has been paid
    Succeeded,
    /// We failed to pay an invoice
    Failed,
}

impl fmt::Display for HTLCStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HTLCStatus::Pending => write!(f, "Pending"),
            HTLCStatus::InFlight => write!(f, "InFlight"),
            HTLCStatus::Succeeded => write!(f, "Succeeded"),
            HTLCStatus::Failed => write!(f, "Failed"),
        }
    }
}

#[derive(Clone)]
pub struct EventHandler<S: MutinyStorage> {
    channel_manager: Arc<PhantomChannelManager<S>>,
    fee_estimator: Arc<MutinyFeeEstimator<S>>,
    wallet: Arc<OnChainWallet<S>>,
    keys_manager: Arc<PhantomKeysManager<S>>,
    persister: Arc<MutinyNodePersister<S>>,
    bump_tx_event_handler: Arc<BumpTxEventHandler<S>>,
    lsp_client_pubkey: Option<PublicKey>,
    logger: Arc<MutinyLogger>,
}

impl<S: MutinyStorage> EventHandler<S> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        channel_manager: Arc<PhantomChannelManager<S>>,
        fee_estimator: Arc<MutinyFeeEstimator<S>>,
        wallet: Arc<OnChainWallet<S>>,
        keys_manager: Arc<PhantomKeysManager<S>>,
        persister: Arc<MutinyNodePersister<S>>,
        bump_tx_event_handler: Arc<BumpTxEventHandler<S>>,
        lsp_client_pubkey: Option<PublicKey>,
        logger: Arc<MutinyLogger>,
    ) -> Self {
        Self {
            channel_manager,
            fee_estimator,
            wallet,
            keys_manager,
            lsp_client_pubkey,
            persister,
            bump_tx_event_handler,
            logger,
        }
    }

    pub async fn handle_event(&self, event: Event) {
        match event {
            Event::FundingGenerationReady {
                temporary_channel_id,
                counterparty_node_id,
                channel_value_satoshis,
                output_script,
                user_channel_id,
            } => {
                log_debug!(self.logger, "EVENT: FundingGenerationReady processing");

                // Get the open parameters for this channel
                let params_opt = match self.persister.get_channel_open_params(user_channel_id) {
                    Ok(params) => params,
                    Err(e) => {
                        log_error!(self.logger, "ERROR: Could not get channel open params: {e}");
                        return;
                    }
                };

                let psbt_result = match &params_opt {
                    None => {
                        log_warn!(
                            self.logger,
                            "WARNING: Could not find channel open params for channel {user_channel_id}"
                        );
                        self.wallet.create_signed_psbt_to_spk(
                            output_script,
                            channel_value_satoshis,
                            None,
                        )
                    }
                    Some(params) => {
                        log_debug!(self.logger, "Opening channel with params: {params:?}");
                        if let Some(utxos) = &params.utxos {
                            self.wallet.create_sweep_psbt_to_output(
                                utxos,
                                output_script,
                                channel_value_satoshis,
                                params.absolute_fee.expect("Absolute fee should be set"),
                            )
                        } else {
                            self.wallet.create_signed_psbt_to_spk(
                                output_script,
                                channel_value_satoshis,
                                Some(params.sats_per_vbyte),
                            )
                        }
                    }
                };

                let label = format!("LN Channel: {}", counterparty_node_id.to_hex());
                let labels = params_opt
                    .as_ref()
                    .and_then(|p| p.labels.clone())
                    .unwrap_or_else(|| vec![label]);

                let psbt = match psbt_result {
                    Ok(psbt) => {
                        if let Err(e) = self.wallet.label_psbt(&psbt, labels) {
                            log_warn!(
                                self.logger,
                                "ERROR: Could not label PSBT, but continuing: {e}"
                            );
                        };
                        psbt
                    }
                    Err(e) => {
                        log_error!(self.logger, "ERROR: Could not create a signed transaction to open channel with: {e}");
                        if let Err(e) = self.channel_manager.force_close_without_broadcasting_txn(
                            &temporary_channel_id,
                            &counterparty_node_id,
                        ) {
                            log_error!(
                                self.logger,
                                "ERROR: Could not force close failed channel: {e:?}"
                            );
                        }
                        return;
                    }
                };

                let tx = psbt.extract_tx();

                if let Err(e) = self.channel_manager.funding_transaction_generated(
                    &temporary_channel_id,
                    &counterparty_node_id,
                    tx.clone(),
                ) {
                    log_error!(
                        self.logger,
                        "ERROR: Could not send funding transaction to channel manager: {e:?}"
                    );
                    return;
                }

                if let Some(mut params) = params_opt {
                    params.opening_tx = Some(tx);

                    let _ = self
                        .persister
                        .persist_channel_open_params(user_channel_id, params);
                }

                log_info!(self.logger, "EVENT: FundingGenerationReady success");
            }
            Event::PaymentClaimable {
                receiver_node_id,
                payment_hash,
                purpose,
                amount_msat,
                ..
            } => {
                log_debug!(self.logger, "EVENT: PaymentReceived received payment from payment hash {} of {amount_msat} millisatoshis to {receiver_node_id:?}", payment_hash.0.to_hex());

                if let Some(payment_preimage) = match purpose {
                    PaymentPurpose::InvoicePayment {
                        payment_preimage, ..
                    } => payment_preimage,
                    PaymentPurpose::SpontaneousPayment(preimage) => Some(preimage),
                } {
                    self.channel_manager.claim_funds(payment_preimage);
                } else {
                    log_error!(self.logger, "ERROR: No payment preimage found");
                };
            }
            Event::PaymentClaimed {
                receiver_node_id,
                payment_hash,
                purpose,
                amount_msat,
            } => {
                log_debug!(self.logger, "EVENT: PaymentClaimed claimed payment from payment hash {} of {} millisatoshis", payment_hash.0.to_hex(), amount_msat);

                let (payment_preimage, payment_secret) = match purpose {
                    PaymentPurpose::InvoicePayment {
                        payment_preimage,
                        payment_secret,
                        ..
                    } => (payment_preimage, Some(payment_secret)),
                    PaymentPurpose::SpontaneousPayment(preimage) => (Some(preimage), None),
                };
                match self
                    .persister
                    .read_payment_info(&payment_hash.0, true, &self.logger)
                {
                    Some(mut saved_payment_info) => {
                        let payment_preimage = payment_preimage.map(|p| p.0);
                        let payment_secret = payment_secret.map(|p| p.0);
                        saved_payment_info.status = HTLCStatus::Succeeded;
                        saved_payment_info.preimage = payment_preimage;
                        saved_payment_info.secret = payment_secret;
                        saved_payment_info.amt_msat = MillisatAmount(Some(amount_msat));
                        saved_payment_info.last_update = crate::utils::now().as_secs();
                        match self.persister.persist_payment_info(
                            &payment_hash.0,
                            &saved_payment_info,
                            true,
                        ) {
                            Ok(_) => (),
                            Err(e) => log_error!(
                                self.logger,
                                "ERROR: could not persist payment info: {e}"
                            ),
                        }
                    }
                    None => {
                        let payment_preimage = payment_preimage.map(|p| p.0);
                        let payment_secret = payment_secret.map(|p| p.0);
                        let last_update = crate::utils::now().as_secs();

                        let payment_info = PaymentInfo {
                            preimage: payment_preimage,
                            secret: payment_secret,
                            status: HTLCStatus::Succeeded,
                            amt_msat: MillisatAmount(Some(amount_msat)),
                            fee_paid_msat: None,
                            payee_pubkey: receiver_node_id,
                            bolt11: None,
                            last_update,
                        };
                        match self.persister.persist_payment_info(
                            &payment_hash.0,
                            &payment_info,
                            true,
                        ) {
                            Ok(_) => (),
                            Err(e) => log_error!(
                                self.logger,
                                "ERROR: could not persist payment info: {e}"
                            ),
                        }
                    }
                }
            }
            Event::PaymentSent {
                payment_preimage,
                payment_hash,
                fee_paid_msat,
                ..
            } => {
                log_debug!(
                    self.logger,
                    "EVENT: PaymentSent: {}",
                    payment_hash.0.to_hex()
                );

                match self
                    .persister
                    .read_payment_info(&payment_hash.0, false, &self.logger)
                {
                    Some(mut saved_payment_info) => {
                        saved_payment_info.status = HTLCStatus::Succeeded;
                        saved_payment_info.preimage = Some(payment_preimage.0);
                        saved_payment_info.fee_paid_msat = fee_paid_msat;
                        saved_payment_info.last_update = crate::utils::now().as_secs();
                        match self.persister.persist_payment_info(
                            &payment_hash.0,
                            &saved_payment_info,
                            false,
                        ) {
                            Ok(_) => (),
                            Err(e) => log_error!(
                                self.logger,
                                "ERROR: could not persist payment info: {e}"
                            ),
                        }
                    }
                    None => {
                        // we succeeded in a payment that we didn't have saved? ...
                        log_warn!(
                            self.logger,
                            "WARN: payment succeeded but we did not have it stored"
                        );
                    }
                }
            }
            Event::OpenChannelRequest {
                temporary_channel_id,
                counterparty_node_id,
                ..
            } => {
                log_debug!(
                    self.logger,
                    "EVENT: OpenChannelRequest incoming: {counterparty_node_id}"
                );

                let mut internal_channel_id_bytes = [0u8; 16];
                if getrandom::getrandom(&mut internal_channel_id_bytes).is_err() {
                    log_debug!(
                        self.logger,
                        "EVENT: OpenChannelRequest failed random number generation"
                    );
                };
                let internal_channel_id = u128::from_be_bytes(internal_channel_id_bytes);

                let log_result = |result: Result<(), APIError>| match result {
                    Ok(_) => log_debug!(self.logger, "EVENT: OpenChannelRequest accepted"),
                    Err(e) => log_debug!(self.logger, "EVENT: OpenChannelRequest error: {e:?}"),
                };

                if self.lsp_client_pubkey.as_ref() != Some(&counterparty_node_id) {
                    // did not match the lsp pubkey, normal open
                    let result = self.channel_manager.accept_inbound_channel(
                        &temporary_channel_id,
                        &counterparty_node_id,
                        internal_channel_id,
                    );
                    log_result(result);
                } else {
                    // matched lsp pubkey, accept 0 conf
                    let result = self
                        .channel_manager
                        .accept_inbound_channel_from_trusted_peer_0conf(
                            &temporary_channel_id,
                            &counterparty_node_id,
                            internal_channel_id,
                        );
                    log_result(result);
                }
            }
            Event::PaymentPathSuccessful { .. } => {
                log_debug!(self.logger, "EVENT: PaymentPathSuccessful, ignored");
            }
            Event::PaymentPathFailed { .. } => {
                log_debug!(self.logger, "EVENT: PaymentPathFailed, ignored");
            }
            Event::ProbeSuccessful { .. } => {
                log_debug!(self.logger, "EVENT: ProbeSuccessful, ignored");
            }
            Event::ProbeFailed { .. } => {
                log_debug!(self.logger, "EVENT: ProbeFailed, ignored");
            }
            Event::PaymentFailed { payment_hash, .. } => {
                log_error!(
                    self.logger,
                    "EVENT: PaymentFailed: {}",
                    payment_hash.0.to_hex()
                );

                match self
                    .persister
                    .read_payment_info(&payment_hash.0, false, &self.logger)
                {
                    Some(mut saved_payment_info) => {
                        saved_payment_info.status = HTLCStatus::Failed;
                        saved_payment_info.last_update = crate::utils::now().as_secs();
                        match self.persister.persist_payment_info(
                            &payment_hash.0,
                            &saved_payment_info,
                            false,
                        ) {
                            Ok(_) => (),
                            Err(e) => log_error!(
                                self.logger,
                                "ERROR: could not persist payment info: {e}"
                            ),
                        }
                    }
                    None => {
                        // we failed in a payment that we didn't have saved? ...
                        log_warn!(
                            self.logger,
                            "WARN: payment failed but we did not have it stored"
                        );
                    }
                }
            }
            Event::PaymentForwarded { .. } => {
                log_info!(self.logger, "EVENT: PaymentForwarded somehow...");
            }
            Event::HTLCHandlingFailed { .. } => {
                log_debug!(self.logger, "EVENT: HTLCHandlingFailed, ignored");
            }
            Event::PendingHTLCsForwardable { time_forwardable } => {
                log_debug!(
                    self.logger,
                    "EVENT: PendingHTLCsForwardable: {time_forwardable:?}, processing..."
                );

                let forwarding_channel_manager = self.channel_manager.clone();
                let min = time_forwardable.as_millis() as i32;
                sleep(min).await;
                forwarding_channel_manager.process_pending_htlc_forwards();
            }
            Event::SpendableOutputs { outputs } => {
                if let Err(e) = self.handle_spendable_outputs(&outputs).await {
                    log_error!(self.logger, "Failed to handle spendable outputs: {e}");
                    // if we have an error we should persist the outputs so we can try again later
                    if let Err(e) = self.persister.persist_failed_spendable_outputs(outputs) {
                        log_error!(
                            self.logger,
                            "Failed to persist failed spendable outputs: {e}"
                        );
                    }
                }
            }
            Event::ChannelClosed {
                channel_id,
                reason,
                user_channel_id,
            } => {
                // if we still have channel open params, then it was just a failed channel open
                // we should not persist this as a closed channel and just delete the channel open params
                if let Ok(Some(_)) = self.persister.get_channel_open_params(user_channel_id) {
                    let _ = self.persister.delete_channel_open_params(user_channel_id);
                    return;
                };

                log_debug!(
                    self.logger,
                    "EVENT: Channel {} closed due to: {:?}",
                    channel_id.to_hex(),
                    reason
                );

                // this doesn't really work, leaving here because maybe sometimes it'll get the node id
                // can be fixed with https://github.com/lightningdevkit/rust-lightning/issues/2343
                let node_id = self.channel_manager.list_channels().iter().find_map(|c| {
                    if c.channel_id == channel_id {
                        Some(c.counterparty.node_id)
                    } else {
                        None
                    }
                });

                let closure = ChannelClosure::new(user_channel_id, channel_id, node_id, reason);
                if let Err(e) = self
                    .persister
                    .persist_channel_closure(user_channel_id, closure)
                {
                    log_error!(self.logger, "Failed to persist channel closure: {e}");
                }
            }
            Event::DiscardFunding { .. } => {
                // A "real" node should probably "lock" the UTXOs spent in funding transactions until
                // the funding transaction either confirms, or this event is generated.
                log_debug!(self.logger, "EVENT: DiscardFunding, ignored");
            }
            Event::ChannelReady {
                channel_id,
                user_channel_id,
                counterparty_node_id,
                channel_type,
            } => {
                log_debug!(
                    self.logger,
                    "EVENT: ChannelReady channel_id: {}, user_channel_id: {}, counterparty_node_id: {}, channel_type: {}",
                    channel_id.to_hex(),
                    user_channel_id,
                    counterparty_node_id.to_hex(),
                    channel_type);

                // Channel is ready, if it is a redshift channel, should update the status.
                if let Ok(Some(mut redshift)) = self
                    .persister
                    .storage
                    .get_redshift(&user_channel_id.to_be_bytes())
                {
                    // get channel
                    if let Some(chan) = self
                        .channel_manager
                        .list_channels_with_counterparty(&counterparty_node_id)
                        .iter()
                        .find(|c| c.channel_id == channel_id)
                    {
                        // update status, unwrap is safe because the channel is ready
                        redshift.channel_opened(chan.funding_txo.unwrap().into_bitcoin_outpoint());

                        // persist
                        if let Err(e) = self.persister.storage.persist_redshift(redshift) {
                            log_error!(self.logger, "Failed to persist redshift: {e}");
                        }
                    }
                }
            }
            Event::ChannelPending {
                channel_id,
                user_channel_id,
                counterparty_node_id,
                ..
            } => {
                log_debug!(
                    self.logger,
                    "EVENT: ChannelPending channel_id: {}, user_channel_id: {}, counterparty_node_id: {}",
                    channel_id.to_hex(),
                    user_channel_id,
                    counterparty_node_id.to_hex());

                if let Err(e) = self.persister.delete_channel_open_params(user_channel_id) {
                    log_warn!(
                        self.logger,
                        "ERROR: Could not delete channel open params, but continuing: {e}"
                    );
                }
            }
            Event::HTLCIntercepted { .. } => {}
            Event::BumpTransaction(event) => self.bump_tx_event_handler.handle_event(&event),
        }
    }

    // Separate function to handle spendable outputs
    // This is so we can return a result and handle errors
    // without having to use a lot of nested if statements
    pub(crate) async fn handle_spendable_outputs(
        &self,
        outputs: &[SpendableOutputDescriptor],
    ) -> anyhow::Result<()> {
        // Filter out static outputs, we don't want to spend them
        // because they have gone to our BDK wallet.
        // This would only be a waste in fees.
        let output_descriptors = outputs
            .iter()
            .filter(|d| match d {
                SpendableOutputDescriptor::StaticOutput { .. } => false,
                SpendableOutputDescriptor::DelayedPaymentOutput(_) => true,
                SpendableOutputDescriptor::StaticPaymentOutput(_) => true,
            })
            .collect::<Vec<_>>();

        // If there are no spendable outputs, we don't need to do anything
        if output_descriptors.is_empty() {
            return Ok(());
        }

        log_debug!(
            self.logger,
            "EVENT: processing SpendableOutputs {}",
            output_descriptors.len()
        );

        let tx_feerate = self
            .fee_estimator
            .get_est_sat_per_1000_weight(ConfirmationTarget::Normal);
        let spending_tx = self
            .keys_manager
            .spend_spendable_outputs(
                &output_descriptors,
                Vec::new(),
                tx_feerate,
                &Secp256k1::new(),
            )
            .map_err(|_| anyhow!("Failed to spend spendable outputs"))?;

        self.wallet.broadcast_transaction(spending_tx).await?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::event::{HTLCStatus, MillisatAmount, PaymentInfo};
    use crate::utils;
    use bitcoin::secp256k1::PublicKey;
    use std::str::FromStr;

    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};
    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    fn test_payment_info_serialization_symmetry() {
        let preimage = [1; 32];
        let pubkey = PublicKey::from_str(
            "02465ed5be53d04fde66c9418ff14a5f2267723810176c9212b722e542dc1afb1b",
        )
        .unwrap();

        let payment_info = PaymentInfo {
            preimage: Some(preimage),
            status: HTLCStatus::Succeeded,
            amt_msat: MillisatAmount(Some(420)),
            fee_paid_msat: None,
            bolt11: None,
            payee_pubkey: Some(pubkey),
            secret: None,
            last_update: utils::now().as_secs(),
        };

        let serialized = serde_json::to_string(&payment_info).unwrap();
        let deserialized: PaymentInfo = serde_json::from_str(&serialized).unwrap();
        assert_eq!(payment_info, deserialized);

        let serialized = serde_json::to_value(&payment_info).unwrap();
        let deserialized: PaymentInfo = serde_json::from_value(serialized).unwrap();
        assert_eq!(payment_info, deserialized);
    }
}
