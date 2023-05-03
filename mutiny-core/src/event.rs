use crate::fees::MutinyFeeEstimator;
use crate::keymanager::PhantomKeysManager;
use crate::ldkstorage::{MutinyNodePersister, PhantomChannelManager};
use crate::logging::MutinyLogger;
use crate::onchain::OnChainWallet;
use crate::utils::sleep;
use anyhow::anyhow;
use bitcoin::hashes::hex::ToHex;
use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::Secp256k1;
use lightning::chain::keysinterface::SpendableOutputDescriptor;
use lightning::events::{Event, PaymentPurpose};
use lightning::{
    chain::chaininterface::{ConfirmationTarget, FeeEstimator},
    log_debug, log_error, log_info, log_warn,
    util::errors::APIError,
    util::logger::{Logger, Record},
};
use lightning_invoice::Invoice;
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
    pub bolt11: Option<Invoice>,
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
pub(crate) enum HTLCStatus {
    Pending,
    InFlight,
    Succeeded,
    Failed,
}

#[derive(Clone)]
pub struct EventHandler {
    channel_manager: Arc<PhantomChannelManager>,
    fee_estimator: Arc<MutinyFeeEstimator>,
    wallet: Arc<OnChainWallet>,
    keys_manager: Arc<PhantomKeysManager>,
    persister: Arc<MutinyNodePersister>,
    lsp_client_pubkey: Option<PublicKey>,
    logger: Arc<MutinyLogger>,
}

impl EventHandler {
    pub(crate) fn new(
        channel_manager: Arc<PhantomChannelManager>,
        fee_estimator: Arc<MutinyFeeEstimator>,
        wallet: Arc<OnChainWallet>,
        keys_manager: Arc<PhantomKeysManager>,
        persister: Arc<MutinyNodePersister>,
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

                let psbt_result = match params_opt {
                    None => self.wallet.create_signed_psbt_to_spk(
                        output_script,
                        channel_value_satoshis,
                        None,
                    ),
                    Some(params) => {
                        let psbt = self.wallet.spend_utxos_to_output(
                            &params.utxos,
                            output_script,
                            channel_value_satoshis,
                        );

                        // delete from storage, if it fails, it is fine, just log it.
                        if let Err(e) = self.persister.delete_channel_open_params(user_channel_id) {
                            log_warn!(
                                self.logger,
                                "ERROR: Could not delete channel open params, but continuing: {e}"
                            );
                        }

                        psbt
                    }
                };

                let psbt = match psbt_result {
                    Ok(psbt) => psbt,
                    Err(e) => {
                        log_error!(self.logger, "ERROR: Could not create a signed transaction to open channel with: {e}");
                        return;
                    }
                };

                if let Err(e) = self.channel_manager.funding_transaction_generated(
                    &temporary_channel_id,
                    &counterparty_node_id,
                    psbt.extract_tx(),
                ) {
                    log_error!(
                        self.logger,
                        "ERROR: Could not send funding transaction to channel manager: {e:?}"
                    );
                    return;
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
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Debug,
                    format_args!(
                        "EVENT: PaymentReceived received payment from payment hash {} of {} millisatoshis to {:?}",
                        payment_hash.0.to_hex(),
                        amount_msat,
                        receiver_node_id
                    ),
                    "event",
                    "",
                    0,
                ));

                let payment_preimage = if let Some(payment_preimage) = match purpose {
                    PaymentPurpose::InvoicePayment {
                        payment_preimage, ..
                    } => payment_preimage,
                    PaymentPurpose::SpontaneousPayment(preimage) => Some(preimage),
                } {
                    payment_preimage
                } else {
                    self.logger.log(&Record::new(
                        lightning::util::logger::Level::Error,
                        format_args!("ERROR: No payment preimage found"),
                        "node",
                        "",
                        0,
                    ));
                    return;
                };
                self.channel_manager.claim_funds(payment_preimage);
            }
            Event::PaymentClaimed {
                receiver_node_id,
                payment_hash,
                purpose,
                amount_msat,
            } => {
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Debug,
                    format_args!(
                        "EVENT: PaymentClaimed claimed payment from payment hash {} of {} millisatoshis",
                        payment_hash.0.to_hex(),
                        amount_msat
                    ),
                    "node",
                    "",
                    0,
                ));

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
                    .read_payment_info(&payment_hash, true, self.logger.clone())
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
                            &payment_hash,
                            &saved_payment_info,
                            true,
                        ) {
                            Ok(_) => (),
                            Err(e) => {
                                self.logger.log(&Record::new(
                                    lightning::util::logger::Level::Error,
                                    format_args!("ERROR: could not persist payment info: {e}"),
                                    "node",
                                    "",
                                    0,
                                ));
                            }
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
                            &payment_hash,
                            &payment_info,
                            true,
                        ) {
                            Ok(_) => (),
                            Err(e) => {
                                self.logger.log(&Record::new(
                                    lightning::util::logger::Level::Error,
                                    format_args!("ERROR: could not persist payment info: {e}"),
                                    "node",
                                    "",
                                    0,
                                ));
                            }
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
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Debug,
                    format_args!("EVENT: PaymentSent: {}", payment_hash.0.to_hex()),
                    "event",
                    "",
                    0,
                ));

                match self
                    .persister
                    .read_payment_info(&payment_hash, false, self.logger.clone())
                {
                    Some(mut saved_payment_info) => {
                        saved_payment_info.status = HTLCStatus::Succeeded;
                        saved_payment_info.preimage = Some(payment_preimage.0);
                        saved_payment_info.fee_paid_msat = fee_paid_msat;
                        saved_payment_info.last_update = crate::utils::now().as_secs();
                        match self.persister.persist_payment_info(
                            &payment_hash,
                            &saved_payment_info,
                            false,
                        ) {
                            Ok(_) => (),
                            Err(e) => {
                                self.logger.log(&Record::new(
                                    lightning::util::logger::Level::Error,
                                    format_args!("ERROR: could not persist payment info: {e}"),
                                    "event",
                                    "",
                                    0,
                                ));
                            }
                        }
                    }
                    None => {
                        // we succeeded in a payment that we didn't have saved? ...
                        self.logger.log(&Record::new(
                            lightning::util::logger::Level::Warn,
                            format_args!("WARN: payment succeeded but we did not have it stored"),
                            "event",
                            "",
                            0,
                        ));
                    }
                }
            }
            Event::OpenChannelRequest {
                temporary_channel_id,
                counterparty_node_id,
                ..
            } => {
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Debug,
                    format_args!("EVENT: OpenChannelRequest incoming"),
                    "event",
                    "",
                    0,
                ));

                let mut internal_channel_id_bytes = [0u8; 16];
                if getrandom::getrandom(&mut internal_channel_id_bytes).is_err() {
                    self.logger.log(&Record::new(
                        lightning::util::logger::Level::Debug,
                        format_args!("EVENT: OpenChannelRequest failed random number generation"),
                        "event",
                        "",
                        0,
                    ));
                };
                let internal_channel_id = u128::from_be_bytes(internal_channel_id_bytes);

                let log_result = |result: Result<(), APIError>| match result {
                    Ok(_) => {
                        self.logger.log(&Record::new(
                            lightning::util::logger::Level::Debug,
                            format_args!("EVENT: OpenChannelRequest accepted"),
                            "event",
                            "",
                            0,
                        ));
                    }
                    Err(e) => {
                        self.logger.log(&Record::new(
                            lightning::util::logger::Level::Debug,
                            format_args!("EVENT: OpenChannelRequest error: {:?}", e),
                            "event",
                            "",
                            0,
                        ));
                    }
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
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Debug,
                    format_args!("EVENT: PaymentPathSuccessful ignored"),
                    "event",
                    "",
                    0,
                ));
            }
            Event::PaymentPathFailed { .. } => {
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Debug,
                    format_args!("EVENT: PaymentPathFailed ignored"),
                    "event",
                    "",
                    0,
                ));
            }
            Event::ProbeSuccessful { .. } => {
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Debug,
                    format_args!("EVENT: ProbeSuccessful ignored"),
                    "event",
                    "",
                    0,
                ));
            }
            Event::ProbeFailed { .. } => {
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Debug,
                    format_args!("EVENT: ProbeFailed ignored"),
                    "event",
                    "",
                    0,
                ));
            }
            Event::PaymentFailed { payment_hash, .. } => {
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Error,
                    format_args!("EVENT: PaymentFailed: {}", payment_hash.0.to_hex()),
                    "event",
                    "",
                    0,
                ));

                match self
                    .persister
                    .read_payment_info(&payment_hash, false, self.logger.clone())
                {
                    Some(mut saved_payment_info) => {
                        saved_payment_info.status = HTLCStatus::Failed;
                        saved_payment_info.last_update = crate::utils::now().as_secs();
                        match self.persister.persist_payment_info(
                            &payment_hash,
                            &saved_payment_info,
                            false,
                        ) {
                            Ok(_) => (),
                            Err(e) => {
                                self.logger.log(&Record::new(
                                    lightning::util::logger::Level::Error,
                                    format_args!("ERROR: could not persist payment info: {e}"),
                                    "event",
                                    "",
                                    0,
                                ));
                            }
                        }
                    }
                    None => {
                        // we failed in a payment that we didn't have saved? ...
                        self.logger.log(&Record::new(
                            lightning::util::logger::Level::Warn,
                            format_args!("WARN: payment failed but we did not have it stored"),
                            "event",
                            "",
                            0,
                        ));
                    }
                }
            }
            Event::PaymentForwarded { .. } => {
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Info,
                    format_args!("EVENT: PaymentForwarded somehow...:"),
                    "event",
                    "",
                    0,
                ));
            }
            Event::HTLCHandlingFailed { .. } => {
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Debug,
                    format_args!("EVENT: HTLCHandlingFailed ignored"),
                    "event",
                    "",
                    0,
                ));
            }
            Event::PendingHTLCsForwardable { time_forwardable } => {
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Debug,
                    format_args!("EVENT: PendingHTLCsForwardable processing"),
                    "event",
                    "",
                    0,
                ));
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
                user_channel_id: _,
            } => {
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Debug,
                    format_args!(
                        "EVENT: Channel {} closed due to: {:?}",
                        channel_id.to_hex(),
                        reason
                    ),
                    "event",
                    "",
                    0,
                ));
            }
            Event::DiscardFunding { .. } => {
                // A "real" node should probably "lock" the UTXOs spent in funding transactions until
                // the funding transaction either confirms, or this event is generated.
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Debug,
                    format_args!("EVENT: DiscardFunding ignored"),
                    "event",
                    "",
                    0,
                ));
            }
            Event::ChannelReady {
                channel_id,
                user_channel_id,
                counterparty_node_id,
                channel_type,
            } => {
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Debug,
                    format_args!("EVENT: ChannelReady channel_id: {}, user_channel_id: {}, counterparty_node_id: {}, channel_type: {}", channel_id.to_hex(), user_channel_id, counterparty_node_id.to_hex(), channel_type),
                    "event",
                    "",
                    0,
                ));
            }
            Event::ChannelPending {
                channel_id,
                user_channel_id,
                counterparty_node_id,
                ..
            } => {
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Debug,
                    format_args!("EVENT: ChannelPending channel_id: {}, user_channel_id: {}, counterparty_node_id: {}", channel_id.to_hex(), user_channel_id, counterparty_node_id.to_hex()),
                    "event",
                    "",
                    0,
                ));
            }
            Event::HTLCIntercepted { .. } => {}
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

        self.wallet.blockchain.broadcast(&spending_tx).await?;

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
