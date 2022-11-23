use crate::ldkstorage::MutinyNodePersister;
use crate::logging::MutinyLogger;
use crate::utils::sleep;
use crate::wallet::MutinyWallet;
use crate::{chain::MutinyChain, ldkstorage::PhantomChannelManager};
use bdk::wallet::AddressIndex;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;
use bitcoin_bech32::WitnessProgram;
use bitcoin_hashes::hex::ToHex;
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use lightning::chain::keysinterface::PhantomKeysManager;
use lightning::util::events::{Event, EventHandler as LdkEventHandler, PaymentPurpose};
use lightning::util::logger::{Logger, Record};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct PaymentInfo {
    pub preimage: Option<[u8; 32]>,
    pub secret: Option<[u8; 32]>,
    pub status: HTLCStatus,
    pub amt_msat: MillisatAmount,
    pub fee_paid_msat: Option<u64>,
    pub bolt11: Option<String>,
    pub last_update: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct MillisatAmount(pub Option<u64>);

#[derive(Serialize, Deserialize, Clone)]
pub(crate) enum HTLCStatus {
    Pending,
    Succeeded,
    Failed,
}

pub struct EventHandler {
    channel_manager: Arc<PhantomChannelManager>,
    chain: Arc<MutinyChain>,
    wallet: Arc<MutinyWallet>,
    keys_manager: Arc<PhantomKeysManager>,
    persister: Arc<MutinyNodePersister>,
    network: Network,
    logger: Arc<MutinyLogger>,
}

impl EventHandler {
    pub(crate) fn new(
        channel_manager: Arc<PhantomChannelManager>,
        chain: Arc<MutinyChain>,
        wallet: Arc<MutinyWallet>,
        keys_manager: Arc<PhantomKeysManager>,
        persister: Arc<MutinyNodePersister>,
        network: Network,
        logger: Arc<MutinyLogger>,
    ) -> Self {
        Self {
            channel_manager,
            chain,
            wallet,
            keys_manager,
            network,
            persister,
            logger,
        }
    }
}

impl LdkEventHandler for EventHandler {
    fn handle_event(&self, event: &Event) {
        match event {
            Event::FundingGenerationReady {
                temporary_channel_id,
                counterparty_node_id,
                channel_value_satoshis,
                output_script,
                ..
            } => {
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Debug,
                    format_args!("EVENT: FundingGenerationReady processing"),
                    "event",
                    "",
                    0,
                ));
                // Construct the raw transaction with one output, that is paid the amount of the
                // channel.
                let addr = WitnessProgram::from_scriptpubkey(
                    &output_script[..],
                    match self.network {
                        Network::Bitcoin => bitcoin_bech32::constants::Network::Bitcoin,
                        Network::Testnet => bitcoin_bech32::constants::Network::Testnet,
                        Network::Regtest => bitcoin_bech32::constants::Network::Regtest,
                        Network::Signet => bitcoin_bech32::constants::Network::Signet,
                    },
                )
                .expect("Lightning funding tx should always be to a SegWit output")
                .to_address();

                let wallet_thread = self.wallet.clone();
                let channel_values_satoshis_thread = *channel_value_satoshis;
                let channel_manager_thread = self.channel_manager.clone();
                let logger_thread = self.logger.clone();
                let temporary_channel_id_thread = *temporary_channel_id;
                let counterparty_node_id_thread = *counterparty_node_id;
                spawn_local(async move {
                    let psbt = match wallet_thread
                        .create_signed_psbt(addr, channel_values_satoshis_thread, None)
                        .await
                    {
                        Ok(psbt) => psbt,
                        Err(e) => {
                            logger_thread.log(&Record::new(
                                lightning::util::logger::Level::Error,
                                format_args!("ERROR: Could not create a signed transaction to open channel with: {}", e),
                                "node",
                                "",
                                0,
                            ));
                            return;
                        }
                    };
                    if channel_manager_thread
                        .funding_transaction_generated(
                            &temporary_channel_id_thread,
                            &counterparty_node_id_thread,
                            psbt.extract_tx(),
                        )
                        .is_err()
                    {
                        logger_thread.log(&Record::new(
                            lightning::util::logger::Level::Error,
                            format_args!("ERROR: Channel went away before we could fund it. The peer disconnected or refused the channel."),
                            "node",
                            "",
                            0,
                        ));
                        return;
                    }

                    logger_thread.log(&Record::new(
                        lightning::util::logger::Level::Info,
                        format_args!("FundingGenerationReady success"),
                        "event",
                        "",
                        0,
                    ));
                })
            }
            Event::PaymentReceived {
                payment_hash,
                purpose,
                amount_msat,
            } => {
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Debug,
                    format_args!(
                        "EVENT: PaymentReceived received payment from payment hash {} of {} millisatoshis",
                        payment_hash.0.to_hex(),
                        amount_msat
                    ),
                    "event",
                    "",
                    0,
                ));

                let payment_preimage = if let Some(payment_preimage) = match purpose {
                    PaymentPurpose::InvoicePayment {
                        payment_preimage, ..
                    } => *payment_preimage,
                    PaymentPurpose::SpontaneousPayment(preimage) => Some(*preimage),
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
                    } => (*payment_preimage, Some(*payment_secret)),
                    PaymentPurpose::SpontaneousPayment(preimage) => (Some(*preimage), None),
                };
                match self.persister.read_payment_info(*payment_hash, true) {
                    Some(mut saved_payment_info) => {
                        let payment_preimage = payment_preimage.map(|p| p.0);
                        let payment_secret = payment_secret.map(|p| p.0);
                        saved_payment_info.status = HTLCStatus::Succeeded;
                        saved_payment_info.preimage = payment_preimage;
                        saved_payment_info.secret = payment_secret;
                        saved_payment_info.last_update = crate::utils::now().as_secs();
                        match self.persister.persist_payment_info(
                            *payment_hash,
                            saved_payment_info,
                            true,
                        ) {
                            Ok(_) => (),
                            Err(e) => {
                                self.logger.log(&Record::new(
                                    lightning::util::logger::Level::Error,
                                    format_args!("ERROR: could not persist payment info: {}", e),
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
                            amt_msat: MillisatAmount(Some(*amount_msat)),
                            fee_paid_msat: None,
                            bolt11: None,
                            last_update,
                        };
                        match self
                            .persister
                            .persist_payment_info(*payment_hash, payment_info, true)
                        {
                            Ok(_) => (),
                            Err(e) => {
                                self.logger.log(&Record::new(
                                    lightning::util::logger::Level::Error,
                                    format_args!("ERROR: could not persist payment info: {}", e),
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

                match self.persister.read_payment_info(*payment_hash, false) {
                    Some(mut saved_payment_info) => {
                        saved_payment_info.status = HTLCStatus::Succeeded;
                        saved_payment_info.preimage = Some(payment_preimage.0);
                        saved_payment_info.fee_paid_msat = *fee_paid_msat;
                        saved_payment_info.last_update = crate::utils::now().as_secs();
                        match self.persister.persist_payment_info(
                            *payment_hash,
                            saved_payment_info,
                            false,
                        ) {
                            Ok(_) => (),
                            Err(e) => {
                                self.logger.log(&Record::new(
                                    lightning::util::logger::Level::Error,
                                    format_args!("ERROR: could not persist payment info: {}", e),
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
            Event::OpenChannelRequest { .. } => {
                // Unreachable, we don't set manually_accept_inbound_channels
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Debug,
                    format_args!("EVENT: OpenChannelRequest ignored"),
                    "event",
                    "",
                    0,
                ));
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

                match self.persister.read_payment_info(*payment_hash, false) {
                    Some(mut saved_payment_info) => {
                        saved_payment_info.status = HTLCStatus::Failed;
                        saved_payment_info.last_update = crate::utils::now().as_secs();
                        match self.persister.persist_payment_info(
                            *payment_hash,
                            saved_payment_info,
                            false,
                        ) {
                            Ok(_) => (),
                            Err(e) => {
                                self.logger.log(&Record::new(
                                    lightning::util::logger::Level::Error,
                                    format_args!("ERROR: could not persist payment info: {}", e),
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
                spawn_local(async move {
                    sleep(min).await;
                    forwarding_channel_manager.process_pending_htlc_forwards();
                });
            }
            Event::SpendableOutputs { outputs } => {
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Debug,
                    format_args!("EVENT: SpendableOutputs processing"),
                    "event",
                    "",
                    0,
                ));
                let outputs_thread = outputs.clone();
                let wallet_thread = self.wallet.clone();
                let keys_manager_thread = self.keys_manager.clone();
                let chain_thread = self.chain.clone();
                spawn_local(async move {
                    let destination_address = wallet_thread
                        .wallet
                        .lock()
                        .await
                        .get_address(AddressIndex::New)
                        .expect("could not get new address");

                    let output_descriptors = &outputs_thread.iter().collect::<Vec<_>>();
                    let tx_feerate =
                        chain_thread.get_est_sat_per_1000_weight(ConfirmationTarget::Normal);
                    let spending_tx = keys_manager_thread
                        .spend_spendable_outputs(
                            output_descriptors,
                            Vec::new(),
                            destination_address.script_pubkey(),
                            tx_feerate,
                            &Secp256k1::new(),
                        )
                        .expect("could not spend spendable outputs");
                    chain_thread.broadcast_transaction(&spending_tx);
                });
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
        }
    }
}
