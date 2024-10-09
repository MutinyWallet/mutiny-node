use async_trait::async_trait;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::Network;
use futures::channel::oneshot;
use lightning::ln::channelmanager::MIN_FINAL_CLTV_EXPIRY_DELTA;
use lightning::ln::PaymentHash;
use lightning::routing::gossip::RoutingFees;
use lightning::routing::router::{RouteHint, RouteHintHop};
use lightning::util::logger::Logger;
use lightning::{log_debug, log_error, log_info};
use lightning_invoice::{Bolt11Invoice, InvoiceBuilder};
use lightning_liquidity::events::Event;
use lightning_liquidity::lsps0::ser::RequestId;
use lightning_liquidity::lsps2::event::LSPS2ClientEvent;
use lightning_liquidity::lsps2::msgs::OpeningFeeParams;
use lightning_liquidity::lsps2::utils::compute_opening_fee;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::{
    error::MutinyError,
    keymanager::PhantomKeysManager,
    ldkstorage::PhantomChannelManager,
    logging::MutinyLogger,
    lsp::{FeeRequest, InvoiceRequest, Lsp, LspConfig},
    node::{parse_peer_info, LiquidityManager},
    storage::MutinyStorage,
    utils,
};

use super::FeeResponse;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct LspsConfig {
    pub connection_string: String,
    pub token: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct JitChannelInfo {
    pub fee_params: OpeningFeeParams,
    pub payment_size_msat: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct GetInfoResponse {
    pub opening_fee_params_menu: Vec<OpeningFeeParams>,
}

pub(crate) struct PendingPaymentInfo {
    pub expected_fee_msat: Option<u64>,
    pub fee_params: OpeningFeeParams,
}

type PendingFeeRequestSender = oneshot::Sender<Result<GetInfoResponse, MutinyError>>;
type PendingBuyRequestSender = oneshot::Sender<Result<Bolt11Invoice, MutinyError>>;

#[derive(Clone)]
pub struct LspsClient<S: MutinyStorage> {
    pub pubkey: PublicKey,
    pub connection_string: String,
    pub token: Option<String>,
    liquidity_manager: Arc<LiquidityManager<S>>,
    channel_manager: Arc<PhantomChannelManager<S>>,
    keys_manager: Arc<PhantomKeysManager<S>>,
    network: Network,
    logger: Arc<MutinyLogger>,
    pending_fee_requests: Arc<Mutex<HashMap<RequestId, PendingFeeRequestSender>>>,
    pending_buy_requests: Arc<Mutex<HashMap<RequestId, PendingBuyRequestSender>>>,
    pending_channel_info: Arc<Mutex<HashMap<RequestId, JitChannelInfo>>>,
    pending_payments: Arc<Mutex<HashMap<PaymentHash, PendingPaymentInfo>>>,
    stop: Arc<AtomicBool>,
}

impl<S: MutinyStorage> LspsClient<S> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        lsp_connection_string: String,
        token: Option<String>,
        liquidity_manager: Arc<LiquidityManager<S>>,
        channel_manager: Arc<PhantomChannelManager<S>>,
        keys_manager: Arc<PhantomKeysManager<S>>,
        network: Network,
        logger: Arc<MutinyLogger>,
        stop: Arc<AtomicBool>,
    ) -> Result<Self, MutinyError> {
        let (lsp_pubkey, _) = parse_peer_info(&lsp_connection_string)?;

        let client = LspsClient {
            pubkey: lsp_pubkey,
            connection_string: lsp_connection_string,
            token,
            liquidity_manager,
            channel_manager,
            keys_manager,
            network,
            logger,
            pending_fee_requests: Arc::new(Mutex::new(HashMap::new())),
            pending_buy_requests: Arc::new(Mutex::new(HashMap::new())),
            pending_channel_info: Arc::new(Mutex::new(HashMap::new())),
            pending_payments: Arc::new(Mutex::new(HashMap::new())),
            stop,
        };

        let events_client = client.clone();
        utils::spawn(async move {
            events_client.handle_events().await;
        });

        Ok(client)
    }

    pub(crate) async fn handle_event(&self, event: Event) {
        match event {
            Event::LSPS2Client(LSPS2ClientEvent::OpeningParametersReady {
                counterparty_node_id,
                opening_fee_params_menu,
                request_id,
            }) => {
                log_debug!(
                    self.logger,
                    "received GetInfoResponse for counterparty_node_id {counterparty_node_id}",
                );

                let mut pending_fee_requests = self.pending_fee_requests.lock().unwrap();

                if let Some(fee_response_sender) = pending_fee_requests.remove(&request_id) {
                    if fee_response_sender
                        .send(Ok(GetInfoResponse {
                            opening_fee_params_menu,
                        }))
                        .is_err()
                    {
                        log_error!(self.logger, "error sending fee response, receiver dropped?");
                    }
                }
            }
            Event::LSPS2Client(LSPS2ClientEvent::InvoiceParametersReady {
                intercept_scid,
                cltv_expiry_delta,
                counterparty_node_id,
                payment_size_msat,
                request_id,
            }) => {
                log_debug!(self.logger, "received InvoiceGenerationReady with intercept_scid {}, cltv_expiry_delta {}, request_id {:?}, counterparty_node_id {}, payment_size_msat {:?}", intercept_scid, cltv_expiry_delta, request_id, counterparty_node_id, payment_size_msat);

                let mut pending_buy_requests = self.pending_buy_requests.lock().unwrap();

                if let Some(buy_response_sender) = pending_buy_requests.remove(&request_id) {
                    let invoice_expiry_delta_secs = 3600;
                    let (payment_hash, payment_secret) = match self
                        .channel_manager
                        .create_inbound_payment(None, invoice_expiry_delta_secs, None)
                    {
                        Ok((payment_hash, payment_secret)) => (payment_hash, payment_secret),
                        Err(_) => {
                            log_error!(self.logger, "error creating inbound payment");
                            if buy_response_sender
                                .send(Err(MutinyError::InvoiceCreationFailed))
                                .is_err()
                            {
                                log_error!(
                                    self.logger,
                                    "error sending buy response, receiver dropped?"
                                );
                            }
                            return;
                        }
                    };

                    let cltv_expiry_delta: u16 = match cltv_expiry_delta.try_into() {
                        Ok(cltv_expiry_delta) => cltv_expiry_delta,
                        Err(e) => {
                            log_error!(
                                self.logger,
                                "error converting cltv_expiry_delta to u16: {:?}",
                                e
                            );
                            if buy_response_sender
                                .send(Err(MutinyError::InvoiceCreationFailed))
                                .is_err()
                            {
                                log_error!(
                                    self.logger,
                                    "error sending buy response, receiver dropped?"
                                );
                            }
                            return;
                        }
                    };

                    let lsp_route_hint = RouteHint(vec![RouteHintHop {
                        src_node_id: counterparty_node_id,
                        short_channel_id: intercept_scid,
                        fees: RoutingFees {
                            base_msat: 0,
                            proportional_millionths: 0,
                        },
                        cltv_expiry_delta,
                        htlc_minimum_msat: None,
                        htlc_maximum_msat: None,
                    }]);

                    let payment_hash = match sha256::Hash::from_slice(&payment_hash.0) {
                        Ok(payment_hash) => payment_hash,
                        Err(e) => {
                            log_error!(
                                self.logger,
                                "error converting payment_hash to sha256::Hash: {:?}",
                                e
                            );
                            if buy_response_sender
                                .send(Err(MutinyError::InvoiceCreationFailed))
                                .is_err()
                            {
                                log_error!(
                                    self.logger,
                                    "error sending buy response, receiver dropped?"
                                );
                            }
                            return;
                        }
                    };

                    let secp = Secp256k1::new();
                    let payee_pub_key = self.keys_manager.get_node_secret_key().public_key(&secp);
                    let mut invoice = InvoiceBuilder::new(self.network.into())
                        .description("".into())
                        .payment_hash(payment_hash)
                        .payment_secret(payment_secret)
                        .duration_since_epoch(utils::now())
                        .payee_pub_key(payee_pub_key)
                        .basic_mpp()
                        .min_final_cltv_expiry_delta(MIN_FINAL_CLTV_EXPIRY_DELTA.into())
                        .private_route(lsp_route_hint);

                    let payment_size_msat = match payment_size_msat {
                        Some(payment_size_msat) => payment_size_msat,
                        None => {
                            log_error!(self.logger, "payment_size_msat was not specified but is required to create an invoice");
                            if buy_response_sender
                                .send(Err(MutinyError::InvoiceCreationFailed))
                                .is_err()
                            {
                                log_error!(
                                    self.logger,
                                    "error sending buy response, receiver dropped?"
                                );
                            }
                            return;
                        }
                    };

                    invoice = invoice.amount_milli_satoshis(payment_size_msat);

                    let invoice = match invoice.try_build_signed(|hash| {
                        let sig = secp
                            .sign_ecdsa_recoverable(hash, &self.keys_manager.get_node_secret_key());

                        // verify that the signature is correct and we produced a valid invoice
                        let pk = secp.recover_ecdsa(hash, &sig)?;
                        if pk != payee_pub_key {
                            return Err(bitcoin::secp256k1::Error::IncorrectSignature);
                        }

                        Ok(sig)
                    }) {
                        Ok(invoice) => invoice,
                        Err(e) => {
                            log_error!(self.logger, "error building signed invoice: {:?}", e);
                            if buy_response_sender
                                .send(Err(MutinyError::InvoiceCreationFailed))
                                .is_err()
                            {
                                log_error!(
                                    self.logger,
                                    "error sending buy response, receiver dropped?"
                                );
                            }
                            return;
                        }
                    };

                    if buy_response_sender.send(Ok(invoice)).is_err() {
                        log_error!(self.logger, "error sending buy response, receiver dropped?");
                    }

                    log_info!(self.logger, "LSPS invoice created successfully");
                }
            }
            _ => {}
        }
    }

    pub(crate) async fn handle_events(&self) {
        loop {
            for event in self.liquidity_manager.get_and_clear_pending_events() {
                self.handle_event(event).await;
            }

            if self.stop.load(Ordering::Relaxed) {
                break;
            }

            utils::sleep(1000).await;
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<S: MutinyStorage> Lsp for LspsClient<S> {
    async fn get_lsp_fee_msat(&self, fee_request: FeeRequest) -> Result<FeeResponse, MutinyError> {
        let (pending_fee_request_sender, pending_fee_request_receiver) =
            oneshot::channel::<Result<GetInfoResponse, MutinyError>>();

        log_debug!(
            self.logger,
            "initiating inbound flow for {}msats with token {:?}",
            fee_request.amount_msat,
            &self.token
        );

        let lsps2_client_handler = self
            .liquidity_manager
            .lsps2_client_handler()
            .expect("to be configured with lsps2 client config");

        let request_id = {
            let mut pending_fee_requests = self.pending_fee_requests.lock().unwrap();
            let request_id =
                lsps2_client_handler.request_opening_params(self.pubkey, self.token.clone());
            log_debug!(
                self.logger,
                "requested opening params from lsp with request_id {:?}",
                request_id
            );
            pending_fee_requests.insert(request_id.clone(), pending_fee_request_sender);
            request_id
        };

        let get_info_response = pending_fee_request_receiver.await.map_err(|e| {
            log_debug!(self.logger, "error receiving get info response: {:?}", e);
            MutinyError::LspGenericError
        })??;

        let fee_params = get_info_response.opening_fee_params_menu[0].clone();

        let min_fee_msat = fee_params.min_fee_msat;
        let proportional_fee = fee_params.proportional;

        log_debug!(
            self.logger,
            "received fee information. min_fee_msat {}, proportional fee {}, min payment {}msats, max payment {}msats",
            min_fee_msat,
            proportional_fee,
            fee_params.min_payment_size_msat,
            fee_params.max_payment_size_msat,
        );

        {
            let mut pending_channel_info = self.pending_channel_info.lock().unwrap();
            pending_channel_info.insert(
                request_id.clone(),
                JitChannelInfo {
                    fee_params,
                    payment_size_msat: fee_request.amount_msat,
                },
            );
        }

        let fee_amount_msat = compute_opening_fee(
            fee_request.amount_msat,
            min_fee_msat,
            proportional_fee.into(),
        )
        .ok_or(MutinyError::LspGenericError)?;

        Ok(FeeResponse {
            id: request_id.0,
            fee_amount_msat,
        })
    }

    async fn get_lsp_invoice(
        &self,
        invoice_request: InvoiceRequest,
    ) -> Result<Bolt11Invoice, MutinyError> {
        let fee_request_id = RequestId(invoice_request.fee_id);
        let (fee_params, payment_size_msat) = {
            let channel_info = self.pending_channel_info.lock().unwrap();
            let channel_info = channel_info
                .get(&fee_request_id)
                .ok_or(MutinyError::LspGenericError)?;

            (
                channel_info.fee_params.clone(),
                channel_info.payment_size_msat,
            )
        };

        let lsps2_client_handler = self
            .liquidity_manager
            .lsps2_client_handler()
            .expect("to be configured with lsps2 client config");

        let (pending_buy_request_sender, pending_buy_request_receiver) =
            oneshot::channel::<Result<Bolt11Invoice, MutinyError>>();

        {
            let mut pending_buy_requests: std::sync::MutexGuard<
                '_,
                HashMap<RequestId, oneshot::Sender<Result<Bolt11Invoice, MutinyError>>>,
            > = self.pending_buy_requests.lock().unwrap();

            let request_id = lsps2_client_handler
                .select_opening_params(self.pubkey, Some(payment_size_msat), fee_params.clone())
                .map_err(|_| MutinyError::LspGenericError)?;

            pending_buy_requests.insert(request_id.clone(), pending_buy_request_sender);
        }

        let invoice = pending_buy_request_receiver
            .await
            .map_err(|_| MutinyError::LspGenericError)??;

        let payment_hash = PaymentHash(invoice.payment_hash().to_byte_array());
        let payment_amount = invoice.amount_milli_satoshis();

        let expected_fee_msat = payment_amount.and_then(|payment_amount| {
            compute_opening_fee(
                payment_amount,
                fee_params.min_fee_msat,
                fee_params.proportional.into(),
            )
        });
        {
            let mut pending_payments = self.pending_payments.lock().unwrap();
            pending_payments.insert(
                payment_hash,
                PendingPaymentInfo {
                    expected_fee_msat,
                    fee_params,
                },
            );
        }

        Ok(invoice)
    }

    async fn get_lsp_pubkey(&self) -> PublicKey {
        self.pubkey
    }

    async fn get_lsp_connection_string(&self) -> String {
        self.connection_string.clone()
    }

    async fn get_config(&self) -> LspConfig {
        LspConfig::Lsps(LspsConfig {
            connection_string: self.connection_string.clone(),
            token: self.token.clone(),
        })
    }

    fn get_expected_skimmed_fee_msat(&self, payment_hash: PaymentHash, payment_size: u64) -> u64 {
        let mut pending_payments = self.pending_payments.lock().unwrap();

        if let Some(pending_payment) = pending_payments.get_mut(&payment_hash) {
            if let Some(expected_fee_msat) = pending_payment.expected_fee_msat {
                return expected_fee_msat;
            }

            compute_opening_fee(
                payment_size,
                pending_payment.fee_params.min_fee_msat,
                pending_payment.fee_params.proportional.into(),
            )
            .unwrap_or(0)
        } else {
            0
        }
    }
}
