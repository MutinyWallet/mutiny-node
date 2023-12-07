use async_trait::async_trait;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::Network;
use futures::channel::oneshot;
use lightning::ln::channelmanager::MIN_FINAL_CLTV_EXPIRY_DELTA;
use lightning::ln::PaymentHash;
use lightning::log_debug;
use lightning::routing::gossip::RoutingFees;
use lightning::routing::router::{RouteHint, RouteHintHop};
use lightning::util::logger::Logger;
use lightning_invoice::{Bolt11Invoice, InvoiceBuilder};
use lightning_liquidity::events;
use lightning_liquidity::lsps2::{LSPS2Event, OpeningFeeParams};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

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

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct LspsConfig {
    pub connection_string: String,
    pub token: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct JitChannelInfo {
    pub channel_id: u128,
    pub fee_params: OpeningFeeParams,
}

#[derive(Clone, Debug)]
pub(crate) struct GetInfoResponse {
    pub jit_channel_id: u128,
    pub opening_fee_params_menu: Vec<OpeningFeeParams>,
}

pub(crate) struct PendingPaymentInfo {
    pub expected_fee_msat: Option<u64>,
    pub fee_params: OpeningFeeParams,
}

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
    pending_fee_requests: Arc<Mutex<HashMap<u128, oneshot::Sender<GetInfoResponse>>>>,
    pending_buy_requests: Arc<Mutex<HashMap<u128, oneshot::Sender<Bolt11Invoice>>>>,
    pending_channel_info: Arc<Mutex<HashMap<u128, JitChannelInfo>>>,
    pending_payments: Arc<Mutex<HashMap<PaymentHash, PendingPaymentInfo>>>,
}

impl<S: MutinyStorage> LspsClient<S> {
    pub(crate) fn new(
        lsp_connection_string: String,
        token: Option<String>,
        liquidity_manager: Arc<LiquidityManager<S>>,
        channel_manager: Arc<PhantomChannelManager<S>>,
        keys_manager: Arc<PhantomKeysManager<S>>,
        network: Network,
        logger: Arc<MutinyLogger>,
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
        };

        let events_client = client.clone();
        utils::spawn(async move {
            events_client.handle_events().await;
        });

        Ok(client)
    }

    pub(crate) async fn handle_events(&self) {
        loop {
            for event in self.liquidity_manager.get_and_clear_pending_events() {
                match event {
                    events::Event::LSPS2(LSPS2Event::GetInfoResponse {
                        jit_channel_id,
                        opening_fee_params_menu,
                        user_channel_id,
                        ..
                    }) => {
                        log_debug!(self.logger, "received get info response!");

                        let mut pending_fee_requests = self.pending_fee_requests.lock().unwrap();

                        if let Some(fee_response_sender) =
                            pending_fee_requests.remove(&user_channel_id)
                        {
                            if let Err(_e) = fee_response_sender.send(GetInfoResponse {
                                jit_channel_id,
                                opening_fee_params_menu,
                            }) {
                                // log error
                            }
                        }
                    }
                    events::Event::LSPS2(LSPS2Event::InvoiceGenerationReady {
                        scid,
                        cltv_expiry_delta,
                        user_channel_id,
                        counterparty_node_id,
                        payment_size_msat,
                        ..
                    }) => {
                        let mut pending_buy_requests = self.pending_buy_requests.lock().unwrap();

                        if let Some(buy_response_sender) =
                            pending_buy_requests.remove(&user_channel_id)
                        {
                            let invoice_expiry_delta_secs = 60 * 60 * 24 * 3;
                            let (payment_hash, payment_secret) = self
                                .channel_manager
                                .create_inbound_payment(None, invoice_expiry_delta_secs, None)
                                .unwrap();

                            let lsp_route_hint = RouteHint(vec![RouteHintHop {
                                src_node_id: counterparty_node_id,
                                short_channel_id: scid,
                                fees: RoutingFees {
                                    base_msat: 0,
                                    proportional_millionths: 0,
                                },
                                cltv_expiry_delta: cltv_expiry_delta.try_into().unwrap(),
                                htlc_minimum_msat: None,
                                htlc_maximum_msat: None,
                            }]);

                            let mut invoice = InvoiceBuilder::new(self.network.into())
                                .description("Coins pls!".into())
                                .payment_hash(sha256::Hash::from_slice(&payment_hash.0).unwrap())
                                .payment_secret(payment_secret)
                                .duration_since_epoch(utils::now())
                                .min_final_cltv_expiry_delta(MIN_FINAL_CLTV_EXPIRY_DELTA.into())
                                .private_route(lsp_route_hint);

                            if let Some(payment_size_msat) = payment_size_msat {
                                invoice = invoice.amount_milli_satoshis(payment_size_msat)
                            };

                            let invoice = invoice
                                .build_signed(|hash| {
                                    Secp256k1::new().sign_ecdsa_recoverable(
                                        hash,
                                        &self.keys_manager.get_node_secret_key(),
                                    )
                                })
                                .unwrap();

                            if let Err(_e) = buy_response_sender.send(invoice) {
                                // log error
                            }
                        }
                    }
                    _ => {}
                }
            }

            utils::sleep(1000).await;
        }
    }
}

/// TODO: import from lightning-liquidity once it's exposed
/// Computes the opening fee given a payment size and the fee parameters.
///
/// Returns [`Option::None`] when the computation overflows.
///
/// See the [`specification`](https://github.com/BitcoinAndLightningLayerSpecs/lsp/tree/main/LSPS2#computing-the-opening_fee) for more details.
pub fn compute_opening_fee(
    payment_size_msat: u64,
    opening_fee_min_fee_msat: u64,
    opening_fee_proportional: u64,
) -> Option<u64> {
    payment_size_msat
        .checked_mul(opening_fee_proportional)
        .and_then(|f| f.checked_add(999999))
        .and_then(|f| f.checked_div(1000000))
        .map(|f| std::cmp::max(f, opening_fee_min_fee_msat))
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<S: MutinyStorage> Lsp for LspsClient<S> {
    async fn get_lsp_fee_msat(&self, fee_request: FeeRequest) -> Result<u64, MutinyError> {
        let inbound_capacity_msat: u64 = self
            .channel_manager
            .list_channels_with_counterparty(&self.get_lsp_pubkey())
            .iter()
            .map(|c| c.inbound_capacity_msat)
            .sum();

        // if there's enough capacity then the LSP won't charge an opening fee to route a normal payment
        // this is only here to keep both voltage + lsps logic symmetric
        if inbound_capacity_msat >= fee_request.amount_msat {
            return Ok(0);
        }

        let (pending_fee_request_sender, pending_fee_request_receiver) =
            oneshot::channel::<GetInfoResponse>();

        {
            let mut pending_fee_requests = self.pending_fee_requests.lock().unwrap();
            pending_fee_requests.insert(fee_request.user_channel_id, pending_fee_request_sender);
        }

        log_debug!(
            self.logger,
            "initiating inbound flow for {}msats with token {:?}",
            fee_request.amount_msat,
            &self.token
        );

        self.liquidity_manager
            .lsps2_create_invoice(
                self.pubkey,
                Some(fee_request.amount_msat),
                self.token.clone(),
                fee_request.user_channel_id,
            )
            .map_err(|e| {
                log_debug!(self.logger, "error creating lsps2 invoice: {:?}", e);
                MutinyError::LspGenericError
            })?;

        let get_info_response = pending_fee_request_receiver.await.map_err(|e| {
            log_debug!(self.logger, "error receiving get info response: {:?}", e);
            MutinyError::LspGenericError
        })?;

        let fee_params = get_info_response.opening_fee_params_menu[0].clone();

        let min_fee_msat = fee_params.min_fee_msat;
        let proportional_fee = fee_params.proportional;

        log_debug!(
            self.logger,
            "received fee information. min_fee_msat {} and proportional fee {}",
            min_fee_msat,
            proportional_fee
        );

        {
            let mut pending_channel_info = self.pending_channel_info.lock().unwrap();
            pending_channel_info.insert(
                fee_request.user_channel_id,
                JitChannelInfo {
                    channel_id: get_info_response.jit_channel_id,
                    fee_params,
                },
            );
        }

        compute_opening_fee(
            fee_request.amount_msat,
            min_fee_msat,
            proportional_fee.into(),
        )
        .ok_or(MutinyError::LspGenericError)
    }

    async fn get_lsp_invoice(
        &self,
        invoice_request: InvoiceRequest,
    ) -> Result<String, MutinyError> {
        let (pending_buy_request_sender, pending_buy_request_receiver) =
            oneshot::channel::<Bolt11Invoice>();

        {
            let mut pending_buy_requests = self.pending_buy_requests.lock().unwrap();
            pending_buy_requests
                .insert(invoice_request.user_channel_id, pending_buy_request_sender);
        }

        let (channel_id, fee_params) = {
            let channel_info = self.pending_channel_info.lock().unwrap();
            let channel_info = channel_info
                .get(&invoice_request.user_channel_id)
                .ok_or(MutinyError::LspGenericError)?;

            (channel_info.channel_id, channel_info.fee_params.clone())
        };

        self.liquidity_manager
            .opening_fee_params_selected(self.pubkey, channel_id, fee_params.clone())
            .map_err(|_| MutinyError::LspGenericError)?;

        let invoice = pending_buy_request_receiver
            .await
            .map_err(|_| MutinyError::LspGenericError)?;

        let payment_hash = PaymentHash(invoice.payment_hash().clone().into_inner());
        let payment_amount = invoice.amount_milli_satoshis();

        let expected_fee_msat = payment_amount
            .map(|payment_amount| {
                compute_opening_fee(
                    payment_amount,
                    fee_params.min_fee_msat,
                    fee_params.proportional.into(),
                )
            })
            .flatten();

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

        Ok(invoice.to_string())
    }

    fn get_lsp_pubkey(&self) -> PublicKey {
        self.pubkey
    }

    fn get_lsp_connection_string(&self) -> String {
        self.connection_string.clone()
    }

    fn get_config(&self) -> LspConfig {
        LspConfig::LspsFlow(LspsConfig {
            connection_string: self.get_lsp_connection_string(),
            token: self.token.clone(),
        })
    }

    fn get_expected_skimmed_fee_msat(&self, payment_hash: PaymentHash, payment_size: u64) -> u64 {
        let mut pending_payments = self.pending_payments.lock().unwrap();
        let pending_payment = pending_payments.get_mut(&payment_hash).unwrap();

        if let Some(expected_fee_msat) = pending_payment.expected_fee_msat {
            return expected_fee_msat;
        }

        compute_opening_fee(
            payment_size,
            pending_payment.fee_params.min_fee_msat,
            pending_payment.fee_params.proportional.into(),
        )
        .unwrap_or(0)
    }
}
