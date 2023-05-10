use crate::fees::P2WSH_OUTPUT_SIZE;
use crate::keymanager::PhantomKeysManager;
use crate::labels::LabelStorage;
use crate::ldkstorage::ChannelOpenParams;
use crate::{
    background::process_events_async,
    chain::MutinyChain,
    error::{MutinyError, MutinyStorageError},
    event::{EventHandler, HTLCStatus, MillisatAmount, PaymentInfo},
    fees::MutinyFeeEstimator,
    gossip::{get_all_peers, read_peer_info, save_peer_connection_info},
    keymanager::{create_keys_manager, pubkey_from_keys_manager},
    ldkstorage::{MutinyNodePersister, PhantomChannelManager},
    logging::MutinyLogger,
    lspclient::LspClient,
    nodemanager::{MutinyInvoice, NodeIndex},
    onchain::OnChainWallet,
    peermanager::{GossipMessageHandler, PeerManager, PeerManagerImpl},
    proxy::WsProxy,
    socket::{
        schedule_descriptor_read, MultiWsSocketDescriptor, WsSocketDescriptor,
        WsTcpSocketDescriptor,
    },
    utils::{self, sleep},
};
use crate::{indexed_db::MutinyStorage, lspclient::FeeRequest};
use anyhow::{anyhow, Context};
use bdk_esplora::esplora_client::AsyncClient;
use bip39::Mnemonic;
use bitcoin::hashes::{hex::ToHex, sha256::Hash as Sha256};
use bitcoin::secp256k1::rand;
use bitcoin::{hashes::Hash, secp256k1::PublicKey, Network, OutPoint};
use lightning::chain::chaininterface::{ConfirmationTarget, FeeEstimator};
use lightning::ln::channelmanager::RecipientOnionFields;
use lightning::{
    chain::{
        chainmonitor,
        keysinterface::{EntropySource, InMemorySigner},
        Filter, Watch,
    },
    ln::{
        channelmanager::{PaymentId, PhantomRouteHints, Retry},
        msgs::NetAddress,
        peer_handler::{
            IgnoringMessageHandler, MessageHandler as LdkMessageHandler,
            SocketDescriptor as LdkSocketDescriptor,
        },
        PaymentHash, PaymentPreimage,
    },
    log_debug, log_error, log_info, log_trace, log_warn,
    routing::{
        gossip,
        gossip::NodeId,
        router::{DefaultRouter, PaymentParameters, RouteParameters},
        scoring::ProbabilisticScorer,
    },
    util::{
        config::{ChannelHandshakeConfig, ChannelHandshakeLimits, UserConfig},
        logger::Logger,
        ser::Writeable,
    },
};
use lightning_invoice::{
    payment::{pay_invoice, pay_zero_value_invoice},
    utils::{create_invoice_from_channelmanager_and_duration_since_epoch, create_phantom_invoice},
    Invoice,
};
use std::{
    net::SocketAddr,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
};
use wasm_bindgen_futures::spawn_local;

const DEFAULT_PAYMENT_TIMEOUT: u64 = 30;

pub(crate) type RapidGossipSync =
    lightning_rapid_gossip_sync::RapidGossipSync<Arc<NetworkGraph>, Arc<MutinyLogger>>;

pub(crate) type NetworkGraph = gossip::NetworkGraph<Arc<MutinyLogger>>;

pub(crate) type MessageHandler = LdkMessageHandler<
    Arc<PhantomChannelManager>,
    Arc<GossipMessageHandler>,
    Arc<IgnoringMessageHandler>,
>;

pub(crate) type ChainMonitor = chainmonitor::ChainMonitor<
    InMemorySigner,
    Arc<dyn Filter + Send + Sync>,
    Arc<MutinyChain>,
    Arc<MutinyFeeEstimator>,
    Arc<MutinyLogger>,
    Arc<MutinyNodePersister>,
>;

pub(crate) type Router =
    DefaultRouter<Arc<NetworkGraph>, Arc<MutinyLogger>, Arc<utils::Mutex<ProbScorer>>>;

pub(crate) type ProbScorer = ProbabilisticScorer<Arc<NetworkGraph>, Arc<MutinyLogger>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ConnectionType {
    Tcp(String),
    Mutiny(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PubkeyConnectionInfo {
    pub pubkey: PublicKey,
    pub connection_type: ConnectionType,
    pub original_connection_string: String,
}

impl PubkeyConnectionInfo {
    pub fn new(connection: &str) -> Result<Self, MutinyError> {
        if connection.is_empty() {
            return Err(MutinyError::PeerInfoParseFailed)
                .context("connect_peer requires peer connection info")?;
        };
        let connection = connection.to_lowercase();
        if connection.starts_with("mutiny:") {
            let stripped_connection = connection.strip_prefix("mutiny:").expect("should strip");
            let (pubkey, peer_addr_str) = split_peer_connection_string(stripped_connection)?;
            Ok(Self {
                pubkey,
                connection_type: ConnectionType::Mutiny(peer_addr_str),
                original_connection_string: connection.to_string(),
            })
        } else {
            let (pubkey, peer_addr_str) = parse_peer_info(&connection)?;
            Ok(Self {
                pubkey,
                connection_type: ConnectionType::Tcp(peer_addr_str),
                original_connection_string: connection,
            })
        }
    }
}

pub(crate) struct Node {
    pub _uuid: String,
    pub child_index: u32,
    stopped_components: Arc<RwLock<Vec<bool>>>,
    pub pubkey: PublicKey,
    pub peer_manager: Arc<dyn PeerManager>,
    pub keys_manager: Arc<PhantomKeysManager>,
    pub channel_manager: Arc<PhantomChannelManager>,
    pub chain_monitor: Arc<ChainMonitor>,
    network: Network,
    pub persister: Arc<MutinyNodePersister>,
    wallet: Arc<OnChainWallet>,
    logger: Arc<MutinyLogger>,
    websocket_proxy_addr: String,
    multi_socket: MultiWsSocketDescriptor,
    pub(crate) lsp_client: Option<LspClient>,
}

impl Node {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn new(
        uuid: String,
        node_index: &NodeIndex,
        stop: Arc<AtomicBool>,
        mnemonic: &Mnemonic,
        storage: MutinyStorage,
        gossip_sync: Arc<RapidGossipSync>,
        scorer: Arc<utils::Mutex<ProbScorer>>,
        chain: Arc<MutinyChain>,
        fee_estimator: Arc<MutinyFeeEstimator>,
        wallet: Arc<OnChainWallet>,
        network: Network,
        websocket_proxy_addr: String,
        esplora: Arc<AsyncClient>,
        lsp_clients: &[LspClient],
        logger: Arc<MutinyLogger>,
    ) -> Result<Self, MutinyError> {
        log_info!(logger, "initialized a new node: {uuid}");

        // a list of components that need to be stopped and whether or not they are stopped
        let stopped_components = Arc::new(RwLock::new(vec![]));

        let keys_manager = Arc::new(create_keys_manager(
            wallet.clone(),
            mnemonic,
            node_index.child_index,
        )?);
        let pubkey = pubkey_from_keys_manager(&keys_manager);

        // init the persister
        let persister = Arc::new(MutinyNodePersister::new(uuid.clone(), storage));

        // init chain monitor
        let chain_monitor: Arc<ChainMonitor> = Arc::new(ChainMonitor::new(
            Some(chain.tx_sync.clone()),
            chain.clone(),
            logger.clone(),
            fee_estimator.clone(),
            persister.clone(),
        ));

        // read channelmonitor state from disk
        let channel_monitors = persister
            .read_channel_monitors(keys_manager.clone())
            .map_err(|e| MutinyError::ReadError {
                source: MutinyStorageError::Other(anyhow!("failed to read channel monitors: {e}")),
            })?;

        let network_graph = gossip_sync.network_graph().clone();

        let router: Arc<Router> = Arc::new(DefaultRouter::new(
            network_graph,
            logger.clone(),
            keys_manager.clone().get_secure_random_bytes(),
            scorer.clone(),
        ));

        // init channel manager
        let mut read_channel_manager = persister
            .read_channel_manager(
                network,
                chain_monitor.clone(),
                chain.clone(),
                fee_estimator.clone(),
                logger.clone(),
                keys_manager.clone(),
                router.clone(),
                channel_monitors,
                esplora,
            )
            .await?;

        let channel_manager: Arc<PhantomChannelManager> =
            Arc::new(read_channel_manager.channel_manager);

        let route_handler = Arc::new(GossipMessageHandler {
            network_graph: gossip_sync.network_graph().clone(),
            logger: logger.clone(),
        });

        // init peer manager
        let ln_msg_handler = MessageHandler {
            chan_handler: channel_manager.clone(),
            route_handler,
            onion_message_handler: Arc::new(IgnoringMessageHandler {}),
        };

        log_info!(logger, "creating lsp client");
        let lsp_client: Option<LspClient> = match node_index.lsp {
            None => {
                if lsp_clients.is_empty() {
                    log_info!(logger, "no lsp saved and no lsp clients available");
                    None
                } else {
                    log_info!(logger, "no lsp saved, picking random one");
                    // If we don't have an lsp saved we should pick a random
                    // one from our client list and save it for next time
                    let rand = rand::random::<usize>() % lsp_clients.len();
                    Some(lsp_clients[rand].clone())
                }
            }
            Some(ref lsp) => lsp_clients.iter().find(|c| &c.url == lsp).cloned(),
        };

        let lsp_client_pubkey = lsp_client.clone().map(|lsp| lsp.pubkey);

        // init event handler
        let event_handler = EventHandler::new(
            channel_manager.clone(),
            fee_estimator,
            wallet.clone(),
            keys_manager.clone(),
            persister.clone(),
            lsp_client_pubkey,
            logger.clone(),
        );
        let peer_man = Arc::new(create_peer_manager(
            keys_manager.clone(),
            ln_msg_handler,
            logger.clone(),
        ));

        // sync to chain tip
        if read_channel_manager.is_restarting {
            let mut chain_listener_channel_monitors = Vec::new();
            for (blockhash, channel_monitor) in read_channel_manager.channel_monitors.drain(..) {
                // Get channel monitor ready to sync
                channel_monitor.load_outputs_to_watch(&chain);

                let outpoint = channel_monitor.get_funding_txo().0;
                chain_listener_channel_monitors.push((
                    blockhash,
                    (
                        channel_monitor,
                        chain.clone(),
                        chain.clone(),
                        logger.clone(),
                    ),
                    outpoint,
                ));
            }

            // give channel monitors to chain monitor
            for item in chain_listener_channel_monitors.drain(..) {
                let channel_monitor = item.1 .0;
                let funding_outpoint = item.2;
                chain_monitor
                    .clone()
                    .watch_channel(funding_outpoint, channel_monitor);
            }
        }

        // Before we start the background processor, retry previously failed
        // spendable outputs. We should do this before we start the background
        // processor so we prevent any race conditions.
        // if we fail to read the spendable outputs, just log a warning and
        // continue
        let retry_spendable_outputs = persister
            .get_failed_spendable_outputs()
            .map_err(|e| MutinyError::ReadError {
                source: MutinyStorageError::Other(anyhow!(
                    "failed to read retry spendable outputs: {e}"
                )),
            })
            .unwrap_or_else(|e| {
                log_warn!(logger, "Failed to read retry spendable outputs: {e}");
                vec![]
            });

        if !retry_spendable_outputs.is_empty() {
            log_info!(
                logger,
                "Retrying {} spendable outputs",
                retry_spendable_outputs.len()
            );

            match event_handler
                .handle_spendable_outputs(&retry_spendable_outputs)
                .await
            {
                Ok(_) => {
                    log_info!(logger, "Successfully retried spendable outputs");
                    persister.clear_failed_spendable_outputs().await?;
                }
                Err(e) => log_warn!(logger, "Failed to retry spendable outputs {e}"),
            }
        }

        let background_persister = persister.clone();
        let background_event_handler = event_handler.clone();
        let background_processor_logger = logger.clone();
        let background_processor_peer_manager = peer_man.clone();
        let background_processor_channel_manager = channel_manager.clone();
        let background_chain_monitor = chain_monitor.clone();
        let background_gossip_sync = gossip_sync.clone();
        let background_logger = logger.clone();
        let background_stop = stop.clone();
        stopped_components.try_write()?.push(false);
        let background_stopped_components = stopped_components.clone();
        spawn_local(async move {
            loop {
                let gs = crate::background::GossipSync::rapid(background_gossip_sync.clone());
                let ev = background_event_handler.clone();
                process_events_async(
                    background_persister.clone(),
                    |e| ev.handle_event(e),
                    background_chain_monitor.clone(),
                    background_processor_channel_manager.clone(),
                    gs,
                    background_processor_peer_manager.clone(),
                    background_processor_logger.clone(),
                    Some(scorer.clone()),
                    |d| {
                        let background_event_stop = background_stop.clone();
                        Box::pin(async move {
                            sleep(d.as_millis() as i32).await;
                            background_event_stop.load(Ordering::Relaxed)
                        })
                    },
                    true,
                )
                .await
                .expect("Failed to process events");

                if background_stop.load(Ordering::Relaxed) {
                    log_debug!(
                        background_logger,
                        "stopping background component for node: {}",
                        pubkey.to_hex(),
                    );
                    stop_component(&background_stopped_components);
                    log_debug!(
                        background_logger,
                        "stopped background component for node: {}",
                        pubkey.to_hex()
                    );
                    break;
                }
            }
        });

        // create a connection immediately to the user's
        // specified mutiny websocket proxy provider.
        let self_connection = PubkeyConnectionInfo {
            pubkey,
            connection_type: ConnectionType::Mutiny(websocket_proxy_addr.to_string()),
            original_connection_string: format!("mutiny:{pubkey}@{websocket_proxy_addr}"),
        };
        let main_proxy = WsProxy::new(
            &websocket_proxy_addr,
            self_connection.clone(),
            logger.clone(),
        )
        .await?;
        let multi_socket = MultiWsSocketDescriptor::new(
            Arc::new(main_proxy),
            peer_man.clone(),
            pubkey.serialize().to_vec(),
            stop.clone(),
        );
        multi_socket.listen();

        start_reconnection_handling(
            pubkey,
            &multi_socket,
            websocket_proxy_addr.clone(),
            self_connection,
            peer_man.clone(),
            &logger,
            uuid.clone(),
            &lsp_client,
            stop.clone(),
            stopped_components.clone(),
        )
        .await?;

        Ok(Node {
            _uuid: uuid,
            stopped_components,
            child_index: node_index.child_index,
            pubkey,
            peer_manager: peer_man,
            keys_manager,
            channel_manager,
            chain_monitor,
            network,
            persister,
            wallet,
            logger,
            websocket_proxy_addr,
            multi_socket,
            lsp_client,
        })
    }

    /// stopped will await until the node is fully shut down
    pub async fn stopped(&self) -> Result<(), MutinyError> {
        loop {
            let all_stopped = {
                let stopped_components = self
                    .stopped_components
                    .try_read()
                    .map_err(|_| MutinyError::NotRunning)?;
                stopped_components.iter().all(|&x| x)
            };

            if all_stopped {
                break;
            }

            sleep(500).await;
        }
        Ok(())
    }

    pub fn node_index(&self) -> NodeIndex {
        NodeIndex {
            child_index: self.child_index,
            lsp: self.lsp_client.clone().map(|l| l.url),
            archived: Some(false),
        }
    }

    pub async fn connect_peer(
        &self,
        peer_connection_info: PubkeyConnectionInfo,
        label: Option<String>,
    ) -> Result<(), MutinyError> {
        match connect_peer_if_necessary(
            self.multi_socket.clone(),
            &self.websocket_proxy_addr,
            &peer_connection_info,
            self.logger.clone(),
            self.peer_manager.clone(),
        )
        .await
        {
            Ok(_) => {
                let node_id = NodeId::from_pubkey(&peer_connection_info.pubkey);

                // if we have the connection info saved in storage, update it if we need to
                // otherwise cache it in temp_peer_connection_map so we can later save it
                // if we open a channel in the future.
                if let Some(saved) = read_peer_info(&node_id)
                    .await?
                    .and_then(|p| p.connection_string)
                {
                    if saved != peer_connection_info.original_connection_string {
                        match save_peer_connection_info(
                            &self._uuid,
                            &node_id,
                            &peer_connection_info.original_connection_string,
                            label,
                        )
                        .await
                        {
                            Ok(_) => (),
                            Err(_) => {
                                log_warn!(self.logger, "WARN: could not store peer connection info")
                            }
                        }
                    }
                } else {
                    // store this so we can reconnect later
                    if let Err(e) = save_peer_connection_info(
                        &self._uuid,
                        &node_id,
                        &peer_connection_info.original_connection_string,
                        label,
                    )
                    .await
                    {
                        log_warn!(
                            self.logger,
                            "WARN: could not store peer connection info: {e}"
                        );
                    }
                }

                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn disconnect_peer(&self, peer_id: PublicKey) {
        self.peer_manager.disconnect_by_node_id(peer_id);
    }

    pub fn get_phantom_route_hint(&self) -> PhantomRouteHints {
        self.channel_manager.get_phantom_route_hints()
    }

    pub async fn create_invoice(
        &self,
        amount_sat: Option<u64>,
        labels: Vec<String>,
        route_hints: Option<Vec<PhantomRouteHints>>,
    ) -> Result<Invoice, MutinyError> {
        // the amount to create for the invoice whether or not there is an lsp
        let (amount_sat, lsp_fee_msat) = if let Some(lsp) = self.lsp_client.clone() {
            // LSP requires an amount:
            let amount_sat = amount_sat.ok_or(MutinyError::BadAmountError)?;

            // Needs any amount over 0 if channel exists
            // Needs amount over 10k if no channel
            let has_usable_channel = self
                .channel_manager
                .list_channels_with_counterparty(&lsp.pubkey)
                .iter()
                .any(|c| c.inbound_capacity_msat >= amount_sat * 1000);
            let min_amount_sat = if has_usable_channel { 1 } else { 10_000 };
            if amount_sat < min_amount_sat {
                return Err(MutinyError::BadAmountError);
            }

            // check the fee from the LSP
            let lsp_fee_msat = lsp
                .get_lsp_fee_msat(FeeRequest {
                    pubkey: self.pubkey.to_hex(),
                    amount_msat: amount_sat * 1000,
                })
                .await?;
            let amount_minus_fee = amount_sat
                .checked_sub(lsp_fee_msat / 1000)
                .ok_or(MutinyError::BadAmountError)?;
            (Some(amount_minus_fee), Some(lsp_fee_msat))
        } else {
            (amount_sat, None)
        };

        let invoice = self
            .create_internal_invoice(amount_sat, lsp_fee_msat, labels, route_hints)
            .await?;

        if let Some(lsp) = self.lsp_client.clone() {
            self.connect_peer(PubkeyConnectionInfo::new(&lsp.connection_string)?, None)
                .await?;
            let lsp_invoice_str = lsp.get_lsp_invoice(invoice.to_string()).await?;
            let lsp_invoice = Invoice::from_str(&lsp_invoice_str)?;

            if invoice.network() != self.network {
                return Err(MutinyError::IncorrectNetwork(invoice.network()));
            }

            if lsp_invoice.payment_hash() != invoice.payment_hash()
                || lsp_invoice.recover_payee_pub_key() != lsp.pubkey
            {
                return Err(MutinyError::InvoiceCreationFailed);
            }

            Ok(lsp_invoice)
        } else {
            Ok(invoice)
        }
    }

    async fn create_internal_invoice(
        &self,
        amount_sat: Option<u64>,
        fee_amount_msat: Option<u64>,
        labels: Vec<String>,
        route_hints: Option<Vec<PhantomRouteHints>>,
    ) -> Result<Invoice, MutinyError> {
        let amount_msat = amount_sat.map(|s| s * 1_000);
        // Set description to empty string to make smallest possible invoice/QR code
        let description = "".to_string();
        let invoice_res = match route_hints {
            None => {
                let now = crate::utils::now();
                create_invoice_from_channelmanager_and_duration_since_epoch(
                    &self.channel_manager.clone(),
                    self.keys_manager.clone(),
                    self.logger.clone(),
                    self.network.into(),
                    amount_msat,
                    description,
                    now,
                    1500,
                    Some(40),
                )
            }
            Some(r) => create_phantom_invoice::<
                Arc<PhantomKeysManager>,
                Arc<PhantomKeysManager>,
                Arc<MutinyLogger>,
            >(
                amount_msat,
                None,
                description,
                1500,
                r,
                self.keys_manager.clone(),
                self.keys_manager.clone(),
                self.logger.clone(),
                self.network.into(),
                Some(40),
                crate::utils::now(),
            ),
        };
        let invoice = invoice_res.map_err(|e| {
            log_error!(self.logger, "ERROR: could not generate invoice: {e}");
            MutinyError::InvoiceCreationFailed
        })?;

        let last_update = crate::utils::now().as_secs();
        let payment_hash = PaymentHash(invoice.payment_hash().into_inner());
        let payment_info = PaymentInfo {
            preimage: None,
            secret: Some(invoice.payment_secret().0),
            status: HTLCStatus::Pending,
            amt_msat: MillisatAmount(amount_msat),
            fee_paid_msat: fee_amount_msat,
            bolt11: Some(invoice.clone()),
            payee_pubkey: None,
            last_update,
        };
        self.persister
            .persist_payment_info(&payment_hash, &payment_info, true)
            .map_err(|e| {
                log_error!(self.logger, "ERROR: could not persist payment info: {e}");
                MutinyError::InvoiceCreationFailed
            })?;

        self.persister
            .storage
            .set_invoice_labels(invoice.clone(), labels)?;

        log_info!(self.logger, "SUCCESS: generated invoice: {invoice}");

        Ok(invoice)
    }

    pub fn get_invoice(&self, invoice: &Invoice) -> Result<MutinyInvoice, MutinyError> {
        let payment_hash = invoice.payment_hash();
        let (payment_info, inbound) = self.get_payment_info_from_persisters(payment_hash)?;
        let labels_map = self.persister.storage.get_invoice_labels()?;
        let labels = labels_map.get(invoice).cloned().unwrap_or_default();
        MutinyInvoice::from(
            payment_info,
            PaymentHash(payment_hash.into_inner()),
            inbound,
            labels,
        )
    }

    pub fn list_invoices(&self) -> Result<Vec<MutinyInvoice>, MutinyError> {
        let mut inbound_invoices = self.list_payment_info_from_persisters(true)?;
        let mut outbound_invoices = self.list_payment_info_from_persisters(false)?;
        inbound_invoices.append(&mut outbound_invoices);
        Ok(inbound_invoices)
    }

    fn list_payment_info_from_persisters(
        &self,
        inbound: bool,
    ) -> Result<Vec<MutinyInvoice>, MutinyError> {
        let now = utils::now();
        let labels_map = self.persister.storage.get_invoice_labels()?;

        Ok(self
            .persister
            .list_payment_info(inbound)?
            .into_iter()
            .filter_map(|(h, i)| {
                let labels = match i.bolt11.clone() {
                    None => vec![],
                    Some(i) => labels_map.get(&i).cloned().unwrap_or_default(),
                };
                let mutiny_invoice = MutinyInvoice::from(i.clone(), h, inbound, labels).ok();

                // filter out expired invoices
                mutiny_invoice.filter(|invoice| {
                    !invoice.bolt11.as_ref().is_some_and(|b| b.would_expire(now))
                        || matches!(i.status, HTLCStatus::Succeeded | HTLCStatus::InFlight)
                })
            })
            .collect())
    }

    fn get_payment_info_from_persisters(
        &self,
        payment_hash: &bitcoin::hashes::sha256::Hash,
    ) -> Result<(PaymentInfo, bool), MutinyError> {
        // try inbound first
        let payment_hash = PaymentHash(payment_hash.into_inner());
        if let Some(payment_info) =
            self.persister
                .read_payment_info(&payment_hash, true, self.logger.clone())
        {
            return Ok((payment_info, true));
        }

        // if no inbound check outbound
        match self
            .persister
            .read_payment_info(&payment_hash, false, self.logger.clone())
        {
            Some(payment_info) => Ok((payment_info, false)),
            None => Err(MutinyError::InvoiceInvalid),
        }
    }

    /// init_invoice_payment sends off the payment but does not wait for results
    /// use pay_invoice_with_timeout to wait for results
    pub fn init_invoice_payment(
        &self,
        invoice: &Invoice,
        amt_sats: Option<u64>,
        labels: Vec<String>,
    ) -> Result<PaymentHash, MutinyError> {
        let (pay_result, amt_msat) = if invoice.amount_milli_satoshis().is_none() {
            if amt_sats.is_none() {
                return Err(MutinyError::InvoiceInvalid);
            }
            let amt_msats = amt_sats.unwrap() * 1_000;
            (
                pay_zero_value_invoice(
                    invoice,
                    amt_msats,
                    Retry::Attempts(5),
                    self.channel_manager.as_ref(),
                ),
                amt_msats,
            )
        } else {
            if amt_sats.is_some() {
                return Err(MutinyError::InvoiceInvalid);
            }
            (
                pay_invoice(invoice, Retry::Attempts(5), self.channel_manager.as_ref()),
                invoice.amount_milli_satoshis().unwrap(),
            )
        };

        if let Err(e) = self
            .persister
            .storage
            .set_invoice_labels(invoice.clone(), labels)
        {
            log_error!(self.logger, "could not set invoice label: {e}");
        }

        let last_update = utils::now().as_secs();
        let mut payment_info = PaymentInfo {
            preimage: None,
            secret: None,
            status: HTLCStatus::InFlight,
            amt_msat: MillisatAmount(Some(amt_msat)),
            fee_paid_msat: None,
            bolt11: Some(invoice.clone()),
            payee_pubkey: None,
            last_update,
        };

        let payment_hash = PaymentHash(invoice.payment_hash().into_inner());
        self.persister
            .persist_payment_info(&payment_hash, &payment_info, false)?;

        match pay_result {
            Ok(_) => Ok(payment_hash),
            Err(e) => {
                log_error!(self.logger, "failed to make payment: {:?}", e);
                // call list channels to see what our channels are
                let current_channels = self.channel_manager.list_channels();
                log_debug!(
                    self.logger,
                    "current channel details: {:?}",
                    current_channels
                );

                payment_info.status = HTLCStatus::Failed;
                self.persister
                    .persist_payment_info(&payment_hash, &payment_info, false)?;
                Err(MutinyError::RoutingFailed)
            }
        }
    }

    async fn await_payment(
        &self,
        payment_hash: PaymentHash,
        timeout: u64,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        let start = utils::now().as_secs();
        loop {
            let now = utils::now().as_secs();
            if now - start > timeout {
                return Err(MutinyError::PaymentTimeout);
            }

            let payment_info =
                self.persister
                    .read_payment_info(&payment_hash, false, self.logger.clone());

            if let Some(info) = payment_info {
                match info.status {
                    HTLCStatus::Succeeded => {
                        let mutiny_invoice =
                            MutinyInvoice::from(info, payment_hash, false, labels)?;
                        return Ok(mutiny_invoice);
                    }
                    HTLCStatus::Failed => return Err(MutinyError::RoutingFailed),
                    _ => {}
                }
            }

            sleep(250).await;
        }
    }

    pub async fn pay_invoice_with_timeout(
        &self,
        invoice: &Invoice,
        amt_sats: Option<u64>,
        timeout_secs: Option<u64>,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        // initiate payment
        let payment_hash = self.init_invoice_payment(invoice, amt_sats, labels.clone())?;
        let timeout: u64 = timeout_secs.unwrap_or(DEFAULT_PAYMENT_TIMEOUT);

        self.await_payment(payment_hash, timeout, labels).await
    }

    /// init_keysend_payment sends off the payment but does not wait for results
    /// use keysend_with_timeout to wait for results
    pub fn init_keysend_payment(
        &self,
        to_node: PublicKey,
        amt_sats: u64,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy).map_err(|_| MutinyError::SeedGenerationFailed)?;
        let payment_id = PaymentId(entropy);

        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy).map_err(|_| MutinyError::SeedGenerationFailed)?;
        let preimage = PaymentPreimage(entropy);

        let amt_msats = amt_sats * 1000;

        let payment_params = PaymentParameters::for_keysend(to_node, 40);
        let route_params: RouteParameters = RouteParameters {
            final_value_msat: amt_msats,
            payment_params,
        };

        let pay_result = self.channel_manager.send_spontaneous_payment_with_retry(
            Some(preimage),
            RecipientOnionFields::spontaneous_empty(),
            payment_id,
            route_params,
            Retry::Attempts(5),
        );

        let payment_hash = PaymentHash(Sha256::hash(&preimage.0).into_inner());

        let last_update = utils::now().as_secs();
        let mut payment_info = PaymentInfo {
            preimage: Some(preimage.0),
            secret: None,
            status: HTLCStatus::InFlight,
            amt_msat: MillisatAmount(Some(amt_msats)),
            fee_paid_msat: None,
            bolt11: None,
            payee_pubkey: Some(to_node),
            last_update,
        };

        self.persister
            .persist_payment_info(&payment_hash, &payment_info, false)?;

        match pay_result {
            Ok(_) => {
                let mutiny_invoice =
                    MutinyInvoice::from(payment_info, payment_hash, false, labels)?;
                Ok(mutiny_invoice)
            }
            Err(_) => {
                payment_info.status = HTLCStatus::Failed;
                self.persister
                    .persist_payment_info(&payment_hash, &payment_info, false)?;
                Err(MutinyError::RoutingFailed)
            }
        }
    }

    pub async fn keysend_with_timeout(
        &self,
        to_node: PublicKey,
        amt_sats: u64,
        labels: Vec<String>,
        timeout_secs: Option<u64>,
    ) -> Result<MutinyInvoice, MutinyError> {
        // initiate payment
        let pay = self.init_keysend_payment(to_node, amt_sats, labels.clone())?;

        let timeout: u64 = timeout_secs.unwrap_or(DEFAULT_PAYMENT_TIMEOUT);
        let payment_hash = PaymentHash(pay.payment_hash.into_inner());

        self.await_payment(payment_hash, timeout, labels).await
    }

    pub async fn open_channel(
        &self,
        pubkey: PublicKey,
        amount_sat: u64,
    ) -> Result<[u8; 32], MutinyError> {
        let mut config = default_user_config();

        // if we are opening channel to LSP, turn off SCID alias until CLN is updated
        // LSP protects all invoice information anyways, so no UTXO leakage
        if let Some(lsp) = self.lsp_client.clone() {
            if pubkey == lsp.pubkey {
                config.channel_handshake_config.negotiate_scid_privacy = false;
            }
        }

        match self
            .channel_manager
            .create_channel(pubkey, amount_sat, 0, 0, Some(config))
        {
            Ok(res) => {
                log_info!(
                    self.logger,
                    "SUCCESS: channel initiated with peer: {pubkey:?}"
                );
                Ok(res)
            }
            Err(e) => {
                log_error!(
                    self.logger,
                    "ERROR: failed to open channel to pubkey {pubkey:?}: {e:?}"
                );
                Err(MutinyError::ChannelCreationFailed)
            }
        }
    }

    pub async fn sweep_utxos_to_channel(
        &self,
        user_chan_id: Option<u128>,
        utxos: &[OutPoint],
        pubkey: PublicKey,
    ) -> Result<[u8; 32], MutinyError> {
        // Calculate the total value of the selected utxos
        let utxo_value: u64 = {
            // find the wallet utxos
            let wallet = self.wallet.wallet.try_read()?;
            let all_utxos = wallet.list_unspent();

            // calculate total value of utxos
            let mut total = 0;
            for utxo in all_utxos {
                if utxos.contains(&utxo.outpoint) {
                    total += utxo.txout.value;
                }
            }
            total
        };

        let sats_per_kw = self
            .wallet
            .fees
            .get_est_sat_per_1000_weight(ConfirmationTarget::Normal);
        // Calculate the expected transaction fee
        let expected_fee = self.wallet.fees.calculate_expected_fee(
            utxos.len(),
            P2WSH_OUTPUT_SIZE,
            None,
            Some(sats_per_kw),
        );

        // channel size is the total value of the utxos minus the fee
        let channel_value_satoshis = utxo_value - expected_fee;

        let mut config = default_user_config();
        // if we are opening channel to LSP, turn off SCID alias until CLN is updated
        // LSP protects all invoice information anyways, so no UTXO leakage
        if let Some(lsp) = self.lsp_client.clone() {
            if pubkey == lsp.pubkey {
                config.channel_handshake_config.negotiate_scid_privacy = false;
            }
        }

        let user_channel_id = user_chan_id.unwrap_or_else(|| {
            // generate random user channel id
            let mut user_channel_id_bytes = [0u8; 16];
            getrandom::getrandom(&mut user_channel_id_bytes).unwrap();
            u128::from_be_bytes(user_channel_id_bytes)
        });

        // save params to db
        let params = ChannelOpenParams {
            sats_per_kw,
            utxos: utxos.to_vec(),
            labels: None,
        };
        self.persister
            .persist_channel_open_params(user_channel_id, params)?;

        match self.channel_manager.create_channel(
            pubkey,
            channel_value_satoshis,
            0,
            user_channel_id,
            Some(config),
        ) {
            Ok(res) => {
                log_info!(
                    self.logger,
                    "SUCCESS: channel initiated with peer: {pubkey:?}"
                );
                Ok(res)
            }
            Err(e) => {
                log_error!(
                    self.logger,
                    "ERROR: failed to open channel to pubkey {pubkey:?}: {e:?}"
                );
                // delete params from db because channel failed
                self.persister.delete_channel_open_params(user_channel_id)?;
                Err(MutinyError::ChannelCreationFailed)
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn start_reconnection_handling(
    node_pubkey: PublicKey,
    multi_socket: &MultiWsSocketDescriptor,
    websocket_proxy_addr: String,
    self_connection: PubkeyConnectionInfo,
    peer_man: Arc<dyn PeerManager>,
    logger: &Arc<MutinyLogger>,
    uuid: String,
    lsp_client: &Option<LspClient>,
    stop: Arc<AtomicBool>,
    stopped_components: Arc<RwLock<Vec<bool>>>,
) -> Result<(), MutinyError> {
    // Attempt connection to LSP first
    if let Some(lsp) = lsp_client.clone() {
        let node_id = NodeId::from_pubkey(&lsp.pubkey);

        match connect_peer_if_necessary(
            multi_socket.clone(),
            &websocket_proxy_addr,
            &PubkeyConnectionInfo::new(lsp.connection_string.as_str())?,
            logger.clone(),
            peer_man.clone(),
        )
        .await
        {
            Ok(_) => {
                log_trace!(logger, "auto connected lsp: {node_id}");
            }
            Err(e) => {
                log_trace!(logger, "could not connect to lsp {node_id}: {e}");
            }
        }

        if let Err(e) =
            save_peer_connection_info(&uuid, &node_id, &lsp.connection_string, None).await
        {
            log_error!(logger, "could not save connection to lsp: {e}");
        }
    };

    let mut multi_socket_reconnect = multi_socket.clone();
    let websocket_proxy_addr_copy = websocket_proxy_addr.clone();
    let self_connection_copy = self_connection.clone();
    let reconnection_stop = stop.clone();
    let reconnection_logger = logger.clone();
    stopped_components.try_write()?.push(false);
    let reconnection_stopped_components = stopped_components.clone();
    spawn_local(async move {
        loop {
            // run through reconnection logic every 5 seconds,
            // check if it should stop once every second.
            for _ in 0..5 {
                if reconnection_stop.load(Ordering::Relaxed) {
                    log_debug!(
                        reconnection_logger,
                        "stopping reconnection component for node: {}",
                        node_pubkey.to_hex(),
                    );
                    stop_component(&reconnection_stopped_components);
                    log_debug!(
                        reconnection_logger,
                        "stopped reconnection component for node: {}",
                        node_pubkey.to_hex(),
                    );
                    return;
                }
                sleep(1_000).await;
            }

            if !multi_socket_reconnect.connected() {
                log_debug!(
                    reconnection_logger,
                    "got disconnected from multi socket proxy, going to reconnect"
                );
                match WsProxy::new(
                    &websocket_proxy_addr_copy,
                    self_connection_copy.clone(),
                    reconnection_logger.clone(),
                )
                .await
                {
                    Ok(main_proxy) => {
                        multi_socket_reconnect.reconnect(Arc::new(main_proxy)).await;
                    }
                    Err(e) => {
                        log_error!(
                            reconnection_logger,
                            "could not create new multi socket proxy: {e}",
                        );
                    }
                };
            } else {
                // send a keep alive message if connected
                multi_socket_reconnect.attempt_keep_alive();
            }
        }
    });

    let connect_peer_man = peer_man.clone();
    let connect_proxy = websocket_proxy_addr.clone();
    let connect_logger = logger.clone();
    let connect_multi_socket = multi_socket.clone();
    let connect_uuid = uuid.clone();
    let connect_stop = stop.clone();
    stopped_components.try_write()?.push(false);
    let connect_stopped_components = stopped_components.clone();
    spawn_local(async move {
        loop {
            for _ in 0..5 {
                if connect_stop.load(Ordering::Relaxed) {
                    log_debug!(
                        connect_logger,
                        "stopping connection component and disconnecting peers for node: {}",
                        node_pubkey.to_hex(),
                    );
                    connect_peer_man.disconnect_all_peers();
                    stop_component(&connect_stopped_components);
                    log_debug!(
                        connect_logger,
                        "stopped connection component and disconnected peers for node: {}",
                        node_pubkey.to_hex(),
                    );
                    break;
                }
                sleep(1_000).await;
            }

            // if we aren't connected to master socket then skip
            // this is either an indication that there's a network issue or another instance of the
            // same node is already connected (we do checking server side), in which case we probably
            // shouldn't connect to the same peers again anyways.
            if !connect_multi_socket.connected() {
                continue;
            }

            let peer_connections = get_all_peers().await.unwrap_or_default();
            let current_connections = connect_peer_man.get_peer_node_ids();

            let not_connected: Vec<(NodeId, String)> = peer_connections
                .into_iter()
                .filter(|(_, d)| {
                    d.connection_string.is_some()
                        && d.nodes.binary_search(&connect_uuid.to_string()).is_ok()
                })
                .map(|(n, d)| (n, d.connection_string.unwrap()))
                .filter(|(n, _)| {
                    !current_connections
                        .iter()
                        .any(|c| &NodeId::from_pubkey(c) == n)
                })
                .collect();

            for (pubkey, conn_str) in not_connected.into_iter() {
                log_trace!(connect_logger, "going to auto connect to peer: {pubkey}");
                let peer_connection_info = match PubkeyConnectionInfo::new(&conn_str) {
                    Ok(p) => p,
                    Err(e) => {
                        log_error!(connect_logger, "could not parse connection info: {e}");
                        continue;
                    }
                };

                match connect_peer_if_necessary(
                    connect_multi_socket.clone(),
                    &connect_proxy,
                    &peer_connection_info,
                    connect_logger.clone(),
                    connect_peer_man.clone(),
                )
                .await
                {
                    Ok(_) => {
                        log_trace!(connect_logger, "auto connected peer: {pubkey}");
                    }
                    Err(e) => {
                        log_warn!(connect_logger, "could not auto connect peer: {e}");
                    }
                }
            }
        }
    });
    Ok(())
}

fn stop_component(stopped_components: &Arc<RwLock<Vec<bool>>>) {
    let mut stopped = stopped_components
        .try_write()
        .expect("can write to stopped components");
    if let Some(first_false) = stopped.iter_mut().find(|x| !**x) {
        *first_false = true;
    }
}

pub(crate) async fn connect_peer_if_necessary(
    multi_socket: MultiWsSocketDescriptor,
    websocket_proxy_addr: &str,
    peer_connection_info: &PubkeyConnectionInfo,
    logger: Arc<MutinyLogger>,
    peer_manager: Arc<dyn PeerManager>,
) -> Result<(), MutinyError> {
    if peer_manager
        .get_peer_node_ids()
        .contains(&peer_connection_info.pubkey)
    {
        Ok(())
    } else {
        connect_peer(
            multi_socket,
            websocket_proxy_addr,
            peer_connection_info,
            logger,
            peer_manager,
        )
        .await
    }
}

pub(crate) async fn connect_peer(
    multi_socket: MultiWsSocketDescriptor,
    websocket_proxy_addr: &str,
    peer_connection_info: &PubkeyConnectionInfo,
    logger: Arc<MutinyLogger>,
    peer_manager: Arc<dyn PeerManager>,
) -> Result<(), MutinyError> {
    // first make a connection to the node
    log_debug!(
        logger,
        "making connection to peer: {:?}",
        peer_connection_info
    );
    let (mut descriptor, socket_addr_opt) = match peer_connection_info.connection_type {
        ConnectionType::Tcp(ref t) => {
            let proxy = WsProxy::new(
                websocket_proxy_addr,
                peer_connection_info.clone(),
                logger.clone(),
            )
            .await?;
            (
                WsSocketDescriptor::Tcp(WsTcpSocketDescriptor::new(Arc::new(proxy))),
                try_get_net_addr_from_socket(t),
            )
        }
        ConnectionType::Mutiny(_) => (
            WsSocketDescriptor::Mutiny(
                multi_socket
                    .create_new_subsocket(peer_connection_info.pubkey.encode())
                    .await,
            ),
            None,
        ),
    };

    // then give that connection to the peer manager
    let initial_bytes = peer_manager.new_outbound_connection(
        peer_connection_info.pubkey,
        descriptor.clone(),
        socket_addr_opt,
    )?;
    log_debug!(logger, "connected to peer: {:?}", peer_connection_info);

    let sent_bytes = descriptor.send_data(&initial_bytes, true);
    log_trace!(
        logger,
        "sent {sent_bytes} to node: {}",
        peer_connection_info.pubkey
    );

    // schedule a reader on the connection
    schedule_descriptor_read(descriptor, peer_manager.clone());

    Ok(())
}

fn try_get_net_addr_from_socket(socket_addr: &str) -> Option<NetAddress> {
    socket_addr
        .parse::<SocketAddr>()
        .ok()
        .map(|socket_addr| match socket_addr {
            SocketAddr::V4(sockaddr) => NetAddress::IPv4 {
                addr: sockaddr.ip().octets(),
                port: sockaddr.port(),
            },
            SocketAddr::V6(sockaddr) => NetAddress::IPv6 {
                addr: sockaddr.ip().octets(),
                port: sockaddr.port(),
            },
        })
}

pub(crate) fn create_peer_manager(
    km: Arc<PhantomKeysManager>,
    lightning_msg_handler: MessageHandler,
    logger: Arc<MutinyLogger>,
) -> PeerManagerImpl {
    let now = crate::utils::now().as_secs();
    let mut ephemeral_bytes = [0u8; 32];
    getrandom::getrandom(&mut ephemeral_bytes).expect("Failed to generate entropy");

    PeerManagerImpl::new(
        lightning_msg_handler,
        now as u32,
        &ephemeral_bytes,
        logger,
        Arc::new(IgnoringMessageHandler {}),
        km,
    )
}

pub(crate) fn parse_peer_info(
    peer_pubkey_and_ip_addr: &str,
) -> Result<(PublicKey, String), MutinyError> {
    let (pubkey, peer_addr_str) = split_peer_connection_string(peer_pubkey_and_ip_addr)?;

    let peer_addr_str_with_port = if peer_addr_str.contains(':') {
        peer_addr_str
    } else {
        format!("{peer_addr_str}:9735")
    };

    Ok((pubkey, peer_addr_str_with_port))
}

pub(crate) fn split_peer_connection_string(
    peer_pubkey_and_ip_addr: &str,
) -> Result<(PublicKey, String), MutinyError> {
    let mut pubkey_and_addr = peer_pubkey_and_ip_addr.split('@');
    let pubkey = pubkey_and_addr
        .next()
        .ok_or_else(|| MutinyError::PeerInfoParseFailed)?;
    let peer_addr_str = pubkey_and_addr
        .next()
        .ok_or_else(|| MutinyError::PeerInfoParseFailed)?;
    let pubkey = PublicKey::from_str(pubkey).map_err(|_| MutinyError::PeerInfoParseFailed)?;
    Ok((pubkey, peer_addr_str.to_string()))
}

pub(crate) fn default_user_config() -> UserConfig {
    UserConfig {
        channel_handshake_limits: ChannelHandshakeLimits {
            // lnd's max to_self_delay is 2016, so we want to be compatible.
            their_to_self_delay: 2016,
            ..Default::default()
        },
        channel_handshake_config: ChannelHandshakeConfig {
            minimum_depth: 1,
            announced_channel: false,
            negotiate_scid_privacy: true,
            commit_upfront_shutdown_pubkey: false,
            max_inbound_htlc_value_in_flight_percent_of_channel: 100,
            ..Default::default()
        },
        manually_accept_inbound_channels: true,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::*;
    use bitcoin::secp256k1::PublicKey;
    use std::str::FromStr;

    use crate::node::parse_peer_info;

    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn test_parse_peer_info() {
        log!("test parse peer info");

        let pub_key = PublicKey::from_str(
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166",
        )
        .unwrap();
        let addr = "127.0.0.1:4000";

        let (peer_pubkey, peer_addr) = parse_peer_info(&format!("{pub_key}@{addr}")).unwrap();

        assert_eq!(pub_key, peer_pubkey);
        assert_eq!(addr, peer_addr);
    }

    #[test]
    async fn test_parse_peer_info_no_port() {
        log!("test parse peer info with no port");

        let pub_key = PublicKey::from_str(
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166",
        )
        .unwrap();
        let addr = "127.0.0.1";
        let port = "9735";

        let (peer_pubkey, peer_addr) = parse_peer_info(&format!("{pub_key}@{addr}")).unwrap();

        assert_eq!(pub_key, peer_pubkey);
        assert_eq!(format!("{addr}:{port}"), peer_addr);
    }
}
