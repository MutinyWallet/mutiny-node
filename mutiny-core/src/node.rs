use crate::labels::LabelStorage;
use crate::ldkstorage::{persist_monitor, ChannelOpenParams};
use crate::multiesplora::MultiEsploraClient;
use crate::nodemanager::ChannelClosure;
use crate::peermanager::LspMessageRouter;
use crate::scb::message_handler::SCBMessageHandler;
use crate::scb::StaticChannelBackup;
use crate::utils::get_monitor_version;
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
    utils::{self, sleep},
};
use crate::{fees::P2WSH_OUTPUT_SIZE, peermanager::connect_peer_if_necessary};
use crate::{keymanager::PhantomKeysManager, scorer::HubPreferentialScorer};
use crate::{lspclient::FeeRequest, storage::MutinyStorage};
use anyhow::{anyhow, Context};
use bdk::FeeRate;
use bitcoin::hashes::{hex::ToHex, sha256::Hash as Sha256};
use bitcoin::secp256k1::rand;
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::{hashes::Hash, secp256k1::PublicKey, BlockHash, Network, OutPoint};
use core::time::Duration;
use futures_util::lock::Mutex;
use lightning::chain::channelmonitor::ChannelMonitor;
use lightning::events::bump_transaction::{BumpTransactionEventHandler, Wallet};
use lightning::ln::PaymentSecret;
use lightning::onion_message::OnionMessenger as LdkOnionMessenger;
use lightning::sign::{EntropySource, InMemorySigner, NodeSigner, Recipient};
use lightning::util::config::MaxDustHTLCExposure;
use lightning::util::ser::{ReadableArgs, Writeable};
use lightning::{
    chain::{chainmonitor, Filter, Watch},
    ln::{
        channelmanager::{PaymentId, PhantomRouteHints, Retry},
        peer_handler::{IgnoringMessageHandler, MessageHandler as LdkMessageHandler},
        PaymentHash, PaymentPreimage,
    },
    log_debug, log_error, log_info, log_trace, log_warn,
    routing::{
        gossip,
        gossip::NodeId,
        router::{DefaultRouter, PaymentParameters, RouteParameters},
    },
    util::{
        config::{ChannelHandshakeConfig, ChannelHandshakeLimits, UserConfig},
        logger::Logger,
    },
};
use lightning::{
    ln::channelmanager::{RecipientOnionFields, RetryableSendFailure},
    routing::scoring::ProbabilisticScoringFeeParameters,
    util::config::ChannelConfig,
};
use lightning_invoice::payment::PaymentError;
use lightning_invoice::{
    payment::{pay_invoice, pay_zero_value_invoice},
    utils::{create_invoice_from_channelmanager_and_duration_since_epoch, create_phantom_invoice},
    Bolt11Invoice,
};
use std::collections::HashMap;
use std::{
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
};

const DEFAULT_PAYMENT_TIMEOUT: u64 = 30;
const INITIAL_RECONNECTION_DELAY: u64 = 5;
const MAX_RECONNECTION_DELAY: u64 = 60;

pub(crate) type BumpTxEventHandler<S: MutinyStorage> = BumpTransactionEventHandler<
    Arc<MutinyChain<S>>,
    Arc<Wallet<Arc<OnChainWallet<S>>, Arc<MutinyLogger>>>,
    Arc<PhantomKeysManager<S>>,
    Arc<MutinyLogger>,
>;

pub(crate) type RapidGossipSync =
    lightning_rapid_gossip_sync::RapidGossipSync<Arc<NetworkGraph>, Arc<MutinyLogger>>;

pub(crate) type NetworkGraph = gossip::NetworkGraph<Arc<MutinyLogger>>;

pub(crate) type OnionMessenger<S: MutinyStorage> = LdkOnionMessenger<
    Arc<PhantomKeysManager<S>>,
    Arc<PhantomKeysManager<S>>,
    Arc<MutinyLogger>,
    Arc<LspMessageRouter>,
    Arc<PhantomChannelManager<S>>,
    IgnoringMessageHandler,
>;

pub(crate) type MessageHandler<S: MutinyStorage> = LdkMessageHandler<
    Arc<PhantomChannelManager<S>>,
    Arc<GossipMessageHandler<S>>,
    Arc<OnionMessenger<S>>,
    Arc<SCBMessageHandler>,
>;

pub(crate) type ChainMonitor<S: MutinyStorage> = chainmonitor::ChainMonitor<
    InMemorySigner,
    Arc<dyn Filter + Send + Sync>,
    Arc<MutinyChain<S>>,
    Arc<MutinyFeeEstimator<S>>,
    Arc<MutinyLogger>,
    Arc<MutinyNodePersister<S>>,
>;

pub(crate) type Router = DefaultRouter<
    Arc<NetworkGraph>,
    Arc<MutinyLogger>,
    Arc<utils::Mutex<HubPreferentialScorer>>,
    ProbabilisticScoringFeeParameters,
    HubPreferentialScorer,
>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionType {
    Tcp(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PubkeyConnectionInfo {
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
        let (pubkey, peer_addr_str) = parse_peer_info(&connection)?;
        Ok(Self {
            pubkey,
            connection_type: ConnectionType::Tcp(peer_addr_str),
            original_connection_string: connection,
        })
    }
}

pub(crate) struct Node<S: MutinyStorage> {
    pub _uuid: String,
    pub child_index: u32,
    stopped_components: Arc<RwLock<Vec<bool>>>,
    pub pubkey: PublicKey,
    pub peer_manager: Arc<dyn PeerManager>,
    pub keys_manager: Arc<PhantomKeysManager<S>>,
    pub channel_manager: Arc<PhantomChannelManager<S>>,
    pub chain_monitor: Arc<ChainMonitor<S>>,
    pub fee_estimator: Arc<MutinyFeeEstimator<S>>,
    pub scb_message_handler: Arc<SCBMessageHandler>,
    network: Network,
    pub persister: Arc<MutinyNodePersister<S>>,
    wallet: Arc<OnChainWallet<S>>,
    logger: Arc<MutinyLogger>,
    pub(crate) lsp_client: Option<LspClient>,
    pub(crate) sync_lock: Arc<Mutex<()>>,
    stop: Arc<AtomicBool>,
    #[cfg(target_arch = "wasm32")]
    websocket_proxy_addr: String,
}

impl<S: MutinyStorage> Node<S> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn new(
        uuid: String,
        node_index: &NodeIndex,
        xprivkey: ExtendedPrivKey,
        storage: S,
        gossip_sync: Arc<RapidGossipSync>,
        scorer: Arc<utils::Mutex<HubPreferentialScorer>>,
        chain: Arc<MutinyChain<S>>,
        fee_estimator: Arc<MutinyFeeEstimator<S>>,
        wallet: Arc<OnChainWallet<S>>,
        network: Network,
        esplora: &MultiEsploraClient,
        lsp_clients: &[LspClient],
        logger: Arc<MutinyLogger>,
        do_not_connect_peers: bool,
        empty_state: bool,
        #[cfg(target_arch = "wasm32")] websocket_proxy_addr: String,
    ) -> Result<Self, MutinyError> {
        log_info!(logger, "initializing a new node: {uuid}");

        // a list of components that need to be stopped and whether or not they are stopped
        let stopped_components = Arc::new(RwLock::new(vec![]));

        let keys_manager = Arc::new(create_keys_manager(
            wallet.clone(),
            xprivkey,
            node_index.child_index,
            logger.clone(),
        )?);
        let pubkey = pubkey_from_keys_manager(&keys_manager);

        // init the persister
        let persister = Arc::new(MutinyNodePersister::new(
            uuid.clone(),
            storage,
            logger.clone(),
        ));

        // init chain monitor
        let chain_monitor: Arc<ChainMonitor<S>> = Arc::new(ChainMonitor::new(
            Some(chain.tx_sync.clone()),
            chain.clone(),
            logger.clone(),
            fee_estimator.clone(),
            persister.clone(),
        ));

        // set chain monitor for persister for async storage
        persister
            .chain_monitor
            .lock()
            .await
            .replace(chain_monitor.clone());

        // read channelmonitor state from disk
        let channel_monitors = if empty_state {
            vec![]
        } else {
            persister
                .read_channel_monitors(keys_manager.clone())
                .map_err(|e| MutinyError::ReadError {
                    source: MutinyStorageError::Other(anyhow!(
                        "failed to read channel monitors: {e}"
                    )),
                })?
        };

        let network_graph = gossip_sync.network_graph().clone();

        let router: Arc<Router> = Arc::new(DefaultRouter::new(
            network_graph,
            logger.clone(),
            keys_manager.clone().get_secure_random_bytes(),
            scorer.clone(),
            scoring_params(),
        ));

        // init channel manager
        let mut read_channel_manager = if empty_state {
            MutinyNodePersister::create_new_channel_manager(
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
            .await?
        } else {
            persister
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
                .await?
        };

        let channel_manager: Arc<PhantomChannelManager<S>> =
            Arc::new(read_channel_manager.channel_manager);

        // Check all existing channels against default configs.
        // If we have default config changes, those should apply
        // to all existing and new channels.
        let default_config = default_user_config().channel_config;
        for channel in channel_manager.list_channels() {
            // unwrap is safe after LDK.0.0.109
            if channel.config.unwrap() != default_config {
                match channel_manager.update_channel_config(
                    &channel.counterparty.node_id,
                    &[channel.channel_id],
                    &default_config,
                ) {
                    Ok(_) => {
                        log_debug!(
                            logger,
                            "changed default config for channel: {}",
                            channel.channel_id.to_hex()
                        )
                    }
                    Err(e) => {
                        log_error!(
                            logger,
                            "error changing default config for channel: {} - {e:?}",
                            channel.channel_id.to_hex()
                        )
                    }
                };
            }
        }

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
        let message_router = Arc::new(LspMessageRouter::new(lsp_client_pubkey));
        let onion_message_handler = Arc::new(OnionMessenger::new(
            keys_manager.clone(),
            keys_manager.clone(),
            logger.clone(),
            message_router,
            channel_manager.clone(),
            IgnoringMessageHandler {},
        ));

        let route_handler = Arc::new(GossipMessageHandler {
            storage: persister.storage.clone(),
            network_graph: gossip_sync.network_graph().clone(),
            logger: logger.clone(),
        });

        // init peer manager
        let scb_message_handler = Arc::new(SCBMessageHandler::new());
        let ln_msg_handler = MessageHandler {
            chan_handler: channel_manager.clone(),
            route_handler,
            onion_message_handler,
            custom_message_handler: scb_message_handler.clone(),
        };

        let bump_tx_event_handler = Arc::new(BumpTransactionEventHandler::new(
            Arc::clone(&chain),
            Arc::new(Wallet::new(Arc::clone(&wallet), Arc::clone(&logger))),
            Arc::clone(&keys_manager),
            Arc::clone(&logger),
        ));

        // init event handler
        let event_handler = EventHandler::new(
            channel_manager.clone(),
            fee_estimator.clone(),
            wallet.clone(),
            keys_manager.clone(),
            persister.clone(),
            bump_tx_event_handler,
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
                    .watch_channel(funding_outpoint, channel_monitor)
                    .map_err(|_| MutinyError::ChainAccessFailed)?;
            }
        }

        // Before we start the background processor, retry previously failed
        // spendable outputs. We should do this before we start the background
        // processor so we prevent any race conditions.
        // if we fail to read the spendable outputs, just log a warning and
        // continue
        if !empty_state {
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
                        persister.clear_failed_spendable_outputs()?;
                    }
                    Err(_) => {
                        // retry them individually then only save failed ones
                        // if there was only one we don't need to retry
                        if retry_spendable_outputs.len() > 1 {
                            let mut failed = vec![];
                            for o in retry_spendable_outputs {
                                if event_handler
                                    .handle_spendable_outputs(&[o.clone()])
                                    .await
                                    .is_err()
                                {
                                    failed.push(o);
                                }
                            }
                            persister.set_failed_spendable_outputs(failed)?;
                        };
                    }
                }
            }
        }

        let stop = Arc::new(AtomicBool::new(false));

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
        utils::spawn(async move {
            loop {
                let gs = crate::background::GossipSync::rapid(background_gossip_sync.clone());
                let ev = background_event_handler.clone();
                if let Err(e) = process_events_async(
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
                {
                    log_error!(background_logger, "error running background processor: {e}",);
                }

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

        if !do_not_connect_peers {
            #[cfg(target_arch = "wasm32")]
            let reconnection_proxy_addr = websocket_proxy_addr.clone();

            let reconnection_storage = persister.storage.clone();
            let reconnection_pubkey = pubkey;
            let reconnection_peer_man = peer_man.clone();
            let reconnection_fee = fee_estimator.clone();
            let reconnection_logger = logger.clone();
            let reconnection_uuid = uuid.clone();
            let reconnection_lsp_client = lsp_client.clone();
            let reconnection_stop = stop.clone();
            let reconnection_stopped_comp = stopped_components.clone();
            reconnection_stopped_comp.try_write()?.push(false);
            utils::spawn(async move {
                start_reconnection_handling(
                    &reconnection_storage,
                    reconnection_pubkey,
                    #[cfg(target_arch = "wasm32")]
                    reconnection_proxy_addr,
                    reconnection_peer_man,
                    reconnection_fee,
                    &reconnection_logger,
                    reconnection_uuid,
                    reconnection_lsp_client.as_ref(),
                    reconnection_stop,
                    reconnection_stopped_comp,
                    network == Network::Regtest,
                )
                .await;
            });
        }

        log_info!(
            logger,
            "Node started: {}",
            keys_manager.get_node_id(Recipient::Node).unwrap()
        );

        let sync_lock = Arc::new(Mutex::new(()));

        // Here we re-attempt to persist any monitors that failed to persist previously.
        let retry_logger = logger.clone();
        let retry_persister = persister.clone();
        let retry_stop = stop.clone();
        let retry_chain_monitor = chain_monitor.clone();
        let retry_sync_lock = sync_lock.clone();
        utils::spawn(async move {
            // sleep 3 seconds before checking, we won't have any pending updates on startup
            sleep(3_000).await;

            loop {
                if retry_stop.load(Ordering::Relaxed) {
                    break;
                }

                let updates = {
                    let _lock = retry_sync_lock.lock().await;
                    retry_chain_monitor.list_pending_monitor_updates()
                };

                for (funding_txo, update_ids) in updates {
                    // if there are no updates, skip
                    if update_ids.is_empty() {
                        continue;
                    }

                    log_debug!(
                        retry_logger,
                        "Retrying to persist monitor for outpoint: {funding_txo:?}"
                    );

                    match retry_chain_monitor.get_monitor(funding_txo) {
                        Ok(monitor) => {
                            let key = retry_persister.get_monitor_key(&funding_txo);
                            let object = monitor.encode();
                            let update_id = monitor.get_latest_update_id();
                            debug_assert_eq!(update_id, get_monitor_version(&object));

                            // safely convert u64 to u32
                            let version = if update_id >= u32::MAX as u64 {
                                u32::MAX
                            } else {
                                update_id as u32
                            };

                            let res = persist_monitor(
                                &retry_persister.storage,
                                &key,
                                &object,
                                Some(version),
                                &retry_logger,
                            )
                            .await;

                            match res {
                                Ok(_) => {
                                    for id in update_ids {
                                        if let Err(e) = retry_chain_monitor
                                            .channel_monitor_updated(funding_txo, id)
                                        {
                                            log_error!(retry_logger, "Error notifying chain monitor of channel monitor update: {e:?}");
                                        }
                                    }
                                }
                                Err(e) => log_error!(
                                    retry_logger,
                                    "Failed to persist monitor for outpoint: {funding_txo:?}, error: {e:?}",
                                ),
                            }
                        }
                        Err(_) => log_error!(
                            retry_logger,
                            "Failed to get monitor for outpoint: {funding_txo:?}"
                        ),
                    }
                }

                // sleep 3 seconds
                sleep(3_000).await;
            }
        });

        Ok(Node {
            _uuid: uuid,
            stopped_components,
            child_index: node_index.child_index,
            pubkey,
            peer_manager: peer_man,
            keys_manager,
            channel_manager,
            chain_monitor,
            fee_estimator,
            scb_message_handler,
            network,
            persister,
            wallet,
            logger,
            lsp_client,
            sync_lock,
            stop,
            #[cfg(target_arch = "wasm32")]
            websocket_proxy_addr,
        })
    }

    pub async fn stop(&self) -> Result<(), MutinyError> {
        self.stop.store(true, Ordering::Relaxed);

        self.stopped().await
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
        let connect_res = connect_peer_if_necessary(
            #[cfg(target_arch = "wasm32")]
            &self.websocket_proxy_addr,
            &peer_connection_info,
            &self.persister.storage,
            self.logger.clone(),
            self.peer_manager.clone(),
            self.fee_estimator.clone(),
            self.stop.clone(),
        )
        .await;
        match connect_res {
            Ok(_) => {
                let node_id = NodeId::from_pubkey(&peer_connection_info.pubkey);

                // if we have the connection info saved in storage, update it if we need to
                // otherwise cache it in temp_peer_connection_map so we can later save it
                // if we open a channel in the future.
                if let Some(saved) = read_peer_info(&self.persister.storage, &node_id)?
                    .and_then(|p| p.connection_string)
                {
                    if saved != peer_connection_info.original_connection_string {
                        match save_peer_connection_info(
                            &self.persister.storage,
                            &self._uuid,
                            &node_id,
                            &peer_connection_info.original_connection_string,
                            label,
                        ) {
                            Ok(_) => (),
                            Err(_) => {
                                log_warn!(self.logger, "WARN: could not store peer connection info")
                            }
                        }
                    }
                } else {
                    // store this so we can reconnect later
                    if let Err(e) = save_peer_connection_info(
                        &self.persister.storage,
                        &self._uuid,
                        &node_id,
                        &peer_connection_info.original_connection_string,
                        label,
                    ) {
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
    ) -> Result<Bolt11Invoice, MutinyError> {
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
            let min_amount_sat = if has_usable_channel {
                1
            } else {
                utils::min_lightning_amount(self.network)
            };
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

            // Convert the fee from msat to sat for comparison and subtraction
            let lsp_fee_sat = lsp_fee_msat / 1000;

            // Ensure that the fee is less than the amount being requested.
            // If it isn't, we don't subtract it.
            // This prevents amount from being subtracted down to 0.
            // This will mean that the LSP fee will be paid by the payer instead.
            let amount_minus_fee = if lsp_fee_sat < amount_sat {
                amount_sat
                    .checked_sub(lsp_fee_sat)
                    .ok_or(MutinyError::BadAmountError)?
            } else {
                amount_sat
            };

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
            let lsp_invoice = match lsp.get_lsp_invoice(invoice.to_string()).await {
                Ok(lsp_invoice_str) => Bolt11Invoice::from_str(&lsp_invoice_str)?,
                Err(e) => {
                    log_error!(self.logger, "Failed to get invoice from LSP: {e}");
                    return Err(e);
                }
            };

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
    ) -> Result<Bolt11Invoice, MutinyError> {
        let amount_msat = amount_sat.map(|s| s * 1_000);
        // Set description to empty string to make smallest possible invoice/QR code
        let description = "".to_string();

        // wait for first sync to complete
        for _ in 0..60 {
            // check if we've been stopped
            if self.stop.load(Ordering::Relaxed) {
                return Err(MutinyError::NotRunning);
            }

            if let Ok(true) = self.persister.storage.has_done_first_sync() {
                break;
            }

            sleep(1_000).await;
        }

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
                    3600,
                    Some(40),
                )
            }
            Some(r) => create_phantom_invoice(
                amount_msat,
                None,
                description,
                3600,
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
            .persist_payment_info(&payment_hash.0, &payment_info, true)
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

    pub fn get_invoice(&self, invoice: &Bolt11Invoice) -> Result<MutinyInvoice, MutinyError> {
        self.get_invoice_by_hash(invoice.payment_hash())
    }

    pub fn get_invoice_by_hash(&self, payment_hash: &Sha256) -> Result<MutinyInvoice, MutinyError> {
        let (payment_info, inbound) = self.get_payment_info_from_persisters(payment_hash)?;
        let labels_map = self.persister.storage.get_invoice_labels()?;
        let labels = payment_info
            .bolt11
            .as_ref()
            .and_then(|inv| labels_map.get(inv).cloned())
            .unwrap_or_default();

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

    /// Gets all the closed channels for this node
    pub fn get_channel_closure(
        &self,
        user_channel_id: u128,
    ) -> Result<Option<ChannelClosure>, MutinyError> {
        self.persister.get_channel_closure(user_channel_id)
    }

    /// Gets all the closed channels for this node
    pub fn get_channel_closures(&self) -> Result<Vec<ChannelClosure>, MutinyError> {
        Ok(self
            .persister
            .list_channel_closures()?
            .into_iter()
            .map(|(id, mut c)| {
                // some old closures might not have the user_channel_id set
                // we set it here to avoid breaking the API
                if c.user_channel_id.is_none() {
                    c.user_channel_id = Some(id.to_be_bytes())
                }
                c
            })
            .collect())
    }

    pub fn get_payment_info_from_persisters(
        &self,
        payment_hash: &bitcoin::hashes::sha256::Hash,
    ) -> Result<(PaymentInfo, bool), MutinyError> {
        // try inbound first
        if let Some(payment_info) =
            self.persister
                .read_payment_info(payment_hash.as_inner(), true, &self.logger)
        {
            return Ok((payment_info, true));
        }

        // if no inbound check outbound
        match self
            .persister
            .read_payment_info(payment_hash.as_inner(), false, &self.logger)
        {
            Some(payment_info) => Ok((payment_info, false)),
            None => Err(MutinyError::InvoiceInvalid),
        }
    }

    fn retry_strategy() -> Retry {
        Retry::Attempts(15)
    }

    /// init_invoice_payment sends off the payment but does not wait for results
    /// use pay_invoice_with_timeout to wait for results
    pub async fn init_invoice_payment(
        &self,
        invoice: &Bolt11Invoice,
        amt_sats: Option<u64>,
        labels: Vec<String>,
    ) -> Result<(PaymentId, PaymentHash), MutinyError> {
        let payment_hash = invoice.payment_hash().as_inner();

        if self
            .persister
            .read_payment_info(payment_hash, false, &self.logger)
            .is_some_and(|p| p.status != HTLCStatus::Failed)
        {
            return Err(MutinyError::NonUniquePaymentHash);
        }

        if self
            .persister
            .read_payment_info(payment_hash, true, &self.logger)
            .is_some_and(|p| p.status != HTLCStatus::Failed)
        {
            return Err(MutinyError::NonUniquePaymentHash);
        }

        // get invoice amount or use amt_sats
        let send_msats = invoice
            .amount_milli_satoshis()
            .or(amt_sats.map(|x| x * 1_000))
            .ok_or(MutinyError::InvoiceInvalid)?;

        // check if we have enough balance to send
        let channels = self.channel_manager.list_channels();
        if channels
            .iter()
            // only consider channels that are confirmed
            .filter(|c| c.is_channel_ready)
            .map(|c| c.balance_msat)
            .sum::<u64>()
            < send_msats
        {
            // Channels exist but not enough capacity
            return Err(MutinyError::InsufficientBalance);
        }

        // make sure node at least has one connection before attempting payment
        // wait for connection before paying, or otherwise instant fail anyways
        for _ in 0..DEFAULT_PAYMENT_TIMEOUT {
            // check if we've been stopped
            if self.stop.load(Ordering::Relaxed) {
                return Err(MutinyError::NotRunning);
            }
            if !self.channel_manager.list_usable_channels().is_empty() {
                break;
            }
            sleep(1_000).await;
        }

        let (pay_result, amt_msat) = if invoice.amount_milli_satoshis().is_none() {
            if amt_sats.is_none() {
                return Err(MutinyError::InvoiceInvalid);
            }
            let amt_msats = amt_sats.unwrap() * 1_000;
            (
                pay_zero_value_invoice(
                    invoice,
                    amt_msats,
                    Self::retry_strategy(),
                    self.channel_manager.as_ref(),
                ),
                amt_msats,
            )
        } else {
            if amt_sats.is_some() {
                return Err(MutinyError::InvoiceInvalid);
            }
            (
                pay_invoice(
                    invoice,
                    Self::retry_strategy(),
                    self.channel_manager.as_ref(),
                ),
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

        self.persister
            .persist_payment_info(payment_hash, &payment_info, false)?;

        match pay_result {
            Ok(id) => Ok((id, PaymentHash(payment_hash.to_owned()))),
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
                    .persist_payment_info(payment_hash, &payment_info, false)?;

                // If the payment failed because of a route not found, check if the amount was
                // valid and return the correct error
                if let PaymentError::Sending(RetryableSendFailure::RouteNotFound) = e {
                    // If the amount was greater than our balance, return an InsufficientBalance error
                    let ln_balance: u64 = current_channels.iter().map(|c| c.balance_msat).sum();
                    if amt_msat > ln_balance {
                        return Err(MutinyError::InsufficientBalance);
                    }

                    // If the amount was within our balance but we couldn't pay because of
                    // the channel reserve, return a ReserveAmountError
                    let reserved_amt: u64 = current_channels
                        .into_iter()
                        .flat_map(|c| c.unspendable_punishment_reserve)
                        .sum::<u64>()
                        * 1_000; // multiply by 1k to convert to msat
                    if ln_balance - reserved_amt < amt_msat {
                        return Err(MutinyError::ReserveAmountError);
                    }
                }

                Err(MutinyError::RoutingFailed)
            }
        }
    }

    async fn await_payment(
        &self,
        payment_id: PaymentId,
        payment_hash: PaymentHash,
        timeout: u64,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        let start = utils::now().as_secs();
        loop {
            let now = utils::now().as_secs();
            if now - start > timeout {
                // stop retrying after timeout, this should help prevent
                // payments completing unexpectedly after the timeout
                self.channel_manager.abandon_payment(payment_id);
                return Err(MutinyError::PaymentTimeout);
            }

            let payment_info =
                self.persister
                    .read_payment_info(&payment_hash.0, false, &self.logger);

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
        invoice: &Bolt11Invoice,
        amt_sats: Option<u64>,
        timeout_secs: Option<u64>,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        // initiate payment
        let (payment_id, payment_hash) = self
            .init_invoice_payment(invoice, amt_sats, labels.clone())
            .await?;
        let timeout: u64 = timeout_secs.unwrap_or(DEFAULT_PAYMENT_TIMEOUT);

        self.await_payment(payment_id, payment_hash, timeout, labels)
            .await
    }

    /// init_keysend_payment sends off the payment but does not wait for results
    /// use keysend_with_timeout to wait for results
    pub fn init_keysend_payment(
        &self,
        to_node: PublicKey,
        amt_sats: u64,
        message: Option<String>,
        labels: Vec<String>,
        payment_id: PaymentId,
    ) -> Result<MutinyInvoice, MutinyError> {
        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy).map_err(|_| MutinyError::SeedGenerationFailed)?;
        let payment_secret = PaymentSecret(entropy);

        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy).map_err(|_| MutinyError::SeedGenerationFailed)?;
        let preimage = PaymentPreimage(entropy);

        let amt_msats = amt_sats * 1000;

        // TODO retry with allow_mpp false just in case recipient does not support
        let payment_params = PaymentParameters::for_keysend(to_node, 40, true);
        let route_params: RouteParameters = RouteParameters {
            final_value_msat: amt_msats,
            payment_params,
            max_total_routing_fee_msat: None,
        };

        let recipient_onion = if let Some(msg) = message {
            // keysend messages are encoded as TLV type 34349334
            RecipientOnionFields::secret_only(payment_secret)
                .with_custom_tlvs(vec![(34349334, msg.encode())])
                .map_err(|_| {
                    log_error!(self.logger, "could not encode keysend message");
                    MutinyError::InvoiceCreationFailed
                })?
        } else {
            RecipientOnionFields::secret_only(payment_secret)
        };

        let pay_result = self.channel_manager.send_spontaneous_payment_with_retry(
            Some(preimage),
            recipient_onion,
            payment_id,
            route_params,
            Self::retry_strategy(),
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
            .persist_payment_info(&payment_hash.0, &payment_info, false)?;

        match pay_result {
            Ok(_) => {
                let mutiny_invoice =
                    MutinyInvoice::from(payment_info, payment_hash, false, labels)?;
                Ok(mutiny_invoice)
            }
            Err(_) => {
                payment_info.status = HTLCStatus::Failed;
                self.persister
                    .persist_payment_info(&payment_hash.0, &payment_info, false)?;
                Err(MutinyError::RoutingFailed)
            }
        }
    }

    pub async fn keysend_with_timeout(
        &self,
        to_node: PublicKey,
        amt_sats: u64,
        message: Option<String>,
        labels: Vec<String>,
        timeout_secs: Option<u64>,
    ) -> Result<MutinyInvoice, MutinyError> {
        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy).map_err(|_| MutinyError::SeedGenerationFailed)?;
        let payment_id = PaymentId(entropy);

        // initiate payment
        let pay =
            self.init_keysend_payment(to_node, amt_sats, message, labels.clone(), payment_id)?;

        let timeout: u64 = timeout_secs.unwrap_or(DEFAULT_PAYMENT_TIMEOUT);
        let payment_hash = PaymentHash(pay.payment_hash.into_inner());

        self.await_payment(payment_id, payment_hash, timeout, labels)
            .await
    }

    async fn await_chan_funding_tx(
        &self,
        user_channel_id: u128,
        pubkey: &PublicKey,
        timeout: u64,
    ) -> Result<OutPoint, MutinyError> {
        let start = utils::now().as_secs();
        loop {
            if self.stop.load(Ordering::Relaxed) {
                return Err(MutinyError::NotRunning);
            }

            // We will get a channel closure event if the peer rejects the channel
            // todo return closure reason to user
            if let Ok(Some(_closure)) = self.persister.get_channel_closure(user_channel_id) {
                return Err(MutinyError::ChannelCreationFailed);
            }

            let channels = self.channel_manager.list_channels_with_counterparty(pubkey);
            let channel = channels
                .iter()
                .find(|c| c.user_channel_id == user_channel_id);

            if let Some(outpoint) = channel.and_then(|c| c.funding_txo) {
                let outpoint = outpoint.into_bitcoin_outpoint();
                log_info!(self.logger, "Channel funding tx found: {}", outpoint);
                log_debug!(self.logger, "Waiting for Channel Pending event");
                loop {
                    // we delete the channel open params on channel pending event
                    // so if we can't find them, we know the channel is pending
                    // and we can safely return
                    if self
                        .persister
                        .get_channel_open_params(user_channel_id)
                        .map(|p| p.is_none())
                        .unwrap_or(false)
                    {
                        return Ok(outpoint);
                    }

                    let now = utils::now().as_secs();
                    if now - start > timeout {
                        return Err(MutinyError::ChannelCreationFailed);
                    }

                    if self.stop.load(Ordering::Relaxed) {
                        return Err(MutinyError::NotRunning);
                    }
                    sleep(250).await;
                }
            }

            let now = utils::now().as_secs();
            if now - start > timeout {
                return Err(MutinyError::ChannelCreationFailed);
            }

            sleep(250).await;
        }
    }

    pub async fn init_open_channel(
        &self,
        pubkey: PublicKey,
        amount_sat: u64,
        fee_rate: Option<f32>,
        user_channel_id: Option<u128>,
    ) -> Result<u128, MutinyError> {
        let mut config = default_user_config();

        // if we are opening channel to LSP, turn off SCID alias until CLN is updated
        // LSP protects all invoice information anyways, so no UTXO leakage
        if let Some(lsp) = self.lsp_client.clone() {
            if pubkey == lsp.pubkey {
                config.channel_handshake_config.negotiate_scid_privacy = false;
            }
        }

        let user_channel_id = user_channel_id.unwrap_or_else(|| {
            // generate random user channel id
            let mut user_channel_id_bytes = [0u8; 16];
            getrandom::getrandom(&mut user_channel_id_bytes).unwrap();
            u128::from_be_bytes(user_channel_id_bytes)
        });

        let sats_per_vbyte = if let Some(sats_vbyte) = fee_rate {
            sats_vbyte
        } else {
            let sats_per_kw = self.wallet.fees.get_normal_fee_rate();

            FeeRate::from_sat_per_kwu(sats_per_kw as f32).as_sat_per_vb()
        };

        // save params to db
        let params = ChannelOpenParams::new(sats_per_vbyte);
        self.persister
            .persist_channel_open_params(user_channel_id, params)?;

        match self.channel_manager.create_channel(
            pubkey,
            amount_sat,
            0,
            user_channel_id,
            Some(config),
        ) {
            Ok(_) => {
                log_info!(
                    self.logger,
                    "SUCCESS: channel initiated with peer: {pubkey:?}"
                );
                Ok(user_channel_id)
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

    pub async fn open_channel_with_timeout(
        &self,
        pubkey: PublicKey,
        amount_sat: u64,
        fee_rate: Option<f32>,
        user_channel_id: Option<u128>,
        timeout: u64,
    ) -> Result<OutPoint, MutinyError> {
        let init = self
            .init_open_channel(pubkey, amount_sat, fee_rate, user_channel_id)
            .await?;

        self.await_chan_funding_tx(init, &pubkey, timeout).await
    }

    pub async fn init_sweep_utxos_to_channel(
        &self,
        user_chan_id: Option<u128>,
        utxos: &[OutPoint],
        pubkey: PublicKey,
    ) -> Result<u128, MutinyError> {
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

        let sats_per_kw = self.wallet.fees.get_normal_fee_rate();

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

        let sats_per_vbyte = FeeRate::from_sat_per_kwu(sats_per_kw as f32).as_sat_per_vb();
        // save params to db
        let params = ChannelOpenParams::new_sweep(sats_per_vbyte, expected_fee, utxos.to_vec());
        self.persister
            .persist_channel_open_params(user_channel_id, params)?;

        match self.channel_manager.create_channel(
            pubkey,
            channel_value_satoshis,
            0,
            user_channel_id,
            Some(config),
        ) {
            Ok(_) => {
                log_info!(
                    self.logger,
                    "SUCCESS: channel initiated with peer: {pubkey:?}"
                );
                Ok(user_channel_id)
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

    pub async fn sweep_utxos_to_channel_with_timeout(
        &self,
        user_chan_id: Option<u128>,
        utxos: &[OutPoint],
        pubkey: PublicKey,
        timeout: u64,
    ) -> Result<OutPoint, MutinyError> {
        let init = self
            .init_sweep_utxos_to_channel(user_chan_id, utxos, pubkey)
            .await?;

        self.await_chan_funding_tx(init, &pubkey, timeout).await
    }

    pub fn create_static_channel_backup(&self) -> Result<StaticChannelBackup, MutinyError> {
        let mut monitors = HashMap::new();
        for outpoint in self.chain_monitor.list_monitors() {
            let monitor = self
                .chain_monitor
                .get_monitor(outpoint)
                .map_err(|_| MutinyError::Other(anyhow!("Failed to get channel monitor")))?;

            let monitor_bytes = monitor.encode();
            monitors.insert(outpoint.into_bitcoin_outpoint(), monitor_bytes);
        }

        Ok(StaticChannelBackup { monitors })
    }

    pub async fn recover_from_static_channel_backup(
        &self,
        scb: StaticChannelBackup,
        peer_connections: &HashMap<PublicKey, String>,
    ) -> Result<(), MutinyError> {
        for (outpoint, monitor_bytes) in scb.monitors {
            let ln_outpoint = lightning::chain::transaction::OutPoint {
                txid: outpoint.txid,
                index: outpoint.vout as u16,
            };

            let reader = &mut lightning::io::Cursor::new(&monitor_bytes);
            let (_, monitor) = <(BlockHash, ChannelMonitor<InMemorySigner>)>::read(
                reader,
                (self.keys_manager.as_ref(), self.keys_manager.as_ref()),
            )?;

            // unwrap is safe for ldk > 0.0.110
            let node_id = monitor
                .get_counterparty_node_id()
                .expect("failed to get node id");

            // watch the channel in the case peer tries to cheat us
            // if there are no claimable balances, we don't need to watch the channel
            if !monitor.get_claimable_balances().is_empty() {
                self.chain_monitor
                    .watch_channel(ln_outpoint, monitor)
                    .map_err(|_| MutinyError::ChainAccessFailed)?;
            } else {
                log_debug!(
                    self.logger,
                    "no claimable balances for channel {ln_outpoint:?}, skipping watch"
                );
            }

            // connect to peer if we have a connection string
            if let Some(connection_string) = peer_connections.get(&node_id) {
                let connect = PubkeyConnectionInfo::new(connection_string)
                    .expect("invalid connection string");
                self.connect_peer(connect, None).await?;
            }

            // then ask peer to force close the channel
            self.scb_message_handler
                .request_channel_close(node_id, ln_outpoint.to_channel_id());
        }

        // fire off all the send events
        if self.scb_message_handler.has_pending_messages() {
            self.peer_manager.process_events();
        }

        Ok(())
    }
}

pub(crate) fn scoring_params() -> ProbabilisticScoringFeeParameters {
    ProbabilisticScoringFeeParameters {
        base_penalty_amount_multiplier_msat: 8192 * 100, // default * 100
        base_penalty_msat: 100_000,                      // 100 sat for each hop
        ..Default::default()
    }
}

#[allow(clippy::too_many_arguments)]
async fn start_reconnection_handling<S: MutinyStorage>(
    storage: &S,
    node_pubkey: PublicKey,
    #[cfg(target_arch = "wasm32")] websocket_proxy_addr: String,
    peer_man: Arc<dyn PeerManager>,
    fee_estimator: Arc<MutinyFeeEstimator<S>>,
    logger: &Arc<MutinyLogger>,
    uuid: String,
    lsp_client: Option<&LspClient>,
    stop: Arc<AtomicBool>,
    stopped_components: Arc<RwLock<Vec<bool>>>,
    skip_fee_estimates: bool,
) {
    // wait for fee estimates sync to finish, it can cause issues if we try to connect before
    // we have fee estimates
    if !skip_fee_estimates {
        loop {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            // make sure we have fee estimates and they are not empty
            if storage
                .get_fee_estimates()
                .map(|m| m.is_some_and(|m| !m.is_empty()))
                .unwrap_or(false)
            {
                break;
            }
            sleep(1_000).await;
        }
    }

    // Attempt initial connections first in the background
    #[cfg(target_arch = "wasm32")]
    let websocket_proxy_addr_copy_proxy = websocket_proxy_addr.clone();

    let proxy_logger = logger.clone();
    let peer_man_proxy = peer_man.clone();
    let proxy_fee_estimator = fee_estimator.clone();
    let lsp_client_copy = lsp_client.cloned();
    let storage_copy = storage.clone();
    let uuid_copy = uuid.clone();
    let stop_copy = stop.clone();
    utils::spawn(async move {
        // Now try to connect to the client's LSP
        if let Some(lsp) = lsp_client_copy {
            let node_id = NodeId::from_pubkey(&lsp.pubkey);

            let connect_res = connect_peer_if_necessary(
                #[cfg(target_arch = "wasm32")]
                &websocket_proxy_addr_copy_proxy,
                &PubkeyConnectionInfo::new(lsp.connection_string.as_str()).unwrap(),
                &storage_copy,
                proxy_logger.clone(),
                peer_man_proxy.clone(),
                proxy_fee_estimator.clone(),
                stop_copy.clone(),
            )
            .await;
            match connect_res {
                Ok(_) => {
                    log_trace!(proxy_logger, "auto connected lsp: {node_id}");
                }
                Err(e) => {
                    log_trace!(proxy_logger, "could not connect to lsp {node_id}: {e}");
                }
            }

            if let Err(e) = save_peer_connection_info(
                &storage_copy,
                &uuid_copy,
                &node_id,
                &lsp.connection_string,
                None,
            ) {
                log_error!(proxy_logger, "could not save connection to lsp: {e}");
            }
        };
    });

    // keep trying to connect each lightning peer if they get disconnected
    let connect_peer_man = peer_man.clone();
    let connect_fee_estimator = fee_estimator.clone();
    let connect_logger = logger.clone();
    let connect_storage = storage.clone();
    utils::spawn(async move {
        // hashMap to store backoff times for each pubkey
        let mut backoff_times = HashMap::new();

        loop {
            for _ in 0..5 {
                if stop.load(Ordering::Relaxed) {
                    log_debug!(
                        connect_logger,
                        "stopping connection component and disconnecting peers for node: {}",
                        node_pubkey.to_hex(),
                    );
                    connect_peer_man.disconnect_all_peers();
                    stop_component(&stopped_components);
                    log_debug!(
                        connect_logger,
                        "stopped connection component and disconnected peers for node: {}",
                        node_pubkey.to_hex(),
                    );
                    return;
                }
                sleep(1_000).await;
            }

            let peer_connections = get_all_peers(&connect_storage).unwrap_or_default();
            let current_connections = connect_peer_man.get_peer_node_ids();

            let not_connected: Vec<(NodeId, String)> = peer_connections
                .into_iter()
                .filter(|(_, d)| {
                    d.connection_string.is_some()
                        && d.nodes.binary_search(&uuid.to_string()).is_ok()
                })
                .map(|(n, d)| (n, d.connection_string.unwrap()))
                .filter(|(n, _)| {
                    !current_connections
                        .iter()
                        .any(|c| &NodeId::from_pubkey(c) == n)
                })
                .collect();

            for (pubkey, conn_str) in not_connected.into_iter() {
                let now = crate::utils::now();

                // initialize backoff time and last attempt time if they do not exist
                let backoff_entry = backoff_times
                    .entry(pubkey)
                    .or_insert((INITIAL_RECONNECTION_DELAY, now));

                // skip this pubkey if not enough time has passed since the last attempt
                if now - backoff_entry.1 < Duration::from_secs(backoff_entry.0) {
                    continue;
                }

                // Update the last attempt time
                backoff_entry.1 = now;

                log_trace!(connect_logger, "going to auto connect to peer: {pubkey}");
                let peer_connection_info = match PubkeyConnectionInfo::new(&conn_str) {
                    Ok(p) => p,
                    Err(e) => {
                        log_error!(connect_logger, "could not parse connection info: {e}");
                        continue;
                    }
                };

                let connect_res = connect_peer_if_necessary(
                    #[cfg(target_arch = "wasm32")]
                    &websocket_proxy_addr,
                    &peer_connection_info,
                    &connect_storage,
                    connect_logger.clone(),
                    connect_peer_man.clone(),
                    connect_fee_estimator.clone(),
                    stop.clone(),
                )
                .await;
                match connect_res {
                    Ok(_) => {
                        log_trace!(connect_logger, "auto connected peer: {pubkey}");
                        // reset backoff time to initial value if connection is successful
                        backoff_entry.0 = INITIAL_RECONNECTION_DELAY;
                    }
                    Err(e) => {
                        log_warn!(connect_logger, "could not auto connect peer: {e}");
                        // double the backoff time if connection fails, but do not exceed max
                        backoff_entry.0 = (backoff_entry.0 * 2).min(MAX_RECONNECTION_DELAY);
                    }
                }
            }
        }
    });
}

fn stop_component(stopped_components: &Arc<RwLock<Vec<bool>>>) {
    let mut stopped = stopped_components
        .try_write()
        .expect("can write to stopped components");
    if let Some(first_false) = stopped.iter_mut().find(|x| !**x) {
        *first_false = true;
    }
}

pub(crate) fn create_peer_manager<S: MutinyStorage>(
    km: Arc<PhantomKeysManager<S>>,
    lightning_msg_handler: MessageHandler<S>,
    logger: Arc<MutinyLogger>,
) -> PeerManagerImpl<S> {
    let now = utils::now().as_secs();
    let mut ephemeral_bytes = [0u8; 32];
    getrandom::getrandom(&mut ephemeral_bytes).expect("Failed to generate entropy");

    PeerManagerImpl::new(
        lightning_msg_handler,
        now as u32,
        &ephemeral_bytes,
        logger,
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
            negotiate_anchors_zero_fee_htlc_tx: true,
            max_inbound_htlc_value_in_flight_percent_of_channel: 100,
            ..Default::default()
        },
        manually_accept_inbound_channels: true,
        channel_config: ChannelConfig {
            // 20k sats, 4x more than normal due to high fee rates
            // Any lightning payment above this, but below current
            // HTLC fees will have issues paying until anchor outputs
            max_dust_htlc_exposure: MaxDustHTLCExposure::FixedLimitMsat(20_000_000),
            ..Default::default()
        },
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
