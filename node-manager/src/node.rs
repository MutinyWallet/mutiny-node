use crate::event::{EventHandler, HTLCStatus, MillisatAmount, PaymentInfo};
use crate::invoice::create_phantom_invoice;
use crate::ldkstorage::{MutinyNodePersister, PhantomChannelManager};
use crate::localstorage::MutinyBrowserStorage;
use crate::utils::currency_from_network;
use crate::wallet::MutinyWallet;
use bitcoin::hashes::Hash;
use bitcoin::Network;
use futures::StreamExt;
use gloo_net::websocket::Message;
use lightning::chain::{chainmonitor, Filter};
use lightning::ln::channelmanager::PhantomRouteHints;
use lightning::ln::msgs::NetAddress;
use lightning::ln::PaymentHash;
use lightning::util::logger::{Logger, Record};
use std::net::{SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use wasm_bindgen_futures::spawn_local;

use crate::chain::MutinyChain;
use crate::tcpproxy::{SocketDescriptor, TcpProxy};
use crate::{
    background::{BackgroundProcessor, GossipSync},
    error::MutinyError,
    keymanager::{create_keys_manager, pubkey_from_keys_manager},
    logging::MutinyLogger,
    nodemanager::NodeIndex,
};
use anyhow::Context;
use bip39::Mnemonic;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::secp256k1::PublicKey;
use lightning::chain::keysinterface::{
    InMemorySigner, KeysInterface, PhantomKeysManager, Recipient,
};
use lightning::ln::peer_handler::{
    IgnoringMessageHandler, MessageHandler as LdkMessageHandler, PeerManager as LdkPeerManager,
    SocketDescriptor as LdkSocketDescriptor,
};
use lightning::routing::gossip;
use lightning::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringParameters};
use lightning_invoice::utils::DefaultRouter;
use lightning_invoice::{payment, Invoice};
use log::{debug, error, info, warn};

pub(crate) type NetworkGraph = gossip::NetworkGraph<Arc<MutinyLogger>>;

pub(crate) type MessageHandler = LdkMessageHandler<
    Arc<PhantomChannelManager>,
    Arc<IgnoringMessageHandler>,
    Arc<IgnoringMessageHandler>,
>;

pub(crate) type PeerManager = LdkPeerManager<
    SocketDescriptor,
    Arc<PhantomChannelManager>,
    Arc<IgnoringMessageHandler>,
    Arc<IgnoringMessageHandler>,
    Arc<MutinyLogger>,
    Arc<IgnoringMessageHandler>,
>;

pub(crate) type ChainMonitor = chainmonitor::ChainMonitor<
    InMemorySigner,
    Arc<dyn Filter + Send + Sync>,
    Arc<MutinyChain>,
    Arc<MutinyChain>,
    Arc<MutinyLogger>,
    Arc<MutinyNodePersister>,
>;

pub(crate) type InvoicePayer<E> =
    payment::InvoicePayer<Arc<PhantomChannelManager>, Router, Arc<MutinyLogger>, E>;

type Router = DefaultRouter<
    Arc<NetworkGraph>,
    Arc<MutinyLogger>,
    Arc<Mutex<ProbabilisticScorer<Arc<NetworkGraph>, Arc<MutinyLogger>>>>,
>;

pub struct Node {
    pub uuid: String,
    pub pubkey: PublicKey,
    pub peer_manager: Arc<PeerManager>,
    pub keys_manager: Arc<PhantomKeysManager>,
    pub chain: Arc<MutinyChain>,
    pub channel_manager: Arc<PhantomChannelManager>,
    pub chain_monitor: Arc<ChainMonitor>,
    pub invoice_payer: Arc<InvoicePayer<EventHandler>>,
    network: Network,
    persister: Arc<MutinyNodePersister>,
    _background_processor: BackgroundProcessor,
    logger: Arc<MutinyLogger>,
}

impl Node {
    pub(crate) async fn new(
        node_index: NodeIndex,
        mnemonic: Mnemonic,
        storage: MutinyBrowserStorage,
        chain: Arc<MutinyChain>,
        wallet: Arc<MutinyWallet>,
        network: Network,
    ) -> Result<Self, MutinyError> {
        info!("initialized a new node: {}", node_index.uuid);

        let logger = Arc::new(MutinyLogger::default());

        let keys_manager = Arc::new(create_keys_manager(mnemonic, node_index.child_index));
        let pubkey = pubkey_from_keys_manager(&keys_manager);

        // init the persister
        let persister = Arc::new(MutinyNodePersister::new(node_index.uuid.clone(), storage));

        // init chain monitor
        let chain_monitor: Arc<ChainMonitor> = Arc::new(ChainMonitor::new(
            None,
            chain.clone(),
            logger.clone(),
            chain.clone(),
            persister.clone(),
        ));

        // read channelmonitor state from disk
        let channel_monitors = persister
            .read_channel_monitors(keys_manager.clone())
            .unwrap();

        // init channel manager
        let channel_manager = persister
            .read_channel_manager(
                network,
                chain_monitor.clone(),
                chain.clone(),
                logger.clone(),
                keys_manager.clone(),
                channel_monitors,
            )
            .await?;
        let channel_manager: Arc<PhantomChannelManager> = Arc::new(channel_manager);

        // init peer manager
        let ln_msg_handler = MessageHandler {
            chan_handler: channel_manager.clone(),
            route_handler: Arc::new(IgnoringMessageHandler {}),
            onion_message_handler: Arc::new(IgnoringMessageHandler {}),
        };

        // init event handler
        let event_handler = EventHandler::new(
            channel_manager.clone(),
            chain.clone(),
            wallet.clone(),
            keys_manager.clone(),
            persister.clone(),
            network,
            logger.clone(),
        );
        let peer_man = Arc::new(create_peer_manager(
            keys_manager.clone(),
            ln_msg_handler,
            logger.clone(),
        ));

        // todo use RGS
        // get network graph
        let genesis_hash = genesis_block(network).block_hash();
        let network_graph = Arc::new(persister.read_network_graph(genesis_hash, logger.clone()));

        // create scorer
        let params = ProbabilisticScoringParameters::default();
        let scorer = Arc::new(Mutex::new(ProbabilisticScorer::new(
            params,
            network_graph.clone(),
            logger.clone(),
        )));

        let router: Router = DefaultRouter::new(
            network_graph,
            logger.clone(),
            keys_manager.get_secure_random_bytes(),
            scorer.clone(),
        );

        let invoice_payer: Arc<InvoicePayer<EventHandler>> = Arc::new(InvoicePayer::new(
            Arc::clone(&channel_manager),
            router,
            Arc::clone(&logger),
            event_handler,
            payment::Retry::Attempts(5), // todo potentially rethink
        ));

        let background_processor_logger = logger.clone();
        let background_processor_invoice_payer = invoice_payer.clone();
        let background_processor_peer_manager = peer_man.clone();
        let background_processor_channel_manager = channel_manager.clone();
        let background_chain_monitor = chain_monitor.clone();
        let gs: GossipSync<_, _, &NetworkGraph, _, Arc<MutinyLogger>> = GossipSync::none();

        let background_processor = BackgroundProcessor::start(
            persister.clone(),
            background_processor_invoice_payer.clone(),
            background_chain_monitor.clone(),
            background_processor_channel_manager.clone(),
            gs,
            background_processor_peer_manager.clone(),
            background_processor_logger.clone(),
            Some(scorer),
        );

        Ok(Node {
            uuid: node_index.uuid,
            pubkey,
            peer_manager: peer_man,
            keys_manager,
            chain,
            channel_manager,
            chain_monitor,
            invoice_payer,
            network,
            persister,
            _background_processor: background_processor,
            logger,
        })
    }

    pub async fn connect_peer(
        &self,
        websocket_proxy_addr: String,
        peer_pubkey_and_ip_addr: String,
    ) -> Result<(), MutinyError> {
        if peer_pubkey_and_ip_addr.is_empty() {
            return Err(MutinyError::PeerInfoParseFailed)
                .context("connect_peer requires peer connection info")?;
        };
        let (pubkey, peer_addr) = match parse_peer_info(peer_pubkey_and_ip_addr) {
            Ok(info) => info,
            Err(e) => {
                return Err(MutinyError::PeerInfoParseFailed)
                    .with_context(|| format!("could not parse peer info: {}", e))?;
            }
        };

        if connect_peer_if_necessary(
            websocket_proxy_addr,
            pubkey,
            peer_addr,
            self.peer_manager.clone(),
        )
        .await
        .is_err()
        {
            Err(MutinyError::PeerInfoParseFailed)
                .with_context(|| format!("could not connect to peer: {pubkey}"))?
        } else {
            Ok(())
        }
    }

    pub fn get_phantom_route_hint(&self) -> PhantomRouteHints {
        self.channel_manager.get_phantom_route_hints()
    }

    pub fn create_phantom_invoice(
        &self,
        amount_sat: u64,
        description: String,
        route_hints: Vec<PhantomRouteHints>,
    ) -> Result<Invoice, MutinyError> {
        let invoice = match create_phantom_invoice::<InMemorySigner, Arc<PhantomKeysManager>>(
            Some(amount_sat * 1000),
            None,
            description,
            1500,
            route_hints,
            self.keys_manager.clone(),
            currency_from_network(self.network),
        ) {
            Ok(inv) => {
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Info,
                    format_args!("SUCCESS: generated invoice: {}", inv),
                    "node",
                    "",
                    0,
                ));
                inv
            }
            Err(e) => {
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Error,
                    format_args!("ERROR: could not generate invoice: {}", e),
                    "node",
                    "",
                    0,
                ));
                return Err(MutinyError::InvoiceCreationFailed);
            }
        };

        let payment_hash = PaymentHash(invoice.payment_hash().into_inner());
        let payment_info = PaymentInfo {
            preimage: None,
            secret: Some(invoice.payment_secret().0),
            status: HTLCStatus::Pending,
            amt_msat: MillisatAmount(Some(amount_sat * 1000)),
        };
        match self
            .persister
            .persist_payment_info(payment_hash, payment_info, true)
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
        Ok(invoice)
    }
}

pub(crate) async fn connect_peer_if_necessary(
    websocket_proxy_addr: String,
    pubkey: PublicKey,
    peer_addr: SocketAddr,
    peer_manager: Arc<PeerManager>,
) -> Result<(), MutinyError> {
    // TODO add this when the peer manager is ready
    /*
    for node_pubkey in peer_manager.get_peer_node_ids() {
        if node_pubkey == pubkey {
            return Ok(());
        }
    }
    */

    // first make a connection to the node
    let tcp_proxy = Arc::new(TcpProxy::new(websocket_proxy_addr, peer_addr).await);
    let mut descriptor = SocketDescriptor::new(tcp_proxy);

    // then give that connection to the peer manager
    let initial_bytes = peer_manager.new_outbound_connection(
        pubkey,
        descriptor.clone(),
        Some(get_net_addr_from_socket(peer_addr)),
    )?;

    let sent_bytes = descriptor.send_data(&initial_bytes, true);
    debug!("sent {sent_bytes} to node: {pubkey}");

    // schedule a reader on the connection
    let mut new_descriptor = descriptor.clone();
    spawn_local(async move {
        while let Some(msg) = descriptor.conn.read.lock().await.next().await {
            if let Ok(msg_contents) = msg {
                match msg_contents {
                    Message::Text(t) => {
                        warn!(
                            "received text from websocket when we should only receive binary: {}",
                            t
                        )
                    }
                    Message::Bytes(b) => {
                        debug!("received binary data from websocket");

                        let read_res = peer_manager.read_event(&mut new_descriptor, &b);
                        match read_res {
                            // TODO handle read boolean event
                            Ok(_read_bool) => {
                                debug!("read event from the node");
                                peer_manager.process_events();
                            }
                            Err(e) => error!("got an error reading event: {}", e),
                        }
                    }
                };
            }
        }

        // TODO when we detect an error, lock the writes and close connection.
        debug!("WebSocket Closed")
    });

    Ok(())
}

fn get_net_addr_from_socket(socket_addr: SocketAddr) -> NetAddress {
    match socket_addr {
        SocketAddr::V4(sockaddr) => NetAddress::IPv4 {
            addr: sockaddr.ip().octets(),
            port: sockaddr.port(),
        },
        SocketAddr::V6(sockaddr) => NetAddress::IPv6 {
            addr: sockaddr.ip().octets(),
            port: sockaddr.port(),
        },
    }
}

pub(crate) fn create_peer_manager(
    km: Arc<PhantomKeysManager>,
    lightning_msg_handler: MessageHandler,
    logger: Arc<MutinyLogger>,
) -> PeerManager {
    let current_time = instant::now();
    let mut ephemeral_bytes = [0u8; 32];
    getrandom::getrandom(&mut ephemeral_bytes).expect("Failed to generate entropy");

    PeerManager::new(
        lightning_msg_handler,
        km.get_node_secret(Recipient::Node)
            .expect("Failed to get node secret"),
        current_time as u32,
        &ephemeral_bytes,
        logger,
        Arc::new(IgnoringMessageHandler {}),
    )
}

pub(crate) fn parse_peer_info(
    peer_pubkey_and_ip_addr: String,
) -> Result<(PublicKey, SocketAddr), MutinyError> {
    let mut pubkey_and_addr = peer_pubkey_and_ip_addr.split('@');
    let pubkey = pubkey_and_addr.next();
    let peer_addr_str = pubkey_and_addr.next();
    if peer_addr_str.is_none() {
        return Err(MutinyError::PeerInfoParseFailed).context(
            "incorrectly formatted peer info. Should be formatted as: `pubkey@host:port`",
        )?;
    }

    let peer_addr = peer_addr_str
        .unwrap()
        .to_socket_addrs()
        .map(|mut r| r.next());
    if peer_addr.is_err() || peer_addr.as_ref().unwrap().is_none() {
        return Err(MutinyError::PeerInfoParseFailed)
            .context("couldn't parse pubkey@host:port into a socket address")?;
    }

    let pubkey = PublicKey::from_str(pubkey.unwrap());
    if pubkey.is_err() {
        return Err(MutinyError::PeerInfoParseFailed)
            .context("unable to parse given pubkey for node")?;
    }

    Ok((pubkey.unwrap(), peer_addr.unwrap().unwrap()))
}

#[cfg(test)]
mod tests {
    use crate::test::*;
    use std::{net::SocketAddr, str::FromStr};

    use crate::node::parse_peer_info;

    use secp256k1::PublicKey;
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

        let (peer_pubkey, peer_addr) = parse_peer_info(format!("{}@{addr}", pub_key)).unwrap();

        assert_eq!(pub_key, peer_pubkey);
        assert_eq!(addr.parse::<SocketAddr>().unwrap(), peer_addr);
    }
}
