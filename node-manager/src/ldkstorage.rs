use crate::chain::MutinyChain;
use crate::error;
use crate::error::MutinyError;
use crate::event::PaymentInfo;
use crate::localstorage::MutinyBrowserStorage;
use crate::logging::MutinyLogger;
use crate::node::ChainMonitor;
use crate::node::NetworkGraph;
use crate::utils::hex_str;
use crate::wallet::esplora_from_network;
use anyhow::anyhow;
use bitcoin::BlockHash;
use bitcoin::Network;
use futures::{try_join, TryFutureExt};
use lightning::chain::channelmonitor::ChannelMonitor;
use lightning::chain::keysinterface::InMemorySigner;
use lightning::chain::keysinterface::PhantomKeysManager;
use lightning::chain::keysinterface::{KeysInterface, Sign};
use lightning::chain::BestBlock;
use lightning::ln::channelmanager::{
    self, ChainParameters, ChannelManager as LdkChannelManager, ChannelManagerReadArgs,
};
use lightning::ln::PaymentHash;
use lightning::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringParameters};
use lightning::util::config::UserConfig;
use lightning::util::persist::KVStorePersister;
use lightning::util::ser::{ReadableArgs, Writeable};
use log::error;
use std::collections::HashMap;
use std::io;
use std::io::Cursor;
use std::ops::Deref;
use std::sync::Arc;

const NETWORK_KEY: &str = "network";
const PROB_SCORER_KEY: &str = "prob_scorer";
const CHANNEL_MANAGER_KEY: &str = "manager";
const MONITORS_PREFIX_KEY: &str = "monitors/";
const PAYMENT_INBOUND_PREFIX_KEY: &str = "payment_inbound/";
const PAYMENT_OUTBOUND_PREFIX_KEY: &str = "payment_outbound/";

pub(crate) type PhantomChannelManager = LdkChannelManager<
    InMemorySigner,
    Arc<ChainMonitor>,
    Arc<MutinyChain>,
    Arc<PhantomKeysManager>,
    Arc<MutinyChain>,
    Arc<MutinyLogger>,
>;

pub struct MutinyNodePersister {
    node_id: String,
    storage: MutinyBrowserStorage,
}

impl MutinyNodePersister {
    pub fn new(node_id: String, storage: MutinyBrowserStorage) -> Self {
        MutinyNodePersister { node_id, storage }
    }

    fn get_key(&self, key: &str) -> String {
        format!("{}_{}", key, self.node_id)
    }

    // name this param _key so it is not confused with the key
    // that has the concatenated node_id
    fn read_value(&self, _key: &str) -> Result<Vec<u8>, MutinyError> {
        let key = self.get_key(_key);
        self.storage.get(key).map_err(MutinyError::read_err)
    }

    pub fn persist_network_graph(&self, network_graph: &NetworkGraph) -> io::Result<()> {
        self.persist(NETWORK_KEY, network_graph)
    }

    pub fn read_network_graph(
        &self,
        genesis_hash: BlockHash,
        logger: Arc<MutinyLogger>,
    ) -> NetworkGraph {
        match self.read_value(NETWORK_KEY) {
            Ok(kv_value) => {
                let mut readable_kv_value = Cursor::new(kv_value);
                match NetworkGraph::read(&mut readable_kv_value, logger.clone()) {
                    Ok(graph) => graph,
                    Err(e) => {
                        error!("Error reading NetworkGraph: {}", e.to_string());
                        NetworkGraph::new(genesis_hash, logger)
                    }
                }
            }
            Err(_) => NetworkGraph::new(genesis_hash, logger),
        }
    }

    pub fn persist_scorer(
        &self,
        scorer: &ProbabilisticScorer<Arc<NetworkGraph>, Arc<MutinyLogger>>,
    ) -> io::Result<()> {
        self.persist(PROB_SCORER_KEY, scorer)
    }

    pub fn read_scorer(
        &self,
        graph: Arc<NetworkGraph>,
        logger: Arc<MutinyLogger>,
    ) -> ProbabilisticScorer<Arc<NetworkGraph>, Arc<MutinyLogger>> {
        let params = ProbabilisticScoringParameters::default();

        match self.read_value(PROB_SCORER_KEY) {
            Ok(kv_value) => {
                let mut readable_kv_value = Cursor::new(kv_value);
                let args = (params.clone(), Arc::clone(&graph), Arc::clone(&logger));
                match ProbabilisticScorer::read(&mut readable_kv_value, args) {
                    Ok(scorer) => scorer,
                    Err(e) => {
                        error!("Error reading ProbabilisticScorer: {}", e.to_string());
                        ProbabilisticScorer::new(params, graph, logger)
                    }
                }
            }
            Err(_) => ProbabilisticScorer::new(params, graph, logger),
        }
    }

    pub fn read_channel_monitors<Signer: Sign, K: Deref>(
        &self,
        keys_manager: K,
    ) -> Result<Vec<(BlockHash, ChannelMonitor<Signer>)>, io::Error>
    where
        K::Target: KeysInterface<Signer = Signer> + Sized,
    {
        let mut res = Vec::new();

        // Get all the channel monitor buffers that exist for this node
        let suffix = self.node_id.as_str();
        let channel_monitor_list: HashMap<String, Vec<u8>> =
            self.storage.scan(MONITORS_PREFIX_KEY, Some(suffix));

        // TODO probably could use a fold here instead
        for (_, data) in channel_monitor_list {
            let mut buffer = Cursor::new(data);
            match <(BlockHash, ChannelMonitor<Signer>)>::read(&mut buffer, &*keys_manager) {
                Ok((blockhash, channel_monitor)) => {
                    res.push((blockhash, channel_monitor));
                }
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Failed to deserialize ChannelMonitor: {}", e),
                    ));
                }
            }
        }

        Ok(res)
    }

    pub async fn read_channel_manager(
        &self,
        network: Network,
        chain_monitor: Arc<ChainMonitor>,
        mutiny_chain: Arc<MutinyChain>,
        mutiny_logger: Arc<MutinyLogger>,
        keys_manager: Arc<PhantomKeysManager>,
        mut channel_monitors: Vec<(BlockHash, ChannelMonitor<InMemorySigner>)>,
    ) -> Result<(PhantomChannelManager, bool), MutinyError> {
        match self.read_value(CHANNEL_MANAGER_KEY) {
            Ok(kv_value) => {
                let mut channel_monitor_mut_references = Vec::new();
                for (_, channel_monitor) in channel_monitors.iter_mut() {
                    channel_monitor_mut_references.push(channel_monitor);
                }
                let read_args = ChannelManagerReadArgs::new(
                    keys_manager,
                    mutiny_chain.clone(),
                    chain_monitor,
                    mutiny_chain,
                    mutiny_logger,
                    UserConfig::default(),
                    channel_monitor_mut_references,
                );
                let mut readable_kv_value = Cursor::new(kv_value);
                let Ok((_, channel_manager)) = <(BlockHash, PhantomChannelManager)>::read(&mut readable_kv_value, read_args) else {
                    return Err(MutinyError::ReadError { source: error::MutinyStorageError::Other(anyhow!("could not read manager")) })
                };
                Ok((channel_manager, true))
            }
            Err(_) => {
                // no key manager stored, start a new one
                let blockchain = esplora_from_network(network);

                let height_future = blockchain
                    .get_height()
                    .map_err(|_| error::MutinyError::ChainAccessFailed);
                let hash_future = blockchain
                    .get_tip_hash()
                    .map_err(|_| error::MutinyError::ChainAccessFailed);
                let (height, hash) = try_join!(height_future, hash_future)?;
                let chain_params = ChainParameters {
                    network,
                    best_block: BestBlock::new(hash, height),
                };

                let fresh_channel_manager = channelmanager::ChannelManager::new(
                    mutiny_chain.clone(),
                    chain_monitor,
                    mutiny_chain,
                    mutiny_logger,
                    keys_manager,
                    UserConfig::default(),
                    chain_params,
                );

                Ok((fresh_channel_manager, false))
            }
        }
    }

    pub(crate) fn persist_payment_info(
        &self,
        payment_hash: PaymentHash,
        payment_info: PaymentInfo,
        inbound: bool,
    ) -> io::Result<()> {
        self.storage
            .set(payment_key(inbound, payment_hash), payment_info)
            .map_err(io::Error::other)
    }

    pub(crate) fn read_payment_info(
        &self,
        payment_hash: PaymentHash,
        inbound: bool,
    ) -> Option<PaymentInfo> {
        let key = self.get_key(payment_key(inbound, payment_hash).as_str());
        let deserialized_value: Result<PaymentInfo, MutinyError> =
            self.storage.get(key).map_err(MutinyError::read_err);
        deserialized_value.ok()
    }

    pub(crate) fn list_payment_info(&self, inbound: bool) -> Vec<(String, PaymentInfo)> {
        let prefix = match inbound {
            true => PAYMENT_INBOUND_PREFIX_KEY,
            false => PAYMENT_OUTBOUND_PREFIX_KEY,
        };
        let map: HashMap<String, PaymentInfo> = self.storage.scan(prefix, None);

        map.into_iter().collect()
    }
}

fn payment_key(inbound: bool, payment_hash: PaymentHash) -> String {
    let key = if inbound {
        format!(
            "{}{}",
            PAYMENT_INBOUND_PREFIX_KEY,
            String::as_str(&hex_str(&payment_hash.0))
        )
    } else {
        format!(
            "{}{}",
            PAYMENT_OUTBOUND_PREFIX_KEY,
            String::as_str(&hex_str(&payment_hash.0))
        )
    };
    key
}

impl KVStorePersister for MutinyNodePersister {
    fn persist<W: Writeable>(&self, key: &str, object: &W) -> io::Result<()> {
        let key_with_node = self.get_key(key);
        self.storage
            .set(key_with_node, object.encode())
            .map_err(io::Error::other)
    }
}
