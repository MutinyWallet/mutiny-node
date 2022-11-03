use std::io;
use std::io::Cursor;
use std::ops::Deref;
use std::sync::Arc;

use bitcoin::BlockHash;
use lightning::chain::channelmonitor::ChannelMonitor;
use lightning::chain::keysinterface::{KeysInterface, Sign};
use lightning::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringParameters};
use lightning::util::persist::KVStorePersister;
use lightning::util::ser::{ReadableArgs, Writeable};
use log::error;

use crate::localstorage::MutinyBrowserStorage;
use crate::logging::MutinyLogger;
use crate::node::NetworkGraph;

pub struct MutinyNodePersister {
    node_id: String,
    storage: MutinyBrowserStorage,
}

impl MutinyNodePersister {
    fn get_key(&self, key: &str) -> String {
        format!("{}_{}", key, self.node_id)
    }

    fn read_value(&self, _key: &str) -> Result<Vec<u8>, io::Error> {
        let key = self.get_key(_key);
        self.storage.get(key).map_err(io::Error::other)
    }

    pub fn persist_network_graph(&self, network_graph: &NetworkGraph) -> io::Result<()> {
        self.persist("network", network_graph)
    }

    pub fn read_network_graph(
        &self,
        genesis_hash: BlockHash,
        logger: Arc<MutinyLogger>,
    ) -> NetworkGraph {
        let (already_init, kv_value) = match self.read_value("network") {
            Ok(kv_value) => (!kv_value.is_empty(), kv_value),
            Err(_) => (false, vec![]),
        };

        if already_init {
            let mut readable_kv_value = Cursor::new(kv_value);
            match NetworkGraph::read(&mut readable_kv_value, logger.clone()) {
                Ok(graph) => graph,
                Err(e) => {
                    error!("Error reading NetworkGraph: {}", e.to_string());
                    NetworkGraph::new(genesis_hash, logger)
                }
            }
        } else {
            NetworkGraph::new(genesis_hash, logger)
        }
    }

    pub fn persist_scorer(
        &self,
        scorer: &ProbabilisticScorer<Arc<NetworkGraph>, Arc<MutinyLogger>>,
    ) -> io::Result<()> {
        self.persist("prob_scorer", scorer)
    }

    pub fn read_scorer(
        &self,
        graph: Arc<NetworkGraph>,
        logger: Arc<MutinyLogger>,
    ) -> ProbabilisticScorer<Arc<NetworkGraph>, Arc<MutinyLogger>> {
        let params = ProbabilisticScoringParameters::default();
        let (already_init, kv_value) = match self.read_value("prob_scorer") {
            Ok(kv_value) => (!kv_value.is_empty(), kv_value),
            Err(_) => (false, vec![]),
        };

        if already_init {
            let mut readable_kv_value = Cursor::new(kv_value);
            let args = (params.clone(), Arc::clone(&graph), Arc::clone(&logger));
            match ProbabilisticScorer::read(&mut readable_kv_value, args) {
                Ok(graph) => graph,
                Err(e) => {
                    error!("Error reading ProbabilisticScorer: {}", e.to_string());
                    ProbabilisticScorer::new(params, graph, logger)
                }
            }
        } else {
            ProbabilisticScorer::new(params, graph, logger)
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
        let channel_monitor_list = self.storage.scan("monitors/", Some(suffix));

        // TODO probably could use a fold here instead
        for (_, value) in channel_monitor_list {
            let data = value.to_string();
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
}

impl KVStorePersister for MutinyNodePersister {
    fn persist<W: Writeable>(&self, key: &str, object: &W) -> io::Result<()> {
        let key_with_node = self.get_key(key);
        self.storage
            .set(key_with_node, object.encode())
            .map_err(io::Error::other)
    }
}
