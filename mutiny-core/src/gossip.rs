use crate::{
    node::decay_params,
    scorer::{HubPreferentialScorer, ProbScorer},
};
use bitcoin::hashes::hex::FromHex;
use bitcoin::Network;
use lightning::ln::msgs::NodeAnnouncement;
use lightning::routing::gossip::NodeId;
use lightning::util::logger::Logger;
use lightning::util::ser::ReadableArgs;
use lightning::{log_debug, log_error, log_info, log_warn};
use reqwest::Client;
use reqwest::{Method, Url};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use crate::logging::MutinyLogger;
use crate::node::{NetworkGraph, RapidGossipSync};
use crate::storage::MutinyStorage;
use crate::utils;
use crate::{auth::MutinyAuthClient, error::MutinyError};

pub(crate) const LN_PEER_METADATA_KEY_PREFIX: &str = "ln_peer/";
pub const GOSSIP_SYNC_TIME_KEY: &str = "last_sync_timestamp";
pub const NETWORK_GRAPH_KEY: &str = "network_graph";
pub const PROB_SCORER_KEY: &str = "prob_scorer";

struct Gossip {
    pub last_sync_timestamp: u32,
    pub network_graph: Arc<NetworkGraph>,
    pub scorer: Option<HubPreferentialScorer>,
}

impl Gossip {
    pub fn new(network: Network, logger: Arc<MutinyLogger>) -> Self {
        Self {
            last_sync_timestamp: 0,
            network_graph: Arc::new(NetworkGraph::new(network, logger)),
            scorer: None,
        }
    }
}

#[allow(dead_code)]
async fn get_scorer(
    storage: &impl MutinyStorage,
    network_graph: Arc<NetworkGraph>,
    logger: Arc<MutinyLogger>,
) -> Result<Option<HubPreferentialScorer>, MutinyError> {
    if let Some(prob_scorer_str) = storage.get_data::<String>(PROB_SCORER_KEY)? {
        let prob_scorer_bytes: Vec<u8> = Vec::from_hex(&prob_scorer_str)?;
        let mut readable_bytes = lightning::io::Cursor::new(prob_scorer_bytes);
        let params = decay_params();
        let args = (params, Arc::clone(&network_graph), Arc::clone(&logger));
        let scorer = ProbScorer::read(&mut readable_bytes, args)?;
        Ok(Some(HubPreferentialScorer::new(scorer)))
    } else {
        Ok(None)
    }
}

#[allow(dead_code)]
async fn get_gossip_data(
    storage: &impl MutinyStorage,
    logger: Arc<MutinyLogger>,
) -> Result<Option<Gossip>, MutinyError> {
    // Get the `last_sync_timestamp`
    let last_sync_timestamp: u32 = match storage.get_data(GOSSIP_SYNC_TIME_KEY)? {
        Some(last_sync_timestamp) => last_sync_timestamp,
        None => return Ok(None),
    };

    // Get the `network_graph`
    let network_graph: Arc<NetworkGraph> = match storage.get_data::<String>(NETWORK_GRAPH_KEY)? {
        Some(network_graph_str) => {
            let network_graph_bytes: Vec<u8> = Vec::from_hex(&network_graph_str)?;
            let mut readable_bytes = lightning::io::Cursor::new(network_graph_bytes);
            Arc::new(NetworkGraph::read(&mut readable_bytes, logger.clone())?)
        }
        None => return Ok(None),
    };

    log_debug!(logger, "Got network graph, getting scorer...");

    let scorer = get_scorer(storage, network_graph.clone(), logger.clone()).await?;

    if scorer.is_none() {
        log_warn!(logger, "Could not read probabilistic scorer from database");
    }

    let gossip = Gossip {
        last_sync_timestamp,
        network_graph,
        scorer,
    };

    Ok(Some(gossip))
}

/// Scorer is the scorer that gets pulled remotely
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scorer {
    pub value: String,
}

pub async fn get_remote_scorer_bytes(
    auth_client: &MutinyAuthClient,
    base_url: &str,
) -> Result<Vec<u8>, MutinyError> {
    let url = Url::parse(&format!("{}/v1/scorer", base_url))
        .map_err(|_| MutinyError::ConnectionFailed)?;

    let response = auth_client
        .request(Method::GET, url, None)
        .await
        .map_err(|_| MutinyError::ConnectionFailed)?;

    let scorer: Scorer = response
        .json()
        .await
        .map_err(|_| MutinyError::ConnectionFailed)?;

    let decoded = base64::decode(scorer.value).map_err(|_| MutinyError::ConnectionFailed)?;
    Ok(decoded)
}

fn write_gossip_data(
    storage: &impl MutinyStorage,
    last_sync_timestamp: u32,
    _network_graph: &NetworkGraph,
) -> Result<(), MutinyError> {
    // Save the last sync timestamp
    storage.set_data(GOSSIP_SYNC_TIME_KEY.to_string(), last_sync_timestamp, None)?;

    // Save the network graph
    // skip for now, we don't read it currently
    // storage.set_data(NETWORK_GRAPH_KEY, network_graph.encode().to_hex(), None)?;

    Ok(())
}

pub async fn get_gossip_sync(
    _storage: &impl MutinyStorage,
    remote_scorer_url: Option<String>,
    auth_client: Option<Arc<MutinyAuthClient>>,
    network: Network,
    logger: Arc<MutinyLogger>,
) -> Result<(RapidGossipSync, HubPreferentialScorer), MutinyError> {
    // Always get default gossip until fixed:
    // https://github.com/lightningdevkit/rapid-gossip-sync-server/issues/45
    let mut gossip_data = Gossip::new(network, logger.clone());

    log_debug!(
        &logger,
        "Previous gossip sync timestamp: {}",
        gossip_data.last_sync_timestamp
    );

    // get network graph
    let gossip_sync = RapidGossipSync::new(gossip_data.network_graph.clone(), logger.clone());

    // Try to get remote scorer if remote_scorer_url and auth_client are available
    if let (Some(url), Some(client)) = (remote_scorer_url, &auth_client) {
        match get_remote_scorer_bytes(client, &url).await {
            Ok(scorer_bytes) => {
                let mut readable_bytes = lightning::io::Cursor::new(scorer_bytes);
                let params = decay_params();
                let args = (
                    params,
                    Arc::clone(&gossip_data.network_graph),
                    Arc::clone(&logger),
                );
                if let Ok(remote_scorer) = ProbScorer::read(&mut readable_bytes, args) {
                    log_debug!(logger, "retrieved remote scorer");
                    let remote_scorer = HubPreferentialScorer::new(remote_scorer);
                    gossip_data.scorer = Some(remote_scorer);
                } else {
                    log_error!(
                        logger,
                        "failed to parse remote scorer, keeping the local one"
                    );
                }
            }
            Err(_) => {
                log_error!(
                    logger,
                    "failed to retrieve remote scorer, keeping the local one"
                );
            }
        }
    }

    let prob_scorer = match gossip_data.scorer {
        Some(scorer) => scorer,
        None => {
            let params = decay_params();
            let scorer = ProbScorer::new(params, gossip_data.network_graph.clone(), logger.clone());
            HubPreferentialScorer::new(scorer)
        }
    };

    Ok((gossip_sync, prob_scorer))
}

pub(crate) async fn fetch_updated_gossip(
    rgs_url: String,
    now: u64,
    last_sync_timestamp: u32,
    gossip_sync: &RapidGossipSync,
    storage: &impl MutinyStorage,
    logger: &MutinyLogger,
) -> Result<(), MutinyError> {
    let http_client = Client::builder()
        .build()
        .map_err(|_| MutinyError::RapidGossipSyncError)?;

    let request = http_client
        .get(&rgs_url)
        .build()
        .map_err(|_| MutinyError::RapidGossipSyncError)?;

    let rgs_response = utils::fetch_with_timeout(&http_client, request).await?;
    let rgs_data = rgs_response
        .bytes()
        .await
        .map_err(|_| MutinyError::RapidGossipSyncError)?
        .to_vec();

    let new_last_sync_timestamp_result =
        gossip_sync.update_network_graph_no_std(&rgs_data, Some(now))?;

    log_info!(
        logger,
        "RGS sync result: {}",
        new_last_sync_timestamp_result
    );

    // save the network graph if has been updated
    if new_last_sync_timestamp_result != last_sync_timestamp {
        write_gossip_data(
            storage,
            new_last_sync_timestamp_result,
            gossip_sync.network_graph(),
        )?;
    }

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct LnPeerMetadata {
    /// The node's network address to connect to
    pub connection_string: Option<String>,
    /// The node's alias given from the node announcement
    pub alias: Option<String>,
    /// The node's color given from the node announcement
    pub color: Option<String>,
    /// The label set by the user for this node
    pub label: Option<String>,
    /// The timestamp of when this information was last updated
    pub timestamp: Option<u32>,
    /// Our nodes' uuids that are connected to this node
    #[serde(default)]
    pub nodes: Vec<String>,
}

impl LnPeerMetadata {
    pub(crate) fn with_connection_string(self, connection_string: String) -> Self {
        Self {
            connection_string: Some(connection_string),
            ..self
        }
    }

    pub(crate) fn with_node(&self, node: String) -> Self {
        let mut nodes = self.nodes.clone();

        if !nodes.contains(&node) {
            nodes.push(node);
            nodes.sort();
        }

        Self {
            nodes,
            ..self.clone()
        }
    }

    pub(crate) fn with_label(&self, label: Option<String>) -> Self {
        Self {
            label,
            ..self.clone()
        }
    }

    pub(crate) fn merge_opt(&self, other: Option<&LnPeerMetadata>) -> LnPeerMetadata {
        match other {
            Some(other) => self.merge(other),
            None => self.clone(),
        }
    }

    pub(crate) fn merge(&self, other: &LnPeerMetadata) -> LnPeerMetadata {
        let (primary, secondary) = if self.timestamp > other.timestamp {
            (self.clone(), other.clone())
        } else {
            (other.clone(), self.clone())
        };

        // combine nodes from both
        let mut nodes: Vec<String> = primary.nodes.into_iter().chain(secondary.nodes).collect();

        // remove duplicates
        nodes.sort();
        nodes.dedup();

        Self {
            connection_string: primary.connection_string.or(secondary.connection_string),
            alias: primary.alias.or(secondary.alias),
            color: primary.color.or(secondary.color),
            label: primary.label.or(secondary.label),
            timestamp: primary.timestamp.or(secondary.timestamp),
            nodes,
        }
    }
}

impl From<NodeAnnouncement> for LnPeerMetadata {
    fn from(value: NodeAnnouncement) -> Self {
        Self {
            connection_string: None, // todo get from addresses
            alias: Some(value.contents.alias.to_string()),
            color: Some(hex::encode(value.contents.rgb)),
            label: None,
            timestamp: Some(value.contents.timestamp),
            nodes: vec![],
        }
    }
}

pub(crate) fn read_peer_info(
    storage: &impl MutinyStorage,
    node_id: &NodeId,
) -> Result<Option<LnPeerMetadata>, MutinyError> {
    let key = format!("{LN_PEER_METADATA_KEY_PREFIX}{node_id}");
    storage.get_data(key)
}

pub(crate) fn get_all_peers(
    storage: &impl MutinyStorage,
) -> Result<HashMap<NodeId, LnPeerMetadata>, MutinyError> {
    let mut peers = HashMap::new();

    let all: HashMap<String, LnPeerMetadata> = storage.scan(LN_PEER_METADATA_KEY_PREFIX, None)?;
    for (key, value) in all {
        // remove the prefix from the key
        let key = key.replace(LN_PEER_METADATA_KEY_PREFIX, "");
        let node_id = NodeId::from_str(&key).map_err(|_| MutinyError::InvalidArgumentsError)?;
        peers.insert(node_id, value);
    }
    Ok(peers)
}

pub(crate) fn save_peer_connection_info(
    storage: &impl MutinyStorage,
    our_node_id: &str,
    node_id: &NodeId,
    connection_string: &str,
    label: Option<String>,
) -> Result<(), MutinyError> {
    let key = format!("{LN_PEER_METADATA_KEY_PREFIX}{node_id}");

    let current: Option<LnPeerMetadata> = storage.get_data(&key)?;

    // If there is already some metadata, we add the connection string to it
    // Otherwise we create a new metadata with the connection string
    let new_info = match current {
        Some(current) => current
            .with_connection_string(connection_string.to_string())
            .with_node(our_node_id.to_string()),
        None => LnPeerMetadata {
            connection_string: Some(connection_string.to_string()),
            label,
            timestamp: Some(utils::now().as_secs() as u32),
            nodes: vec![our_node_id.to_string()],
            ..Default::default()
        },
    };

    storage.set_data(key, new_info, None)?;
    Ok(())
}

pub(crate) fn set_peer_label(
    storage: &impl MutinyStorage,
    node_id: &NodeId,
    label: Option<String>,
) -> Result<(), MutinyError> {
    // We filter out empty labels
    let label = label.filter(|l| !l.is_empty());
    let key = format!("{LN_PEER_METADATA_KEY_PREFIX}{node_id}");

    let current: Option<LnPeerMetadata> = storage.get_data(&key)?;

    // If there is already some metadata, we add the label to it
    // Otherwise we create a new metadata with the label
    let new_info = match current {
        Some(current) => current.with_label(label),
        None => LnPeerMetadata {
            label,
            timestamp: Some(utils::now().as_secs() as u32),
            ..Default::default()
        },
    };

    storage.set_data(key, new_info, None)?;
    Ok(())
}

pub(crate) fn delete_peer_info(
    storage: &impl MutinyStorage,
    uuid: &str,
    node_id: &NodeId,
) -> Result<(), MutinyError> {
    let key = format!("{LN_PEER_METADATA_KEY_PREFIX}{node_id}");

    let current: Option<LnPeerMetadata> = storage.get_data(&key)?;

    if let Some(mut current) = current {
        current.nodes.retain(|n| n != uuid);
        if current.nodes.is_empty() {
            storage.delete(&[key])?;
        } else {
            storage.set_data(key, current, None)?;
        }
    }

    Ok(())
}

pub(crate) fn save_ln_peer_info(
    storage: &impl MutinyStorage,
    node_id: &NodeId,
    info: &LnPeerMetadata,
) -> Result<(), MutinyError> {
    let key = format!("{LN_PEER_METADATA_KEY_PREFIX}{node_id}");

    let current: Option<LnPeerMetadata> = storage.get_data(&key)?;

    let new_info = info.merge_opt(current.as_ref());

    // if the new info is different than the current info, we should to save it
    if !current.is_some_and(|c| c == new_info) {
        storage.set_data(key, new_info, None)?;
    }

    Ok(())
}

pub(crate) fn get_rgs_url(
    network: Network,
    user_provided_url: Option<&str>,
    last_sync_time: Option<u32>,
) -> Option<String> {
    let last_sync_time = last_sync_time.unwrap_or(0);
    if let Some(url) = user_provided_url.filter(|url| !url.is_empty()) {
        let url = url.strip_suffix('/').unwrap_or(url);
        Some(format!("{url}/{last_sync_time}"))
    } else {
        match network {
            Network::Bitcoin => Some(format!(
                "https://rapidsync.lightningdevkit.org/snapshot/{last_sync_time}"
            )),
            Network::Testnet => Some(format!(
                "https://rapidsync.lightningdevkit.org/testnet/snapshot/{last_sync_time}"
            )),
            Network::Signet => Some(format!(
                "https://rgs.mutinynet.com/snapshot/{last_sync_time}"
            )),
            Network::Regtest => None,
            net => panic!("Unknown Network {net}!"),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::storage::MemoryStorage;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use uuid::Uuid;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    fn dummy_node_id() -> NodeId {
        let secp = Secp256k1::new();
        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy).unwrap();
        let secret_key = SecretKey::from_slice(&entropy).unwrap();
        let pubkey = secret_key.public_key(&secp);
        NodeId::from_pubkey(&pubkey)
    }

    fn dummy_peer_info() -> (NodeId, LnPeerMetadata) {
        let node_id = dummy_node_id();
        let uuid = Uuid::new_v4().to_string();
        let data = LnPeerMetadata {
            connection_string: Some("example.com:9735".to_string()),
            alias: Some("test alias".to_string()),
            color: Some("123456".to_string()),
            label: Some("test label".to_string()),
            timestamp: Some(utils::now().as_secs() as u32),
            nodes: vec![uuid],
        };

        (node_id, data)
    }

    #[test]
    fn test_merge_peer_info() {
        let no_timestamp = LnPeerMetadata {
            alias: Some("none".to_string()),
            timestamp: None,
            ..Default::default()
        };
        let max_timestamp = LnPeerMetadata {
            alias: Some("max".to_string()),
            timestamp: Some(u32::MAX),
            ..Default::default()
        };
        let min_timestamp = LnPeerMetadata {
            alias: Some("min".to_string()),
            timestamp: Some(u32::MIN),
            ..Default::default()
        };

        assert_eq!(no_timestamp.merge(&max_timestamp), max_timestamp);
        assert_eq!(no_timestamp.merge(&min_timestamp), min_timestamp);
        assert_eq!(max_timestamp.merge(&min_timestamp), max_timestamp);
    }

    #[test]
    // hack to disable this test
    #[cfg(feature = "ignored_tests")]
    async fn test_gossip() {
        crate::test_utils::log!("test RGS sync");
        let storage = MemoryStorage::default();

        let logger = Arc::new(MutinyLogger::default());
        let _gossip_sync = get_gossip_sync(&storage, None, None, Network::Regtest, logger.clone())
            .await
            .unwrap();

        let data = get_gossip_data(&storage, logger).await.unwrap();

        assert!(data.is_some());
        assert!(data.unwrap().last_sync_timestamp > 0);
    }

    #[test]
    fn test_peer_info() {
        let storage = MemoryStorage::default();
        let (node_id, data) = dummy_peer_info();

        save_ln_peer_info(&storage, &node_id, &data).unwrap();

        let read = read_peer_info(&storage, &node_id).unwrap();
        let all = get_all_peers(&storage).unwrap();

        assert!(read.is_some());
        assert_eq!(read.unwrap(), data);
        assert_eq!(all.len(), 1);
        assert_eq!(*all.get(&node_id).unwrap(), data);

        delete_peer_info(&storage, data.nodes.first().unwrap(), &node_id).unwrap();

        let read = read_peer_info(&storage, &node_id).unwrap();

        assert!(read.is_none());
    }

    #[test]
    fn test_delete_label() {
        let storage = MemoryStorage::default();

        let (node_id, data) = dummy_peer_info();

        save_ln_peer_info(&storage, &node_id, &data).unwrap();

        // remove the label
        set_peer_label(&storage, &node_id, None).unwrap();

        let read = read_peer_info(&storage, &node_id).unwrap();

        let expected = LnPeerMetadata {
            label: None,
            ..data
        };

        assert!(read.is_some());
        assert_eq!(read.unwrap(), expected);
    }
}
