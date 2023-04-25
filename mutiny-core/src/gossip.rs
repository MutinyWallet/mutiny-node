use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::anyhow;
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::Network;
use gloo_utils::format::JsValueSerdeExt;
use lightning::ln::msgs::NodeAnnouncement;
use lightning::routing::gossip::NodeId;
use lightning::routing::scoring::ProbabilisticScoringParameters;
use lightning::util::ser::{ReadableArgs, Writeable};
use log::{debug, error, info, warn};
use reqwest::Client;
use rexie::{ObjectStore, Rexie, Store, TransactionMode};
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::spawn_local;

use crate::error::{MutinyError, MutinyStorageError};
use crate::logging::MutinyLogger;
use crate::node::{NetworkGraph, ProbScorer, RapidGossipSync};
use crate::utils;
use crate::wallet::get_rgs_url;

pub(crate) const GOSSIP_DATABASE_NAME: &str = "gossip";
pub(crate) const GOSSIP_OBJECT_STORE_NAME: &str = "gossip_store";
pub(crate) const LN_PEER_METADATA_STORE_NAME: &str = "ln_peer_store";

pub(crate) const GOSSIP_SYNC_TIME_KEY: &str = "last_sync_timestamp";
pub(crate) const NETWORK_GRAPH_KEY: &str = "network_graph";
pub(crate) const PROB_SCORER_KEY: &str = "prob_scorer";

struct Gossip {
    pub last_sync_timestamp: u32,
    pub network_graph: Arc<NetworkGraph>,
    pub scorer: Option<ProbScorer>,
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

async fn build_gossip_database() -> Result<Rexie, MutinyError> {
    // Create a new database
    let rexie = Rexie::builder(GOSSIP_DATABASE_NAME)
        .version(2)
        .add_object_store(ObjectStore::new(GOSSIP_OBJECT_STORE_NAME))
        .add_object_store(ObjectStore::new(LN_PEER_METADATA_STORE_NAME))
        // Build the database
        .build()
        .await?;

    Ok(rexie)
}

async fn get_gossip_data(
    rexie: &Rexie,
    logger: Arc<MutinyLogger>,
) -> Result<Option<Gossip>, MutinyError> {
    // Create a new read-only transaction
    let transaction = rexie.transaction(&[GOSSIP_OBJECT_STORE_NAME], TransactionMode::ReadOnly)?;

    let store = transaction.store(GOSSIP_OBJECT_STORE_NAME)?;

    // Get the `last_sync_timestamp`
    let last_sync_timestamp_js = store.get(&JsValue::from(GOSSIP_SYNC_TIME_KEY)).await?;

    // If the key doesn't exist, we return None
    if last_sync_timestamp_js.is_null() || last_sync_timestamp_js.is_undefined() {
        return Ok(None);
    }

    let last_sync_timestamp: u32 =
        last_sync_timestamp_js
            .as_f64()
            .ok_or_else(|| MutinyError::ReadError {
                source: MutinyStorageError::Other(anyhow!(
                    "could not read last_sync_timestamp, got {:?}",
                    last_sync_timestamp_js
                )),
            })? as u32;

    // Get the `network_graph`
    let network_graph_js = store.get(&JsValue::from(NETWORK_GRAPH_KEY)).await?;

    // If the key doesn't exist, we return None
    if network_graph_js.is_null() || network_graph_js.is_undefined() {
        return Ok(None);
    }

    let network_graph_str: String = network_graph_js.into_serde()?;
    let network_graph_bytes: Vec<u8> = Vec::from_hex(&network_graph_str)?;
    let mut readable_bytes = lightning::io::Cursor::new(network_graph_bytes);
    let network_graph = Arc::new(NetworkGraph::read(&mut readable_bytes, logger.clone())?);

    debug!("Got network graph, getting scorer...");

    // Get the probabilistic scorer
    let prob_scorer_js = store.get(&JsValue::from(PROB_SCORER_KEY)).await?;

    // If the key doesn't exist, we return None for the scorer
    if prob_scorer_js.is_null() || prob_scorer_js.is_undefined() {
        let gossip = Gossip {
            last_sync_timestamp,
            network_graph,
            scorer: None,
        };
        return Ok(Some(gossip));
    }

    let prob_scorer_str: String = prob_scorer_js.into_serde()?;
    let prob_scorer_bytes: Vec<u8> = Vec::from_hex(&prob_scorer_str)?;
    let mut readable_bytes = lightning::io::Cursor::new(prob_scorer_bytes);
    let params = ProbabilisticScoringParameters::default();
    let args = (params, Arc::clone(&network_graph), Arc::clone(&logger));
    let scorer = ProbScorer::read(&mut readable_bytes, args);

    if let Err(e) = scorer.as_ref() {
        warn!("Could not read probabilistic scorer from database: {e}");
    }

    let gossip = Gossip {
        last_sync_timestamp,
        network_graph,
        scorer: scorer.ok(),
    };

    transaction.done().await?;

    Ok(Some(gossip))
}

async fn write_gossip_data(
    rexie: &Rexie,
    last_sync_timestamp: u32,
    network_graph: &NetworkGraph,
) -> Result<(), MutinyError> {
    // Create a new read-write transaction
    let transaction = rexie.transaction(&[GOSSIP_OBJECT_STORE_NAME], TransactionMode::ReadWrite)?;

    let store = transaction.store(GOSSIP_OBJECT_STORE_NAME)?;

    // Save the last sync timestamp
    store
        .put(
            &JsValue::from(last_sync_timestamp),
            Some(&JsValue::from(GOSSIP_SYNC_TIME_KEY)),
        )
        .await?;

    // Save the network graph
    let network_graph_str = network_graph.encode().to_hex();
    write_network_graph_to_store(&store, &network_graph_str).await?;

    // Waits for the transaction to complete
    transaction.done().await?;

    Ok(())
}

/// Write the Network Graph to indexedDB
/// This is done in a spawn_local so that it can be done for sync functions
pub fn persist_network_graph(network_graph: &NetworkGraph) -> Result<(), lightning::io::Error> {
    let network_graph_str = network_graph.encode().to_hex();
    spawn_local(async move {
        write_network_graph(&network_graph_str)
            .await
            .expect("Failed to write network graph")
    });
    Ok(())
}

async fn write_network_graph(network_graph_str: &str) -> Result<(), MutinyError> {
    let rexie = build_gossip_database().await?;
    // Create a new read-write transaction
    let transaction = rexie.transaction(&[GOSSIP_OBJECT_STORE_NAME], TransactionMode::ReadWrite)?;

    let store = transaction.store(GOSSIP_OBJECT_STORE_NAME)?;

    // Save the network graph
    write_network_graph_to_store(&store, network_graph_str).await?;

    // Waits for the transaction to complete
    transaction.done().await?;

    Ok(())
}

/// Write the Probabilistic Scorer to indexedDB
/// This is done in a spawn_local so that it can be done for sync functions
pub fn persist_scorer(scorer: &utils::Mutex<ProbScorer>) -> Result<(), lightning::io::Error> {
    let scorer_str = scorer.encode().to_hex();
    spawn_local(async move {
        write_scorer(&scorer_str)
            .await
            .expect("Failed to write scorer")
    });
    Ok(())
}

async fn write_scorer(scorer_str: &str) -> Result<(), MutinyError> {
    let rexie = build_gossip_database().await?;
    // Create a new read-write transaction
    let transaction = rexie.transaction(&[GOSSIP_OBJECT_STORE_NAME], TransactionMode::ReadWrite)?;

    let store = transaction.store(GOSSIP_OBJECT_STORE_NAME)?;

    // Save the scorer
    write_scorer_to_store(&store, scorer_str).await?;

    // Waits for the transaction to complete
    transaction.done().await?;

    Ok(())
}

async fn write_network_graph_to_store(
    store: &Store,
    network_graph_str: &str,
) -> Result<(), MutinyError> {
    let network_graph_js = JsValue::from_serde(network_graph_str)?;
    store
        .put(&network_graph_js, Some(&JsValue::from(NETWORK_GRAPH_KEY)))
        .await?;

    Ok(())
}

async fn write_scorer_to_store(store: &Store, scorer_str: &str) -> Result<(), MutinyError> {
    let scorer_js = JsValue::from_serde(scorer_str)?;
    store
        .put(&scorer_js, Some(&JsValue::from(PROB_SCORER_KEY)))
        .await?;

    Ok(())
}

pub async fn get_gossip_sync(
    user_rgs_url: Option<String>,
    network: Network,
    logger: Arc<MutinyLogger>,
) -> Result<(RapidGossipSync, ProbScorer), MutinyError> {
    let rexie = build_gossip_database().await?;

    // if we error out, we just use the default gossip data
    let gossip_data = match get_gossip_data(&rexie, logger.clone()).await {
        Ok(Some(gossip_data)) => gossip_data,
        Ok(None) => Gossip::new(network, logger.clone()),
        Err(e) => {
            error!("Error getting gossip data from storage: {e}, re-syncing gossip...");
            Gossip::new(network, logger.clone())
        }
    };

    debug!(
        "Previous gossip sync timestamp: {}",
        gossip_data.last_sync_timestamp
    );

    // get network graph
    let gossip_sync = RapidGossipSync::new(gossip_data.network_graph.clone(), logger.clone());

    let prob_scorer = match gossip_data.scorer {
        Some(scorer) => scorer,
        None => {
            let params = ProbabilisticScoringParameters::default();
            ProbScorer::new(params, gossip_data.network_graph.clone(), logger)
        }
    };

    let now = utils::now().as_secs();

    // remove stale channels
    gossip_sync
        .network_graph()
        .remove_stale_channels_and_tracking_with_time(now);

    // if the last sync was less than 24 hours ago, we don't need to sync
    let time_since_sync = now - gossip_data.last_sync_timestamp as u64;
    if time_since_sync < 86_400 {
        return Ok((gossip_sync, prob_scorer));
    };

    let rgs_url = get_rgs_url(network, user_rgs_url, Some(gossip_data.last_sync_timestamp));
    info!("RGS URL: {}", rgs_url);

    let fetch_result = fetch_updated_gossip(
        rgs_url,
        now,
        gossip_data.last_sync_timestamp,
        &gossip_sync,
        &rexie,
    )
    .await;

    if fetch_result.is_err() {
        warn!("Failed to fetch updated gossip, using default gossip data");
    }

    Ok((gossip_sync, prob_scorer))
}

async fn fetch_updated_gossip(
    rgs_url: String,
    now: u64,
    last_sync_timestamp: u32,
    gossip_sync: &RapidGossipSync,
    rexie: &Rexie,
) -> Result<(), MutinyError> {
    let http_client = Client::builder()
        .build()
        .map_err(|_| MutinyError::RapidGossipSyncError)?;
    let rgs_response = http_client
        .get(rgs_url)
        .send()
        .await
        .map_err(|_| MutinyError::RapidGossipSyncError)?;

    let rgs_data = rgs_response
        .bytes()
        .await
        .map_err(|_| MutinyError::RapidGossipSyncError)?
        .to_vec();

    let new_last_sync_timestamp_result =
        gossip_sync.update_network_graph_no_std(&rgs_data, Some(now))?;

    info!("RGS sync result: {}", new_last_sync_timestamp_result);

    // save the network graph if has been updated
    if new_last_sync_timestamp_result != last_sync_timestamp {
        write_gossip_data(
            rexie,
            new_last_sync_timestamp_result,
            gossip_sync.network_graph(),
        )
        .await?;
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

    pub(crate) fn merge_opt(&self, other: &Option<LnPeerMetadata>) -> LnPeerMetadata {
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
        let mut nodes: Vec<String> = primary
            .nodes
            .into_iter()
            .chain(secondary.nodes.into_iter())
            .collect();

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
            color: Some(value.contents.rgb.to_hex()),
            label: None,
            timestamp: Some(value.contents.timestamp),
            nodes: vec![],
        }
    }
}

pub(crate) async fn read_peer_info(
    node_id: &NodeId,
) -> Result<Option<LnPeerMetadata>, MutinyError> {
    let rexie = build_gossip_database().await?;
    // Create a new read-write transaction
    let transaction =
        rexie.transaction(&[LN_PEER_METADATA_STORE_NAME], TransactionMode::ReadOnly)?;
    let store = transaction.store(LN_PEER_METADATA_STORE_NAME)?;

    let key = JsValue::from(node_id.to_string());

    let json: JsValue = store.get(&key).await?;
    let data: Option<LnPeerMetadata> = json.into_serde()?;

    // Waits for the transaction to complete
    transaction.done().await?;

    Ok(data)
}

pub(crate) async fn get_all_peers() -> Result<HashMap<NodeId, LnPeerMetadata>, MutinyError> {
    let rexie = build_gossip_database().await?;
    // Create a new read-write transaction
    let transaction =
        rexie.transaction(&[LN_PEER_METADATA_STORE_NAME], TransactionMode::ReadOnly)?;
    let store = transaction.store(LN_PEER_METADATA_STORE_NAME)?;

    let mut peers = HashMap::new();

    let all_json = store.get_all(None, None, None, None).await?;
    for (key, value) in all_json {
        let node_id = NodeId::from_str(&key.as_string().unwrap())?;
        let data: Option<LnPeerMetadata> = value.into_serde()?;

        if let Some(peer_metadata) = data {
            peers.insert(node_id, peer_metadata);
        }
    }

    // Waits for the transaction to complete
    transaction.done().await?;

    Ok(peers)
}

pub(crate) async fn save_peer_connection_info(
    our_node_id: &str,
    node_id: &NodeId,
    connection_string: &str,
    label: Option<String>,
) -> Result<(), MutinyError> {
    let rexie = build_gossip_database().await?;
    // Create a new read-write transaction
    let transaction =
        rexie.transaction(&[LN_PEER_METADATA_STORE_NAME], TransactionMode::ReadWrite)?;
    let store = transaction.store(LN_PEER_METADATA_STORE_NAME)?;

    let key = JsValue::from(node_id.to_string());

    let current_js: JsValue = store.get(&key).await?;
    let current: Option<LnPeerMetadata> = current_js.into_serde()?;

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

    let json = JsValue::from_serde(&new_info)?;
    store.put(&json, Some(&key)).await?;

    // Waits for the transaction to complete
    transaction.done().await?;

    Ok(())
}

pub(crate) async fn set_peer_label(
    node_id: &NodeId,
    label: Option<String>,
) -> Result<(), MutinyError> {
    // We filter out empty labels
    let label = label.filter(|l| !l.is_empty());
    let rexie = build_gossip_database().await?;
    // Create a new read-write transaction
    let transaction =
        rexie.transaction(&[LN_PEER_METADATA_STORE_NAME], TransactionMode::ReadWrite)?;
    let store = transaction.store(LN_PEER_METADATA_STORE_NAME)?;

    let key = JsValue::from(node_id.to_string());

    let current_js: JsValue = store.get(&key).await?;
    let current: Option<LnPeerMetadata> = current_js.into_serde()?;

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

    let json = JsValue::from_serde(&new_info)?;
    store.put(&json, Some(&key)).await?;

    // Waits for the transaction to complete
    transaction.done().await?;

    Ok(())
}

pub(crate) async fn delete_peer_info(uuid: &str, node_id: &NodeId) -> Result<(), MutinyError> {
    let rexie = build_gossip_database().await?;
    // Create a new read-write transaction
    let transaction =
        rexie.transaction(&[LN_PEER_METADATA_STORE_NAME], TransactionMode::ReadWrite)?;
    let store = transaction.store(LN_PEER_METADATA_STORE_NAME)?;

    let key = JsValue::from(node_id.to_string());

    let current_js: JsValue = store.get(&key).await?;
    let current: Option<LnPeerMetadata> = current_js.into_serde()?;

    if let Some(mut current) = current {
        current.nodes.retain(|n| n != uuid);
        if current.nodes.is_empty() {
            store.delete(&key).await?;
        } else {
            let json = JsValue::from_serde(&current)?;
            store.put(&json, Some(&key)).await?;
        }
    }

    // Waits for the transaction to complete
    transaction.done().await?;

    Ok(())
}

pub(crate) async fn save_ln_peer_info(
    node_id: &NodeId,
    info: &LnPeerMetadata,
) -> Result<(), MutinyError> {
    let rexie = build_gossip_database().await?;
    // Create a new read-write transaction
    let transaction =
        rexie.transaction(&[LN_PEER_METADATA_STORE_NAME], TransactionMode::ReadWrite)?;
    let store = transaction.store(LN_PEER_METADATA_STORE_NAME)?;

    let key = JsValue::from(node_id.to_string());

    let current_js: JsValue = store.get(&key).await?;
    let current: Option<LnPeerMetadata> = current_js.into_serde()?;

    let new_info = info.merge_opt(&current);

    // if the new info is different than the current info, we should to save it
    if !current.is_some_and(|c| c == new_info) {
        let json = JsValue::from_serde(&new_info)?;
        store.put(&json, Some(&key)).await?;
    }

    // Waits for the transaction to complete
    transaction.done().await?;

    Ok(())
}

#[cfg(test)]
pub fn get_dummy_gossip(
    _user_rgs_url: Option<String>,
    network: Network,
    logger: Arc<MutinyLogger>,
) -> (RapidGossipSync, ProbScorer) {
    let network_graph = Arc::new(NetworkGraph::new(network, logger.clone()));
    let gossip_sync = RapidGossipSync::new(network_graph.clone(), logger.clone());
    let scorer = ProbScorer::new(
        ProbabilisticScoringParameters::default(),
        network_graph,
        logger,
    );

    (gossip_sync, scorer)
}

#[cfg(test)]
mod test {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use uuid::Uuid;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    use crate::test_utils::*;

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
        // delete the database if it exists
        Rexie::delete(GOSSIP_DATABASE_NAME).await.unwrap();

        let rexie = build_gossip_database().await.unwrap();

        let logger = Arc::new(MutinyLogger::default());
        let _gossip_sync = get_gossip_sync(None, Network::Testnet, logger.clone())
            .await
            .unwrap();

        let data = get_gossip_data(&rexie, logger).await.unwrap();

        assert!(data.is_some());
        assert!(data.unwrap().last_sync_timestamp > 0);

        cleanup_gossip_test().await;
    }

    #[test]
    // hack to disable this test
    #[cfg(feature = "ignored_tests")]
    async fn test_peer_info() {
        // delete the database if it exists
        Rexie::delete(GOSSIP_DATABASE_NAME).await.unwrap();

        let (node_id, data) = dummy_peer_info();

        save_ln_peer_info(&node_id, &data).await.unwrap();

        let read = read_peer_info(&node_id).await.unwrap();

        assert!(read.is_some());
        assert_eq!(read.unwrap(), data);

        delete_peer_info(data.nodes.first().unwrap(), &node_id)
            .await
            .unwrap();

        let read = read_peer_info(&node_id).await.unwrap();

        assert!(read.is_none());

        cleanup_gossip_test().await;
    }

    #[test]
    async fn test_delete_label() {
        // delete the database if it exists
        Rexie::delete(GOSSIP_DATABASE_NAME).await.unwrap();

        let (node_id, data) = dummy_peer_info();

        save_ln_peer_info(&node_id, &data).await.unwrap();

        // remove the label
        set_peer_label(&node_id, None).await.unwrap();

        let read = read_peer_info(&node_id).await.unwrap();

        let expected = LnPeerMetadata {
            label: None,
            ..data
        };

        assert!(read.is_some());
        assert_eq!(read.unwrap(), expected);

        cleanup_gossip_test().await;
    }
}
