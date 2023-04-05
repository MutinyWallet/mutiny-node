use std::sync::Arc;

use anyhow::anyhow;
use bitcoin::Network;
use bitcoin_hashes::hex::{FromHex, ToHex};
use lightning::util::ser::{ReadableArgs, Writeable};
use log::{debug, error, info, warn};
use reqwest::Client;
use rexie::{ObjectStore, Rexie, TransactionMode};
use wasm_bindgen::JsValue;

use crate::error::{MutinyError, MutinyStorageError};
use crate::logging::MutinyLogger;
use crate::node::{NetworkGraph, RapidGossipSync};
use crate::wallet::get_rgs_url;

pub(crate) const GOSSIP_DATABASE_NAME: &str = "gossip";
pub(crate) const GOSSIP_OBJECT_STORE_NAME: &str = "gossip_store";
pub(crate) const GOSSIP_SYNC_TIME_KEY: &str = "last_sync_timestamp";
pub(crate) const NETWORK_GRAPH_KEY: &str = "network_graph";

struct Gossip {
    pub last_sync_timestamp: u32,
    pub network_graph: NetworkGraph,
}

impl Gossip {
    pub fn new(network: Network, logger: Arc<MutinyLogger>) -> Self {
        Self {
            last_sync_timestamp: 0,
            network_graph: NetworkGraph::new(network, logger),
        }
    }
}

async fn build_gossip_database() -> Result<Rexie, MutinyError> {
    // Create a new database
    let rexie = Rexie::builder(GOSSIP_DATABASE_NAME)
        // Set the version of the database to 1.0
        .version(1)
        .add_object_store(ObjectStore::new(GOSSIP_OBJECT_STORE_NAME))
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

    let network_graph_str: String = serde_wasm_bindgen::from_value(network_graph_js)?;
    let network_graph_bytes: Vec<u8> = Vec::from_hex(&network_graph_str)?;
    let mut readable_bytes = lightning::io::Cursor::new(network_graph_bytes);
    let network_graph = NetworkGraph::read(&mut readable_bytes, logger)?;

    let gossip = Gossip {
        last_sync_timestamp,
        network_graph,
    };

    Ok(Some(gossip))
}

async fn write_network_graph(
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
    let network_graph_js = serde_wasm_bindgen::to_value(&network_graph.encode().to_hex())?;
    store
        .put(&network_graph_js, Some(&JsValue::from(NETWORK_GRAPH_KEY)))
        .await?;

    // Waits for the transaction to complete
    transaction.done().await?;

    Ok(())
}

pub async fn get_gossip_sync(
    user_rgs_url: Option<String>,
    network: Network,
    logger: Arc<MutinyLogger>,
) -> Result<RapidGossipSync, MutinyError> {
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
    let network_graph = Arc::new(gossip_data.network_graph);
    let gossip_sync = RapidGossipSync::new(network_graph, logger);

    let now = crate::utils::now().as_secs();

    // if the last sync was less than 24 hours ago, we don't need to sync
    let time_since_sync = now - gossip_data.last_sync_timestamp as u64;
    if time_since_sync < 86_400 {
        return Ok(gossip_sync);
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

    Ok(gossip_sync)
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
        write_network_graph(
            &rexie,
            new_last_sync_timestamp_result,
            &gossip_sync.network_graph(),
        )
        .await?;
    }

    Ok(())
}

#[cfg(test)]
pub fn get_dummy_gossip(
    _user_rgs_url: Option<String>,
    network: Network,
    logger: Arc<MutinyLogger>,
) -> RapidGossipSync {
    let network_graph = Arc::new(NetworkGraph::new(network, logger.clone()));
    RapidGossipSync::new(network_graph, logger)
}

#[cfg(test)]
mod test {
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn test_gossip() {
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
    }
}
