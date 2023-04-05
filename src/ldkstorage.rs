use crate::chain::MutinyChain;
use crate::error::MutinyError;
use crate::event::PaymentInfo;
use crate::fees::MutinyFeeEstimator;
use crate::gossip;
use crate::localstorage::MutinyBrowserStorage;
use crate::logging::MutinyLogger;
use crate::node::{default_user_config, ChainMonitor, ProbScorer};
use crate::node::{NetworkGraph, Router};
use crate::{error, utils};
use anyhow::anyhow;
use bdk::blockchain::EsploraBlockchain;
use bitcoin::BlockHash;
use bitcoin::Network;
use bitcoin_hashes::hex::ToHex;
use futures::{try_join, TryFutureExt};
use lightning::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate};
use lightning::chain::keysinterface::PhantomKeysManager;
use lightning::chain::keysinterface::{InMemorySigner, WriteableEcdsaChannelSigner};
use lightning::chain::BestBlock;
use lightning::ln::channelmanager::{
    self, ChainParameters, ChannelManager as LdkChannelManager, ChannelManagerReadArgs,
};
use lightning::ln::PaymentHash;
use lightning::util::logger::Logger;
use lightning::util::logger::Record;
use lightning::util::persist::Persister;
use lightning::util::ser::{ReadableArgs, Writeable};
use secp256k1::PublicKey;
use std::collections::HashMap;
use std::io;

use lightning::chain;
use lightning::chain::chainmonitor::{MonitorUpdateId, Persist};
use lightning::chain::transaction::OutPoint;
use lightning::io::Error;
use std::str::FromStr;
use std::sync::Arc;

const CHANNEL_MANAGER_KEY: &str = "manager";
const MONITORS_PREFIX_KEY: &str = "monitors/";
const PAYMENT_INBOUND_PREFIX_KEY: &str = "payment_inbound/";
const PAYMENT_OUTBOUND_PREFIX_KEY: &str = "payment_outbound/";
const PEER_PREFIX_KEY: &str = "peer/";

pub(crate) type PhantomChannelManager = LdkChannelManager<
    Arc<ChainMonitor>,
    Arc<MutinyChain>,
    Arc<PhantomKeysManager>,
    Arc<PhantomKeysManager>,
    Arc<PhantomKeysManager>,
    Arc<MutinyFeeEstimator>,
    Arc<Router>,
    Arc<MutinyLogger>,
>;

pub struct MutinyNodePersister {
    node_id: String,
    storage: MutinyBrowserStorage,
}

pub(crate) struct ReadChannelManager {
    pub channel_manager: PhantomChannelManager,
    pub is_restarting: bool,
    pub channel_monitors: Vec<(BlockHash, ChannelMonitor<InMemorySigner>)>,
}

impl MutinyNodePersister {
    pub fn new(node_id: String, storage: MutinyBrowserStorage) -> Self {
        MutinyNodePersister { node_id, storage }
    }

    fn get_key(&self, key: &str) -> String {
        format!("{}_{}", key, self.node_id)
    }

    fn persist_local_storage<W: Writeable>(&self, key: &str, object: &W) -> Result<(), Error> {
        let key_with_node = self.get_key(key);
        self.storage
            .set(key_with_node, object.encode())
            .map_err(|_| lightning::io::ErrorKind::Other.into())
    }

    // name this param _key so it is not confused with the key
    // that has the concatenated node_id
    fn read_value(&self, _key: &str) -> Result<Vec<u8>, MutinyError> {
        let key = self.get_key(_key);
        self.storage.get(key).map_err(MutinyError::read_err)
    }

    pub fn read_channel_monitors(
        &self,
        keys_manager: Arc<PhantomKeysManager>,
    ) -> Result<Vec<(BlockHash, ChannelMonitor<InMemorySigner>)>, io::Error> {
        // Get all the channel monitor buffers that exist for this node
        let suffix = self.node_id.as_str();
        let channel_monitor_list: HashMap<String, Vec<u8>> =
            self.storage.scan(MONITORS_PREFIX_KEY, Some(suffix));

        let res = channel_monitor_list
            .iter()
            .fold(Ok(Vec::new()), |current_res, (_, data)| match current_res {
                Err(e) => Err(e),
                Ok(mut accum) => {
                    let mut buffer = lightning::io::Cursor::new(data);
                    match <(BlockHash, ChannelMonitor<InMemorySigner>)>::read(
                        &mut buffer,
                        (keys_manager.as_ref(), keys_manager.as_ref()),
                    ) {
                        Ok((blockhash, channel_monitor)) => {
                            accum.push((blockhash, channel_monitor));
                            Ok(accum)
                        }
                        Err(e) => Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Failed to deserialize ChannelMonitor: {e}"),
                        )),
                    }
                }
            })?;

        Ok(res)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn read_channel_manager(
        &self,
        network: Network,
        chain_monitor: Arc<ChainMonitor>,
        mutiny_chain: Arc<MutinyChain>,
        fee_estimator: Arc<MutinyFeeEstimator>,
        mutiny_logger: Arc<MutinyLogger>,
        keys_manager: Arc<PhantomKeysManager>,
        router: Arc<Router>,
        mut channel_monitors: Vec<(BlockHash, ChannelMonitor<InMemorySigner>)>,
        esplora: Arc<EsploraBlockchain>,
    ) -> Result<ReadChannelManager, MutinyError> {
        match self.read_value(CHANNEL_MANAGER_KEY) {
            Ok(kv_value) => {
                let mut channel_monitor_mut_references = Vec::new();
                for (_, channel_monitor) in channel_monitors.iter_mut() {
                    channel_monitor_mut_references.push(channel_monitor);
                }
                let read_args = ChannelManagerReadArgs::new(
                    keys_manager.clone(),
                    keys_manager.clone(),
                    keys_manager.clone(),
                    fee_estimator,
                    chain_monitor,
                    mutiny_chain,
                    router,
                    mutiny_logger,
                    default_user_config(),
                    channel_monitor_mut_references,
                );
                let mut readable_kv_value = lightning::io::Cursor::new(kv_value);
                let Ok((_, channel_manager)) = <(BlockHash, PhantomChannelManager)>::read(&mut readable_kv_value, read_args) else {
                    return Err(MutinyError::ReadError { source: error::MutinyStorageError::Other(anyhow!("could not read manager")) })
                };
                Ok(ReadChannelManager {
                    channel_manager,
                    is_restarting: true,
                    channel_monitors,
                })
            }
            Err(_) => {
                // no key manager stored, start a new one

                let height_future = esplora
                    .get_height()
                    .map_err(|_| error::MutinyError::ChainAccessFailed);
                let hash_future = esplora
                    .get_tip_hash()
                    .map_err(|_| error::MutinyError::ChainAccessFailed);
                let (height, hash) = try_join!(height_future, hash_future)?;
                let chain_params = ChainParameters {
                    network,
                    best_block: BestBlock::new(hash, height),
                };

                let fresh_channel_manager: PhantomChannelManager =
                    channelmanager::ChannelManager::new(
                        fee_estimator,
                        chain_monitor,
                        mutiny_chain,
                        router,
                        mutiny_logger,
                        keys_manager.clone(),
                        keys_manager.clone(),
                        keys_manager,
                        default_user_config(),
                        chain_params,
                    );

                Ok(ReadChannelManager {
                    channel_manager: fresh_channel_manager,
                    is_restarting: false,
                    channel_monitors,
                })
            }
        }
    }

    pub(crate) fn persist_payment_info(
        &self,
        payment_hash: PaymentHash,
        payment_info: PaymentInfo,
        inbound: bool,
    ) -> io::Result<()> {
        let key = self.get_key(payment_key(inbound, payment_hash).as_str());
        self.storage
            .set(key, payment_info)
            .map_err(io::Error::other)
    }

    pub(crate) fn read_payment_info(
        &self,
        payment_hash: PaymentHash,
        inbound: bool,
        logger: Arc<MutinyLogger>,
    ) -> Option<PaymentInfo> {
        let key = self.get_key(payment_key(inbound, payment_hash).as_str());
        logger.log(&Record::new(
            lightning::util::logger::Level::Trace,
            format_args!("Trace: checking payment key: {key}"),
            "node",
            "",
            0,
        ));
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

    pub(crate) fn read_peer_connection_info(&self, peer_pubkey: String) -> Option<String> {
        let key = self.get_key(peer_key(peer_pubkey).as_str());
        let deserialized_value: Result<String, MutinyError> =
            self.storage.get(key).map_err(MutinyError::read_err);
        deserialized_value.ok()
    }

    pub(crate) fn persist_peer_connection_info(
        &self,
        peer_pubkey: String,
        connection_string: String,
    ) -> io::Result<()> {
        let key = self.get_key(peer_key(peer_pubkey).as_str());
        self.storage
            .set(key, connection_string)
            .map_err(io::Error::other)
    }

    // FIXME: Useful to keep around until we use it
    #[allow(dead_code)]
    pub(crate) fn delete_peer_connection_info(&self, peer_pubkey: String) {
        let key = self.get_key(peer_key(peer_pubkey).as_str());
        MutinyBrowserStorage::delete(key)
    }

    pub(crate) fn list_peer_connection_info(&self) -> Vec<(PublicKey, String)> {
        let suffix = self.node_id.as_str();
        let map: HashMap<String, String> = self.storage.scan(PEER_PREFIX_KEY, Some(suffix));
        map.into_iter()
            .map(|(k, v)| {
                let k = String::from(k.strip_prefix(PEER_PREFIX_KEY).unwrap());
                let k = k.strip_suffix(suffix).unwrap().strip_suffix('_').unwrap();
                let pubkey = PublicKey::from_str(k).unwrap();
                (pubkey, v)
            })
            .collect()
    }
}

fn peer_key(pubkey: String) -> String {
    format!("{PEER_PREFIX_KEY}{pubkey}")
}

fn payment_key(inbound: bool, payment_hash: PaymentHash) -> String {
    if inbound {
        format!(
            "{}{}",
            PAYMENT_INBOUND_PREFIX_KEY,
            payment_hash.0.to_hex().as_str()
        )
    } else {
        format!(
            "{}{}",
            PAYMENT_OUTBOUND_PREFIX_KEY,
            payment_hash.0.to_hex().as_str()
        )
    }
}

impl
    Persister<
        '_,
        Arc<ChainMonitor>,
        Arc<MutinyChain>,
        Arc<PhantomKeysManager>,
        Arc<PhantomKeysManager>,
        Arc<PhantomKeysManager>,
        Arc<MutinyFeeEstimator>,
        Arc<Router>,
        Arc<MutinyLogger>,
        utils::Mutex<ProbScorer>,
    > for MutinyNodePersister
{
    fn persist_manager(&self, channel_manager: &PhantomChannelManager) -> Result<(), Error> {
        self.persist_local_storage(CHANNEL_MANAGER_KEY, channel_manager)
    }

    fn persist_graph(&self, network_graph: &NetworkGraph) -> Result<(), Error> {
        gossip::persist_network_graph(network_graph)
    }

    fn persist_scorer(&self, scorer: &utils::Mutex<ProbScorer>) -> Result<(), Error> {
        gossip::persist_scorer(scorer)
    }
}

impl<ChannelSigner: WriteableEcdsaChannelSigner> Persist<ChannelSigner> for MutinyNodePersister {
    fn persist_new_channel(
        &self,
        funding_txo: OutPoint,
        monitor: &ChannelMonitor<ChannelSigner>,
        _update_id: MonitorUpdateId,
    ) -> chain::ChannelMonitorUpdateStatus {
        let key = format!(
            "{MONITORS_PREFIX_KEY}/{}_{}",
            funding_txo.txid.to_hex(),
            funding_txo.index
        );
        match self.persist_local_storage(&key, monitor) {
            Ok(()) => chain::ChannelMonitorUpdateStatus::Completed,
            Err(_) => chain::ChannelMonitorUpdateStatus::PermanentFailure,
        }
    }

    fn update_persisted_channel(
        &self,
        funding_txo: OutPoint,
        _update: Option<&ChannelMonitorUpdate>,
        monitor: &ChannelMonitor<ChannelSigner>,
        _update_id: MonitorUpdateId,
    ) -> chain::ChannelMonitorUpdateStatus {
        let key = format!(
            "{MONITORS_PREFIX_KEY}/{}_{}",
            funding_txo.txid.to_hex(),
            funding_txo.index
        );
        match self.persist_local_storage(&key, monitor) {
            Ok(()) => chain::ChannelMonitorUpdateStatus::Completed,
            Err(_) => chain::ChannelMonitorUpdateStatus::PermanentFailure,
        }
    }
}
