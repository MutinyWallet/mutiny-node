use crate::chain::MutinyChain;
use crate::error::{MutinyError, MutinyStorageError};
use crate::event::PaymentInfo;
use crate::fees::MutinyFeeEstimator;
use crate::gossip::{NETWORK_GRAPH_KEY, PROB_SCORER_KEY};
use crate::keymanager::PhantomKeysManager;
use crate::logging::MutinyLogger;
use crate::node::{default_user_config, ChainMonitor, ProbScorer};
use crate::node::{NetworkGraph, Router};
use crate::nodemanager::ChannelClosure;
use crate::storage::{MutinyStorage, VersionedValue};
use crate::utils;
use anyhow::anyhow;
use bdk_esplora::esplora_client::AsyncClient;
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::Network;
use bitcoin::{BlockHash, Transaction};
use futures::{try_join, TryFutureExt};
use lightning::chain::chainmonitor::{MonitorUpdateId, Persist};
use lightning::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate};
use lightning::chain::transaction::OutPoint;
use lightning::chain::BestBlock;
use lightning::io::Cursor;
use lightning::ln::channelmanager::{
    self, ChainParameters, ChannelManager as LdkChannelManager, ChannelManagerReadArgs,
};
use lightning::ln::PaymentHash;
use lightning::sign::{InMemorySigner, SpendableOutputDescriptor, WriteableEcdsaChannelSigner};
use lightning::util::logger::Logger;
use lightning::util::persist::Persister;
use lightning::util::ser::{Readable, ReadableArgs, Writeable};
use lightning::{chain, log_debug, log_error, log_trace};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

pub const CHANNEL_MANAGER_KEY: &str = "manager";
pub const MONITORS_PREFIX_KEY: &str = "monitors/";
const PAYMENT_INBOUND_PREFIX_KEY: &str = "payment_inbound/";
const PAYMENT_OUTBOUND_PREFIX_KEY: &str = "payment_outbound/";
const CHANNEL_OPENING_PARAMS_PREFIX: &str = "chan_open_params/";
const CHANNEL_CLOSURE_PREFIX: &str = "channel_closure/";
const FAILED_SPENDABLE_OUTPUT_DESCRIPTOR_KEY: &str = "failed_spendable_outputs";

pub(crate) type PhantomChannelManager<S: MutinyStorage> = LdkChannelManager<
    Arc<ChainMonitor<S>>,
    Arc<MutinyChain<S>>,
    Arc<PhantomKeysManager<S>>,
    Arc<PhantomKeysManager<S>>,
    Arc<PhantomKeysManager<S>>,
    Arc<MutinyFeeEstimator<S>>,
    Arc<Router>,
    Arc<MutinyLogger>,
>;

#[derive(Clone)]
pub struct MutinyNodePersister<S: MutinyStorage> {
    node_id: String,
    pub(crate) storage: S,
    manager_version: Arc<AtomicU32>,
    logger: Arc<MutinyLogger>,
}

pub(crate) struct ReadChannelManager<S: MutinyStorage> {
    pub channel_manager: PhantomChannelManager<S>,
    pub is_restarting: bool,
    pub channel_monitors: Vec<(BlockHash, ChannelMonitor<InMemorySigner>)>,
}

impl<S: MutinyStorage> MutinyNodePersister<S> {
    pub fn new(node_id: String, storage: S, logger: Arc<MutinyLogger>) -> Self {
        MutinyNodePersister {
            node_id,
            storage,
            manager_version: Arc::new(AtomicU32::new(0)),
            logger,
        }
    }

    #[cfg(test)]
    pub(crate) fn manager_version(&self) -> u32 {
        self.manager_version.load(Ordering::Relaxed)
    }

    fn get_key(&self, key: &str) -> String {
        format!("{}_{}", key, self.node_id)
    }

    fn persist_local_storage<W: Writeable>(
        &self,
        key: &str,
        object: &W,
        version: Option<u32>,
    ) -> Result<(), lightning::io::Error> {
        let key_with_node = self.get_key(key);
        self.storage
            .set_data(key_with_node, object.encode(), version)
            .map_err(|e| {
                match e {
                    MutinyError::PersistenceFailed { source } => {
                        log_error!(self.logger, "Persistence failed on {key}: {source}");
                    }
                    _ => {
                        log_error!(self.logger, "Error storing {key}: {e}");
                    }
                };
                lightning::io::ErrorKind::Other.into()
            })
    }

    // name this param _key so it is not confused with the key
    // that has the concatenated node_id
    fn read_value(&self, _key: &str) -> Result<Vec<u8>, MutinyError> {
        let key = self.get_key(_key);
        match self.storage.get_data(&key) {
            Ok(Some(value)) => Ok(value),
            Ok(None) => Err(MutinyError::read_err(MutinyStorageError::Other(anyhow!(
                "No value found for key: {key}"
            )))),
            Err(e) => Err(e),
        }
    }

    pub fn read_channel_monitors(
        &self,
        keys_manager: Arc<PhantomKeysManager<S>>,
    ) -> Result<Vec<(BlockHash, ChannelMonitor<InMemorySigner>)>, io::Error> {
        // Get all the channel monitor buffers that exist for this node
        let suffix = self.node_id.as_str();
        let channel_monitor_list: HashMap<String, Vec<u8>> = self
            .storage
            .scan(MONITORS_PREFIX_KEY, Some(suffix))
            .map_err(|_| io::ErrorKind::Other)?;

        let res = channel_monitor_list
            .iter()
            .fold(Ok(Vec::new()), |current_res, (_, data)| match current_res {
                Err(e) => Err(e),
                Ok(mut accum) => {
                    let mut buffer = Cursor::new(data);
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
        chain_monitor: Arc<ChainMonitor<S>>,
        mutiny_chain: Arc<MutinyChain<S>>,
        fee_estimator: Arc<MutinyFeeEstimator<S>>,
        mutiny_logger: Arc<MutinyLogger>,
        keys_manager: Arc<PhantomKeysManager<S>>,
        router: Arc<Router>,
        channel_monitors: Vec<(BlockHash, ChannelMonitor<InMemorySigner>)>,
        esplora: Arc<AsyncClient>,
    ) -> Result<ReadChannelManager<S>, MutinyError> {
        log_debug!(mutiny_logger, "Reading channel manager from storage");
        let key = self.get_key(CHANNEL_MANAGER_KEY);
        match self.storage.get_data::<VersionedValue>(&key) {
            Ok(Some(versioned_value)) => {
                // new encoding is in hex
                let hex: String = serde_json::from_value(versioned_value.value.clone())?;
                let bytes = FromHex::from_hex(&hex)?;
                let res = Self::parse_channel_manager(
                    bytes,
                    chain_monitor,
                    mutiny_chain,
                    fee_estimator,
                    mutiny_logger,
                    keys_manager,
                    router,
                    channel_monitors,
                )?;

                self.manager_version
                    .swap(versioned_value.version, Ordering::Relaxed);

                Ok(res)
            }
            Ok(None) => {
                // no key manager stored, start a new one

                Self::create_new_channel_manager(
                    network,
                    chain_monitor,
                    mutiny_chain,
                    fee_estimator,
                    mutiny_logger,
                    keys_manager,
                    router,
                    channel_monitors,
                    esplora,
                )
                .await
            }
            Err(_) => {
                // old encoding with no version number and as an array of numbers
                let bytes = self.read_value(CHANNEL_MANAGER_KEY)?;
                Self::parse_channel_manager(
                    bytes,
                    chain_monitor,
                    mutiny_chain,
                    fee_estimator,
                    mutiny_logger,
                    keys_manager,
                    router,
                    channel_monitors,
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn parse_channel_manager(
        bytes: Vec<u8>,
        chain_monitor: Arc<ChainMonitor<S>>,
        mutiny_chain: Arc<MutinyChain<S>>,
        fee_estimator: Arc<MutinyFeeEstimator<S>>,
        mutiny_logger: Arc<MutinyLogger>,
        keys_manager: Arc<PhantomKeysManager<S>>,
        router: Arc<Router>,
        mut channel_monitors: Vec<(BlockHash, ChannelMonitor<InMemorySigner>)>,
    ) -> Result<ReadChannelManager<S>, MutinyError> {
        let mut channel_monitor_mut_references = Vec::new();
        for (_, channel_monitor) in channel_monitors.iter_mut() {
            channel_monitor_mut_references.push(channel_monitor);
        }
        let read_args = ChannelManagerReadArgs::new(
            keys_manager.clone(),
            keys_manager.clone(),
            keys_manager,
            fee_estimator,
            chain_monitor,
            mutiny_chain,
            router,
            mutiny_logger,
            default_user_config(),
            channel_monitor_mut_references,
        );
        let mut readable_kv_value = Cursor::new(bytes);
        let Ok((_, channel_manager)) = <(BlockHash, PhantomChannelManager<S>)>::read(&mut readable_kv_value, read_args) else {
            return Err(MutinyError::ReadError { source: MutinyStorageError::Other(anyhow!("could not read manager")) })
        };
        Ok(ReadChannelManager {
            channel_manager,
            is_restarting: true,
            channel_monitors,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn create_new_channel_manager(
        network: Network,
        chain_monitor: Arc<ChainMonitor<S>>,
        mutiny_chain: Arc<MutinyChain<S>>,
        fee_estimator: Arc<MutinyFeeEstimator<S>>,
        mutiny_logger: Arc<MutinyLogger>,
        keys_manager: Arc<PhantomKeysManager<S>>,
        router: Arc<Router>,
        channel_monitors: Vec<(BlockHash, ChannelMonitor<InMemorySigner>)>,
        esplora: Arc<AsyncClient>,
    ) -> Result<ReadChannelManager<S>, MutinyError> {
        // if regtest, we don't need to get the tip hash and can
        // just use genesis, this also lets us use regtest in tests
        let best_block = if network == Network::Regtest {
            BestBlock::from_network(network)
        } else {
            let height_future = esplora
                .get_height()
                .map_err(|_| MutinyError::ChainAccessFailed);
            let hash_future = esplora
                .get_tip_hash()
                .map_err(|_| MutinyError::ChainAccessFailed);
            let (height, hash) = try_join!(height_future, hash_future)?;
            BestBlock::new(hash, height)
        };
        let chain_params = ChainParameters {
            network,
            best_block,
        };

        let fresh_channel_manager: PhantomChannelManager<S> = channelmanager::ChannelManager::new(
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
            utils::now().as_secs() as u32,
        );

        Ok(ReadChannelManager {
            channel_manager: fresh_channel_manager,
            is_restarting: false,
            channel_monitors,
        })
    }

    pub(crate) fn persist_payment_info(
        &self,
        payment_hash: &PaymentHash,
        payment_info: &PaymentInfo,
        inbound: bool,
    ) -> io::Result<()> {
        let key = self.get_key(payment_key(inbound, payment_hash).as_str());
        self.storage
            .set_data(key, payment_info, None)
            .map_err(io::Error::other)
    }

    pub(crate) fn read_payment_info(
        &self,
        payment_hash: &PaymentHash,
        inbound: bool,
        logger: &MutinyLogger,
    ) -> Option<PaymentInfo> {
        let key = self.get_key(payment_key(inbound, payment_hash).as_str());
        log_trace!(logger, "Trace: checking payment key: {key}");
        let deserialized_value: Result<Option<PaymentInfo>, MutinyError> =
            self.storage.get_data(key);
        deserialized_value.ok().flatten()
    }

    pub(crate) fn list_payment_info(
        &self,
        inbound: bool,
    ) -> Result<Vec<(PaymentHash, PaymentInfo)>, MutinyError> {
        let prefix = match inbound {
            true => PAYMENT_INBOUND_PREFIX_KEY,
            false => PAYMENT_OUTBOUND_PREFIX_KEY,
        };
        let suffix = format!("_{}", self.node_id);
        let map: HashMap<String, PaymentInfo> = self.storage.scan(prefix, Some(&suffix))?;

        // convert keys to PaymentHash
        Ok(map
            .into_iter()
            .map(|(key, value)| {
                let payment_hash_str = key.trim_start_matches(prefix).trim_end_matches(&suffix);
                let hash: [u8; 32] =
                    FromHex::from_hex(payment_hash_str).expect("key should be a sha256 hash");
                (PaymentHash(hash), value)
            })
            .collect())
    }

    pub(crate) fn persist_channel_closure(
        &self,
        user_channel_id: u128,
        closure: ChannelClosure,
    ) -> Result<(), MutinyError> {
        let key = self.get_key(&format!(
            "{CHANNEL_CLOSURE_PREFIX}{}",
            user_channel_id.to_be_bytes().to_hex()
        ));
        self.storage.set_data(key, closure, None)?;
        Ok(())
    }

    pub(crate) fn get_channel_closure(
        &self,
        user_channel_id: u128,
    ) -> Result<Option<ChannelClosure>, MutinyError> {
        let key = self.get_key(&format!(
            "{CHANNEL_CLOSURE_PREFIX}{}",
            user_channel_id.to_be_bytes().to_hex()
        ));
        self.storage.get_data(key)
    }

    pub(crate) fn list_channel_closures(&self) -> Result<Vec<(u128, ChannelClosure)>, MutinyError> {
        let suffix = format!("_{}", self.node_id);
        let map: HashMap<String, ChannelClosure> =
            self.storage.scan(CHANNEL_CLOSURE_PREFIX, Some(&suffix))?;

        Ok(map
            .into_iter()
            .map(|(key, value)| {
                // convert keys to u128
                let user_channel_id_str = key
                    .trim_start_matches(CHANNEL_CLOSURE_PREFIX)
                    .trim_end_matches(&suffix);
                let user_channel_id: [u8; 16] = FromHex::from_hex(user_channel_id_str)
                    .expect(&format!("key should be a u128 got {user_channel_id_str}"));

                let user_channel_id = u128::from_be_bytes(user_channel_id);
                (user_channel_id, value)
            })
            .collect())
    }

    /// Persists the failed spendable outputs to storage.
    /// Previously failed spendable outputs are not overwritten.
    ///
    /// This is used to retry spending them later.
    pub fn persist_failed_spendable_outputs(
        &self,
        failed: Vec<SpendableOutputDescriptor>,
    ) -> anyhow::Result<()> {
        let key = self.get_key(FAILED_SPENDABLE_OUTPUT_DESCRIPTOR_KEY);

        // get the currently stored descriptors encoded as hex
        // if there are none, use an empty vector
        let mut descriptors: Vec<String> = self.storage.get_data(&key)?.unwrap_or_default();

        // convert the failed descriptors to hex
        let failed_hex: Vec<String> = failed
            .into_iter()
            .map(|desc| desc.encode().to_hex())
            .collect();

        // add the new descriptors
        descriptors.extend(failed_hex);

        self.storage.set_data(key, descriptors, None)?;

        Ok(())
    }

    /// Persists the failed spendable outputs to storage.
    /// Previously failed spendable outputs are overwritten.
    ///
    /// This is used to retry spending them later.
    pub fn set_failed_spendable_outputs(
        &self,
        descriptors: Vec<SpendableOutputDescriptor>,
    ) -> anyhow::Result<()> {
        let key = self.get_key(FAILED_SPENDABLE_OUTPUT_DESCRIPTOR_KEY);

        // convert the failed descriptors to hex
        let descriptors_hex: Vec<String> = descriptors
            .into_iter()
            .map(|desc| desc.encode().to_hex())
            .collect();

        self.storage.set_data(key, descriptors_hex, None)?;

        Ok(())
    }

    /// Retrieves the failed spendable outputs from storage
    pub fn get_failed_spendable_outputs(&self) -> anyhow::Result<Vec<SpendableOutputDescriptor>> {
        let key = self.get_key(FAILED_SPENDABLE_OUTPUT_DESCRIPTOR_KEY);

        // get the currently stored descriptors encoded as hex
        // if there are none, use an empty vector
        let strings: Vec<String> = self.storage.get_data(&key)?.unwrap_or_default();

        // convert the hex strings to descriptors
        let mut descriptors = vec![];
        for desc in strings {
            let bytes =
                Vec::from_hex(&desc).map_err(|_| anyhow!("failed to decode descriptor {desc}"))?;
            let descriptor = SpendableOutputDescriptor::read(&mut Cursor::new(bytes))
                .map_err(|_| anyhow!("failed to read descriptor from storage: {desc}"))?;
            descriptors.push(descriptor);
        }

        Ok(descriptors)
    }

    /// Clears the failed spendable outputs from storage
    /// This is used when the failed spendable outputs have been successfully spent
    pub fn clear_failed_spendable_outputs(&self) -> anyhow::Result<()> {
        let key = self.get_key(FAILED_SPENDABLE_OUTPUT_DESCRIPTOR_KEY);
        self.storage.delete(&[key])?;

        Ok(())
    }

    pub(crate) fn persist_channel_open_params(
        &self,
        id: u128,
        params: ChannelOpenParams,
    ) -> Result<(), MutinyError> {
        let key = self.get_key(&channel_open_params_key(id));
        self.storage.set_data(key, params, None)
    }

    pub(crate) fn get_channel_open_params(
        &self,
        id: u128,
    ) -> Result<Option<ChannelOpenParams>, MutinyError> {
        let key = self.get_key(&channel_open_params_key(id));
        self.storage.get_data(key)
    }

    pub(crate) fn delete_channel_open_params(&self, id: u128) -> Result<(), MutinyError> {
        let key = self.get_key(&channel_open_params_key(id));
        self.storage.delete(&[key])
    }
}

fn channel_open_params_key(id: u128) -> String {
    format!("{CHANNEL_OPENING_PARAMS_PREFIX}{id}")
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct ChannelOpenParams {
    pub(crate) sats_per_vbyte: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) absolute_fee: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) utxos: Option<Vec<bitcoin::OutPoint>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) labels: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) opening_tx: Option<Transaction>,
}

impl ChannelOpenParams {
    pub fn new(sats_per_vbyte: f32) -> Self {
        Self {
            sats_per_vbyte,
            absolute_fee: None,
            utxos: None,
            labels: None,
            opening_tx: None,
        }
    }

    pub fn new_sweep(
        sats_per_vbyte: f32,
        absolute_fee: u64,
        utxos: Vec<bitcoin::OutPoint>,
    ) -> Self {
        Self {
            sats_per_vbyte,
            absolute_fee: Some(absolute_fee),
            utxos: Some(utxos),
            labels: None,
            opening_tx: None,
        }
    }
}

fn payment_key(inbound: bool, payment_hash: &PaymentHash) -> String {
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

impl<S: MutinyStorage>
    Persister<
        '_,
        Arc<ChainMonitor<S>>,
        Arc<MutinyChain<S>>,
        Arc<PhantomKeysManager<S>>,
        Arc<PhantomKeysManager<S>>,
        Arc<PhantomKeysManager<S>>,
        Arc<MutinyFeeEstimator<S>>,
        Arc<Router>,
        Arc<MutinyLogger>,
        utils::Mutex<ProbScorer>,
    > for MutinyNodePersister<S>
{
    fn persist_manager(
        &self,
        channel_manager: &PhantomChannelManager<S>,
    ) -> Result<(), lightning::io::Error> {
        let old = self.manager_version.fetch_add(1, Ordering::Relaxed);
        let version = old + 1;
        let key = self.get_key(CHANNEL_MANAGER_KEY);

        let value = VersionedValue {
            version,
            value: serde_json::to_value(channel_manager.encode().to_hex()).unwrap(),
        };

        self.storage
            .set_data(key, value, Some(version))
            .map_err(|_| lightning::io::ErrorKind::Other.into())
    }

    fn persist_graph(&self, network_graph: &NetworkGraph) -> Result<(), lightning::io::Error> {
        self.storage
            .set_data(NETWORK_GRAPH_KEY, network_graph.encode().to_hex(), None)
            .map_err(|_| lightning::io::ErrorKind::Other.into())
    }

    fn persist_scorer(
        &self,
        scorer: &utils::Mutex<ProbScorer>,
    ) -> Result<(), lightning::io::Error> {
        let scorer_str = scorer.encode().to_hex();
        self.storage
            .set_data(PROB_SCORER_KEY, scorer_str, None)
            .map_err(|_| lightning::io::ErrorKind::Other.into())
    }
}

impl<ChannelSigner: WriteableEcdsaChannelSigner, S: MutinyStorage> Persist<ChannelSigner>
    for MutinyNodePersister<S>
{
    fn persist_new_channel(
        &self,
        funding_txo: OutPoint,
        monitor: &ChannelMonitor<ChannelSigner>,
        _update_id: MonitorUpdateId,
    ) -> chain::ChannelMonitorUpdateStatus {
        let key = format!(
            "{MONITORS_PREFIX_KEY}{}_{}",
            funding_txo.txid.to_hex(),
            funding_txo.index
        );
        // safely convert u64 to u32
        let update_id = monitor.get_latest_update_id();
        let version = if update_id >= u32::MAX as u64 {
            u32::MAX
        } else {
            update_id as u32
        };

        match self.persist_local_storage(&key, monitor, Some(version)) {
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
            "{MONITORS_PREFIX_KEY}{}_{}",
            funding_txo.txid.to_hex(),
            funding_txo.index
        );
        // safely convert u64 to u32
        let update_id = monitor.get_latest_update_id();
        let version = if update_id >= u32::MAX as u64 {
            u32::MAX
        } else {
            update_id as u32
        };

        match self.persist_local_storage(&key, monitor, Some(version)) {
            Ok(()) => chain::ChannelMonitorUpdateStatus::Completed,
            Err(_) => chain::ChannelMonitorUpdateStatus::PermanentFailure,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::event::{HTLCStatus, MillisatAmount};
    use crate::keymanager::create_keys_manager;
    use crate::onchain::OnChainWallet;
    use crate::storage::MemoryStorage;
    use crate::{esplora::EsploraSyncClient, node::scoring_params};
    use bip39::Mnemonic;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::PublicKey;
    use bitcoin::util::bip32::ExtendedPrivKey;
    use bitcoin::Txid;
    use esplora_client::Builder;
    use lightning::routing::router::DefaultRouter;
    use lightning::routing::scoring::ProbabilisticScoringDecayParameters;
    use lightning::sign::EntropySource;
    use std::str::FromStr;
    use std::sync::atomic::AtomicBool;
    use uuid::Uuid;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    use super::*;

    use crate::test_utils::*;

    wasm_bindgen_test_configure!(run_in_browser);

    fn get_test_persister() -> MutinyNodePersister<MemoryStorage> {
        let id = Uuid::new_v4().to_string();
        let storage = MemoryStorage::default();
        MutinyNodePersister::new(id, storage, Arc::new(MutinyLogger::default()))
    }

    #[test]
    fn test_persist_payment_info() {
        let test_name = "test_persist_payment_info";
        log!("{}", test_name);

        let persister = get_test_persister();
        let preimage = [1; 32];
        let payment_hash = PaymentHash([0; 32]);
        let pubkey = PublicKey::from_str(
            "02465ed5be53d04fde66c9418ff14a5f2267723810176c9212b722e542dc1afb1b",
        )
        .unwrap();

        let payment_info = PaymentInfo {
            preimage: Some(preimage),
            status: HTLCStatus::Succeeded,
            amt_msat: MillisatAmount(Some(420)),
            fee_paid_msat: None,
            bolt11: None,
            payee_pubkey: Some(pubkey),
            secret: None,
            last_update: utils::now().as_secs(),
        };
        let result = persister.persist_payment_info(&payment_hash, &payment_info, true);
        assert!(result.is_ok());

        let result = persister.read_payment_info(&payment_hash, true, &MutinyLogger::default());

        assert!(result.is_some());
        assert_eq!(result.clone().unwrap().preimage, Some(preimage));
        assert_eq!(result.unwrap().status, HTLCStatus::Succeeded);

        let list = persister.list_payment_info(true).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].0, payment_hash);
        assert_eq!(list[0].1.preimage, Some(preimage));

        let result = persister.read_payment_info(&payment_hash, true, &MutinyLogger::default());

        assert!(result.is_some());
        assert_eq!(result.clone().unwrap().preimage, Some(preimage));
        assert_eq!(result.unwrap().status, HTLCStatus::Succeeded);

        let list = persister.list_payment_info(true).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].0, payment_hash);
        assert_eq!(list[0].1.preimage, Some(preimage));
    }

    #[test]
    fn test_persist_channel_closure() {
        let test_name = "test_persist_channel_closure";
        log!("{}", test_name);

        let persister = get_test_persister();

        let user_channel_id: u128 = 123456789;
        let closure = ChannelClosure {
            user_channel_id: Some(user_channel_id.to_be_bytes()),
            channel_id: Some([1; 32]),
            node_id: None,
            reason: "This is a test.".to_string(),
            timestamp: utils::now().as_secs(),
        };
        let result = persister.persist_channel_closure(user_channel_id, closure.clone());
        assert!(result.is_ok());

        let result = persister.list_channel_closures().unwrap();
        assert_eq!(result, vec![(user_channel_id, closure.clone())]);

        let result = persister.get_channel_closure(user_channel_id).unwrap();
        assert_eq!(result, Some(closure));
    }

    #[test]
    fn test_persist_spendable_output_descriptor() {
        let test_name = "test_persist_spendable_output_descriptor";
        log!("{}", test_name);

        let persister = get_test_persister();

        let static_output_0 = SpendableOutputDescriptor::StaticOutput {
            outpoint: OutPoint {
                txid: Txid::all_zeros(),
                index: 0,
            },
            output: Default::default(),
        };
        let result = persister.persist_failed_spendable_outputs(vec![static_output_0.clone()]);
        assert!(result.is_ok());

        let result = persister.get_failed_spendable_outputs().unwrap();
        assert_eq!(result, vec![static_output_0.clone()]);

        let static_output_1 = SpendableOutputDescriptor::StaticOutput {
            outpoint: OutPoint {
                txid: Txid::all_zeros(),
                index: 1,
            },
            output: Default::default(),
        };
        let result = persister.persist_failed_spendable_outputs(vec![static_output_1.clone()]);
        assert!(result.is_ok());

        let result = persister.get_failed_spendable_outputs().unwrap();
        assert_eq!(result, vec![static_output_0, static_output_1]);

        let result = persister.clear_failed_spendable_outputs();
        assert!(result.is_ok());

        let result = persister.get_failed_spendable_outputs().unwrap();
        assert!(result.is_empty());
    }

    const MANAGER_BYTES: [u8; 256] = [
        1, 1, 246, 30, 238, 59, 99, 163, 128, 164, 119, 160, 99, 175, 50, 178, 187, 201, 124, 159,
        249, 240, 31, 44, 66, 37, 233, 115, 152, 129, 8, 0, 0, 0, 0, 3, 123, 222, 76, 244, 143, 88,
        178, 115, 155, 195, 17, 83, 168, 252, 26, 45, 231, 72, 39, 21, 96, 23, 203, 8, 101, 10,
        238, 136, 77, 5, 250, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100,
        172, 120, 225, 100, 172, 120, 225, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 113, 1,
        2, 0, 0, 3, 2, 0, 0, 5, 33, 3, 49, 56, 184, 182, 87, 71, 249, 167, 155, 99, 242, 124, 162,
        190, 245, 15, 63, 119, 66, 102, 88, 52, 223, 137, 219, 56, 27, 137, 175, 103, 200, 26, 7,
        32, 23, 65, 121, 234, 117, 201, 12, 57, 255, 124, 147, 188, 210, 48, 53, 179, 20, 157, 122,
        21, 212, 195, 166, 222, 214, 124, 167, 7, 217, 175, 93, 50, 9, 0, 11, 32, 124, 241, 131,
        188, 131, 90, 195, 214, 250, 125, 197, 126, 163, 168, 131, 111, 78, 41, 166, 218, 20, 49,
        233, 172, 19, 243, 93, 239, 33, 64, 36, 240,
    ];

    #[test]
    async fn test_upgrade_channel_manager() {
        let test_name = "test_channel_manager";
        log!("{}", test_name);

        let mnemonic = Mnemonic::from_str(
            "shallow car virus tree add switch spring bulb midnight license modify junior",
        )
        .unwrap();

        let network = Network::Signet;

        let persister = Arc::new(get_test_persister());
        // encode old version into persister
        persister
            .storage
            .set_data(
                persister.get_key(CHANNEL_MANAGER_KEY),
                MANAGER_BYTES.to_vec(),
                None,
            )
            .unwrap();

        // need to init a bunch of stuff to read a channel manager

        let logger = Arc::new(MutinyLogger::default());

        let stop = Arc::new(AtomicBool::new(false));
        let xpriv = ExtendedPrivKey::new_master(network, &mnemonic.to_seed("")).unwrap();

        let esplora_server_url = "https://mutinynet.com/api/".to_string();
        let esplora = Arc::new(Builder::new(&esplora_server_url).build_async().unwrap());
        let fees = Arc::new(MutinyFeeEstimator::new(
            persister.storage.clone(),
            esplora.clone(),
            logger.clone(),
        ));
        let tx_sync = Arc::new(EsploraSyncClient::new(esplora_server_url, logger.clone()));

        let wallet = Arc::new(
            OnChainWallet::new(
                xpriv,
                persister.storage.clone(),
                network,
                esplora.clone(),
                fees.clone(),
                stop,
                logger.clone(),
            )
            .unwrap(),
        );

        let km = Arc::new(create_keys_manager(wallet.clone(), xpriv, 0, logger.clone()).unwrap());

        let chain = Arc::new(MutinyChain::new(tx_sync, wallet, logger.clone()));

        let network_graph = Arc::new(NetworkGraph::new(network, logger.clone()));
        let scorer = ProbScorer::new(
            ProbabilisticScoringDecayParameters::default(),
            network_graph.clone(),
            logger.clone(),
        );

        // init chain monitor
        let chain_monitor: Arc<ChainMonitor<MemoryStorage>> = Arc::new(ChainMonitor::new(
            Some(chain.tx_sync.clone()),
            chain.clone(),
            logger.clone(),
            fees.clone(),
            persister.clone(),
        ));

        let router: Arc<Router> = Arc::new(DefaultRouter::new(
            network_graph,
            logger.clone(),
            km.clone().get_secure_random_bytes(),
            Arc::new(utils::Mutex::new(scorer)),
            scoring_params(),
        ));

        // make sure it correctly reads
        let read = persister
            .read_channel_manager(
                network,
                chain_monitor.clone(),
                chain.clone(),
                fees.clone(),
                logger.clone(),
                km.clone(),
                router.clone(),
                vec![],
                esplora.clone(),
            )
            .await
            .unwrap();
        // starts at version 0
        assert_eq!(persister.manager_version(), 0);
        assert!(read.is_restarting);

        // persist, should be new version
        persister.persist_manager(&read.channel_manager).unwrap();
        assert_eq!(persister.manager_version(), 1);

        // make sure we can read with new encoding
        let read = persister
            .read_channel_manager(
                network,
                chain_monitor,
                chain.clone(),
                fees.clone(),
                logger.clone(),
                km,
                router,
                vec![],
                esplora,
            )
            .await
            .unwrap();

        // should be same version
        assert_eq!(persister.manager_version(), 1);
        assert!(read.is_restarting);
    }
}
