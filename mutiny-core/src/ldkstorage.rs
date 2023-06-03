use crate::chain::MutinyChain;
use crate::error::{MutinyError, MutinyStorageError};
use crate::event::{ChannelClosure, PaymentInfo};
use crate::fees::MutinyFeeEstimator;
use crate::gossip::{NETWORK_GRAPH_KEY, PROB_SCORER_KEY};
use crate::keymanager::PhantomKeysManager;
use crate::logging::MutinyLogger;
use crate::node::{default_user_config, ChainMonitor, ProbScorer};
use crate::node::{NetworkGraph, Router};
use crate::storage::MutinyStorage;
use crate::utils;
use anyhow::anyhow;
use bdk_esplora::esplora_client::AsyncClient;
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::BlockHash;
use bitcoin::Network;
use futures::{try_join, TryFutureExt};
use lightning::chain::chainmonitor::{MonitorUpdateId, Persist};
use lightning::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate};
use lightning::chain::keysinterface::{
    InMemorySigner, SpendableOutputDescriptor, WriteableEcdsaChannelSigner,
};
use lightning::chain::transaction::OutPoint;
use lightning::chain::BestBlock;
use lightning::io::Cursor;
use lightning::ln::channelmanager::{
    self, ChainParameters, ChannelManager as LdkChannelManager, ChannelManagerReadArgs,
};
use lightning::ln::PaymentHash;
use lightning::util::logger::Logger;
use lightning::util::persist::Persister;
use lightning::util::ser::{Readable, ReadableArgs, Writeable};
use lightning::{chain, log_trace};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
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
    Arc<MutinyChain>,
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
}

pub(crate) struct ReadChannelManager<S: MutinyStorage> {
    pub channel_manager: PhantomChannelManager<S>,
    pub is_restarting: bool,
    pub channel_monitors: Vec<(BlockHash, ChannelMonitor<InMemorySigner>)>,
}

impl<S: MutinyStorage> MutinyNodePersister<S> {
    pub fn new(node_id: String, storage: S) -> Self {
        MutinyNodePersister { node_id, storage }
    }

    fn get_key(&self, key: &str) -> String {
        format!("{}_{}", key, self.node_id)
    }

    fn persist_local_storage<W: Writeable>(
        &self,
        key: &str,
        object: &W,
    ) -> Result<(), lightning::io::Error> {
        let key_with_node = self.get_key(key);
        self.storage
            .set_data(key_with_node, object.encode())
            .map_err(|_| lightning::io::ErrorKind::Other.into())
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
        chain_monitor: Arc<ChainMonitor<S>>,
        mutiny_chain: Arc<MutinyChain>,
        fee_estimator: Arc<MutinyFeeEstimator<S>>,
        mutiny_logger: Arc<MutinyLogger>,
        keys_manager: Arc<PhantomKeysManager<S>>,
        router: Arc<Router>,
        mut channel_monitors: Vec<(BlockHash, ChannelMonitor<InMemorySigner>)>,
        esplora: Arc<AsyncClient>,
    ) -> Result<ReadChannelManager<S>, MutinyError> {
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
                let mut readable_kv_value = Cursor::new(kv_value);
                let Ok((_, channel_manager)) = <(BlockHash, PhantomChannelManager<S>)>::read(&mut readable_kv_value, read_args) else {
                    return Err(MutinyError::ReadError { source: MutinyStorageError::Other(anyhow!("could not read manager")) })
                };
                Ok(ReadChannelManager {
                    channel_manager,
                    is_restarting: true,
                    channel_monitors,
                })
            }
            Err(_) => {
                // no key manager stored, start a new one

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

                let fresh_channel_manager: PhantomChannelManager<S> =
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
        payment_hash: &PaymentHash,
        payment_info: &PaymentInfo,
        inbound: bool,
    ) -> io::Result<()> {
        let key = self.get_key(payment_key(inbound, payment_hash).as_str());
        self.storage
            .set_data(key, payment_info)
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
        self.storage.set_data(key, closure)?;
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

    #[allow(dead_code)] // todo expose to front end
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

        self.storage.set_data(key, descriptors)?;

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
        self.storage.set_data(key, params)
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
    pub sats_per_kw: u32,
    pub utxos: Vec<bitcoin::OutPoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
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
        Arc<MutinyChain>,
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
        self.persist_local_storage(CHANNEL_MANAGER_KEY, channel_manager)
    }

    fn persist_graph(&self, network_graph: &NetworkGraph) -> Result<(), lightning::io::Error> {
        self.storage
            .set_data(NETWORK_GRAPH_KEY, network_graph.encode().to_hex())
            .map_err(|_| lightning::io::ErrorKind::Other.into())
    }

    fn persist_scorer(
        &self,
        scorer: &utils::Mutex<ProbScorer>,
    ) -> Result<(), lightning::io::Error> {
        let scorer_str = scorer.encode().to_hex();
        self.storage
            .set_data(PROB_SCORER_KEY, scorer_str)
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
            "{MONITORS_PREFIX_KEY}{}_{}",
            funding_txo.txid.to_hex(),
            funding_txo.index
        );
        match self.persist_local_storage(&key, monitor) {
            Ok(()) => chain::ChannelMonitorUpdateStatus::Completed,
            Err(_) => chain::ChannelMonitorUpdateStatus::PermanentFailure,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::event::{HTLCStatus, MillisatAmount};
    use crate::storage::MemoryStorage;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::PublicKey;
    use bitcoin::Txid;
    use std::str::FromStr;
    use uuid::Uuid;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    use super::*;

    use crate::test_utils::*;

    wasm_bindgen_test_configure!(run_in_browser);

    fn get_test_persister() -> MutinyNodePersister<MemoryStorage> {
        let id = Uuid::new_v4().to_string();
        let storage = MemoryStorage::default();
        MutinyNodePersister::new(id, storage)
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
}
