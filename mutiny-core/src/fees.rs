use crate::logging::MutinyLogger;
use crate::storage::MutinyStorage;
use crate::{error::MutinyError, utils};
use bdk::FeeRate;
use bitcoin::Weight;
use esplora_client::AsyncClient;
use futures::lock::Mutex;
use lightning::chain::chaininterface::{
    ConfirmationTarget, FeeEstimator, FEERATE_FLOOR_SATS_PER_KW,
};
use lightning::log_trace;
use lightning::util::logger::Logger;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

// Constants for overhead, input, and output sizes
pub(crate) const TX_OVERHEAD: usize = 10;
pub(crate) const TAPROOT_INPUT_NON_WITNESS_SIZE: usize = 41;
pub(crate) const TAPROOT_INPUT_WITNESS_SIZE: usize = 67;
pub(crate) const P2WSH_OUTPUT_SIZE: usize = 43;
#[allow(dead_code)]
pub(crate) const TAPROOT_OUTPUT_SIZE: usize = 43;

#[derive(Clone)]
pub struct MutinyFeeEstimator<S: MutinyStorage> {
    storage: S,
    esplora: Arc<AsyncClient>,
    logger: Arc<MutinyLogger>,
    last_fee_update_time_secs: Arc<Mutex<Option<u64>>>,
}

impl<S: MutinyStorage> MutinyFeeEstimator<S> {
    pub fn new(
        storage: S,
        esplora: Arc<AsyncClient>,
        logger: Arc<MutinyLogger>,
    ) -> MutinyFeeEstimator<S> {
        MutinyFeeEstimator {
            storage,
            esplora,
            logger,
            last_fee_update_time_secs: Arc::new(Mutex::new(None)),
        }
    }

    /// Calculate the estimated fee in satoshis for a transaction.
    /// It is assumed that the inputs will be Taproot key spends.
    pub fn calculate_expected_fee(
        &self,
        num_utxos: usize,
        output_size: usize,
        change_size: Option<usize>,
        sats_per_kw: Option<u32>,
    ) -> u64 {
        // if no fee rate is provided, use the normal confirmation target
        let sats_per_kw = sats_per_kw.unwrap_or_else(|| self.get_normal_fee_rate());
        let expected_weight = {
            // Calculate the non-witness and witness data sizes
            let non_witness_size = TX_OVERHEAD
                + (num_utxos * TAPROOT_INPUT_NON_WITNESS_SIZE)
                + output_size
                + change_size.unwrap_or(0);
            let witness_size = num_utxos * TAPROOT_INPUT_WITNESS_SIZE;

            // Calculate the transaction weight
            (non_witness_size * 4) + witness_size
        };

        FeeRate::from_sat_per_kwu(sats_per_kw as f32)
            .fee_wu(Weight::from_wu(expected_weight as u64))
    }

    async fn get_last_sync_time(&self) -> Option<u64> {
        let lock = self.last_fee_update_time_secs.lock().await;
        *lock
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct MempoolFees {
    fastest_fee: f64,
    half_hour_fee: f64,
    hour_fee: f64,
    economy_fee: f64,
    minimum_fee: f64,
}

impl<S: MutinyStorage> MutinyFeeEstimator<S> {
    async fn get_mempool_recommended_fees(&self) -> anyhow::Result<HashMap<String, f64>> {
        let client = self.esplora.client();
        let request = client
            .get(format!("{}/v1/fees/recommended", self.esplora.url()))
            .build()?;

        let fees_response = utils::fetch_with_timeout(client, request)
            .await?
            .error_for_status()?;
        let fees = fees_response.json::<MempoolFees>().await?;

        // convert to hashmap of num blocks -> fee rate
        let mut fee_estimates = HashMap::new();
        fee_estimates.insert("1".to_string(), fees.fastest_fee);
        fee_estimates.insert("3".to_string(), fees.half_hour_fee);
        fee_estimates.insert("6".to_string(), fees.hour_fee);
        fee_estimates.insert("12".to_string(), fees.economy_fee);
        fee_estimates.insert("1008".to_string(), fees.minimum_fee);

        Ok(fee_estimates)
    }

    pub async fn update_fee_estimates_if_necessary(&self) -> Result<(), MutinyError> {
        let last_sync = self.get_last_sync_time().await;
        if last_sync.is_none() || utils::now().as_secs() > last_sync.unwrap() + 60 * 10 {
            self.update_fee_estimates().await?;
        }
        Ok(())
    }

    async fn update_fee_estimates(&self) -> Result<(), MutinyError> {
        // first try mempool.space's API
        let mempool_fees = self.get_mempool_recommended_fees().await;

        // if that fails, fall back to esplora's API
        let fee_estimates = match mempool_fees {
            Ok(mempool_fees) => {
                log_trace!(self.logger, "Retrieved fees from mempool");
                mempool_fees
            }
            Err(e) => {
                log_trace!(
                    self.logger,
                    "Failed to retrieve fees from mempool, falling back to esplora: {e}"
                );
                self.esplora.get_fee_estimates().await.map_err(|e| {
                    log_trace!(self.logger, "Failed to get esplora fee: {e}");
                    e
                })?
            }
        };

        self.storage.insert_fee_estimates(fee_estimates)?;
        let mut update_time_lock = self.last_fee_update_time_secs.lock().await;
        *update_time_lock = Some(utils::now().as_secs());

        Ok(())
    }

    pub fn get_low_fee_rate(&self) -> u32 {
        // MinAllowedNonAnchorChannelRemoteFee is a fee rate we expect to get slowly
        self.get_est_sat_per_1000_weight(ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee)
    }

    pub fn get_normal_fee_rate(&self) -> u32 {
        // NonAnchorChannelFee is a fee rate we expect to be confirmed in 6 blocks
        self.get_est_sat_per_1000_weight(ConfirmationTarget::NonAnchorChannelFee)
    }

    pub fn get_high_fee_rate(&self) -> u32 {
        // OnChainSweep is the highest fee rate we have, so use that
        self.get_est_sat_per_1000_weight(ConfirmationTarget::OnChainSweep)
    }
}

impl<S: MutinyStorage> FeeEstimator for MutinyFeeEstimator<S> {
    fn get_est_sat_per_1000_weight(&self, confirmation_target: ConfirmationTarget) -> u32 {
        let num_blocks = num_blocks_from_conf_target(confirmation_target);
        let fallback_fee = fallback_fee_from_conf_target(confirmation_target);

        let fee = match self.storage.get_fee_estimates() {
            Err(_) | Ok(None) => fallback_fee,
            Ok(Some(estimates)) => {
                let found = estimates.get(&num_blocks.to_string());
                match found {
                    Some(num) => {
                        log_trace!(self.logger, "Got fee rate from saved cache!");
                        let sats_vbyte = num.to_owned();
                        // convert to sats per kw
                        let fee_rate = sats_vbyte * 250.0;

                        // return the fee rate, but make sure it's not lower than the floor
                        (fee_rate as u32).max(FEERATE_FLOOR_SATS_PER_KW)
                    }
                    None => fallback_fee,
                }
            }
        };

        // any post processing we do after we get the fee rate from the cache
        match confirmation_target {
            ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee => fee - 250, // helps with rounding errors
            ConfirmationTarget::AnchorChannelFee => (fee / 2).max(250), // do half the mempool minimum just to prevent force closes
            _ => fee,
        }
    }
}

fn num_blocks_from_conf_target(confirmation_target: ConfirmationTarget) -> usize {
    match confirmation_target {
        ConfirmationTarget::AnchorChannelFee => 1008,
        ConfirmationTarget::MinAllowedAnchorChannelRemoteFee => 1008,
        ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee => 1008,
        ConfirmationTarget::ChannelCloseMinimum => 1008,
        ConfirmationTarget::NonAnchorChannelFee => 6,
        ConfirmationTarget::OnChainSweep => 1,
    }
}

fn fallback_fee_from_conf_target(confirmation_target: ConfirmationTarget) -> u32 {
    match confirmation_target {
        ConfirmationTarget::MinAllowedAnchorChannelRemoteFee => 3 * 250,
        ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee => 3 * 250,
        ConfirmationTarget::ChannelCloseMinimum => 10 * 250,
        ConfirmationTarget::AnchorChannelFee => 10 * 250,
        ConfirmationTarget::NonAnchorChannelFee => 20 * 250,
        ConfirmationTarget::OnChainSweep => 50 * 250,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(not(target_arch = "wasm32"))]
    use crate::storage::{MemoryStorage, MutinyStorage};
    #[cfg(not(target_arch = "wasm32"))]
    use crate::test_utils::*;
    #[cfg(not(target_arch = "wasm32"))]
    use esplora_client::Builder;
    #[cfg(not(target_arch = "wasm32"))]
    use std::collections::HashMap;

    #[cfg(not(target_arch = "wasm32"))]
    async fn create_fee_estimator() -> MutinyFeeEstimator<MemoryStorage> {
        let storage = MemoryStorage::default();
        let esplora = Arc::new(
            Builder::new("https://mutinynet.com/api")
                .build_async()
                .unwrap(),
        );
        let logger = Arc::new(MutinyLogger::default());

        MutinyFeeEstimator::new(storage, esplora, logger)
    }

    #[test]
    fn test_num_blocks_from_conf_target() {
        assert_eq!(
            num_blocks_from_conf_target(ConfirmationTarget::ChannelCloseMinimum),
            1008
        );
        assert_eq!(
            num_blocks_from_conf_target(ConfirmationTarget::NonAnchorChannelFee),
            6
        );
        assert_eq!(
            num_blocks_from_conf_target(ConfirmationTarget::OnChainSweep),
            1
        );
    }

    #[test]
    fn test_fallback_fee_from_conf_target() {
        assert_eq!(
            fallback_fee_from_conf_target(ConfirmationTarget::ChannelCloseMinimum),
            2_500
        );
        assert_eq!(
            fallback_fee_from_conf_target(ConfirmationTarget::NonAnchorChannelFee),
            5_000
        );
        assert_eq!(
            fallback_fee_from_conf_target(ConfirmationTarget::OnChainSweep),
            12_500
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_update_fee_estimates() {
        let test_name = "test_update_fee_estimates";
        log!("{}", test_name);

        let fee_estimator = create_fee_estimator().await;
        fee_estimator.update_fee_estimates().await.unwrap();

        let fee_estimates = fee_estimator.storage.get_fee_estimates().unwrap().unwrap();
        assert!(!fee_estimates.is_empty());
        assert!(fee_estimates.get("3").is_some());
        assert!(fee_estimates.get("6").is_some());
        assert!(fee_estimates.get("1008").is_some());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_get_est_sat_per_1000_weight() {
        let test_name = "test_get_est_sat_per_1000_weight";
        log!("{}", test_name);

        let fee_estimator = create_fee_estimator().await;
        // set up the cache
        let mut fee_estimates = HashMap::new();
        fee_estimates.insert("6".to_string(), 10_f64);
        fee_estimator
            .storage
            .insert_fee_estimates(fee_estimates)
            .unwrap();

        // test that we get the fee rate from the cache
        assert_eq!(
            fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::NonAnchorChannelFee),
            2500
        );

        // test that we get the fallback fee rate
        assert_eq!(
            fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::ChannelCloseMinimum),
            2_500
        );
        assert_eq!(
            fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::OnChainSweep),
            12_500
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_estimate_expected_fee() {
        let test_name = "test_estimate_expected_fee";
        log!("{}", test_name);

        let fee_estimator = create_fee_estimator().await;

        assert_eq!(
            fee_estimator.calculate_expected_fee(
                1,
                TAPROOT_OUTPUT_SIZE,
                Some(TAPROOT_OUTPUT_SIZE),
                Some(1_000)
            ),
            616
        );

        // set up the cache
        let mut fee_estimates = HashMap::new();
        fee_estimates.insert("3".to_string(), 20_f64);
        fee_estimates.insert("6".to_string(), 8_f64);
        fee_estimates.insert("1008".to_string(), 1_f64);
        fee_estimator
            .storage
            .insert_fee_estimates(fee_estimates)
            .unwrap();

        assert_eq!(
            fee_estimator.calculate_expected_fee(1, P2WSH_OUTPUT_SIZE, None, None),
            888
        );

        assert_eq!(
            fee_estimator.calculate_expected_fee(1, P2WSH_OUTPUT_SIZE, None, Some(4000)),
            1776
        );

        assert_eq!(
            fee_estimator.calculate_expected_fee(3, P2WSH_OUTPUT_SIZE, None, None),
            1816
        );

        assert_eq!(
            fee_estimator.calculate_expected_fee(
                3,
                P2WSH_OUTPUT_SIZE,
                Some(TAPROOT_OUTPUT_SIZE),
                None
            ),
            2160
        );
    }
}
