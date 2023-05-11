use crate::error::MutinyError;
use crate::logging::MutinyLogger;
use crate::storage::MutinyStorage;
use bdk::FeeRate;
use esplora_client::AsyncClient;
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
        let sats_per_kw = sats_per_kw
            .unwrap_or_else(|| self.get_est_sat_per_1000_weight(ConfirmationTarget::Normal));
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
        FeeRate::from_sat_per_kwu(sats_per_kw as f32).fee_wu(expected_weight)
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
        let fees = self
            .esplora
            .client()
            .get(&format!("{}/v1/fees/recommended", self.esplora.url()))
            .send()
            .await?
            .error_for_status()?
            .json::<MempoolFees>()
            .await?;

        // convert to hashmap of num blocks -> fee rate
        let mut fee_estimates = HashMap::new();
        fee_estimates.insert("1".to_string(), fees.fastest_fee);
        fee_estimates.insert("3".to_string(), fees.half_hour_fee);
        fee_estimates.insert("6".to_string(), fees.hour_fee);
        fee_estimates.insert("12".to_string(), fees.economy_fee);
        fee_estimates.insert("1008".to_string(), fees.minimum_fee);

        Ok(fee_estimates)
    }

    pub async fn update_fee_estimates(&self) -> Result<(), MutinyError> {
        // first try mempool.space's API
        let mempool_fees = self.get_mempool_recommended_fees().await;

        // if that fails, fall back to esplora's API
        let fee_estimates = match mempool_fees {
            Ok(mempool_fees) => mempool_fees,
            Err(_) => self.esplora.get_fee_estimates().await?,
        };

        self.storage.insert_fee_estimates(fee_estimates)?;

        Ok(())
    }
}

impl<S: MutinyStorage> FeeEstimator for MutinyFeeEstimator<S> {
    fn get_est_sat_per_1000_weight(&self, confirmation_target: ConfirmationTarget) -> u32 {
        let num_blocks = num_blocks_from_conf_target(confirmation_target);
        let fallback_fee = fallback_fee_from_conf_target(confirmation_target);

        match self.storage.get_fee_estimates() {
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
        }
    }
}

fn num_blocks_from_conf_target(confirmation_target: ConfirmationTarget) -> usize {
    match confirmation_target {
        ConfirmationTarget::Background => 12,
        ConfirmationTarget::Normal => 6,
        ConfirmationTarget::HighPriority => 3,
    }
}

fn fallback_fee_from_conf_target(confirmation_target: ConfirmationTarget) -> u32 {
    match confirmation_target {
        ConfirmationTarget::Background => FEERATE_FLOOR_SATS_PER_KW,
        ConfirmationTarget::Normal => 2000,
        ConfirmationTarget::HighPriority => 5000,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::storage::{MemoryStorage, MutinyStorage};
    use crate::test_utils::*;
    use esplora_client::Builder;
    use std::collections::HashMap;

    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    async fn create_fee_estimator() -> MutinyFeeEstimator<MemoryStorage> {
        let storage = MemoryStorage::new(None);
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
            num_blocks_from_conf_target(ConfirmationTarget::Background),
            12
        );
        assert_eq!(num_blocks_from_conf_target(ConfirmationTarget::Normal), 6);
        assert_eq!(
            num_blocks_from_conf_target(ConfirmationTarget::HighPriority),
            3
        );
    }

    #[test]
    fn test_fallback_fee_from_conf_target() {
        assert_eq!(
            fallback_fee_from_conf_target(ConfirmationTarget::Background),
            253
        );
        assert_eq!(
            fallback_fee_from_conf_target(ConfirmationTarget::Normal),
            2000
        );
        assert_eq!(
            fallback_fee_from_conf_target(ConfirmationTarget::HighPriority),
            5000
        );
    }

    #[test]
    async fn test_update_fee_estimates() {
        let test_name = "test_update_fee_estimates";
        log!("{}", test_name);

        let fee_estimator = create_fee_estimator().await;
        fee_estimator.update_fee_estimates().await.unwrap();

        let fee_estimates = fee_estimator.storage.get_fee_estimates().unwrap().unwrap();
        assert!(!fee_estimates.is_empty());
        assert!(fee_estimates.get("3").is_some());
        assert!(fee_estimates.get("6").is_some());
        assert!(fee_estimates.get("12").is_some());
    }

    #[test]
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
            fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Normal),
            2500
        );

        // test that we get the fallback fee rate
        assert_eq!(
            fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::Background),
            253
        );
        assert_eq!(
            fee_estimator.get_est_sat_per_1000_weight(ConfirmationTarget::HighPriority),
            5000
        );
    }

    #[test]
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
