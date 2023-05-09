use crate::error::MutinyError;
use crate::indexed_db::MutinyStorage;
use crate::logging::MutinyLogger;
use esplora_client::AsyncClient;
use lightning::chain::chaininterface::{
    ConfirmationTarget, FeeEstimator, FEERATE_FLOOR_SATS_PER_KW,
};
use lightning::log_trace;
use lightning::util::logger::Logger;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct MutinyFeeEstimator {
    storage: MutinyStorage,
    esplora: Arc<AsyncClient>,
    logger: Arc<MutinyLogger>,
}

impl MutinyFeeEstimator {
    pub fn new(
        storage: MutinyStorage,
        esplora: Arc<AsyncClient>,
        logger: Arc<MutinyLogger>,
    ) -> MutinyFeeEstimator {
        MutinyFeeEstimator {
            storage,
            esplora,
            logger,
        }
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

impl MutinyFeeEstimator {
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

impl FeeEstimator for MutinyFeeEstimator {
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
    use crate::indexed_db::MutinyStorage;
    use crate::test_utils::*;
    use esplora_client::Builder;
    use std::collections::HashMap;

    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

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
        let storage = MutinyStorage::new("".to_string()).await.unwrap();
        let esplora = Arc::new(
            Builder::new("https://mutinynet.com/api")
                .build_async()
                .unwrap(),
        );
        let logger = Arc::new(MutinyLogger::default());

        let fee_estimator = MutinyFeeEstimator::new(storage, esplora, logger);

        fee_estimator.update_fee_estimates().await.unwrap();

        let fee_estimates = fee_estimator.storage.get_fee_estimates().unwrap().unwrap();
        assert!(!fee_estimates.is_empty());
        assert!(fee_estimates.get("3").is_some());
        assert!(fee_estimates.get("6").is_some());
        assert!(fee_estimates.get("12").is_some());

        cleanup_all().await;
    }

    #[test]
    async fn test_get_est_sat_per_1000_weight() {
        let storage = MutinyStorage::new("".to_string()).await.unwrap();
        let mut fee_estimates = HashMap::new();
        fee_estimates.insert("6".to_string(), 10_f64);
        storage.insert_fee_estimates(fee_estimates).unwrap();
        let esplora = Arc::new(
            Builder::new("https://mutinynet.com/api")
                .build_async()
                .unwrap(),
        );

        let logger = Arc::new(MutinyLogger::default());
        let fee_estimator = MutinyFeeEstimator::new(storage, esplora, logger);

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

        cleanup_all().await;
    }
}
