use crate::indexed_db::MutinyStorage;
use lightning::chain::chaininterface::{
    ConfirmationTarget, FeeEstimator, FEERATE_FLOOR_SATS_PER_KW,
};
use log::trace;

#[derive(Clone)]
pub struct MutinyFeeEstimator {
    storage: MutinyStorage,
}

impl MutinyFeeEstimator {
    pub fn new(storage: MutinyStorage) -> MutinyFeeEstimator {
        MutinyFeeEstimator { storage }
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
                        trace!("Got fee rate from saved cache!");
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
    async fn test_get_est_sat_per_1000_weight() {
        let storage = MutinyStorage::new("".to_string()).await.unwrap();
        let mut fee_estimates = HashMap::new();
        fee_estimates.insert("6".to_string(), 10_f64);
        storage.insert_fee_estimates(fee_estimates).unwrap();

        let fee_estimator = MutinyFeeEstimator::new(storage);

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

        cleanup_wallet_test().await;
    }
}
