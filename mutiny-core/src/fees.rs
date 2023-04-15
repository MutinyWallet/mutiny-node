use crate::localstorage::MutinyBrowserStorage;
use bdk::FeeRate;
use lightning::chain::chaininterface::{
    ConfirmationTarget, FeeEstimator, FEERATE_FLOOR_SATS_PER_KW,
};
use log::trace;

#[derive(Debug, Clone, Default)]
pub struct MutinyFeeEstimator {}

impl FeeEstimator for MutinyFeeEstimator {
    fn get_est_sat_per_1000_weight(&self, confirmation_target: ConfirmationTarget) -> u32 {
        let num_blocks = num_blocks_from_conf_target(confirmation_target);
        let fallback_fee = fallback_fee_from_conf_target(confirmation_target);

        match MutinyBrowserStorage::get_fee_estimates() {
            Err(_) => fallback_fee,
            Ok(estimates) => {
                let found = estimates.get(num_blocks.to_string().as_str());
                match found {
                    Some(num) => {
                        trace!("Got fee rate from saved cache!");
                        let sats_vbyte = num.to_owned() as f32;
                        let fee_rate = FeeRate::from_sat_per_vb(sats_vbyte);
                        (fee_rate.fee_wu(1000) as u32).max(FEERATE_FLOOR_SATS_PER_KW)
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
