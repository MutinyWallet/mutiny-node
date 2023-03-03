use std::sync::Arc;

use bdk::FeeRate;
use bdk_macros::maybe_await;
use bitcoin::{Script, Transaction, Txid};
use lightning::chain::chaininterface::{
    BroadcasterInterface, ConfirmationTarget, FeeEstimator, FEERATE_FLOOR_SATS_PER_KW,
};
use lightning::chain::{Filter, WatchedOutput};
use lightning_transaction_sync::EsploraSyncClient;
use log::{error, trace};
use wasm_bindgen_futures::spawn_local;

use crate::localstorage::MutinyBrowserStorage;
use crate::logging::MutinyLogger;

pub struct MutinyChain {
    pub tx_sync: Arc<EsploraSyncClient<Arc<MutinyLogger>>>,
}

impl MutinyChain {
    pub(crate) fn new(tx_sync: Arc<EsploraSyncClient<Arc<MutinyLogger>>>) -> Self {
        Self { tx_sync }
    }
}

impl Filter for MutinyChain {
    fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
        self.tx_sync.register_tx(txid, script_pubkey);
    }

    fn register_output(&self, output: WatchedOutput) {
        self.tx_sync.register_output(output);
    }
}

impl BroadcasterInterface for MutinyChain {
    fn broadcast_transaction(&self, tx: &Transaction) {
        let blockchain = self.tx_sync.clone();
        let tx_clone = tx.clone();
        spawn_local(async move {
            maybe_await!(blockchain.client().broadcast(&tx_clone))
                .unwrap_or_else(|_| error!("failed to broadcast tx! {}", tx_clone.txid()))
        });
    }
}

impl FeeEstimator for MutinyChain {
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
                        let satsVbyte = num.to_owned() as f32;
                        let fee_rate = FeeRate::from_sat_per_vb(satsVbyte);
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
