use std::sync::Arc;

use crate::esplora::EsploraSyncClient;
use bdk_macros::maybe_await;
use bitcoin::{Script, Transaction, Txid};
use lightning::chain::chaininterface::BroadcasterInterface;
use lightning::chain::{Filter, WatchedOutput};
use lightning::log_error;
use lightning::util::logger::Logger;
use wasm_bindgen_futures::spawn_local;

use crate::logging::MutinyLogger;

pub struct MutinyChain {
    pub tx_sync: Arc<EsploraSyncClient<Arc<MutinyLogger>>>,
    logger: Arc<MutinyLogger>,
}

impl MutinyChain {
    pub(crate) fn new(
        tx_sync: Arc<EsploraSyncClient<Arc<MutinyLogger>>>,
        logger: Arc<MutinyLogger>,
    ) -> Self {
        Self { tx_sync, logger }
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
        let logger = self.logger.clone();
        spawn_local(async move {
            maybe_await!(blockchain.client().broadcast(&tx_clone)).unwrap_or_else(|_| {
                log_error!(logger, "failed to broadcast tx! {}", tx_clone.txid())
            })
        });
    }
}
