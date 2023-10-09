use std::sync::Arc;

use crate::esplora::EsploraSyncClient;
use bitcoin::{Script, Transaction, Txid};
use lightning::chain::chaininterface::BroadcasterInterface;
use lightning::chain::{Filter, WatchedOutput};
use lightning::log_warn;
use lightning::util::logger::Logger;
use surrealdb::Connection;

use crate::logging::MutinyLogger;
use crate::onchain::OnChainWallet;
use crate::utils;

pub struct MutinyChain<S: Connection + Clone> {
    pub tx_sync: Arc<EsploraSyncClient<Arc<MutinyLogger>>>,
    pub wallet: Arc<OnChainWallet<S>>,
    logger: Arc<MutinyLogger>,
}

impl<S: Connection + Clone> MutinyChain<S> {
    pub(crate) fn new(
        tx_sync: Arc<EsploraSyncClient<Arc<MutinyLogger>>>,
        wallet: Arc<OnChainWallet<S>>,
        logger: Arc<MutinyLogger>,
    ) -> Self {
        Self {
            tx_sync,
            wallet,
            logger,
        }
    }
}

impl<S: Connection + Clone> Filter for MutinyChain<S> {
    fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
        self.tx_sync.register_tx(txid, script_pubkey);
    }

    fn register_output(&self, output: WatchedOutput) {
        self.tx_sync.register_output(output);
    }
}

impl<S: Connection + Clone> BroadcasterInterface for MutinyChain<S> {
    fn broadcast_transactions(&self, txs: &[&Transaction]) {
        let txs_clone = txs
            .iter()
            .map(|tx| (*tx).clone())
            .collect::<Vec<Transaction>>();
        let wallet = self.wallet.clone();
        let logger = self.logger.clone();
        utils::spawn(async move {
            for tx in txs_clone {
                if let Err(e) = wallet.broadcast_transaction(tx).await {
                    log_warn!(logger, "Error broadcasting transaction: {e}")
                }
            }
        });
    }
}
