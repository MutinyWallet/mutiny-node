use std::sync::Arc;

use crate::esplora::EsploraSyncClient;
use bitcoin::{Script, Transaction, Txid};
use lightning::chain::chaininterface::BroadcasterInterface;
use lightning::chain::{Filter, WatchedOutput};
use lightning::log_warn;
use lightning::util::logger::Logger;

use crate::logging::MutinyLogger;
use crate::onchain::OnChainWallet;
use crate::storage::MutinyStorage;
use crate::utils;

pub struct MutinyChain<S: MutinyStorage> {
    pub tx_sync: Arc<EsploraSyncClient<Arc<MutinyLogger>>>,
    pub wallet: Arc<OnChainWallet<S>>,
    logger: Arc<MutinyLogger>,
}

impl<S: MutinyStorage> MutinyChain<S> {
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

impl<S: MutinyStorage> Filter for MutinyChain<S> {
    fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
        self.tx_sync.register_tx(txid, script_pubkey);
    }

    fn register_output(&self, output: WatchedOutput) {
        self.tx_sync.register_output(output);
    }
}

impl<S: MutinyStorage> BroadcasterInterface for MutinyChain<S> {
    fn broadcast_transaction(&self, tx: &Transaction) {
        let tx_clone = tx.clone();
        let wallet = self.wallet.clone();
        let logger = self.logger.clone();
        utils::spawn(async move {
            if let Err(e) = wallet.broadcast_transaction(tx_clone).await {
                log_warn!(logger, "Error broadcasting transaction: {e}")
            }
        });
    }
}
