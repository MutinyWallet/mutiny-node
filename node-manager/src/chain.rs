use bitcoin::{BlockHash, BlockHeader, Script, Transaction, Txid};

use crate::error::MutinyError;
use crate::wallet::MutinyWallet;
use bdk::blockchain::Blockchain;
use bdk_macros::maybe_await;
use lightning::chain::chaininterface::{
    BroadcasterInterface, ConfirmationTarget, FeeEstimator, FEERATE_FLOOR_SATS_PER_KW,
};
use lightning::chain::{Confirm, Filter, WatchedOutput};
use log::error;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use wasm_bindgen_futures::spawn_local;

pub struct MutinyChain {
    wallet: Arc<MutinyWallet>,
    // Transactions that were registered via the `Filter` interface and have to be processed.
    queued_transactions: Mutex<HashSet<Txid>>,
    // Transactions that were previously processed, but must not be forgotten yet.
    watched_transactions: Mutex<HashSet<Txid>>,
    // Outputs that were registered via the `Filter` interface and have to be processed.
    queued_outputs: Mutex<HashSet<WatchedOutput>>,
    // Outputs that were previously processed, but must not be forgotten yet.
    watched_outputs: Mutex<HashSet<WatchedOutput>>,
    // The tip hash observed during our last sync.
    last_sync_hash: futures::lock::Mutex<Option<BlockHash>>,
}

impl MutinyChain {
    pub(crate) fn new(wallet: Arc<MutinyWallet>) -> Self {
        let watched_transactions = Mutex::new(HashSet::new());
        let queued_transactions = Mutex::new(HashSet::new());
        let watched_outputs = Mutex::new(HashSet::new());
        let queued_outputs = Mutex::new(HashSet::new());
        let last_sync_hash = futures::lock::Mutex::new(None);
        Self {
            wallet,
            queued_transactions,
            watched_transactions,
            queued_outputs,
            watched_outputs,
            last_sync_hash,
        }
    }

    /// Syncs the LDK wallet via the `Confirm` interface. We run in a loop until we completed a
    /// full iteration without
    pub(crate) async fn sync(
        &self,
        confirmables: Vec<&(dyn Confirm + Sync)>,
    ) -> Result<(), MutinyError> {
        // This lock makes sure we're syncing once at a time.
        let mut locked_last_sync_hash = self.last_sync_hash.lock().await;

        let client = &*self.wallet.blockchain;

        let mut tip_hash = client.get_tip_hash().await?;

        loop {
            let registrations_are_pending = self.process_queues();
            let tip_is_new = Some(tip_hash) != *locked_last_sync_hash;

            // We loop until any registered transactions have been processed at least once, or the
            // tip hasn't been updated during the last iteration.
            if !registrations_are_pending && !tip_is_new {
                // Nothing to do.
                break;
            } else {
                // Update the known tip to the newest one.
                if tip_is_new {
                    // First check for any unconfirmed transactions and act on it immediately.
                    self.sync_unconfirmed_transactions(&confirmables).await?;

                    match self.sync_best_block_updated(&confirmables, &tip_hash).await {
                        Ok(()) => {}
                        Err(MutinyError::ChainAccessFailed) => {
                            // Immediately restart syncing when we encounter any inconsistencies.
                            continue;
                        }
                        Err(err) => {
                            // (Semi-)permanent failure, retry later.
                            return Err(err);
                        }
                    }
                }

                match self.get_confirmed_transactions().await {
                    Ok((confirmed_txs, unconfirmed_registered_txs, unspent_registered_outputs)) => {
                        // Double-check tip hash. If something changed, restart last-minute.
                        tip_hash = client.get_tip_hash().await?;
                        if Some(tip_hash) != *locked_last_sync_hash {
                            continue;
                        }

                        self.sync_confirmed_transactions(
                            &confirmables,
                            confirmed_txs,
                            unconfirmed_registered_txs,
                            unspent_registered_outputs,
                        );
                    }
                    Err(MutinyError::ChainAccessFailed) => {
                        // Immediately restart syncing when we encounter any inconsistencies.
                        continue;
                    }
                    Err(err) => {
                        // (Semi-)permanent failure, retry later.
                        return Err(err);
                    }
                }
                *locked_last_sync_hash = Some(tip_hash);
            }
        }
        Ok(())
    }

    // Processes the transaction and output queues, returns `true` if new items had been
    // registered.
    fn process_queues(&self) -> bool {
        let mut pending_registrations = false;
        {
            let mut locked_queued_transactions = self.queued_transactions.lock().unwrap();
            if !locked_queued_transactions.is_empty() {
                let mut locked_watched_transactions = self.watched_transactions.lock().unwrap();
                pending_registrations = true;

                locked_watched_transactions.extend(locked_queued_transactions.iter());
                *locked_queued_transactions = HashSet::new();
            }
        }
        {
            let mut locked_queued_outputs = self.queued_outputs.lock().unwrap();
            if !locked_queued_outputs.is_empty() {
                let mut locked_watched_outputs = self.watched_outputs.lock().unwrap();
                pending_registrations = true;

                locked_watched_outputs.extend(locked_queued_outputs.iter().cloned());
                *locked_queued_outputs = HashSet::new();
            }
        }
        pending_registrations
    }

    async fn sync_best_block_updated(
        &self,
        confirmables: &Vec<&(dyn Confirm + Sync)>,
        tip_hash: &BlockHash,
    ) -> Result<(), MutinyError> {
        let client = &*self.wallet.blockchain;

        // Inform the interface of the new block.
        let tip_header = client.get_header_by_hash(tip_hash).await?;
        let tip_status = client.get_block_status(tip_hash).await?;
        if tip_status.in_best_chain {
            if let Some(tip_height) = tip_status.height {
                for c in confirmables {
                    c.best_block_updated(&tip_header, tip_height);
                }
            }
        } else {
            return Err(MutinyError::ChainAccessFailed);
        }
        Ok(())
    }

    fn sync_confirmed_transactions(
        &self,
        confirmables: &Vec<&(dyn Confirm + Sync)>,
        confirmed_txs: Vec<ConfirmedTx>,
        unconfirmed_registered_txs: HashSet<Txid>,
        unspent_registered_outputs: HashSet<WatchedOutput>,
    ) {
        for ctx in confirmed_txs {
            for c in confirmables {
                c.transactions_confirmed(
                    &ctx.block_header,
                    &[(ctx.pos, &ctx.tx)],
                    ctx.block_height,
                );
            }
        }

        *self.watched_transactions.lock().unwrap() = unconfirmed_registered_txs;
        *self.watched_outputs.lock().unwrap() = unspent_registered_outputs;
    }

    async fn get_confirmed_transactions(
        &self,
    ) -> Result<(Vec<ConfirmedTx>, HashSet<Txid>, HashSet<WatchedOutput>), MutinyError> {
        let client = &*self.wallet.blockchain;

        // First, check the confirmation status of registered transactions as well as the
        // status of dependent transactions of registered outputs.

        let mut confirmed_txs = Vec::new();

        // Check in the current queue, as well as in registered transactions leftover from
        // previous iterations.
        let registered_txs = self.watched_transactions.lock().unwrap().clone();

        // Remember all registered but unconfirmed transactions for future processing.
        let mut unconfirmed_registered_txs = HashSet::new();

        for txid in registered_txs {
            if let Some(confirmed_tx) = self.get_confirmed_tx(&txid, None, None).await? {
                confirmed_txs.push(confirmed_tx);
            } else {
                unconfirmed_registered_txs.insert(txid);
            }
        }

        // Check all registered outputs for dependent spending transactions.
        let registered_outputs = self.watched_outputs.lock().unwrap().clone();

        // Remember all registered outputs that haven't been spent for future processing.
        let mut unspent_registered_outputs = HashSet::new();

        for output in registered_outputs {
            if let Some(output_status) = client
                .get_output_status(&output.outpoint.txid, output.outpoint.index as u64)
                .await?
            {
                if let Some(spending_txid) = output_status.txid {
                    if let Some(spending_tx_status) = output_status.status {
                        if let Some(confirmed_tx) = self
                            .get_confirmed_tx(
                                &spending_txid,
                                spending_tx_status.block_hash,
                                spending_tx_status.block_height,
                            )
                            .await?
                        {
                            confirmed_txs.push(confirmed_tx);
                            continue;
                        }
                    }
                }
            }
            unspent_registered_outputs.insert(output);
        }

        // Sort all confirmed transactions first by block height, then by in-block
        // position, and finally feed them to the interface in order.
        confirmed_txs.sort_unstable_by(|tx1, tx2| {
            tx1.block_height
                .cmp(&tx2.block_height)
                .then_with(|| tx1.pos.cmp(&tx2.pos))
        });

        Ok((
            confirmed_txs,
            unconfirmed_registered_txs,
            unspent_registered_outputs,
        ))
    }

    async fn get_confirmed_tx(
        &self,
        txid: &Txid,
        expected_block_hash: Option<BlockHash>,
        known_block_height: Option<u32>,
    ) -> Result<Option<ConfirmedTx>, MutinyError> {
        let client = &*self.wallet.blockchain;

        if let Some(merkle_proof) = client.get_merkle_proof(txid).await? {
            let block_hash = client.get_block_hash(merkle_proof.block_height).await?;
            if let Some(expected_block_hash) = expected_block_hash {
                if expected_block_hash != block_hash {
                    return Err(MutinyError::ChainAccessFailed);
                }
            }

            let block_header = client.get_header_by_hash(&block_hash).await?;

            if let Some(tx) = client.get_tx(txid).await? {
                // We can take a shortcut here if a previous call already gave us the height.
                if let Some(block_height) = known_block_height {
                    // if we have mismatched heights something probably went wrong
                    if merkle_proof.block_height != block_height {
                        return Err(MutinyError::ChainAccessFailed);
                    }
                    return Ok(Some(ConfirmedTx {
                        tx,
                        block_header,
                        pos: merkle_proof.pos,
                        block_height,
                    }));
                }

                return Ok(Some(ConfirmedTx {
                    tx,
                    block_header,
                    pos: merkle_proof.pos,
                    block_height: merkle_proof.block_height,
                }));
            }
        }
        Ok(None)
    }

    async fn sync_unconfirmed_transactions(
        &self,
        confirmables: &Vec<&(dyn Confirm + Sync)>,
    ) -> Result<(), MutinyError> {
        let client = &*self.wallet.blockchain;
        // Query the interface for relevant txids and check whether they are still
        // in the best chain, mark them unconfirmed otherwise.

        let relevant_txids = confirmables
            .iter()
            .flat_map(|c| c.get_relevant_txids())
            .collect::<Vec<Txid>>();
        for txid in relevant_txids {
            match client.get_tx_status(&txid).await {
                Ok(Some(status)) => {
                    // Skip if the tx in question is still confirmed.
                    if status.confirmed {
                        continue;
                    }
                }
                // if the tx no longer exists or errors, we should
                // consider it unconfirmed
                Ok(None) => (),
                Err(_) => (),
            }

            for c in confirmables {
                c.transaction_unconfirmed(&txid);
            }
        }

        Ok(())
    }
}

struct ConfirmedTx {
    tx: Transaction,
    block_header: BlockHeader,
    block_height: u32,
    pos: usize,
}

impl Filter for MutinyChain {
    fn register_tx(&self, txid: &Txid, _script_pubkey: &Script) {
        self.queued_transactions.lock().unwrap().insert(*txid);
    }

    fn register_output(&self, output: WatchedOutput) {
        self.queued_outputs.lock().unwrap().insert(output);
    }
}

impl BroadcasterInterface for MutinyChain {
    fn broadcast_transaction(&self, tx: &Transaction) {
        let blockchain = self.wallet.blockchain.clone();
        let tx_clone = tx.clone();
        spawn_local(async move {
            maybe_await!(blockchain.broadcast(&tx_clone))
                .unwrap_or_else(|_| error!("failed to broadcast tx! {}", tx_clone.txid()))
        });
    }
}

impl FeeEstimator for MutinyChain {
    fn get_est_sat_per_1000_weight(&self, confirmation_target: ConfirmationTarget) -> u32 {
        // todo get from esplora
        fallback_fee_from_conf_target(confirmation_target)
    }
}

fn fallback_fee_from_conf_target(confirmation_target: ConfirmationTarget) -> u32 {
    match confirmation_target {
        ConfirmationTarget::Background => FEERATE_FLOOR_SATS_PER_KW,
        ConfirmationTarget::Normal => 2000,
        ConfirmationTarget::HighPriority => 5000,
    }
}
