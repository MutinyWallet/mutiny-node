use async_trait::async_trait;
use bdk_chain::{
    bitcoin::{BlockHash, OutPoint, Script, Txid},
    collections::BTreeMap,
    keychain::LocalUpdate,
    BlockId, ConfirmationTimeAnchor,
};
use bdk_esplora::EsploraAsyncExt;
use bitcoin::secp256k1::rand;
use bitcoin::secp256k1::rand::prelude::SliceRandom;
use bitcoin::{BlockHeader, MerkleBlock, Transaction};
use esplora_client::{AsyncClient, BlockStatus, Error, OutputStatus, TxStatus};
use futures::{stream::FuturesOrdered, TryStreamExt};
use reqwest::Client;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct MultiEsploraClient {
    clients: Vec<Arc<AsyncClient>>,
}

impl MultiEsploraClient {
    pub fn new(clients: Vec<Arc<AsyncClient>>) -> Self {
        if clients.is_empty() {
            panic!("No esplora clients provided");
        }

        Self { clients }
    }

    /// Broadcast a [`Transaction`] to Esplora
    fn get_random_client(&self) -> Arc<AsyncClient> {
        let client = self.clients.choose(&mut rand::thread_rng()).unwrap();
        client.clone()
    }

    pub(crate) fn client(&self) -> Client {
        let client = self.get_random_client();
        client.client().to_owned()
    }

    pub(crate) fn url(&self) -> String {
        let client = self.get_random_client();
        client.url().to_owned()
    }

    pub async fn broadcast(&self, transaction: &Transaction) -> Result<(), Error> {
        // broadcast transaction to random client
        let client = self.get_random_client();
        client.broadcast(transaction).await
    }

    /// Get the [`BlockHash`] of a specific block height
    pub async fn get_block_hash(&self, block_height: u32) -> Result<BlockHash, Error> {
        let client = self.get_random_client();
        client.get_block_hash(block_height).await
    }

    /// Get the current block height
    pub async fn get_height(&self) -> Result<u32, Error> {
        let client = self.get_random_client();
        client.get_height().await
    }

    /// Get the current tip hash
    pub async fn get_tip_hash(&self) -> Result<BlockHash, Error> {
        let client = self.get_random_client();
        client.get_tip_hash().await
    }

    /// Get confirmed transaction history for the specified address/scripthash,
    /// sorted with newest first. Returns 25 transactions per page.
    /// More can be requested by specifying the last txid seen by the previous query.
    pub async fn scripthash_txs(
        &self,
        script: &Script,
        last_seen: Option<Txid>,
    ) -> Result<Vec<esplora_client::Tx>, Error> {
        let client = self.get_random_client();
        client.scripthash_txs(script, last_seen).await
    }

    /// Get a [`Transaction`] option given its [`Txid`]
    pub async fn get_tx(&self, txid: &Txid) -> Result<Option<Transaction>, Error> {
        let client = self.get_random_client();
        client.get_tx(txid).await
    }

    /// Get the status of a [`Transaction`] given its [`Txid`].
    pub async fn get_tx_status(&self, txid: &Txid) -> Result<TxStatus, Error> {
        let client = self.get_random_client();
        client.get_tx_status(txid).await
    }

    /// Get the spending status of an output given a [`Txid`] and the output index.
    pub async fn get_output_status(
        &self,
        txid: &Txid,
        index: u64,
    ) -> Result<Option<OutputStatus>, Error> {
        let client = self.get_random_client();
        client.get_output_status(txid, index).await
    }

    /// Get the [`BlockStatus`] given a particular [`BlockHash`].
    pub async fn get_block_status(&self, block_hash: &BlockHash) -> Result<BlockStatus, Error> {
        let client = self.get_random_client();
        client.get_block_status(block_hash).await
    }

    /// Get a [`MerkleBlock`] inclusion proof for a [`Transaction`] with the given [`Txid`].
    pub async fn get_merkle_block(&self, tx_hash: &Txid) -> Result<Option<MerkleBlock>, Error> {
        let client = self.get_random_client();
        client.get_merkle_block(tx_hash).await
    }

    /// Get a [`BlockHeader`] given a particular block hash.
    pub async fn get_header_by_hash(&self, block_hash: &BlockHash) -> Result<BlockHeader, Error> {
        let client = self.get_random_client();
        client.get_header_by_hash(block_hash).await
    }

    /// Get an map where the key is the confirmation target (in number of blocks)
    /// and the value is the estimated feerate (in sat/vB).
    pub async fn get_fee_estimates(&self) -> Result<HashMap<String, f64>, Error> {
        let client = self.get_random_client();
        client.get_fee_estimates().await
    }
}

// copied from bdk
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl EsploraAsyncExt for MultiEsploraClient {
    async fn scan<K: Ord + Clone + Send>(
        &self,
        local_chain: &BTreeMap<u32, BlockHash>,
        keychain_spks: BTreeMap<
            K,
            impl IntoIterator<IntoIter = impl Iterator<Item = (u32, Script)> + Send> + Send,
        >,
        txids: impl IntoIterator<IntoIter = impl Iterator<Item = Txid> + Send> + Send,
        outpoints: impl IntoIterator<IntoIter = impl Iterator<Item = OutPoint> + Send> + Send,
        stop_gap: usize,
        parallel_requests: usize,
    ) -> Result<LocalUpdate<K, ConfirmationTimeAnchor>, Error> {
        let parallel_requests = Ord::max(parallel_requests, 1);

        let (mut update, tip_at_start) = loop {
            let mut update = LocalUpdate::<K, ConfirmationTimeAnchor>::default();

            for (&height, &original_hash) in local_chain.iter().rev() {
                let update_block_id = BlockId {
                    height,
                    hash: self.get_block_hash(height).await?,
                };
                let _ = update
                    .chain
                    .insert_block(update_block_id)
                    .expect("cannot repeat height here");
                if update_block_id.hash == original_hash {
                    break;
                }
            }

            let tip_at_start = BlockId {
                height: self.get_height().await?,
                hash: self.get_tip_hash().await?,
            };

            if update.chain.insert_block(tip_at_start).is_ok() {
                break (update, tip_at_start);
            }
        };

        for (keychain, spks) in keychain_spks {
            let mut spks = spks.into_iter();
            let mut last_active_index = None;
            let mut empty_scripts = 0;
            type IndexWithTxs = (u32, Vec<esplora_client::Tx>);

            loop {
                let futures = (0..parallel_requests)
                    .filter_map(|_| {
                        let (index, script) = spks.next()?;
                        let client = self.clone();
                        Some(async move {
                            let mut related_txs = client.scripthash_txs(&script, None).await?;

                            let n_confirmed =
                                related_txs.iter().filter(|tx| tx.status.confirmed).count();
                            // esplora pages on 25 confirmed transactions. If there are 25 or more we
                            // keep requesting to see if there's more.
                            if n_confirmed >= 25 {
                                loop {
                                    let new_related_txs = client
                                        .scripthash_txs(
                                            &script,
                                            Some(related_txs.last().unwrap().txid),
                                        )
                                        .await?;
                                    let n = new_related_txs.len();
                                    related_txs.extend(new_related_txs);
                                    // we've reached the end
                                    if n < 25 {
                                        break;
                                    }
                                }
                            }

                            Result::<_, Error>::Ok((index, related_txs))
                        })
                    })
                    .collect::<FuturesOrdered<_>>();

                let n_futures = futures.len();

                for (index, related_txs) in futures.try_collect::<Vec<IndexWithTxs>>().await? {
                    if related_txs.is_empty() {
                        empty_scripts += 1;
                    } else {
                        last_active_index = Some(index);
                        empty_scripts = 0;
                    }
                    for tx in related_txs {
                        let anchor = map_confirmation_time_anchor(&tx.status, tip_at_start);

                        let _ = update.graph.insert_tx(tx.to_tx());
                        if let Some(anchor) = anchor {
                            let _ = update.graph.insert_anchor(tx.txid, anchor);
                        }
                    }
                }

                if n_futures == 0 || empty_scripts >= stop_gap {
                    break;
                }
            }

            if let Some(last_active_index) = last_active_index {
                update.keychain.insert(keychain, last_active_index);
            }
        }

        for txid in txids.into_iter() {
            if update.graph.get_tx(txid).is_none() {
                match self.get_tx(&txid).await? {
                    Some(tx) => {
                        let _ = update.graph.insert_tx(tx);
                    }
                    None => continue,
                }
            }
            match self.get_tx_status(&txid).await? {
                tx_status if tx_status.confirmed => {
                    if let Some(anchor) = map_confirmation_time_anchor(&tx_status, tip_at_start) {
                        let _ = update.graph.insert_anchor(txid, anchor);
                    }
                }
                _ => continue,
            }
        }

        for op in outpoints.into_iter() {
            let mut op_txs = Vec::with_capacity(2);
            if let (
                Some(tx),
                tx_status @ TxStatus {
                    confirmed: true, ..
                },
            ) = (
                self.get_tx(&op.txid).await?,
                self.get_tx_status(&op.txid).await?,
            ) {
                op_txs.push((tx, tx_status));
                if let Some(OutputStatus {
                    txid: Some(txid),
                    status: Some(spend_status),
                    ..
                }) = self.get_output_status(&op.txid, op.vout as _).await?
                {
                    if let Some(spend_tx) = self.get_tx(&txid).await? {
                        op_txs.push((spend_tx, spend_status));
                    }
                }
            }

            for (tx, status) in op_txs {
                let txid = tx.txid();
                let anchor = map_confirmation_time_anchor(&status, tip_at_start);

                let _ = update.graph.insert_tx(tx);
                if let Some(anchor) = anchor {
                    let _ = update.graph.insert_anchor(txid, anchor);
                }
            }
        }

        if tip_at_start.hash != self.get_block_hash(tip_at_start.height).await? {
            // A reorg occurred, so let's find out where all the txids we found are now in the chain
            let txids_found = update
                .graph
                .full_txs()
                .map(|tx_node| tx_node.txid)
                .collect::<Vec<_>>();
            update.chain = EsploraAsyncExt::scan_without_keychain(
                self,
                local_chain,
                [],
                txids_found,
                [],
                parallel_requests,
            )
            .await?
            .chain;
        }

        Ok(update)
    }
}

fn map_confirmation_time_anchor(
    tx_status: &TxStatus,
    tip_at_start: BlockId,
) -> Option<ConfirmationTimeAnchor> {
    match (tx_status.block_time, tx_status.block_height) {
        (Some(confirmation_time), Some(confirmation_height)) => Some(ConfirmationTimeAnchor {
            anchor_block: tip_at_start,
            confirmation_height,
            confirmation_time,
        }),
        _ => None,
    }
}
