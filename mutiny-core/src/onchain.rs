use anyhow::anyhow;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use bdk::chain::{BlockId, ConfirmationTime};
use bdk::psbt::PsbtUtils;
use bdk::template::DescriptorTemplateOut;
use bdk::wallet::{AddressIndex, Update};
use bdk::{FeeRate, LocalOutput, SignOptions, Wallet};
use bdk_chain::indexed_tx_graph::Indexer;
use bdk_esplora::EsploraAsyncExt;
use bitcoin::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey};
use bitcoin::consensus::serialize;
use bitcoin::psbt::{Input, PartiallySignedTransaction};
use bitcoin::{Address, Network, OutPoint, Script, ScriptBuf, Transaction, Txid};
use esplora_client::AsyncClient;
use hex_conservative::DisplayHex;
use lightning::events::bump_transaction::{Utxo, WalletSource};
use lightning::util::logger::Logger;
use lightning::{log_debug, log_error, log_info, log_trace, log_warn};

use crate::error::MutinyError;
use crate::fees::MutinyFeeEstimator;
use crate::labels::*;
use crate::logging::MutinyLogger;
use crate::nodemanager::TransactionDetails;
use crate::storage::{
    IndexItem, MutinyStorage, OnChainStorage, KEYCHAIN_STORE_KEY, NEED_FULL_SYNC_KEY,
    ONCHAIN_PREFIX,
};
use crate::utils::{now, sleep};

pub(crate) const FULL_SYNC_STOP_GAP: usize = 150;
pub(crate) const RESTORE_SYNC_STOP_GAP: usize = 20;

#[derive(Clone)]
pub struct OnChainWallet<S: MutinyStorage> {
    pub wallet: Arc<RwLock<Wallet<OnChainStorage<S>>>>,
    pub(crate) storage: S,
    pub network: Network,
    pub blockchain: Arc<AsyncClient>,
    pub fees: Arc<MutinyFeeEstimator<S>>,
    pub(crate) stop: Arc<AtomicBool>,
    logger: Arc<MutinyLogger>,
}

impl<S: MutinyStorage> OnChainWallet<S> {
    pub fn new(
        xprivkey: ExtendedPrivKey,
        db: S,
        network: Network,
        esplora: Arc<AsyncClient>,
        fees: Arc<MutinyFeeEstimator<S>>,
        stop: Arc<AtomicBool>,
        logger: Arc<MutinyLogger>,
    ) -> Result<OnChainWallet<S>, MutinyError> {
        let account_number = 0;
        let (receive_descriptor_template, change_descriptor_template) =
            get_tr_descriptors_for_extended_key(xprivkey, network, account_number)?;

        // if we have a keychain set, load the wallet, otherwise create one
        let load_wallet_res = Wallet::load(
            receive_descriptor_template.clone(),
            Some(change_descriptor_template.clone()),
            OnChainStorage(db.clone()),
        );
        let wallet = match load_wallet_res {
            Ok(wallet) => wallet,
            Err(bdk::wallet::LoadError::NotInitialized) => {
                // we don't have a bdk wallet, create one
                Wallet::new(
                    receive_descriptor_template,
                    Some(change_descriptor_template),
                    OnChainStorage(db.clone()),
                    network,
                )?
            }
            Err(bdk::wallet::LoadError::Load(_)) => {
                // failed to read storage, means we have old encoding and need to delete and re-init wallet
                db.delete(&[KEYCHAIN_STORE_KEY])?;
                db.set_data(NEED_FULL_SYNC_KEY.to_string(), true, None)?;
                Wallet::new(
                    receive_descriptor_template,
                    Some(change_descriptor_template),
                    OnChainStorage(db.clone()),
                    network,
                )?
            }
            Err(e) => {
                log_error!(logger, "Failed to load wallet: {e}");
                return Err(MutinyError::WalletOperationFailed);
            }
        };

        Ok(OnChainWallet {
            wallet: Arc::new(RwLock::new(wallet)),
            storage: db,
            network,
            blockchain: esplora,
            fees,
            stop,
            logger,
        })
    }

    pub async fn broadcast_transaction(&self, tx: Transaction) -> Result<(), MutinyError> {
        let txid = tx.txid();
        log_info!(self.logger, "Broadcasting transaction: {txid}");
        log_debug!(self.logger, "Transaction: {}", serialize(&tx).as_hex());

        if let Err(e) = self.blockchain.broadcast(&tx).await {
            log_error!(self.logger, "Failed to broadcast transaction ({txid}): {e}");
            return Err(MutinyError::Other(anyhow!(
                "Failed to broadcast transaction ({txid}): {e}"
            )));
        } else if let Err(e) = self
            .insert_tx(
                tx,
                ConfirmationTime::Unconfirmed {
                    last_seen: now().as_secs(),
                },
                None,
            )
            .await
        {
            log_warn!(self.logger, "ERROR: Could not sync broadcasted tx ({txid}), will be synced in next iteration: {e:?}");
        }

        Ok(())
    }

    /// Tries to commit a wallet update, returns true if successful.
    fn try_commit_update(&self, update: Update) -> Result<bool, MutinyError> {
        // get wallet lock for writing and apply the update
        match self.wallet.try_write() {
            Ok(mut wallet) => match wallet.apply_update(update) {
                Ok(_) => {
                    // commit the changes
                    wallet.commit()?;
                    drop(wallet); // drop so we can read from wallet

                    // update the activity index, just get the list of transactions
                    // and insert them into the index, this is done in background so shouldn't
                    // block the wallet update
                    let index_items = self
                        .list_transactions(false)?
                        .into_iter()
                        .map(|t| IndexItem {
                            timestamp: match t.confirmation_time {
                                ConfirmationTime::Confirmed { time, .. } => Some(time),
                                ConfirmationTime::Unconfirmed { .. } => None,
                            },
                            key: format!("{ONCHAIN_PREFIX}{}", t.txid),
                        })
                        .collect::<Vec<_>>();

                    let index = self.storage.activity_index();
                    let mut index = index.try_write()?;
                    // remove old-onchain txs
                    index.retain(|i| !i.key.starts_with(ONCHAIN_PREFIX));
                    index.extend(index_items);

                    Ok(true)
                }
                Err(e) => {
                    // failed to apply wallet update
                    log_error!(self.logger, "Could not apply wallet update: {e}");
                    Err(MutinyError::Other(anyhow!("Could not apply update: {e}")))
                }
            },
            Err(e) => {
                // if we can't get the lock, we just return and try again later
                log_error!(
                    self.logger,
                    "Could not get wallet lock: {e}, retrying in 250ms"
                );

                if self.stop.load(Ordering::Relaxed) {
                    return Err(MutinyError::NotRunning);
                };

                Ok(false)
            }
        }
    }

    pub async fn sync(&self) -> Result<(), MutinyError> {
        // if we need a full sync from a restore
        if self.storage.get(NEED_FULL_SYNC_KEY)?.unwrap_or_default() {
            self.full_sync(RESTORE_SYNC_STOP_GAP).await?;
            self.storage.delete(&[NEED_FULL_SYNC_KEY])?;
        }
        // get first wallet lock that only needs to read
        let (spks, txids, chain, prev_tip) = {
            if let Ok(wallet) = self.wallet.try_read() {
                let spk_vec = wallet
                    .spk_index()
                    .unused_spks()
                    .map(|(_, _, v)| ScriptBuf::from(v))
                    .collect::<Vec<_>>();

                let chain = wallet.local_chain();
                let chain_tip = chain.tip().block_id();

                let unconfirmed_txids = wallet
                    .tx_graph()
                    .list_chain_txs(chain, chain_tip)
                    .filter(|canonical_tx| !canonical_tx.chain_position.is_confirmed())
                    .map(|canonical_tx| canonical_tx.tx_node.txid)
                    .collect::<Vec<Txid>>();

                (
                    spk_vec,
                    unconfirmed_txids,
                    chain.clone(),
                    wallet.latest_checkpoint(),
                )
            } else {
                log_error!(self.logger, "Could not get wallet lock to sync");
                return Err(MutinyError::WalletOperationFailed);
            }
        };

        let update_graph = self
            .blockchain
            .sync(spks, txids, core::iter::empty(), 5)
            .await?;
        let missing_heights = update_graph.missing_heights(&chain);
        let chain_update = self
            .blockchain
            .update_local_chain(prev_tip, missing_heights)
            .await?;
        let update = Update {
            graph: update_graph,
            chain: Some(chain_update),
            ..Default::default()
        };

        for _ in 0..10 {
            let successful = self.try_commit_update(update.clone())?;

            if successful {
                return Ok(());
            } else {
                // if we can't get the lock, sleep for 250ms and try again
                sleep(250).await;
            }
        }

        log_error!(self.logger, "Could not get wallet lock after 10 retries");
        Err(MutinyError::WalletOperationFailed)
    }

    pub async fn full_sync(&self, gap: usize) -> Result<(), MutinyError> {
        // get first wallet lock that only needs to read
        let (spks, prev_tip, chain) = {
            if let Ok(wallet) = self.wallet.try_read() {
                (
                    wallet.all_unbounded_spk_iters(),
                    wallet.latest_checkpoint(),
                    wallet.local_chain().clone(),
                )
            } else {
                log_error!(self.logger, "Could not get wallet lock to sync");
                return Err(MutinyError::WalletOperationFailed);
            }
        };

        let (update_graph, last_active_indices) = self.blockchain.full_scan(spks, gap, 5).await?;
        let missing_heights = update_graph.missing_heights(&chain);
        let chain_update = self
            .blockchain
            .update_local_chain(prev_tip, missing_heights)
            .await?;
        let update = Update {
            last_active_indices,
            graph: update_graph,
            chain: Some(chain_update),
        };

        // get new wallet lock for writing and apply the update
        for _ in 0..10 {
            let successful = self.try_commit_update(update.clone())?;

            if successful {
                return Ok(());
            } else {
                sleep(250).await;
            }
        }

        log_error!(self.logger, "Could not get wallet lock after 10 retries");
        Err(MutinyError::WalletOperationFailed)
    }

    pub(crate) async fn insert_tx(
        &self,
        tx: Transaction,
        position: ConfirmationTime,
        block_id: Option<BlockId>,
    ) -> Result<(), MutinyError> {
        let txid = tx.txid();
        match position {
            ConfirmationTime::Confirmed { .. } => {
                // if the transaction is confirmed and we have the block id,
                // we can insert it directly
                if let Some(block_id) = block_id {
                    let mut wallet = self.wallet.try_write()?;
                    wallet.insert_checkpoint(block_id)?;
                    wallet.insert_tx(tx, position)?;
                } else {
                    // if the transaction is confirmed and we don't have the block id,
                    // we should just sync the wallet otherwise we can get an error
                    // with the wallet being behind the blockchain
                    self.sync().await?;

                    return Ok(());
                }
            }
            ConfirmationTime::Unconfirmed { .. } => {
                // if the transaction is unconfirmed, we can just insert it
                let mut wallet = self.wallet.try_write()?;

                // if we already have the transaction, we don't need to insert it
                if wallet.get_tx(txid).is_none() {
                    // insert tx and commit changes
                    wallet.insert_tx(tx, position)?;
                    wallet.commit()?;
                } else {
                    log_debug!(
                        self.logger,
                        "Tried to insert already existing transaction ({txid})",
                    )
                }
            }
        }

        // update activity index
        let index = self.storage.activity_index();
        let mut index = index.try_write()?;
        let key = format!("{ONCHAIN_PREFIX}{txid}");
        index.retain(|i| i.key != key); // remove old version

        // then insert the new version
        index.insert(IndexItem {
            timestamp: match position {
                ConfirmationTime::Confirmed { time, .. } => Some(time),
                ConfirmationTime::Unconfirmed { .. } => None,
            },
            key,
        });

        Ok(())
    }

    pub(crate) fn cancel_tx(&self, tx: &Transaction) -> Result<(), MutinyError> {
        let mut wallet = self.wallet.try_write()?;
        wallet.cancel_tx(tx);
        Ok(())
    }

    fn is_mine(&self, script: &Script) -> Result<bool, MutinyError> {
        Ok(self.wallet.try_read()?.is_mine(script))
    }

    pub fn list_utxos(&self) -> Result<Vec<LocalOutput>, MutinyError> {
        Ok(self.wallet.try_read()?.list_unspent().collect())
    }

    pub async fn process_payjoin_proposal(
        &self,
        proposal: payjoin::receive::v2::UncheckedProposal,
    ) -> Result<payjoin::receive::v2::PayjoinProposal, payjoin::Error> {
        use payjoin::Error;

        // Receive Check 1 bypass: We're not an automated payment processor.
        let proposal = proposal.assume_interactive_receiver();
        log::trace!("check1");

        // Receive Check 2: receiver can't sign for proposal inputs
        let proposal = proposal.check_inputs_not_owned(|input| {
            self.is_mine(input).map_err(|e| Error::Server(e.into()))
        })?;
        log::trace!("check2");

        // Receive Check 3: receiver can't sign for proposal inputs
        let proposal = proposal.check_no_mixed_input_scripts()?;
        log::trace!("check3");

        // Receive Check 4: have we seen this input before?
        let payjoin = proposal.check_no_inputs_seen_before(|_input| {
            // This check ensures an automated sender does not get phished. It is not necessary for interactive payjoin **where the sender cannot generate bip21s from us**
            // assume false since Mutiny is not an automatic payment processor
            Ok(false)
        })?;
        log::trace!("check4");

        let mut provisional_payjoin = payjoin.identify_receiver_outputs(|output| {
            self.is_mine(output).map_err(|e| Error::Server(e.into()))
        })?;
        self.try_contributing_inputs(&mut provisional_payjoin)
            .map_err(|e| Error::Server(e.into()))?;

        // Outputs may be substituted for e.g. batching at this stage
        // We're not doing this yet.

        // Don't provide input to transactions with a fee rate below the low fee rate
        // They might lock our coins up
        let min_pj_fee_rate =
            bitcoin::FeeRate::from_sat_per_kwu(self.fees.get_low_fee_rate() as u64);
        let payjoin_proposal = provisional_payjoin.finalize_proposal(
            |psbt| {
                let mut psbt = psbt.clone();
                self.wallet
                    .try_write()
                    .map_err(|_| Error::Server(MutinyError::WalletSigningFailed.into()))?
                    .sign(&mut psbt, SignOptions::default())
                    .map_err(|_| Error::Server(MutinyError::WalletSigningFailed.into()))?;
                Ok(psbt)
            },
            Some(min_pj_fee_rate),
        )?;
        let payjoin_psbt_tx = payjoin_proposal.psbt().clone().extract_tx();
        self.insert_tx(
            payjoin_psbt_tx,
            ConfirmationTime::unconfirmed(crate::utils::now().as_secs()),
            None,
        )
        .await
        .map_err(|_| Error::Server(MutinyError::WalletOperationFailed.into()))?;
        log::debug!(
            "Receiver's Payjoin proposal PSBT Rsponse: {:#?}",
            payjoin_proposal.psbt()
        );
        Ok(payjoin_proposal)
    }

    fn try_contributing_inputs(
        &self,
        payjoin: &mut payjoin::receive::v2::ProvisionalProposal,
    ) -> Result<(), MutinyError> {
        use payjoin::bitcoin::Amount;

        let available_inputs = self.list_utxos()?;
        let candidate_inputs: std::collections::HashMap<Amount, OutPoint> = available_inputs
            .iter()
            .filter(|u| u.confirmation_time.is_confirmed())
            .map(|i| (Amount::from_sat(i.txout.value), i.outpoint))
            .collect();

        let selected_outpoint = payjoin
            .try_preserving_privacy(candidate_inputs)
            .map_err(|_| anyhow!("no privacy-preserving selection available"))?;
        let selected_utxo = available_inputs
            .iter()
            .find(|i| i.outpoint == selected_outpoint)
            .ok_or(anyhow!("This shouldn't happen. Failed to retrieve the privacy preserving utxo from those we provided to the seclector."))?;
        log::debug!("selected utxo: {:#?}", selected_utxo);

        payjoin.contribute_witness_input(selected_utxo.txout.clone(), selected_outpoint);
        Ok(())
    }

    pub fn list_transactions(
        &self,
        include_raw: bool,
    ) -> Result<Vec<TransactionDetails>, MutinyError> {
        if let Ok(wallet) = self.wallet.try_read() {
            let txs = wallet
                .transactions()
                .filter_map(|tx| {
                    // skip txs that were not relevant to our bdk wallet
                    if wallet.spk_index().is_tx_relevant(tx.tx_node.tx) {
                        let (sent, received) = wallet.spk_index().sent_and_received(tx.tx_node.tx);

                        let transaction = if include_raw {
                            Some(tx.tx_node.tx.clone())
                        } else {
                            None
                        };

                        let fee = wallet.calculate_fee(tx.tx_node.tx).ok();

                        Some(TransactionDetails {
                            transaction,
                            txid: tx.tx_node.txid,
                            received,
                            sent,
                            fee,
                            confirmation_time: tx.chain_position.cloned().into(),
                            labels: vec![],
                        })
                    } else {
                        None
                    }
                })
                .collect();
            return Ok(txs);
        }
        log_error!(
            self.logger,
            "Could not get wallet lock to list transactions"
        );
        Err(MutinyError::WalletOperationFailed)
    }

    pub fn get_transaction(&self, txid: Txid) -> Result<Option<TransactionDetails>, MutinyError> {
        let wallet = self.wallet.try_read()?;
        let bdk_tx = wallet.get_tx(txid);

        match bdk_tx {
            None => Ok(None),
            Some(tx) => {
                let (sent, received) = wallet.sent_and_received(tx.tx_node.tx);
                let fee = wallet.calculate_fee(tx.tx_node.tx).ok();
                let details = TransactionDetails {
                    transaction: Some(tx.tx_node.tx.to_owned()),
                    txid,
                    received,
                    sent,
                    fee,
                    confirmation_time: tx.chain_position.cloned().into(),
                    labels: vec![],
                };

                Ok(Some(details))
            }
        }
    }

    #[allow(dead_code)]
    fn get_psbt_previous_labels(
        &self,
        psbt: &PartiallySignedTransaction,
    ) -> Result<Vec<String>, MutinyError> {
        // first get previous labels
        let address_labels = self.storage.get_address_labels()?;

        // get previous addresses
        let prev_addresses = psbt
            .inputs
            .iter()
            .filter_map(|i| {
                let address = if let Some(out) = i.witness_utxo.as_ref() {
                    Address::from_script(&out.script_pubkey, self.network).ok()
                } else {
                    None
                };

                address
            })
            .collect::<Vec<_>>();

        // get addresses from previous labels
        let prev_labels = prev_addresses
            .iter()
            .filter_map(|addr| address_labels.get(&addr.to_string()))
            .flatten()
            .cloned()
            .collect::<Vec<_>>();

        Ok(prev_labels)
    }

    #[allow(dead_code)]
    pub(crate) fn label_psbt(
        &self,
        psbt: &PartiallySignedTransaction,
        labels: Vec<String>,
    ) -> Result<(), MutinyError> {
        let mut prev_labels = vec![];

        // add on new labels
        prev_labels.extend(labels);

        // deduplicate labels and create aggregate label
        // we use a HashSet to deduplicate so we can retain the order of the labels
        let mut seen = HashSet::new();
        let agg_labels = prev_labels
            .into_iter()
            .filter(|s| seen.insert(s.clone()))
            .collect::<Vec<_>>();

        // add output addresses to previous addresses
        let addresses = psbt
            .unsigned_tx
            .output
            .iter()
            .filter_map(|o| Address::from_script(&o.script_pubkey, self.network).ok())
            .collect::<Vec<_>>();

        // set label for send to address
        for addr in addresses {
            self.storage.set_address_labels(addr, agg_labels.clone())?;
        }

        Ok(())
    }

    pub fn create_signed_psbt(
        &self,
        send_to: Address,
        amount: u64,
        fee_rate: Option<f32>,
    ) -> Result<PartiallySignedTransaction, MutinyError> {
        self.create_signed_psbt_to_spk(send_to.script_pubkey(), amount, fee_rate)
    }

    pub fn create_signed_psbt_to_spk(
        &self,
        spk: ScriptBuf,
        amount: u64,
        fee_rate: Option<f32>,
    ) -> Result<PartiallySignedTransaction, MutinyError> {
        let mut wallet = self.wallet.try_write()?;

        let fee_rate = if let Some(rate) = fee_rate {
            FeeRate::from_sat_per_vb(rate)
        } else {
            let sat_per_kwu = self.fees.get_normal_fee_rate();
            FeeRate::from_sat_per_kwu(sat_per_kwu as f32)
        };
        let mut psbt = {
            let mut builder = wallet.build_tx();
            builder
                .add_recipient(spk, amount)
                .enable_rbf()
                .fee_rate(fee_rate);
            builder.finish()?
        };
        log_debug!(self.logger, "Unsigned PSBT: {psbt}");
        let finalized = wallet.sign(&mut psbt, SignOptions::default())?;
        log_debug!(self.logger, "finalized: {finalized}");
        Ok(psbt)
    }

    pub async fn send(
        &self,
        destination_address: Address,
        amount: u64,
        labels: Vec<String>,
        fee_rate: Option<f32>,
    ) -> Result<Txid, MutinyError> {
        let psbt = self.create_signed_psbt(destination_address, amount, fee_rate)?;
        self.label_psbt(&psbt, labels)?;

        let raw_transaction = psbt.extract_tx();
        let txid = raw_transaction.txid();

        self.broadcast_transaction(raw_transaction).await?;
        log_debug!(self.logger, "Transaction broadcast! TXID: {txid}");
        Ok(txid)
    }

    pub async fn send_payjoin(
        &self,
        mut original_psbt: PartiallySignedTransaction,
        mut proposal_psbt: PartiallySignedTransaction,
        labels: Vec<String>,
    ) -> Result<Transaction, MutinyError> {
        let wallet = self.wallet.try_read()?;

        // add original psbt input map data in place so BDK knows which scripts to sign,
        // proposal_psbt only contains the sender input outpoints, not scripts, which BDK
        // does not look up
        fn input_pairs(
            psbt: &mut PartiallySignedTransaction,
        ) -> Box<dyn Iterator<Item = (&bitcoin::TxIn, &mut Input)> + '_> {
            Box::new(psbt.unsigned_tx.input.iter().zip(&mut psbt.inputs))
        }

        let mut original_inputs = input_pairs(&mut original_psbt).peekable();

        for (proposed_txin, proposed_psbtin) in input_pairs(&mut proposal_psbt) {
            log_trace!(
                self.logger,
                "Proposed txin: {:?}",
                proposed_txin.previous_output
            );
            if let Some((original_txin, original_psbtin)) = original_inputs.peek() {
                log_trace!(
                    self.logger,
                    "Original txin: {:?}",
                    original_txin.previous_output
                );
                log_trace!(self.logger, "Original psbtin: {original_psbtin:?}");
                if proposed_txin.previous_output == original_txin.previous_output {
                    proposed_psbtin.witness_utxo = original_psbtin.witness_utxo.clone();
                    proposed_psbtin.non_witness_utxo = original_psbtin.non_witness_utxo.clone();
                    original_inputs.next();
                }
            }
        }

        log_trace!(self.logger, "Augmented PSBT: {proposal_psbt:?}");
        // sign and finalize payjoin
        let result = wallet.sign(&mut proposal_psbt, SignOptions::default());
        log_trace!(self.logger, "Sign result: {result:?}");
        result?;
        drop(wallet);

        self.label_psbt(&proposal_psbt, labels)?;
        let payjoin = proposal_psbt.extract_tx();

        Ok(payjoin)
    }

    pub fn create_sweep_psbt(
        &self,
        spk: ScriptBuf,
        fee_rate: Option<f32>,
    ) -> Result<PartiallySignedTransaction, MutinyError> {
        let mut wallet = self.wallet.try_write()?;

        let fee_rate = if let Some(rate) = fee_rate {
            FeeRate::from_sat_per_vb(rate)
        } else {
            let sat_per_kwu = self.fees.get_normal_fee_rate();
            FeeRate::from_sat_per_kwu(sat_per_kwu as f32)
        };
        let mut psbt = {
            let mut builder = wallet.build_tx();
            builder
                .drain_wallet() // Spend all outputs in this wallet.
                .drain_to(spk)
                .enable_rbf()
                .fee_rate(fee_rate);
            builder.finish()?
        };
        log_debug!(self.logger, "Unsigned PSBT: {psbt}");
        let finalized = wallet.sign(&mut psbt, SignOptions::default())?;
        log_debug!(self.logger, "finalized: {finalized}");
        Ok(psbt)
    }

    pub async fn sweep(
        &self,
        destination_address: Address,
        labels: Vec<String>,
        fee_rate: Option<f32>,
    ) -> Result<Txid, MutinyError> {
        let psbt = self.create_sweep_psbt(destination_address.script_pubkey(), fee_rate)?;
        self.label_psbt(&psbt, labels)?;

        let raw_transaction = psbt.extract_tx();
        let txid = raw_transaction.txid();

        self.broadcast_transaction(raw_transaction).await?;
        log_debug!(self.logger, "Transaction broadcast! TXID: {txid}");
        Ok(txid)
    }

    /// Creates a PSBT that spends all the selected utxos a given output.
    /// A fee rate is not specified because it should be precalculated
    /// in the output's amount.
    pub(crate) fn create_sweep_psbt_to_output(
        &self,
        utxos: &[OutPoint],
        spk: ScriptBuf,
        amount_sats: u64,
        absolute_fee: u64,
    ) -> Result<PartiallySignedTransaction, MutinyError> {
        let mut wallet = self.wallet.try_write()?;
        let mut psbt = {
            let mut builder = wallet.build_tx();
            builder
                .manually_selected_only()
                .add_utxos(utxos)?
                .add_recipient(spk, amount_sats)
                .fee_absolute(absolute_fee)
                .enable_rbf();
            builder.finish()?
        };
        log_debug!(self.logger, "Unsigned PSBT: {psbt}");
        let finalized = wallet.sign(&mut psbt, SignOptions::default())?;
        log_debug!(self.logger, "finalized: {finalized}");
        Ok(psbt)
    }

    pub fn estimate_tx_fee(
        &self,
        spk: ScriptBuf,
        amount: u64,
        fee_rate: Option<f32>,
    ) -> Result<u64, MutinyError> {
        let psbt = self.create_signed_psbt_to_spk(spk, amount, fee_rate)?;

        psbt.fee_amount().ok_or(MutinyError::WalletOperationFailed)
    }

    pub fn estimate_sweep_tx_fee(
        &self,
        spk: ScriptBuf,
        fee_rate: Option<f32>,
    ) -> Result<u64, MutinyError> {
        let psbt = self.create_sweep_psbt(spk, fee_rate)?;

        psbt.fee_amount().ok_or(MutinyError::WalletOperationFailed)
    }

    /// Bumps the given transaction by replacing the given tx with a transaction at
    /// the new given fee rate in sats/vbyte
    pub async fn bump_fee(&self, txid: Txid, new_fee_rate: f32) -> Result<Txid, MutinyError> {
        let tx = {
            let mut wallet = self.wallet.try_write()?;
            // build RBF fee bump tx
            let mut builder = wallet.build_fee_bump(txid)?;
            builder.fee_rate(FeeRate::from_sat_per_vb(new_fee_rate));
            let mut psbt = builder.finish()?;
            wallet.sign(&mut psbt, SignOptions::default())?;

            psbt.extract_tx()
        };

        let txid = tx.txid();

        self.broadcast_transaction(tx).await?;
        log_debug!(self.logger, "Fee bump Transaction broadcast! TXID: {txid}");
        Ok(txid)
    }
}

fn get_tr_descriptors_for_extended_key(
    master_xprv: ExtendedPrivKey,
    network: Network,
    account_number: u32,
) -> Result<(DescriptorTemplateOut, DescriptorTemplateOut), MutinyError> {
    let coin_type = coin_type_from_network(network);

    let base_path = DerivationPath::from_str("m/86'")?;
    let derivation_path = base_path.extend([
        ChildNumber::from_hardened_idx(coin_type)?,
        ChildNumber::from_hardened_idx(account_number)?,
    ]);

    let receive_descriptor_template = bdk::descriptor!(tr((
        master_xprv,
        derivation_path.extend([ChildNumber::Normal { index: 0 }])
    )))?;
    let change_descriptor_template = bdk::descriptor!(tr((
        master_xprv,
        derivation_path.extend([ChildNumber::Normal { index: 1 }])
    )))?;

    Ok((receive_descriptor_template, change_descriptor_template))
}

pub(crate) fn coin_type_from_network(network: Network) -> u32 {
    match network {
        Network::Bitcoin => 0,
        Network::Testnet => 1,
        Network::Signet => 1,
        Network::Regtest => 1,
        net => panic!("Got unknown network: {net}!"),
    }
}

pub(crate) fn get_esplora_url(network: Network, user_provided_url: Option<String>) -> String {
    if let Some(url) = user_provided_url {
        url
    } else {
        match network {
            Network::Bitcoin => "https://mutiny.mempool.space/api",
            Network::Testnet => "https://mempool.space/testnet/api",
            Network::Signet => "https://mutinynet.com/api",
            Network::Regtest => "http://localhost:3003",
            net => panic!("Got unknown network: {net}!"),
        }
        .to_string()
    }
}

impl<S: MutinyStorage> WalletSource for OnChainWallet<S> {
    fn list_confirmed_utxos(&self) -> Result<Vec<Utxo>, ()> {
        let wallet = self.wallet.try_read().map_err(|_| ())?;
        let utxos = wallet
            .list_unspent()
            .map(|u| Utxo {
                outpoint: u.outpoint,
                output: u.txout,
                satisfaction_weight: 4 + 2 + 64,
            })
            .collect();

        Ok(utxos)
    }

    fn get_change_script(&self) -> Result<ScriptBuf, ()> {
        let mut wallet = self.wallet.try_write().map_err(|_| ())?;
        let addr = wallet
            .try_get_internal_address(AddressIndex::New)
            .map_err(|_| ())?
            .address;
        Ok(addr.script_pubkey())
    }

    fn sign_psbt(&self, mut psbt: PartiallySignedTransaction) -> Result<Transaction, ()> {
        let wallet = self.wallet.try_read().map_err(|e| {
            log_error!(
                self.logger,
                "Could not get wallet lock to sign transaction: {e:?}"
            )
        })?;

        // need to trust witness_utxo for signing since that's LDK sets in the psbt
        let sign_options = SignOptions {
            trust_witness_utxo: true,
            ..Default::default()
        };
        wallet
            .sign(&mut psbt, sign_options)
            .map_err(|e| log_error!(self.logger, "Could not sign transaction: {e:?}"))?;

        Ok(psbt.extract_tx())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use crate::{encrypt::encryption_key_from_pass, storage::MemoryStorage};
    use bip39::Mnemonic;
    use bitcoin::Address;
    use esplora_client::Builder;
    use std::str::FromStr;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};
    wasm_bindgen_test_configure!(run_in_browser);

    async fn create_wallet() -> OnChainWallet<MemoryStorage> {
        let mnemonic = Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").expect("could not generate");
        let esplora = Arc::new(
            Builder::new("https://blockstream.info/testnet/api/")
                .build_async()
                .unwrap(),
        );
        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let db = MemoryStorage::new(Some(pass), Some(cipher), None);
        let logger = Arc::new(MutinyLogger::default());
        let fees = Arc::new(MutinyFeeEstimator::new(
            db.clone(),
            esplora.clone(),
            logger.clone(),
        ));
        let stop = Arc::new(AtomicBool::new(false));
        let xpriv = ExtendedPrivKey::new_master(Network::Testnet, &mnemonic.to_seed("")).unwrap();

        OnChainWallet::new(xpriv, db, Network::Testnet, esplora, fees, stop, logger).unwrap()
    }

    #[test]
    async fn test_create_wallet() {
        let test_name = "create_wallet";
        log!("{}", test_name);
        let _wallet = create_wallet().await;
    }

    #[test]
    async fn test_label_psbt() {
        let test_name = "label_psbt";
        log!("{}", test_name);
        let wallet = create_wallet().await;

        let psbt = PartiallySignedTransaction::from_str("cHNidP8BAKACAAAAAqsJSaCMWvfEm4IS9Bfi8Vqz9cM9zxU4IagTn4d6W3vkAAAAAAD+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAEHakcwRAIgR1lmF5fAGwNrJZKJSGhiGDR9iYZLcZ4ff89X0eURZYcCIFMJ6r9Wqk2Ikf/REf3xM286KdqGbX+EhtdVRs7tr5MZASEDXNxh/HupccC1AaZGoqg7ECy0OIEhfKaC3Ibi1z+ogpIAAQEgAOH1BQAAAAAXqRQ1RebjO4MsRwUPJNPuuTycA5SLx4cBBBYAFIXRNTfy4mVAWjTbr6nj3aAfuCMIAAAA").unwrap();

        // set label for input
        let input_addr = Address::from_str("2Mx6uYKYGW5J6sV59e5NsdtCTsJYRxednbx")
            .unwrap()
            .assume_checked();
        let prev_label = "previous".to_string();
        wallet
            .storage
            .set_address_labels(input_addr, vec![prev_label])
            .unwrap();

        let send_to_addr = Address::from_str("mrKjeffvbnmKJURrLNdqLkfrptLrFtnkFx")
            .unwrap()
            .assume_checked();
        let change_addr = Address::from_str("mqfKJuj2Ea4RtXsKawQWrqosGeHFTrp6iZ")
            .unwrap()
            .assume_checked();
        let label = "test".to_string();

        let result = wallet.label_psbt(&psbt, vec![label.clone()]);
        assert!(result.is_ok());

        let expected_labels = vec![label.clone()];

        let addr_labels = wallet.storage.get_address_labels().unwrap();
        assert_eq!(addr_labels.len(), 3);
        assert_eq!(
            addr_labels.get(&send_to_addr.to_string()),
            Some(&expected_labels)
        );
        assert_eq!(
            addr_labels.get(&change_addr.to_string()),
            Some(&expected_labels)
        );

        let label = wallet.storage.get_label(&label).unwrap();
        assert!(label.is_some());
        assert_eq!(label.clone().unwrap().addresses.len(), 2);
        assert!(label
            .clone()
            .unwrap()
            .addresses
            .contains(&send_to_addr.to_string()));
        assert!(label.unwrap().addresses.contains(&change_addr.to_string()));
    }
}
