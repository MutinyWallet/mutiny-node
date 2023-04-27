use std::str::FromStr;
use std::sync::{Arc, RwLock};

use bdk::chain::{BlockId, ConfirmationTime};
use bdk::template::DescriptorTemplateOut;
use bdk::{FeeRate, LocalUtxo, SignOptions, TransactionDetails, Wallet};
use bdk_esplora::{esplora_client, EsploraAsyncExt};
use bdk_macros::maybe_await;
use bip39::Mnemonic;
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey};
use bitcoin::{Address, Network, Script, Transaction, Txid};
use esplora_client::AsyncClient;
use lightning::chain::chaininterface::{ConfirmationTarget, FeeEstimator};
use log::debug;

use crate::error::MutinyError;
use crate::fees::MutinyFeeEstimator;
use crate::indexed_db::MutinyStorage;

#[derive(Clone)]
pub struct MutinyWallet {
    pub wallet: Arc<RwLock<Wallet<MutinyStorage>>>,
    pub network: Network,
    pub blockchain: Arc<AsyncClient>,
    fees: Arc<MutinyFeeEstimator>,
}

impl MutinyWallet {
    pub fn new(
        mnemonic: &Mnemonic,
        db: MutinyStorage,
        network: Network,
        esplora: Arc<AsyncClient>,
        fees: Arc<MutinyFeeEstimator>,
    ) -> Result<MutinyWallet, MutinyError> {
        let seed = mnemonic.to_seed("");
        let xprivkey = ExtendedPrivKey::new_master(network, &seed)?;
        let account_number = 0;
        let (receive_descriptor_template, change_descriptor_template) =
            get_tr_descriptors_for_extended_key(xprivkey, network, account_number)?;

        let wallet = Wallet::new(
            receive_descriptor_template,
            Some(change_descriptor_template),
            db,
            network,
        )?;

        Ok(MutinyWallet {
            wallet: Arc::new(RwLock::new(wallet)),
            network,
            blockchain: esplora,
            fees,
        })
    }

    pub async fn sync(&self) -> Result<(), MutinyError> {
        // get first wallet lock that only needs to read
        let (checkpoints, spks) = {
            let wallet = self.wallet.try_read()?;
            let checkpoints = wallet.checkpoints();
            let spks = wallet
                .spks_of_all_keychains()
                .into_iter()
                .map(|(k, spks)| (k, spks))
                .collect();

            (checkpoints.clone(), spks)
        };

        let update = self
            .blockchain
            .scan(
                &checkpoints,
                spks,
                core::iter::empty(),
                core::iter::empty(),
                50,
                5,
            )
            .await?;
        // get new wallet lock for writing
        let mut wallet = self.wallet.try_write()?;
        wallet.apply_update(update)?;
        wallet.commit()?;

        Ok(())
    }

    pub(crate) async fn insert_tx(
        &self,
        tx: Transaction,
        position: ConfirmationTime,
        block_id: Option<BlockId>,
    ) -> Result<(), MutinyError> {
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
                    self.sync().await?
                }
            }
            ConfirmationTime::Unconfirmed => {
                // if the transaction is unconfirmed, we can just insert it
                let mut wallet = self.wallet.try_write()?;
                wallet.insert_tx(tx, position)?;
            }
        }

        Ok(())
    }

    pub fn list_utxos(&self) -> Result<Vec<LocalUtxo>, MutinyError> {
        Ok(self.wallet.try_read()?.list_unspent())
    }

    pub fn list_transactions(
        &self,
        include_raw: bool,
    ) -> Result<Vec<TransactionDetails>, MutinyError> {
        #[allow(deprecated)]
        Ok(self.wallet.try_read()?.list_transactions(include_raw))
    }

    pub fn get_transaction(
        &self,
        txid: Txid,
        include_raw: bool,
    ) -> Result<Option<TransactionDetails>, MutinyError> {
        Ok(self.wallet.try_read()?.get_tx(txid, include_raw))
    }

    pub fn create_signed_psbt(
        &self,
        send_to: Address,
        amount: u64,
        fee_rate: Option<f32>,
    ) -> Result<bitcoin::psbt::PartiallySignedTransaction, MutinyError> {
        if !send_to.is_valid_for_network(self.network) {
            return Err(MutinyError::IncorrectNetwork(send_to.network));
        }

        self.create_signed_psbt_to_spk(send_to.script_pubkey(), amount, fee_rate)
    }

    pub fn create_signed_psbt_to_spk(
        &self,
        spk: Script,
        amount: u64,
        fee_rate: Option<f32>,
    ) -> Result<bitcoin::psbt::PartiallySignedTransaction, MutinyError> {
        let mut wallet = self.wallet.try_write()?;

        let fee_rate = if let Some(rate) = fee_rate {
            FeeRate::from_sat_per_vb(rate)
        } else {
            let sat_per_kwu = self
                .fees
                .get_est_sat_per_1000_weight(ConfirmationTarget::Normal);
            FeeRate::from_sat_per_kwu(sat_per_kwu as f32)
        };
        let (mut psbt, details) = {
            let mut builder = wallet.build_tx();
            builder
                .add_recipient(spk, amount)
                .enable_rbf()
                .fee_rate(fee_rate);
            builder.finish()?
        };
        debug!("Transaction details: {:#?}", details);
        debug!("Unsigned PSBT: {}", &psbt);
        let finalized = wallet.sign(&mut psbt, SignOptions::default())?;
        debug!("{}", finalized);
        Ok(psbt)
    }

    pub async fn send(
        &self,
        destination_address: Address,
        amount: u64,
        fee_rate: Option<f32>,
    ) -> Result<Txid, MutinyError> {
        let psbt = self.create_signed_psbt(destination_address, amount, fee_rate)?;

        let raw_transaction = psbt.extract_tx();
        let txid = raw_transaction.txid();

        maybe_await!(self.blockchain.broadcast(&raw_transaction))?;
        debug!("Transaction broadcast! TXID: {txid}");
        Ok(txid)
    }

    pub fn create_sweep_psbt(
        &self,
        destination_address: Address,
        fee_rate: Option<f32>,
    ) -> Result<bitcoin::psbt::PartiallySignedTransaction, MutinyError> {
        if !destination_address.is_valid_for_network(self.network) {
            return Err(MutinyError::IncorrectNetwork(destination_address.network));
        }

        let mut wallet = self.wallet.try_write()?;

        let fee_rate = if let Some(rate) = fee_rate {
            FeeRate::from_sat_per_vb(rate)
        } else {
            let sat_per_kwu = self
                .fees
                .get_est_sat_per_1000_weight(ConfirmationTarget::Normal);
            FeeRate::from_sat_per_kwu(sat_per_kwu as f32)
        };
        let (mut psbt, details) = {
            let mut builder = wallet.build_tx();
            builder
                .drain_wallet() // Spend all outputs in this wallet.
                .drain_to(destination_address.script_pubkey())
                .enable_rbf()
                .fee_rate(fee_rate);
            builder.finish()?
        };
        debug!("Transaction details: {:#?}", details);
        debug!("Unsigned PSBT: {}", &psbt);
        let finalized = wallet.sign(&mut psbt, SignOptions::default())?;
        debug!("{}", finalized);
        Ok(psbt)
    }

    pub async fn sweep(
        &self,
        destination_address: Address,
        fee_rate: Option<f32>,
    ) -> Result<Txid, MutinyError> {
        let psbt = self.create_sweep_psbt(destination_address, fee_rate)?;

        let raw_transaction = psbt.extract_tx();
        let txid = raw_transaction.txid();

        maybe_await!(self.blockchain.broadcast(&raw_transaction))?;
        debug!("Transaction broadcast! TXID: {txid}");
        Ok(txid)
    }
}

fn get_tr_descriptors_for_extended_key(
    master_xprv: ExtendedPrivKey,
    network: Network,
    account_number: u32,
) -> Result<(DescriptorTemplateOut, DescriptorTemplateOut), MutinyError> {
    let coin_type = match network {
        Network::Bitcoin => 0,
        Network::Testnet => 1,
        Network::Signet => 1,
        Network::Regtest => 1,
    };

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

pub(crate) fn get_esplora_url(network: Network, user_provided_url: Option<String>) -> String {
    if let Some(url) = user_provided_url {
        url
    } else {
        match network {
            Network::Bitcoin => "https://mempool.space/api",
            Network::Testnet => "https://mempool.space/testnet/api",
            Network::Signet => "https://mutinynet.com/api",
            Network::Regtest => "http://localhost:3003",
        }
        .to_string()
    }
}

pub(crate) fn get_rgs_url(
    network: Network,
    user_provided_url: Option<String>,
    last_sync_time: Option<u32>,
) -> String {
    let last_sync_time = last_sync_time.unwrap_or(0);
    if let Some(url) = user_provided_url.filter(|url| !url.is_empty()) {
        let url = url.strip_suffix('/').unwrap_or(&url);
        format!("{url}/{last_sync_time}")
    } else {
        // todo - handle regtest
        match network {
            Network::Bitcoin => {
                format!("https://rapidsync.lightningdevkit.org/snapshot/{last_sync_time}")
            }
            Network::Testnet => {
                format!("https://rapidsync.lightningdevkit.org/testnet/snapshot/{last_sync_time}")
            }
            Network::Signet => {
                format!("https://rgs.mutinynet.com/snapshot/{last_sync_time}")
            }
            Network::Regtest => {
                // for now use the signet rgs because it is the least amount of data
                format!("https://rgs.mutinynet.com/snapshot/{last_sync_time}")
            }
        }
    }
}
