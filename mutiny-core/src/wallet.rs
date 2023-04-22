use std::str::FromStr;
use std::sync::{Arc, RwLock};

use bdk::keys::ExtendedKey;
use bdk::template::DescriptorTemplateOut;
use bdk::{FeeRate, LocalUtxo, SignOptions, TransactionDetails, Wallet};
use bdk_esplora::{esplora_client, EsploraAsyncExt};
use bdk_macros::maybe_await;
use bip39::Mnemonic;
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey};
use bitcoin::{Address, Network, Script, Txid};
use esplora_client::AsyncClient;
use log::debug;

use crate::error::MutinyError;
use crate::indexed_db::MutinyStorage;
use crate::utils::is_valid_network;

#[derive(Clone)]
pub struct MutinyWallet {
    pub wallet: Arc<RwLock<Wallet<MutinyStorage>>>,
    network: Network,
    pub blockchain: Arc<AsyncClient>,
}

impl MutinyWallet {
    pub fn new(
        mnemonic: &Mnemonic,
        db: MutinyStorage,
        network: Network,
        esplora: Arc<AsyncClient>,
    ) -> MutinyWallet {
        let entropy = mnemonic.to_entropy();
        let xprivkey = ExtendedPrivKey::new_master(network, &entropy).unwrap();
        let xkey = ExtendedKey::from(xprivkey);
        let account_number = 0;
        let (receive_descriptor_template, change_descriptor_template) =
            get_tr_descriptors_for_extended_key(xkey, network, account_number);

        let wallet = Wallet::new(
            receive_descriptor_template,
            Some(change_descriptor_template),
            db,
            network,
        )
        .expect("Error creating wallet");

        MutinyWallet {
            wallet: Arc::new(RwLock::new(wallet)),
            network,
            blockchain: esplora,
        }
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
        if !is_valid_network(self.network, send_to.network) {
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
            // self.blockchain.estimate_fee(1).await?
            // todo get from esplora
            FeeRate::from_sat_per_vb(5.0)
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
        if !is_valid_network(self.network, destination_address.network) {
            return Err(MutinyError::IncorrectNetwork(destination_address.network));
        }

        let mut wallet = self.wallet.try_write()?;

        let fee_rate = if let Some(rate) = fee_rate {
            FeeRate::from_sat_per_vb(rate)
        } else {
            // self.blockchain.estimate_fee(1).await?
            // todo get from esplora
            FeeRate::from_sat_per_vb(5.0)
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

// mostly copied from sensei
fn get_tr_descriptors_for_extended_key(
    xkey: ExtendedKey,
    network: Network,
    account_number: u32,
) -> (DescriptorTemplateOut, DescriptorTemplateOut) {
    let master_xprv = xkey.into_xprv(network).unwrap();
    let coin_type = match network {
        Network::Bitcoin => 0,
        Network::Testnet => 1,
        Network::Signet => 1,
        Network::Regtest => 1,
    };

    let base_path = DerivationPath::from_str("m/86'").unwrap();
    let derivation_path = base_path.extend([
        ChildNumber::from_hardened_idx(coin_type).unwrap(),
        ChildNumber::from_hardened_idx(account_number).unwrap(),
    ]);

    let receive_descriptor_template = bdk::descriptor!(tr((
        master_xprv,
        derivation_path.extend([ChildNumber::Normal { index: 0 }])
    )))
    .unwrap();
    let change_descriptor_template = bdk::descriptor!(tr((
        master_xprv,
        derivation_path.extend([ChildNumber::Normal { index: 1 }])
    )))
    .unwrap();

    (receive_descriptor_template, change_descriptor_template)
}

pub(crate) fn get_esplora_url(network: Network, user_provided_url: Option<String>) -> String {
    if let Some(url) = user_provided_url {
        url
    } else {
        match network {
            Network::Bitcoin => "https://blockstream.info/api",
            Network::Testnet => "https://blockstream.info/testnet/api",
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
    if let Some(url) = user_provided_url {
        if url.is_empty() {
            get_rgs_url(network, None, Some(last_sync_time))
        } else {
            url
        }
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
                format!("https://rgs.mutinynet.com/snapshots/{last_sync_time}")
            }
            Network::Regtest => {
                // for now use the signet rgs because it is the least amount of data
                format!("https://rgs.mutinynet.com/snapshot/{last_sync_time}")
            }
        }
    }
}
