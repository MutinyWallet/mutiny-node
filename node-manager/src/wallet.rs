use anyhow::Context;
use futures::lock::Mutex;
use log::{debug, error};
use std::str::FromStr;
use std::sync::Arc;

use bdk::blockchain::{Blockchain, EsploraBlockchain};
use bdk::keys::ExtendedKey;
use bdk::template::DescriptorTemplateOut;
use bdk::{FeeRate, SignOptions, SyncOptions, Wallet};
use bdk_macros::maybe_await;
use bip39::Mnemonic;
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey};
use bitcoin::{Address, Network, Transaction};
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use wasm_bindgen_futures::spawn_local;

use crate::error::MutinyError;
use crate::localstorage::MutinyBrowserStorage;

#[derive(Debug)]
pub struct MutinyWallet {
    pub wallet: Mutex<Wallet<MutinyBrowserStorage>>,
    blockchain: Arc<EsploraBlockchain>,
}

impl MutinyWallet {
    pub fn new(
        mnemonic: Mnemonic,
        database: MutinyBrowserStorage,
        network: Network,
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
            network,
            database,
        )
        .expect("Error creating wallet");

        MutinyWallet {
            wallet: Mutex::new(wallet),
            blockchain: Arc::new(esplora_from_network(network)),
        }
    }

    pub async fn sync(&self) -> Result<(), MutinyError> {
        let wallet = self.wallet.lock().await;

        maybe_await!(wallet.sync(&self.blockchain, SyncOptions::default()))?;

        Ok(())
    }

    pub async fn send(
        &self,
        destination_address: String,
        amount: u64,
        fee_rate: Option<f32>,
    ) -> Result<bitcoin::Txid, MutinyError> {
        let wallet = self.wallet.lock().await;

        // TODO: would like to be able to convert from Bitcoin lib errors directly to MutinyError somehow
        // Like this doesn't seem to do anything:
        // #[derive(Error, Debug)]
        // pub enum MutinyBitcoinError {
        //     #[error("Failed to use browser storage")]
        //     AddressError {
        //         #[from]
        //         source: bitcoin::util::address::Error,
        //     },
        // }
        let send_to =
            Address::from_str(&destination_address).with_context(|| "Address parse error")?;

        let fee_rate = if let Some(rate) = fee_rate {
            FeeRate::from_sat_per_vb(rate)
        } else {
            self.blockchain.estimate_fee(1).await?
        };

        let (mut psbt, details) = {
            let mut builder = wallet.build_tx();
            builder
                .add_recipient(send_to.script_pubkey(), amount)
                .enable_rbf()
                .fee_rate(fee_rate);
            builder.finish()?
        };

        debug!("Transaction details: {:#?}", details);
        debug!("Unsigned PSBT: {}", &psbt);

        let finalized = wallet.sign(&mut psbt, SignOptions::default())?;

        debug!("{}", finalized);

        let raw_transaction = psbt.extract_tx();
        let txid = raw_transaction.txid();

        maybe_await!(self.blockchain.broadcast(&raw_transaction))?;

        let explorer_url = match wallet.network() {
            Network::Bitcoin => Ok("https://mempool.space/tx/"),
            Network::Testnet => Ok("https://mempool.space/testnet/tx/"),
            Network::Signet => Ok("https://mempool.space/signet/tx/"),
            Network::Regtest => Err(bdk::Error::Generic(
                "No esplora client available for regtest".to_string(),
            )),
        }?;

        debug!("Transaction broadcast! TXID: {txid}.\nExplorer URL: {explorer_url}{txid}");

        Ok(txid)
    }
}

impl BroadcasterInterface for MutinyWallet {
    fn broadcast_transaction(&self, tx: &Transaction) {
        let blockchain = self.blockchain.clone();
        let tx_clone = tx.clone();
        spawn_local(async move {
            maybe_await!(blockchain.broadcast(&tx_clone))
                .unwrap_or_else(|_| error!("failed to broadcast tx! {}", tx_clone.txid()))
        });
    }
}

const MIN_FEERATE: u32 = 253 * 4;

impl FeeEstimator for MutinyWallet {
    fn get_est_sat_per_1000_weight(&self, confirmation_target: ConfirmationTarget) -> u32 {
        // TODO
        MIN_FEERATE
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

pub fn esplora_from_network(network: Network) -> EsploraBlockchain {
    let url = match network {
        Network::Bitcoin => Ok("https://blockstream.info/api"),
        Network::Testnet => Ok("https://blockstream.info/testnet/api"),
        Network::Signet => Ok("https://mempool.space/signet/api"),
        Network::Regtest => Err(bdk::Error::Generic(
            "No esplora client available for regtest".to_string(),
        )),
    }
    .expect("What did I tell you about regtest?");
    EsploraBlockchain::new(url, 20)
}
