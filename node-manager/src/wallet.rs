use futures::lock::Mutex;
use log::debug;
use std::str::FromStr;

use crate::error::Error::ChainAccessFailed;
use bdk::blockchain::{Blockchain, EsploraBlockchain, GetHeight};
use bdk::keys::ExtendedKey;
use bdk::template::DescriptorTemplateOut;
use bdk::{FeeRate, SignOptions, SyncOptions, Wallet};
use bip39::Mnemonic;
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey};
use bitcoin::util::uint::Uint256;
use bitcoin::{Address, Block, BlockHash, Network, Transaction};
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use lightning_block_sync::BlockData::FullBlock;
use lightning_block_sync::{
    AsyncBlockSourceResult, BlockData, BlockHeaderData, BlockSource, BlockSourceError,
};

use crate::localstorage::MutinyBrowserStorage;

#[derive(Debug)]
pub struct MutinyWallet {
    pub wallet: Mutex<Wallet<MutinyBrowserStorage>>,
    blockchain: EsploraBlockchain,
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

        let url = match network {
            Network::Bitcoin => Ok("https://blockstream.info/api"),
            Network::Testnet => Ok("https://blockstream.info/testnet/api"),
            Network::Signet => Ok("https://mempool.space/signet/api"),
            Network::Regtest => Err(bdk::Error::Generic(
                "No esplora client available for regtest".to_string(),
            )),
        }
        .expect("What did I tell you about regtest?");

        let blockchain = EsploraBlockchain::new(url, 20);

        let wallet = Wallet::new(
            receive_descriptor_template,
            Some(change_descriptor_template),
            network,
            database,
        )
        .expect("Error creating wallet");

        MutinyWallet {
            wallet: Mutex::new(wallet),
            blockchain,
        }
    }

    pub async fn sync(&self) -> Result<(), bdk::Error> {
        let wallet = self.wallet.lock().await;

        wallet.sync(&self.blockchain, SyncOptions::default()).await
    }

    pub async fn send(
        &self,
        destination_address: String,
        amount: u64,
        fee_rate: Option<f32>,
    ) -> Result<bitcoin::Txid, bdk::Error> {
        let wallet = self.wallet.lock().await;

        let send_to = Address::from_str(&destination_address)
            .map_err(|e| bdk::Error::Generic(e.to_string()))?;

        let fee_rate = if let Some(rate) = fee_rate {
            FeeRate::from_sat_per_vb(rate)
        } else {
            self.blockchain.estimate_fee(1).await?
        };

        let (psbt, details) = {
            let mut builder = wallet.build_tx();
            builder
                .add_recipient(send_to.script_pubkey(), amount)
                .enable_rbf()
                .fee_rate(fee_rate);
            builder.finish()?
        };

        debug!("Transaction details: {:#?}", details);
        debug!("Unsigned PSBT: {}", &psbt);

        let mut psbt = psbt;

        let finalized = wallet.sign(&mut psbt, SignOptions::default())?;

        debug!("{}", finalized);

        let raw_transaction = psbt.extract_tx();
        let txid = raw_transaction.txid();

        let _ = &self.blockchain.broadcast(&raw_transaction).await?;

        let explorer_url = match wallet.network() {
            Network::Bitcoin => Ok("https://mempool.space/tx/"),
            Network::Testnet => Ok("https://mempool.space/testnet/tx/"),
            Network::Signet => Ok("https://mempool.space/signet/tx/"),
            Network::Regtest => Err(bdk::Error::Generic(
                "No esplora client available for regtest".to_string(),
            )),
        }
        .expect("What did I tell you about regtest?");

        debug!("Transaction broadcast! TXID: {txid}.\nExplorer URL: {explorer_url}{txid}");

        Ok(txid)
    }
}

impl BlockSource for MutinyWallet {
    fn get_header<'a>(
        &'a self,
        header_hash: &'a BlockHash,
        _height_hint: Option<u32>,
    ) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
        Box::pin(async move {
            let status = self.blockchain.get_block_status(header_hash).await.unwrap();
            let res = self.blockchain.get_header_by_hash(header_hash).await.unwrap();
            let converted_res = BlockHeaderData {
                header: bitcoin::BlockHeader {
                    version: res.version,
                    prev_blockhash: res.prev_blockhash,
                    merkle_root: res.merkle_root,
                    time: res.time as u32,
                    bits: res.bits,
                    nonce: res.nonce,
                },
                height: status.height.unwrap(),
                chainwork: unimplemented!(),
            };
            Ok(converted_res)
        })
    }

    fn get_block<'a>(
        &'a self,
        header_hash: &'a BlockHash,
    ) -> AsyncBlockSourceResult<'a, BlockData> {
        Box::pin(async move {
            let res_opt = self.blockchain.get_block_raw(header_hash).await.unwrap();

            match res_opt {
                Some(res) => Ok(FullBlock(res)),
                None => Err(BlockSourceError::transient(ChainAccessFailed)),
            }
        })
    }

    fn get_best_block<'a>(&'a self) -> AsyncBlockSourceResult<(BlockHash, Option<u32>)> {
        Box::pin(async {
            let height = self.blockchain.get_height()?;
            let hash = self.blockchain.get_tip_hash().await?;

            let tuple = (hash, Some(height));
            Ok(tuple)
        })
    }
}

impl FeeEstimator for MutinyWallet {
    fn get_est_sat_per_1000_weight(&self, _confirmation_target: ConfirmationTarget) -> u32 {
        // todo pull for fees in a separate thread
        4000 as u32
    }
}

impl BroadcasterInterface for MutinyWallet {
    fn broadcast_transaction(&self, tx: &Transaction) {
        self.blockchain.broadcast(&tx).unwrap()
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
        _ => 1,
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
