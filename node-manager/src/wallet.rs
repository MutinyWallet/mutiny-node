use futures::lock::Mutex;
use log::debug;
use std::str::FromStr;

use bdk::blockchain::EsploraBlockchain;
use bdk::keys::ExtendedKey;
use bdk::template::DescriptorTemplateOut;
use bdk::{FeeRate, SignOptions, SyncOptions, Wallet};
use bip39::Mnemonic;
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey};
use bitcoin::{Address, Network};

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

        let db = MutinyBrowserStorage::default();

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
    ) -> Result<bitcoin::Txid, bdk::Error> {
        let wallet = self.wallet.lock().await;

        let send_to = Address::from_str(&destination_address)
            .map_err(|e| bdk::Error::Generic(e.to_string()))?;

        let (psbt, details) = {
            let mut builder = wallet.build_tx();
            builder
                .add_recipient(send_to.script_pubkey(), amount)
                .enable_rbf()
                .do_not_spend_change()
                .fee_rate(FeeRate::from_sat_per_vb(5.0));
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
