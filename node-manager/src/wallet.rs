use futures::lock::Mutex;
use std::str::FromStr;

use bdk::blockchain::EsploraBlockchain;
use bdk::keys::ExtendedKey;
use bdk::template::DescriptorTemplateOut;
use bdk::{SyncOptions, Wallet};
use bip39::Mnemonic;
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey};
use bitcoin::Network;

use crate::localstorage::MutinyBrowserStorage;

#[derive(Debug)]
pub struct MutinyWallet {
    pub wallet: Mutex<Wallet<MutinyBrowserStorage>>,
}

impl MutinyWallet {
    pub fn new(mnemonic: Mnemonic, network: Network) -> MutinyWallet {
        let entropy = mnemonic.to_entropy();
        let xprivkey = ExtendedPrivKey::new_master(network, &entropy).unwrap();
        let xkey = ExtendedKey::from(xprivkey);
        let account_number = 0;
        let (receive_descriptor_template, change_descriptor_template) =
            get_tr_descriptors_for_extended_key(xkey, network, account_number);

        let db = MutinyBrowserStorage::default();

        let wallet = Wallet::new(
            receive_descriptor_template,
            Some(change_descriptor_template),
            network,
            db,
        )
        .expect("Error creating wallet");

        MutinyWallet {
            wallet: Mutex::new(wallet),
        }
    }

    pub async fn sync(&self) -> Result<(), bdk::Error> {
        let wallet = self.wallet.lock().await;
        let url = match wallet.network() {
            Network::Bitcoin => Ok("https://blockstream.info/api"),
            Network::Testnet => Ok("https://blockstream.info/testnet/api"),
            Network::Signet => Ok("https://mempool.space/signet/api"),
            Network::Regtest => Err(bdk::Error::Generic(
                "No esplora client available for regtest".to_string(),
            )),
        }?;

        let blockchain = EsploraBlockchain::new(url, 20);
        wallet.sync(&blockchain, SyncOptions::default()).await
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
