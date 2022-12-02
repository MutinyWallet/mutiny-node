use crate::localstorage::MutinyBrowserStorage;
use bdk::blockchain::EsploraBlockchain;
use bdk::database::Database;
use bdk::keys::ExtendedKey;
use bdk::wallet::AddressIndex;
use bdk::{SignOptions, Wallet};
use bdk_macros::maybe_await;
use bip39::Mnemonic;
use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::util::address::Address;
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey};
use bitcoin::{Block, Network, Script, Transaction, TxIn, Witness};
use dlc_manager::error::Error as ManagerError;
use dlc_manager::error::Error::WalletError;
use dlc_manager::{Blockchain, Utxo};
use log::error;
use secp256k1::Secp256k1;
use std::str::FromStr;
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

#[derive(Debug)]
pub struct MutinyDLCWallet {
    wallet: Arc<Wallet<MutinyBrowserStorage>>,
    blockchain: Arc<EsploraBlockchain>,
    storage: Arc<MutinyBrowserStorage>,
    mnemonic: Mnemonic,
}

fn bdk_err_to_manager_err(e: bdk::Error) -> ManagerError {
    WalletError(Box::new(e))
}

impl MutinyDLCWallet {
    fn derive_secret_key(&self, index: u32) -> secp256k1::SecretKey {
        let entropy = self.mnemonic.to_entropy();
        let network = self.wallet.network();
        let xprivkey = ExtendedPrivKey::new_master(network, &entropy).unwrap();
        let xkey: ExtendedKey = ExtendedKey::from(xprivkey);
        let master_xprv = xkey.into_xprv(network).unwrap();
        let coin_type = match network {
            Network::Bitcoin => 0,
            Network::Testnet => 1,
            Network::Signet => 1,
            Network::Regtest => 1,
        };

        let base_path = DerivationPath::from_str("m/585'").unwrap();

        let derivation_path = base_path.extend([
            ChildNumber::from_hardened_idx(coin_type).unwrap(),
            ChildNumber::from_hardened_idx(index).unwrap(),
        ]);

        let k = master_xprv
            .derive_priv(&Secp256k1::new(), &derivation_path)
            .unwrap();

        k.private_key
    }
}

impl dlc_manager::Signer for MutinyDLCWallet {
    fn sign_tx_input(
        &self,
        tx: &mut bitcoin::blockdata::transaction::Transaction,
        input_index: usize,
        tx_out: &bitcoin::blockdata::transaction::TxOut,
        redeem_script: Option<bitcoin::blockdata::script::Script>,
    ) -> Result<(), ManagerError> {
        let sig_options = SignOptions {
            trust_witness_utxo: true,
            ..Default::default()
        };

        // need an unsigned version of the tx to sign
        let unsigned_tx = {
            let tx_clone = tx.clone();
            let unsigned_inputs = tx_clone
                .input
                .iter()
                .map(|i| TxIn {
                    previous_output: i.previous_output,
                    script_sig: Script::new(),
                    sequence: i.sequence,
                    witness: Witness::default(),
                })
                .collect();

            Transaction {
                version: tx_clone.version,
                lock_time: tx_clone.lock_time,
                input: unsigned_inputs,
                output: tx_clone.output,
            }
        };

        let psbt_r = PartiallySignedTransaction::from_unsigned_tx(unsigned_tx);

        match psbt_r {
            Ok(mut psbt) => {
                psbt.inputs[input_index].witness_utxo = Some(tx_out.clone());
                psbt.inputs[input_index].redeem_script = redeem_script;

                self.wallet
                    .sign(&mut psbt, sig_options)
                    .map_err(bdk_err_to_manager_err)?;

                let signed_tx = psbt.extract_tx();

                tx.input[input_index].script_sig = signed_tx.input[input_index].script_sig.clone();
                tx.input[input_index].witness = signed_tx.input[input_index].witness.clone();

                Ok(())
            }
            Err(e) => Err(WalletError(Box::new(e))),
        }
    }

    fn get_secret_key_for_pubkey(
        &self,
        pubkey: &secp256k1::PublicKey,
    ) -> Result<secp256k1::SecretKey, ManagerError> {
        let index = self
            .storage
            .get_dlc_key_index(pubkey)
            .map_err(bdk_err_to_manager_err)?;

        Ok(self.derive_secret_key(index))
    }
}

impl dlc_manager::Wallet for MutinyDLCWallet {
    fn get_new_address(&self) -> Result<Address, ManagerError> {
        self.wallet
            .get_address(AddressIndex::New)
            .map(|a| a.address)
            .map_err(bdk_err_to_manager_err)
    }

    fn get_new_secret_key(&self) -> Result<secp256k1::SecretKey, ManagerError> {
        let index = self
            .storage
            .increment_last_dlc_key_index()
            .map_err(bdk_err_to_manager_err)?;

        let private_key = self.derive_secret_key(index);

        self.storage
            .save_dlc_key_index(index, private_key.public_key(&Secp256k1::new()))
            .map_err(bdk_err_to_manager_err)?;

        Ok(private_key)
    }

    // fixme doesn't use fee rate
    // fixme bdk can't lock inputs
    fn get_utxos_for_amount(
        &self,
        amount: u64,
        _fee_rate: Option<u64>,
        _lock_utxos: bool,
    ) -> Result<Vec<Utxo>, ManagerError> {
        let unspent = self.wallet.list_unspent().map_err(bdk_err_to_manager_err)?;
        // todo randomize order of unspent
        let utxos_iter = unspent.iter().cloned().map(|utxo| {
            let addr =
                Address::from_script(&utxo.txout.script_pubkey, self.wallet.network()).unwrap();
            Utxo {
                tx_out: utxo.txout,
                outpoint: utxo.outpoint,
                address: addr,
                redeem_script: Script::new(),
            }
        });

        let mut accum: Vec<Utxo> = Vec::new();

        for utxo in utxos_iter {
            if accum.iter().map(|a| a.tx_out.value).sum::<u64>() >= amount {
                return Ok(accum);
            } else {
                accum.push(utxo)
            }
        }

        let available = accum.iter().map(|a| a.tx_out.value).sum();
        if available >= amount {
            Ok(accum)
        } else {
            Err(bdk_err_to_manager_err(bdk::Error::InsufficientFunds {
                needed: amount,
                available,
            }))
        }
    }

    fn import_address(&self, _address: &Address) -> Result<(), ManagerError> {
        // I don't think we need to do this?
        // todo research if we do
        Ok(())
    }

    fn get_transaction(
        &self,
        tx_id: &bitcoin::hash_types::Txid,
    ) -> Result<bitcoin::blockdata::transaction::Transaction, ManagerError> {
        let tx_opt = self
            .wallet
            .get_tx(tx_id, true)
            .map_err(bdk_err_to_manager_err)?;

        match tx_opt {
            Some(tx_details) => Ok(tx_details.transaction.unwrap()),
            None => Err(bdk_err_to_manager_err(bdk::Error::TransactionNotFound)),
        }
    }

    fn get_transaction_confirmations(
        &self,
        tx_id: &bitcoin::hash_types::Txid,
    ) -> Result<u32, ManagerError> {
        self.wallet
            .get_tx(tx_id, false)
            .map_err(bdk_err_to_manager_err)
            .and_then(|tx_opt| {
                let conf_time = tx_opt.and_then(|t| t.confirmation_time);
                match conf_time {
                    None => Err(bdk_err_to_manager_err(bdk::Error::TransactionNotFound)),
                    Some(block_time) => {
                        let last_sync = self
                            .wallet
                            .database()
                            .get_sync_time()
                            .map_err(bdk_err_to_manager_err)?
                            .unwrap();

                        Ok(last_sync.block_time.height - block_time.height + 1)
                    }
                }
            })
    }
}

impl Blockchain for MutinyDLCWallet {
    fn send_transaction(&self, tx: &Transaction) -> Result<(), ManagerError> {
        let blockchain = self.blockchain.clone();
        let tx_clone = tx.clone();
        spawn_local(async move {
            maybe_await!(blockchain.broadcast(&tx_clone))
                .unwrap_or_else(|_| error!("failed to broadcast tx! {}", tx_clone.txid()))
        });

        Ok(())
    }

    fn get_network(&self) -> Result<Network, ManagerError> {
        Ok(self.wallet.network())
    }

    fn get_blockchain_height(&self) -> Result<u64, ManagerError> {
        let last_sync = self
            .wallet
            .database()
            .get_sync_time()
            .map_err(bdk_err_to_manager_err)?
            .unwrap();

        Ok(last_sync.block_time.height as u64)
    }

    fn get_block_at_height(&self, _height: u64) -> Result<Option<Block>, ManagerError> {
        Ok(None)
    }
}
