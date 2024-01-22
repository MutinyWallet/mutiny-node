use crate::dlc::storage::DlcStorage;
use crate::error::MutinyError;
use crate::fees::MutinyFeeEstimator;
use crate::logging::MutinyLogger;
use crate::onchain::OnChainWallet;
use crate::storage::MutinyStorage;
use crate::utils;
use bdk::wallet::AddressIndex;
use bdk::SignOptions;
use bdk_chain::ConfirmationTime;
use bdk_coin_select::{Candidate, CoinSelector, Drain, FeeRate, Target};
use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::secp256k1::{All, PublicKey, Secp256k1, SecretKey};
use bitcoin::util::bip32::ChildNumber;
use bitcoin::{Address, Block, Network, OutPoint, Script, Transaction, Txid, XOnlyPublicKey};
use dlc_manager::contract::signed_contract::SignedContract;
use dlc_manager::error::Error;
use dlc_manager::{Oracle, Signer, Storage, Time, Utxo};
use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
use futures_util::lock::Mutex;
use lightning::log_error;
use lightning::util::logger::Logger;
use std::collections::HashMap;
use std::sync::Arc;

mod storage;

pub use storage::{DLC_CONTRACT_KEY_PREFIX, DLC_KEY_INDEX_KEY};

pub(crate) type DlcManager<S: MutinyStorage> = dlc_manager::manager::Manager<
    Arc<DlcWallet<S>>,
    Arc<DlcBlockchain<S>>,
    Arc<DlcStorage<S>>,
    Arc<DummyOracleClient>,
    Arc<MutinyTimeProvider>,
    Arc<MutinyFeeEstimator<S>>,
>;

/// Handles DLC functionality in Mutiny.
#[derive(Clone)]
pub struct DlcHandler<S: MutinyStorage> {
    pub manager: Arc<Mutex<DlcManager<S>>>,
    pub store: Arc<DlcStorage<S>>,
    pub logger: Arc<MutinyLogger>,
}

impl<S: MutinyStorage> DlcHandler<S> {
    pub fn new(
        wallet: Arc<OnChainWallet<S>>,
        logger: Arc<MutinyLogger>,
    ) -> Result<Self, MutinyError> {
        let store = Arc::new(DlcStorage::new(wallet.storage.clone()));

        let dlc_wallet = DlcWallet {
            wallet: wallet.clone(),
            storage: store.clone(),
            logger: logger.clone(),
            secp: Secp256k1::new(),
        };

        let manager = DlcManager::new(
            Arc::new(dlc_wallet),
            Arc::new(DlcBlockchain(wallet.clone())),
            store.clone(),
            HashMap::new(),
            Arc::new(MutinyTimeProvider {}),
            wallet.fees.clone(),
        )
        .map_err(|e| anyhow::anyhow!("Failed to create dlc manager: {e}"))?;

        Ok(Self {
            manager: Arc::new(Mutex::new(manager)),
            store,
            logger,
        })
    }

    /// Outputs to watch for on the blockchain. This is used to detect when a contract is closed
    /// by our counter party.
    ///
    /// If a contract is closed by our counter party, the [`on_counterparty_close`] method should
    /// be called.
    pub fn outputs_to_watch(&self) -> Result<Vec<(OutPoint, SignedContract)>, Error> {
        let contracts: Vec<SignedContract> = self.store.get_confirmed_contracts()?;

        let outpoints = contracts
            .into_iter()
            .map(|c| (c.accepted_contract.dlc_transactions.get_fund_outpoint(), c))
            .collect();

        Ok(outpoints)
    }
}

/// Converts a bdk error to a manager error
fn bdk_err_to_manager_err(e: bdk::Error) -> Error {
    create_wallet_error(&format!("{:?}", e))
}

/// Creates a wallet error from a string
fn create_wallet_error(error: &str) -> Error {
    Error::WalletError(Box::new(std::io::Error::new(
        std::io::ErrorKind::Other,
        error,
    )))
}

/// A wrapper around a bdk wallet that implements the different traits needed by the dlc manager
#[derive(Clone)]
pub struct DlcWallet<S: MutinyStorage> {
    pub wallet: Arc<OnChainWallet<S>>,
    pub storage: Arc<DlcStorage<S>>,
    pub logger: Arc<MutinyLogger>,
    pub secp: Secp256k1<All>,
}

impl<S: MutinyStorage> DlcWallet<S> {
    pub fn get_secret_key_for_index(&self, index: u32) -> SecretKey {
        let network_index = if self.wallet.network == Network::Bitcoin {
            ChildNumber::from_hardened_idx(0).expect("infallible")
        } else {
            ChildNumber::from_hardened_idx(1).expect("infallible")
        };

        let path = [
            ChildNumber::from_hardened_idx(586).expect("infallible"),
            network_index,
            ChildNumber::from_hardened_idx(index).unwrap(),
        ];

        self.wallet
            .xprivkey
            .derive_priv(&self.secp, &path)
            .unwrap()
            .private_key
    }
}

impl<S: MutinyStorage> Signer for DlcWallet<S> {
    fn sign_psbt_input(
        &self,
        psbt: &mut PartiallySignedTransaction,
        input_index: usize,
    ) -> Result<(), Error> {
        let Ok(wallet) = self.wallet.wallet.try_read() else {
            log_error!(self.logger, "Could not get wallet lock to sign tx input");
            return Err(create_wallet_error(
                "Failed to get wallet lock to sign tx input",
            ));
        };

        let sig_options = SignOptions {
            trust_witness_utxo: true,
            ..Default::default()
        };

        let mut to_sign = psbt.clone();
        wallet.sign(&mut to_sign, sig_options).map_err(|e| {
            log_error!(self.logger, "Failed to sign tx input: {e:?}");
            bdk_err_to_manager_err(e)
        })?;

        // Since we can only sign the whole PSBT, we need to just copy over
        // the one input we signed.
        // https://github.com/bitcoindevkit/bdk/issues/1219
        psbt.inputs[input_index] = to_sign.inputs[input_index].clone();

        Ok(())
    }

    fn get_secret_key_for_pubkey(&self, pk: &PublicKey) -> Result<SecretKey, Error> {
        let index = self
            .storage
            .get_index_for_key(pk)
            .map_err(|e| Error::WalletError(Box::new(e)))?;

        Ok(self.get_secret_key_for_index(index))
    }
}

impl<S: MutinyStorage> dlc_manager::Wallet for DlcWallet<S> {
    fn get_new_address(&self) -> Result<Address, Error> {
        let Ok(mut wallet) = self.wallet.wallet.try_write() else {
            log_error!(self.logger, "Could not get wallet lock to get new address");
            return Err(create_wallet_error(
                "Failed to get wallet lock to get new address",
            ));
        };

        let address = wallet.get_address(AddressIndex::New).address;
        Ok(address)
    }

    fn get_new_change_address(&self) -> Result<Address, Error> {
        let Ok(mut wallet) = self.wallet.wallet.try_write() else {
            log_error!(
                self.logger,
                "Could not get wallet lock to get new change address"
            );
            return Err(create_wallet_error(
                "Failed to get wallet lock to get new change address",
            ));
        };

        let address = wallet.get_internal_address(AddressIndex::New).address;
        Ok(address)
    }

    fn get_new_secret_key(&self) -> Result<SecretKey, Error> {
        let index = self.storage.get_next_key_index();
        let key = self.get_secret_key_for_index(index);
        let pk = PublicKey::from_secret_key(&self.secp, &key);
        self.storage
            .add_new_key(pk, index)
            .map_err(|e| Error::WalletError(Box::new(e)))?;

        Ok(key)
    }

    fn get_utxos_for_amount(
        &self,
        amount: u64,
        fee_rate: Option<u64>,
        _lock_utxos: bool,
    ) -> Result<Vec<Utxo>, Error> {
        let utxos = self
            .wallet
            .list_utxos()
            .map_err(|e| Error::WalletError(Box::new(e)))?
            .into_iter()
            // only use confirmed utxos
            .filter(|u| matches!(u.confirmation_time, ConfirmationTime::Confirmed { .. }))
            .collect::<Vec<_>>();

        let candidates = utxos
            .iter()
            .map(|u| Candidate::new_tr_keyspend(u.txout.value))
            .collect::<Vec<_>>();

        let target = Target {
            feerate: FeeRate::from_sat_per_vb(fee_rate.unwrap_or(10) as f32),
            min_fee: 0,
            value: amount,
        };

        // base weight of 212 is standard for DLC transaction
        let mut coin_selector = CoinSelector::new(&candidates, 212);
        coin_selector
            .select_until_target_met(target, Drain::none())
            .map_err(|e| {
                log_error!(self.logger, "Failed to select coins: {e:?}");
                Error::WalletError(Box::new(e))
            })?;

        // Check that selection is finished!
        debug_assert!(coin_selector.is_target_met(target, Drain::none()));

        // get indices of selected coins
        let indices = coin_selector.selected_indices();

        let mut selection: Vec<Utxo> = Vec::with_capacity(indices.len());
        for index in indices {
            let utxo = &utxos[*index];

            let address =
                Address::from_script(&utxo.txout.script_pubkey, self.wallet.network).unwrap();
            let u = Utxo {
                tx_out: utxo.txout.clone(),
                outpoint: utxo.outpoint,
                address,
                redeem_script: Script::new(),
                reserved: false,
            };

            selection.push(u);
        }

        Ok(selection)
    }

    fn import_address(&self, _address: &Address) -> Result<(), Error> {
        // BDK does not support importing addresses which is fine.
        // We will always see the funding tx spending our funds and we will be able to track the
        // closing tx as well.
        Ok(())
    }
}

pub struct MutinyTimeProvider {}
impl Time for MutinyTimeProvider {
    fn unix_time_now(&self) -> u64 {
        utils::now().as_secs()
    }
}

pub struct DlcBlockchain<S: MutinyStorage>(Arc<OnChainWallet<S>>);

impl<S: MutinyStorage> dlc_manager::Blockchain for DlcBlockchain<S> {
    fn send_transaction(&self, transaction: &Transaction) -> Result<(), Error> {
        let tx = transaction.clone();
        let wallet = self.0.clone();
        utils::spawn(async move {
            if let Err(e) = wallet.broadcast_transaction(tx).await {
                log_error!(wallet.logger, "Failed to broadcast transaction: {e}");
            }
        });
        Ok(())
    }

    fn get_network(&self) -> Result<Network, Error> {
        Ok(self.0.network)
    }

    fn get_blockchain_height(&self) -> Result<u64, Error> {
        let Ok(wallet) = self.0.wallet.try_read() else {
            log_error!(
                self.0.logger,
                "Could not get wallet lock to get blockchain height"
            );
            return Err(create_wallet_error(
                "Failed to get wallet lock to get blockchain height",
            ));
        };

        Ok(wallet
            .latest_checkpoint()
            .map(|c| c.height as u64)
            .unwrap_or(0)) // if no checkpoint, then we assume 0
    }

    fn get_block_at_height(&self, _: u64) -> Result<Block, Error> {
        unimplemented!("Only needed for channels")
    }

    fn get_transaction(&self, tx_id: &Txid) -> Result<Transaction, Error> {
        let Ok(wallet) = self.0.wallet.try_read() else {
            log_error!(
                self.0.logger,
                "Could not get wallet lock to get transaction"
            );
            return Err(create_wallet_error(
                "Failed to get wallet lock to get transaction",
            ));
        };

        Ok(wallet.get_tx(*tx_id, true).unwrap().transaction.unwrap())
    }

    fn get_transaction_confirmations(&self, tx_id: &Txid) -> Result<u32, Error> {
        let Ok(wallet) = self.0.wallet.try_read() else {
            log_error!(
                self.0.logger,
                "Could not get wallet lock to get tx confirmations"
            );
            return Err(create_wallet_error(
                "Failed to get wallet lock to get tx confirmations",
            ));
        };

        let Some(tx) = wallet.get_tx(*tx_id, true) else {
            // if we don't have the tx, then it is unconfirmed, so return 0
            return Ok(0);
        };

        match tx.confirmation_time {
            ConfirmationTime::Confirmed { height, .. } => {
                let cur = wallet
                    .latest_checkpoint()
                    .map(|c| c.height)
                    .ok_or(create_wallet_error("Failed to get latest checkpoint"))?;

                Ok(cur.saturating_sub(height) + 1)
            }
            ConfirmationTime::Unconfirmed { .. } => Ok(0),
        }
    }
}

pub struct DummyOracleClient {}

impl Oracle for DummyOracleClient {
    fn get_public_key(&self) -> XOnlyPublicKey {
        unimplemented!("Unused")
    }

    fn get_announcement(&self, _: &str) -> Result<OracleAnnouncement, Error> {
        unimplemented!("Unused")
    }

    fn get_attestation(&self, _: &str) -> Result<OracleAttestation, Error> {
        unimplemented!("Unused")
    }
}
