use crate::error::MutinyError;
use crate::labels::LabelStorage;
use crate::logging::MutinyLogger;
use crate::onchain::OnChainWallet;
use crate::storage::MutinyStorage;
use bdk::wallet::AddressIndex;
use bip39::Mnemonic;
use bitcoin::bech32::u5;
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::ecdsa::RecoverableSignature;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, Signing};
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey};
use bitcoin::{Script, Transaction, TxOut};
use lightning::chain::keysinterface::{
    EntropySource, InMemorySigner, KeyMaterial, NodeSigner,
    PhantomKeysManager as LdkPhantomKeysManager, Recipient, SignerProvider,
    SpendableOutputDescriptor,
};
use lightning::ln::msgs::{DecodeError, UnsignedGossipMessage};
use lightning::ln::script::ShutdownScript;
use lightning::log_warn;
use lightning::util::logger::Logger;
use std::sync::Arc;

pub struct PhantomKeysManager<S: MutinyStorage> {
    inner: LdkPhantomKeysManager,
    wallet: Arc<OnChainWallet<S>>,
    logger: Arc<MutinyLogger>,
}

impl<S: MutinyStorage> PhantomKeysManager<S> {
    pub fn new(
        wallet: Arc<OnChainWallet<S>>,
        seed: &[u8; 32],
        starting_time_secs: u64,
        starting_time_nanos: u32,
        cross_node_seed: &[u8; 32],
        logger: Arc<MutinyLogger>,
    ) -> Self {
        let inner = LdkPhantomKeysManager::new(
            seed,
            starting_time_secs,
            starting_time_nanos,
            cross_node_seed,
        );
        Self {
            inner,
            wallet,
            logger,
        }
    }

    /// See [`KeysManager::spend_spendable_outputs`] for documentation on this method.
    pub fn spend_spendable_outputs<C: Signing>(
        &self,
        descriptors: &[&SpendableOutputDescriptor],
        outputs: Vec<TxOut>,
        feerate_sat_per_1000_weight: u32,
        secp_ctx: &Secp256k1<C>,
    ) -> Result<Transaction, ()> {
        let address = {
            let mut wallet = self.wallet.wallet.try_write().map_err(|_| ())?;
            wallet.get_internal_address(AddressIndex::New).address
        };

        let result = self.inner.spend_spendable_outputs(
            descriptors,
            outputs,
            address.script_pubkey(),
            feerate_sat_per_1000_weight,
            secp_ctx,
        );

        match result {
            Ok(tx) => {
                // Add a label to the address so that we can track that this was a force close
                if let Err(e) = self
                    .wallet
                    .storage
                    .set_address_labels(address, vec!["Swept Force Close".to_string()])
                {
                    log_warn!(
                        self.logger,
                        "Failed to set address label for spendable outputs: {e}"
                    )
                }
                Ok(tx)
            }
            Err(e) => Err(e),
        }
    }
}

impl<S: MutinyStorage> EntropySource for PhantomKeysManager<S> {
    fn get_secure_random_bytes(&self) -> [u8; 32] {
        self.inner.get_secure_random_bytes()
    }
}

impl<S: MutinyStorage> NodeSigner for PhantomKeysManager<S> {
    fn get_inbound_payment_key_material(&self) -> KeyMaterial {
        self.inner.get_inbound_payment_key_material()
    }

    fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
        self.inner.get_node_id(recipient)
    }

    fn ecdh(
        &self,
        recipient: Recipient,
        other_key: &PublicKey,
        tweak: Option<&Scalar>,
    ) -> Result<SharedSecret, ()> {
        self.inner.ecdh(recipient, other_key, tweak)
    }

    fn sign_invoice(
        &self,
        hrp_bytes: &[u8],
        invoice_data: &[u5],
        recipient: Recipient,
    ) -> Result<RecoverableSignature, ()> {
        self.inner.sign_invoice(hrp_bytes, invoice_data, recipient)
    }

    fn sign_gossip_message(&self, msg: UnsignedGossipMessage) -> Result<Signature, ()> {
        self.inner.sign_gossip_message(msg)
    }
}

impl<S: MutinyStorage> SignerProvider for PhantomKeysManager<S> {
    type Signer = InMemorySigner;

    fn generate_channel_keys_id(
        &self,
        inbound: bool,
        channel_value_satoshis: u64,
        user_channel_id: u128,
    ) -> [u8; 32] {
        self.inner
            .generate_channel_keys_id(inbound, channel_value_satoshis, user_channel_id)
    }

    fn derive_channel_signer(
        &self,
        channel_value_satoshis: u64,
        channel_keys_id: [u8; 32],
    ) -> Self::Signer {
        self.inner
            .derive_channel_signer(channel_value_satoshis, channel_keys_id)
    }

    fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::Signer, DecodeError> {
        self.inner.read_chan_signer(reader)
    }

    fn get_destination_script(&self) -> Script {
        let mut wallet = self.wallet.wallet.try_write().unwrap();
        wallet
            .get_address(AddressIndex::New)
            .address
            .script_pubkey()
    }

    fn get_shutdown_scriptpubkey(&self) -> ShutdownScript {
        let mut wallet = self.wallet.wallet.try_write().unwrap();
        let script = wallet
            .get_address(AddressIndex::New)
            .address
            .script_pubkey();
        ShutdownScript::try_from(script).unwrap()
    }
}

pub fn generate_seed(num_words: u8) -> Result<Mnemonic, MutinyError> {
    // the bip39 library supports 12. 15, 18, 21, and 24 word mnemonics
    // we only support 12 & 24 for backwards compatibility with other wallets
    let entropy_size = match num_words {
        12 => 16,
        24 => 32,
        _ => return Err(MutinyError::SeedGenerationFailed),
    };

    let mut entropy = vec![0u8; entropy_size];
    getrandom::getrandom(&mut entropy).map_err(|_| MutinyError::SeedGenerationFailed)?;
    let mnemonic =
        Mnemonic::from_entropy(&entropy).map_err(|_| MutinyError::SeedGenerationFailed)?;
    Ok(mnemonic)
}

// A node private key will be derived from `m/0'/X'`, where its node pubkey will
// be derived from the LDK default being `m/0'/X'/0'`. The PhantomKeysManager shared
// key secret will be derived from `m/0'`.
pub(crate) fn create_keys_manager<S: MutinyStorage>(
    wallet: Arc<OnChainWallet<S>>,
    mnemonic: &Mnemonic,
    child_index: u32,
    logger: Arc<MutinyLogger>,
) -> Result<PhantomKeysManager<S>, MutinyError> {
    let context = Secp256k1::new();

    let seed = mnemonic.to_seed("");
    let xprivkey = ExtendedPrivKey::new_master(wallet.network, &seed)?;
    let shared_key = xprivkey.derive_priv(
        &context,
        &DerivationPath::from(vec![ChildNumber::from_hardened_idx(0)?]),
    )?;

    let xpriv = shared_key.derive_priv(
        &context,
        &DerivationPath::from(vec![ChildNumber::from_hardened_idx(child_index)?]),
    )?;

    let now = crate::utils::now();

    Ok(PhantomKeysManager::new(
        wallet,
        &xpriv.private_key.secret_bytes(),
        now.as_secs(),
        now.as_nanos() as u32,
        &shared_key.private_key.secret_bytes(),
        logger,
    ))
}

pub(crate) fn pubkey_from_keys_manager<S: MutinyStorage>(
    keys_manager: &PhantomKeysManager<S>,
) -> PublicKey {
    keys_manager
        .get_node_id(Recipient::Node)
        .expect("cannot parse node id")
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    use crate::{keymanager::pubkey_from_keys_manager, test_utils::*};

    use super::create_keys_manager;
    use crate::fees::MutinyFeeEstimator;
    use crate::logging::MutinyLogger;
    use crate::onchain::OnChainWallet;
    use crate::storage::MemoryStorage;
    use bip39::Mnemonic;
    use bitcoin::Network;
    use esplora_client::Builder;
    use std::str::FromStr;
    use std::sync::Arc;

    #[test]
    async fn derive_pubkey_child_from_seed() {
        let test_name = "derive_pubkey_child_from_seed";
        log!("{}", test_name);

        let mnemonic = Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").expect("could not generate");
        let esplora = Arc::new(
            Builder::new("https://blockstream.info/testnet/api/")
                .build_async()
                .unwrap(),
        );
        let db = MemoryStorage::new(Some(uuid::Uuid::new_v4().to_string()));
        let logger = Arc::new(MutinyLogger::default());
        let fees = Arc::new(MutinyFeeEstimator::new(
            db.clone(),
            esplora.clone(),
            logger.clone(),
        ));

        let wallet = Arc::new(
            OnChainWallet::new(
                &mnemonic,
                db,
                Network::Testnet,
                esplora,
                fees,
                logger.clone(),
            )
            .unwrap(),
        );

        let km = create_keys_manager(wallet.clone(), &mnemonic, 1, logger.clone()).unwrap();
        let pubkey = pubkey_from_keys_manager(&km);
        assert_eq!(
            "02cae09cf2c8842ace44068a5bf3117a494ebbf69a99e79712483c36f97cdb7b54",
            pubkey.to_string()
        );

        let km = create_keys_manager(wallet.clone(), &mnemonic, 2, logger.clone()).unwrap();
        let second_pubkey = pubkey_from_keys_manager(&km);
        assert_eq!(
            "03fcc9eaaf0b84946ea7935e3bc4f2b498893c2f53e5d2994d6877d149601ce553",
            second_pubkey.to_string()
        );

        let km = create_keys_manager(wallet, &mnemonic, 2, logger).unwrap();
        let second_pubkey_again = pubkey_from_keys_manager(&km);

        assert_eq!(second_pubkey, second_pubkey_again);
    }
}
