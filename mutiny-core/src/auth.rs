use crate::error::MutinyError;
use crate::indexed_db::MutinyStorage;
use anyhow::anyhow;
use bitcoin::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1::{ecdsa, All, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use url::Url;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthProfile {
    pub index: u32,
    pub name: String,
    pub used_services: Vec<String>,
}

impl AuthProfile {
    pub fn new(index: u32, name: String) -> Self {
        Self {
            index,
            name,
            used_services: vec![],
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SigningProfile {
    pub profile: AuthProfile,
    hashing_key: SecretKey,
}

impl SigningProfile {
    pub fn new(profile: AuthProfile, hashing_key: SecretKey) -> Self {
        Self {
            profile,
            hashing_key,
        }
    }

    // todo: should this be in lnurl-rs?
    pub(crate) fn get_derivation_path(&self, url: Url) -> Result<DerivationPath, MutinyError> {
        // There exists a private hashingKey which is derived by user LN WALLET using m/138'/0 path.
        let mut engine = HmacEngine::<sha256::Hash>::new(&self.hashing_key.secret_bytes());

        // LN SERVICE full domain name is extracted from login LNURL
        let host = url.host().ok_or(anyhow::anyhow!("No host"))?;

        // and then hashed using hmacSha256(hashingKey, full service domain name)
        engine.input(host.to_string().as_bytes());
        let derivation_mat = Hmac::<sha256::Hash>::from_engine(engine).into_inner();

        // First 16 bytes are taken from resulting hash and then turned into a sequence of 4 u32 values
        let uints: [u32; 4] = (0..4)
            .map(|i| u32::from_be_bytes(derivation_mat[(i * 4)..((i + 1) * 4)].try_into().unwrap()))
            .collect::<Vec<u32>>()
            .try_into()
            .expect("slice with incorrect length");
        // parse into ChildNumbers so we handle hardened vs unhardened
        let children = uints.map(ChildNumber::from);

        // which are in turn used to derive a service-specific linkingKey using m/138'/<long1>/<long2>/<long3>/<long4> path
        let path = DerivationPath::from_str(&format!(
            "m/138'/{}/{}/{}/{}",
            children[0], children[1], children[2], children[3]
        ))
        .map_err(|e| MutinyError::Other(anyhow!("Error deriving path: {e}")))?;

        Ok(path)
    }

    pub(crate) fn get_secret_key(
        &self,
        context: &Secp256k1<All>,
        xprivkey: ExtendedPrivKey,
        url: Url,
    ) -> Result<SecretKey, MutinyError> {
        let path = self.get_derivation_path(url)?;
        let key = xprivkey
            .derive_priv(context, &path)
            .map_err(|e| MutinyError::Other(anyhow!("Error deriving key for path {path}: {e}")))?;
        Ok(key.private_key)
    }
}

#[derive(Clone)]
pub struct AuthManager {
    profiles: Arc<RwLock<Vec<SigningProfile>>>,
    xprivkey: ExtendedPrivKey,
    storage: MutinyStorage,
    context: Secp256k1<All>,
}

impl AuthManager {
    pub fn new(xprivkey: ExtendedPrivKey, storage: MutinyStorage) -> Result<Self, MutinyError> {
        let context = Secp256k1::new();
        let mut auth_profiles = storage.get_auth_profiles()?;
        // Sort profiles by index so we can just iterate over them
        auth_profiles.sort_by(|a, b| a.index.cmp(&b.index));

        let mut profiles = vec![];
        for profile in auth_profiles {
            let base_path = DerivationPath::from_str(&format!("m/138'/{}", profile.index))?;
            let key = xprivkey.derive_priv(&context, &base_path)?;
            profiles.push(SigningProfile::new(profile, key.private_key));
        }

        // Check that the profiles are in the correct order
        for (i, p) in profiles.iter().enumerate() {
            if p.profile.index as usize != i {
                return Err(MutinyError::Other(anyhow!(
                    "Auth profile index mismatch: {} != {}",
                    p.profile.index,
                    i
                )));
            }
        }

        Ok(Self {
            profiles: Arc::new(RwLock::new(profiles)),
            xprivkey,
            storage,
            context,
        })
    }

    #[inline]
    pub(crate) fn create_init(&self) -> Result<(), MutinyError> {
        if self.profiles.try_read()?.is_empty() {
            self.add_profile("Default".to_string())?;
        }
        Ok(())
    }

    pub fn add_profile(&self, name: String) -> Result<u32, MutinyError> {
        let mut profiles = self.profiles.try_write()?;
        let index = profiles.len() as u32;
        let profile = AuthProfile::new(index, name);

        let base_path = DerivationPath::from_str(&format!("m/138'/{index}"))?;
        let key = self.xprivkey.derive_priv(&self.context, &base_path)?;
        let signing_profile = SigningProfile::new(profile, key.private_key);
        profiles.push(signing_profile);

        // Update storage with new list of profiles
        self.storage
            .update_auth_profiles(profiles.iter().map(|p| p.profile.clone()).collect())?;

        Ok(index)
    }

    pub fn get_profiles(&self) -> Result<Vec<AuthProfile>, MutinyError> {
        Ok(self
            .profiles
            .try_read()?
            .iter()
            .map(|p| p.profile.clone())
            .collect())
    }

    pub fn get_profile(&self, index: usize) -> Result<Option<AuthProfile>, MutinyError> {
        Ok(self
            .profiles
            .try_read()?
            .get(index)
            .map(|p| p.profile.clone()))
    }

    pub fn sign(
        &self,
        profile_index: usize,
        url: Url,
        k1: &[u8; 32],
    ) -> Result<(ecdsa::Signature, PublicKey), MutinyError> {
        let profile = {
            let profiles = self.profiles.try_read()?;
            profiles
                .get(profile_index)
                .ok_or(MutinyError::LnUrlFailure)?
                .clone()
        };

        let sk = profile.get_secret_key(&self.context, self.xprivkey, url)?;
        let pubkey = sk.public_key(&self.context);

        let msg = Message::from_slice(k1).expect("32 bytes, guaranteed by type");
        let sig = self.context.sign_ecdsa(&msg, &sk);

        Ok((sig, pubkey))
    }

    pub fn add_used_service(&self, profile_index: usize, url: Url) -> Result<(), MutinyError> {
        let mut profile = self
            .get_profile(profile_index)?
            .ok_or(MutinyError::LnUrlFailure)?;

        let service = url.host().ok_or(anyhow::anyhow!("No host"))?.to_string();

        if !profile.used_services.contains(&service) {
            profile.used_services.push(service);
        }

        let mut profiles = self.profiles.try_write()?;
        profiles[profile_index].profile = profile;

        // Update storage with new list of profiles
        self.storage
            .update_auth_profiles(profiles.iter().map(|p| p.profile.clone()).collect())?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::keymanager::generate_seed;
    use crate::test_utils::cleanup_wallet_test;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::Network;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};
    wasm_bindgen_test_configure!(run_in_browser);

    use super::*;

    async fn create_manager() -> AuthManager {
        cleanup_wallet_test().await;

        let storage = MutinyStorage::new("".to_string()).await.unwrap();
        let mnemonic = generate_seed(12).unwrap();
        let seed = mnemonic.to_seed("");
        let xprivkey = ExtendedPrivKey::new_master(Network::Regtest, &seed).unwrap();
        let auth = AuthManager::new(xprivkey, storage).unwrap();
        auth.create_init().unwrap();
        auth
    }

    #[test]
    fn test_lud_05_static_test_vector() {
        let auth_prof = AuthProfile::new(0, "Default".to_string());
        let hashing_key_byes: [u8; 32] =
            FromHex::from_hex("7d417a6a5e9a6a4a879aeaba11a11838764c8fa2b959c242d43dea682b3e409b")
                .unwrap();
        let hashing_key = SecretKey::from_slice(&hashing_key_byes).unwrap();
        let profile = SigningProfile::new(auth_prof, hashing_key);
        let url = Url::parse("https://site.com").unwrap();

        let path = profile.get_derivation_path(url).unwrap();
        let expected = DerivationPath::from_str(&format!(
            "m/138'/{}/{}/{}/{}",
            ChildNumber::from(1588488367),
            ChildNumber::from(2659270754),
            ChildNumber::from(38110259),
            ChildNumber::from(4136336762),
        ))
        .unwrap();

        assert_eq!(path, expected);
    }

    #[test]
    async fn test_create_signature() {
        let auth = create_manager().await;

        let k1 = [0; 32];

        let (sig, pk) = auth
            .sign(0, Url::parse("https://mutinywallet.com").unwrap(), &k1)
            .unwrap();

        auth.context
            .verify_ecdsa(&Message::from_slice(&k1).unwrap(), &sig, &pk)
            .unwrap();

        cleanup_wallet_test().await;
    }

    #[test]
    async fn test_add_used_service() {
        let auth = create_manager().await;

        let url = Url::parse("https://mutinywallet.com").unwrap();

        auth.add_used_service(0, url.clone()).unwrap();

        assert!(auth
            .get_profile(0)
            .unwrap()
            .unwrap()
            .used_services
            .contains(&url.host().unwrap().to_string()));

        cleanup_wallet_test().await;
    }

    #[test]
    async fn test_add_profile() {
        let auth = create_manager().await;

        let url = Url::parse("https://mutinywallet.com").unwrap();
        let k1 = [0; 32];

        let (sig1, pk1) = auth.sign(0, url.clone(), &k1).unwrap();

        let new_index = auth.add_profile("profile2".to_string()).unwrap();
        let (sig2, pk2) = auth.sign(new_index as usize, url, &k1).unwrap();

        assert_ne!(sig1, sig2);
        assert_ne!(pk1, pk2);

        let profiles = auth.get_profiles().unwrap();
        assert_eq!(profiles.len(), 2);

        cleanup_wallet_test().await;
    }
}
