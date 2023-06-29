use crate::error::MutinyError;
use crate::storage::MutinyStorage;
use anyhow::anyhow;
use bitcoin::secp256k1::{ecdsa, All, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey};
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

    pub(crate) fn get_secret_key(
        &self,
        context: &Secp256k1<All>,
        xprivkey: ExtendedPrivKey,
        url: Url,
    ) -> Result<SecretKey, MutinyError> {
        let path = lnurl::get_derivation_path(self.hashing_key.secret_bytes(), url)?;
        let key = xprivkey
            .derive_priv(context, &path)
            .map_err(|e| MutinyError::Other(anyhow!("Error deriving key for path {path}: {e}")))?;
        Ok(key.private_key)
    }
}

#[derive(Clone)]
pub struct AuthManager<S: MutinyStorage> {
    profiles: Arc<RwLock<Vec<SigningProfile>>>,
    xprivkey: ExtendedPrivKey,
    storage: S,
    context: Secp256k1<All>,
}

impl<S: MutinyStorage> AuthManager<S> {
    pub fn new(xprivkey: ExtendedPrivKey, storage: S) -> Result<Self, MutinyError> {
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
    use crate::storage::MemoryStorage;
    use crate::test_utils::*;
    use bitcoin::Network;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};
    wasm_bindgen_test_configure!(run_in_browser);

    use super::*;

    fn create_manager() -> AuthManager<MemoryStorage> {
        let storage = MemoryStorage::default();
        let mnemonic = generate_seed(12).unwrap();
        let seed = mnemonic.to_seed("");
        let xprivkey = ExtendedPrivKey::new_master(Network::Regtest, &seed).unwrap();
        let auth = AuthManager::new(xprivkey, storage).unwrap();
        auth.create_init().unwrap();
        auth
    }

    #[test]
    async fn test_create_signature() {
        let test_name = "test_create_signature";
        log!("{}", test_name);

        let auth = create_manager();

        let k1 = [0; 32];

        let (sig, pk) = auth
            .sign(0, Url::parse("https://mutinywallet.com").unwrap(), &k1)
            .unwrap();

        auth.context
            .verify_ecdsa(&Message::from_slice(&k1).unwrap(), &sig, &pk)
            .unwrap();
    }

    #[test]
    async fn test_add_used_service() {
        let test_name = "test_add_used_service";
        log!("{}", test_name);

        let auth = create_manager();

        let url = Url::parse("https://mutinywallet.com").unwrap();

        auth.add_used_service(0, url.clone()).unwrap();

        assert!(auth
            .get_profile(0)
            .unwrap()
            .unwrap()
            .used_services
            .contains(&url.host().unwrap().to_string()));
    }

    #[test]
    async fn test_add_profile() {
        let test_name = "test_add_profile";
        log!("{}", test_name);

        let auth = create_manager();

        let url = Url::parse("https://mutinywallet.com").unwrap();
        let k1 = [0; 32];

        let (sig1, pk1) = auth.sign(0, url.clone(), &k1).unwrap();

        let new_index = auth.add_profile("profile2".to_string()).unwrap();
        let (sig2, pk2) = auth.sign(new_index as usize, url, &k1).unwrap();

        assert_ne!(sig1, sig2);
        assert_ne!(pk1, pk2);

        let profiles = auth.get_profiles().unwrap();
        assert_eq!(profiles.len(), 2);
    }
}
