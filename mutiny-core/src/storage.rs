use crate::auth::AuthProfile;
use crate::encrypt::{decrypt, encrypt};
use crate::error::{MutinyError, MutinyStorageError};
use crate::ldkstorage::CHANNEL_MANAGER_KEY;
use crate::nodemanager::NodeStorage;
use anyhow::anyhow;
use bdk::chain::{Append, PersistBackend};
use bip39::Mnemonic;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub const KEYCHAIN_STORE_KEY: &str = "bdk_keychain";
pub(crate) const MNEMONIC_KEY: &str = "mnemonic";
const NODES_KEY: &str = "nodes";
const AUTH_PROFILES_KEY: &str = "auth_profiles";
const FEE_ESTIMATES_KEY: &str = "fee_estimates";
const FIRST_SYNC_KEY: &str = "first_sync";

fn needs_encryption(key: &str) -> bool {
    match key {
        MNEMONIC_KEY => true,
        str if str.starts_with(CHANNEL_MANAGER_KEY) => true,
        _ => false,
    }
}

pub fn encrypt_value(
    key: impl AsRef<str>,
    value: Value,
    password: Option<&str>,
) -> Result<Value, MutinyError> {
    // Only bother encrypting if a password is set
    let res = match password {
        Some(pw) if needs_encryption(key.as_ref()) => {
            let str = serde_json::to_string(&value)?;
            let ciphertext = encrypt(&str, pw);
            Value::String(ciphertext)
        }
        _ => value,
    };

    Ok(res)
}

pub fn decrypt_value(
    key: impl AsRef<str>,
    value: Value,
    password: Option<&str>,
) -> Result<Value, MutinyError> {
    // Only bother encrypting if a password is set
    let json: Value = match password {
        Some(pw) if needs_encryption(key.as_ref()) => {
            let str: String = serde_json::from_value(value)?;
            let ciphertext = decrypt(&str, pw);
            serde_json::from_str(&ciphertext)?
        }
        _ => value,
    };

    Ok(json)
}

pub trait MutinyStorage: Clone + Sized + 'static {
    /// Get the password used to encrypt the storage
    fn password(&self) -> Option<&str>;

    /// Set a value in the storage, the value will already be encrypted if needed
    fn set<T>(&self, key: impl AsRef<str>, value: T) -> Result<(), MutinyError>
    where
        T: Serialize;

    /// Set a value in the storage, the function will encrypt the value if needed
    fn set_data<T>(&self, key: impl AsRef<str>, value: T) -> Result<(), MutinyError>
    where
        T: Serialize,
    {
        let data = serde_json::to_value(value).map_err(|e| MutinyError::PersistenceFailed {
            source: MutinyStorageError::SerdeError { source: e },
        })?;

        let json: Value = encrypt_value(key.as_ref(), data, self.password())?;

        self.set(key, json)
    }

    /// Get a value from the storage, use get_data if you want the value to be decrypted
    fn get<T>(&self, key: impl AsRef<str>) -> Result<Option<T>, MutinyError>
    where
        T: for<'de> Deserialize<'de>;

    /// Get a value from the storage, the function will decrypt the value if needed
    fn get_data<T>(&self, key: impl AsRef<str>) -> Result<Option<T>, MutinyError>
    where
        T: for<'de> Deserialize<'de>,
    {
        match self.get(&key)? {
            None => Ok(None),
            Some(value) => {
                let json: Value = decrypt_value(&key, value, self.password())?;
                let data: T = serde_json::from_value(json)?;
                Ok(Some(data))
            }
        }
    }

    /// Delete a set of values from the storage
    fn delete(&self, keys: &[impl AsRef<str>]) -> Result<(), MutinyError>;

    /// Start the storage, this will be called before any other methods
    async fn start(&mut self) -> Result<(), MutinyError>;

    /// Stop the storage, this will be called when the application is shutting down
    fn stop(&self);

    /// Check if the storage is connected
    fn connected(&self) -> Result<bool, MutinyError>;

    /// Scan the storage for keys with a given prefix and suffix, this will return a list of keys
    /// If this function does not properly filter the keys, it can cause major problems.
    fn scan_keys(&self, prefix: &str, suffix: Option<&str>) -> Result<Vec<String>, MutinyError>;

    /// Scan the storage for keys with a given prefix and suffix, and then gets their values
    fn scan<T>(&self, prefix: &str, suffix: Option<&str>) -> Result<HashMap<String, T>, MutinyError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let keys = self.scan_keys(prefix, suffix)?;

        Ok(keys
            .into_iter()
            .filter_map(|key| {
                self.get_data(&key)
                    .ok()
                    .flatten()
                    .map(|value: T| (key, value))
            })
            .collect())
    }

    /// Insert a mnemonic into the storage
    fn insert_mnemonic(&self, mnemonic: Mnemonic) -> Result<Mnemonic, MutinyError> {
        self.set_data(MNEMONIC_KEY, &mnemonic)?;
        Ok(mnemonic)
    }

    /// Get the mnemonic from the storage
    fn get_mnemonic(&self) -> Result<Mnemonic, MutinyError> {
        let mnemonic: Option<Mnemonic> = self.get_data(MNEMONIC_KEY)?;
        match mnemonic {
            Some(m) => Ok(m),
            None => Err(MutinyError::NotFound),
        }
    }

    /// Override the storage with the new JSON object
    async fn import(json: Value) -> Result<(), MutinyError>;

    /// Deletes all data from the storage
    async fn clear() -> Result<(), MutinyError>;

    /// Replaces the existing auth profiles with the new ones
    fn update_auth_profiles(&self, profiles: Vec<AuthProfile>) -> Result<(), MutinyError> {
        // Check that the profiles are in the correct order
        for (i, p) in profiles.iter().enumerate() {
            if p.index as usize != i {
                return Err(MutinyError::Other(anyhow!(
                    "Auth profile index mismatch: {} != {}",
                    p.index,
                    i
                )));
            }
        }

        self.set_data(AUTH_PROFILES_KEY, profiles)
    }

    /// Gets the auth profiles from storage
    fn get_auth_profiles(&self) -> Result<Vec<AuthProfile>, MutinyError> {
        let res: Option<Vec<AuthProfile>> = self.get_data(AUTH_PROFILES_KEY)?;
        Ok(res.unwrap_or_default()) // if no profiles exist, return an empty vec
    }

    /// Gets the node indexes from storage
    fn get_nodes(&self) -> Result<NodeStorage, MutinyError> {
        let res: Option<NodeStorage> = self.get_data(NODES_KEY)?;
        match res {
            Some(nodes) => Ok(nodes),
            None => Ok(NodeStorage::default()),
        }
    }

    /// Inserts the node indexes into storage
    fn insert_nodes(&self, nodes: NodeStorage) -> Result<(), MutinyError> {
        self.set_data(NODES_KEY, nodes)
    }

    /// Get the current fee estimates from storage
    /// The key is block target, the value is the fee in satoshis per byte
    fn get_fee_estimates(&self) -> Result<Option<HashMap<String, f64>>, MutinyError> {
        self.get_data(FEE_ESTIMATES_KEY)
    }

    /// Inserts the fee estimates into storage
    /// The key is block target, the value is the fee in satoshis per byte
    fn insert_fee_estimates(&self, fees: HashMap<String, f64>) -> Result<(), MutinyError> {
        self.set_data(FEE_ESTIMATES_KEY, fees)
    }

    fn has_done_first_sync(&self) -> Result<bool, MutinyError> {
        self.get_data::<bool>(FIRST_SYNC_KEY)
            .map(|v| v == Some(true))
    }

    fn set_done_first_sync(&self) -> Result<(), MutinyError> {
        self.set_data(FIRST_SYNC_KEY, true)
    }
}

#[derive(Debug, Clone)]
pub struct MemoryStorage {
    pub password: Option<String>,
    pub memory: Arc<RwLock<HashMap<String, Value>>>,
}

impl MemoryStorage {
    pub fn new(password: Option<String>) -> Self {
        Self {
            password,
            memory: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new(None)
    }
}

impl MutinyStorage for MemoryStorage {
    fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    fn set<T>(&self, key: impl AsRef<str>, value: T) -> Result<(), MutinyError>
    where
        T: Serialize,
    {
        let key = key.as_ref().to_string();
        let data = serde_json::to_value(value).map_err(|e| MutinyError::PersistenceFailed {
            source: MutinyStorageError::SerdeError { source: e },
        })?;
        let mut map = self
            .memory
            .try_write()
            .map_err(|e| MutinyError::write_err(e.into()))?;
        map.insert(key, data);

        Ok(())
    }

    fn get<T>(&self, key: impl AsRef<str>) -> Result<Option<T>, MutinyError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let map = self
            .memory
            .try_read()
            .map_err(|e| MutinyError::read_err(e.into()))?;

        match map.get(key.as_ref()) {
            None => Ok(None),
            Some(value) => {
                let data: T = serde_json::from_value(value.to_owned())?;
                Ok(Some(data))
            }
        }
    }

    fn delete(&self, keys: &[impl AsRef<str>]) -> Result<(), MutinyError> {
        let keys: Vec<String> = keys.iter().map(|k| k.as_ref().to_string()).collect();

        let mut map = self
            .memory
            .try_write()
            .map_err(|e| MutinyError::write_err(e.into()))?;

        for key in keys {
            map.remove(&key);
        }

        Ok(())
    }

    async fn start(&mut self) -> Result<(), MutinyError> {
        Ok(())
    }

    fn stop(&self) {}

    fn connected(&self) -> Result<bool, MutinyError> {
        Ok(false)
    }

    fn scan_keys(&self, prefix: &str, suffix: Option<&str>) -> Result<Vec<String>, MutinyError> {
        let map = self
            .memory
            .try_read()
            .map_err(|e| MutinyError::read_err(e.into()))?;

        Ok(map
            .keys()
            .filter(|key| {
                key.starts_with(prefix) && (suffix.is_none() || key.ends_with(suffix.unwrap()))
            })
            .cloned()
            .collect())
    }

    async fn import(_json: Value) -> Result<(), MutinyError> {
        Ok(())
    }

    async fn clear() -> Result<(), MutinyError> {
        Ok(())
    }
}

// Dummy implementation for testing or if people want to ignore persistence
impl MutinyStorage for () {
    fn password(&self) -> Option<&str> {
        None
    }

    fn set<T>(&self, _key: impl AsRef<str>, _value: T) -> Result<(), MutinyError>
    where
        T: Serialize,
    {
        Ok(())
    }

    fn get<T>(&self, _key: impl AsRef<str>) -> Result<Option<T>, MutinyError>
    where
        T: for<'de> Deserialize<'de>,
    {
        Ok(None)
    }

    fn delete(&self, _keys: &[impl AsRef<str>]) -> Result<(), MutinyError> {
        Ok(())
    }

    async fn start(&mut self) -> Result<(), MutinyError> {
        Ok(())
    }

    fn stop(&self) {}

    fn connected(&self) -> Result<bool, MutinyError> {
        Ok(false)
    }

    fn scan_keys(&self, _prefix: &str, _suffix: Option<&str>) -> Result<Vec<String>, MutinyError> {
        Ok(Vec::new())
    }

    async fn import(_json: Value) -> Result<(), MutinyError> {
        Ok(())
    }

    async fn clear() -> Result<(), MutinyError> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct OnChainStorage<S: MutinyStorage>(pub(crate) S);

impl<K, S: MutinyStorage> PersistBackend<K> for OnChainStorage<S>
where
    K: Default + Clone + Append + serde::Serialize + serde::de::DeserializeOwned,
{
    type WriteError = MutinyError;
    type LoadError = MutinyError;

    fn write_changes(&mut self, changeset: &K) -> Result<(), Self::WriteError> {
        if changeset.is_empty() {
            return Ok(());
        }

        match self.0.get_data::<K>(KEYCHAIN_STORE_KEY)? {
            Some(mut keychain_store) => {
                keychain_store.append(changeset.clone());
                self.0.set_data(KEYCHAIN_STORE_KEY, keychain_store)
            }
            None => self.0.set_data(KEYCHAIN_STORE_KEY, changeset),
        }
    }

    fn load_from_persistence(&mut self) -> Result<K, Self::LoadError> {
        if let Some(k) = self.0.get_data(KEYCHAIN_STORE_KEY)? {
            Ok(k)
        } else {
            // If there is no keychain store, we return an empty one
            Ok(K::default())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::storage::MemoryStorage;
    use crate::test_utils::*;
    use crate::{keymanager, storage::MutinyStorage};
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    fn insert_and_get_mnemonic_no_password() {
        let test_name = "insert_and_get_mnemonic_no_password";
        log!("{}", test_name);

        let seed = keymanager::generate_seed(12).unwrap();

        let storage = MemoryStorage::new(None);
        let mnemonic = storage.insert_mnemonic(seed).unwrap();

        let stored_mnemonic = storage.get_mnemonic().unwrap();
        assert_eq!(mnemonic, stored_mnemonic);
    }

    #[test]
    fn insert_and_get_mnemonic_with_password() {
        let test_name = "insert_and_get_mnemonic_with_password";
        log!("{}", test_name);

        let seed = keymanager::generate_seed(12).unwrap();

        let storage = MemoryStorage::new(Some(uuid::Uuid::new_v4().to_string()));

        let mnemonic = storage.insert_mnemonic(seed).unwrap();

        let stored_mnemonic = storage.get_mnemonic().unwrap();
        assert_eq!(mnemonic, stored_mnemonic);
    }
}
