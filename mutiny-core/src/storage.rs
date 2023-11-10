use crate::encrypt::{decrypt_with_password, encrypt, encryption_key_from_pass, Cipher};
use crate::error::{MutinyError, MutinyStorageError};
use crate::ldkstorage::CHANNEL_MANAGER_KEY;
use crate::nodemanager::{NodeStorage, DEVICE_LOCK_INTERVAL_SECS};
use crate::utils::{now, spawn};
use crate::vss::{MutinyVssClient, VssKeyValueItem};
use bdk::chain::{Append, PersistBackend};
use bip39::Mnemonic;
use lightning::log_error;
use lightning::util::logger::Logger;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

pub const KEYCHAIN_STORE_KEY: &str = "bdk_keychain";
pub const MNEMONIC_KEY: &str = "mnemonic";
pub(crate) const NEED_FULL_SYNC_KEY: &str = "needs_full_sync";
pub const NODES_KEY: &str = "nodes";
const FEE_ESTIMATES_KEY: &str = "fee_estimates";
pub const BITCOIN_PRICE_CACHE_KEY: &str = "bitcoin_price_cache";
const FIRST_SYNC_KEY: &str = "first_sync";
pub(crate) const DEVICE_ID_KEY: &str = "device_id";
pub const DEVICE_LOCK_KEY: &str = "device_lock";
pub(crate) const EXPECTED_NETWORK_KEY: &str = "network";

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
    cipher: Option<Cipher>,
) -> Result<Value, MutinyError> {
    // Only bother encrypting if a password is set
    let res = match cipher {
        Some(c) if needs_encryption(key.as_ref()) => {
            let str = serde_json::to_string(&value)?;
            let ciphertext = encrypt(&str, c)?;
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
            let ciphertext = decrypt_with_password(&str, pw)?;
            serde_json::from_str(&ciphertext)?
        }
        _ => value,
    };

    Ok(json)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedValue {
    pub version: u32,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceLock {
    pub time: u32,
    pub device: String,
}

impl DeviceLock {
    /// Check if the device is locked
    /// This is determined if the time is less than 2 minutes ago
    pub fn is_locked(&self, id: &str) -> bool {
        let now = now().as_secs();
        let diff = now.saturating_sub(self.time as u64);
        diff < DEVICE_LOCK_INTERVAL_SECS * 2 && self.device != id
    }
}

pub trait MutinyStorage: Clone + Sized + 'static {
    /// Get the password used to encrypt the storage
    fn password(&self) -> Option<&str>;

    /// Get the encryption key used for storage
    fn cipher(&self) -> Option<Cipher>;

    /// Get the VSS client used for storage
    fn vss_client(&self) -> Option<Arc<MutinyVssClient>>;

    /// Set a value in the storage, the value will already be encrypted if needed
    fn set<T>(&self, key: impl AsRef<str>, value: T) -> Result<(), MutinyError>
    where
        T: Serialize;

    /// Set a value in the storage, the value will already be encrypted if needed
    /// This is an async version of set, it is not required to implement this
    /// If this is not implemented, the default implementation will just call set
    async fn set_async<T>(&self, key: impl AsRef<str>, value: T) -> Result<(), MutinyError>
    where
        T: Serialize,
    {
        self.set(key, value)
    }

    /// Set a value in the storage, the function will encrypt the value if needed
    fn set_data<T>(
        &self,
        key: impl AsRef<str>,
        value: T,
        version: Option<u32>,
    ) -> Result<(), MutinyError>
    where
        T: Serialize,
    {
        let data = serde_json::to_value(value).map_err(|e| MutinyError::PersistenceFailed {
            source: MutinyStorageError::SerdeError { source: e },
        })?;

        if let (Some(vss), Some(version)) = (self.vss_client(), version) {
            let item = VssKeyValueItem {
                key: key.as_ref().to_string(),
                value: data.clone(),
                version,
            };
            spawn(async move {
                if let Err(e) = vss.put_objects(vec![item]).await {
                    log_error!(vss.logger, "Failed to put object in VSS: {e}");
                }
            });
        }

        let json: Value = encrypt_value(key.as_ref(), data, self.cipher())?;

        self.set(key, json)
    }

    /// Set a value in the storage, the function will encrypt the value if needed
    async fn set_data_async<T>(
        &self,
        key: impl AsRef<str>,
        value: T,
        version: Option<u32>,
    ) -> Result<(), MutinyError>
    where
        T: Serialize,
    {
        let data = serde_json::to_value(value).map_err(|e| MutinyError::PersistenceFailed {
            source: MutinyStorageError::SerdeError { source: e },
        })?;

        // encrypt value in async block so it can be done in parallel
        // with the VSS call
        let local_data = data.clone();
        let local_fut = async {
            let json: Value = encrypt_value(key.as_ref(), local_data, self.cipher())?;
            self.set_async(key.as_ref(), json).await
        };

        // save to VSS if it is enabled
        let vss_fut = async {
            if let (Some(vss), Some(version)) = (self.vss_client(), version) {
                let item = VssKeyValueItem {
                    key: key.as_ref().to_string(),
                    value: data,
                    version,
                };

                vss.put_objects(vec![item]).await
            } else {
                Ok(())
            }
        };

        futures::try_join!(local_fut, vss_fut)?;

        Ok(())
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

        let mut map = HashMap::with_capacity(keys.len());

        for key in keys {
            let kv = self.get_data::<T>(&key)?;
            if let Some(v) = kv {
                map.insert(key, v);
            }
        }

        Ok(map)
    }

    /// Insert a mnemonic into the storage
    fn insert_mnemonic(&self, mnemonic: Mnemonic) -> Result<Mnemonic, MutinyError> {
        self.set_data(MNEMONIC_KEY, &mnemonic, None)?;
        Ok(mnemonic)
    }

    /// Get the mnemonic from the storage
    fn get_mnemonic(&self) -> Result<Option<Mnemonic>, MutinyError> {
        self.get_data(MNEMONIC_KEY)
    }

    fn change_password(
        &mut self,
        new: Option<String>,
        new_cipher: Option<Cipher>,
    ) -> Result<(), MutinyError>;

    fn change_password_and_rewrite_storage(
        &mut self,
        old: Option<String>,
        new: Option<String>,
    ) -> Result<(), MutinyError> {
        // check if old password is correct
        if old != self.password().map(|s| s.to_owned()) {
            return Err(MutinyError::IncorrectPassword);
        }

        // get all of our keys
        let mut keys: Vec<String> = self.scan_keys("", None)?;
        // get the ones that need encryption
        keys.retain(|k| needs_encryption(k));

        // decrypt all of the values
        let mut values: HashMap<String, Value> = HashMap::new();
        for key in keys.iter() {
            let value = self.get_data(key)?;
            if let Some(v) = value {
                values.insert(key.to_owned(), v);
            }
        }

        // change the password
        let new_cipher = new
            .as_ref()
            .filter(|p| !p.is_empty())
            .map(|p| encryption_key_from_pass(p))
            .transpose()?;
        self.change_password(new, new_cipher)?;

        // encrypt all of the values
        for (key, value) in values.iter() {
            self.set_data(key, value, None)?;
        }

        Ok(())
    }

    /// Override the storage with the new JSON object
    async fn import(json: Value) -> Result<(), MutinyError>;

    /// Deletes all data from the storage
    async fn clear() -> Result<(), MutinyError>;

    /// Deletes all data from the storage and removes lock from VSS
    async fn delete_all(&self) -> Result<(), MutinyError> {
        Self::clear().await?;
        // remove lock from VSS if is is enabled
        if self.vss_client().is_some() {
            let device = self.get_device_id()?;
            // set time to 0 to unlock
            let lock = DeviceLock { time: 0, device };
            // still update the version so it is written to VSS
            let time = now().as_secs() as u32;
            self.set_data(DEVICE_LOCK_KEY, lock, Some(time))?;
        }

        Ok(())
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
        let version = Some(nodes.version);
        self.set_data(NODES_KEY, nodes, version)
    }

    /// Get the current fee estimates from storage
    /// The key is block target, the value is the fee in satoshis per byte
    fn get_fee_estimates(&self) -> Result<Option<HashMap<String, f64>>, MutinyError> {
        self.get_data(FEE_ESTIMATES_KEY)
    }

    /// Inserts the fee estimates into storage
    /// The key is block target, the value is the fee in satoshis per byte
    fn insert_fee_estimates(&self, fees: HashMap<String, f64>) -> Result<(), MutinyError> {
        self.set_data(FEE_ESTIMATES_KEY, fees, None)
    }

    /// Get the current bitcoin price cache from storage
    fn get_bitcoin_price_cache(&self) -> Result<HashMap<String, f32>, MutinyError> {
        Ok(self.get_data(BITCOIN_PRICE_CACHE_KEY)?.unwrap_or_default())
    }

    /// Inserts the bitcoin price cache into storage
    fn insert_bitcoin_price_cache(&self, prices: HashMap<String, f32>) -> Result<(), MutinyError> {
        self.set_data(BITCOIN_PRICE_CACHE_KEY, prices, None)
    }

    fn has_done_first_sync(&self) -> Result<bool, MutinyError> {
        self.get_data::<bool>(FIRST_SYNC_KEY)
            .map(|v| v == Some(true))
    }

    fn set_done_first_sync(&self) -> Result<(), MutinyError> {
        self.set_data(FIRST_SYNC_KEY, true, None)
    }

    fn get_device_id(&self) -> Result<String, MutinyError> {
        match self.get_data(DEVICE_ID_KEY)? {
            Some(id) => Ok(id),
            None => {
                let new_id = Uuid::new_v4().to_string();
                self.set_data(DEVICE_ID_KEY, &new_id, None)?;
                Ok(new_id)
            }
        }
    }

    fn get_device_lock(&self) -> Result<Option<DeviceLock>, MutinyError> {
        self.get_data(DEVICE_LOCK_KEY)
    }

    fn set_device_lock(&self) -> Result<(), MutinyError> {
        let device = self.get_device_id()?;
        if let Some(lock) = self.get_device_lock()? {
            if lock.is_locked(&device) {
                return Err(MutinyError::AlreadyRunning);
            }
        }

        let time = now().as_secs() as u32;
        let lock = DeviceLock { time, device };
        self.set_data(DEVICE_LOCK_KEY, lock, Some(time))
    }

    async fn fetch_device_lock(&self) -> Result<Option<DeviceLock>, MutinyError>;
}

#[derive(Clone)]
pub struct MemoryStorage {
    pub password: Option<String>,
    pub cipher: Option<Cipher>,
    pub memory: Arc<RwLock<HashMap<String, Value>>>,
    pub vss_client: Option<Arc<MutinyVssClient>>,
}

impl MemoryStorage {
    pub fn new(
        password: Option<String>,
        cipher: Option<Cipher>,
        vss_client: Option<Arc<MutinyVssClient>>,
    ) -> Self {
        Self {
            cipher,
            password,
            memory: Arc::new(RwLock::new(HashMap::new())),
            vss_client,
        }
    }

    pub async fn load_from_vss(&self) -> Result<(), MutinyError> {
        if let Some(vss) = self.vss_client() {
            let keys = vss.list_key_versions(None).await?;
            let mut items = HashMap::new();
            for key in keys {
                let obj = vss.get_object(&key.key).await?;
                items.insert(key.key, obj.value);
            }
            let mut map = self
                .memory
                .try_write()
                .map_err(|e| MutinyError::write_err(e.into()))?;
            map.extend(items);
        }

        Ok(())
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new(None, None, None)
    }
}

impl MutinyStorage for MemoryStorage {
    fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    fn cipher(&self) -> Option<Cipher> {
        self.cipher.to_owned()
    }

    fn vss_client(&self) -> Option<Arc<MutinyVssClient>> {
        self.vss_client.clone()
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

    fn change_password(
        &mut self,
        new: Option<String>,
        new_cipher: Option<Cipher>,
    ) -> Result<(), MutinyError> {
        self.password = new;
        self.cipher = new_cipher;
        Ok(())
    }

    async fn import(_json: Value) -> Result<(), MutinyError> {
        Ok(())
    }

    async fn clear() -> Result<(), MutinyError> {
        Ok(())
    }

    async fn fetch_device_lock(&self) -> Result<Option<DeviceLock>, MutinyError> {
        self.get_device_lock()
    }
}

// Dummy implementation for testing or if people want to ignore persistence
impl MutinyStorage for () {
    fn password(&self) -> Option<&str> {
        None
    }

    fn cipher(&self) -> Option<Cipher> {
        None
    }

    fn vss_client(&self) -> Option<Arc<MutinyVssClient>> {
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

    fn change_password(
        &mut self,
        _new: Option<String>,
        _new_cipher: Option<Cipher>,
    ) -> Result<(), MutinyError> {
        Ok(())
    }

    async fn import(_json: Value) -> Result<(), MutinyError> {
        Ok(())
    }

    async fn clear() -> Result<(), MutinyError> {
        Ok(())
    }

    async fn fetch_device_lock(&self) -> Result<Option<DeviceLock>, MutinyError> {
        self.get_device_lock()
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
                self.0.set_data(KEYCHAIN_STORE_KEY, keychain_store, None)
            }
            None => self.0.set_data(KEYCHAIN_STORE_KEY, changeset, None),
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
    use crate::test_utils::*;
    use crate::utils::sleep;
    use crate::{encrypt::encryption_key_from_pass, storage::MemoryStorage};
    use crate::{keymanager, storage::MutinyStorage};
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    fn insert_and_get_mnemonic_no_password() {
        let test_name = "insert_and_get_mnemonic_no_password";
        log!("{}", test_name);

        let seed = keymanager::generate_seed(12).unwrap();

        let storage = MemoryStorage::default();
        let mnemonic = storage.insert_mnemonic(seed).unwrap();

        let stored_mnemonic = storage.get_mnemonic().unwrap();
        assert_eq!(Some(mnemonic), stored_mnemonic);
    }

    #[test]
    fn insert_and_get_mnemonic_with_password() {
        let test_name = "insert_and_get_mnemonic_with_password";
        log!("{}", test_name);

        let seed = keymanager::generate_seed(12).unwrap();

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher), None);

        let mnemonic = storage.insert_mnemonic(seed).unwrap();

        let stored_mnemonic = storage.get_mnemonic().unwrap();
        assert_eq!(Some(mnemonic), stored_mnemonic);
    }

    #[test]
    async fn test_device_lock() {
        let test_name = "test_device_lock";
        log!("{}", test_name);

        let vss = std::sync::Arc::new(create_vss_client().await);
        let storage = MemoryStorage::new(None, None, Some(vss.clone()));
        storage.load_from_vss().await.unwrap();

        let id = storage.get_device_id().unwrap();
        let lock = storage.get_device_lock().unwrap();
        assert_eq!(None, lock);

        storage.set_device_lock().unwrap();
        // sleep 1 second to make sure it writes to VSS
        sleep(1_000).await;

        let lock = storage.get_device_lock().unwrap();
        assert!(lock.is_some());
        assert!(!lock.clone().unwrap().is_locked(&id));
        assert!(lock.clone().unwrap().is_locked("different_id"));
        assert_eq!(lock.unwrap().device, id);

        // make sure we can set lock again, should work because same device id
        storage.set_device_lock().unwrap();
        // sleep 1 second to make sure it writes to VSS
        sleep(1_000).await;

        // create new storage with new device id and make sure we can't set lock
        let storage = MemoryStorage::new(None, None, Some(vss));
        storage.load_from_vss().await.unwrap();

        let new_id = storage.get_device_id().unwrap();
        assert_ne!(id, new_id);

        let lock = storage.get_device_lock().unwrap();
        assert!(lock.is_some());
        // not locked for active device
        assert!(!lock.clone().unwrap().is_locked(&id));
        // is locked for new device
        assert!(lock.clone().unwrap().is_locked(&new_id));
        assert_eq!(lock.unwrap().device, id);

        assert!(storage.set_device_lock().is_err())
    }
}
