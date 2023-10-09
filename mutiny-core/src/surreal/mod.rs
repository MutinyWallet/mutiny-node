use crate::encrypt::{decrypt_with_password, encrypt, encryption_key_from_pass, Cipher};
use crate::error::{MutinyError, MutinyStorageError};
use crate::ldkstorage::*;
use crate::logging::MutinyLogger;
use crate::nodemanager::NodeStorage;
use crate::storage::DeviceLock;
use crate::utils::{now, spawn};
use crate::vss::{MutinyVssClient, VssKeyValueItem};
use bdk_chain::{Append, PersistBackend};
use bip39::Mnemonic;
use lightning::util::logger::Logger;
use lightning::{log_debug, log_error};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use surrealdb::{Connection, Surreal};
use uuid::Uuid;

pub const KV_NAME: &str = "mutiny_surreal_db";

pub const KEYCHAIN_STORE_KEY: &str = "bdk_keychain";
pub(crate) const MNEMONIC_KEY: &str = "mnemonic";
pub(crate) const NEED_FULL_SYNC_KEY: &str = "needs_full_sync";
pub const NODES_KEY: &str = "nodes";
const FEE_ESTIMATES_KEY: &str = "fee_estimates";
pub const BITCOIN_PRICE_CACHE_KEY: &str = "bitcoin_price_cache";
const FIRST_SYNC_KEY: &str = "first_sync";
pub(crate) const DEVICE_ID_KEY: &str = "device_id";
pub const DEVICE_LOCK_KEY: &str = "device_lock";

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
    cipher: Option<&Cipher>,
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

#[derive(Clone, Serialize, Deserialize)]
pub struct MnemonicStorage {
    pub mnemonic: Mnemonic,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceId {
    pub device_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FirstSync {
    pub fist_sync: bool,
}

#[derive(Clone)]
pub struct SurrealDb<C: Connection> {
    db: Surreal<C>,
    password: Option<String>,
    cipher: Option<Cipher>,
    vss_client: Option<Arc<MutinyVssClient>>,
    logger: Arc<MutinyLogger>,
}

impl<C> SurrealDb<C>
where
    C: Connection + Clone,
{
    pub fn new(
        db: Surreal<C>,
        password: Option<String>,
        cipher: Option<Cipher>,
        vss_client: Option<Arc<MutinyVssClient>>,
        logger: Arc<MutinyLogger>,
    ) -> Self {
        Self {
            db,
            password,
            cipher,
            vss_client,
            logger,
        }
    }

    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    pub fn vss_client(&self) -> Option<Arc<MutinyVssClient>> {
        self.vss_client.clone()
    }

    fn set<T>(&self, key: impl AsRef<str>, value: T) -> Result<(), MutinyError>
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        let db = self.db.clone();
        let key = key.as_ref().to_string();
        let value = serde_json::to_value(value)?;
        let logger = self.logger.clone();
        spawn(async move {
            let res: surrealdb::Result<Option<T>> = db.update((KV_NAME, &key)).content(value).await;

            if let Err(e) = res {
                log_error!(logger, "Failed to store {key}: {e}")
            }
        });

        Ok(())
    }

    pub async fn set_async<T>(&self, key: impl AsRef<str>, value: T) -> Result<(), MutinyError>
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        let _: Option<T> = self
            .db
            .update((KV_NAME, key.as_ref()))
            .content(value)
            .await
            .map_err(|e| {
                log_error!(self.logger, "Failed to write {}: {e}", key.as_ref());
                MutinyError::write_err(e.into())
            })?;

        Ok(())
    }

    pub fn set_data<T>(
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

        if let (Some(vss), Some(version)) = (self.vss_client.clone(), version) {
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

        let json: Value = encrypt_value(key.as_ref(), data, self.cipher.as_ref())?;

        self.set(key, json)
    }

    /// Set a value in the storage, the function will encrypt the value if needed
    pub async fn set_data_async<T>(
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
            let json: Value = encrypt_value(key.as_ref(), local_data, self.cipher.as_ref())?;
            self.set_async(key.as_ref(), json).await.map_err(|e| {
                log_error!(self.logger, "Failed to write {}: {e}", key.as_ref());
                e
            })
        };

        // save to VSS if it is enabled
        let vss_fut = async {
            if let (Some(vss), Some(version)) = (self.vss_client.as_ref(), version) {
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
    pub async fn get<T>(&self, key: impl AsRef<str>) -> Result<Option<T>, MutinyError>
    where
        T: for<'de> Deserialize<'de>,
    {
        Ok(self.db.select((KV_NAME, key.as_ref())).await.map_err(|e| {
            log_error!(self.logger, "Failed to read {}: {e}", key.as_ref());
            MutinyError::read_err(e.into())
        })?)
    }

    /// Get a value from the storage, the function will decrypt the value if needed
    pub async fn get_data<T>(&self, key: impl AsRef<str>) -> Result<Option<T>, MutinyError>
    where
        T: for<'de> Deserialize<'de>,
    {
        match self.get(&key).await.map_err(|e| {
            log_error!(self.logger, "Failed to read {}: {e}", key.as_ref());
            e
        })? {
            None => Ok(None),
            Some(value) => {
                let json: Value = decrypt_value(&key, value, self.password.as_deref())?;
                let data: T = serde_json::from_value(json)?;
                Ok(Some(data))
            }
        }
    }

    /// Delete a set of values from the storage
    pub async fn delete(&self, keys: &[impl AsRef<str>]) -> Result<(), MutinyError> {
        for key in keys {
            let _: Option<Value> = self
                .db
                .delete((KV_NAME, key.as_ref()))
                .await
                .map_err(|e| MutinyError::write_err(e.into()))?;
        }

        Ok(())
    }

    /// Start the storage, this will be called before any other methods
    pub async fn start(&mut self) -> Result<(), MutinyError> {
        Ok(())
    }

    /// Stop the storage, this will be called when the application is shutting down
    pub fn stop(&self) {}

    /// Check if the storage is connected
    pub fn connected(&self) -> Result<bool, MutinyError> {
        Ok(true)
    }

    /// Scan the storage for keys with a given prefix and suffix, this will return a list of keys
    /// If this function does not properly filter the keys, it can cause major problems.
    fn scan_keys(&self, _prefix: &str, _suffix: Option<&str>) -> Result<Vec<String>, MutinyError> {
        Ok(vec![])
    }

    /// Scan the storage for keys with a given prefix and suffix, and then gets their values
    pub async fn scan<T>(
        &self,
        prefix: &str,
        suffix: Option<&str>,
    ) -> Result<HashMap<String, T>, MutinyError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let keys = self.scan_keys(prefix, suffix)?;

        let mut map = HashMap::with_capacity(keys.len());

        for key in keys {
            let kv = self.get_data::<T>(&key).await?;
            if let Some(v) = kv {
                map.insert(key, v);
            }
        }

        Ok(map)
    }

    /// Insert a mnemonic into the storage
    pub async fn insert_mnemonic(&self, mnemonic: Mnemonic) -> Result<Mnemonic, MutinyError> {
        log_debug!(self.logger, "Inserting mnemonic into storage");
        let value = MnemonicStorage {
            mnemonic: mnemonic.clone(),
        };
        self.set_data_async(MNEMONIC_KEY, value, None).await?;
        Ok(mnemonic)
    }

    /// Get the mnemonic from the storage
    pub async fn get_mnemonic(&self) -> Result<Option<Mnemonic>, MutinyError> {
        Ok(self
            .get_data::<MnemonicStorage>(MNEMONIC_KEY)
            .await
            .map_err(|e| {
                log_error!(self.logger, "Failed to read mnemonic: {e}");
                e
            })?
            .map(|d| d.mnemonic))
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

    pub async fn change_password_and_rewrite_storage(
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
            let value = self.get_data(key).await?;
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
            self.set_data_async(key, value, None).await?;
        }

        Ok(())
    }

    /// Override the storage with the new JSON object
    pub async fn import(_json: Value) -> Result<(), MutinyError> {
        // todo
        Ok(())
    }

    /// Deletes all data from the storage
    pub async fn clear() -> Result<(), MutinyError> {
        // todo
        Ok(())
    }

    /// Deletes all data from the storage and removes lock from VSS
    pub async fn delete_all(&self) -> Result<(), MutinyError> {
        Self::clear().await?;
        // remove lock from VSS if is is enabled
        if self.vss_client.as_ref().is_some() {
            let device = self.get_device_id().await?;
            // set time to 0 to unlock
            let lock = DeviceLock { time: 0, device };
            // still update the version so it is written to VSS
            let time = now().as_secs() as u32;
            self.set_data_async(DEVICE_LOCK_KEY, lock, Some(time))
                .await?;
        }

        Ok(())
    }

    /// Gets the node indexes from storage
    pub async fn get_nodes(&self) -> Result<NodeStorage, MutinyError> {
        let res: Option<NodeStorage> = self.get_data(NODES_KEY).await?;
        match res {
            Some(nodes) => Ok(nodes),
            None => Ok(NodeStorage::default()),
        }
    }

    /// Inserts the node indexes into storage
    pub fn insert_nodes(&self, nodes: NodeStorage) -> Result<(), MutinyError> {
        let version = Some(nodes.version);
        self.set_data(NODES_KEY, nodes, version)
    }

    /// Get the current fee estimates from storage
    /// The key is block target, the value is the fee in satoshis per byte
    pub async fn get_fee_estimates(&self) -> Result<Option<HashMap<String, f64>>, MutinyError> {
        self.get_data(FEE_ESTIMATES_KEY).await
    }

    /// Inserts the fee estimates into storage
    /// The key is block target, the value is the fee in satoshis per byte
    pub fn insert_fee_estimates(&self, fees: HashMap<String, f64>) -> Result<(), MutinyError> {
        self.set_data(FEE_ESTIMATES_KEY, fees, None)
    }

    /// Get the current bitcoin price cache from storage
    pub async fn get_bitcoin_price_cache(&self) -> Result<HashMap<String, f32>, MutinyError> {
        Ok(self
            .get_data(BITCOIN_PRICE_CACHE_KEY)
            .await?
            .unwrap_or_default())
    }

    /// Inserts the bitcoin price cache into storage
    pub fn insert_bitcoin_price_cache(
        &self,
        prices: HashMap<String, f32>,
    ) -> Result<(), MutinyError> {
        self.set_data(BITCOIN_PRICE_CACHE_KEY, prices, None)
    }

    pub async fn has_done_first_sync(&self) -> Result<bool, MutinyError> {
        self.get_data::<FirstSync>(FIRST_SYNC_KEY)
            .await
            .map(|v| v.map(|v| v.fist_sync) == Some(true))
    }

    pub fn set_done_first_sync(&self) -> Result<(), MutinyError> {
        let value = FirstSync { fist_sync: true };
        self.set_data(FIRST_SYNC_KEY, value, None)
    }

    pub async fn get_device_id(&self) -> Result<String, MutinyError> {
        match self.get_data::<DeviceId>(DEVICE_ID_KEY).await? {
            Some(id) => Ok(id.device_id),
            None => {
                let new_id = Uuid::new_v4().to_string();
                let device = DeviceId {
                    device_id: new_id.clone(),
                };
                self.set_data(DEVICE_ID_KEY, device, None)?;
                Ok(new_id)
            }
        }
    }

    pub async fn get_device_lock(&self) -> Result<Option<DeviceLock>, MutinyError> {
        self.get_data(DEVICE_LOCK_KEY).await
    }

    pub async fn set_device_lock(&self) -> Result<(), MutinyError> {
        let device = self.get_device_id().await?;
        if let Some(lock) = self.get_device_lock().await? {
            if lock.is_locked(&device) {
                return Err(MutinyError::AlreadyRunning);
            }
        }

        let time = now().as_secs() as u32;
        let lock = DeviceLock { time, device };
        self.set_data_async(DEVICE_LOCK_KEY, lock, Some(time)).await
    }
}

impl<K, C: Connection> PersistBackend<K> for SurrealDb<C>
where
    K: Default + Clone + Append + serde::Serialize + serde::de::DeserializeOwned,
{
    type WriteError = MutinyError;
    type LoadError = MutinyError;

    fn write_changes(&mut self, _changeset: &K) -> Result<(), Self::WriteError> {
        Ok(())
        // if changeset.is_empty() {
        //     return Ok(());
        // }
        //
        // match self.0.get_data::<K>(KEYCHAIN_STORE_KEY)? {
        //     Some(mut keychain_store) => {
        //         keychain_store.append(changeset.clone());
        //         self.0.set_data(KEYCHAIN_STORE_KEY, keychain_store, None)
        //     }
        //     None => self.0.set_data(KEYCHAIN_STORE_KEY, changeset, None),
        // }
    }

    fn load_from_persistence(&mut self) -> Result<K, Self::LoadError> {
        // if let Some(k) = self.0.get_data(KEYCHAIN_STORE_KEY)? {
        //     Ok(k)
        // } else {
        //     // If there is no keychain store, we return an empty one
        //     Ok(K::default())
        // }
        Ok(K::default())
    }
}
