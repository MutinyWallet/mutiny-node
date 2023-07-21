use anyhow::anyhow;
use gloo_storage::{LocalStorage, Storage};
use gloo_utils::format::JsValueSerdeExt;
use lightning::util::logger::Logger;
use lightning::{log_debug, log_error};
use log::error;
use mutiny_core::encrypt::encryption_key_from_pass;
use mutiny_core::logging::MutinyLogger;
use mutiny_core::nodemanager::NodeStorage;
use mutiny_core::storage::*;
use mutiny_core::vss::*;
use mutiny_core::*;
use mutiny_core::{
    encrypt::Cipher,
    error::{MutinyError, MutinyStorageError},
};
use rexie::{ObjectStore, Rexie, TransactionMode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::spawn_local;

pub(crate) const WALLET_DATABASE_NAME: &str = "wallet";
pub(crate) const WALLET_OBJECT_STORE_NAME: &str = "wallet_store";

#[derive(Clone)]
pub struct IndexedDbStorage {
    pub(crate) password: Option<String>,
    pub cipher: Option<Cipher>,
    /// In-memory cache of the wallet data
    /// This is used to avoid having to read from IndexedDB on every get.
    /// This is a RwLock because we want to be able to read from it without blocking
    memory: Arc<RwLock<HashMap<String, Value>>>,
    pub(crate) indexed_db: Arc<RwLock<Option<Rexie>>>,
    vss: Option<Arc<MutinyVssClient>>,
    logger: Arc<MutinyLogger>,
}

impl IndexedDbStorage {
    pub async fn new(
        password: Option<String>,
        cipher: Option<Cipher>,
        vss: Option<Arc<MutinyVssClient>>,
        logger: Arc<MutinyLogger>,
    ) -> Result<IndexedDbStorage, MutinyError> {
        let indexed_db = Arc::new(RwLock::new(Some(Self::build_indexed_db_database().await?)));
        let password = password.filter(|p| !p.is_empty());

        let map = Self::read_all(&indexed_db, password.clone(), vss.as_deref(), &logger).await?;
        let memory = Arc::new(RwLock::new(map));

        Ok(IndexedDbStorage {
            password,
            cipher,
            memory,
            indexed_db,
            vss,
            logger,
        })
    }

    async fn save_to_indexed_db(
        indexed_db: &Arc<RwLock<Option<Rexie>>>,
        key: &str,
        data: &Value,
    ) -> Result<(), MutinyError> {
        let tx = indexed_db
            .try_write()
            .map_err(|e| MutinyError::read_err(e.into()))
            .and_then(|mut indexed_db_lock| {
                if let Some(indexed_db) = &mut *indexed_db_lock {
                    indexed_db
                        .transaction(&[WALLET_OBJECT_STORE_NAME], TransactionMode::ReadWrite)
                        .map_err(|e| {
                            MutinyError::read_err(
                                anyhow!("Failed to create indexed db transaction: {e}").into(),
                            )
                        })
                } else {
                    Err(MutinyError::read_err(MutinyStorageError::IndexedDBError))
                }
            })?;

        let store = tx.store(WALLET_OBJECT_STORE_NAME).map_err(|e| {
            MutinyError::read_err(anyhow!("Failed to create indexed db store: {e}").into())
        })?;

        // save to indexed db
        store
            .put(&JsValue::from_serde(&data)?, Some(&JsValue::from(key)))
            .await
            .map_err(|_| MutinyError::write_err(MutinyStorageError::IndexedDBError))?;

        tx.done()
            .await
            .map_err(|_| MutinyError::write_err(MutinyStorageError::IndexedDBError))?;

        Ok(())
    }

    async fn delete_from_indexed_db(
        indexed_db: &Arc<RwLock<Option<Rexie>>>,
        keys: &[String],
    ) -> Result<(), MutinyError> {
        let tx = indexed_db
            .try_write()
            .map_err(|e| {
                error!("Failed to acquire indexed db lock: {e}");
                MutinyError::read_err(e.into())
            })
            .and_then(|mut indexed_db_lock| {
                if let Some(indexed_db) = &mut *indexed_db_lock {
                    indexed_db
                        .transaction(&[WALLET_OBJECT_STORE_NAME], TransactionMode::ReadWrite)
                        .map_err(|e| {
                            error!("Failed to create indexed db transaction: {e}");
                            MutinyError::read_err(
                                anyhow!("Failed to create indexed db transaction: {e}").into(),
                            )
                        })
                } else {
                    error!("No indexed db instance found");
                    Err(MutinyError::read_err(MutinyStorageError::IndexedDBError))
                }
            })?;

        let store = tx.store(WALLET_OBJECT_STORE_NAME).map_err(|e| {
            error!("Failed to create indexed db store: {e}");
            MutinyError::read_err(anyhow!("Failed to create indexed db store {e}").into())
        })?;

        // delete from indexed db
        for key in keys {
            store
                .delete(&JsValue::from(key))
                .await
                .map_err(|_| MutinyError::write_err(MutinyStorageError::IndexedDBError))?;
        }

        tx.done()
            .await
            .map_err(|_| MutinyError::write_err(MutinyStorageError::IndexedDBError))?;

        Ok(())
    }

    pub(crate) async fn read_all(
        indexed_db: &Arc<RwLock<Option<Rexie>>>,
        password: Option<String>,
        vss: Option<&MutinyVssClient>,
        logger: &MutinyLogger,
    ) -> Result<HashMap<String, Value>, MutinyError> {
        let store = {
            let tx = indexed_db
                .try_read()
                .map_err(|e| MutinyError::read_err(e.into()))
                .and_then(|indexed_db_lock| {
                    if let Some(indexed_db) = &*indexed_db_lock {
                        indexed_db
                            .transaction(&[WALLET_OBJECT_STORE_NAME], TransactionMode::ReadOnly)
                            .map_err(|e| {
                                MutinyError::read_err(
                                    anyhow!("Failed to create indexed db transaction: {e}").into(),
                                )
                            })
                    } else {
                        Err(MutinyError::read_err(MutinyStorageError::IndexedDBError))
                    }
                })?;
            tx.store(WALLET_OBJECT_STORE_NAME).map_err(|e| {
                MutinyError::read_err(anyhow!("Failed to create indexed db store {e}").into())
            })?
        };

        let cipher = password
            .as_ref()
            .filter(|p| !p.is_empty())
            .map(|p| encryption_key_from_pass(p))
            .transpose()?;

        // use a memory storage to handle encryption and decryption
        let map = MemoryStorage::new(password, cipher, None);

        let all_json = store.get_all(None, None, None, None).await.map_err(|e| {
            MutinyError::read_err(anyhow!("Failed to get all from store: {e}").into())
        })?;

        for (key, value) in all_json {
            let key = key
                .as_string()
                .ok_or(MutinyError::read_err(MutinyStorageError::Other(anyhow!(
                    "key from indexedDB is not a string"
                ))))?;

            let json: Value = value.into_serde()?;
            map.set(key, json)?;
        }

        // get the local storage data, this should take priority if it is being used
        log_debug!(logger, "Reading from local storage");
        let local_storage = LocalStorage::raw();
        let length = LocalStorage::length();
        for index in 0..length {
            let key_opt: Option<String> = local_storage.key(index).unwrap();

            if let Some(key) = key_opt {
                // only add to the map if it is a key we expect
                // this is to prevent any unexpected data from being added to the map
                // from either malicious 3rd party or a previous version of the wallet
                if write_to_local_storage(&key) {
                    let value: Value = LocalStorage::get(&key).unwrap();
                    map.set(key, value)?;
                }
            }
        }

        match vss {
            None => {
                let final_map = map.memory.read().unwrap();
                Ok(final_map.clone())
            }
            Some(vss) => {
                log_debug!(logger, "Reading from vss");
                let keys = vss.list_key_versions(None).await?;
                let mut futs = vec![];
                for kv in keys {
                    futs.push(Self::handle_vss_key(kv, vss, &map, logger));
                }
                let results = futures::future::join_all(futs).await;
                for result in results {
                    if let Some((key, value)) = result? {
                        map.set_data(key, value, None)?;
                    }
                }
                let final_map = map.memory.read().unwrap();
                Ok(final_map.clone())
            }
        }
    }

    async fn handle_vss_key(
        kv: KeyVersion,
        vss: &MutinyVssClient,
        current: &MemoryStorage,
        logger: &MutinyLogger,
    ) -> Result<Option<(String, Value)>, MutinyError> {
        log_debug!(
            logger,
            "Found vss key {} with version {}",
            kv.key,
            kv.version
        );

        match kv.key.as_str() {
            NODES_KEY => {
                let obj = vss.get_object(&kv.key).await?;
                // we can get version from node storage, so we should compare
                match current.get_data::<NodeStorage>(&kv.key)? {
                    Some(versioned) => {
                        if versioned.version <= kv.version
                            && serde_json::from_value::<NodeStorage>(obj.value.clone()).is_ok()
                        {
                            return Ok(Some((kv.key, obj.value)));
                        }
                    }
                    None => return Ok(Some((kv.key, obj.value))),
                }
            }
            DEVICE_LOCK_KEY => {
                let obj = vss.get_object(&kv.key).await?;
                // we can get version from device lock, so we should compare
                match current.get_data::<DeviceLock>(&kv.key)? {
                    Some(versioned) => {
                        if versioned.time <= kv.version
                            && serde_json::from_value::<DeviceLock>(obj.value.clone()).is_ok()
                        {
                            return Ok(Some((kv.key, obj.value)));
                        }
                    }
                    None => return Ok(Some((kv.key, obj.value))),
                }
            }
            key => {
                if key.starts_with(MONITORS_PREFIX_KEY) {
                    let obj = vss.get_object(&kv.key).await?;
                    // we can get versions from monitors, so we should compare
                    match current.get::<Vec<u8>>(&kv.key)? {
                        Some(bytes) => {
                            // check first byte is 1, then take u64 from next 8 bytes
                            let current_version =
                                u64::from_be_bytes(bytes[1..9].try_into().unwrap());
                            // if the current version is less than the version from vss, then we want to use the vss version
                            if current_version < kv.version as u64 {
                                return Ok(Some((kv.key, obj.value)));
                            }
                        }
                        None => return Ok(Some((kv.key, obj.value))),
                    }
                } else if key.starts_with(CHANNEL_MANAGER_KEY) {
                    let obj = vss.get_object(&kv.key).await?;
                    // we can get versions from channel manager, so we should compare
                    match current.get_data::<VersionedValue>(&kv.key)? {
                        Some(versioned) => {
                            if versioned.version <= kv.version
                                && serde_json::from_value::<VersionedValue>(obj.value.clone())
                                    .is_ok()
                            {
                                return Ok(Some((kv.key, obj.value)));
                            }
                        }
                        None => {
                            if serde_json::from_value::<VersionedValue>(obj.value.clone()).is_ok() {
                                return Ok(Some((kv.key, obj.value)));
                            }
                        }
                    }
                }
            }
        }

        log_debug!(
            logger,
            "Skipping vss key {} with version {}",
            kv.key,
            kv.version
        );

        Ok(None)
    }

    async fn build_indexed_db_database() -> Result<Rexie, MutinyError> {
        let rexie = Rexie::builder(WALLET_DATABASE_NAME)
            .version(1)
            .add_object_store(ObjectStore::new(WALLET_OBJECT_STORE_NAME))
            .build()
            .await
            .map_err(|e| {
                MutinyError::read_err(anyhow!("Failed to create indexed db database {e}").into())
            })?;

        Ok(rexie)
    }

    #[cfg(test)]
    pub(crate) async fn reload_from_indexed_db(&self) -> Result<(), MutinyError> {
        let map = Self::read_all(
            &self.indexed_db,
            self.password.clone(),
            self.vss.as_deref(),
            &self.logger,
        )
        .await?;
        let mut memory = self
            .memory
            .try_write()
            .map_err(|e| MutinyError::write_err(e.into()))?;
        *memory = map;
        Ok(())
    }
}

/// Some values only are read once, so we can remove them from memory after reading them
/// to save memory.
///
/// We also need to skip writing them to the in memory storage on updates.
fn used_once(key: &str) -> bool {
    matches!(
        key,
        NETWORK_GRAPH_KEY | PROB_SCORER_KEY | GOSSIP_SYNC_TIME_KEY | KEYCHAIN_STORE_KEY
    )
}

/// To help prevent force closes we save to local storage as well as indexed db.
/// This is because indexed db is not always reliable.
///
/// We need to do this for the channel manager and channel monitors.
fn write_to_local_storage(key: &str) -> bool {
    match key {
        str if str.starts_with(CHANNEL_MANAGER_KEY) => true,
        str if str.starts_with(MONITORS_PREFIX_KEY) => true,
        _ => false,
    }
}

impl MutinyStorage for IndexedDbStorage {
    fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    fn cipher(&self) -> Option<Cipher> {
        self.cipher.to_owned()
    }

    fn vss_client(&self) -> Option<Arc<MutinyVssClient>> {
        self.vss.clone()
    }

    fn set<T>(&self, key: impl AsRef<str>, value: T) -> Result<(), MutinyError>
    where
        T: Serialize,
    {
        let key = key.as_ref().to_string();
        let data = serde_json::to_value(value).map_err(|e| MutinyError::PersistenceFailed {
            source: MutinyStorageError::SerdeError { source: e },
        })?;

        let indexed_db = self.indexed_db.clone();
        let key_clone = key.clone();
        let data_clone = data.clone();
        let logger = self.logger.clone();
        spawn_local(async move {
            if let Err(e) = Self::save_to_indexed_db(&indexed_db, &key_clone, &data_clone).await {
                log_error!(logger, "Failed to save ({key_clone}) to indexed db: {e}");
            };
        });

        // Some values we want to write to local storage as well as indexed db
        if write_to_local_storage(&key) {
            LocalStorage::set(&key, &data).map_err(|e| {
                MutinyError::write_err(MutinyStorageError::Other(anyhow!(format!(
                    "Failed to write to local storage: {e}"
                ))))
            })?;
        }

        // some values only are read once, so we don't need to write them to memory,
        // just need them in indexed db for next time
        if !used_once(key.as_ref()) {
            let mut map = self
                .memory
                .try_write()
                .map_err(|e| MutinyError::write_err(e.into()))?;
            map.insert(key, data);
        }

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
        match map.get(key.as_ref()).cloned() {
            None => Ok(None),
            Some(value) => {
                // drop the map so we aren't holding the lock while deserializing
                // we also need to drop if we are going to remove the value from memory
                drop(map);

                let data: T = serde_json::from_value(value)?;

                // some values only are read once, so we can remove them from memory
                if used_once(key.as_ref()) {
                    let mut map = self
                        .memory
                        .try_write()
                        .map_err(|e| MutinyError::write_err(e.into()))?;
                    map.remove(key.as_ref());
                }

                Ok(Some(data))
            }
        }
    }

    fn delete(&self, keys: &[impl AsRef<str>]) -> Result<(), MutinyError> {
        let keys: Vec<String> = keys.iter().map(|k| k.as_ref().to_string()).collect();

        let indexed_db = self.indexed_db.clone();
        let keys_clone = keys.clone();
        let logger = self.logger.clone();
        spawn_local(async move {
            if let Err(e) = Self::delete_from_indexed_db(&indexed_db, &keys_clone).await {
                log_error!(
                    logger,
                    "Failed to delete ({keys_clone:?}) from indexed db: {e}"
                );
            }
        });

        let mut map = self
            .memory
            .try_write()
            .map_err(|e| MutinyError::write_err(e.into()))?;

        for key in keys {
            // Some values we want to write to local storage as well as indexed db
            // we should delete them from local storage as well
            if write_to_local_storage(&key) {
                LocalStorage::delete(&key)
            }
            map.remove(&key);
        }

        Ok(())
    }

    async fn start(&mut self) -> Result<(), MutinyError> {
        let indexed_db = if self.indexed_db.try_read()?.is_none() {
            Arc::new(RwLock::new(Some(Self::build_indexed_db_database().await?)))
        } else {
            self.indexed_db.clone()
        };

        let map = Self::read_all(
            &indexed_db,
            self.password.clone(),
            self.vss.as_deref(),
            &self.logger,
        )
        .await?;
        let memory = Arc::new(RwLock::new(map));
        self.indexed_db = indexed_db;
        self.memory = memory;
        Ok(())
    }

    fn stop(&self) {
        if let Ok(mut indexed_db_lock) = self.indexed_db.try_write() {
            if let Some(indexed_db) = indexed_db_lock.take() {
                indexed_db.close();
            }
        }
    }

    fn connected(&self) -> Result<bool, MutinyError> {
        Ok(self.indexed_db.try_read()?.is_some())
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

    async fn import(json: Value) -> Result<(), MutinyError> {
        Self::clear().await?;
        let indexed_db = Self::build_indexed_db_database().await?;
        let tx = indexed_db
            .transaction(&[WALLET_OBJECT_STORE_NAME], TransactionMode::ReadWrite)
            .map_err(|e| {
                MutinyError::write_err(
                    anyhow!("Failed to create indexed db transaction: {e}").into(),
                )
            })?;
        let store = tx.store(WALLET_OBJECT_STORE_NAME).map_err(|e| {
            MutinyError::write_err(anyhow!("Failed to create indexed db store: {e}").into())
        })?;

        let map = json
            .as_object()
            .ok_or(MutinyError::write_err(MutinyStorageError::Other(anyhow!(
                "json is not an object"
            ))))?;

        for (key, value) in map {
            let key = JsValue::from(key);
            let value = JsValue::from_serde(&value)?;
            store.put(&value, Some(&key)).await.map_err(|e| {
                MutinyError::write_err(anyhow!("Failed to write to indexed db: {e}").into())
            })?;
        }

        tx.done().await.map_err(|e| {
            MutinyError::write_err(anyhow!("Failed to write to indexed db: {e}").into())
        })?;
        indexed_db.close();

        Ok(())
    }

    async fn clear() -> Result<(), MutinyError> {
        let indexed_db = Self::build_indexed_db_database().await?;
        let tx = indexed_db
            .transaction(&[WALLET_OBJECT_STORE_NAME], TransactionMode::ReadWrite)
            .map_err(|e| MutinyError::write_err(anyhow!("Failed clear indexed db: {e}").into()))?;
        let store = tx
            .store(WALLET_OBJECT_STORE_NAME)
            .map_err(|e| MutinyError::write_err(anyhow!("Failed clear indexed db: {e}").into()))?;

        store
            .clear()
            .await
            .map_err(|e| MutinyError::write_err(anyhow!("Failed clear indexed db: {e}").into()))?;

        tx.done()
            .await
            .map_err(|e| MutinyError::write_err(anyhow!("Failed clear indexed db: {e}").into()))?;

        // We use some localstorage right now for ensuring channel data
        LocalStorage::clear();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::indexed_db::IndexedDbStorage;
    use crate::utils::sleep;
    use crate::utils::test::log;
    use bip39::Mnemonic;
    use mutiny_core::storage::MutinyStorage;
    use mutiny_core::{encrypt::encryption_key_from_pass, logging::MutinyLogger};
    use serde_json::json;
    use std::str::FromStr;
    use std::sync::Arc;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn test_empty_string_as_none() {
        let test_name = "test_empty_string_as_none";
        log!("{test_name}");

        let logger = Arc::new(MutinyLogger::default());
        let storage = IndexedDbStorage::new(Some("".to_string()), None, None, logger)
            .await
            .unwrap();

        assert_eq!(storage.password, None);
    }

    #[test]
    async fn test_get_set_delete() {
        let test_name = "test_get_set_delete";
        log!("{test_name}");

        let key = "test_key";
        let value = "test_value";

        let logger = Arc::new(MutinyLogger::default());
        let password = "password".to_string();
        let cipher = encryption_key_from_pass(&password).unwrap();
        let storage = IndexedDbStorage::new(Some(password), Some(cipher), None, logger)
            .await
            .unwrap();

        let result: Option<String> = storage.get(key).unwrap();
        assert_eq!(result, None);

        storage.set(key, value).unwrap();

        let result: Option<String> = storage.get(key).unwrap();
        assert_eq!(result, Some(value.to_string()));

        // wait for the storage to be persisted
        sleep(1_000).await;
        // reload and check again
        storage.reload_from_indexed_db().await.unwrap();
        let result: Option<String> = storage.get(key).unwrap();
        assert_eq!(result, Some(value.to_string()));

        storage.delete(&[key]).unwrap();

        let result: Option<String> = storage.get(key).unwrap();
        assert_eq!(result, None);

        // wait for the storage to be persisted
        sleep(1_000).await;
        // reload and check again
        storage.reload_from_indexed_db().await.unwrap();
        let result: Option<String> = storage.get(key).unwrap();
        assert_eq!(result, None);

        // clear the storage to clean up
        IndexedDbStorage::clear().await.unwrap();
    }

    #[test]
    async fn test_import() {
        let test_name = "test_import";
        log!("{test_name}");

        let json = json!(
            {
                "test_key": "test_value",
                "test_key2": "test_value2"
            }
        );

        IndexedDbStorage::import(json).await.unwrap();

        let logger = Arc::new(MutinyLogger::default());
        let password = "password".to_string();
        let cipher = encryption_key_from_pass(&password).unwrap();
        let storage = IndexedDbStorage::new(Some(password), Some(cipher), None, logger)
            .await
            .unwrap();

        let result: Option<String> = storage.get("test_key").unwrap();
        assert_eq!(result, Some("test_value".to_string()));

        let result: Option<String> = storage.get("test_key2").unwrap();
        assert_eq!(result, Some("test_value2".to_string()));

        // clear the storage to clean up
        IndexedDbStorage::clear().await.unwrap();
    }

    #[test]
    async fn test_clear() {
        let test_name = "test_clear";
        log!("{test_name}");

        let key = "test_key";
        let value = "test_value";

        let logger = Arc::new(MutinyLogger::default());
        let password = "password".to_string();
        let cipher = encryption_key_from_pass(&password).unwrap();
        let storage = IndexedDbStorage::new(Some(password), Some(cipher), None, logger)
            .await
            .unwrap();

        storage.set(key, value).unwrap();

        IndexedDbStorage::clear().await.unwrap();

        storage.reload_from_indexed_db().await.unwrap();

        let result: Option<String> = storage.get(key).unwrap();
        assert_eq!(result, None);

        // clear the storage to clean up
        IndexedDbStorage::clear().await.unwrap();
    }

    #[test]
    async fn insert_and_get_mnemonic_no_password() {
        let test_name = "insert_and_get_mnemonic_no_password";
        log!("{test_name}");

        let seed = Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").expect("could not generate");

        let logger = Arc::new(MutinyLogger::default());
        let storage = IndexedDbStorage::new(None, None, None, logger)
            .await
            .unwrap();
        let mnemonic = storage.insert_mnemonic(seed).unwrap();

        let stored_mnemonic = storage.get_mnemonic().unwrap();
        assert_eq!(Some(mnemonic), stored_mnemonic);

        // clear the storage to clean up
        IndexedDbStorage::clear().await.unwrap();
    }

    #[test]
    async fn insert_and_get_mnemonic_with_password() {
        let test_name = "insert_and_get_mnemonic_with_password";
        log!("{test_name}");

        let seed = Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").expect("could not generate");

        let logger = Arc::new(MutinyLogger::default());
        let password = "password".to_string();
        let cipher = encryption_key_from_pass(&password).unwrap();
        let storage = IndexedDbStorage::new(Some(password), Some(cipher), None, logger)
            .await
            .unwrap();

        let mnemonic = storage.insert_mnemonic(seed).unwrap();

        let stored_mnemonic = storage.get_mnemonic().unwrap();
        assert_eq!(Some(mnemonic), stored_mnemonic);

        // clear the storage to clean up
        IndexedDbStorage::clear().await.unwrap();
    }
}
