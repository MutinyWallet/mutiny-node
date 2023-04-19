use crate::encrypt::{decrypt, encrypt};
use crate::error::{MutinyError, MutinyStorageError};
use crate::ldkstorage::CHANNEL_MANAGER_KEY;
use anyhow::anyhow;
use bip39::Mnemonic;
use rexie::{ObjectStore, Rexie, TransactionMode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::spawn_local;

pub(crate) const WALLET_DATABASE_NAME: &str = "wallet";
pub(crate) const WALLET_OBJECT_STORE_NAME: &str = "wallet_store";

const MNEMONIC_KEY: &str = "mnemonic";

#[derive(Clone)]
pub struct MutinyStorage {
    pub(crate) password: Option<String>,
    /// In-memory cache of the wallet data
    /// This is used to avoid having to read from IndexedDB on every get.
    /// This is a RwLock because we want to be able to read from it without blocking
    memory: Arc<RwLock<HashMap<String, serde_json::Value>>>,
    indexed_db: Arc<Rexie>,
}

impl MutinyStorage {
    pub async fn new(password: String) -> Result<MutinyStorage, MutinyError> {
        let indexed_db = Arc::new(Self::build_indexed_db_database().await?);

        // If the password is empty, set to None
        let password = Some(password).filter(|pw| !pw.is_empty());

        let map = Self::read_all(&indexed_db, &password).await?;
        let memory = Arc::new(RwLock::new(map));

        Ok(MutinyStorage {
            password,
            memory,
            indexed_db,
        })
    }

    pub(crate) fn set<T>(&self, key: impl AsRef<str>, value: T) -> Result<(), MutinyError>
    where
        T: Serialize,
    {
        let data = serde_json::to_value(value)?;
        let mut map = self
            .memory
            .write()
            .map_err(|e| MutinyError::write_err(e.into()))?;
        map.insert(key.as_ref().to_string(), data.clone());

        let indexed_db = self.indexed_db.clone();
        let password = self.password.clone();
        let key = key.as_ref().to_string();
        spawn_local(async move {
            Self::save_to_indexed_db(indexed_db, &password, &key, &data)
                .await
                .expect(&format!("Failed to save to indexed db: {key}"))
        });

        Ok(())
    }

    async fn save_to_indexed_db(
        indexed_db: Arc<Rexie>,
        password: &Option<String>,
        key: &str,
        data: &serde_json::Value,
    ) -> Result<(), MutinyError> {
        let tx = indexed_db
            .as_ref()
            .transaction(&[WALLET_OBJECT_STORE_NAME], TransactionMode::ReadWrite)?;

        let store = tx.store(WALLET_OBJECT_STORE_NAME)?;

        // Only bother encrypting if a password is set
        let json = match password {
            Some(pw) if Self::needs_encryption(key) => {
                let str = serde_json::to_string(data)?;
                let ciphertext = encrypt(&str, pw);
                serde_wasm_bindgen::to_value(&ciphertext)?
            }
            _ => serde_wasm_bindgen::to_value(data)?,
        };

        // save to indexed db
        store.put(&json, Some(&JsValue::from(key))).await?;

        tx.done().await?;

        Ok(())
    }

    pub(crate) fn get<T>(&self, key: impl AsRef<str>) -> Result<Option<T>, MutinyError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let map = self
            .memory
            .read()
            .map_err(|e| MutinyError::read_err(e.into()))?;
        match map.get(key.as_ref()) {
            None => Ok(None),
            Some(value) => {
                let data: T = serde_json::from_value(value.clone())?;
                Ok(Some(data))
            }
        }
    }

    pub(crate) fn scan<T>(
        &self,
        prefix: &str,
        suffix: Option<&str>,
    ) -> Result<HashMap<String, T>, MutinyError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let map = self
            .memory
            .read()
            .map_err(|e| MutinyError::read_err(e.into()))?;

        Ok(map
            .keys()
            .filter(|key| {
                key.starts_with(prefix) && (suffix.is_none() || key.ends_with(suffix.unwrap()))
            })
            .filter_map(|key| {
                self.get(key)
                    .ok()
                    .flatten()
                    .map(|value: T| (key.to_owned(), value))
            })
            .collect())
    }

    pub(crate) async fn insert_mnemonic(
        &self,
        mnemonic: Mnemonic,
    ) -> Result<Mnemonic, MutinyError> {
        // Instead of calling self.set we manually write to indexed db
        // so we get a guarantee that the mnemonic is saved before we return

        let data = serde_json::to_value(mnemonic.to_string())?;
        Self::save_to_indexed_db(self.indexed_db.clone(), &self.password, MNEMONIC_KEY, &data)
            .await?;
        Ok(mnemonic)
    }

    pub(crate) async fn get_mnemonic(&self) -> Result<Mnemonic, MutinyError> {
        let tx = self
            .indexed_db
            .transaction(&[WALLET_OBJECT_STORE_NAME], TransactionMode::ReadOnly)?;
        let store = tx.store(WALLET_OBJECT_STORE_NAME)?;

        let key = JsValue::from(MNEMONIC_KEY);
        let json = store.get(&key).await?;
        let value: Option<String> = serde_wasm_bindgen::from_value(json)?;

        let mnemonic = match value {
            Some(mnemonic) => Mnemonic::from_str(&mnemonic)?,
            None => return Err(MutinyError::InvalidMnemonic), // maybe need a better error
        };

        tx.done().await?;

        Ok(mnemonic)
    }

    pub(crate) async fn has_mnemonic() -> Result<bool, MutinyError> {
        let indexed_db = Self::build_indexed_db_database().await?;
        let tx = indexed_db.transaction(&[WALLET_OBJECT_STORE_NAME], TransactionMode::ReadOnly)?;
        let store = tx.store(WALLET_OBJECT_STORE_NAME)?;

        let key = JsValue::from(MNEMONIC_KEY);
        let json = store.get(&key).await?;
        let value: Option<String> = serde_wasm_bindgen::from_value(json)?;

        Ok(value.is_some())
    }

    async fn build_indexed_db_database() -> Result<Rexie, MutinyError> {
        let rexie = Rexie::builder(WALLET_DATABASE_NAME)
            .version(1)
            .add_object_store(ObjectStore::new(WALLET_OBJECT_STORE_NAME))
            .build()
            .await?;

        Ok(rexie)
    }

    async fn read_all(
        indexed_db: &Rexie,
        password: &Option<String>,
    ) -> Result<HashMap<String, serde_json::Value>, MutinyError> {
        let tx = indexed_db.transaction(&[WALLET_OBJECT_STORE_NAME], TransactionMode::ReadOnly)?;

        let store = tx.store(WALLET_OBJECT_STORE_NAME)?;

        let mut map = HashMap::new();
        let all_json = store.get_all(None, None, None, None).await?;
        let mut iter = all_json.into_iter();
        while let Some((key, value)) = iter.next() {
            let key = key
                .as_string()
                .ok_or(MutinyError::read_err(MutinyStorageError::Other(anyhow!(
                    "key from indexedDB is not a string"
                ))))?;
            let json: Option<serde_json::Value> = match password {
                Some(pw) if Self::needs_encryption(&key) => {
                    let str: String = serde_wasm_bindgen::from_value(value)?;
                    let ciphertext = decrypt(&str, pw);
                    serde_json::from_str(&ciphertext)?
                }
                _ => serde_wasm_bindgen::from_value(value)?,
            };

            if let Some(json) = json {
                map.insert(key, json);
            }
        }

        Ok(map)
    }

    fn needs_encryption(key: &str) -> bool {
        match key {
            MNEMONIC_KEY => true,
            str if str.starts_with(CHANNEL_MANAGER_KEY) => true,
            _ => false,
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) async fn clear() -> Result<(), MutinyError> {
        let indexed_db = Self::build_indexed_db_database().await?;
        let tx = indexed_db.transaction(&[WALLET_OBJECT_STORE_NAME], TransactionMode::ReadWrite)?;
        let store = tx.store(WALLET_OBJECT_STORE_NAME)?;

        store.clear().await?;

        tx.done().await?;

        Ok(())
    }
}
