use anyhow::anyhow;
use async_trait::async_trait;
use futures_util::lock::Mutex;
use mutiny_core::encrypt::{encryption_key_from_pass, Cipher};
use mutiny_core::error::MutinyError;
use mutiny_core::storage::{DelayedKeyValueItem, DeviceLock, IndexItem, MutinyStorage};
use mutiny_core::vss::MutinyVssClient;
use rocksdb::{IteratorMode, WriteBatchWithTransaction, DB};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, RwLock};

#[derive(Clone)]
pub struct RocksDB {
    pub(crate) password: Option<String>,
    pub cipher: Option<Cipher>,
    db: Arc<DB>,
    delayed_keys: Arc<Mutex<HashMap<String, DelayedKeyValueItem>>>,
    activity_index: Arc<RwLock<BTreeSet<IndexItem>>>,
}

impl RocksDB {
    pub fn new(db_file: &str, password: Option<String>) -> anyhow::Result<Self> {
        let db = DB::open_default(db_file)?;

        let cipher = password
            .as_ref()
            .filter(|p| !p.is_empty())
            .map(|p| encryption_key_from_pass(p))
            .transpose()?;

        Ok(Self {
            password,
            cipher,
            db: Arc::new(db),
            delayed_keys: Arc::new(Mutex::new(HashMap::new())),
            activity_index: Arc::new(RwLock::new(BTreeSet::new())),
        })
    }
}

#[async_trait]
impl MutinyStorage for RocksDB {
    fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    fn cipher(&self) -> Option<Cipher> {
        self.cipher.clone()
    }

    fn vss_client(&self) -> Option<Arc<MutinyVssClient>> {
        None
    }

    fn activity_index(&self) -> Arc<RwLock<BTreeSet<IndexItem>>> {
        self.activity_index.clone()
    }

    fn set(&self, items: Vec<(String, impl Serialize)>) -> Result<(), MutinyError> {
        let mut batch = WriteBatchWithTransaction::<false>::default();
        for (key, value) in items {
            let json = serde_json::to_string(&value).map_err(|e| {
                MutinyError::Other(anyhow!("Error serializing value: {e} for key: {key}"))
            })?;
            batch.put(key.as_bytes(), json.as_bytes());
        }
        self.db
            .write(batch)
            .map_err(|e| MutinyError::Other(anyhow!("Error inserting keys to db: {e}")))?;

        Ok(())
    }

    fn get_delayed_objects(&self) -> Arc<Mutex<HashMap<String, DelayedKeyValueItem>>> {
        self.delayed_keys.clone()
    }

    fn get<T>(&self, key: impl AsRef<str>) -> Result<Option<T>, MutinyError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let key = key.as_ref();

        if let Some(value) = self
            .db
            .get(key)
            .map_err(|e| MutinyError::Other(anyhow!("Failed to read value ({key}) from db: {e}")))?
        {
            let json: T = serde_json::from_slice(value.as_ref())?;
            return Ok(Some(json));
        }

        Ok(None)
    }

    fn delete(&self, keys: &[impl AsRef<str>]) -> Result<(), MutinyError> {
        // start batch operation
        let mut batch = WriteBatchWithTransaction::<false>::default();
        for key in keys {
            batch.delete(key.as_ref())
        }

        // apply batch to delete all keys
        self.db
            .write(batch)
            .map_err(|e| MutinyError::Other(anyhow!("Error removing keys from db: {e}")))?;

        Ok(())
    }

    async fn start(&mut self) -> Result<(), MutinyError> {
        Ok(())
    }

    fn stop(&self) {}

    fn connected(&self) -> Result<bool, MutinyError> {
        Ok(true)
    }

    fn scan_keys(&self, prefix: &str, suffix: Option<&str>) -> Result<Vec<String>, MutinyError> {
        let iter = self.db.iterator(IteratorMode::Start);

        let mut keys: Vec<String> = vec![];
        for item in iter {
            let (key, _) =
                item.map_err(|e| MutinyError::Other(anyhow!("Error reading keys from db: {e}")))?;
            let key = String::from_utf8(key.into_vec())?;
            if key.starts_with(prefix) && (suffix.is_none() || key.ends_with(suffix.unwrap())) {
                keys.push(key);
            }
        }
        Ok(keys)
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

    async fn import(_json: serde_json::value::Value) -> Result<(), MutinyError> {
        // fixme, we should change this trait to take &self
        unimplemented!()
    }

    async fn clear() -> Result<(), MutinyError> {
        // fixme, we should change this trait to take &self
        unimplemented!()
    }

    async fn fetch_device_lock(&self) -> Result<Option<DeviceLock>, MutinyError> {
        self.get_device_lock()
    }
}
