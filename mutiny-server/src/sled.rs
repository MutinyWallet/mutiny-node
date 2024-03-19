use anyhow::anyhow;
use async_trait::async_trait;
use bitcoin::hashes::serde::{Deserialize, Serialize};
use futures_util::lock::Mutex;
use mutiny_core::encrypt::{encryption_key_from_pass, Cipher};
use mutiny_core::error::MutinyError;
use mutiny_core::storage::{DelayedKeyValueItem, DeviceLock, MutinyStorage};
use mutiny_core::vss::MutinyVssClient;
use sled::IVec;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct SledStorage {
    pub(crate) password: Option<String>,
    pub cipher: Option<Cipher>,
    db: sled::Db,
}

impl SledStorage {
    pub fn new(db_file: &str, password: Option<String>) -> anyhow::Result<Self> {
        let db = {
            match sled::open(db_file) {
                Ok(db) => db,
                Err(_) => {
                    std::fs::create_dir_all(db_file)?;
                    sled::open(db_file)?
                }
            }
        };

        let cipher = password
            .as_ref()
            .filter(|p| !p.is_empty())
            .map(|p| encryption_key_from_pass(p))
            .transpose()?;

        Ok(Self {
            password,
            cipher,
            db,
        })
    }
}

fn ivec_to_string(vec: IVec) -> Result<String, MutinyError> {
    String::from_utf8(vec.to_vec())
        .map_err(|e| MutinyError::Other(anyhow!("Failed to decode value to string: {e}")))
}

#[async_trait]
impl MutinyStorage for SledStorage {
    fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    fn cipher(&self) -> Option<Cipher> {
        self.cipher.clone()
    }

    fn vss_client(&self) -> Option<Arc<MutinyVssClient>> {
        None
    }

    fn set(&self, items: Vec<(String, impl Serialize)>) -> Result<(), MutinyError> {
        let items = items
            .into_iter()
            .map(|(k, v)| {
                serde_json::to_string(&v)
                    .map_err(|e| {
                        MutinyError::Other(anyhow!("Error serializing value: {e} for key: {k}"))
                    })
                    .map(|d| (k, d))
            })
            .collect::<Result<Vec<(String, String)>, MutinyError>>()?;

        for (k, v) in items {
            self.db
                .insert(&k, v.as_bytes())
                .map_err(|e| MutinyError::Other(anyhow!("Error inserting key: {e} into sled: {k}")))?;
        }

        Ok(())
    }

    fn get<T>(&self, key: impl AsRef<str>) -> Result<Option<T>, MutinyError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let key = key.as_ref();

        if let Some(value) = self.db.get(key).map_err(|e| {
            MutinyError::Other(anyhow!("Failed to read value ({key}) from sled db: {e}"))
        })? {
            // convert from bytes to deserialized value
            let str = ivec_to_string(value)?;
            let json: T = serde_json::from_str(&str)?;

            return Ok(Some(json));
        }

        Ok(None)
    }

    fn delete(&self, keys: &[impl AsRef<str>]) -> Result<(), MutinyError> {
        // start batch operation
        let mut batch = sled::Batch::default();
        for key in keys {
            let key = key.as_ref();
            batch.remove(key);
        }
        // apply batch to delete all keys
        self.db
            .apply_batch(batch)
            .map_err(|e| MutinyError::Other(anyhow!("Error removing keys: from sled: {e}")))?;

        Ok(())
    }

    async fn start(&mut self) -> Result<(), MutinyError> {
        Ok(())
    }

    // TODO
    fn stop(&self) {}

    // TODO
    fn connected(&self) -> Result<bool, MutinyError> {
        Ok(true)
    }

    fn scan_keys(&self, prefix: &str, suffix: Option<&str>) -> Result<Vec<String>, MutinyError> {
        let prefix = prefix.as_bytes();
        let suffix = suffix.map(|s| s.as_bytes());

        let mut keys: Vec<String> = vec![];
        while let Some(Ok(k)) = self.db.iter().keys().next() {
            if k.starts_with(prefix) && suffix.map_or(true, |s| k.ends_with(s)) {
                keys.push(ivec_to_string(k)?);
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

    fn get_delayed_objects(&self) -> Arc<Mutex<HashMap<String, DelayedKeyValueItem>>> {
        Arc::new(Mutex::new(HashMap::new()))
    }
}
