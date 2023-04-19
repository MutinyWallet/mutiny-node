use std::collections::HashMap;
use std::str;

use gloo_storage::errors::StorageError;
use gloo_storage::{LocalStorage, Storage};
use serde::{Deserialize, Serialize};

use crate::encrypt::*;
use crate::error::MutinyStorageError;
use crate::nodemanager::NodeStorage;

const NODES_KEY: &str = "nodes";
const FEE_ESTIMATES_KEY: &str = "fee_estimates";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutinyBrowserStorage {
    pub(crate) password: String,
}

impl MutinyBrowserStorage {
    pub fn new(password: String) -> MutinyBrowserStorage {
        MutinyBrowserStorage { password }
    }

    // A wrapper for LocalStorage::set that converts the error to MutinyError
    pub(crate) fn set<T>(&self, key: impl AsRef<str>, value: T) -> Result<(), MutinyStorageError>
    where
        T: Serialize,
    {
        let data = serde_json::to_string(&value)?;
        // Only bother encrypting if a password is set
        if self.password.is_empty() {
            Ok(LocalStorage::set(key, data)?)
        } else {
            let ciphertext = encrypt(data.as_str(), self.password.as_str());
            Ok(LocalStorage::set(key, ciphertext)?)
        }
    }

    /// Get the value for the specified key
    pub(crate) fn get<T>(&self, key: impl AsRef<str>) -> Result<T, MutinyStorageError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let data: String = LocalStorage::get(key)?;
        // Only bother decrypting if a password is set
        if self.password.is_empty() {
            Ok(serde_json::from_str::<T>(data.as_str())?)
        } else {
            let decrypted_data = decrypt(data.as_str(), self.password.as_str());
            Ok(serde_json::from_str::<T>(decrypted_data.as_str())?)
        }
    }

    // FIXME: Useful to keep around until we use it
    #[allow(dead_code)]
    pub(crate) fn delete(key: impl AsRef<str>) {
        LocalStorage::delete(key);
    }

    pub(crate) fn scan<T>(&self, prefix: &str, suffix: Option<&str>) -> HashMap<String, T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let local_storage = LocalStorage::raw();
        let length = LocalStorage::length();
        let mut map = HashMap::with_capacity(length as usize);
        for index in 0..length {
            let key_opt: Option<String> = local_storage.key(index).unwrap();

            if let Some(key) = key_opt {
                if key.starts_with(prefix) && (suffix.is_none() || key.ends_with(suffix.unwrap())) {
                    let value: T = self.get(&key).unwrap();
                    map.insert(key, value);
                }
            }
        }

        map
    }

    pub(crate) fn get_nodes() -> Result<NodeStorage, MutinyStorageError> {
        let res: gloo_storage::Result<NodeStorage> = LocalStorage::get(NODES_KEY);
        match res {
            Ok(k) => Ok(k),
            Err(e) => match e {
                StorageError::KeyNotFound(_) => Ok(NodeStorage {
                    nodes: HashMap::new(),
                }),
                _ => Err(e)?,
            },
        }
    }

    pub(crate) fn insert_nodes(nodes: NodeStorage) -> Result<(), MutinyStorageError> {
        Ok(LocalStorage::set(NODES_KEY, nodes)?)
    }

    pub(crate) fn get_fee_estimates() -> Result<HashMap<String, f64>, MutinyStorageError> {
        Ok(LocalStorage::get(FEE_ESTIMATES_KEY)?)
    }

    pub(crate) fn insert_fee_estimates(
        fees: HashMap<String, f64>,
    ) -> Result<(), MutinyStorageError> {
        Ok(LocalStorage::set(FEE_ESTIMATES_KEY, fees)?)
    }
}
