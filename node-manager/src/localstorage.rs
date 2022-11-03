use std::collections::HashMap;
use std::str;
use std::str::FromStr;

use bip39::Mnemonic;

use gloo_storage::errors::StorageError;
use gloo_storage::{LocalStorage, Storage};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::encrypt::*;
use crate::error::MutinyStorageError;
use crate::nodemanager::NodeStorage;

const mnemonic_key: &str = "mnemonic";
const nodes_key: &str = "nodes";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutinyBrowserStorage {
    password: String,
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
        let ciphertext = encrypt(data.as_str(), self.password.as_str());
        Ok(LocalStorage::set(key, ciphertext)?)
    }

    /// Get the value for the specified key
    pub(crate) fn get<T>(&self, key: impl AsRef<str>) -> Result<T, MutinyStorageError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let ciphertext: String = LocalStorage::get(key)?;
        let data = decrypt(ciphertext.as_str(), self.password.as_str());
        Ok(serde_json::from_str::<T>(data.as_str())?)
    }

    // mostly a copy of self.get_all()
    pub(crate) fn scan_prefix(&self, prefix: String) -> Map<String, Value> {
        let local_storage = LocalStorage::raw();
        let length = LocalStorage::length();
        let mut map = Map::with_capacity(length as usize);
        for index in 0..length {
            let key_opt: Option<String> = local_storage.key(index).unwrap();

            if let Some(key) = key_opt {
                if key.starts_with(String::as_str(&prefix)) {
                    let value: Value = self.get(&key).unwrap();
                    map.insert(key, value);
                }
            }
        }

        map
    }

    pub(crate) fn insert_mnemonic(&self, mnemonic: Mnemonic) -> Mnemonic {
        self.set(mnemonic_key, mnemonic.to_string())
            .expect("Failed to write to storage");
        mnemonic
    }

    pub(crate) fn get_mnemonic(&self) -> anyhow::Result<Mnemonic> {
        // TODO: here's another way to write this... but the error conversions end up being a pain in the ass
        //
        // self.get(mnemonic_key)
        //     .and_then(|raw_mnemonic| {
        //         Ok(Mnemonic::from_str(raw_mnemonic)
        //             .with_context(|| format!("BIP 39 parse error"))?)
        //     })
        //     .with_context(|| format!("storage error"))

        let res: Result<String, MutinyStorageError> = self.get(mnemonic_key);
        match res {
            Ok(str) => Ok(Mnemonic::from_str(&str).expect("could not parse specified mnemonic")),
            Err(e) => Err(e)?,
        }
    }

    pub(crate) fn has_mnemonic() -> bool {
        LocalStorage::get::<String>("mnemonic").is_ok()
    }

    #[allow(dead_code)]
    pub(crate) fn delete_mnemonic() {
        LocalStorage::delete(mnemonic_key);
    }

    pub(crate) fn get_nodes() -> Result<NodeStorage, MutinyStorageError> {
        let res: gloo_storage::Result<NodeStorage> = LocalStorage::get(nodes_key);
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
        Ok(LocalStorage::set(nodes_key, nodes)?)
    }
}
