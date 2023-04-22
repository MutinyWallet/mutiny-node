use std::collections::HashMap;
use std::str;

use gloo_storage::errors::StorageError;
use gloo_storage::{LocalStorage, Storage};

use crate::error::MutinyStorageError;
use crate::nodemanager::NodeStorage;

const NODES_KEY: &str = "nodes";
const FEE_ESTIMATES_KEY: &str = "fee_estimates";

pub struct MutinyBrowserStorage {}

// TODO move these to indexedDB
impl MutinyBrowserStorage {
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
