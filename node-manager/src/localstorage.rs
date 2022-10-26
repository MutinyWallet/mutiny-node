use std::collections::HashMap;
use std::str::FromStr;

use crate::nodemanager::NodeStorage;
use bdk::database::{BatchDatabase, BatchOperations, Database, SyncTime};
use bdk::{KeychainKind, LocalUtxo, TransactionDetails};
use bip39::Mnemonic;
use bitcoin::consensus::deserialize;
use bitcoin::consensus::encode::serialize;
use bitcoin::hash_types::Txid;
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::{OutPoint, Script, Transaction};
use gloo_storage::{LocalStorage, Storage};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

const mnemonic_key: &str = "mnemonic";
const nodes_key: &str = "nodes";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MutinyBrowserStorage {}

impl MutinyBrowserStorage {
    pub fn new() -> MutinyBrowserStorage {
        MutinyBrowserStorage {}
    }

    // A wrapper for LocalStorage::set that converts the error to bdk::Error
    fn set<T>(&self, key: impl AsRef<str>, value: T) -> Result<(), bdk::Error>
    where
        T: Serialize,
    {
        LocalStorage::set(key, value).map_err(|_| bdk::Error::Generic("Storage error".to_string()))
    }

    /// Get the value for the specified key
    fn get<T>(&self, key: impl AsRef<str>) -> gloo_storage::Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        LocalStorage::get::<T>(key)
    }

    // mostly a copy of self.get_all()
    fn scan_prefix(&self, prefix: String) -> Map<String, Value> {
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

    pub fn insert_mnemonic(&self, mnemonic: Mnemonic) -> Mnemonic {
        self.set(mnemonic_key, mnemonic.to_string())
            .expect("Failed to write to storage");
        mnemonic
    }

    pub fn get_mnemonic(&self) -> gloo_storage::Result<Mnemonic> {
        let res: gloo_storage::Result<String> = self.get(mnemonic_key);
        match res {
            Ok(str) => Ok(Mnemonic::from_str(&str).expect("could not parse specified mnemonic")),
            Err(e) => Err(e),
        }
    }

    pub fn has_mnemonic() -> bool {
        LocalStorage::get::<String>("mnemonic").is_ok()
    }

    #[allow(dead_code)]
    pub fn delete_mnemonic() {
        LocalStorage::delete(mnemonic_key);
    }

    pub fn get_nodes() -> gloo_storage::Result<NodeStorage> {
        let res: gloo_storage::Result<NodeStorage> = LocalStorage::get(nodes_key);
        match res {
            Ok(k) => Ok(k),
            Err(e) => match e {
                gloo_storage::errors::StorageError::KeyNotFound(_) => Ok(NodeStorage {
                    nodes: HashMap::new(),
                }),
                _ => Err(e),
            },
        }
    }

    pub fn insert_nodes(nodes: NodeStorage) -> gloo_storage::Result<()> {
        LocalStorage::set(nodes_key, nodes)
    }
}

// path -> script       p{i,e}<path> -> script
// script -> path       s<script> -> {i,e}<path>
// outpoint             u<outpoint> -> txout
// rawtx                r<txid> -> tx
// transactions         t<txid> -> tx details
// deriv indexes        c{i,e} -> u32
// descriptor checksum  d{i,e} -> vec<u8>
// last sync time       l -> { height, timestamp }

enum MapKey<'a> {
    Path((Option<KeychainKind>, Option<u32>)),
    Script(Option<&'a Script>),
    Utxo(Option<&'a OutPoint>),
    RawTx(Option<&'a Txid>),
    Transaction(Option<&'a Txid>),
    LastIndex(KeychainKind),
    SyncTime,
    DescriptorChecksum(KeychainKind),
}

// copied from bdk
impl MapKey<'_> {
    fn as_prefix(&self) -> Vec<u8> {
        match self {
            MapKey::Path((st, _)) => {
                let mut v = b"p".to_vec();
                if let Some(st) = st {
                    v.push(st.as_byte());
                }
                v
            }
            MapKey::Script(_) => b"s".to_vec(),
            MapKey::Utxo(_) => b"u".to_vec(),
            MapKey::RawTx(_) => b"r".to_vec(),
            MapKey::Transaction(_) => b"t".to_vec(),
            MapKey::LastIndex(st) => [b"c", st.as_ref()].concat(),
            MapKey::SyncTime => b"l".to_vec(),
            MapKey::DescriptorChecksum(st) => [b"d", st.as_ref()].concat(),
        }
    }

    fn serialize_content(&self) -> Vec<u8> {
        match self {
            MapKey::Path((_, Some(child))) => child.to_be_bytes().to_vec(),
            MapKey::Script(Some(s)) => serialize(*s),
            MapKey::Utxo(Some(s)) => serialize(*s),
            MapKey::RawTx(Some(s)) => serialize(*s),
            MapKey::Transaction(Some(s)) => serialize(*s),
            _ => vec![],
        }
    }

    pub fn as_map_key(&self) -> String {
        let mut v = self.as_prefix();
        v.extend_from_slice(&self.serialize_content());

        v.to_hex()
    }
}

#[derive(Serialize, Deserialize)]
struct ScriptPubKeyInfo {
    pub keychain: KeychainKind,
    pub path: u32,
}

impl BatchOperations for MutinyBrowserStorage {
    fn set_script_pubkey(
        &mut self,
        script: &Script,
        keychain: KeychainKind,
        path: u32,
    ) -> Result<(), bdk::Error> {
        let key = MapKey::Path((Some(keychain), Some(path))).as_map_key();
        self.set(key, script.clone())?;

        let key = MapKey::Script(Some(script)).as_map_key();
        let spk_info = ScriptPubKeyInfo { keychain, path };
        self.set(key, spk_info)?;

        Ok(())
    }

    fn set_utxo(&mut self, utxo: &LocalUtxo) -> Result<(), bdk::Error> {
        let key = MapKey::Utxo(Some(&utxo.outpoint)).as_map_key();
        self.set(key, utxo)?;

        Ok(())
    }
    fn set_raw_tx(&mut self, transaction: &Transaction) -> Result<(), bdk::Error> {
        let key = MapKey::RawTx(Some(&transaction.txid())).as_map_key();
        self.set(key, transaction.clone())?;

        Ok(())
    }
    fn set_tx(&mut self, transaction: &TransactionDetails) -> Result<(), bdk::Error> {
        let key = MapKey::Transaction(Some(&transaction.txid)).as_map_key();

        // insert the raw_tx if present
        if let Some(ref tx) = transaction.transaction {
            self.set_raw_tx(tx)?;
        }

        // remove the raw tx from the serialized version
        let mut transaction = transaction.clone();
        transaction.transaction = None;

        self.set(key, transaction)?;

        Ok(())
    }
    fn set_last_index(&mut self, keychain: KeychainKind, value: u32) -> Result<(), bdk::Error> {
        let key = MapKey::LastIndex(keychain).as_map_key();
        self.set(key, value)?;

        Ok(())
    }
    fn set_sync_time(&mut self, data: SyncTime) -> Result<(), bdk::Error> {
        let key = MapKey::SyncTime.as_map_key();
        self.set(key, data)?;

        Ok(())
    }

    fn del_script_pubkey_from_path(
        &mut self,
        keychain: KeychainKind,
        path: u32,
    ) -> Result<Option<Script>, bdk::Error> {
        let key = MapKey::Path((Some(keychain), Some(path))).as_map_key();
        let res: Option<Script> = self.get(&key).ok();
        LocalStorage::delete(&key);

        Ok(res)
    }
    fn del_path_from_script_pubkey(
        &mut self,
        script: &Script,
    ) -> Result<Option<(KeychainKind, u32)>, bdk::Error> {
        let key = MapKey::Script(Some(script)).as_map_key();
        let res: Option<ScriptPubKeyInfo> = self.get(&key).ok();
        LocalStorage::delete(&key);

        match res {
            None => Ok(None),
            Some(spk_info) => Ok(Some((spk_info.keychain, spk_info.path))),
        }
    }
    fn del_utxo(&mut self, outpoint: &OutPoint) -> Result<Option<LocalUtxo>, bdk::Error> {
        let key = MapKey::Utxo(Some(outpoint)).as_map_key();
        let res: Option<LocalUtxo> = self.get(&key).ok();
        LocalStorage::delete(&key);

        Ok(res)
    }
    fn del_raw_tx(&mut self, txid: &Txid) -> Result<Option<Transaction>, bdk::Error> {
        let key = MapKey::RawTx(Some(txid)).as_map_key();
        let res: Option<Transaction> = self.get(&key).ok();
        LocalStorage::delete(&key);

        Ok(res)
    }
    fn del_tx(
        &mut self,
        txid: &Txid,
        include_raw: bool,
    ) -> Result<Option<TransactionDetails>, bdk::Error> {
        let raw_tx = if include_raw {
            self.del_raw_tx(txid)?
        } else {
            None
        };

        let key = MapKey::Transaction(Some(txid)).as_map_key();
        let res: Option<TransactionDetails> = self.get(&key).ok();
        LocalStorage::delete(&key);

        match res {
            None => Ok(None),
            Some(mut val) => {
                val.transaction = raw_tx;

                Ok(Some(val))
            }
        }
    }
    fn del_last_index(&mut self, keychain: KeychainKind) -> Result<Option<u32>, bdk::Error> {
        let key = MapKey::LastIndex(keychain).as_map_key();
        let res: Option<u32> = self.get(&key).ok();
        LocalStorage::delete(&key);

        Ok(res)
    }
    fn del_sync_time(&mut self) -> Result<Option<SyncTime>, bdk::Error> {
        let key = MapKey::SyncTime.as_map_key();
        let res: Option<SyncTime> = self.get(&key).ok();
        LocalStorage::delete(&key);

        Ok(res)
    }
}

impl Database for MutinyBrowserStorage {
    fn check_descriptor_checksum<B: AsRef<[u8]>>(
        &mut self,
        keychain: KeychainKind,
        bytes: B,
    ) -> Result<(), bdk::Error> {
        let key = MapKey::DescriptorChecksum(keychain).as_map_key();

        let prev = self.get::<Vec<u8>>(&key).ok();
        if let Some(val) = prev {
            if val == bytes.as_ref().to_vec() {
                Ok(())
            } else {
                Err(bdk::Error::ChecksumMismatch)
            }
        } else {
            self.set(key, bytes.as_ref().to_vec())?;
            Ok(())
        }
    }

    fn iter_script_pubkeys(
        &self,
        keychain: Option<KeychainKind>,
    ) -> Result<Vec<Script>, bdk::Error> {
        let key = MapKey::Path((keychain, None)).as_map_key();
        self.scan_prefix(key)
            .into_iter()
            .map(|(_, value)| -> Result<_, bdk::Error> {
                let str_opt = value.as_str();

                match str_opt {
                    Some(str) => Script::from_hex(str)
                        .map_err(|_| bdk::Error::Generic(String::from("Error decoding json"))),
                    None => Err(bdk::Error::Generic(String::from("Error decoding json"))),
                }
            })
            .collect()
    }

    fn iter_utxos(&self) -> Result<Vec<LocalUtxo>, bdk::Error> {
        let key = MapKey::Utxo(None).as_map_key();
        self.scan_prefix(key)
            .into_iter()
            .map(|(_, value)| -> Result<_, bdk::Error> {
                let utxo: LocalUtxo = Deserialize::deserialize(value)?;
                Ok(utxo)
            })
            .collect()
    }

    fn iter_raw_txs(&self) -> Result<Vec<Transaction>, bdk::Error> {
        let key = MapKey::RawTx(None).as_map_key();
        self.scan_prefix(key)
            .into_iter()
            .map(|(_, value)| -> Result<_, bdk::Error> {
                let tx: Transaction = Deserialize::deserialize(value)?;
                Ok(tx)
            })
            .collect()
    }

    fn iter_txs(&self, include_raw: bool) -> Result<Vec<TransactionDetails>, bdk::Error> {
        let key = MapKey::Transaction(None).as_map_key();
        self.scan_prefix(key)
            .into_iter()
            .map(|(key, value)| -> Result<_, bdk::Error> {
                let mut tx_details: TransactionDetails = Deserialize::deserialize(value)?;
                if include_raw {
                    // first byte is prefix for the map, need to drop it
                    let rm_prefix_opt = key.get(2..key.len());
                    match rm_prefix_opt {
                        Some(rm_prefix) => {
                            let k_bytes = Vec::from_hex(rm_prefix)?;
                            let txid = deserialize(k_bytes.as_slice())?;
                            tx_details.transaction = self.get_raw_tx(&txid)?;
                            Ok(tx_details)
                        }
                        None => Err(bdk::Error::Generic(String::from(
                            "Error parsing txid from json",
                        ))),
                    }
                } else {
                    Ok(tx_details)
                }
            })
            .collect()
    }

    fn get_script_pubkey_from_path(
        &self,
        keychain: KeychainKind,
        path: u32,
    ) -> Result<Option<Script>, bdk::Error> {
        let key = MapKey::Path((Some(keychain), Some(path))).as_map_key();
        Ok(self.get::<Script>(&key).ok())
    }

    fn get_path_from_script_pubkey(
        &self,
        script: &Script,
    ) -> Result<Option<(KeychainKind, u32)>, bdk::Error> {
        let key = MapKey::Script(Some(script)).as_map_key();
        Ok(self
            .get::<ScriptPubKeyInfo>(&key)
            .ok()
            .map(|info| (info.keychain, info.path)))
    }

    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<LocalUtxo>, bdk::Error> {
        let key = MapKey::Utxo(Some(outpoint)).as_map_key();
        let res: Option<LocalUtxo> = self.get(key).ok();

        Ok(res)
    }

    fn get_raw_tx(&self, txid: &Txid) -> Result<Option<Transaction>, bdk::Error> {
        let key = MapKey::RawTx(Some(txid)).as_map_key();
        Ok(self.get::<Transaction>(&key).ok())
    }

    fn get_tx(
        &self,
        txid: &Txid,
        include_raw: bool,
    ) -> Result<Option<TransactionDetails>, bdk::Error> {
        let key = MapKey::Transaction(Some(txid)).as_map_key();
        Ok(self
            .get::<TransactionDetails>(&key)
            .ok()
            .map(|mut txdetails| {
                if include_raw {
                    txdetails.transaction = self.get_raw_tx(txid).unwrap();
                }

                txdetails
            }))
    }

    fn get_last_index(&self, keychain: KeychainKind) -> Result<Option<u32>, bdk::Error> {
        let key = MapKey::LastIndex(keychain).as_map_key();
        Ok(self.get::<u32>(key).ok())
    }

    fn get_sync_time(&self) -> Result<Option<SyncTime>, bdk::Error> {
        let key = MapKey::SyncTime.as_map_key();
        Ok(self.get::<SyncTime>(key).ok())
    }

    // inserts 0 if not present
    fn increment_last_index(&mut self, keychain: KeychainKind) -> Result<u32, bdk::Error> {
        let key = MapKey::LastIndex(keychain).as_map_key();
        let current_opt = self.get::<u32>(&key).ok();
        let value = current_opt.map(|s| s + 1).unwrap_or_else(|| 0);
        self.set(key, value)?;

        Ok(value)
    }
}

impl BatchDatabase for MutinyBrowserStorage {
    type Batch = Self;

    fn begin_batch(&self) -> Self::Batch {
        MutinyBrowserStorage::new()
    }

    fn commit_batch(&mut self, mut _batch: Self::Batch) -> Result<(), bdk::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bdk::database::{BatchDatabase, Database, SyncTime};
    use bdk::{BlockTime, KeychainKind, LocalUtxo, TransactionDetails};
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::hex::*;
    use bitcoin::*;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    use crate::localstorage::MutinyBrowserStorage;
    use crate::test::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    // todo this is copied from bdk::database::test, can we pull it from dependency?

    pub fn test_script_pubkey<D: Database>(mut db: D) {
        let script =
            Script::from_hex("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac").unwrap();
        let path = 42;
        let keychain = KeychainKind::External;

        db.set_script_pubkey(&script, keychain, path).unwrap();

        assert_eq!(
            db.get_script_pubkey_from_path(keychain, path).unwrap(),
            Some(script.clone())
        );
        assert_eq!(
            db.get_path_from_script_pubkey(&script).unwrap(),
            Some((keychain, path))
        );
    }

    #[allow(dead_code)]
    pub fn test_batch_script_pubkey<D: BatchDatabase>(mut db: D) {
        let mut batch = db.begin_batch();

        let script =
            Script::from_hex("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac").unwrap();
        let path = 42;
        let keychain = KeychainKind::External;

        batch.set_script_pubkey(&script, keychain, path).unwrap();

        assert_eq!(
            db.get_script_pubkey_from_path(keychain, path).unwrap(),
            None
        );
        assert_eq!(db.get_path_from_script_pubkey(&script).unwrap(), None);

        db.commit_batch(batch).unwrap();

        assert_eq!(
            db.get_script_pubkey_from_path(keychain, path).unwrap(),
            Some(script.clone())
        );
        assert_eq!(
            db.get_path_from_script_pubkey(&script).unwrap(),
            Some((keychain, path))
        );
    }

    pub fn test_iter_script_pubkey<D: Database>(mut db: D) {
        let script =
            Script::from_hex("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac").unwrap();
        let path = 42;
        let keychain = KeychainKind::External;

        db.set_script_pubkey(&script, keychain, path).unwrap();

        assert_eq!(db.iter_script_pubkeys(None).unwrap().len(), 1);
    }

    pub fn test_del_script_pubkey<D: Database>(mut db: D) {
        let script =
            Script::from_hex("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac").unwrap();
        let path = 42;
        let keychain = KeychainKind::External;

        db.set_script_pubkey(&script, keychain, path).unwrap();
        assert_eq!(db.iter_script_pubkeys(None).unwrap().len(), 1);

        db.del_script_pubkey_from_path(keychain, path).unwrap();
        assert_eq!(db.iter_script_pubkeys(None).unwrap().len(), 0);
    }

    pub fn test_utxo<D: Database>(mut db: D) {
        let outpoint = OutPoint::from_str(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:0",
        )
        .unwrap();
        let script =
            Script::from_hex("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac").unwrap();
        let txout = TxOut {
            value: 133742,
            script_pubkey: script,
        };
        let utxo = LocalUtxo {
            txout,
            outpoint,
            keychain: KeychainKind::External,
            is_spent: true,
        };

        db.set_utxo(&utxo).unwrap();
        db.set_utxo(&utxo).unwrap();
        assert_eq!(db.iter_utxos().unwrap().len(), 1);
        assert_eq!(db.get_utxo(&outpoint).unwrap(), Some(utxo));
    }

    pub fn test_raw_tx<D: Database>(mut db: D) {
        let hex_tx = Vec::<u8>::from_hex("02000000000101f58c18a90d7a76b30c7e47d4e817adfdd79a6a589a615ef36e360f913adce2cd0000000000feffffff0210270000000000001600145c9a1816d38db5cbdd4b067b689dc19eb7d930e2cf70aa2b080000001600140f48b63160043047f4f60f7f8f551f80458f693f024730440220413f42b7bc979945489a38f5221e5527d4b8e3aa63eae2099e01945896ad6c10022024ceec492d685c31d8adb64e935a06933877c5ae0e21f32efe029850914c5bad012102361caae96f0e9f3a453d354bb37a5c3244422fb22819bf0166c0647a38de39f21fca2300").unwrap();
        let mut tx: Transaction = deserialize(&hex_tx).unwrap();

        db.set_raw_tx(&tx).unwrap();

        let txid = tx.txid();

        assert_eq!(db.get_raw_tx(&txid).unwrap(), Some(tx.clone()));

        // mutate transaction's witnesses
        for tx_in in tx.input.iter_mut() {
            tx_in.witness = Witness::new();
        }

        let updated_hex_tx = serialize(&tx);

        // verify that mutation was successful
        assert_ne!(hex_tx, updated_hex_tx);

        db.set_raw_tx(&tx).unwrap();

        let txid = tx.txid();

        assert_eq!(db.get_raw_tx(&txid).unwrap(), Some(tx));
    }

    pub fn test_tx<D: Database>(mut db: D) {
        let hex_tx = Vec::<u8>::from_hex("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000").unwrap();
        let tx: Transaction = deserialize(&hex_tx).unwrap();
        let txid = tx.txid();
        let mut tx_details = TransactionDetails {
            transaction: Some(tx),
            txid,
            received: 1337,
            sent: 420420,
            fee: Some(140),
            confirmation_time: Some(BlockTime {
                timestamp: 123456,
                height: 1000,
            }),
        };

        db.set_tx(&tx_details).unwrap();

        // get with raw tx too
        assert_eq!(
            db.get_tx(&tx_details.txid, true).unwrap(),
            Some(tx_details.clone())
        );
        // get only raw_tx
        assert_eq!(
            db.get_raw_tx(&tx_details.txid).unwrap(),
            tx_details.transaction
        );

        // now get without raw_tx
        tx_details.transaction = None;
        assert_eq!(
            db.get_tx(&tx_details.txid, false).unwrap(),
            Some(tx_details)
        );
    }

    pub fn test_list_transaction<D: Database>(mut db: D) {
        let hex_tx = Vec::<u8>::from_hex("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000").unwrap();
        let tx: Transaction = deserialize(&hex_tx).unwrap();
        let txid = tx.txid();
        let mut tx_details = TransactionDetails {
            transaction: Some(tx),
            txid,
            received: 1337,
            sent: 420420,
            fee: Some(140),
            confirmation_time: Some(BlockTime {
                timestamp: 123456,
                height: 1000,
            }),
        };

        db.set_tx(&tx_details).unwrap();

        // get raw tx
        assert_eq!(db.iter_txs(true).unwrap(), vec![tx_details.clone()]);

        // now get without raw tx
        tx_details.transaction = None;

        // get not raw tx
        assert_eq!(db.iter_txs(false).unwrap(), vec![tx_details.clone()]);
    }

    pub fn test_last_index<D: Database>(mut db: D) {
        db.set_last_index(KeychainKind::External, 1337).unwrap();

        assert_eq!(
            db.get_last_index(KeychainKind::External).unwrap(),
            Some(1337)
        );
        assert_eq!(db.get_last_index(KeychainKind::Internal).unwrap(), None);

        let res = db.increment_last_index(KeychainKind::External).unwrap();
        assert_eq!(res, 1338);
        let res = db.increment_last_index(KeychainKind::Internal).unwrap();
        assert_eq!(res, 0);

        assert_eq!(
            db.get_last_index(KeychainKind::External).unwrap(),
            Some(1338)
        );
        assert_eq!(db.get_last_index(KeychainKind::Internal).unwrap(), Some(0));
    }

    pub fn test_sync_time<D: Database>(mut db: D) {
        assert!(db.get_sync_time().unwrap().is_none());

        db.set_sync_time(SyncTime {
            block_time: BlockTime {
                height: 100,
                timestamp: 1000,
            },
        })
        .unwrap();

        let extracted = db.get_sync_time().unwrap();
        assert!(extracted.is_some());
        assert_eq!(extracted.as_ref().unwrap().block_time.height, 100);
        assert_eq!(extracted.as_ref().unwrap().block_time.timestamp, 1000);

        db.del_sync_time().unwrap();
        assert!(db.get_sync_time().unwrap().is_none());
    }

    pub fn test_iter_raw_txs<D: Database>(mut db: D) {
        let txs = db.iter_raw_txs().unwrap();
        assert!(txs.is_empty());

        let hex_tx = Vec::<u8>::from_hex("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000").unwrap();
        let first_tx: Transaction = deserialize(&hex_tx).unwrap();

        let hex_tx = Vec::<u8>::from_hex("02000000000101f58c18a90d7a76b30c7e47d4e817adfdd79a6a589a615ef36e360f913adce2cd0000000000feffffff0210270000000000001600145c9a1816d38db5cbdd4b067b689dc19eb7d930e2cf70aa2b080000001600140f48b63160043047f4f60f7f8f551f80458f693f024730440220413f42b7bc979945489a38f5221e5527d4b8e3aa63eae2099e01945896ad6c10022024ceec492d685c31d8adb64e935a06933877c5ae0e21f32efe029850914c5bad012102361caae96f0e9f3a453d354bb37a5c3244422fb22819bf0166c0647a38de39f21fca2300").unwrap();
        let second_tx: Transaction = deserialize(&hex_tx).unwrap();

        db.set_raw_tx(&first_tx).unwrap();
        db.set_raw_tx(&second_tx).unwrap();

        let txs = db.iter_raw_txs().unwrap();

        assert!(txs.contains(&first_tx));
        assert!(txs.contains(&second_tx));
        assert_eq!(txs.len(), 2);
    }

    pub fn test_del_path_from_script_pubkey<D: Database>(mut db: D) {
        let keychain = KeychainKind::External;

        let script =
            Script::from_hex("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac").unwrap();
        let path = 42;

        let res = db.del_path_from_script_pubkey(&script).unwrap();

        assert!(res.is_none());

        let _res = db.set_script_pubkey(&script, keychain, path);
        let (chain, child) = db.del_path_from_script_pubkey(&script).unwrap().unwrap();

        assert_eq!(chain, keychain);
        assert_eq!(child, path);

        let res = db.get_path_from_script_pubkey(&script).unwrap();
        assert!(res.is_none());
    }

    pub fn test_iter_script_pubkeys<D: Database>(mut db: D) {
        let keychain = KeychainKind::External;
        let scripts = db.iter_script_pubkeys(Some(keychain)).unwrap();
        assert!(scripts.is_empty());

        let first_script =
            Script::from_hex("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac").unwrap();
        let path = 42;

        db.set_script_pubkey(&first_script, keychain, path).unwrap();

        let second_script =
            Script::from_hex("00145c9a1816d38db5cbdd4b067b689dc19eb7d930e2").unwrap();
        let path = 57;

        db.set_script_pubkey(&second_script, keychain, path)
            .unwrap();
        let scripts = db.iter_script_pubkeys(Some(keychain)).unwrap();

        assert!(scripts.contains(&first_script));
        assert!(scripts.contains(&second_script));
        assert_eq!(scripts.len(), 2);
    }

    pub fn test_del_utxo<D: Database>(mut db: D) {
        let outpoint = OutPoint::from_str(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:0",
        )
        .unwrap();
        let script =
            Script::from_hex("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac").unwrap();
        let txout = TxOut {
            value: 133742,
            script_pubkey: script,
        };
        let utxo = LocalUtxo {
            txout,
            outpoint,
            keychain: KeychainKind::External,
            is_spent: true,
        };

        let res = db.del_utxo(&outpoint).unwrap();
        assert!(res.is_none());

        db.set_utxo(&utxo).unwrap();

        let res = db.del_utxo(&outpoint).unwrap();

        assert_eq!(res.unwrap(), utxo);

        let res = db.get_utxo(&outpoint).unwrap();
        assert!(res.is_none());
    }

    pub fn test_del_raw_tx<D: Database>(mut db: D) {
        let hex_tx = Vec::<u8>::from_hex("02000000000101f58c18a90d7a76b30c7e47d4e817adfdd79a6a589a615ef36e360f913adce2cd0000000000feffffff0210270000000000001600145c9a1816d38db5cbdd4b067b689dc19eb7d930e2cf70aa2b080000001600140f48b63160043047f4f60f7f8f551f80458f693f024730440220413f42b7bc979945489a38f5221e5527d4b8e3aa63eae2099e01945896ad6c10022024ceec492d685c31d8adb64e935a06933877c5ae0e21f32efe029850914c5bad012102361caae96f0e9f3a453d354bb37a5c3244422fb22819bf0166c0647a38de39f21fca2300").unwrap();
        let tx: Transaction = deserialize(&hex_tx).unwrap();

        let res = db.del_raw_tx(&tx.txid()).unwrap();

        assert!(res.is_none());

        db.set_raw_tx(&tx).unwrap();

        let res = db.del_raw_tx(&tx.txid()).unwrap();

        assert_eq!(res.unwrap(), tx);

        let res = db.get_raw_tx(&tx.txid()).unwrap();
        assert!(res.is_none());
    }

    pub fn test_del_tx<D: Database>(mut db: D) {
        let hex_tx = Vec::<u8>::from_hex("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000").unwrap();
        let tx: Transaction = deserialize(&hex_tx).unwrap();
        let txid = tx.txid();
        let mut tx_details = TransactionDetails {
            transaction: Some(tx.clone()),
            txid,
            received: 1337,
            sent: 420420,
            fee: Some(140),
            confirmation_time: Some(BlockTime {
                timestamp: 123456,
                height: 1000,
            }),
        };

        let res = db.del_tx(&tx.txid(), true).unwrap();

        assert!(res.is_none());

        db.set_tx(&tx_details).unwrap();

        let res = db.del_tx(&tx.txid(), false).unwrap();
        tx_details.transaction = None;
        assert_eq!(res.unwrap(), tx_details);

        let res = db.get_tx(&tx.txid(), true).unwrap();
        assert!(res.is_none());

        let res = db.get_raw_tx(&tx.txid()).unwrap();
        assert_eq!(res.unwrap(), tx);

        db.set_tx(&tx_details).unwrap();
        let res = db.del_tx(&tx.txid(), true).unwrap();
        tx_details.transaction = Some(tx.clone());
        assert_eq!(res.unwrap(), tx_details);

        let res = db.get_tx(&tx.txid(), true).unwrap();
        assert!(res.is_none());

        let res = db.get_raw_tx(&tx.txid()).unwrap();
        assert!(res.is_none());
    }

    pub fn test_del_last_index<D: Database>(mut db: D) {
        let keychain = KeychainKind::External;

        let _res = db.increment_last_index(keychain);

        let res = db.get_last_index(keychain).unwrap().unwrap();

        assert_eq!(res, 0);

        let _res = db.increment_last_index(keychain);

        let res = db.del_last_index(keychain).unwrap().unwrap();

        assert_eq!(res, 1);

        let res = db.get_last_index(keychain).unwrap();
        assert!(res.is_none());
    }

    pub fn test_check_descriptor_checksum<D: Database>(mut db: D) {
        // insert checksum associated to keychain
        let checksum = "1cead456".as_bytes();
        let keychain = KeychainKind::External;
        let _res = db.check_descriptor_checksum(keychain, checksum);

        // check if `check_descriptor_checksum` throws
        // `Error::ChecksumMismatch` error if the
        // function is passed a checksum that does
        // not match the one initially inserted
        let checksum = "1cead454".as_bytes();
        let keychain = KeychainKind::External;
        let res = db.check_descriptor_checksum(keychain, checksum);

        assert!(res.is_err());
    }

    fn get_tree() -> MutinyBrowserStorage {
        cleanup_test();
        MutinyBrowserStorage::default()
    }

    #[test]
    fn script_pubkey_test() {
        test_script_pubkey(get_tree());
    }

    // fixme, we don't actually batch, is that okay?
    // #[test]
    // fn script_pubkey_test_batch() {
    //     test_batch_script_pubkey(get_tree());
    // }

    #[test]
    fn script_pubkey_test_iter() {
        test_iter_script_pubkey(get_tree());
    }

    #[test]
    fn script_pubkey_test_del() {
        test_del_script_pubkey(get_tree());
    }

    #[test]
    fn utxo_test() {
        test_utxo(get_tree());
    }

    #[test]
    fn raw_tx_test() {
        test_raw_tx(get_tree());
    }

    #[test]
    fn tx_test() {
        test_tx(get_tree());
    }

    #[test]
    fn last_index_test() {
        test_last_index(get_tree());
    }

    #[test]
    fn sync_time_test() {
        test_sync_time(get_tree());
    }

    #[test]
    fn iter_raw_txs_test() {
        test_iter_raw_txs(get_tree());
    }

    #[test]
    fn list_txs_test() {
        test_list_transaction(get_tree());
    }

    #[test]
    fn del_path_from_script_pubkey_test() {
        test_del_path_from_script_pubkey(get_tree());
    }

    #[test]
    fn iter_script_pubkeys_test() {
        test_iter_script_pubkeys(get_tree());
    }

    #[test]
    fn del_utxo_test() {
        test_del_utxo(get_tree());
    }

    #[test]
    fn del_raw_tx_test() {
        test_del_raw_tx(get_tree());
    }

    #[test]
    fn del_tx_test() {
        test_del_tx(get_tree());
    }

    #[test]
    fn del_last_index_test() {
        test_del_last_index(get_tree());
    }

    #[test]
    fn check_descriptor_checksum_test() {
        test_check_descriptor_checksum(get_tree());
    }
}
