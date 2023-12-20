use crate::HTLCStatus;
use crate::{
    error::{MutinyError, MutinyStorageError},
    logging::MutinyLogger,
    nodemanager::MutinyInvoice,
    sql::ApplicationStore,
};
use async_trait::async_trait;
use bitcoin::hashes::sha256;
use bitcoin::secp256k1::PublicKey;
use fedimint_core::db::{
    mem_impl::{MemDatabase, MemTransaction},
    IDatabaseTransactionOps, IDatabaseTransactionOpsCore, IRawDatabase, IRawDatabaseTransaction,
    PrefixStream,
};
use gluesql::prelude::{Glue, Payload, Value};
use lightning::{log_debug, log_error, log_trace, util::logger::Logger};
use lightning_invoice::Bolt11Invoice;
use std::str::FromStr;

use std::{fmt, sync::Arc};

#[cfg(not(target_arch = "wasm32"))]
use tokio::sync::Mutex;

#[cfg(target_arch = "wasm32")]
use gluesql::core::executor::ValidateError;

#[cfg(target_arch = "wasm32")]
use crate::utils;

#[cfg(target_arch = "wasm32")]
use futures::lock::Mutex;

#[cfg(target_arch = "wasm32")]
use futures::StreamExt;

#[cfg(not(target_arch = "wasm32"))]
use gluesql::prelude::MemoryStorage;

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone)]
pub struct FedimintDB {
    pub(crate) db: Arc<Mutex<Glue<MemoryStorage>>>, // TODO eventually use sled for server version
    fedimint_memory: Arc<MemDatabase>,
    federation_id: String,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone)]
pub struct GlueDB {
    pub(crate) db: Arc<Mutex<Glue<MemoryStorage>>>, // TODO eventually use sled for server version
    logger: Arc<MutinyLogger>,
}

#[cfg(target_arch = "wasm32")]
use gluesql::prelude::IdbStorage;

#[cfg(target_arch = "wasm32")]
#[derive(Clone)]
pub struct GlueDB {
    pub(crate) db: Arc<Mutex<Glue<IdbStorage>>>,
    logger: Arc<MutinyLogger>,
}

impl GlueDB {
    pub async fn new(
        #[cfg(target_arch = "wasm32")] namespace: Option<String>,
        logger: Arc<MutinyLogger>,
    ) -> Result<Self, MutinyError> {
        log_debug!(logger, "initializing glue storage");

        #[cfg(target_arch = "wasm32")]
        let storage = IdbStorage::new(namespace)
            .await
            .map_err(|_| MutinyError::ReadError {
                source: MutinyStorageError::IndexedDBError,
            })?;

        #[cfg(not(target_arch = "wasm32"))]
        let storage = MemoryStorage::default();

        let mut glue_db = Glue::new(storage);
        glue_db
            .execute(
                "CREATE TABLE IF NOT EXISTS mutiny_kv (key TEXT PRIMARY KEY, val BYTEA NOT NULL, version INTEGER NOT NULL)",
            )
            .await
            .map_err(|_| MutinyError::write_err(MutinyStorageError::IndexedDBError))?;

        glue_db
            .execute(
                "CREATE TABLE IF NOT EXISTS mutiny_invoice (
                    bolt11 TEXT,
                    description TEXT NULL,
                    payment_hash TEXT PRIMARY KEY,
                    preimage TEXT NULL,
                    payee_pubkey TEXT NULL,
                    amount_sats INTEGER NULL,
                    expire INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    fees_paid INTEGER NULL,
                    inbound BOOLEAN,
                    labels TEXT,
                    last_updated INTEGER
                )",
            )
            .await
            .map_err(|_| MutinyError::write_err(MutinyStorageError::IndexedDBError))?;

        log_debug!(logger, "done setting up GlueDB");

        Ok(Self {
            db: Arc::new(Mutex::new(glue_db)),
            logger,
        })
    }

    pub async fn new_fedimint_client_db(
        &self,
        federation_id: String,
    ) -> Result<FedimintDB, MutinyError> {
        FedimintDB::new(self.db.clone(), federation_id, self.logger.clone()).await
    }
}

impl ApplicationStore for GlueDB {
    async fn save_payment(&self, invoice: MutinyInvoice) -> Result<(), MutinyError> {
        #[cfg(not(target_arch = "wasm32"))]
        unimplemented!("can't run on servers until Send is supported in Glue");

        #[cfg(target_arch = "wasm32")]
        {
            let labels_json = serde_json::to_string(&invoice.labels).map_err(|_| {
                MutinyError::PersistenceFailed {
                    source: MutinyStorageError::IndexedDBError,
                }
            })?;
            let payment_hash = invoice.payment_hash.to_string();
            let payee_pubkey = invoice.payee_pubkey.map(|k| k.to_string());
            let bolt11 = invoice.bolt11.map(|b| b.to_string());
            let preimage = invoice.preimage.clone();
            let status = invoice.status.to_string();

            let sql = format!(
                "INSERT INTO mutiny_invoice (bolt11, description, payment_hash, preimage, payee_pubkey, amount_sats, expire, status, fees_paid, inbound, labels, last_updated)
                VALUES ({}, {}, '{}', {}, {}, {}, {}, '{}', {}, {}, '{}', {})",
                bolt11.as_ref().map(|s| format!("'{}'", s)).unwrap_or("NULL".to_string()),
                invoice.description.as_ref().map(|s| format!("'{}'", s)).unwrap_or("NULL".to_string()),
                payment_hash,
                preimage.as_ref().map(|s| format!("'{}'", s)).unwrap_or("NULL".to_string()),
                payee_pubkey.as_ref().map(|s| format!("'{}'", s)).unwrap_or("NULL".to_string()),
                invoice.amount_sats.as_ref().map(|s| format!("{}", s)).unwrap_or("NULL".to_string()),
                invoice.expire,
                status,
                invoice.fees_paid.as_ref().map(|s| format!("{}", s)).unwrap_or("NULL".to_string()),
                invoice.inbound,
                labels_json,
                invoice.last_updated,
            );

            let mut glue = self.db.lock().await;
            match glue.execute(&sql).await {
                Ok(_) => Ok(()),
                Err(gluesql_core::error::Error::Validate(
                    ValidateError::DuplicateEntryOnPrimaryKeyField(_),
                )) => {
                    // Define the UPDATE query
                    let update_sql = format!(
                        "UPDATE mutiny_invoice 
                         SET bolt11 = {}, description = {}, preimage = {}, payee_pubkey = {}, 
                             amount_sats = {}, expire = {}, status = '{}', fees_paid = {}, inbound = {}, 
                             labels = '{}', last_updated = {} 
                         WHERE payment_hash = '{}'",
                        bolt11.as_ref().map(|s| format!("'{}'", s)).unwrap_or("NULL".to_string()),
                        invoice.description.as_ref().map(|s| format!("'{}'", s)).unwrap_or("NULL".to_string()),
                        preimage.as_ref().map(|s| format!("'{}'", s)).unwrap_or("NULL".to_string()),
                        payee_pubkey.as_ref().map(|s| format!("'{}'", s)).unwrap_or("NULL".to_string()),
                        invoice.amount_sats.as_ref().map(|s| format!("{}", s)).unwrap_or("NULL".to_string()),
                        invoice.expire,
                        status,
                        invoice.fees_paid.as_ref().map(|s| format!("{}", s)).unwrap_or("NULL".to_string()),
                        invoice.inbound,
                        labels_json,
                        invoice.last_updated,
                        payment_hash,
                    );

                    glue.execute(&update_sql).await.map_err(|_| {
                        MutinyError::PersistenceFailed {
                            source: MutinyStorageError::IndexedDBError,
                        }
                    })?;
                    Ok(())
                }
                _ => Err(MutinyError::PersistenceFailed {
                    source: MutinyStorageError::IndexedDBError,
                }),
            }
        }
    }

    async fn get_payment(
        &self,
        payment_hash: &bitcoin::hashes::sha256::Hash,
    ) -> Result<Option<MutinyInvoice>, MutinyError> {
        #[cfg(not(target_arch = "wasm32"))]
        unimplemented!("can't run on servers until Send is supported in Glue");

        #[cfg(target_arch = "wasm32")]
        {
            log_trace!(self.logger, "calling get_payment");

            let payment_hash_str = payment_hash.to_string();
            let select_query = format!(
                "SELECT bolt11, description, payment_hash, preimage, payee_pubkey, amount_sats, expire, status, fees_paid, inbound, labels, last_updated FROM mutiny_invoice WHERE payment_hash = '{}'",
                payment_hash_str
            );

            log_trace!(self.logger, "locking db");
            let mut glue = self.db.lock().await;
            log_trace!(self.logger, "running query: {select_query}");
            let mut result = glue.execute(&select_query).await.map_err(|e| {
                log_error!(
                    self.logger,
                    "failed to execute query ({}): {e}",
                    select_query
                );
                MutinyError::PersistenceFailed {
                    source: MutinyStorageError::IndexedDBError,
                }
            })?;

            log_trace!(self.logger, "going through rows");
            if let Payload::Select { rows, .. } = result.pop().unwrap() {
                if let Some(row) = rows.first() {
                    log_trace!(self.logger, "parsing first row");
                    let invoice = parse_row_to_invoice(row.to_vec(), self.logger.clone())?;
                    Ok(Some(invoice))
                } else {
                    Ok(None)
                }
            } else {
                log_error!(
                    self.logger,
                    "could not find a row when executing query ({})",
                    select_query
                );
                Err(MutinyError::PersistenceFailed {
                    source: MutinyStorageError::IndexedDBError,
                })
            }
        }
    }

    async fn update_payment_status(
        &self,
        payment_hash: &bitcoin::hashes::sha256::Hash,
        status: HTLCStatus,
    ) -> Result<(), MutinyError> {
        #[cfg(not(target_arch = "wasm32"))]
        unimplemented!("can't run on servers until Send is supported in Glue");

        #[cfg(target_arch = "wasm32")]
        {
            let status_str = status.to_string();
            let payment_hash_str = payment_hash.to_string();
            let now = utils::now().as_secs();
            let sql = format!(
                "UPDATE mutiny_invoice SET status = '{}', last_updated = {} WHERE payment_hash = '{}'",
                status_str, now, payment_hash_str
            );

            let mut glue = self.db.lock().await;
            glue.execute(&sql)
                .await
                .map_err(|_| MutinyError::PersistenceFailed {
                    source: MutinyStorageError::IndexedDBError,
                })?;
            Ok(())
        }
    }

    async fn update_payment_fee(
        &self,
        payment_hash: &bitcoin::hashes::sha256::Hash,
        fee: Option<u64>,
    ) -> Result<(), MutinyError> {
        #[cfg(not(target_arch = "wasm32"))]
        unimplemented!("can't run on servers until Send is supported in Glue");

        #[cfg(target_arch = "wasm32")]
        {
            let fee_str = match fee {
                Some(fee_value) => fee_value.to_string(),
                None => "NULL".to_string(),
            };
            let payment_hash_str = payment_hash.to_string();
            let now = utils::now().as_secs();
            let sql = format!(
                "UPDATE mutiny_invoice SET fees_paid = {}, last_updated = {} WHERE payment_hash = '{}'",
                fee_str, now, payment_hash_str
            );

            let mut glue = self.db.lock().await;
            glue.execute(&sql)
                .await
                .map_err(|_| MutinyError::PersistenceFailed {
                    source: MutinyStorageError::IndexedDBError,
                })?;
            Ok(())
        }
    }

    async fn update_payment_preimage(
        &self,
        payment_hash: &bitcoin::hashes::sha256::Hash,
        preimage: Option<String>,
    ) -> Result<(), MutinyError> {
        #[cfg(not(target_arch = "wasm32"))]
        unimplemented!("can't run on servers until Send is supported in Glue");

        #[cfg(target_arch = "wasm32")]
        {
            let preimage_str = match preimage {
                Some(ref img) => format!("'{}'", img),
                None => "NULL".to_string(),
            };
            let payment_hash_str = payment_hash.to_string();
            let now = utils::now().as_secs();
            let sql = format!(
                "UPDATE mutiny_invoice SET preimage = {}, last_updated = {} WHERE payment_hash = '{}'",
                preimage_str, now, payment_hash_str
            );

            let mut glue = self.db.lock().await;
            glue.execute(&sql)
                .await
                .map_err(|_| MutinyError::PersistenceFailed {
                    source: MutinyStorageError::IndexedDBError,
                })?;
            Ok(())
        }
    }

    async fn list_payments(&self) -> Result<Vec<MutinyInvoice>, MutinyError> {
        #[cfg(not(target_arch = "wasm32"))]
        unimplemented!("can't run on servers until Send is supported in Glue");

        #[cfg(target_arch = "wasm32")]
        {
            let select_query = "SELECT bolt11, description, payment_hash, preimage, payee_pubkey, amount_sats, expire, status, fees_paid, inbound, labels, last_updated FROM mutiny_invoice";

            let mut glue = self.db.lock().await;
            let mut result =
                glue.execute(&select_query)
                    .await
                    .map_err(|_| MutinyError::PersistenceFailed {
                        source: MutinyStorageError::IndexedDBError,
                    })?;

            let mut invoices = Vec::new();
            if let Payload::Select { rows, .. } = result.pop().unwrap() {
                for row in rows {
                    let invoice = parse_row_to_invoice(row.to_vec(), self.logger.clone())?;
                    invoices.push(invoice);
                }
            } else {
                return Err(MutinyError::PersistenceFailed {
                    source: MutinyStorageError::IndexedDBError,
                });
            }

            Ok(invoices)
        }
    }
}

fn parse_row_to_invoice(
    row: Vec<Value>,
    logger: Arc<MutinyLogger>,
) -> Result<MutinyInvoice, MutinyError> {
    let bolt11 = match &row[0] {
        Value::Str(val) => {
            let b = Bolt11Invoice::from_str(val).map_err(|e| {
                log_error!(logger, "failed to parse invoice ({}): {e}", val);
                e
            })?;
            Some(b)
        }
        _ => None,
    };
    let description = match &row[1] {
        Value::Str(val) => Some(val.clone()),
        _ => None,
    };
    let payment_hash = match &row[2] {
        Value::Str(val) => sha256::Hash::from_str(val).map_err(|e| {
            log_error!(logger, "failed to parse hash ({}): {e}", val);
            e
        })?,
        _ => panic!("Expected String for preimage"),
    };
    let preimage = match &row[3] {
        Value::Str(val) => Some(val.clone()),
        _ => None,
    };
    let payee_pubkey = match &row[4] {
        Value::Str(val) => {
            let b = PublicKey::from_str(val).map_err(|e| {
                log_error!(logger, "failed to parse pubkey ({}): {e}", val);
                MutinyError::PersistenceFailed {
                    source: MutinyStorageError::IndexedDBError,
                }
            })?;
            Some(b)
        }
        _ => None,
    };
    let amount_sats = match &row[5] {
        Value::I64(val) => Some(*val as u64),
        _ => None,
    };
    let expire = match &row[6] {
        Value::I64(val) => *val as u64,
        _ => panic!("Expected i64 for expire"),
    };
    let status = match &row[7] {
        Value::Str(val) => HTLCStatus::from_str(val).map_err(|e| {
            log_error!(logger, "failed to parse status ({}): {e}", val);
            MutinyError::PersistenceFailed {
                source: MutinyStorageError::IndexedDBError,
            }
        })?,
        _ => HTLCStatus::Pending,
    };
    let fees_paid = match &row[8] {
        Value::I64(val) => Some(*val as u64),
        _ => None,
    };
    let inbound = match &row[9] {
        Value::Bool(val) => *val,
        _ => false,
    };
    let labels = match &row[10] {
        Value::Str(val) => {
            let labels_vec: Vec<String> = serde_json::from_str(val).map_err(|e| {
                log_error!(logger, "failed to parse labels ({}): {e}", val);
                MutinyError::PersistenceFailed {
                    source: MutinyStorageError::IndexedDBError,
                }
            })?;
            labels_vec
        }
        _ => vec![],
    };
    let last_updated = match &row[11] {
        Value::I64(val) => *val as u64,
        _ => panic!("Expected i64 for last_updated"),
    };

    Ok(MutinyInvoice {
        bolt11,
        description,
        payment_hash,
        preimage,
        payee_pubkey,
        amount_sats,
        expire,
        status,
        fees_paid,
        inbound,
        labels,
        last_updated,
    })
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone)]
pub struct FedimintDB {
    pub(crate) db: Arc<Mutex<Glue<IdbStorage>>>,
    fedimint_memory: Arc<MemDatabase>,
    federation_id: String,
}

impl fmt::Debug for FedimintDB {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FedimintDB").finish()
    }
}

impl FedimintDB {
    pub async fn new(
        #[cfg(target_arch = "wasm32")] db: Arc<Mutex<Glue<IdbStorage>>>,
        #[cfg(not(target_arch = "wasm32"))] db: Arc<Mutex<Glue<MemoryStorage>>>,
        federation_id: String,
        logger: Arc<MutinyLogger>,
    ) -> Result<Self, MutinyError> {
        log_debug!(logger, "initializing glue storage");

        let fedimint_memory = MemDatabase::new();

        {
            let mut glue_db = db.lock().await;

            let select_query = format!(
                "SELECT val FROM mutiny_kv WHERE key = '{}'",
                key_id(&federation_id)
            );
            let mut result =
                glue_db
                    .execute(select_query)
                    .await
                    .map_err(|_| MutinyError::ReadError {
                        source: MutinyStorageError::IndexedDBError,
                    })?;

            if let Payload::Select { rows, .. } = result.pop().expect("should get something") {
                if rows.is_empty() {
                    let stmt = format!(
                        "INSERT INTO mutiny_kv (key, val, version) VALUES ('{}', X'', 0)",
                        key_id(&federation_id)
                    );
                    glue_db
                        .execute(stmt)
                        .await
                        .map_err(|_| MutinyError::ReadError {
                            source: MutinyStorageError::IndexedDBError,
                        })?;
                } else if let Some(row) = rows.first() {
                    if let Value::Bytea(binary_data) = &row[0] {
                        if !binary_data.is_empty() {
                            let key_value_pairs: Vec<(Vec<u8>, Vec<u8>)> =
                                bincode::deserialize(binary_data).map_err(|e| {
                                    MutinyError::ReadError {
                                        source: MutinyStorageError::Other(e.into()),
                                    }
                                })?;

                            let mut mem_db_tx = fedimint_memory.begin_transaction().await;
                            for (key, value) in key_value_pairs {
                                mem_db_tx
                                    .raw_insert_bytes(&key, &value)
                                    .await
                                    .map_err(|_| {
                                        MutinyError::write_err(MutinyStorageError::IndexedDBError)
                                    })?;
                            }
                            mem_db_tx.commit_tx().await.map_err(|_| {
                                MutinyError::write_err(MutinyStorageError::IndexedDBError)
                            })?;
                        }
                    } else {
                        return Err(MutinyError::ReadError {
                            source: MutinyStorageError::IndexedDBError,
                        });
                    }
                }
            } else {
                return Err(MutinyError::ReadError {
                    source: MutinyStorageError::IndexedDBError,
                });
            }
        }

        log_debug!(logger, "done setting up FedimintDB for fedimint");

        Ok(Self {
            db,
            federation_id,
            fedimint_memory: Arc::new(fedimint_memory),
        })
    }
}

fn key_id(federation_id: &str) -> String {
    format!("fedimint_key_{}", federation_id)
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl IRawDatabase for FedimintDB {
    type Transaction<'a> = GluePseudoTransaction<'a>;

    async fn begin_transaction<'a>(&'a self) -> GluePseudoTransaction {
        GluePseudoTransaction {
            db: self.db.clone(),
            federation_id: self.federation_id.clone(),
            mem: self.fedimint_memory.begin_transaction().await,
        }
    }
}

pub struct GluePseudoTransaction<'a> {
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) db: Arc<Mutex<Glue<MemoryStorage>>>,
    #[cfg(target_arch = "wasm32")]
    pub(crate) db: Arc<Mutex<Glue<IdbStorage>>>,
    federation_id: String,
    mem: MemTransaction<'a>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<'a> IRawDatabaseTransaction for GluePseudoTransaction<'a> {
    async fn commit_tx(mut self) -> anyhow::Result<()> {
        #[cfg(not(target_arch = "wasm32"))]
        unimplemented!("can't run on servers until Send is supported in Glue");

        #[cfg(target_arch = "wasm32")]
        {
            let key_value_pairs = self
                .mem
                .raw_find_by_prefix(&[])
                .await?
                .collect::<Vec<(Vec<u8>, Vec<u8>)>>()
                .await;
            self.mem.commit_tx().await?;

            let serialized_data =
                bincode::serialize(&key_value_pairs).map_err(anyhow::Error::new)?;
            let hex_serialized_data = hex::encode(serialized_data);

            let update_query = format!(
                "UPDATE mutiny_kv SET val = X'{}' WHERE key = '{}'",
                hex_serialized_data,
                key_id(&self.federation_id)
            );

            let mut db = self.db.lock().await;

            db.execute(&update_query)
                .await
                .map_err(anyhow::Error::new)?;

            Ok(())
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<'a> IDatabaseTransactionOpsCore for GluePseudoTransaction<'a> {
    async fn raw_insert_bytes(
        &mut self,
        key: &[u8],
        value: &[u8],
    ) -> anyhow::Result<Option<Vec<u8>>> {
        self.mem.raw_insert_bytes(key, value).await
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        self.mem.raw_get_bytes(key).await
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        self.mem.raw_remove_entry(key).await
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> anyhow::Result<PrefixStream<'_>> {
        self.mem.raw_find_by_prefix(key_prefix).await
    }

    async fn raw_remove_by_prefix(&mut self, key_prefix: &[u8]) -> anyhow::Result<()> {
        self.mem.raw_remove_by_prefix(key_prefix).await
    }

    async fn raw_find_by_prefix_sorted_descending(
        &mut self,
        key_prefix: &[u8],
    ) -> anyhow::Result<PrefixStream<'_>> {
        self.mem
            .raw_find_by_prefix_sorted_descending(key_prefix)
            .await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<'a> IDatabaseTransactionOps for GluePseudoTransaction<'a> {
    async fn rollback_tx_to_savepoint(&mut self) -> anyhow::Result<()> {
        self.mem.rollback_tx_to_savepoint().await
    }

    async fn set_tx_savepoint(&mut self) -> anyhow::Result<()> {
        self.mem.set_tx_savepoint().await
    }
}

#[cfg(test)]
use gluesql::core::store::GStore;
#[cfg(test)]
use gluesql::core::store::GStoreMut;

#[cfg(test)]
async fn create_glue_and_fedimint_storage() {
    let db = GlueDB::new(
        #[cfg(target_arch = "wasm32")]
        Some("create_glue_and_fedimint_storage".to_string()),
        Arc::new(MutinyLogger::default()),
    )
    .await
    .unwrap();

    db.new_fedimint_client_db("create_glue_storage".to_string())
        .await
        .unwrap();
}

#[cfg(test)]
async fn create_glue_and_payments_storage() {
    use bitcoin::hashes::hex::{FromHex, ToHex};

    const INVOICE: &str = "lnbc923720n1pj9nr6zpp5xmvlq2u5253htn52mflh2e6gn7pk5ht0d4qyhc62fadytccxw7hqhp5l4s6qwh57a7cwr7zrcz706qx0qy4eykcpr8m8dwz08hqf362egfscqzzsxqzfvsp5pr7yjvcn4ggrf6fq090zey0yvf8nqvdh2kq7fue0s0gnm69evy6s9qyyssqjyq0fwjr22eeg08xvmz88307yqu8tqqdjpycmermks822fpqyxgshj8hvnl9mkh6srclnxx0uf4ugfq43d66ak3rrz4dqcqd23vxwpsqf7dmhm";

    let db = GlueDB::new(
        #[cfg(target_arch = "wasm32")]
        Some("create_glue_and_payments_storage".to_string()),
        Arc::new(MutinyLogger::default()),
    )
    .await
    .unwrap();

    let preimage: [u8; 32] =
        FromHex::from_hex("7600f5a9ad72452dea7ad86dabbc9cb46be96a1a2fcd961e041d066b38d93008")
            .unwrap();

    let payment_hash =
        sha256::Hash::from_hex("55ecf9169a6fa07e8ba181fdddf5b0bcc7860176659fa22a7cca9da2a359a33b")
            .unwrap();

    let pubkey =
        PublicKey::from_str("02465ed5be53d04fde66c9418ff14a5f2267723810176c9212b722e542dc1afb1b")
            .unwrap();

    let i = Bolt11Invoice::from_str(INVOICE).unwrap();

    let label = "test".to_string();
    let labels = vec![label.clone()];

    let invoice1: MutinyInvoice = MutinyInvoice {
        bolt11: Some(i),
        description: Some("dest".to_string()),
        payment_hash,
        preimage: Some(preimage.to_hex()),
        payee_pubkey: Some(pubkey),
        amount_sats: Some(100),
        expire: 1681781585,
        status: HTLCStatus::Succeeded,
        fees_paid: Some(1),
        inbound: false,
        labels: labels.clone(),
        last_updated: 1681781585,
    };
    db.save_payment(invoice1.clone()).await.unwrap();

    let db_invoice = db.get_payment(&payment_hash).await.unwrap().unwrap();
    assert_eq!(invoice1, db_invoice);

    let db_invoices = db.list_payments().await.unwrap();
    assert_eq!(db_invoices.len(), 1);
    assert_eq!(invoice1, db_invoices[0]);

    let payment_hash2 =
        sha256::Hash::from_hex("05ecf9169a6fa07e8ba181fdddf5b0bcc7860176659fa22a7cca9da2a359a33b")
            .unwrap();

    let i = Bolt11Invoice::from_str(INVOICE).unwrap();

    let mut invoice2: MutinyInvoice = MutinyInvoice {
        bolt11: Some(i.clone()),
        description: Some("dest".to_string()),
        payment_hash: payment_hash2,
        preimage: Some(preimage.to_hex()),
        payee_pubkey: Some(pubkey),
        amount_sats: Some(1000),
        expire: 1681781585,
        status: HTLCStatus::Pending,
        fees_paid: Some(1),
        inbound: false,
        labels: labels.clone(),
        last_updated: 1681781585,
    };
    db.save_payment(invoice2.clone()).await.unwrap();

    let db_invoice2 = db.get_payment(&payment_hash2).await.unwrap().unwrap();
    assert_eq!(invoice2, db_invoice2);
    assert_ne!(invoice1, db_invoice2);

    let db_invoices = db.list_payments().await.unwrap();
    assert_eq!(db_invoices.len(), 2);
    assert_eq!(invoice1, db_invoices[1]);
    assert_eq!(invoice2, db_invoices[0]);

    invoice2.status = HTLCStatus::Succeeded;
    db.save_payment(invoice2.clone()).await.unwrap();
    let db_invoice2_updated = db.get_payment(&payment_hash2).await.unwrap().unwrap();
    assert_eq!(invoice2, db_invoice2_updated);
    assert_ne!(db_invoice2, db_invoice2_updated);

    // allow nullable values
    let payment_hash_nullable =
        sha256::Hash::from_hex("44ecf9169a6fa07e8ba181fdddf5b0bcc7860176659fa22a7cca9da2a359a33b")
            .unwrap();
    let invoice_nullable: MutinyInvoice = MutinyInvoice {
        bolt11: Some(i),
        description: None,
        payment_hash: payment_hash_nullable,
        preimage: None,
        payee_pubkey: None,
        amount_sats: None,
        expire: 1681781585,
        status: HTLCStatus::Succeeded,
        fees_paid: None,
        inbound: false,
        labels: labels.clone(),
        last_updated: 1681781585,
    };
    db.save_payment(invoice_nullable.clone()).await.unwrap();

    let db_invoice_nullable = db
        .get_payment(&payment_hash_nullable)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(invoice_nullable, db_invoice_nullable);
}

#[cfg(test)]
async fn update_payments() {
    use bitcoin::hashes::hex::{FromHex, ToHex};

    const INVOICE: &str = "lnbc923720n1pj9nr6zpp5xmvlq2u5253htn52mflh2e6gn7pk5ht0d4qyhc62fadytccxw7hqhp5l4s6qwh57a7cwr7zrcz706qx0qy4eykcpr8m8dwz08hqf362egfscqzzsxqzfvsp5pr7yjvcn4ggrf6fq090zey0yvf8nqvdh2kq7fue0s0gnm69evy6s9qyyssqjyq0fwjr22eeg08xvmz88307yqu8tqqdjpycmermks822fpqyxgshj8hvnl9mkh6srclnxx0uf4ugfq43d66ak3rrz4dqcqd23vxwpsqf7dmhm";

    let db = GlueDB::new(
        #[cfg(target_arch = "wasm32")]
        Some("update_payments".to_string()),
        Arc::new(MutinyLogger::default()),
    )
    .await
    .unwrap();

    let preimage: [u8; 32] =
        FromHex::from_hex("7600f5a9ad72452dea7ad86dabbc9cb46be96a1a2fcd961e041d066b38d93008")
            .unwrap();

    let payment_hash =
        sha256::Hash::from_hex("55ecf9169a6fa07e8ba181fdddf5b0bcc7860176659fa22a7cca9da2a359a33b")
            .unwrap();

    let pubkey =
        PublicKey::from_str("02465ed5be53d04fde66c9418ff14a5f2267723810176c9212b722e542dc1afb1b")
            .unwrap();

    let i = Bolt11Invoice::from_str(INVOICE).unwrap();

    let label = "test".to_string();
    let labels = vec![label.clone()];

    let invoice1: MutinyInvoice = MutinyInvoice {
        bolt11: Some(i),
        description: Some("dest".to_string()),
        payment_hash,
        preimage: Some(preimage.to_hex()),
        payee_pubkey: Some(pubkey),
        amount_sats: Some(100),
        expire: 1681781585,
        status: HTLCStatus::Pending,
        fees_paid: Some(1),
        inbound: false,
        labels: labels.clone(),
        last_updated: 1681781585,
    };
    db.save_payment(invoice1.clone()).await.unwrap();

    let db_invoice = db.get_payment(&payment_hash).await.unwrap().unwrap();
    assert_eq!(invoice1, db_invoice);

    let db_invoices = db.list_payments().await.unwrap();
    assert_eq!(db_invoices.len(), 1);
    assert_eq!(invoice1, db_invoices[0]);

    // Test update_payment_status
    let new_status = HTLCStatus::Succeeded;
    db.update_payment_status(&payment_hash, new_status.clone())
        .await
        .unwrap();
    let updated_invoice = db.get_payment(&payment_hash).await.unwrap().unwrap();
    assert_eq!(updated_invoice.status, new_status);

    // Test update_payment_fee
    let new_fee = Some(10u64);
    db.update_payment_fee(&payment_hash, new_fee).await.unwrap();
    let updated_invoice_fee = db.get_payment(&payment_hash).await.unwrap().unwrap();
    assert_eq!(updated_invoice_fee.fees_paid, new_fee);

    // Test update_payment_preimage
    let new_preimage: Option<String> =
        Some("0600f5a9ad72452dea7ad86dabbc9cb46be96a1a2fcd961e041d066b38d93008".to_string());
    db.update_payment_preimage(&payment_hash, new_preimage.clone())
        .await
        .unwrap();
    let updated_invoice_preimage = db.get_payment(&payment_hash).await.unwrap().unwrap();
    assert_eq!(updated_invoice_preimage.preimage, new_preimage);

    // Test to make the timestamp was updated
    assert!(updated_invoice.last_updated <= updated_invoice_fee.last_updated);
    assert!(updated_invoice_fee.last_updated <= updated_invoice_preimage.last_updated);
}

#[cfg(test)]
async fn create_glue_storage_value() {
    let db = GlueDB::new(
        #[cfg(target_arch = "wasm32")]
        Some("create_glue_storage_value".to_string()),
        Arc::new(MutinyLogger::default()),
    )
    .await
    .unwrap();

    let f = db
        .new_fedimint_client_db("create_glue_storage".to_string())
        .await
        .unwrap();

    let mut tx = f.begin_transaction().await;
    let previous_bytes = tx
        .raw_insert_bytes("k".as_bytes(), "v".as_bytes())
        .await
        .unwrap();
    assert!(previous_bytes.is_none());

    let tx_get_bytes = tx.raw_get_bytes("k".as_bytes()).await.unwrap();
    assert_eq!(tx_get_bytes, Some("v".as_bytes().to_vec()));

    tx.commit_tx().await.unwrap();

    let mut tx_after_commit = f.begin_transaction().await;
    let bytes_after_commit = tx_after_commit.raw_get_bytes("k".as_bytes()).await.unwrap();
    assert_eq!(bytes_after_commit, Some("v".as_bytes().to_vec()));

    // now reinit the DB and see if it loads the same values from the table
    let same_f = db
        .new_fedimint_client_db("create_glue_storage".to_string())
        .await
        .unwrap();
    let mut tx = same_f.begin_transaction().await;
    let tx_get_bytes = tx.raw_get_bytes("k".as_bytes()).await.unwrap();
    assert_eq!(tx_get_bytes, Some("v".as_bytes().to_vec()));
}

#[cfg(test)]
async fn run_basic_glue_tests<T: GStore + GStoreMut>(glue: &mut Glue<T>) {
    use std::borrow::Cow;

    use gluesql::core::{
        ast::{AstLiteral, Expr},
        ast_builder::{num, table, Execute, ExprNode},
    };

    glue.execute("DROP TABLE IF EXISTS api_test").await.unwrap();
    glue.execute(
        "CREATE TABLE api_test (
            id INTEGER,
            name TEXT,
            nullable TEXT NULL,
            is BOOLEAN
        )",
    )
    .await
    .unwrap();

    glue.execute(
        "INSERT INTO api_test (
            id,
            name,
            nullable,
            is
        ) VALUES
            (1, 'test1', 'not null', TRUE),
            (2, 'test2', NULL, FALSE)",
    )
    .await
    .unwrap();

    let select_query = "SELECT id, name, nullable, is FROM api_test";
    let mut result = glue.execute(select_query).await.unwrap();

    assert_eq!(result.len(), 1);

    if let Payload::Select { rows, .. } = result.pop().unwrap() {
        assert_eq!(rows.len(), 2);

        let row1 = &rows[0];
        assert_eq!(row1[0], Value::I64(1));
        assert_eq!(row1[1], Value::Str("test1".to_string()));
        assert_eq!(row1[2], Value::Str("not null".to_string()));
        assert_eq!(row1[3], Value::Bool(true));

        let row2 = &rows[1];
        assert_eq!(row2[0], Value::I64(2));
        assert_eq!(row2[1], Value::Str("test2".to_string()));
        assert_eq!(row2[2], Value::Null);
        assert_eq!(row2[3], Value::Bool(false));
    } else {
        panic!("Expected Payload::Select");
    }

    // Use AST Builder to insert another row
    table("api_test")
        .insert()
        .columns("id, name, nullable, is")
        .values(vec![vec![
            num(3),
            ExprNode::QuotedString(Cow::Owned("test3".to_string())),
            ExprNode::Expr(Cow::Owned(Expr::Literal(AstLiteral::Null))),
            ExprNode::Expr(Cow::Owned(Expr::Literal(AstLiteral::Boolean(true)))),
        ]])
        .execute(glue)
        .await
        .unwrap();

    // Use AST Builder to select all rows
    let ast_select_all = table("api_test").select().execute(glue).await.unwrap();

    if let Payload::Select { rows, .. } = ast_select_all {
        assert_eq!(rows.len(), 3);

        struct ApiTestRow {
            id: i64,
            name: String,
            nullable: Option<String>,
            is: bool,
        }

        let api_test_rows = rows
            .into_iter()
            .map(|row| ApiTestRow {
                id: match row[0] {
                    Value::I64(val) => val,
                    _ => panic!("Expected I64 for id"),
                },
                name: match &row[1] {
                    Value::Str(val) => val.clone(),
                    _ => panic!("Expected Str for name"),
                },
                nullable: match &row[2] {
                    Value::Str(val) => Some(val.clone()),
                    Value::Null => None,
                    _ => panic!("Expected Str or Null for nullable"),
                },
                is: match row[3] {
                    Value::Bool(val) => val,
                    _ => panic!("Expected Bool for is"),
                },
            })
            .collect::<Vec<_>>();

        assert_eq!(api_test_rows[2].id, 3);
        assert_eq!(api_test_rows[2].name, "test3");
        assert!(api_test_rows[2].nullable.is_none());
        assert!(api_test_rows[2].is);
    } else {
        panic!("Expected Payload::Select");
    }

    // do some bytea tests
    glue.execute("CREATE TABLE IF NOT EXISTS mutiny_kv (key TEXT PRIMARY KEY, val BYTEA NOT NULL)")
        .await
        .unwrap();

    let key_value_pairs = vec![
        (vec![1, 2, 3], vec![4, 5, 6]),
        (vec![7, 8, 9], vec![10, 11, 12]),
    ];
    let serialized_data = bincode::serialize(&key_value_pairs).unwrap();
    let hex_serialized_data = hex::encode(serialized_data);

    glue.execute("INSERT INTO mutiny_kv (key, val) VALUES ('storage', X'')")
        .await
        .unwrap();
    let select_query = "SELECT val FROM mutiny_kv WHERE key = 'storage'";
    let mut result = glue.execute(select_query).await.unwrap();

    if let Payload::Select { rows, .. } = result.pop().expect("should get something") {
        if let Some(row) = rows.first() {
            if let Value::Bytea(hex_string) = &row[0] {
                let serialized_data = hex::decode(hex_string).unwrap();
                assert!(serialized_data.is_empty());
            } else {
                panic!("Expected bytea");
            }
        }
    } else {
        panic!("Expected Payload::Select");
    }

    let update_query = format!(
        "UPDATE mutiny_kv SET val = X'{}' WHERE key = 'fedimint_storage'",
        hex_serialized_data
    );
    glue.execute(&update_query).await.unwrap();

    let select_query = "SELECT val FROM mutiny_kv WHERE key = 'fedimint_storage'";
    let mut result = glue.execute(select_query).await.unwrap();

    if let Payload::Select { rows, .. } = result.pop().expect("should get something") {
        if let Some(row) = rows.first() {
            if let Value::Bytea(binary_data) = &row[0] {
                let retrieved_pairs: Vec<(Vec<u8>, Vec<u8>)> =
                    bincode::deserialize(binary_data).unwrap();

                assert_eq!(retrieved_pairs, key_value_pairs);
            } else {
                panic!("Expected bytea");
            }
        }
    } else {
        panic!("Expected Payload::Select");
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use gluesql::prelude::MemoryStorage;
    use tokio;

    #[tokio::test]
    async fn basic_glue_tests() {
        let storage = MemoryStorage::default();
        let mut glue = Glue::new(storage);
        run_basic_glue_tests(&mut glue).await;
    }

    #[cfg(feature = "ignored_tests")]
    #[tokio::test]
    async fn create_glue_storage_tests() {
        create_glue_and_fedimint_storage().await;
    }

    #[cfg(feature = "ignored_tests")]
    #[tokio::test]
    async fn create_glue_storage_value_tests() {
        create_glue_storage_value().await;
    }

    #[cfg(feature = "ignored_tests")]
    #[tokio::test]
    async fn create_glue_and_payments_storage_tests() {
        create_glue_and_payments_storage().await;
    }

    #[cfg(feature = "ignored_tests")]
    #[tokio::test]
    async fn update_payments_tests() {
        update_payments().await;
    }
}

#[cfg(test)]
#[cfg(target_arch = "wasm32")]
mod wasm_tests {
    use gluesql::prelude::{Glue, IdbStorage};
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn basic_wasm32_glue_tests() {
        let storage = IdbStorage::new(Some("basic_wasm32_glue_tests".to_string()))
            .await
            .unwrap();
        let mut glue = Glue::new(storage);
        run_basic_glue_tests(&mut glue).await;
    }

    #[test]
    async fn create_glue_storage_tests() {
        create_glue_and_fedimint_storage().await;
    }

    #[test]
    async fn create_glue_storage_value_tests() {
        create_glue_storage_value().await;
    }

    #[test]
    async fn create_glue_and_payments_storage_tests() {
        create_glue_and_payments_storage().await;
    }

    #[test]
    async fn update_payments_tests() {
        update_payments().await;
    }
}
