use crate::{
    error::{MutinyError, MutinyStorageError},
    logging::MutinyLogger,
};
use async_trait::async_trait;
use fedimint_core::db::{
    mem_impl::{MemDatabase, MemTransaction},
    IDatabaseTransactionOps, IDatabaseTransactionOpsCore, IRawDatabase, IRawDatabaseTransaction,
    PrefixStream,
};
use gluesql::prelude::{Glue, Payload, Value};
use lightning::{log_debug, util::logger::Logger};

use std::{fmt, sync::Arc};

#[cfg(not(target_arch = "wasm32"))]
use tokio::sync::Mutex;

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

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
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
}
