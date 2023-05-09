use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use crate::utils::Mutex;
use crate::{error::MutinyError, utils::sleep};
use chrono::Utc;
use gloo_utils::format::JsValueSerdeExt;
use lightning::util::logger::{Level, Logger, Record};
use log::*;
use rexie::{ObjectStore, Rexie, TransactionMode};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::spawn_local;

pub(crate) const LOGGING_DATABASE_NAME: &str = "logging";
pub(crate) const LOGGING_OBJECT_STORE_NAME: &str = "log_store";
pub(crate) const LOGGING_KEY: &str = "logs";

const MAX_LOG_ITEMS: usize = 1_000;

#[derive(Clone)]
pub struct MutinyLogger {
    should_write_to_storage: bool,
    memory_logs: Arc<Mutex<Vec<String>>>,
}

impl MutinyLogger {
    pub(crate) fn with_writer(stop: Arc<AtomicBool>, db_prefix: Option<String>) -> Self {
        let l = MutinyLogger {
            should_write_to_storage: true,
            memory_logs: Arc::new(Mutex::new(vec![])),
        };

        let log_copy = l.clone();
        spawn_local(async move {
            let logging_db = build_logging_database(db_prefix).await;
            if logging_db.is_err() {
                error!("could not build logging database, log entries will be lost");
                return;
            }
            let logging_db = logging_db.unwrap();

            loop {
                // wait up to 5s, checking graceful shutdown check each 1s.
                for _ in 0..5 {
                    if stop.load(Ordering::Relaxed) {
                        logging_db.close();
                        return;
                    }
                    sleep(1_000).await;
                }

                // if there's any in memory logs, append them to the file system
                let memory_logs_clone = {
                    if let Ok(mut memory_logs) = log_copy.memory_logs.lock() {
                        let logs = memory_logs.clone();
                        memory_logs.clear();
                        Some(logs)
                    } else {
                        warn!("Failed to lock memory_logs, log entires may be lost.");
                        None
                    }
                };

                if let Some(mut logs) = memory_logs_clone {
                    if !logs.is_empty() {
                        // append them to storage
                        match write_logging_data(&logging_db, &mut logs).await {
                            Ok(_) => {}
                            Err(_) => {
                                error!("could not write logging data to storage, trying again next time, log entires may be lost");
                            }
                        }
                    }
                }
            }
        });

        l
    }

    pub(crate) async fn get_logs(
        &self,
        db_prefix: Option<String>,
    ) -> Result<Option<Vec<String>>, MutinyError> {
        if !self.should_write_to_storage {
            return Ok(None);
        }
        let logging_db = build_logging_database(db_prefix).await?;
        get_logging_data(&logging_db).await
    }
}

impl Default for MutinyLogger {
    fn default() -> Self {
        Self {
            should_write_to_storage: Default::default(),
            memory_logs: Arc::new(Mutex::new(vec![])),
        }
    }
}

impl Logger for MutinyLogger {
    fn log(&self, record: &Record) {
        let raw_log = record.args.to_string();
        let log = format!(
            "{} {:<5} [{}:{}] {}\n",
            // Note that a "real" lightning node almost certainly does *not* want subsecond
            // precision for message-receipt information as it makes log entries a target for
            // deanonymization attacks. For testing, however, its quite useful.
            Utc::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            record.level,
            record.module_path,
            record.line,
            raw_log
        );

        if self.should_write_to_storage {
            if let Ok(mut memory_logs) = self.memory_logs.lock() {
                memory_logs.push(log.clone());
            } else {
                warn!("Failed to lock memory_logs, log entry may be lost.");
            }
        }

        match record.level {
            Level::Gossip => trace!("{}", log),
            Level::Trace => trace!("{}", log),
            Level::Debug => debug!("{}", log),
            Level::Info => info!("{}", log),
            Level::Warn => warn!("{}", log),
            Level::Error => error!("{}", log),
        }
    }
}

async fn build_logging_database(db_prefix: Option<String>) -> Result<Rexie, MutinyError> {
    let db_name = db_prefix
        .map(|prefix| format!("{}_{}", prefix, LOGGING_DATABASE_NAME))
        .unwrap_or_else(|| String::from(LOGGING_DATABASE_NAME));

    let rexie = Rexie::builder(&db_name)
        .version(1)
        .add_object_store(ObjectStore::new(LOGGING_OBJECT_STORE_NAME))
        .build()
        .await?;

    Ok(rexie)
}

#[cfg(any(test, feature = "test-utils"))]
pub(crate) async fn clear(db_prefix: Option<String>) -> Result<(), MutinyError> {
    let indexed_db = build_logging_database(db_prefix).await?;
    let tx = indexed_db.transaction(&[LOGGING_OBJECT_STORE_NAME], TransactionMode::ReadWrite)?;
    let store = tx.store(LOGGING_OBJECT_STORE_NAME)?;

    store.clear().await?;

    tx.done().await?;

    Ok(())
}

async fn get_logging_data(rexie: &Rexie) -> Result<Option<Vec<String>>, MutinyError> {
    // Create a new read-only transaction
    let transaction = rexie.transaction(&[LOGGING_OBJECT_STORE_NAME], TransactionMode::ReadOnly)?;

    let mut store = transaction.store(LOGGING_OBJECT_STORE_NAME)?;

    let res = get_logging_data_with_transaction_store(&mut store).await;

    transaction.done().await?;

    res
}

/// Pass in a transaction to get the data for.
/// It is up to the caller to call `transaction.done()`
async fn get_logging_data_with_transaction_store(
    store: &mut rexie::Store,
) -> Result<Option<Vec<String>>, MutinyError> {
    let logging_js = store.get(&JsValue::from(LOGGING_KEY)).await?;

    // If the key doesn't exist, we return None
    if logging_js.is_null() || logging_js.is_undefined() {
        return Ok(None);
    }

    let logging_data: Vec<String> = logging_js.into_serde()?;

    Ok(Some(logging_data))
}

async fn write_logging_data(
    rexie: &Rexie,
    recent_logs: &mut Vec<String>,
) -> Result<(), MutinyError> {
    // Create a new read-write transaction
    let transaction =
        rexie.transaction(&[LOGGING_OBJECT_STORE_NAME], TransactionMode::ReadWrite)?;

    let mut store = transaction.store(LOGGING_OBJECT_STORE_NAME)?;

    // get the existing data so we can append to it, trimming if needed
    let mut existing_logs = get_logging_data_with_transaction_store(&mut store)
        .await?
        .unwrap_or_default();
    existing_logs.append(recent_logs);
    if existing_logs.len() > MAX_LOG_ITEMS {
        let start_index = existing_logs.len() - MAX_LOG_ITEMS;
        existing_logs.drain(..start_index);
    }

    // Save the logs
    store
        .put(
            &JsValue::from_serde(&serde_json::to_value(existing_logs).unwrap()).unwrap(),
            Some(&JsValue::from(LOGGING_KEY)),
        )
        .await?;

    // Waits for the transaction to complete
    transaction.done().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    use lightning::{log_debug, util::logger::Logger};
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    use crate::{test_utils::*, utils::sleep};

    use crate::logging::MutinyLogger;

    #[test]
    async fn log_without_storage() {
        let test_name = "log_without_storage";
        log!("{}", test_name);

        let logger = MutinyLogger::default();
        assert_eq!(
            logger.get_logs(Some(test_name.to_string())).await.unwrap(),
            None
        );

        log_debug!(logger, "testing");

        // saves every 5s, so do one second later
        sleep(6_000).await;

        assert_eq!(
            logger.get_logs(Some(test_name.to_string())).await.unwrap(),
            None
        );
    }

    #[test]
    async fn log_with_storage() {
        let test_name = "log_with_storage";
        log!("{}", test_name);

        let stop = Arc::new(AtomicBool::new(false));
        let logger = MutinyLogger::with_writer(stop.clone(), Some(test_name.to_string()));

        let log_str = "testing logging with storage";
        log_debug!(logger, "{}", log_str);

        // saves every 5s, so do one second later
        sleep(6_000).await;

        assert!(logger
            .get_logs(Some(test_name.to_string()))
            .await
            .unwrap()
            .unwrap()
            .first()
            .unwrap()
            .contains(log_str));

        stop.swap(true, Ordering::Relaxed);
    }
}
