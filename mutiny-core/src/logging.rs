use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use crate::surreal::SurrealDb;
use crate::utils::Mutex;
use crate::{error::MutinyError, utils, utils::sleep};
use chrono::Utc;
use lightning::util::logger::{Level, Logger, Record};
use log::*;
use surrealdb::Connection;

pub(crate) const LOGGING_KEY: &str = "logs";

const MAX_LOG_ITEMS: usize = 10_000;

#[derive(Clone)]
pub struct MutinyLogger {
    should_write_to_storage: bool,
    memory_logs: Arc<Mutex<Vec<String>>>,
}

impl MutinyLogger {
    pub fn with_writer<S: Connection + Clone>(
        stop: Arc<AtomicBool>,
        logging_db: SurrealDb<S>,
    ) -> Self {
        let l = MutinyLogger {
            should_write_to_storage: true,
            memory_logs: Arc::new(Mutex::new(vec![])),
        };

        let log_copy = l.clone();
        utils::spawn(async move {
            loop {
                // wait up to 5s, checking graceful shutdown check each 1s.
                for _ in 0..5 {
                    if stop.load(Ordering::Relaxed) {
                        logging_db.stop();
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
                        warn!("Failed to lock memory_logs, log entries may be lost.");
                        None
                    }
                };

                if let Some(logs) = memory_logs_clone {
                    if !logs.is_empty() {
                        // append them to storage
                        match write_logging_data(&logging_db, logs).await {
                            Ok(_) => {}
                            Err(_) => {
                                error!("could not write logging data to storage, trying again next time, log entries may be lost");
                            }
                        }
                    }
                }
            }
        });

        l
    }

    pub(crate) async fn get_logs<S: Connection + Clone>(
        &self,
        storage: &SurrealDb<S>,
    ) -> Result<Option<Vec<String>>, MutinyError> {
        if !self.should_write_to_storage {
            return Ok(None);
        }
        get_logging_data(storage).await
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

        if self.should_write_to_storage && record.level >= Level::Trace {
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

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Logs {
    logs: Vec<String>,
}

async fn get_logging_data<S: Connection + Clone>(
    storage: &SurrealDb<S>,
) -> Result<Option<Vec<String>>, MutinyError> {
    Ok(storage.get_data::<Logs>(LOGGING_KEY).await?.map(|l| l.logs))
}

async fn write_logging_data<S: Connection + Clone>(
    storage: &SurrealDb<S>,
    mut recent_logs: Vec<String>,
) -> Result<(), MutinyError> {
    // get the existing data so we can append to it, trimming if needed
    // Note there is a potential race condition here if the logs are being written to
    // concurrently, but we don't care about that for now.
    let mut existing_logs: Vec<String> = get_logging_data(storage).await?.unwrap_or_default();
    existing_logs.append(&mut recent_logs);
    if existing_logs.len() > MAX_LOG_ITEMS {
        let start_index = existing_logs.len() - MAX_LOG_ITEMS;
        existing_logs.drain(..start_index);
    }

    let logs = Logs {
        logs: existing_logs,
    };

    // Save the logs
    storage.set_data_async(LOGGING_KEY, logs, None).await?;

    Ok(())
}

#[cfg(test)]
use crate::test_utils::log;

#[cfg(test)]
#[derive(Clone)]
pub struct TestLogger {}

#[cfg(test)]
impl Logger for TestLogger {
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

        log!("{}", log);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    use lightning::{log_debug, util::logger::Logger};
    use surrealdb::Surreal;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    use crate::{test_utils::*, utils::sleep};

    use crate::logging::MutinyLogger;
    use crate::surreal::SurrealDb;
    use surrealdb::engine::local::Mem;
    use surrealdb::opt::Config;
    use surrealdb::Surreal;

    #[test]
    async fn log_without_storage() {
        let test_name = "log_without_storage";
        log!("{}", test_name);

        let logger = MutinyLogger::default();
        assert_eq!(logger.get_logs(&()).await.unwrap(), None);

        log_debug!(logger, "testing");

        // saves every 5s, so do one second later
        sleep(6_000).await;

        assert_eq!(logger.get_logs(&()).await.unwrap(), None);
    }

    #[test]
    async fn log_with_storage() {
        let test_name = "log_with_storage";
        log!("{}", test_name);

        let config = Config::default().strict();
        let db = Surreal::new::<Mem>(config).await?;
        let storage = SurrealDb::new(db, None, None, None, Arc::new(MutinyLogger::default()));

        let stop = Arc::new(AtomicBool::new(false));
        let logger = MutinyLogger::with_writer(stop.clone(), storage.clone());

        let log_str = "testing logging with storage";
        log_debug!(logger, "{}", log_str);

        // saves every 5s, so do one second later
        sleep(6_000).await;

        assert!(logger
            .get_logs(&storage)
            .await
            .unwrap()
            .unwrap()
            .first()
            .unwrap()
            .contains(log_str));

        stop.swap(true, Ordering::Relaxed);
    }
}
