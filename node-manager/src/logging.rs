use chrono::Utc;
use gloo_storage::{LocalStorage, Storage};
use lightning::util::logger::{Level, Logger, Record};
use log::*;

#[derive(Default, Debug, Eq, PartialEq, Copy, Clone)]
pub struct MutinyLogger {}

use crate::utils::now;

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

        let key = format!("log_{}", now().as_secs());
        if let Err(e) = LocalStorage::set(key, log.clone()) {
            println!("Error writing log to local storage: {}", e);
        };

        match record.level {
            Level::Gossip => trace!("{}", log),
            Level::Trace => debug!("{}", log),
            Level::Debug => debug!("{}", log),
            Level::Info => info!("{}", log),
            Level::Warn => warn!("{}", log),
            Level::Error => error!("{}", log),
        }
    }
}

// fn clear_logs_until_now() {
//     // Get the current time in seconds
//     let now = now().as_secs();

//     let local_storage = LocalStorage::raw();
//     let length = LocalStorage::length();
//     for index in 0..length {
//         let key_opt: Option<String> = local_storage.key(index).unwrap();

//         if let Some(key) = key_opt {
//             if key.starts_with("log_") {
//                 // Extract the timestamp from the log key
//                 let timestamp_string = key.replace("log_", "");
//                 let timestamp = timestamp_string.parse::<u64>().unwrap();

//                 // Remove the log entry from local storage if its timestamp is less than or equal to the current time
//                 if timestamp <= now {
//                     local_storage.delete(&key).unwrap();
//                 }
//             }
//         }
//     }
// }
