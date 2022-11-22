use chrono::Utc;
use lightning::util::logger::{Level, Logger, Record};
use log::*;

#[derive(Default, Debug, Eq, PartialEq, Copy, Clone)]
pub struct MutinyLogger {}

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
