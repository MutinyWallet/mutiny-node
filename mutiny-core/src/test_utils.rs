use gloo_storage::{LocalStorage, Storage};

macro_rules! log {
        ( $( $t:tt )* ) => {
            web_sys::console::log_1(&format!( $( $t )* ).into());
        }
    }
pub(crate) use log;
use rexie::Rexie;

use crate::gossip::GOSSIP_DATABASE_NAME;
use crate::indexed_db::MutinyStorage;

pub fn cleanup_test() {
    LocalStorage::clear();
}

pub async fn cleanup_gossip_test() {
    cleanup_test();
    Rexie::delete(GOSSIP_DATABASE_NAME).await.unwrap();
}

pub async fn cleanup_wallet_test() {
    cleanup_test();
    MutinyStorage::clear().await.unwrap();
}
