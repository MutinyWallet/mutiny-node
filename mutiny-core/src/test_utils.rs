use futures::join;

#[allow(unused_macros)]
macro_rules! log {
        ( $( $t:tt )* ) => {
            web_sys::console::log_1(&format!( $( $t )* ).into());
        }
    }
#[allow(unused_imports)]
pub(crate) use log;
use rexie::Rexie;

use crate::indexed_db::MutinyStorage;
use crate::{gossip::GOSSIP_DATABASE_NAME, logging};

async fn cleanup_gossip_test() {
    Rexie::delete(GOSSIP_DATABASE_NAME).await.unwrap();
}

async fn cleanup_wallet_test() {
    MutinyStorage::clear().await.unwrap();
}

async fn cleanup_logging_test() {
    logging::clear().await.unwrap();
}

pub async fn cleanup_all() {
    let cleanup_gossip = cleanup_gossip_test();
    let cleanup_wallet = cleanup_wallet_test();
    let cleanup_logging = cleanup_logging_test();

    join!(cleanup_gossip, cleanup_wallet, cleanup_logging);
}
