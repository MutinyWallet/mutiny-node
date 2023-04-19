#![crate_name = "mutiny_core"]
// wasm is considered "extra_unused_type_parameters"
#![allow(incomplete_features, clippy::extra_unused_type_parameters)]
#![feature(io_error_other)]
#![feature(async_fn_in_trait)]
// background file is mostly an LDK copy paste
mod background;

mod bdkstorage;
mod chain;
mod encrypt;
pub mod error;
pub mod esplora;
mod event;
mod fees;
mod gossip;
mod indexed_db;
mod keymanager;
mod ldkstorage;
mod localstorage;
mod logging;
mod lspclient;
mod node;
pub mod nodemanager;
mod peermanager;
mod proxy;
mod socket;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
mod utils;
mod wallet;
