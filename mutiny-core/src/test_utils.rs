pub fn create_manager() -> AuthManager<MemoryStorage> {
    let storage = MemoryStorage::default();
    let mnemonic = generate_seed(12).unwrap();
    let seed = mnemonic.to_seed("");
    let xprivkey = ExtendedPrivKey::new_master(Network::Regtest, &seed).unwrap();
    let auth = AuthManager::new(xprivkey, storage).unwrap();
    auth.create_init().unwrap();
    auth
}

#[allow(unused_macros)]
macro_rules! log {
        ( $( $t:tt )* ) => {
            #[cfg(target_arch = "wasm32")]
            web_sys::console::log_1(&format!( $( $t )* ).into());
            #[cfg(not(target_arch = "wasm32"))]
            println!( $( $t )* );
        }
    }
use bitcoin::{util::bip32::ExtendedPrivKey, Network};
#[allow(unused_imports)]
pub(crate) use log;

use crate::{generate_seed, lnurlauth::AuthManager, storage::MemoryStorage};
