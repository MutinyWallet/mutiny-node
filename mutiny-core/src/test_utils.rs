pub fn create_manager() -> AuthManager {
    let mnemonic = generate_seed(12).unwrap();
    let seed = mnemonic.to_seed("");
    let xprivkey = ExtendedPrivKey::new_master(Network::Regtest, &seed).unwrap();
    AuthManager::new(xprivkey).unwrap()
}

pub async fn create_vss_client() -> MutinyVssClient {
    // Set up test auth client
    let auth_manager = create_manager();
    let lnurl_client = Arc::new(
        lnurl::Builder::default()
            .build_async()
            .expect("failed to make lnurl client"),
    );
    let logger = Arc::new(MutinyLogger::default());
    let url = "https://auth-staging.mutinywallet.com";

    let auth_client =
        MutinyAuthClient::new(auth_manager, lnurl_client, logger.clone(), url.to_string());

    // Test authenticate method
    match auth_client.authenticate().await {
        Ok(_) => assert!(auth_client.is_authenticated().is_some()),
        Err(e) => panic!("Authentication failed with error: {:?}", e),
    };

    let encryption_key = SecretKey::from_slice(&[2; 32]).unwrap();

    MutinyVssClient::new(
        Arc::new(auth_client),
        "https://storage-staging.mutinywallet.com".to_string(),
        encryption_key,
        logger,
    )
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
use bitcoin::secp256k1::SecretKey;
use bitcoin::{util::bip32::ExtendedPrivKey, Network};
#[allow(unused_imports)]
pub(crate) use log;
use std::sync::Arc;

use crate::auth::MutinyAuthClient;
use crate::logging::MutinyLogger;
use crate::vss::MutinyVssClient;
use crate::{generate_seed, lnurlauth::AuthManager};
