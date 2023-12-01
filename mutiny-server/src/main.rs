#![allow(incomplete_features)]

mod config;
mod sled;

use crate::config::Config;
use bitcoin::util::bip32::ExtendedPrivKey;
use clap::Parser;
use log::{debug, info};
use mutiny_core::storage::MutinyStorage;
use mutiny_core::{generate_seed, MutinyWallet};
use shutdown::Shutdown;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    pretty_env_logger::try_init()?;
    let mut shutdown = Shutdown::new().unwrap();
    let config: Config = Config::parse();

    let network = config.network();
    let storage = sled::SledStorage::new(&config.db_file, config.password)?;

    let mnemonic = match storage.get_mnemonic() {
        Ok(Some(mnemonic)) => mnemonic,
        Ok(None) => {
            let seed = generate_seed(12)?;
            storage.insert_mnemonic(seed)?
        }
        Err(_) => {
            // if we get an error, then we have the wrong password
            return Err(anyhow::anyhow!("Wrong password"));
        }
    };

    let seed = mnemonic.to_seed("");
    let xprivkey = ExtendedPrivKey::new_master(network, &seed).unwrap();

    let config = mutiny_core::MutinyWalletConfig::new(
        xprivkey,
        network,
        config.esplora_url,
        config.rgs_url,
        config.lsp_url,
        None,
        None,
        None,
        false,
        true,
    );

    debug!("Initializing wallet...");
    let wallet = MutinyWallet::new(storage, config, None).await.unwrap();

    // create node
    let _node = match wallet.node_manager.list_nodes().await?.first() {
        None => wallet.node_manager.new_node().await?.pubkey,
        Some(node) => *node,
    };

    debug!("Wallet initialized!");

    // wait for shutdown hook
    shutdown.recv().await;
    info!("shutdown hook received, stopping...");
    // once we get hook, stop wallet
    wallet.stop().await?;
    // sleep 1 second to make sure fully shutdown
    tokio::time::sleep(Duration::from_secs(1)).await;
    Ok(())
}
