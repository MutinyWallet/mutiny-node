#![allow(incomplete_features)]

mod config;
mod sled;
mod routes;

use crate::config::Config;
use crate::sled::SledStorage;
use axum::http::{StatusCode, Uri};
use axum::routing::{get, post};
use axum::{Extension, Router};
use bitcoin::bip32::ExtendedPrivKey;
use clap::Parser;
use log::{debug, info};
use mutiny_core::storage::MutinyStorage;
use mutiny_core::{generate_seed, MutinyWalletBuilder, MutinyWalletConfig};
use shutdown::Shutdown;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    pretty_env_logger::try_init()?;
    let mut shutdown = Shutdown::new().unwrap();
    let config: Config = Config::parse();

    let network = config.network();
    let storage = SledStorage::new(&config.db_file, config.clone().password)?;

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

    let wallet_config = MutinyWalletConfig::new(
        xprivkey,
        network,
        config.esplora_url,
        config.rgs_url,
        config.lsp_url,
    );

    debug!("Initializing wallet...");
    let wallet = MutinyWalletBuilder::new(xprivkey, storage).with_config(wallet_config).build().await?;

    let listener = tokio::net::TcpListener::bind(format!("{}:{}", config.bind, config.port))
        .await?;

    debug!("Wallet initialized!");

    let state = routes::State {
        mutiny_wallet: wallet.clone(),
    };

    let server_router = Router::new()
        .route("/newaddress", get(routes::new_address))
        .route("/sendtoaddress", post(routes::send_to_address))
        .route("/openchannel", post(routes::open_channel))
        .route("/invoice", post(routes::create_invoice))
        .route("/payinvoice", post(routes::pay_invoice))
        .route("/balance", get(routes::get_balance))
        .fallback(fallback)
        .layer(Extension(state.clone()));

    axum::serve(listener, server_router).await.unwrap();

    // wait for shutdown hook
    shutdown.recv().await;
    info!("shutdown hook received, stopping...");
    // once we get hook, stop wallet
    wallet.stop().await?;
    // sleep 1 second to make sure fully shutdown
    tokio::time::sleep(Duration::from_secs(1)).await;
    Ok(())
}

async fn fallback(uri: Uri) -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, format!("No route for {}", uri))
}
