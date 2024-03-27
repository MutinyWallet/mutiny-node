#![allow(incomplete_features)]

mod config;
mod extractor;
mod routes;
mod sled;

use crate::config::Config;
use crate::sled::SledStorage;
use axum::http::{StatusCode, Uri};
use axum::routing::{get, post};
use axum::{Extension, Router};
use bitcoin::bip32::ExtendedPrivKey;
use clap::Parser;
use log::{debug, info};
use mutiny_core::storage::MutinyStorage;
use mutiny_core::{generate_seed, MutinyWalletBuilder, MutinyWalletConfigBuilder};
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

    let mut config_builder = MutinyWalletConfigBuilder::new(xprivkey).with_network(network);
    if let Some(url) = config.esplora_url {
        config_builder.with_user_esplora_url(url);
    }
    if let Some(url) = config.rgs_url {
        config_builder.with_user_rgs_url(url);
    }
    if let Some(url) = config.lsp_url {
        config_builder.with_lsp_url(url);
    }
    let wallet_config = config_builder.build();

    debug!("Initializing wallet...");
    let wallet = MutinyWalletBuilder::new(xprivkey, storage)
        .with_config(wallet_config)
        .build()
        .await?;

    debug!("Wallet initialized!");

    let state = routes::State {
        mutiny_wallet: wallet.clone(),
    };

    tokio::spawn(async move {
        let server_router = Router::new()
            .route("/newaddress", get(routes::new_address))
            .route("/sendtoaddress", post(routes::send_to_address))
            .route("/openchannel", post(routes::open_channel))
            .route("/closechannel", post(routes::close_channel))
            .route("/createinvoice", post(routes::create_invoice))
            .route("/payinvoice", post(routes::pay_invoice))
            .route("/payments/incoming", get(routes::get_incoming_payments))
            .route("/payment/:paymentHash", get(routes::get_payment))
            .route("/balance", get(routes::get_balance))
            .route("/getinfo", get(routes::get_node_info))
            .fallback(fallback)
            .layer(Extension(state.clone()));

        let listener = tokio::net::TcpListener::bind(format!("{}:{}", config.bind, config.port))
            .await
            .expect("failed to parse bind/port");

        axum::serve(listener, server_router).await.unwrap();
    });

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
