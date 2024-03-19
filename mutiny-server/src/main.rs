#![allow(incomplete_features)]

mod config;
mod sled;

use crate::config::Config;
use crate::sled::SledStorage;
use axum::http::{StatusCode, Uri};
use axum::routing::get;
use axum::{Extension, Router, Json};
use bitcoin::bip32::ExtendedPrivKey;
use clap::Parser;
use log::{debug, info};
use mutiny_core::storage::MutinyStorage;
use mutiny_core::{generate_seed, MutinyWallet, MutinyWalletBuilder, MutinyWalletConfig};
use serde_json::{json, Value};
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

    // create node
    let _node = match wallet.node_manager.list_nodes().await?.first() {
        None => wallet.node_manager.new_node().await?.pubkey,
        Some(node) => *node
    };

    debug!("Wallet initialized!");

    let listener = tokio::net::TcpListener::bind(format!("{}:{}", config.bind, config.port))
        .await?;

    //println!("mutiny server running on http://{}", &listener.into());
    println!("mutiny server running");

    let state = State {
        mutiny_wallet: wallet.clone(),
    };

    let server_router = Router::new()
        .route("/newaddress", get(new_address))
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

#[derive(Clone)]
pub struct State {
    pub mutiny_wallet: MutinyWallet<SledStorage>,
}

pub async fn new_address(Extension(state): Extension<State>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let address = state.mutiny_wallet.node_manager.get_new_address(vec![]).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
    })?;
    Ok(Json(json!(address)))
}

async fn fallback(uri: Uri) -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, format!("No route for {}", uri))
}
