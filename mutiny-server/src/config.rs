use bitcoin::Network;
use clap::Parser;
use std::str::FromStr;

#[derive(Parser, Debug, Clone)]
#[command(version, author, about)]
/// Mutiny Wallet
pub struct Config {
    #[clap(default_value_t = String::from("sled.db"), long)]
    /// Location of database file
    pub db_file: String,
    #[clap(long)]
    /// Password used for encrypting sensitive data in database
    pub password: Option<String>,
    #[clap(default_value_t = String::from("0.0.0.0"), long)]
    /// Bind address for mutiny server
    pub bind: String,
    #[clap(default_value_t = 3000, long)]
    /// Port for mutiny server
    pub port: u16,
    #[clap(default_value_t = String::from("signet"), short, long)]
    /// Network to run on ["bitcoin", "testnet", "signet, "regtest"]
    pub network: String,
    #[clap(long)]
    /// URL to Flow 2.0 LSP
    pub lsp_url: Option<String>,
    #[clap(long)]
    /// URL to Rapid Gossip Sync server
    pub rgs_url: Option<String>,
    #[clap(long)]
    /// URL to esplora instance
    pub esplora_url: Option<String>,
}

impl Config {
    pub fn network(&self) -> Network {
        Network::from_str(&self.network).expect("Invalid network")
    }
}
