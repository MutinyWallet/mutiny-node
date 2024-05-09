use electrsd::bitcoind::bitcoincore_rpc::bitcoincore_rpc_json::AddressType;
use electrsd::bitcoind::bitcoincore_rpc::RpcApi;
use electrsd::bitcoind::BitcoinD;
use electrsd::electrum_client::ElectrumApi;
use electrsd::{bitcoind, ElectrsD};
use lazy_static::lazy_static;
use lnd::tonic_lnd::lnrpc::{
    GetInfoRequest, NewAddressRequest, OpenChannelRequest, WalletBalanceRequest,
};
use lnd::{Lnd, LndConf};
use mutiny_core::bitcoin::bip32::ExtendedPrivKey;
use mutiny_core::bitcoin::{Address, Amount, Network};
use mutiny_core::lightning::util::ser::Writeable;
use mutiny_core::storage::MemoryStorage;
use mutiny_core::{
    generate_seed, MutinyWallet, MutinyWalletBuilder, MutinyWalletConfigBuilder,
    PubkeyConnectionInfo,
};
use std::env;
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::{Mutex, OnceCell};

lazy_static! {
    pub static ref BITCOIND: BitcoinD = {
        let bitcoind_exe = env::var("BITCOIND_EXE")
            .ok()
            .or_else(|| bitcoind::downloaded_exe_path().ok())
            .expect(
                "you need to provide an env var BITCOIND_EXE or specify a bitcoind version feature",
            );
        let conf = bitcoind::Conf::default();
        BitcoinD::with_conf(bitcoind_exe, &conf).unwrap()
    };
    pub static ref ELECTRSD: ElectrsD = {
        let electrs_exe = env::var("ELECTRS_EXE")
            .ok()
            .or_else(electrsd::downloaded_exe_path)
            .expect(
                "you need to provide env var ELECTRS_EXE or specify an electrsd version feature",
            );
        let mut conf = electrsd::Conf::default();
        conf.http_enabled = true;
        ElectrsD::with_conf(electrs_exe, &BITCOIND, &conf).unwrap()
    };
    pub static ref MINER: Mutex<()> = Mutex::new(());
}

pub static PREMINE: OnceCell<()> = OnceCell::const_new();

pub async fn generate_blocks_and_wait(num: usize) {
    let _miner = MINER.lock().await;
    let cur_height = BITCOIND.client.get_block_count().unwrap();
    generate_blocks(num);
    wait_for_block(cur_height as usize + num);
}

pub fn generate_blocks(num: usize) {
    let address = BITCOIND
        .client
        .get_new_address(Some("test"), Some(AddressType::Bech32m))
        .unwrap()
        .assume_checked();
    let _block_hashes = BITCOIND
        .client
        .generate_to_address(num as u64, &address)
        .unwrap();
}

pub fn wait_for_block(min_height: usize) {
    let mut header = ELECTRSD.client.block_headers_subscribe().unwrap();
    loop {
        if header.height >= min_height {
            break;
        }
        header = exponential_backoff_poll(|| {
            ELECTRSD.trigger().unwrap();
            ELECTRSD.client.ping().unwrap();
            ELECTRSD.client.block_headers_pop().unwrap()
        });
    }
}

fn exponential_backoff_poll<T, F>(mut poll: F) -> T
where
    F: FnMut() -> Option<T>,
{
    let mut delay = Duration::from_millis(64);
    loop {
        match poll() {
            Some(data) => break data,
            None if delay.as_millis() < 512 => delay = delay.mul_f32(2.0),
            None => {}
        }

        std::thread::sleep(delay);
    }
}

pub async fn create_mutiny_wallet() -> MutinyWallet<MemoryStorage> {
    PREMINE
        .get_or_init(|| async {
            generate_blocks_and_wait(101).await;
        })
        .await;

    let mnemonic = generate_seed(12).unwrap();
    let network = Network::Regtest;
    let xpriv = ExtendedPrivKey::new_master(network, &mnemonic.to_seed("")).unwrap();

    let storage = MemoryStorage::new(None, None, None);
    let mut config = MutinyWalletConfigBuilder::new(xpriv).with_network(network);
    let url = format!("http://{}", ELECTRSD.esplora_url.clone().unwrap());
    config.with_user_esplora_url(url.replace("0.0.0.0", "127.0.0.1"));

    let mw = MutinyWalletBuilder::new(xpriv, storage)
        .with_config(config.build())
        .build()
        .await
        .expect("mutiny wallet should initialize");

    mw
}

pub async fn create_lnd() -> Lnd {
    PREMINE
        .get_or_init(|| async {
            generate_blocks_and_wait(101).await;
        })
        .await;

    let lnd_exe = env::var("LND_EXE")
        .ok()
        .or_else(lnd::downloaded_exe_path)
        .expect("you need to provide env var LND_EXE or specify an lnd version feature");
    let mut config = LndConf::default();
    config.view_stdout = false;
    let mut lnd = Lnd::with_conf(lnd_exe, &config, &BITCOIND).await.unwrap();
    let lightning = lnd.client.lightning();

    let lnd_address = lightning
        .new_address(NewAddressRequest {
            r#type: 2,
            ..Default::default()
        })
        .await
        .unwrap();
    let lnd_address = Address::from_str(&lnd_address.into_inner().address).unwrap();

    BITCOIND
        .client
        .send_to_address(
            &lnd_address.assume_checked(),
            Amount::from_sat(100_000_000),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

    generate_blocks_and_wait(1).await;

    // wait for lnd to sync
    for _ in 0..240 {
        let balance = lightning
            .wallet_balance(WalletBalanceRequest {})
            .await
            .unwrap();
        let balance = balance.into_inner();
        if balance.confirmed_balance >= 100_000_000 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    wait_for_lnd_sync(&mut lnd).await;

    lnd
}

pub async fn wait_for_lnd_sync(lnd: &mut Lnd) {
    let lightning = lnd.client.lightning();
    for _ in 0..240 {
        let info = lightning.get_info(GetInfoRequest {}).await.unwrap();
        let info = info.into_inner();
        if info.synced_to_chain {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    panic!("lnd did not sync");
}

pub async fn fund_mutiny_wallet(mw: &MutinyWallet<MemoryStorage>) {
    let address = mw.node_manager.get_new_address(vec![]).unwrap();
    let unchecked_address = Address::from_str(&address.to_string()).unwrap();

    let tx_details = mw
        .node_manager
        .check_address(unchecked_address.clone())
        .await
        .unwrap();
    assert!(tx_details.is_none());

    BITCOIND
        .client
        .send_to_address(
            &address,
            Amount::from_sat(100_000_000),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

    generate_blocks_and_wait(1).await;

    let tx_details = mw
        .node_manager
        .check_address(unchecked_address.clone())
        .await
        .unwrap();

    assert!(tx_details.is_some());
}

pub async fn get_lnd_connection_info(lnd: &mut Lnd) -> PubkeyConnectionInfo {
    let lightning = lnd.client.lightning();
    let info = lightning.get_info(GetInfoRequest {}).await.unwrap();
    let info = info.into_inner();

    let connection_string = format!(
        "{}@{}",
        info.identity_pubkey,
        lnd.listen_url.as_deref().unwrap()
    );

    PubkeyConnectionInfo::new(&connection_string).unwrap()
}

pub async fn open_channel_from_mutiny(mw: &MutinyWallet<MemoryStorage>, lnd: &mut Lnd) {
    // get some coins in the wallet
    fund_mutiny_wallet(&mw).await;
    // make sure lnd is synced
    wait_for_lnd_sync(lnd).await;

    let connection_info = get_lnd_connection_info(lnd).await;
    mw.node_manager
        .connect_to_peer(None, &connection_info.original_connection_string, None)
        .await
        .unwrap();

    // wait for stable connection
    tokio::time::sleep(Duration::from_millis(250)).await;

    let chan = mw
        .node_manager
        .sweep_all_to_channel(Some(connection_info.pubkey))
        .await
        .unwrap();
    assert!(!chan.is_usable);

    generate_blocks_and_wait(6).await;

    // wait for channel to be usable
    tokio::time::sleep(Duration::from_secs(2)).await;
    wait_for_lnd_sync(lnd).await;

    let chans = mw.node_manager.list_channels().await.unwrap();
    assert_eq!(chans.len(), 1);
    assert!(chans[0].is_usable);
    assert!(chans[0].is_anchor);
}

pub async fn open_channel_from_lnd(mw: &MutinyWallet<MemoryStorage>, lnd: &mut Lnd) {
    let connection_info = get_lnd_connection_info(lnd).await;
    mw.node_manager
        .connect_to_peer(None, &connection_info.original_connection_string, None)
        .await
        .unwrap();

    // wait for stable connection
    tokio::time::sleep(Duration::from_secs(1)).await;

    let node = mw.node_manager.list_nodes().await.unwrap()[0];
    let lightning = lnd.client.lightning();

    let _ = lightning
        .open_channel_sync(OpenChannelRequest {
            node_pubkey: node.encode(),
            local_funding_amount: 1_000_000,
            private: true,
            ..Default::default()
        })
        .await
        .unwrap();

    generate_blocks_and_wait(6).await;

    // wait for channel to be usable
    tokio::time::sleep(Duration::from_secs(2)).await;
    wait_for_lnd_sync(lnd).await;

    let chans = mw.node_manager.list_channels().await.unwrap();
    assert_eq!(chans.len(), 1);
    assert!(chans[0].is_usable);
    assert!(chans[0].is_anchor);
}
