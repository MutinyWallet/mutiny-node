#![cfg(not(target_arch = "wasm32"))]
#![cfg(test)]

use crate::utils::*;
use electrsd::bitcoind::bitcoincore_rpc::RpcApi;
use lnd::tonic_lnd::lnrpc::channel_point::FundingTxid;
use lnd::tonic_lnd::lnrpc::{ChannelPoint, CloseChannelRequest, InvoiceRequest, SendRequest};
use mutiny_core::bitcoin::{Address, Amount};
use mutiny_core::event::HTLCStatus;
use mutiny_core::lightning_invoice::Bolt11Invoice;
use std::str::FromStr;
use std::time::Duration;

mod utils;

#[tokio::test]
async fn test_fund_mutiny_wallet() {
    let mw = create_mutiny_wallet().await;

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

#[tokio::test]
async fn test_open_channel_from_mutiny() {
    let mw = create_mutiny_wallet().await;
    let mut lnd = create_lnd().await;
    open_channel_from_mutiny(&mw, &mut lnd).await;
}

#[tokio::test]
async fn test_open_channel_from_lnd() {
    let mw = create_mutiny_wallet().await;
    let mut lnd = create_lnd().await;
    open_channel_from_lnd(&mw, &mut lnd).await;
}

#[tokio::test]
async fn test_pay_invoice() {
    let mw = create_mutiny_wallet().await;
    let mut lnd = create_lnd().await;
    open_channel_from_mutiny(&mw, &mut lnd).await;

    let lightning = lnd.client.lightning();
    let resp = lightning
        .add_invoice(InvoiceRequest {
            memo: "".to_string(),
            value_msat: 10_000_000, // 10k sats
            private: false,
            is_keysend: false,
            is_amp: false,
        })
        .await
        .unwrap();
    let invoice = Bolt11Invoice::from_str(&resp.into_inner().payment_request).unwrap();

    let inv = mw.pay_invoice(&invoice, None, vec![]).await.unwrap();

    assert_eq!(inv.status, HTLCStatus::Succeeded);
    assert!(inv.preimage.is_some());
    assert!(inv.fees_paid.is_some());
}

/// Open a channel from mutiny to lnd and then have mutiny force close it
#[tokio::test]
async fn force_close_outbound_channel_from_mutiny() {
    let mw = create_mutiny_wallet().await;
    let mut lnd = create_lnd().await;
    open_channel_from_mutiny(&mw, &mut lnd).await;

    let starting_balance = mw.get_balance().await.unwrap();
    assert_eq!(starting_balance.on_chain(), 0);
    assert_eq!(starting_balance.lightning, 99_997_780);

    let channel = mw.node_manager.list_channels().await.unwrap()[0].clone();
    mw.node_manager
        .close_channel(&channel.outpoint.unwrap(), None, true, false)
        .await
        .unwrap();

    let new_balance = mw.get_balance().await.unwrap();
    assert_eq!(new_balance.on_chain(), starting_balance.on_chain());
    assert_eq!(new_balance.lightning, 0);
    assert_eq!(new_balance.force_close, 99_994_310);

    // generate some blocks for ldk to handle the force close
    generate_blocks_and_wait(6).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    generate_blocks_and_wait(300).await;

    // need to sleep for ldk to handle the sweep
    // fixme figure out how to lower this
    tokio::time::sleep(Duration::from_secs(40)).await;

    // wait for mutiny to sync and sweep the channel
    for _ in 0..10 {
        generate_blocks_and_wait(6).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        let balance = mw.get_balance().await.unwrap();
        if balance.on_chain() > starting_balance.on_chain() && balance.force_close == 0 {
            break;
        }
    }

    // check that we swept the channel
    let final_balance = mw.get_balance().await.unwrap();
    assert_eq!(final_balance.lightning, 0);
    assert_eq!(final_balance.force_close, 0);
    assert!(final_balance.on_chain() > starting_balance.on_chain());
}

/// Open a channel from lnd to mutiny and then have mutiny force close it
#[tokio::test]
async fn force_close_inbound_channel_from_mutiny() {
    let mw = create_mutiny_wallet().await;
    let mut lnd = create_lnd().await;
    open_channel_from_lnd(&mw, &mut lnd).await;

    let invoice = mw.create_lightning_invoice(10_000, vec![]).await.unwrap();

    let lightning = lnd.client.lightning();
    let resp = lightning
        .send_payment_sync(SendRequest {
            payment_request: invoice.bolt11.unwrap().to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    let resp = resp.into_inner();
    assert_eq!(resp.payment_error, "");

    // wait for payment to complete
    tokio::time::sleep(Duration::from_secs(1)).await;

    let starting_balance = mw.get_balance().await.unwrap();
    assert_eq!(starting_balance.on_chain(), 0);
    assert_eq!(starting_balance.lightning, 10_000);

    let channel = mw.node_manager.list_channels().await.unwrap()[0].clone();
    mw.node_manager
        .close_channel(&channel.outpoint.unwrap(), None, true, false)
        .await
        .unwrap();

    let new_balance = mw.get_balance().await.unwrap();
    assert_eq!(new_balance.on_chain(), starting_balance.on_chain());
    assert_eq!(new_balance.lightning, 0);
    assert_eq!(new_balance.force_close, 10_000);

    // generate some blocks for ldk to handle the force close
    generate_blocks_and_wait(6).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    generate_blocks_and_wait(300).await;

    // need to sleep for ldk to handle the sweep
    // fixme figure out how to lower this
    tokio::time::sleep(Duration::from_secs(40)).await;

    // wait for mutiny to sync and sweep the channel
    for _ in 0..10 {
        generate_blocks_and_wait(6).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        let balance = mw.get_balance().await.unwrap();
        if balance.on_chain() > starting_balance.on_chain() && balance.force_close == 0 {
            break;
        }
    }

    // check that we swept the channel
    let final_balance = mw.get_balance().await.unwrap();
    assert_eq!(final_balance.lightning, 0);
    assert_eq!(final_balance.force_close, 0);
    assert_eq!(final_balance.on_chain(), 7_550);
}

/// Open a channel from mutiny to lnd and then have lnd force close it
#[tokio::test]
async fn force_close_outbound_channel_from_lnd() {
    let mw = create_mutiny_wallet().await;
    let mut lnd = create_lnd().await;
    open_channel_from_mutiny(&mw, &mut lnd).await;

    let starting_balance = mw.get_balance().await.unwrap();
    assert_eq!(starting_balance.on_chain(), 0);
    assert_eq!(starting_balance.lightning, 99_997_780);

    // force close the channel
    let channel = mw.node_manager.list_channels().await.unwrap()[0]
        .outpoint
        .clone()
        .unwrap();
    let lightning = lnd.client.lightning();
    lightning
        .close_channel(CloseChannelRequest {
            channel_point: Some(ChannelPoint {
                output_index: channel.vout,
                funding_txid: Some(FundingTxid::FundingTxidStr(channel.txid.to_string())),
            }),
            force: true,
            ..Default::default()
        })
        .await
        .unwrap();

    // mine the close transaction
    generate_blocks_and_wait(1).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let new_balance = mw.get_balance().await.unwrap();
    assert_eq!(new_balance.on_chain(), starting_balance.on_chain());
    assert_eq!(new_balance.lightning, 0);
    assert_eq!(new_balance.force_close, 99_994_310);

    // generate some blocks for ldk to handle the force close
    generate_blocks_and_wait(6).await;

    // wait for mutiny to sync and sweep the channel
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let balance = mw.get_balance().await.unwrap();
        if balance.on_chain() > starting_balance.on_chain() && balance.force_close == 0 {
            break;
        }
    }

    // check that we swept the channel
    let final_balance = mw.get_balance().await.unwrap();
    assert_eq!(final_balance.lightning, 0);
    assert_eq!(final_balance.force_close, 0);
    assert!(final_balance.on_chain() > starting_balance.on_chain());
}

/// Open a channel from lnd to mutiny and then have lnd force close it
#[tokio::test]
async fn force_close_inbound_channel_from_lnd() {
    let mw = create_mutiny_wallet().await;
    let mut lnd = create_lnd().await;
    open_channel_from_lnd(&mw, &mut lnd).await;

    let invoice = mw.create_lightning_invoice(100_000, vec![]).await.unwrap();

    let lightning = lnd.client.lightning();
    let resp = lightning
        .send_payment_sync(SendRequest {
            payment_request: invoice.bolt11.unwrap().to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    let resp = resp.into_inner();
    assert_eq!(resp.payment_error, "");

    // wait for payment to complete
    tokio::time::sleep(Duration::from_secs(1)).await;

    let starting_balance = mw.get_balance().await.unwrap();
    assert_eq!(starting_balance.on_chain(), 0);
    assert_eq!(starting_balance.lightning, 100_000);

    // force close the channel
    let channel = mw.node_manager.list_channels().await.unwrap()[0]
        .outpoint
        .clone()
        .unwrap();
    let lightning = lnd.client.lightning();
    lightning
        .close_channel(CloseChannelRequest {
            channel_point: Some(ChannelPoint {
                output_index: channel.vout,
                funding_txid: Some(FundingTxid::FundingTxidStr(channel.txid.to_string())),
            }),
            force: true,
            ..Default::default()
        })
        .await
        .unwrap();

    // mine the close transaction and wait mutiny to sync
    generate_blocks_and_wait(3).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let new_balance = mw.get_balance().await.unwrap();
    assert_eq!(new_balance.on_chain(), starting_balance.on_chain());
    assert_eq!(new_balance.lightning, 0);
    assert_eq!(new_balance.force_close, 100_000);

    // wait for mutiny to sync and sweep the channel
    for _ in 0..10 {
        generate_blocks_and_wait(6).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        let balance = mw.get_balance().await.unwrap();
        if balance.on_chain() > starting_balance.on_chain() && balance.force_close == 0 {
            break;
        }
    }

    // check that we swept the channel
    let final_balance = mw.get_balance().await.unwrap();
    assert_eq!(final_balance.lightning, 0);
    assert_eq!(final_balance.force_close, 0);
    assert_eq!(final_balance.on_chain(), 97_550);
}
