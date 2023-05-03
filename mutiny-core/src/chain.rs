use std::sync::Arc;

use crate::esplora::EsploraSyncClient;
use bdk_macros::maybe_await;
use bitcoin::hashes::hex::ToHex;
use bitcoin::{Script, Transaction, Txid};
use lightning::chain::chaininterface::BroadcasterInterface;
use lightning::chain::{Filter, WatchedOutput};
use lightning::util::ser::Writeable;
use log::error;
use nostr_sdk::{Client, Keys, Tag};
use wasm_bindgen_futures::spawn_local;

use crate::logging::MutinyLogger;

pub struct MutinyChain {
    pub tx_sync: Arc<EsploraSyncClient<Arc<MutinyLogger>>>,
    network_magic: [u8; 4],
}

impl MutinyChain {
    pub(crate) fn new(
        tx_sync: Arc<EsploraSyncClient<Arc<MutinyLogger>>>,
        network_magic: [u8; 4],
    ) -> Self {
        Self {
            tx_sync,
            network_magic,
        }
    }

    async fn broadcast_tx_over_nostr(
        tx: &Transaction,
        network_magic: [u8; 4],
    ) -> anyhow::Result<()> {
        // Generate new keys
        let ephemeral_key: Keys = Keys::generate();

        // Create new client
        let client = Client::new(&ephemeral_key);

        // TODO make relays configurable
        // Add relays
        client.add_relay("wss://relay.damus.io").await?;
        client.add_relay("wss://nostr.mutinywallet.com").await?;
        client.add_relay("wss://relay.nostr.info").await?;

        // Connect to relays
        client.connect().await;

        let tag = Tag::Generic("magic".into(), vec![network_magic.to_hex()]);
        let base64_tx = base64::encode(tx.encode());
        let event = nostr_sdk::event::builder::EventBuilder::new(28333.into(), base64_tx, &[tag])
            .to_event(&ephemeral_key)?;

        client.send_event(event).await?;

        client.disconnect().await?;

        Ok(())
    }
}

impl Filter for MutinyChain {
    fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
        self.tx_sync.register_tx(txid, script_pubkey);
    }

    fn register_output(&self, output: WatchedOutput) {
        self.tx_sync.register_output(output);
    }
}

impl BroadcasterInterface for MutinyChain {
    fn broadcast_transaction(&self, tx: &Transaction) {
        let blockchain = self.tx_sync.clone();
        let tx_clone = tx.clone();
        let magic = self.network_magic;
        spawn_local(async move {
            // broadcast to esplora client
            maybe_await!(blockchain.client().broadcast(&tx_clone))
                .unwrap_or_else(|_| error!("failed to broadcast tx! {}", tx_clone.txid()));

            // broadcast to nostr
            MutinyChain::broadcast_tx_over_nostr(&tx_clone, magic)
                .await
                .unwrap_or_else(|_| {
                    error!("failed to broadcast tx over nostr! {}", tx_clone.txid())
                });
        });
    }
}
