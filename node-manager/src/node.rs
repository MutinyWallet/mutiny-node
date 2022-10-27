use std::sync::Arc;

use crate::{
    error,
    keymanager::{create_keys_manager, pubkey_from_keys_manager},
    nodemanager::NodeIndex,
};
use bip32::XPrv;
use bip39::Mnemonic;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use lightning::chain::keysinterface::{KeysInterface, KeysManager};
use log::info;

pub struct Node {
    pub uuid: String,
    pub pubkey: PublicKey,
    pub keys_manager: Arc<KeysManager>,
}

impl Node {
    pub fn new(node_index: NodeIndex, mnemonic: Mnemonic) -> Result<Self, error::Error> {
        info!("initialized a new node: {}", node_index.uuid);

        let keys_manager = create_keys_manager(mnemonic, node_index.child_index);
        let pubkey = pubkey_from_keys_manager(&keys_manager);

        Ok(Node {
            uuid: node_index.uuid,
            pubkey,
            keys_manager: Arc::new(keys_manager),
        })
    }
}
