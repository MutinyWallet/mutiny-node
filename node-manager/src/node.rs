use std::sync::Arc;

use crate::{
    error::MutinyError,
    keymanager::{create_keys_manager, pubkey_from_keys_manager},
    logging::MutinyLogger,
    nodemanager::NodeIndex,
};
use bip39::Mnemonic;
use bitcoin::secp256k1::PublicKey;
use lightning::chain::keysinterface::KeysManager;
use lightning::routing::gossip;
use log::info;

pub(crate) type NetworkGraph = gossip::NetworkGraph<Arc<MutinyLogger>>;

pub struct Node {
    pub uuid: String,
    pub pubkey: PublicKey,
    pub keys_manager: Arc<KeysManager>,
}

impl Node {
    pub(crate) fn new(node_index: NodeIndex, mnemonic: Mnemonic) -> Result<Self, MutinyError> {
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
