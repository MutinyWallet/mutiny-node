use crate::error;
use bip32::XPrv;
use bitcoin::secp256k1::PublicKey;
use log::info;

pub struct Node {
    pub node_id: String,
    pub pubkey: PublicKey,
    pub xpriv: XPrv,
}

impl Node {
    pub fn new(node_id: String, pubkey: PublicKey, xpriv: XPrv) -> Result<Self, error::Error> {
        info!("initialized a new node: {pubkey}");

        Ok(Node {
            node_id,
            pubkey,
            xpriv,
        })
    }
}
