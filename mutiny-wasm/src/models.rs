use bitcoin::hashes::hex::ToHex;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
#[wasm_bindgen]
pub struct MutinyInvoice {
    bolt11: Option<String>,
    description: Option<String>,
    payment_hash: String,
    preimage: Option<String>,
    payee_pubkey: Option<String>,
    pub amount_sats: Option<u64>,
    pub expire: u64,
    pub paid: bool,
    pub fees_paid: Option<u64>,
    pub is_send: bool,
}

#[wasm_bindgen]
impl MutinyInvoice {
    #[wasm_bindgen(getter)]
    pub fn bolt11(&self) -> Option<String> {
        self.bolt11.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn description(&self) -> Option<String> {
        self.description.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn payment_hash(&self) -> String {
        self.payment_hash.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn preimage(&self) -> Option<String> {
        self.preimage.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn payee_pubkey(&self) -> Option<String> {
        self.payee_pubkey.clone()
    }
}

impl From<mutiny_core::nodemanager::MutinyInvoice> for MutinyInvoice {
    fn from(m: mutiny_core::nodemanager::MutinyInvoice) -> Self {
        MutinyInvoice {
            bolt11: m.bolt11,
            description: m.description,
            payment_hash: m.payment_hash,
            preimage: m.preimage,
            payee_pubkey: m.payee_pubkey,
            amount_sats: m.amount_sats,
            expire: m.expire,
            paid: m.paid,
            fees_paid: m.fees_paid,
            is_send: m.is_send,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
#[wasm_bindgen]
pub struct MutinyPeer {
    pubkey: secp256k1::PublicKey,
    connection_string: String,
    pub is_connected: bool,
}

#[wasm_bindgen]
impl MutinyPeer {
    #[wasm_bindgen(getter)]
    pub fn pubkey(&self) -> String {
        self.pubkey.to_hex()
    }

    #[wasm_bindgen(getter)]
    pub fn connection_string(&self) -> String {
        self.connection_string.clone()
    }
}

impl From<mutiny_core::nodemanager::MutinyPeer> for MutinyPeer {
    fn from(m: mutiny_core::nodemanager::MutinyPeer) -> Self {
        MutinyPeer {
            pubkey: m.pubkey,
            connection_string: m.connection_string,
            is_connected: m.is_connected,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
#[wasm_bindgen]
pub struct MutinyChannel {
    pub balance: u64,
    pub size: u64,
    pub reserve: u64,
    outpoint: Option<String>,
    peer: String,
    pub confirmed: bool,
}

#[wasm_bindgen]
impl MutinyChannel {
    #[wasm_bindgen(getter)]
    pub fn outpoint(&self) -> Option<String> {
        self.outpoint.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn peer(&self) -> String {
        self.peer.clone()
    }
}

impl From<mutiny_core::nodemanager::MutinyChannel> for MutinyChannel {
    fn from(m: mutiny_core::nodemanager::MutinyChannel) -> Self {
        MutinyChannel {
            balance: m.balance,
            size: m.size,
            reserve: m.reserve,
            outpoint: m.outpoint,
            peer: m.peer,
            confirmed: m.confirmed,
        }
    }
}

#[wasm_bindgen]
pub struct MutinyBalance {
    pub confirmed: u64,
    pub unconfirmed: u64,
    pub lightning: u64,
}

impl From<mutiny_core::nodemanager::MutinyBalance> for MutinyBalance {
    fn from(m: mutiny_core::nodemanager::MutinyBalance) -> Self {
        MutinyBalance {
            confirmed: m.confirmed,
            unconfirmed: m.unconfirmed,
            lightning: m.lightning,
        }
    }
}

#[wasm_bindgen]
pub struct LnUrlParams {
    pub max: u64,
    pub min: u64,
    tag: String,
}

#[wasm_bindgen]
impl LnUrlParams {
    #[wasm_bindgen(getter)]
    pub fn tag(&self) -> String {
        self.tag.clone()
    }
}

impl From<mutiny_core::nodemanager::LnUrlParams> for LnUrlParams {
    fn from(m: mutiny_core::nodemanager::LnUrlParams) -> Self {
        LnUrlParams {
            max: m.max,
            min: m.min,
            tag: m.tag,
        }
    }
}

// This is the NodeIdentity that refer to a specific node
// Used for public facing identification.
#[wasm_bindgen]
pub struct NodeIdentity {
    uuid: String,
    pubkey: String,
}

#[wasm_bindgen]
impl NodeIdentity {
    #[wasm_bindgen(getter)]
    pub fn uuid(&self) -> String {
        self.uuid.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn pubkey(&self) -> String {
        self.pubkey.clone()
    }
}

impl From<mutiny_core::nodemanager::NodeIdentity> for NodeIdentity {
    fn from(m: mutiny_core::nodemanager::NodeIdentity) -> Self {
        NodeIdentity {
            uuid: m.uuid,
            pubkey: m.pubkey,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
#[wasm_bindgen]
pub struct MutinyBip21RawMaterials {
    address: String,
    invoice: String,
    btc_amount: Option<String>,
    description: Option<String>,
}

#[wasm_bindgen]
impl MutinyBip21RawMaterials {
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.address.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn invoice(&self) -> String {
        self.invoice.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn btc_amount(&self) -> Option<String> {
        self.btc_amount.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn description(&self) -> Option<String> {
        self.description.clone()
    }
}

impl From<mutiny_core::nodemanager::MutinyBip21RawMaterials> for MutinyBip21RawMaterials {
    fn from(m: mutiny_core::nodemanager::MutinyBip21RawMaterials) -> Self {
        MutinyBip21RawMaterials {
            address: m.address,
            invoice: m.invoice,
            btc_amount: m.btc_amount,
            description: m.description,
        }
    }
}
