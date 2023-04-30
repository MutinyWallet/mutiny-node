use crate::error::MutinyError;
use crate::indexed_db::MutinyStorage;
use crate::nodemanager::NodeManager;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, OutPoint};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RedshiftStatus {
    /// The channel to the introduction node is opening.
    /// We are waiting for the channel to open before we can
    /// send the payment.
    ChannelOpening,
    /// The channel to the introduction node is open.
    /// We are attempting to pay the receiving node.
    ///
    /// The u64 is the amount of sats we've successfully
    /// sent to the receiving node.
    AttemptingPayments(u64),
    /// The redshift was success and is now complete.
    Completed,
    /// The redshift failed. The error is given.
    Failed(String),
}

impl RedshiftStatus {
    /// Returns true if the redshift is in progress.
    pub fn is_in_progress(&self) -> bool {
        match self {
            RedshiftStatus::ChannelOpening => true,
            RedshiftStatus::AttemptingPayments(_) => true,
            RedshiftStatus::Completed => false,
            RedshiftStatus::Failed(_) => false,
        }
    }
}

/// Where the redshift final redshift payment is going.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RedshiftRecipient {
    /// Public key of one of Mutiny's internal nodes.
    Lightning(PublicKey),
    /// An address to send the final payment to.
    /// This will be from closing the final channel.
    ///
    /// If this is None, an address will be generated
    /// by the KeysManager.
    OnChain(Option<Address>),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Redshift {
    pub id: u128,
    pub input_utxo: OutPoint,
    pub status: RedshiftStatus,
    pub recipient: RedshiftRecipient,
    pub output_utxo: Option<OutPoint>,
    pub introduction_channel: Option<OutPoint>,
    pub output_channel: Option<OutPoint>,
    pub introduction_node: PublicKey,
    pub amount_sats: u64,
    pub change_amt: Option<u64>,
    pub fees_paid: u64,
}

impl Redshift {
    pub fn channel_opened(&mut self, chan_id: OutPoint) {
        self.introduction_channel = Some(chan_id);
        self.status = RedshiftStatus::AttemptingPayments(0);
    }

    pub fn payment_attempted(&mut self, amount: u64) {
        if let RedshiftStatus::AttemptingPayments(paid) = &mut self.status {
            *paid += amount;
        }
    }

    pub fn fail(&mut self, error: String) {
        self.status = RedshiftStatus::Failed(error);
    }
}

pub trait RedshiftStorage {
    fn get_redshifts_for_utxo(&self, utxo: &OutPoint) -> Result<Vec<Redshift>, MutinyError>;
    fn get_redshifts(&self) -> Result<Vec<Redshift>, MutinyError>;
    fn update_redshift(&self, redshift: Redshift) -> Result<(), MutinyError>;
}

const REDSHIFT_KEY_PREFIX: &str = "redshift/";

fn get_redshift_key(utxo: &OutPoint) -> String {
    format!("{REDSHIFT_KEY_PREFIX}{utxo}")
}

impl RedshiftStorage for MutinyStorage {
    fn get_redshifts_for_utxo(&self, utxo: &OutPoint) -> Result<Vec<Redshift>, MutinyError> {
        let redshifts = self.get(get_redshift_key(utxo))?;
        Ok(redshifts.unwrap_or_default())
    }

    fn get_redshifts(&self) -> Result<Vec<Redshift>, MutinyError> {
        let map: HashMap<String, Vec<Redshift>> = self.scan(REDSHIFT_KEY_PREFIX, None)?;
        Ok(map.values().flat_map(|v| v.to_owned()).collect())
    }

    fn update_redshift(&self, redshift: Redshift) -> Result<(), MutinyError> {
        let utxo = &redshift.input_utxo.clone();
        let mut redshifts = self.get_redshifts_for_utxo(utxo)?;

        if let Some(idx) = redshifts.iter().position(|s| s.id == redshift.id) {
            redshifts[idx] = redshift;
        } else {
            redshifts.push(redshift);
        };

        self.set(get_redshift_key(utxo), redshifts)
    }
}

pub trait RedshiftManager {
    /// Initializes a redshift. Creates a new node and attempts
    /// to open a channel to the introduction node.
    fn init_redshift(
        &self,
        utxo: OutPoint,
        recipient: RedshiftRecipient,
        introduction_node: PublicKey,
    ) -> Result<Redshift, MutinyError>;
}

impl RedshiftManager for NodeManager {
    fn init_redshift(
        &self,
        utxo: OutPoint,
        recipient: RedshiftRecipient,
        introduction_node: PublicKey,
    ) -> Result<Redshift, MutinyError> {
        todo!()
    }
}
