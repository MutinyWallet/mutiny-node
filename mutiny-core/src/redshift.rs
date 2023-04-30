use crate::error::MutinyError;
use crate::indexed_db::MutinyStorage;
use crate::nodemanager::NodeManager;
use crate::utils;
use crate::utils::sleep;
use anyhow::anyhow;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, OutPoint};
use log::{debug, error};
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
    pub sending_node: PublicKey,
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
    async fn await_chan_funding_tx(
        &self,
        sending_node: &PublicKey,
        user_channel_id: u128,
        timeout: u64,
    ) -> Result<OutPoint, MutinyError>;

    /// Initializes a redshift. Creates a new node and attempts
    /// to open a channel to the introduction node.
    async fn init_redshift(
        &self,
        utxo: OutPoint,
        recipient: RedshiftRecipient,
        introduction_node: Option<PublicKey>,
        connection_string: Option<&str>,
    ) -> Result<Redshift, MutinyError>;

    async fn attempt_payments(&self, rs: Redshift) -> Result<(), MutinyError>;
}

impl RedshiftManager for NodeManager {
    async fn await_chan_funding_tx(
        &self,
        sending_node: &PublicKey,
        user_channel_id: u128,
        timeout: u64,
    ) -> Result<OutPoint, MutinyError> {
        let node = {
            let nodes = self.nodes.lock().await;
            nodes.get(sending_node).unwrap().to_owned()
        };
        let start = utils::now().as_secs();
        loop {
            let channels = node.channel_manager.list_channels();
            let channel = channels
                .iter()
                .find(|c| c.user_channel_id == user_channel_id);

            if let Some(outpoint) = channel.and_then(|c| c.funding_txo) {
                return Ok(outpoint.into_bitcoin_outpoint());
            }

            let now = utils::now().as_secs();
            if now - start > timeout {
                return Err(MutinyError::PaymentTimeout);
            }

            sleep(250).await;
        }
    }

    async fn init_redshift(
        &self,
        utxo: OutPoint,
        recipient: RedshiftRecipient,
        introduction_node: Option<PublicKey>,
        connection_string: Option<&str>,
    ) -> Result<Redshift, MutinyError> {
        // verify utxo exists
        let utxos = self.list_utxos()?;
        let u = utxos
            .iter()
            .find(|u| u.outpoint == utxo)
            .ok_or_else(|| MutinyError::Other(anyhow!("Could not find UTXO")))?;

        // create new node
        let node = self.new_node().await?;

        // connect to introduction node
        let introduction_node = match (introduction_node, connection_string) {
            (Some(i), Some(c)) => {
                let connect_string = format!("{i}@{c}");
                self.connect_to_peer(&node.pubkey, &connect_string, None)
                    .await?;
                i
            }
            _ => {
                // get the first LSP as the introduction node
                // TODO allow falling back to others
                if self.lsp_clients.is_empty() {
                    return Err(MutinyError::LspFailure);
                } else {
                    self.lsp_clients.first().unwrap().pubkey
                }
            }
        };

        // generate random user channel id
        let mut user_channel_id_bytes = [0u8; 16];
        getrandom::getrandom(&mut user_channel_id_bytes)
            .map_err(|_| MutinyError::Other(anyhow!("Failed to generate user channel id")))?;
        let user_chan_id = u128::from_be_bytes(user_channel_id_bytes);

        // initiate channel open
        let channel = self
            .sweep_utxos_to_channel(Some(user_chan_id), &node.pubkey, &[utxo], introduction_node)
            .await?;

        // fees paid for opening channel.
        let fees = u.txout.value - channel.size;

        let channel_outpoint = self
            .await_chan_funding_tx(&node.pubkey, user_chan_id, 60)
            .await?;

        // save to db
        let redshift = Redshift {
            id: user_chan_id,
            input_utxo: utxo,
            status: RedshiftStatus::ChannelOpening,
            sending_node: node.pubkey,
            recipient,
            output_utxo: None,
            introduction_channel: Some(channel_outpoint),
            output_channel: None,
            introduction_node,
            amount_sats: u.txout.value,
            change_amt: None,
            fees_paid: fees,
        };
        self.storage.update_redshift(redshift.clone())?;

        Ok(redshift)
    }

    async fn attempt_payments(&self, mut rs: Redshift) -> Result<(), MutinyError> {
        // TODO find the max channel reserve
        let max_sats = (rs.amount_sats as f64 * 0.99) as u64;
        let _min_sats = 10_000;

        // get the node making the payment
        let nodes = self.nodes.lock().await;
        let sending_node = nodes.get(&rs.sending_node).ok_or(MutinyError::NotFound)?;

        let receiving_node = match rs.recipient {
            RedshiftRecipient::Lightning(receiving_pubkey) => {
                nodes.get(&receiving_pubkey).ok_or(MutinyError::NotFound)?
            }
            RedshiftRecipient::OnChain(_) => {
                // TODO specific address
                let new_receiving_node = self.new_node().await?.pubkey;
                nodes
                    .get(&new_receiving_node)
                    .ok_or(MutinyError::NotFound)?
            }
        };

        // TODO for loop while max_sats is not hit
        // TODO get the real number to attempt
        let local_max = max_sats;

        // get an invoice from the receiving node
        let invoice = receiving_node
            .create_invoice(Some(local_max), None, None)
            .await?; // TODO probably should handle error

        // make attempts to pay it
        match sending_node
            .pay_invoice_with_timeout(&invoice, None, None)
            .await
        {
            Ok(i) => {
                if i.paid {
                    debug!("paid the redshift invoice");
                    rs.payment_attempted(local_max);
                } else {
                    // TODO need to handle payments still pending
                    debug!("payment still pending...");
                }
            }
            Err(e) => {
                // TODO keep going through loop
                error!("could not pay: {e}");
                return Err(MutinyError::RoutingFailed);
            }
        }

        // TODO once completely done, close the existing channel

        Ok(())
    }
}
