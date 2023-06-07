use crate::error::MutinyError;
use crate::nodemanager::NodeManager;
use crate::storage::MutinyStorage;
use crate::utils;
use crate::utils::sleep;
use anyhow::anyhow;
use bitcoin::hashes::hex::ToHex;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, OutPoint};
use lightning::{log_debug, log_error, log_info};
use lightning::{log_warn, util::logger::Logger};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::Ordering;

// When creating a new node sleep for 5 seconds to give it time to start up.
const NEW_NODE_SLEEP_DURATION: i32 = 5_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RedshiftStatus {
    /// The channel to the introduction node is opening.
    /// We are waiting for the channel to open before we can
    /// send the payment.
    ChannelOpening,
    /// The channel to the introduction node is open.
    /// We are ready to being attempting payments.
    ChannelOpened,
    /// The channel to the introduction node is open.
    /// We are attempting to pay the receiving node.
    AttemptingPayments,
    /// The payments have been completed and now
    /// we are attempting to close the channels.
    ClosingChannels,
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
            RedshiftStatus::ChannelOpened => true,
            RedshiftStatus::AttemptingPayments => true,
            RedshiftStatus::ClosingChannels => true,
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
    pub id: [u8; 16],
    pub input_utxo: OutPoint,
    pub status: RedshiftStatus,
    pub sending_node: PublicKey,
    pub recipient: RedshiftRecipient,
    /// The node that will receive the lightning payment.
    /// This will be one of Mutiny's internal nodes.
    pub receiving_node: Option<PublicKey>,
    pub output_utxo: Option<OutPoint>,
    pub introduction_channel: Option<OutPoint>,
    /// output_channel will be None if being kept in lightning, this is only relevant when the
    /// channels will be closed into an on chain address
    pub output_channel: Option<Vec<OutPoint>>,
    pub introduction_node: PublicKey,
    pub amount_sats: u64,
    pub sats_sent: u64,
    pub change_amt: Option<u64>,
    pub fees_paid: u64,
}

impl Redshift {
    pub fn channel_opened(&mut self, chan_id: OutPoint) {
        self.introduction_channel = Some(chan_id);
        self.status = RedshiftStatus::ChannelOpened;
    }

    pub fn payment_successful(&mut self, amount: u64, fees_paid: u64) {
        self.sats_sent += amount;
        self.fees_paid += fees_paid;
    }

    pub fn fail(&mut self, error: String) {
        self.status = RedshiftStatus::Failed(error);
    }
}

pub trait RedshiftStorage {
    fn get_redshift(&self, utxo: &[u8; 16]) -> Result<Option<Redshift>, MutinyError>;
    fn get_redshifts(&self) -> Result<Vec<Redshift>, MutinyError>;
    fn persist_redshift(&self, redshift: Redshift) -> Result<(), MutinyError>;
}

const REDSHIFT_KEY_PREFIX: &str = "redshift/";

fn get_redshift_key(id: &[u8; 16]) -> String {
    format!("{REDSHIFT_KEY_PREFIX}{}", id.to_hex())
}

impl<S: MutinyStorage> RedshiftStorage for S {
    fn get_redshift(&self, id: &[u8; 16]) -> Result<Option<Redshift>, MutinyError> {
        let redshifts = self.get_data(get_redshift_key(id))?;
        Ok(redshifts)
    }

    fn get_redshifts(&self) -> Result<Vec<Redshift>, MutinyError> {
        let map: HashMap<String, Redshift> = self.scan(REDSHIFT_KEY_PREFIX, None)?;
        Ok(map.values().map(|v| v.to_owned()).collect())
    }

    fn persist_redshift(&self, redshift: Redshift) -> Result<(), MutinyError> {
        self.set_data(get_redshift_key(&redshift.id), redshift)
    }
}

pub trait RedshiftManager {
    /// Initializes a redshift. Creates a new node and attempts
    /// to open a channel to the introduction node.
    async fn init_redshift(
        &self,
        utxo: OutPoint,
        recipient: RedshiftRecipient,
        introduction_node: Option<PublicKey>,
        connection_string: Option<&str>,
    ) -> Result<Redshift, MutinyError>;

    fn get_redshift(&self, id: &[u8; 16]) -> Result<Option<Redshift>, MutinyError>;

    async fn attempt_payments(&self, rs: Redshift) -> Result<(), MutinyError>;

    async fn close_channels(&self, rs: Redshift) -> Result<(), MutinyError>;
}

impl<S: MutinyStorage> RedshiftManager for NodeManager<S> {
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

        sleep(NEW_NODE_SLEEP_DURATION).await;

        // connect to introduction node
        let introduction_node = match (introduction_node, connection_string) {
            (Some(i), Some(c)) => {
                let connect_string = format!("{i}@{c}");
                self.connect_to_peer(&node.pubkey, &connect_string, None)
                    .await?;
                i
            }
            (Some(i), None) => {
                let node = self.get_node(&node.pubkey).await?;

                if node.peer_manager.get_peer_node_ids().contains(&i) {
                    i
                } else {
                    return Err(MutinyError::Other(anyhow!(
                        "Could not connect to introduction node"
                    )));
                }
            }
            _ => {
                // TODO this would be better if it was a random node
                let node = self.get_node(&node.pubkey).await?;
                match &node.lsp_client {
                    Some(lsp) => lsp.pubkey,
                    None => return Err(MutinyError::LspFailure),
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
            .sweep_utxos_to_channel(
                Some(user_chan_id),
                &node.pubkey,
                &[utxo],
                Some(introduction_node),
            )
            .await?;

        // fees paid for opening channel.
        let fees = u.txout.value - channel.size;

        // save to db
        let redshift = Redshift {
            id: user_chan_id.to_be_bytes(),
            input_utxo: utxo,
            status: RedshiftStatus::ChannelOpening,
            sending_node: node.pubkey,
            recipient,
            receiving_node: None,
            output_utxo: None,
            introduction_channel: channel.outpoint,
            output_channel: None,
            introduction_node,
            amount_sats: u.txout.value,
            sats_sent: 0,
            change_amt: None,
            fees_paid: fees,
        };
        self.storage.persist_redshift(redshift.clone())?;

        Ok(redshift)
    }

    fn get_redshift(&self, id: &[u8; 16]) -> Result<Option<Redshift>, MutinyError> {
        self.storage.get_redshift(id)
    }

    async fn attempt_payments(&self, mut rs: Redshift) -> Result<(), MutinyError> {
        log_info!(
            &self.logger,
            "Attempting payments for redshift {}",
            rs.id.to_hex()
        );

        // get the node making the payment
        let sending_node = self.get_node(&rs.sending_node).await?;

        // find the channel reserve the introduction channel
        // TODO use outbound_capacity_msat
        let reserve = match rs.introduction_channel {
            None => 0,
            Some(chan) => sending_node
                .channel_manager
                .list_channels()
                .iter()
                .find_map(|c| {
                    if c.funding_txo.map(|u| u.into_bitcoin_outpoint()) == Some(chan) {
                        c.unspendable_punishment_reserve
                    } else {
                        None
                    }
                })
                .unwrap_or(0),
        };

        // original utxo value - opening tx fee - channel reserve
        let max_sats = rs.amount_sats - rs.fees_paid - reserve;
        // account for Voltage LSP minimum
        let min_sats = utils::min_lightning_amount(self.get_network());

        let receiving_node = match rs.recipient {
            RedshiftRecipient::Lightning(receiving_pubkey) => {
                self.get_node(&receiving_pubkey).await?
            }
            RedshiftRecipient::OnChain(_) => {
                let new_receiving_node = self.new_node().await?.pubkey;
                // sleep to let new node init properly
                sleep(NEW_NODE_SLEEP_DURATION).await;

                self.get_node(&new_receiving_node).await?
            }
        };
        // save receiving node to db
        rs.receiving_node = Some(receiving_node.pubkey);
        self.storage.persist_redshift(rs.clone())?;

        // attempt payments in loop until we sent all or hit min sats
        let mut local_max_sats = max_sats;
        let get_invoice_failures = 0;
        loop {
            // stop looping if ordered to stop
            if self.stop.load(Ordering::Relaxed) {
                break;
            }

            log_debug!(
                &self.logger,
                "Looping through payments for redshift {}: sats={}",
                rs.id.to_hex(),
                local_max_sats,
            );
            // keep trying until the amount is too small to send through
            if local_max_sats < min_sats {
                log_debug!(
                    &self.logger,
                    "Local max amount is less than min for redshift {}: sats={}",
                    rs.id.to_hex(),
                    local_max_sats,
                );
                // if no payments were made, consider it a fail
                if rs.sats_sent == 0 {
                    log_error!(
                        &self.logger,
                        "No payments were made for redshift {}: sats={}",
                        rs.id.to_hex(),
                        local_max_sats,
                    );
                    rs.fail("no payments were made".to_string());
                } else {
                    rs.status = RedshiftStatus::ClosingChannels;
                }
                break;
            }
            log_debug!(
                &self.logger,
                "Getting an invoice for redshift {}: sats={}",
                rs.id.to_hex(),
                local_max_sats,
            );

            // get an invoice from the receiving node
            let invoice = match receiving_node
                .create_invoice(Some(local_max_sats), vec!["Redshift".to_string()], None)
                .await
            {
                Ok(i) => i,
                Err(_) => {
                    if get_invoice_failures > 3 {
                        break;
                    }
                    log_debug!(
                        &self.logger,
                        "Could not get an invoice, trying again for redshift {}",
                        rs.id.to_hex(),
                    );
                    sleep(1000).await;
                    continue;
                }
            };

            log_debug!(
                &self.logger,
                "created invoice: {}",
                invoice.payment_hash().to_hex()
            );

            let label = format!("Redshift: {}", rs.id.to_hex());
            // make attempts to pay it
            match sending_node
                .pay_invoice_with_timeout(&invoice, None, None, vec![label])
                .await
            {
                Ok(i) => {
                    if i.paid {
                        let amount_sent = i.amount_sats.expect("invoice must have amount");
                        log_debug!(
                            &self.logger,
                            "successfully paid the redshift invoice {amount_sent} sats"
                        );
                        // update the redshift with the payment
                        rs.payment_successful(amount_sent, i.fees_paid.unwrap_or(0));

                        // check if the max amount was sent on all tries
                        if rs.sats_sent >= max_sats {
                            rs.status = RedshiftStatus::ClosingChannels;
                            break;
                        }

                        // save to db, to update the frontend
                        // do it after the if statement so we don't save the redshift twice
                        self.storage.persist_redshift(rs.clone())?;

                        // keep trying with the remaining amount
                        local_max_sats = max_sats.saturating_sub(rs.sats_sent);
                    } else {
                        // TODO need to handle payments still pending
                        log_debug!(&self.logger, "payment still pending...");
                    }
                }
                Err(e) => {
                    log_error!(&self.logger, "could not pay: {e}");
                    // Keep trying to pay but go down 5% of the channel amount
                    let decrement = (max_sats as f64 * 0.05) as u64;
                    local_max_sats = local_max_sats.saturating_sub(decrement);
                }
            }
        }

        log_debug!(
            &self.logger,
            "Redshift {} completed with status: {:?}",
            rs.id.to_hex(),
            rs.status
        );

        // save to db
        self.storage.persist_redshift(rs.clone())?;

        // begin closing channels
        self.close_channels(rs).await?;

        Ok(())
    }

    async fn close_channels(&self, mut rs: Redshift) -> Result<(), MutinyError> {
        // close introduction channel
        match rs.introduction_channel.as_ref() {
            Some(chan) => {
                self.close_channel(chan).await?
                // todo need to set change amount to on the amount we get back
            }
            None => log_debug!(&self.logger, "no introduction channel to close"),
        }

        // close receiving channel(s)
        match &rs.recipient {
            RedshiftRecipient::Lightning(_) => {} // Keep channel open in lightning case
            RedshiftRecipient::OnChain(_addr) => {
                let receiving_node = match &rs.receiving_node {
                    None => {
                        log_error!(
                            &self.logger,
                            "no receiving node for redshift {}, cannot close channels",
                            rs.id.to_hex()
                        );
                        return Err(MutinyError::Other(anyhow!(
                            "No receiving node for on-chain redshift"
                        )));
                    }
                    Some(node) => self.get_node(node).await?,
                };

                // close all the channels that were opened on the receiving node, if the receiving
                // node was only created temporarily for the purpose of being thrown away
                // record all of the channel outpoints.
                let mut channel_outpoints: Vec<OutPoint> = vec![];
                for c in receiving_node.channel_manager.list_channels() {
                    if let Some(funding_txo) = c.funding_txo {
                        let channel_outpoint = funding_txo.into_bitcoin_outpoint();
                        self.close_channel(&channel_outpoint).await?;
                        channel_outpoints.push(channel_outpoint);
                    }
                }
                // Set rs.output_channel to None if channel_outpoints is empty
                rs.output_channel = if channel_outpoints.is_empty() {
                    log_warn!(
                        &self.logger,
                        "Expecting at least one channel from a receiving redshift node to close..."
                    );
                    None
                } else {
                    Some(channel_outpoints)
                };
            }
        }

        // TODO archive nodes afterwards

        rs.status = RedshiftStatus::Completed;
        // save to db
        self.storage.persist_redshift(rs)?;

        Ok(())
    }
}

// TODO add more redshift tests
#[cfg(test)]
mod test {
    use crate::storage::MemoryStorage;
    use std::str::FromStr;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    use crate::test_utils::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    fn dummy_redshift() -> Redshift {
        let pubkey = PublicKey::from_str(
            "02465ed5be53d04fde66c9418ff14a5f2267723810176c9212b722e542dc1afb1b",
        )
        .unwrap();

        Redshift {
            id: [0u8; 16],
            input_utxo: Default::default(),
            status: RedshiftStatus::ChannelOpening,
            sending_node: pubkey,
            recipient: RedshiftRecipient::OnChain(None),
            receiving_node: None,
            output_utxo: None,
            introduction_channel: None,
            output_channel: None,
            introduction_node: pubkey,
            amount_sats: 69_420,
            sats_sent: 0,
            change_amt: None,
            fees_paid: 123,
        }
    }

    #[test]
    async fn test_redshift_persistence() {
        let test_name = "test_create_signature";
        log!("{}", test_name);

        let storage = MemoryStorage::default();
        let rs = dummy_redshift();

        assert!(storage.get_redshifts().unwrap().is_empty());

        storage.persist_redshift(rs.clone()).unwrap();

        let read = storage.get_redshift(&rs.id).unwrap();
        assert_eq!(read.unwrap(), rs);

        let all = storage.get_redshifts().unwrap();
        assert_eq!(all, vec![rs]);
    }
}
