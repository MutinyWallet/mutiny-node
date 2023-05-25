use crate::error::MutinyError;
use crate::nodemanager::NodeManager;
use crate::storage::MutinyStorage;
use crate::utils;
use anyhow::anyhow;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey};
use lightning::util::logger::Logger;
use lightning::{log_error, log_warn};
use lightning_invoice::Invoice;
use nostr::key::SecretKey;
use nostr::nips::nip47::{
    ErrorCode, Method, NIP47Error, NostrWalletConnectURI, Request, Response, ResponseResult,
};
use nostr::prelude::{decrypt, encrypt};
use nostr::{Event, EventBuilder, EventId, Filter, Keys, Kind, Tag, Timestamp};
use nostr_sdk::Client;
use std::str::FromStr;

const MAX_ZAP_AMOUNT_SATS: u64 = 10_000;

/// Manages Nostr keys and has different utilities for nostr specific things
pub struct NostrManager {
    /// Primary key used for nostr, this will be used for signing events
    pub primary_key: Keys,
    /// Client key used for Nostr Wallet Connect.
    /// Mutiny will never use this key but it will be given to the client
    /// in the connect URI.
    nwc_client_key: Keys,
    /// Server key used for Nostr Wallet Connect.
    /// The nostr client will use this key to encrypt messages to the wallet.
    /// Mutiny will use this key to decrypt messages from the nostr client.
    nwc_server_key: Keys,
    pub relays: Vec<String>,
}

impl NostrManager {
    fn derive_nostr_key(xprivkey: ExtendedPrivKey, index: i32) -> Result<Keys, MutinyError> {
        let context = Secp256k1::new();

        let path = DerivationPath::from_str(&format!("m/44'/1237'/{index}'/0/0"))?;
        let key = xprivkey.derive_priv(&context, &path)?;

        // just converting to nostr secret key, unwrap is safe
        let secret_key = SecretKey::from_slice(&key.private_key.secret_bytes()).unwrap();
        Ok(Keys::new(secret_key))
    }

    /// Creates a new NostrManager
    pub fn from_mnemonic(
        xprivkey: ExtendedPrivKey,
        relays: Vec<String>,
    ) -> Result<Self, MutinyError> {
        if relays.is_empty() {
            return Err(MutinyError::Other(anyhow!("No relays provided")));
        }

        let primary_key = Self::derive_nostr_key(xprivkey, 0)?;
        let nwc_client_key = Self::derive_nostr_key(xprivkey, 1)?;
        let nwc_server_key = Self::derive_nostr_key(xprivkey, 2)?;

        Ok(Self {
            primary_key,
            nwc_client_key,
            nwc_server_key,
            relays,
        })
    }

    pub fn get_nwc_uri(&self) -> anyhow::Result<String> {
        let relay_url = self.relays.first().ok_or(anyhow!("No relays"))?;
        let uri = NostrWalletConnectURI::new(
            self.nwc_server_key.public_key(),
            relay_url.parse()?,
            Some(self.nwc_client_key.secret_key().unwrap()),
            None,
        )?;

        Ok(uri.to_string())
    }

    pub fn create_nwc_filter(&self) -> Filter {
        let client_pubkey = self.nwc_client_key.public_key();
        let server_pubkey = self.nwc_server_key.public_key();

        let fifteen_mins_ago = utils::now().as_secs() - 15 * 60;

        Filter::new()
            .kinds(vec![Kind::WalletConnectRequest])
            .author(client_pubkey.to_string())
            .pubkey(server_pubkey)
            .since(Timestamp::from(fifteen_mins_ago))
    }

    /// Create Nostr Wallet Connect Info event
    pub fn create_nwc_info_event(&self) -> anyhow::Result<Event> {
        let info = EventBuilder::new(Kind::WalletConnectInfo, "pay_invoice".to_string(), &[])
            .to_event(&self.nwc_server_key)?;
        Ok(info)
    }

    pub async fn broadcast_nwc_info_event(&self) -> anyhow::Result<EventId> {
        let client = Client::new(&self.nwc_server_key);
        client.add_relays(self.relays.clone()).await?;
        client.connect().await;

        let info = self.create_nwc_info_event()?;
        let event_id = client.send_event(info).await?;

        Ok(event_id)
    }

    /// Handle a Nostr Wallet Connect request, returns a response event if one is needed
    pub async fn handle_nwc_request<S: MutinyStorage>(
        &self,
        event: Event,
        node_manager: &NodeManager<S>,
        from_node: &PublicKey,
    ) -> anyhow::Result<Option<Event>> {
        let client_pubkey = self.nwc_client_key.public_key();
        if event.kind == Kind::WalletConnectRequest && event.pubkey == client_pubkey {
            let server_key = self.nwc_server_key.secret_key()?;

            let decrypted = decrypt(&server_key, &client_pubkey, &event.content)?;
            let req: Request = Request::from_json(decrypted)?;

            // only respond to pay invoice requests
            if req.method != Method::PayInvoice {
                return Ok(None);
            }

            let invoice = Invoice::from_str(&req.params.invoice)
                .map_err(|_| anyhow!("Failed to parse invoice"))?;
            let msats = invoice.amount_milli_satoshis().unwrap_or(0);

            // verify amount is under 10k sats
            let content = if msats <= MAX_ZAP_AMOUNT_SATS * 1_000 {
                // todo we could get the author of the event we zapping and use that as the label
                let labels = vec!["Zap!".to_string()];
                match node_manager
                    .pay_invoice(from_node, &invoice, None, labels)
                    .await
                {
                    Ok(inv) => {
                        // preimage should be set after a successful payment
                        let preimage = inv.preimage.expect("preimage not set");
                        Response {
                            result_type: Method::PayInvoice,
                            error: None,
                            result: Some(ResponseResult { preimage }),
                        }
                    }
                    Err(e) => {
                        log_error!(node_manager.logger, "failed to pay invoice: {e}");
                        Response {
                            result_type: Method::PayInvoice,
                            error: Some(NIP47Error {
                                code: ErrorCode::InsufficantBalance,
                                message: format!("Failed to pay invoice: {e}"),
                            }),
                            result: None,
                        }
                    }
                }
            } else {
                log_warn!(
                    node_manager.logger,
                    "Invoice amount too high: {msats} msats"
                );

                Response {
                    result_type: Method::PayInvoice,
                    error: Some(NIP47Error {
                        code: ErrorCode::QuotaExceeded,
                        message: format!("Invoice amount too high: {msats} msats"),
                    }),
                    result: None,
                }
            };

            let encrypted = encrypt(&server_key, &client_pubkey, content.as_json())?;

            let p_tag = Tag::PubKey(event.pubkey, None);
            let e_tag = Tag::Event(event.id, None, None);
            let response =
                EventBuilder::new(Kind::WalletConnectResponse, encrypted, &[p_tag, e_tag])
                    .to_event(&self.nwc_server_key)?;

            return Ok(Some(response));
        }

        Ok(None)
    }
}
