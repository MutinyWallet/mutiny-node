use crate::dlc::DlcHandler;
use crate::error::MutinyError;
use crate::logging::MutinyLogger;
use crate::storage::MutinyStorage;
use bitcoin::hashes::hex::ToHex;
use dlc::secp256k1_zkp::PublicKey;
use dlc_manager::Storage;
use dlc_messages::message_handler::read_dlc_message;
use dlc_messages::{Message, WireMessage};
use lightning::ln::wire::Type;
use lightning::util::logger::Logger;
use lightning::util::ser::{Readable, Writeable};
use lightning::{log_info, log_warn};
use nostr::key::{Keys, XOnlyPublicKey};
use nostr::prelude::{decrypt, encrypt, Parity};
use nostr::Url;
use nostr::{Event, EventBuilder, EventId, Filter, Kind, Tag};
use std::io::Read;
use std::sync::Arc;

pub const DLC_WIRE_MESSAGE_KIND: Kind = Kind::Ephemeral(28_888);

/// A wrapper around a DLC message that indicates if it is an error
pub(crate) enum DlcMessageType {
    Normal(Message),
    Error([u8; 32]),
}

/// Handles Nostr DLC events
pub struct NostrDlcHandler<S: MutinyStorage> {
    key: Keys,
    pub relay: Url,
    dlc: Arc<DlcHandler<S>>,
    logger: Arc<MutinyLogger>,
}

impl<S: MutinyStorage> NostrDlcHandler<S> {
    pub fn new(key: Keys, relay: Url, dlc: Arc<DlcHandler<S>>, logger: Arc<MutinyLogger>) -> Self {
        Self {
            key,
            relay,
            dlc,
            logger,
        }
    }

    /// Returns the public key of the handler, this is the key that is used to send and receive events
    pub fn public_key(&self) -> XOnlyPublicKey {
        self.key.public_key()
    }

    /// A nostr filter that can be used to subscribe to events for this handler, this should be used to subscribe to events
    pub fn create_wire_msg_filter(&self) -> Filter {
        Filter::new()
            .kind(DLC_WIRE_MESSAGE_KIND)
            .pubkey(self.key.public_key())
    }

    /// Turns an DLC message into a Nostr event
    pub(crate) fn create_wire_msg_event(
        &self,
        to: XOnlyPublicKey,
        event_id: Option<EventId>,
        msg: DlcMessageType,
    ) -> Result<Event, MutinyError> {
        let bytes = match msg {
            DlcMessageType::Normal(msg) => {
                let mut bytes = msg.type_id().encode();
                bytes.extend(msg.encode());
                bytes
            }
            DlcMessageType::Error(err) => {
                let mut bytes = 0u16.encode();
                bytes.extend(err);
                bytes
            }
        };
        let content = encrypt(&self.key.secret_key().unwrap(), &to, base64::encode(bytes))?;
        let p_tag = Tag::PublicKey {
            public_key: to,
            relay_url: None,
            alias: None,
            uppercase: false,
        };
        let e_tag = event_id.map(|event_id| Tag::Event {
            event_id,
            relay_url: None,
            marker: None,
        });
        let tags = [Some(p_tag), e_tag]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let event = EventBuilder::new(DLC_WIRE_MESSAGE_KIND, content, tags).to_event(&self.key)?;

        Ok(event)
    }

    /// Parses a Nostr event into a DLC message
    pub(crate) fn parse_wire_msg_event(
        &self,
        event: &Event,
    ) -> Result<DlcMessageType, MutinyError> {
        // Decrypt the message and parse to bytes
        let content = decrypt(
            &self.key.secret_key().unwrap(),
            &event.pubkey,
            &event.content,
        )?;
        let bytes = base64::decode(content)?;
        let mut cursor = lightning::io::Cursor::new(&bytes);

        // Parse the message
        let msg_type: u16 = Readable::read(&mut cursor)?;

        // If the message is an error, return it
        if msg_type == 0 {
            let mut err = [0u8; 32];
            cursor.read_exact(&mut err)?;
            return Ok(DlcMessageType::Error(err));
        }

        let Some(wire) = read_dlc_message(msg_type, &mut cursor)? else {
            log_warn!(self.logger, "Error reading message {}", bytes.to_hex());
            return Err(MutinyError::DLCManagerError);
        };

        match wire {
            WireMessage::Message(msg) => Ok(DlcMessageType::Normal(msg)),
            WireMessage::SegmentStart(_) | WireMessage::SegmentChunk(_) => {
                Err(MutinyError::InvalidArgumentsError)
            }
        }
    }

    /// Handles a DLC wire event, returns an event to reply with if needed
    pub async fn handle_dlc_wire_event(&self, event: Event) -> Result<Option<Event>, MutinyError> {
        // Only handle DLC wire messages
        if event.kind != DLC_WIRE_MESSAGE_KIND {
            return Ok(None);
        }
        log_info!(self.logger, "Received DLC wire message");

        let msg = self.parse_wire_msg_event(&event).map_err(|e| {
            log_warn!(self.logger, "Error parsing DLC wire message: {e:?}");
            e
        })?;

        match msg {
            DlcMessageType::Normal(msg) => {
                let pubkey =
                    PublicKey::from_slice(&event.pubkey.public_key(Parity::Even).serialize())
                        .expect("converting pubkey between crates should not fail");
                let mut dlc = self.dlc.manager.lock().await;

                match dlc.on_dlc_message(&msg, pubkey) {
                    Err(e) => {
                        log_warn!(self.logger, "Error handling DLC message: {e:?}");
                        let id = match msg {
                            Message::Offer(o) => o.temporary_contract_id,
                            Message::Accept(a) => a.temporary_contract_id,
                            Message::Sign(s) => s.contract_id,
                            _ => [0u8; 32],
                        };
                        let err = DlcMessageType::Error(id);
                        let event =
                            self.create_wire_msg_event(event.pubkey, Some(event.id), err)?;
                        Ok(Some(event))
                    }
                    Ok(Some(msg)) => {
                        let event = self.create_wire_msg_event(
                            event.pubkey,
                            Some(event.id),
                            DlcMessageType::Normal(msg),
                        )?;
                        Ok(Some(event))
                    }
                    Ok(None) => Ok(None),
                }
            }
            DlcMessageType::Error(id) => {
                // delete contract since it failed
                let dlc = self.dlc.manager.lock().await;
                dlc.get_store().delete_contract(&id)?;

                Ok(None)
            }
        }
    }
}

#[cfg(test)]
#[cfg(target_arch = "wasm32")]
mod wasm_test {
    use super::*;
    use crate::storage::MemoryStorage;
    use crate::test_utils::create_node;
    use dlc_messages::OfferDlc;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn test_dlc_serialization() {
        let storage = MemoryStorage::default();
        let node = create_node(storage.clone()).await;
        let dlc = Arc::new(DlcHandler::new(node.wallet.clone(), node.logger.clone()).unwrap());
        let handler = NostrDlcHandler::new(
            Keys::generate(),
            Url::parse("https://nostr.mutinywallet.com").unwrap(),
            dlc,
            node.logger.clone(),
        );

        let input = include_str!("../../test_inputs/dlc_offer.json");
        let offer: OfferDlc = serde_json::from_str(input).unwrap();
        let msg = DlcMessageType::Normal(Message::Offer(offer.clone()));

        let event = handler
            .create_wire_msg_event(handler.public_key(), None, msg)
            .unwrap();
        let parsed = handler.parse_wire_msg_event(&event).unwrap();

        match parsed {
            DlcMessageType::Normal(Message::Offer(parsed_offer)) => assert_eq!(offer, parsed_offer),
            _ => panic!("Wrong message type"),
        }

        // test error parsing
        let id = [3u8; 32];
        let msg = DlcMessageType::Error(id);

        let event = handler
            .create_wire_msg_event(handler.public_key(), None, msg)
            .unwrap();
        let parsed = handler.parse_wire_msg_event(&event).unwrap();

        match parsed {
            DlcMessageType::Error(error_id) => assert_eq!(id, error_id),
            _ => panic!("Wrong message type"),
        }
    }
}
