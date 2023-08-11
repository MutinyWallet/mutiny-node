use std::sync::Arc;

use ldk_lsp_client::LSPS_MESSAGE_TYPE_ID;
use crate::{scb::message_handler::SCBMessageHandler, node::LiquidityManager, storage::MutinyStorage};

use lightning::ln::wire::{Type, CustomMessageReader};
use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::ln::msgs::{DecodeError, LightningError};
use lightning::io::{Error, Read};
use lightning::util::ser::{Writer, Writeable};
use lightning::ln::features::{InitFeatures, NodeFeatures};
use bitcoin::secp256k1::PublicKey;

pub struct MutinyMessageHandler<S: MutinyStorage> {
    pub liquidity: Arc<LiquidityManager<S>>,
    pub scb: Arc<SCBMessageHandler>
}

pub enum MutinyMessage<S: MutinyStorage> {
    Liquidity(<LiquidityManager<S> as CustomMessageReader>::CustomMessage),
    Scb(<SCBMessageHandler as CustomMessageReader>::CustomMessage)
}

impl<S: MutinyStorage> std::fmt::Debug for MutinyMessage<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Liquidity(arg0) => f.debug_tuple("Liquidity").field(arg0).finish(),
            Self::Scb(arg0) => f.debug_tuple("Scb").field(arg0).finish(),
        }
    }
}

impl<S: MutinyStorage> CustomMessageHandler for MutinyMessageHandler<S> {
    fn handle_custom_message(
        &self, msg: Self::CustomMessage, sender_node_id: &PublicKey
    ) -> Result<(), LightningError> {
        match msg {
            MutinyMessage::Liquidity(message) => {
                CustomMessageHandler::handle_custom_message(
                    self.liquidity.as_ref(), message, sender_node_id
                )
            },
            MutinyMessage::Scb(message) => {
                CustomMessageHandler::handle_custom_message(self.scb.as_ref(), message, sender_node_id)
            },
        }
    }

    fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)> {
        vec![].into_iter()
                .chain(
                    self.liquidity
                        .get_and_clear_pending_msg()
                        .into_iter()
                        .map(|(pubkey, message)| (pubkey, MutinyMessage::Liquidity(message)))
                )
                .chain(
                    self.scb
                        .get_and_clear_pending_msg()
                        .into_iter()
                        .map(|(pubkey, message)| (pubkey, MutinyMessage::Scb(message)))
                )
            .collect()
    }

    fn provided_node_features(&self) -> NodeFeatures {
        NodeFeatures::empty()
            | self.liquidity.provided_node_features()
            | self.scb.provided_node_features()
    }

    fn provided_init_features(
        &self, their_node_id: &PublicKey
    ) -> InitFeatures {
        InitFeatures::empty()
            | self.liquidity.provided_init_features(their_node_id)
            | self.scb.provided_init_features(their_node_id)
    }
}

impl<S: MutinyStorage> CustomMessageReader for MutinyMessageHandler<S> {
    type CustomMessage = MutinyMessage<S>;
    fn read<R: Read>(
        &self, message_type: u16, buffer: &mut R
    ) -> Result<Option<Self::CustomMessage>, DecodeError> {
        match message_type {
            LSPS_MESSAGE_TYPE_ID => {
                match <LiquidityManager<S> as CustomMessageReader>::read(&self.liquidity, message_type, buffer)? {
                    None => unreachable!(),
                    Some(message) => Ok(Some(MutinyMessage::Liquidity(message)))
                }
            }
            _ => Ok(None),
        }
    }
}

impl<S: MutinyStorage> Type for MutinyMessage<S> {
    fn type_id(&self) -> u16 {
        match self {
            MutinyMessage::Liquidity(message) => message.type_id(),
            MutinyMessage::Scb(message) => message.type_id()
        }
    }
}

impl<S: MutinyStorage> Writeable for MutinyMessage<S> {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
        match self {
            MutinyMessage::Liquidity(message) => message.write(writer),
            MutinyMessage::Scb(message) => message.write(writer),
        }
    }
}