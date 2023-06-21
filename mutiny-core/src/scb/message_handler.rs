use crate::utils::Mutex;
use bitcoin::secp256k1::PublicKey;
use lightning::ln::msgs::{ChannelReestablish, OptionalField};
use lightning::ln::msgs::{DecodeError, LightningError};
use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::ln::wire::CustomMessageReader;
use std::collections::VecDeque;

/// Custom message handler for Static Channel Backups.
///
/// This will send bogus channel reestablish messages to the peer, which will
/// trigger the peer to close the channel on our behalf.
pub struct SCBMessageHandler {
    msg_events: Mutex<VecDeque<(PublicKey, ChannelReestablish)>>,
}

impl Default for SCBMessageHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SCBMessageHandler {
    /// Creates a new instance of a [`SCBMessageHandler`]
    pub fn new() -> Self {
        SCBMessageHandler {
            msg_events: Mutex::new(VecDeque::new()),
        }
    }

    /// Send a message to the peer with given node id. Note that the message is not
    /// sent right away, but only when the LDK
    /// [`lightning::ln::peer_handler::PeerManager::process_events`] is next called.
    pub fn request_channel_close(&self, node_id: PublicKey, channel_id: [u8; 32]) {
        let msg = ChannelReestablish {
            channel_id,
            next_local_commitment_number: 0,
            next_remote_commitment_number: 0,
            data_loss_protect: OptionalField::Absent,
        };
        self.msg_events.lock().unwrap().push_back((node_id, msg));
    }

    /// Returns whether the message handler has any message to be sent.
    pub fn has_pending_messages(&self) -> bool {
        !self.msg_events.lock().unwrap().is_empty()
    }
}

/// Dummy implementation of [`CustomMessageReader`] for [`SCBMessageHandler`].
/// We are just sending [`ChannelReestablish`] messages, which are not
/// custom messages, but we need to implement this trait to be able to use
/// the [`CustomMessageHandler`] trait.
impl CustomMessageReader for SCBMessageHandler {
    type CustomMessage = ChannelReestablish;
    fn read<R: lightning::io::Read>(
        &self,
        _msg_type: u16,
        _buffer: &mut R,
    ) -> Result<Option<Self::CustomMessage>, DecodeError> {
        Ok(None)
    }
}

impl CustomMessageHandler for SCBMessageHandler {
    fn handle_custom_message(
        &self,
        _msg: ChannelReestablish,
        _org: &PublicKey,
    ) -> Result<(), LightningError> {
        // We don't need to do anything here, since we are just sending
        Ok(())
    }

    fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)> {
        self.msg_events.lock().unwrap().drain(..).collect()
    }
}
