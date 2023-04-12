use crate::gossip::read_peer_info;
use crate::node::NetworkGraph;
use crate::{
    gossip, ldkstorage::PhantomChannelManager, logging::MutinyLogger, socket::WsSocketDescriptor,
};
use bitcoin::secp256k1::PublicKey;
use bitcoin::BlockHash;
use lightning::chain::keysinterface::PhantomKeysManager;
use lightning::ln::features::{InitFeatures, NodeFeatures};
use lightning::ln::msgs;
use lightning::ln::msgs::{LightningError, NetAddress, RoutingMessageHandler};
use lightning::ln::peer_handler::PeerHandleError;
use lightning::ln::peer_handler::{IgnoringMessageHandler, PeerManager as LdkPeerManager};
use lightning::routing::gossip::NodeId;
use lightning::routing::utxo::{UtxoLookup, UtxoLookupError, UtxoResult};
use lightning::util::events::{MessageSendEvent, MessageSendEventsProvider};
use log::warn;
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

pub(crate) trait PeerManager {
    fn get_peer_node_ids(&self) -> Vec<PublicKey>;

    fn new_outbound_connection(
        &self,
        their_node_id: PublicKey,
        descriptor: WsSocketDescriptor,
        remote_network_address: Option<NetAddress>,
    ) -> Result<Vec<u8>, PeerHandleError>;

    fn new_inbound_connection(
        &self,
        descriptor: WsSocketDescriptor,
        remote_network_address: Option<NetAddress>,
    ) -> Result<(), PeerHandleError>;

    fn write_buffer_space_avail(
        &self,
        descriptor: &mut WsSocketDescriptor,
    ) -> Result<(), PeerHandleError>;

    fn read_event(
        &self,
        descriptor: &mut WsSocketDescriptor,
        data: &[u8],
    ) -> Result<bool, PeerHandleError>;

    fn process_events(&self);

    fn socket_disconnected(&self, descriptor: &mut WsSocketDescriptor);

    fn disconnect_by_node_id(&self, node_id: PublicKey);

    fn disconnect_all_peers(&self);

    fn timer_tick_occurred(&self);

    fn broadcast_node_announcement(
        &self,
        rgb: [u8; 3],
        alias: [u8; 32],
        addresses: Vec<NetAddress>,
    );
}

pub(crate) type PeerManagerImpl = LdkPeerManager<
    WsSocketDescriptor,
    Arc<PhantomChannelManager>,
    Arc<GossipMessageHandler>,
    Arc<IgnoringMessageHandler>,
    Arc<MutinyLogger>,
    Arc<IgnoringMessageHandler>,
    Arc<PhantomKeysManager>,
>;

impl PeerManager for PeerManagerImpl {
    fn get_peer_node_ids(&self) -> Vec<PublicKey> {
        self.get_peer_node_ids().into_iter().map(|x| x.0).collect()
    }

    fn new_outbound_connection(
        &self,
        their_node_id: PublicKey,
        descriptor: WsSocketDescriptor,
        remote_network_address: Option<NetAddress>,
    ) -> Result<Vec<u8>, PeerHandleError> {
        self.new_outbound_connection(their_node_id, descriptor, remote_network_address)
    }

    fn new_inbound_connection(
        &self,
        descriptor: WsSocketDescriptor,
        remote_network_address: Option<NetAddress>,
    ) -> Result<(), PeerHandleError> {
        self.new_inbound_connection(descriptor, remote_network_address)
    }

    fn write_buffer_space_avail(
        &self,
        descriptor: &mut WsSocketDescriptor,
    ) -> Result<(), PeerHandleError> {
        self.write_buffer_space_avail(descriptor)
    }

    fn read_event(
        &self,
        peer_descriptor: &mut WsSocketDescriptor,
        data: &[u8],
    ) -> Result<bool, PeerHandleError> {
        self.read_event(peer_descriptor, data)
    }

    fn process_events(&self) {
        self.process_events()
    }

    fn socket_disconnected(&self, descriptor: &mut WsSocketDescriptor) {
        self.socket_disconnected(descriptor)
    }

    fn disconnect_by_node_id(&self, node_id: PublicKey) {
        self.disconnect_by_node_id(node_id)
    }

    fn disconnect_all_peers(&self) {
        self.disconnect_all_peers()
    }

    fn timer_tick_occurred(&self) {
        self.timer_tick_occurred()
    }

    fn broadcast_node_announcement(
        &self,
        rgb: [u8; 3],
        alias: [u8; 32],
        addresses: Vec<NetAddress>,
    ) {
        self.broadcast_node_announcement(rgb, alias, addresses)
    }
}

#[derive(Clone)]
pub struct GossipMessageHandler {
    pub(crate) network_graph: Arc<NetworkGraph>,
}

impl MessageSendEventsProvider for GossipMessageHandler {
    fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> {
        Vec::new()
    }
}

// I needed some type to implement RoutingMessageHandler, but I don't want to implement it
// we don't need to lookup UTXOs, so we can just return an error
// This should never actually be called because we are passing in None for the UTXO lookup
struct ErroringUtxoLookup {}
impl UtxoLookup for ErroringUtxoLookup {
    fn get_utxo(&self, _genesis_hash: &BlockHash, _short_channel_id: u64) -> UtxoResult {
        UtxoResult::Sync(Err(UtxoLookupError::UnknownTx))
    }
}

impl RoutingMessageHandler for GossipMessageHandler {
    fn handle_node_announcement(
        &self,
        msg: &msgs::NodeAnnouncement,
    ) -> Result<bool, LightningError> {
        let msg_clone = msg.clone();
        spawn_local(async move {
            // We use RGS to sync gossip, but we can save the node's metadata (alias and color)
            // we should only save it for relevant peers however (i.e. peers we have a channel with)
            if read_peer_info(&msg_clone.contents.node_id)
                .await
                .ok()
                .flatten()
                .is_some()
            {
                let node_id = msg_clone.contents.node_id;
                if let Err(e) = gossip::save_ln_peer_info(&node_id, &msg_clone.into()).await {
                    warn!("Failed to save node announcement for {node_id}: {e}");
                }
            }
        });

        // because we got the announcement, may as well update our network graph
        self.network_graph.update_node_from_announcement(msg)?;

        Ok(false)
    }

    fn handle_channel_announcement(
        &self,
        msg: &msgs::ChannelAnnouncement,
    ) -> Result<bool, LightningError> {
        // because we got the channel, may as well update our network graph
        self.network_graph
            .update_channel_from_announcement::<Arc<ErroringUtxoLookup>>(msg, &None)?;
        Ok(false)
    }

    fn handle_channel_update(&self, msg: &msgs::ChannelUpdate) -> Result<bool, LightningError> {
        // because we got the update, may as well update our network graph
        self.network_graph.update_channel(msg)?;
        Ok(false)
    }

    fn get_next_channel_announcement(
        &self,
        _starting_point: u64,
    ) -> Option<(
        msgs::ChannelAnnouncement,
        Option<msgs::ChannelUpdate>,
        Option<msgs::ChannelUpdate>,
    )> {
        None
    }

    fn get_next_node_announcement(
        &self,
        _starting_point: Option<&NodeId>,
    ) -> Option<msgs::NodeAnnouncement> {
        None
    }

    fn peer_connected(
        &self,
        _their_node_id: &PublicKey,
        _init: &msgs::Init,
        _inbound: bool,
    ) -> Result<(), ()> {
        Ok(())
    }

    fn handle_reply_channel_range(
        &self,
        _their_node_id: &PublicKey,
        _msg: msgs::ReplyChannelRange,
    ) -> Result<(), LightningError> {
        Ok(())
    }

    fn handle_reply_short_channel_ids_end(
        &self,
        _their_node_id: &PublicKey,
        _msg: msgs::ReplyShortChannelIdsEnd,
    ) -> Result<(), LightningError> {
        Ok(())
    }

    fn handle_query_channel_range(
        &self,
        _their_node_id: &PublicKey,
        _msg: msgs::QueryChannelRange,
    ) -> Result<(), LightningError> {
        Ok(())
    }

    fn handle_query_short_channel_ids(
        &self,
        _their_node_id: &PublicKey,
        _msg: msgs::QueryShortChannelIds,
    ) -> Result<(), LightningError> {
        Ok(())
    }

    fn processing_queue_high(&self) -> bool {
        false
    }

    fn provided_node_features(&self) -> NodeFeatures {
        NodeFeatures::empty()
    }

    fn provided_init_features(&self, _their_node_id: &PublicKey) -> InitFeatures {
        InitFeatures::empty()
    }
}
