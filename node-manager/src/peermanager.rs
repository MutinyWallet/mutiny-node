use crate::{ldkstorage::PhantomChannelManager, logging::MutinyLogger, socket::WsSocketDescriptor};
use bitcoin::secp256k1::PublicKey;
use lightning::ln::msgs::NetAddress;
use lightning::ln::peer_handler::PeerHandleError;
use lightning::ln::peer_handler::{IgnoringMessageHandler, PeerManager as LdkPeerManager};
use std::sync::Arc;

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

    fn disconnect_by_node_id(&self, node_id: PublicKey, no_connection_possible: bool);

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
    Arc<IgnoringMessageHandler>,
    Arc<IgnoringMessageHandler>,
    Arc<MutinyLogger>,
    Arc<IgnoringMessageHandler>,
    Arc<PhantomChannelManager>,
>;

impl PeerManager for PeerManagerImpl {
    fn get_peer_node_ids(&self) -> Vec<PublicKey> {
        self.get_peer_node_ids()
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

    fn disconnect_by_node_id(&self, node_id: PublicKey, no_connection_possible: bool) {
        self.disconnect_by_node_id(node_id, no_connection_possible)
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
