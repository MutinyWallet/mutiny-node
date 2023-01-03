use crate::{ldkstorage::PhantomChannelManager, logging::MutinyLogger, socket::WsSocketDescriptor};
use lightning::ln::peer_handler::{IgnoringMessageHandler, PeerManager as LdkPeerManager};
use std::sync::Arc;

pub(crate) type PeerManager = LdkPeerManager<
    WsSocketDescriptor,
    Arc<PhantomChannelManager>,
    Arc<IgnoringMessageHandler>,
    Arc<IgnoringMessageHandler>,
    Arc<MutinyLogger>,
    Arc<IgnoringMessageHandler>,
>;
