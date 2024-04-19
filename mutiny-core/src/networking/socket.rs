use crate::logging::MutinyLogger;
use crate::utils;
use crate::{error::MutinyError, peermanager::PeerManager};
use futures::{pin_mut, select, FutureExt};
use lightning::{ln::peer_handler, log_error, util::logger::Logger};
use lightning::{ln::peer_handler::SocketDescriptor, log_trace};
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::networking::ws_socket::WsTcpSocketDescriptor;

pub trait ReadDescriptor {
    async fn read(&self) -> Option<Result<Vec<u8>, MutinyError>>;
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum MutinySocketDescriptor {
    Tcp(WsTcpSocketDescriptor),
}

impl ReadDescriptor for MutinySocketDescriptor {
    async fn read(&self) -> Option<Result<Vec<u8>, MutinyError>> {
        match self {
            MutinySocketDescriptor::Tcp(s) => s.read().await,
        }
    }
}

impl peer_handler::SocketDescriptor for MutinySocketDescriptor {
    fn send_data(&mut self, data: &[u8], resume_read: bool) -> usize {
        match self {
            MutinySocketDescriptor::Tcp(s) => s.send_data(data, resume_read),
        }
    }

    fn disconnect_socket(&mut self) {
        match self {
            MutinySocketDescriptor::Tcp(s) => s.disconnect_socket(),
        }
    }
}

pub fn schedule_descriptor_read<P: PeerManager>(
    mut descriptor: MutinySocketDescriptor,
    peer_manager: Arc<P>,
    logger: Arc<MutinyLogger>,
    stop: Arc<AtomicBool>,
) {
    log_trace!(logger, "scheduling descriptor reader");
    let descriptor_clone = descriptor.clone();
    utils::spawn(async move {
        loop {
            let read_fut = Box::pin(descriptor_clone.read()).fuse();
            if let Some(msg) = read_fut.await {
                match msg {
                    Ok(b) => {
                        log_trace!(logger, "received binary data from websocket: {}", b.len());

                        let read_res = peer_manager.read_event(&mut descriptor, &b);
                        match read_res {
                            Ok(_read_bool) => {
                                peer_manager.process_events();
                            }
                            Err(e) => log_error!(logger, "got an error reading event: {}", e),
                        }
                    }
                    Err(e) => {
                        log_error!(logger, "got an error reading msg: {}", e);
                        descriptor.disconnect_socket();
                        peer_manager.socket_disconnected(&mut descriptor);
                        peer_manager.process_events();
                        break;
                    }
                }
            }
        }
        log_trace!(logger, "WebSocket Closed")
    });
}
