use crate::utils;
use crate::{error::MutinyError, peermanager::PeerManager};
use futures::{pin_mut, select, FutureExt};
use lightning::{ln::peer_handler, log_error, util::logger::Logger};
use lightning::{ln::peer_handler::SocketDescriptor, log_trace};
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(target_arch = "wasm32")]
use crate::networking::ws_socket::WsTcpSocketDescriptor;

#[cfg(not(target_arch = "wasm32"))]
use crate::networking::tcp_socket::TcpSocketDescriptor;

pub trait ReadDescriptor {
    async fn read(&self) -> Option<Result<Vec<u8>, MutinyError>>;
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum MutinySocketDescriptor {
    #[cfg(target_arch = "wasm32")]
    Tcp(WsTcpSocketDescriptor),
    #[cfg(not(target_arch = "wasm32"))]
    Native(TcpSocketDescriptor),
}

impl ReadDescriptor for MutinySocketDescriptor {
    async fn read(&self) -> Option<Result<Vec<u8>, MutinyError>> {
        match self {
            #[cfg(target_arch = "wasm32")]
            MutinySocketDescriptor::Tcp(s) => s.read().await,
            #[cfg(not(target_arch = "wasm32"))]
            MutinySocketDescriptor::Native(s) => s.read().await,
        }
    }
}

impl peer_handler::SocketDescriptor for MutinySocketDescriptor {
    fn send_data(&mut self, data: &[u8], resume_read: bool) -> usize {
        match self {
            #[cfg(target_arch = "wasm32")]
            MutinySocketDescriptor::Tcp(s) => s.send_data(data, resume_read),
            #[cfg(not(target_arch = "wasm32"))]
            MutinySocketDescriptor::Native(s) => s.send_data(data, resume_read),
        }
    }

    fn disconnect_socket(&mut self) {
        match self {
            #[cfg(target_arch = "wasm32")]
            MutinySocketDescriptor::Tcp(s) => s.disconnect_socket(),
            #[cfg(not(target_arch = "wasm32"))]
            MutinySocketDescriptor::Native(s) => s.disconnect_socket(),
        }
    }
}

pub fn schedule_descriptor_read(
    mut descriptor: MutinySocketDescriptor,
    peer_manager: Arc<dyn PeerManager>,
    logger: Arc<dyn Logger>,
    stop: Arc<AtomicBool>,
) {
    log_trace!(logger, "scheduling descriptor reader");
    let descriptor_clone = descriptor.clone();
    utils::spawn(async move {
        loop {
            let mut read_fut = Box::pin(descriptor_clone.read()).fuse();
            let delay_fut = Box::pin(utils::sleep(1_000)).fuse();
            pin_mut!(delay_fut);
            select! {
                msg_option = read_fut => {
                    if let Some(msg) = msg_option {
                        match msg {
                            Ok(b) => {
                                log_trace!(logger, "received binary data from websocket");

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
                                break;
                            }
                        }
                    }
                }
                _ = delay_fut => {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                }
            }
        }
        log_trace!(logger, "WebSocket Closed")
    });
}
