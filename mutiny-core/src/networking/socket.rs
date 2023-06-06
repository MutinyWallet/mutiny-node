use crate::peermanager::PeerManager;
use crate::utils;
use futures::{pin_mut, select, FutureExt};
use gloo_net::websocket::Message;
use lightning::{ln::peer_handler, log_debug, log_error, util::logger::Logger};
use lightning::{ln::peer_handler::SocketDescriptor, log_trace};
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(target_arch = "wasm32")]
use crate::networking::ws_socket::{SubWsSocketDescriptor, WsTcpSocketDescriptor};

pub trait ReadDescriptor {
    async fn read(&self) -> Option<Result<Message, gloo_net::websocket::WebSocketError>>;
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum MutinySocketDescriptor {
    #[cfg(target_arch = "wasm32")]
    Tcp(WsTcpSocketDescriptor),
    #[cfg(target_arch = "wasm32")]
    Mutiny(SubWsSocketDescriptor),
    #[cfg(not(target_arch = "wasm32"))]
    Native(), // TODO this might not be the best approach
}

impl ReadDescriptor for MutinySocketDescriptor {
    async fn read(&self) -> Option<Result<Message, gloo_net::websocket::WebSocketError>> {
        match self {
            #[cfg(target_arch = "wasm32")]
            MutinySocketDescriptor::Tcp(s) => s.read().await,
            #[cfg(target_arch = "wasm32")]
            MutinySocketDescriptor::Mutiny(s) => s.read().await,
            #[cfg(not(target_arch = "wasm32"))]
            MutinySocketDescriptor::Native() => todo!(),
        }
    }
}

impl peer_handler::SocketDescriptor for MutinySocketDescriptor {
    fn send_data(&mut self, data: &[u8], resume_read: bool) -> usize {
        match self {
            #[cfg(target_arch = "wasm32")]
            MutinySocketDescriptor::Tcp(s) => s.send_data(data, resume_read),
            #[cfg(target_arch = "wasm32")]
            MutinySocketDescriptor::Mutiny(s) => s.send_data(data, resume_read),
            #[cfg(not(target_arch = "wasm32"))]
            MutinySocketDescriptor::Native() => todo!(),
        }
    }

    fn disconnect_socket(&mut self) {
        match self {
            #[cfg(target_arch = "wasm32")]
            MutinySocketDescriptor::Tcp(s) => s.disconnect_socket(),
            #[cfg(target_arch = "wasm32")]
            MutinySocketDescriptor::Mutiny(s) => s.disconnect_socket(),
            #[cfg(not(target_arch = "wasm32"))]
            MutinySocketDescriptor::Native() => todo!(),
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
                            Ok(msg_contents) => {
                                match msg_contents {
                                    Message::Text(_) => {
                                        log_trace!(logger, "ignoring text sent directly to ldk socket");
                                    }
                                    Message::Bytes(b) => {
                                        log_trace!(logger, "received binary data from websocket");

                                        let read_res = peer_manager.read_event(&mut descriptor, &b);
                                        match read_res {
                                            Ok(_read_bool) => {
                                                peer_manager.process_events();
                                            }
                                            Err(e) => log_error!(logger, "got an error reading event: {}", e),
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                match e {
                                    gloo_net::websocket::WebSocketError::ConnectionError => {
                                        log_error!(logger, "got connection error");
                                    }
                                    gloo_net::websocket::WebSocketError::ConnectionClose(e) => match e.code {
                                        1000 => log_trace!(logger, "normal connection closure"),
                                        1006 => log_debug!(logger, "abnormal connection closure"),
                                        _ => log_error!(logger, "connection closed due to: {:?}", e),
                                    },
                                    gloo_net::websocket::WebSocketError::MessageSendError(e) => {
                                        log_error!(logger, "got an error sending msg: {}", e);
                                    }
                                    _ => {
                                        log_error!(logger, "got an error reading msg: {}", e);
                                    }
                                }
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
