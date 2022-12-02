use crate::proxy::Proxy;
use futures::{SinkExt, StreamExt};
use gloo_net::websocket::Message;
use lightning::ln::peer_handler;
use log::debug;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) trait ReadDescriptor {
    async fn read(&self) -> Option<Result<Message, gloo_net::websocket::WebSocketError>>;
}

#[derive(Clone, Eq, PartialEq, Hash)]
pub(crate) enum WsSocketDescriptor {
    Tcp(WsTcpSocketDescriptor),
}

impl ReadDescriptor for WsSocketDescriptor {
    async fn read(&self) -> Option<Result<Message, gloo_net::websocket::WebSocketError>> {
        match self {
            WsSocketDescriptor::Tcp(s) => s.read().await,
        }
    }
}

impl peer_handler::SocketDescriptor for WsSocketDescriptor {
    fn send_data(&mut self, data: &[u8], resume_read: bool) -> usize {
        match self {
            WsSocketDescriptor::Tcp(s) => s.send_data(data, resume_read),
        }
    }

    fn disconnect_socket(&mut self) {
        match self {
            WsSocketDescriptor::Tcp(s) => s.disconnect_socket(),
        }
    }
}

pub(crate) struct WsTcpSocketDescriptor {
    conn: Arc<Proxy>,
    id: u64,
}
impl WsTcpSocketDescriptor {
    pub fn new(conn: Arc<Proxy>) -> Self {
        let id = ID_COUNTER.fetch_add(1, Ordering::AcqRel);
        Self { conn, id }
    }
}

impl ReadDescriptor for WsTcpSocketDescriptor {
    async fn read(&self) -> Option<Result<Message, gloo_net::websocket::WebSocketError>> {
        self.conn.read.lock().await.next().await
    }
}

unsafe impl Send for WsTcpSocketDescriptor {}
unsafe impl Sync for WsTcpSocketDescriptor {}

impl peer_handler::SocketDescriptor for WsTcpSocketDescriptor {
    fn send_data(&mut self, data: &[u8], _resume_read: bool) -> usize {
        let vec = Vec::from(data);
        self.conn.send(vec);
        data.len()
    }

    fn disconnect_socket(&mut self) {
        let cloned = self.conn.write.clone();
        spawn_local(async move {
            let mut conn = cloned.lock().await;
            let _ = conn.close();
            debug!("closed websocket");
        });
    }
}
impl Clone for WsTcpSocketDescriptor {
    fn clone(&self) -> Self {
        Self {
            conn: Arc::clone(&self.conn),
            id: self.id,
        }
    }
}
impl Eq for WsTcpSocketDescriptor {}
impl PartialEq for WsTcpSocketDescriptor {
    fn eq(&self, o: &Self) -> bool {
        self.id == o.id
    }
}
impl Hash for WsTcpSocketDescriptor {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}
