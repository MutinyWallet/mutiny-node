use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{net::SocketAddr, sync::Arc};

use futures::stream::SplitStream;
use futures::{lock::Mutex, stream::SplitSink, SinkExt, StreamExt};
use gloo_net::websocket::{futures::WebSocket, Message};
use lightning::ln::peer_handler;
use log::debug;
use wasm_bindgen_futures::spawn_local;

pub struct TcpProxy {
    write: WsSplit,
    read: ReadSplit,
}

type WsSplit = Arc<Mutex<SplitSink<WebSocket, Message>>>;
type ReadSplit = Arc<Mutex<SplitStream<WebSocket>>>;

impl TcpProxy {
    pub async fn new(proxy_url: String, peer_addr: SocketAddr) -> Self {
        let ws = WebSocket::open(String::as_str(&proxy_to_url(proxy_url, peer_addr))).unwrap();
        let (write, read) = ws.split();
        TcpProxy {
            write: Arc::new(Mutex::new(write)),
            read: Arc::new(Mutex::new(read)),
        }
    }

    pub fn send(&self, data: Vec<u8>) {
        debug!("initiating sending down websocket");

        // There can only be one sender at a time
        // Cannot send and write at the same time either
        // TODO check if the connection is closed before trying to send.
        let cloned_conn = self.write.clone();
        spawn_local(async move {
            let mut write = cloned_conn.lock().await;
            write.send(Message::Bytes(data)).await.unwrap();
            debug!("sent data down websocket");
        });
    }
}

fn proxy_to_url(proxy_url: String, peer_addr: SocketAddr) -> String {
    format!(
        "{proxy_url}/v1/{}/{}",
        peer_addr.ip().to_string().replace('.', "_"),
        peer_addr.port()
    )
}

static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct SocketDescriptor {
    pub conn: Arc<TcpProxy>,
    id: u64,
}
impl SocketDescriptor {
    pub fn new(conn: Arc<TcpProxy>) -> Self {
        let id = ID_COUNTER.fetch_add(1, Ordering::AcqRel);
        Self { conn, id }
    }

    pub async fn read(&self) -> Option<Result<Message, gloo_net::websocket::WebSocketError>> {
        self.conn.read.lock().await.next().await
    }
}
unsafe impl Send for SocketDescriptor {}
unsafe impl Sync for SocketDescriptor {}

impl peer_handler::SocketDescriptor for SocketDescriptor {
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
impl Clone for SocketDescriptor {
    fn clone(&self) -> Self {
        Self {
            conn: Arc::clone(&self.conn),
            id: self.id,
        }
    }
}
impl Eq for SocketDescriptor {}
impl PartialEq for SocketDescriptor {
    fn eq(&self, o: &Self) -> bool {
        self.id == o.id
    }
}
impl Hash for SocketDescriptor {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use crate::test::*;

    use crate::tcpproxy::{proxy_to_url, TcpProxy};

    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn test_websocket_proxy_init() {
        log!("test websocket proxy");

        // TODO do something useful
        let _proxy = TcpProxy::new(
            "ws://127.0.0.1:3001".to_string(),
            "127.0.0.1:4000".parse().unwrap(),
        )
        .await;
    }

    #[test]
    fn test_proxy_to_url() {
        log!("test proxy to url");

        assert_eq!(
            "ws://127.0.0.1:3001/v1/127_0_0_1/4000".to_string(),
            proxy_to_url(
                "ws://127.0.0.1:3001".to_string(),
                "127.0.0.1:4000".parse().unwrap(),
            )
        )
    }
}
