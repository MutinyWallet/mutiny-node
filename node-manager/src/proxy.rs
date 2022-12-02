use std::{net::SocketAddr, sync::Arc};

use futures::stream::SplitStream;
use futures::{lock::Mutex, stream::SplitSink, SinkExt, StreamExt};
use gloo_net::websocket::{futures::WebSocket, Message};
use log::debug;
use wasm_bindgen_futures::spawn_local;

pub(crate) struct Proxy {
    pub write: WsSplit,
    pub read: ReadSplit,
}

type WsSplit = Arc<Mutex<SplitSink<WebSocket, Message>>>;
type ReadSplit = Arc<Mutex<SplitStream<WebSocket>>>;

impl Proxy {
    pub async fn from_tcp_addr(proxy_url: String, peer_addr: SocketAddr) -> Self {
        let ws = WebSocket::open(String::as_str(&proxy_to_url(proxy_url, peer_addr))).unwrap();
        let (write, read) = ws.split();
        Self {
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

pub fn proxy_to_url(proxy_url: String, peer_addr: SocketAddr) -> String {
    format!(
        "{proxy_url}/v1/{}/{}",
        peer_addr.ip().to_string().replace('.', "_"),
        peer_addr.port()
    )
}

#[cfg(test)]
mod tests {
    use crate::test::*;

    use crate::proxy::{proxy_to_url, Proxy};

    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn test_websocket_proxy_init() {
        log!("test websocket proxy");

        // TODO do something useful
        let _proxy = Proxy::from_tcp_addr(
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
