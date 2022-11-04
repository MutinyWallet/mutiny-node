use std::{net::SocketAddr, sync::Arc};

use futures::{lock::Mutex, stream::SplitSink, SinkExt, StreamExt};
use gloo_net::websocket::{futures::WebSocket, Message};
use log::{debug, info};
use wasm_bindgen_futures::spawn_local;

pub struct TcpProxy {
    connection: WsSplit,
}

type WsSplit = Arc<Mutex<SplitSink<WebSocket, Message>>>;

impl TcpProxy {
    pub async fn new(proxy_url: String, peer_addr: SocketAddr) -> Self {
        let ws = WebSocket::open(String::as_str(&proxy_to_url(proxy_url, peer_addr))).unwrap();
        let (write, mut read) = ws.split();

        spawn_local(async move {
            // TODO callback or pass bytes over to some stream reader.
            // need to figure out how LDK wants this incoming data.
            while let Some(msg) = read.next().await {
                if let Ok(msg_contents) = msg {
                    match msg_contents {
                        Message::Text(t) => {
                            info!("receive text from websocket {}", t)
                        }
                        Message::Bytes(b) => {
                            info!(
                                "receive binary from websocket {}",
                                String::from_utf8_lossy(&b)
                            )
                        }
                    };
                }
            }

            // TODO when we detect an error, lock the writes and close connection.
            debug!("WebSocket Closed")
        });

        TcpProxy {
            connection: Arc::new(Mutex::new(write)),
        }
    }

    pub fn send(&self) {
        debug!("initiating sending down websocket");

        // There can only be one sender at a time
        // Cannot send and write at the same time either
        // TODO check if the connection is closed before trying to send.
        let cloned_conn = self.connection.clone();
        spawn_local(async move {
            let mut write = cloned_conn.lock().await;
            write
                .send(Message::Bytes(String::from("test\n").into_bytes().to_vec()))
                .await
                .unwrap();
            write
                .send(Message::Bytes(
                    String::from("test 2\n").into_bytes().to_vec(),
                ))
                .await
                .unwrap();
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
