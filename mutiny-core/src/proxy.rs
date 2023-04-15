use crate::error::MutinyError;
use crate::node::ConnectionType;
use crate::node::PubkeyConnectionInfo;
use async_trait::async_trait;
use futures::stream::SplitStream;
use futures::{lock::Mutex, stream::SplitSink, SinkExt, StreamExt};
use gloo_net::websocket::{futures::WebSocket, Message};
use log::debug;
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

#[cfg(test)]
use mockall::{automock, predicate::*};

#[cfg_attr(test, automock)]
#[async_trait(?Send)]
pub(crate) trait Proxy {
    fn send(&self, data: Message);
    async fn read(&self) -> Option<Result<Message, gloo_net::websocket::WebSocketError>>;
    async fn close(&self);
}

pub(crate) struct WsProxy {
    write: WsSplit,
    read: ReadSplit,
}

type WsSplit = Arc<Mutex<SplitSink<WebSocket, Message>>>;
type ReadSplit = Arc<Mutex<SplitStream<WebSocket>>>;

impl WsProxy {
    pub async fn new(
        proxy_url: String,
        peer_connection_info: PubkeyConnectionInfo,
    ) -> Result<Self, MutinyError> {
        let ws = match peer_connection_info.connection_type {
            ConnectionType::Tcp(s) => {
                WebSocket::open(String::as_str(&tcp_proxy_to_url(proxy_url.clone(), s)?))
                    .map_err(|_| MutinyError::ConnectionFailed)?
            }
            ConnectionType::Mutiny(url) => WebSocket::open(String::as_str(
                &mutiny_conn_proxy_to_url(url, peer_connection_info.pubkey.to_string()),
            ))
            .map_err(|_| MutinyError::ConnectionFailed)?,
        };

        debug!("connected to ws: {proxy_url}");

        let (write, read) = ws.split();
        Ok(Self {
            write: Arc::new(Mutex::new(write)),
            read: Arc::new(Mutex::new(read)),
        })
    }
}

#[async_trait(?Send)]
impl Proxy for WsProxy {
    fn send(&self, data: Message) {
        debug!("initiating sending down websocket");

        // There can only be one sender at a time
        // Cannot send and write at the same time either
        // TODO check if the connection is closed before trying to send.
        let cloned_conn = self.write.clone();
        spawn_local(async move {
            let mut write = cloned_conn.lock().await;
            write.send(data).await.unwrap();
            debug!("sent data down websocket");
        });
    }

    async fn read(&self) -> Option<Result<Message, gloo_net::websocket::WebSocketError>> {
        self.read.lock().await.next().await
    }

    async fn close(&self) {
        let _ = self.write.lock().await.close().await;
        debug!("closed websocket");
    }
}

pub fn tcp_proxy_to_url(proxy_url: String, peer_addr: String) -> Result<String, MutinyError> {
    let mut parts = peer_addr.split(':');
    let host = parts.next().ok_or(MutinyError::PeerInfoParseFailed)?;
    let port = parts.next().ok_or(MutinyError::PeerInfoParseFailed)?;
    Ok(format!(
        "{proxy_url}/v1/{}/{}",
        host.replace('.', "_"),
        port
    ))
}

pub fn mutiny_conn_proxy_to_url(proxy_url: String, peer_pubkey: String) -> String {
    format!("{proxy_url}/v1/mutiny/{peer_pubkey}",)
}

#[cfg(test)]
mod tests {
    use crate::proxy::{Proxy, PubkeyConnectionInfo};
    use crate::test::*;

    use crate::proxy::{mutiny_conn_proxy_to_url, tcp_proxy_to_url, WsProxy};

    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    const PEER_PUBKEY: &str = "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443";

    #[test]
    #[cfg(feature = "ignored_tests")]
    async fn test_websocket_proxy_init() {
        log!("test websocket proxy");

        // TODO do something useful
        let proxy = WsProxy::new(
            "ws://127.0.0.1:3001".to_string(),
            PubkeyConnectionInfo::new(format!("{}@{}", PEER_PUBKEY, "127.0.0.1:4000")).unwrap(),
        )
        .await
        .unwrap();

        proxy.close().await;
    }

    #[test]
    fn test_proxy_to_url() {
        log!("test proxy to url");

        assert_eq!(
            "ws://127.0.0.1:3001/v1/127_0_0_1/4000".to_string(),
            tcp_proxy_to_url(
                "ws://127.0.0.1:3001".to_string(),
                "127.0.0.1:4000".parse().unwrap(),
            )
            .unwrap()
        );

        assert_eq!(
            ("ws://127.0.0.1:3001/v1/mutiny/".to_owned() + PEER_PUBKEY),
            mutiny_conn_proxy_to_url("ws://127.0.0.1:3001".to_string(), PEER_PUBKEY.to_string(),)
        )
    }
}
