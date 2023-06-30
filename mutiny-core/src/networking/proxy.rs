use crate::node::ConnectionType;
use crate::node::PubkeyConnectionInfo;
use crate::{error::MutinyError, utils, utils::sleep};
use async_trait::async_trait;
use futures::stream::SplitStream;
use futures::{lock::Mutex, stream::SplitSink, SinkExt, StreamExt};
use gloo_net::websocket::{futures::WebSocket, Message, State};
use lightning::{log_debug, log_trace};
use lightning::{log_error, util::logger::Logger};
use std::sync::Arc;

use crate::logging::MutinyLogger;
#[cfg(test)]
use mockall::{automock, predicate::*};

#[cfg_attr(test, automock)]
#[async_trait(?Send)]
pub trait Proxy {
    fn send(&self, data: Message);
    async fn read(&self) -> Option<Result<Message, gloo_net::websocket::WebSocketError>>;
    async fn close(&self);
}

pub struct WsProxy {
    write: WsSplit,
    read: ReadSplit,
    logger: Arc<MutinyLogger>,
}

pub type WsSplit = Arc<Mutex<SplitSink<WebSocket, Message>>>;
pub type ReadSplit = Arc<Mutex<SplitStream<WebSocket>>>;

impl WsProxy {
    pub async fn new(
        proxy_url: &str,
        peer_connection_info: PubkeyConnectionInfo,
        logger: Arc<MutinyLogger>,
    ) -> Result<Self, MutinyError> {
        let ws = match peer_connection_info.connection_type {
            ConnectionType::Tcp(s) => WebSocket::open(&tcp_proxy_to_url(proxy_url, &s)?)
                .map_err(|_| MutinyError::ConnectionFailed)?,
        };

        // wait for connected status or time out at 10s
        let mut retries = 10;
        while retries > 0 {
            match ws.state() {
                State::Open => break,
                State::Closed => break,
                _ => {
                    sleep(1_000).await;
                    retries -= 1;
                }
            }
        }

        match ws.state() {
            State::Open => {}
            _ => return Err(MutinyError::ConnectionFailed),
        }

        // TODO wait until we get an OK response from websocket.
        // A connection to the proxy for connections just means that
        // it just connected to the proxy. It does not mean the proxy
        // successfully connected out to the other end. They may be
        // offline and shortly cut off from the WS but that happens
        // outside of the connect flow. This will falsely return success.

        log_debug!(logger, "connected to ws: {proxy_url}");

        let (write, read) = ws.split();
        Ok(Self {
            write: Arc::new(Mutex::new(write)),
            read: Arc::new(Mutex::new(read)),
            logger,
        })
    }
}

#[async_trait(?Send)]
impl Proxy for WsProxy {
    fn send(&self, data: Message) {
        // There can only be one sender at a time
        // Cannot send and write at the same time either
        // TODO check if the connection is closed before trying to send.
        let cloned_conn = self.write.clone();
        let logger = self.logger.clone();
        utils::spawn(async move {
            let mut write = cloned_conn.lock().await;
            match write.send(data).await {
                Ok(_) => {
                    log_trace!(logger, "sent data down websocket");
                }
                Err(e) => {
                    log_error!(logger, "error sending data down websocket: {e}");
                }
            }
        });
    }

    async fn read(&self) -> Option<Result<Message, gloo_net::websocket::WebSocketError>> {
        self.read.lock().await.next().await
    }

    async fn close(&self) {
        let _ = self.write.lock().await.close().await;
        log_debug!(self.logger, "closed websocket");
    }
}

pub fn tcp_proxy_to_url(proxy_url: &str, peer_addr: &str) -> Result<String, MutinyError> {
    let mut parts = peer_addr.split(':');
    let host = parts.next().ok_or(MutinyError::PeerInfoParseFailed)?;
    let port = parts.next().ok_or(MutinyError::PeerInfoParseFailed)?;
    Ok(format!(
        "{proxy_url}/v1/{}/{}",
        host.replace('.', "_"),
        port
    ))
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "ignored_tests")]
    use crate::networking::proxy::*;

    use crate::test_utils::*;

    use crate::networking::proxy::tcp_proxy_to_url;

    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    // test ignored because it connects to a real server
    #[cfg(feature = "ignored_tests")]
    async fn test_websocket_proxy_init() {
        log!("test websocket proxy");
        let logger = Arc::new(MutinyLogger::default());

        // ACINQ's node pubkey
        const PEER_PUBKEY: &str =
            "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f";

        let proxy = WsProxy::new(
            "wss://p.mutinywallet.com",
            PubkeyConnectionInfo::new(&format!("{}@{}", PEER_PUBKEY, "3.33.236.230:9735")).unwrap(),
            logger,
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
            tcp_proxy_to_url("ws://127.0.0.1:3001", "127.0.0.1:4000").unwrap()
        );
    }
}
