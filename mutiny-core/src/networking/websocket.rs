use async_trait::async_trait;
use futures::{SinkExt, StreamExt};

#[cfg(target_arch = "wasm32")]
use std::sync::Arc;

#[cfg(target_arch = "wasm32")]
use futures::lock::Mutex;

#[async_trait(?Send)]
pub trait SimpleWebSocket {
    async fn new(url: String) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: Sized;
    async fn send(&mut self, msg: String) -> Result<(), Box<dyn std::error::Error>>;
    async fn recv(&mut self) -> Result<String, Box<dyn std::error::Error>>;
}

#[cfg(target_arch = "wasm32")]
pub struct WebSocketImpl {
    write: crate::networking::proxy::WsSplit,
    read: crate::networking::proxy::ReadSplit,
}

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
impl SimpleWebSocket for WebSocketImpl {
    async fn new(url: String) -> Result<Self, Box<dyn std::error::Error>> {
        let ws = gloo_net::websocket::futures::WebSocket::open(&url)?;
        let (write, read) = ws.split();
        Ok(Self {
            write: Arc::new(Mutex::new(write)),
            read: Arc::new(Mutex::new(read)),
        })
    }

    async fn send(&mut self, msg: String) -> Result<(), Box<dyn std::error::Error>> {
        Ok(self
            .write
            .lock()
            .await
            .send(gloo_net::websocket::Message::Text(msg))
            .await?)
    }

    async fn recv(&mut self) -> Result<String, Box<dyn std::error::Error>> {
        Ok(if let Some(msg) = self.read.lock().await.next().await {
            match msg? {
                gloo_net::websocket::Message::Text(text) => text,
                _ => return Err("received non-text message".into()),
            }
        } else {
            return Err("failed to receive message".into());
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub struct WebSocketImpl {
    ws: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
}

#[async_trait(?Send)]
#[cfg(not(target_arch = "wasm32"))]
impl SimpleWebSocket for WebSocketImpl {
    async fn new(url: String) -> Result<Self, Box<dyn std::error::Error>> {
        let (ws_stream, _response) = tokio_tungstenite::connect_async(url)
            .await
            .map_err(Box::new)?;
        Ok(Self { ws: ws_stream })
    }

    async fn send(&mut self, msg: String) -> Result<(), Box<dyn std::error::Error>> {
        Ok(self
            .ws
            .send(tokio_tungstenite::tungstenite::Message::Text(msg))
            .await?)
    }

    async fn recv(&mut self) -> Result<String, Box<dyn std::error::Error>> {
        match self.ws.next().await {
            Some(Ok(tokio_tungstenite::tungstenite::Message::Text(msg))) => Ok(msg),
            Some(Ok(_)) => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "received non-text message",
            ))),
            Some(Err(e)) => Err(Box::new(e)),
            None => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "failed to receive message",
            ))),
        }
    }
}
