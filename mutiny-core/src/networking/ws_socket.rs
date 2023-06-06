use crate::networking::socket::ReadDescriptor;
use crate::utils;
use crate::{error::MutinyError, networking::proxy::Proxy};
use gloo_net::websocket::Message;
use lightning::ln::peer_handler;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct WsTcpSocketDescriptor {
    conn: Arc<dyn Proxy>,
    id: u64,
}

impl WsTcpSocketDescriptor {
    pub fn new(conn: Arc<dyn Proxy>) -> Self {
        let id = ID_COUNTER.fetch_add(1, Ordering::AcqRel);
        Self { conn, id }
    }
}

impl ReadDescriptor for WsTcpSocketDescriptor {
    async fn read(&self) -> Option<Result<Vec<u8>, MutinyError>> {
        match self.conn.read().await {
            Some(Ok(Message::Bytes(b))) => Some(Ok(b)),
            Some(Ok(Message::Text(_))) => {
                // Ignoring text messages sent through tcp socket
                None
            }
            Some(Err(_)) => Some(Err(MutinyError::ConnectionFailed)),
            None => None,
        }
    }
}

unsafe impl Send for WsTcpSocketDescriptor {}
unsafe impl Sync for WsTcpSocketDescriptor {}

impl peer_handler::SocketDescriptor for WsTcpSocketDescriptor {
    fn send_data(&mut self, data: &[u8], _resume_read: bool) -> usize {
        let vec = Vec::from(data);
        self.conn.send(Message::Bytes(vec));
        data.len()
    }

    fn disconnect_socket(&mut self) {
        let cloned = self.conn.clone();
        utils::spawn(async move {
            cloned.close().await;
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

impl std::fmt::Debug for WsTcpSocketDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "({})", self.id)
    }
}

#[cfg(test)]
mod tests {
    use crate::networking::proxy::MockProxy;

    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    use crate::networking::socket::MutinySocketDescriptor;
    use crate::networking::ws_socket::WsTcpSocketDescriptor;
    use std::sync::Arc;

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn test_eq_for_ws_socket_descriptor() {
        // Test ne and eq for WsTcpSocketDescriptor
        let mock_proxy = Arc::new(MockProxy::new());
        let tcp_ws = MutinySocketDescriptor::Tcp(WsTcpSocketDescriptor::new(mock_proxy));

        let mock_proxy_2 = Arc::new(MockProxy::new());
        let tcp_ws_2 = MutinySocketDescriptor::Tcp(WsTcpSocketDescriptor::new(mock_proxy_2));
        assert_ne!(tcp_ws, tcp_ws_2);

        let mock_proxy_3 = Arc::new(MockProxy::new());
        let tcp_ws_3 = MutinySocketDescriptor::Tcp(WsTcpSocketDescriptor::new(mock_proxy_3));
        assert_eq!(tcp_ws_3.clone(), tcp_ws_3);
    }
}
