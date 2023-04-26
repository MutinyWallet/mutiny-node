use crate::peermanager::PeerManager;
use crate::proxy::Proxy;
use crate::utils;
use bitcoin::hashes::hex::ToHex;
use crossbeam_channel::{unbounded, Receiver, Sender};
use futures::lock::Mutex;
use gloo_net::websocket::events::CloseEvent;
use gloo_net::websocket::Message;
use lightning::ln::peer_handler;
use lightning::ln::peer_handler::SocketDescriptor;
use ln_websocket_proxy::MutinyProxyCommand;
use log::{debug, error, trace};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

static ID_COUNTER: AtomicU64 = AtomicU64::new(0);
const PUBKEY_BYTES_LEN: usize = 33;
pub(crate) type SubSocketMap =
    Arc<Mutex<HashMap<Vec<u8>, (SubWsSocketDescriptor, Sender<Message>)>>>;

pub(crate) trait ReadDescriptor {
    async fn read(&self) -> Option<Result<Message, gloo_net::websocket::WebSocketError>>;
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub(crate) enum WsSocketDescriptor {
    Tcp(WsTcpSocketDescriptor),
    Mutiny(SubWsSocketDescriptor),
}

impl ReadDescriptor for WsSocketDescriptor {
    async fn read(&self) -> Option<Result<Message, gloo_net::websocket::WebSocketError>> {
        match self {
            WsSocketDescriptor::Tcp(s) => s.read().await,
            WsSocketDescriptor::Mutiny(s) => s.read().await,
        }
    }
}

impl peer_handler::SocketDescriptor for WsSocketDescriptor {
    fn send_data(&mut self, data: &[u8], resume_read: bool) -> usize {
        match self {
            WsSocketDescriptor::Tcp(s) => s.send_data(data, resume_read),
            WsSocketDescriptor::Mutiny(s) => s.send_data(data, resume_read),
        }
    }

    fn disconnect_socket(&mut self) {
        match self {
            WsSocketDescriptor::Tcp(s) => s.disconnect_socket(),
            WsSocketDescriptor::Mutiny(s) => s.disconnect_socket(),
        }
    }
}

pub(crate) struct WsTcpSocketDescriptor {
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
    async fn read(&self) -> Option<Result<Message, gloo_net::websocket::WebSocketError>> {
        self.conn.read().await
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
        spawn_local(async move {
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

#[derive(Clone)]
pub(crate) struct MultiWsSocketDescriptor {
    conn: Arc<dyn Proxy>,
    read_from_sub_socket: Receiver<Message>,
    send_to_multi_socket: Sender<Message>,
    socket_map: SubSocketMap,
    peer_manager: Arc<dyn PeerManager>,
    our_peer_pubkey: Vec<u8>,
    connected: Arc<AtomicBool>,
}
impl MultiWsSocketDescriptor {
    pub fn new(
        conn: Arc<dyn Proxy>,
        peer_manager: Arc<dyn PeerManager>,
        our_peer_pubkey: Vec<u8>,
    ) -> Self {
        trace!("setting up multi websocket descriptor");

        let (send_to_multi_socket, read_from_sub_socket): (Sender<Message>, Receiver<Message>) =
            unbounded();

        let socket_map: SubSocketMap = Arc::new(Mutex::new(HashMap::new()));

        Self {
            conn,
            send_to_multi_socket,
            read_from_sub_socket,
            socket_map,
            peer_manager,
            our_peer_pubkey,
            connected: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    pub async fn reconnect(&mut self, conn: Arc<dyn Proxy>) {
        let mut socket_map = self.socket_map.lock().await;
        trace!("setting up multi websocket descriptor");
        // if reconnecting master socket, disconnect and clear all subsockets
        for (_id, (subsocket, _sender)) in socket_map.iter_mut() {
            // tell the subsocket to stop processing
            // and ldk to disconnect that peer
            subsocket.disconnect_socket();
            self.peer_manager
                .socket_disconnected(&mut WsSocketDescriptor::Mutiny(subsocket.clone()));
        }

        socket_map.clear();
        self.conn = conn;
        self.connected.store(true, Ordering::Relaxed);

        self.listen();
    }

    pub async fn create_new_subsocket(&self, id: Vec<u8>) -> SubWsSocketDescriptor {
        let (send_to_sub_socket, read_from_multi_socket): (Sender<Message>, Receiver<Message>) =
            unbounded();
        create_new_subsocket(
            self.socket_map.clone(),
            self.send_to_multi_socket.clone(),
            send_to_sub_socket,
            read_from_multi_socket,
            id,
            self.our_peer_pubkey.clone(),
        )
        .await
    }

    pub fn listen(&self) {
        // This first part will take in messages from the websocket connection
        // to the proxy and decide what to do with them. If it is a binary message
        // then it is a message from one mutiny peer to another with the first bytes
        // being the pubkey it is for. In that case, it will find the subsocket
        // for the pubkey it is for and send the rest of the bytes to it.
        //
        // The websocket proxy may also send commands to the multi websocket descriptor.
        // A disconnection message indicates that a subsocket descriptor needs to be
        // closed but the underlying connection should stay open. This indicates that
        // the other peer went away or there was an issue connecting / sending to them.
        let conn_copy = self.conn.clone();
        let socket_map_copy = self.socket_map.clone();
        let send_to_multi_socket_copy = self.send_to_multi_socket.clone();
        let peer_manager_copy = self.peer_manager.clone();
        let connected_copy = self.connected.clone();
        let our_peer_pubkey_copy = self.our_peer_pubkey.clone();
        trace!("spawning multi socket connection reader");
        spawn_local(async move {
            while let Some(msg) = conn_copy.read().await {
                if let Ok(msg) = msg {
                    match msg {
                        Message::Text(msg) => {
                            // This is a text command from the server. Parse the type
                            // of command it is and act accordingly.
                            // parse and implement subsocket disconnections.
                            // Right now subsocket is very tied to a specific node,
                            // later we should share a single connection amongst all pubkeys and in
                            // which case "to" will be important to parse.
                            let command: MutinyProxyCommand = match serde_json::from_str(&msg) {
                                Ok(c) => c,
                                Err(e) => {
                                    error!("couldn't parse text command from proxy, ignoring: {e}");
                                    continue;
                                }
                            };
                            match command {
                                MutinyProxyCommand::Disconnect { to: _to, from } => {
                                    let mut locked_socket_map = socket_map_copy.lock().await;
                                    match locked_socket_map.get_mut(&from) {
                                        Some((subsocket, _sender)) => {
                                            // if we got told by server to disconnect then stop
                                            // reading from the socket and tell LDK that the socket
                                            // is disconnected.
                                            debug!("was told by server to disconnect subsocket connection with {}", from.to_hex());
                                            subsocket.stop_reading();
                                            peer_manager_copy.socket_disconnected(
                                                &mut WsSocketDescriptor::Mutiny(subsocket.clone()),
                                            );
                                            locked_socket_map.remove(&from);
                                        }
                                        None => {
                                            error!("tried to disconnect a subsocket that doesn't exist...");
                                        }
                                    }
                                }
                            };
                        }
                        Message::Bytes(msg) => {
                            // This is a mutiny to mutiny connection with pubkey + bytes
                            // as the binary message. Parse the msg and see which pubkey
                            // it belongs to.
                            trace!("received a binary message on multi socket...");
                            if msg.len() < PUBKEY_BYTES_LEN {
                                error!("msg not long enough to have pubkey, ignoring...");
                                continue;
                            }
                            let (id_bytes, message_bytes) = msg.split_at(PUBKEY_BYTES_LEN);

                            // now send that data to the right subsocket;
                            let socket_lock = socket_map_copy.lock().await;
                            let found_subsocket = socket_lock.get(id_bytes);
                            match found_subsocket {
                                Some((_subsocket, sender)) => {
                                    match sender.send(Message::Bytes(message_bytes.to_vec())) {
                                        Ok(_) => {
                                            trace!(
                                                "found subsocket to forward bytes to: {:?}",
                                                id_bytes
                                            );
                                        }
                                        Err(e) => error!("error sending msg to channel: {}", e),
                                    };
                                }
                                None => {
                                    drop(socket_lock);

                                    // create a new subsocket and pass it to peer_manager
                                    trace!(
                                        "no connection found for socket address, creating new: {:?}",
                                        id_bytes
                                    );
                                    let (send_to_sub_socket, read_from_multi_socket): (
                                        Sender<Message>,
                                        Receiver<Message>,
                                    ) = unbounded();
                                    let mut inbound_subsocket = WsSocketDescriptor::Mutiny(
                                        create_new_subsocket(
                                            socket_map_copy.clone(),
                                            send_to_multi_socket_copy.clone(),
                                            send_to_sub_socket.clone(),
                                            read_from_multi_socket,
                                            id_bytes.to_vec(),
                                            our_peer_pubkey_copy.clone(),
                                        )
                                        .await,
                                    );
                                    trace!("created new subsocket: {:?}", id_bytes);
                                    match peer_manager_copy
                                        .new_inbound_connection(inbound_subsocket.clone(), None)
                                    {
                                        Ok(_) => {
                                            trace!(
                                                "gave new subsocket to peer manager: {:?}",
                                                id_bytes
                                            );
                                            schedule_descriptor_read(
                                                inbound_subsocket,
                                                peer_manager_copy.clone(),
                                            );

                                            // now that we have the inbound connection, send the original
                                            // message to our new subsocket descriptor
                                            match send_to_sub_socket
                                                .send(Message::Bytes(message_bytes.to_vec()))
                                            {
                                                Ok(_) => {
                                                    trace!("sent incoming message to new subsocket channel: {:?}", id_bytes)
                                                }
                                                Err(e) => {
                                                    error!("error sending msg to channel: {}", e)
                                                }
                                            };
                                        }
                                        Err(_) => {
                                            error!(
                                                "peer manager could not handle subsocket for: {:?}, deleting...",
                                                id_bytes
                                            );
                                            let mut locked_socket_map =
                                                socket_map_copy.lock().await;
                                            inbound_subsocket.disconnect_socket();
                                            peer_manager_copy
                                                .socket_disconnected(&mut inbound_subsocket);
                                            locked_socket_map.remove(id_bytes);
                                        }
                                    };
                                }
                            };
                        }
                    }
                }
            }
            trace!("leaving multi socket connection reader");
            connected_copy.store(false, Ordering::Relaxed)
        });

        let read_channel_copy = self.read_from_sub_socket.clone();
        let conn_copy_send = self.conn.clone();
        let connected_copy_send = self.connected.clone();
        trace!("spawning multi socket channel reader");
        spawn_local(async move {
            loop {
                if let Ok(msg) = read_channel_copy.try_recv() {
                    trace!("multi socket channel reader sending data to proxy");
                    conn_copy_send.send(msg)
                }
                if !connected_copy_send.load(Ordering::Relaxed) {
                    break;
                }
                utils::sleep(50).await;
            }
            trace!("leaving multi socket channel reader");
        });
    }
}

pub(crate) fn schedule_descriptor_read(
    descriptor: WsSocketDescriptor,
    peer_manager: Arc<dyn PeerManager>,
) {
    trace!("scheduling descriptor reader");
    let mut descriptor = descriptor;
    spawn_local(async move {
        while let Some(msg) = descriptor.read().await {
            match msg {
                Ok(msg_contents) => {
                    match msg_contents {
                        Message::Text(_) => {
                            // text should not directly be sent to these sockets
                            // the multi ws socket descriptor intercepts the m2m
                            // sockets, meanwhile the tcp socket proxy never deals
                            // with command messages.
                            trace!("ignoring text sent directly to ldk socket");
                        }
                        Message::Bytes(b) => {
                            trace!("received binary data from websocket");

                            let read_res = peer_manager.read_event(&mut descriptor, &b);
                            match read_res {
                                // TODO handle read boolean event
                                Ok(_read_bool) => {
                                    trace!("read event from the node");
                                    peer_manager.process_events();
                                }
                                Err(e) => error!("got an error reading event: {}", e),
                            }
                        }
                    };
                }
                Err(e) => {
                    match e {
                        gloo_net::websocket::WebSocketError::ConnectionError => {
                            error!("got connection error");
                        }
                        gloo_net::websocket::WebSocketError::ConnectionClose(e) => match e.code {
                            // TODO make connection closes from proxy be 1000
                            1000 => trace!("normal connection closure"),
                            1006 => debug!("abnormal connection closure"),
                            _ => error!("connection closed due to: {:?}", e),
                        },
                        gloo_net::websocket::WebSocketError::MessageSendError(e) => {
                            error!("got an error sending msg: {}", e);
                        }
                        _ => {
                            error!("got an error reading msg: {}", e);
                        }
                    };
                    break;
                }
            }
        }

        // TODO when we detect an error, lock the writes and close connection.
        trace!("WebSocket Closed")
    });
}

async fn create_new_subsocket(
    socket_map: SubSocketMap,
    send_to_multi_socket: Sender<Message>,
    send_to_sub_socket: Sender<Message>,
    read_from_multi_socket: Receiver<Message>,
    peer_pubkey: Vec<u8>,
    our_pubkey: Vec<u8>,
) -> SubWsSocketDescriptor {
    let new_subsocket = SubWsSocketDescriptor::new(
        send_to_multi_socket,
        read_from_multi_socket,
        peer_pubkey.clone(),
        our_pubkey,
    );

    socket_map
        .lock()
        .await
        .insert(peer_pubkey, (new_subsocket.clone(), send_to_sub_socket));

    new_subsocket
}

pub(crate) struct SubWsSocketDescriptor {
    send_channel: Sender<Message>,
    read_channel: Receiver<Message>,
    peer_pubkey_bytes: Vec<u8>,
    our_pubkey_bytes: Vec<u8>,
    id: u64,
    stop: Arc<AtomicBool>,
}
impl SubWsSocketDescriptor {
    pub fn new(
        send_channel: Sender<Message>,
        read_channel: Receiver<Message>,
        peer_pubkey_bytes: Vec<u8>,
        our_pubkey_bytes: Vec<u8>,
    ) -> Self {
        let id = ID_COUNTER.fetch_add(1, Ordering::AcqRel);
        Self {
            read_channel,
            send_channel,
            peer_pubkey_bytes,
            our_pubkey_bytes,
            id,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn stop_reading(&self) {
        self.stop.store(true, Ordering::Relaxed)
    }
}

impl ReadDescriptor for SubWsSocketDescriptor {
    async fn read(&self) -> Option<Result<Message, gloo_net::websocket::WebSocketError>> {
        loop {
            if self.stop.load(Ordering::Relaxed) {
                trace!("stopping subsocket channel reader");
                return Some(Err(gloo_net::websocket::WebSocketError::ConnectionClose(
                    CloseEvent {
                        code: 1000,
                        reason: "subsocket told to stop".to_string(),
                        was_clean: true,
                    },
                )));
            }
            if let Ok(msg) = self.read_channel.try_recv() {
                return Some(Ok(msg));
            }
            utils::sleep(50).await;
        }
    }
}

impl peer_handler::SocketDescriptor for SubWsSocketDescriptor {
    fn send_data(&mut self, data: &[u8], _resume_read: bool) -> usize {
        if self.stop.load(Ordering::Relaxed) {
            trace!("ignoring request to send down stopped subsocket");
            return 0;
        }

        let mut addr_prefix = self.peer_pubkey_bytes.to_vec();
        let mut vec = Vec::from(data);
        addr_prefix.append(&mut vec);
        let res = self.send_channel.send(Message::Bytes(addr_prefix));
        if res.is_err() {
            0
        } else {
            data.len()
        }
    }

    fn disconnect_socket(&mut self) {
        trace!("disconnecting socket from LDK");
        let res = self.send_channel.send(Message::Text(
            serde_json::to_string(&MutinyProxyCommand::Disconnect {
                to: self.peer_pubkey_bytes.clone(),
                from: self.our_pubkey_bytes.clone(),
            })
            .unwrap(),
        ));
        if res.is_err() {
            error!("tried to send disconnect message to proxy but failed..")
        }
        self.stop.store(true, Ordering::Relaxed)
    }
}

unsafe impl Send for SubWsSocketDescriptor {}
unsafe impl Sync for SubWsSocketDescriptor {}

impl Clone for SubWsSocketDescriptor {
    fn clone(&self) -> Self {
        Self {
            read_channel: self.read_channel.clone(),
            send_channel: self.send_channel.clone(),
            peer_pubkey_bytes: self.peer_pubkey_bytes.clone(),
            our_pubkey_bytes: self.our_pubkey_bytes.clone(),
            id: self.id,
            stop: self.stop.clone(),
        }
    }
}
impl Eq for SubWsSocketDescriptor {}
impl PartialEq for SubWsSocketDescriptor {
    fn eq(&self, o: &Self) -> bool {
        self.id == o.id
    }
}
impl Hash for SubWsSocketDescriptor {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl std::fmt::Debug for SubWsSocketDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "({})", self.id)
    }
}

#[cfg(test)]
mod tests {
    use crate::proxy::MockProxy;

    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    use super::WsSocketDescriptor;
    use crate::socket::create_new_subsocket;
    use crate::socket::SubSocketMap;
    use crate::socket::WsTcpSocketDescriptor;
    use bitcoin::secp256k1::PublicKey;
    use crossbeam_channel::{unbounded, Receiver, Sender};
    use futures::lock::Mutex;
    use gloo_net::websocket::Message;
    use lightning::util::ser::Writeable;
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::sync::Arc;

    wasm_bindgen_test_configure!(run_in_browser);

    const PEER_PUBKEY: &str = "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443";

    const OTHER_PEER_PUBKEY: &str =
        "03b661d965727a0751bd876efe3c826f89d5056f98501924222abd552bc2ba0ab1";

    #[test]
    async fn test_eq_for_ws_socket_descriptor() {
        // Test ne and eq for WsTcpSocketDescriptor
        let mock_proxy = Arc::new(MockProxy::new());
        let tcp_ws = WsSocketDescriptor::Tcp(WsTcpSocketDescriptor::new(mock_proxy));

        let mock_proxy_2 = Arc::new(MockProxy::new());
        let tcp_ws_2 = WsSocketDescriptor::Tcp(WsTcpSocketDescriptor::new(mock_proxy_2));
        assert_ne!(tcp_ws, tcp_ws_2);

        let mock_proxy_3 = Arc::new(MockProxy::new());
        let tcp_ws_3 = WsSocketDescriptor::Tcp(WsTcpSocketDescriptor::new(mock_proxy_3));
        assert_eq!(tcp_ws_3.clone(), tcp_ws_3);

        // Test ne and eq for WsTcpSocketDescriptor
        let (send_to_multi_socket, _): (Sender<Message>, Receiver<Message>) = unbounded();

        let socket_map: SubSocketMap = Arc::new(Mutex::new(HashMap::new()));
        let (send_to_sub_socket, read_from_multi_socket): (Sender<Message>, Receiver<Message>) =
            unbounded();
        let sub_ws_socket = create_new_subsocket(
            socket_map.clone(),
            send_to_multi_socket.clone(),
            send_to_sub_socket,
            read_from_multi_socket,
            PublicKey::from_str(OTHER_PEER_PUBKEY).unwrap().encode(),
            PublicKey::from_str(PEER_PUBKEY).unwrap().encode(),
        )
        .await;
        let mutiny_ws = WsSocketDescriptor::Mutiny(sub_ws_socket);

        let (send_to_multi_socket_2, _): (Sender<Message>, Receiver<Message>) = unbounded();

        let socket_map_2: SubSocketMap = Arc::new(Mutex::new(HashMap::new()));
        let (send_to_sub_socket_2, read_from_multi_socket_2): (Sender<Message>, Receiver<Message>) =
            unbounded();
        let sub_ws_socket_2 = create_new_subsocket(
            socket_map_2.clone(),
            send_to_multi_socket_2.clone(),
            send_to_sub_socket_2,
            read_from_multi_socket_2,
            PublicKey::from_str(OTHER_PEER_PUBKEY).unwrap().encode(),
            PublicKey::from_str(PEER_PUBKEY).unwrap().encode(),
        )
        .await;
        let mutiny_ws_2 = WsSocketDescriptor::Mutiny(sub_ws_socket_2);
        assert_ne!(mutiny_ws, mutiny_ws_2);

        let (send_to_multi_socket_3, _): (Sender<Message>, Receiver<Message>) = unbounded();

        let socket_map_3: SubSocketMap = Arc::new(Mutex::new(HashMap::new()));
        let (send_to_sub_socket_3, read_from_multi_socket_3): (Sender<Message>, Receiver<Message>) =
            unbounded();
        let sub_ws_socket_3 = create_new_subsocket(
            socket_map_3.clone(),
            send_to_multi_socket_3.clone(),
            send_to_sub_socket_3,
            read_from_multi_socket_3,
            PublicKey::from_str(OTHER_PEER_PUBKEY).unwrap().encode(),
            PublicKey::from_str(PEER_PUBKEY).unwrap().encode(),
        )
        .await;
        let mutiny_ws_3 = WsSocketDescriptor::Mutiny(sub_ws_socket_3);
        assert_eq!(mutiny_ws_3.clone(), mutiny_ws_3);
    }
}
