use crate::node::PeerManager;
use crate::proxy::Proxy;
use crate::utils;
use crossbeam_channel::{unbounded, Receiver, Sender};
use futures::lock::Mutex;
use futures::{SinkExt, StreamExt};
use gloo_net::websocket::Message;
use lightning::ln::peer_handler;
use log::{debug, error, info, trace, warn};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

static ID_COUNTER: AtomicU64 = AtomicU64::new(0);
const PUBKEY_BYTES_LEN: usize = 33;

pub(crate) trait ReadDescriptor {
    async fn read(&self) -> Option<Result<Message, gloo_net::websocket::WebSocketError>>;
}

#[derive(Clone, Eq, PartialEq, Hash)]
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

#[derive(Clone)]
pub(crate) struct MultiWsSocketDescriptor {
    conn: Arc<Proxy>,
    id: u64,
    read_from_sub_socket: Receiver<Message>,
    send_to_multi_socket: Sender<Message>,
    socket_map: Arc<Mutex<HashMap<Vec<u8>, Sender<Message>>>>,
    peer_manager: Arc<PeerManager>,
    connected: Arc<AtomicBool>,
}
impl MultiWsSocketDescriptor {
    pub fn new(conn: Arc<Proxy>, peer_manager: Arc<PeerManager>) -> Self {
        debug!("setting up multi websocket descriptor");

        let id = ID_COUNTER.fetch_add(1, Ordering::AcqRel);
        let (send_to_multi_socket, read_from_sub_socket): (Sender<Message>, Receiver<Message>) =
            unbounded();

        let socket_map: Arc<Mutex<HashMap<Vec<u8>, Sender<Message>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        Self {
            conn,
            id,
            send_to_multi_socket,
            read_from_sub_socket,
            socket_map,
            peer_manager,
            connected: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn connected(&self) -> bool {
        return self.connected.load(Ordering::Relaxed);
    }

    pub fn reconnect(&mut self, conn: Arc<Proxy>) {
        let (send_to_multi_socket, read_from_sub_socket): (Sender<Message>, Receiver<Message>) =
            unbounded();

        let socket_map: Arc<Mutex<HashMap<Vec<u8>, Sender<Message>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        self.conn = conn;
        self.send_to_multi_socket = send_to_multi_socket;
        self.read_from_sub_socket = read_from_sub_socket;
        self.socket_map = socket_map;
        self.connected.store(true, Ordering::Relaxed);

        self.listen();
    }

    pub async fn create_new_subsocket(&self, id: Vec<u8>) -> SubWsSocketDescriptor {
        create_new_subsocket(
            self.socket_map.clone(),
            self.send_to_multi_socket.clone(),
            id,
        )
        .await
    }

    pub fn listen(&self) {
        let conn_copy = self.conn.clone();
        let socket_map_copy = self.socket_map.clone();
        let send_to_multi_socket_copy = self.send_to_multi_socket.clone();
        let peer_manager_copy = self.peer_manager.clone();
        let connected_copy = self.connected.clone();
        debug!("spawning multi socket connection reader");
        spawn_local(async move {
            while let Some(msg) = conn_copy.read.lock().await.next().await {
                if let Ok(Message::Bytes(msg)) = msg {
                    // parse the msg and see which pubkey it belongs to
                    if msg.len() < PUBKEY_BYTES_LEN {
                        debug!("msg not long enough to have pubkey, ignoring...");
                        continue;
                    }
                    let (id_bytes, message_bytes) = msg.split_at(PUBKEY_BYTES_LEN);

                    // now send that data to the right subsocket
                    let socket_lock = socket_map_copy.lock().await;
                    let found_subsocket = socket_lock.get(id_bytes);
                    match found_subsocket {
                        Some(s) => {
                            match s.send(Message::Bytes(message_bytes.to_vec())) {
                                Ok(_) => (),
                                Err(e) => error!("error sending msg to channel: {}", e),
                            };
                        }
                        None => {
                            drop(socket_lock);

                            // create a new subsocket and pass it to peer_manager
                            debug!(
                                "no connection found for socket address, creating new: {:?}",
                                id_bytes
                            );
                            let inbound_subsocket = WsSocketDescriptor::Mutiny(
                                create_new_subsocket(
                                    socket_map_copy.clone(),
                                    send_to_multi_socket_copy.clone(),
                                    id_bytes.to_vec(),
                                )
                                .await,
                            );
                            debug!("created new subsocket: {:?}", id_bytes);
                            match peer_manager_copy
                                .new_inbound_connection(inbound_subsocket.clone(), None)
                            {
                                Ok(_) => {
                                    debug!("gave new subsocket to peer manager: {:?}", id_bytes);
                                    schedule_descriptor_read(
                                        inbound_subsocket,
                                        peer_manager_copy.clone(),
                                    );

                                    // now that we have the inbound connection, send the original
                                    // message to our new subsocket descriptor
                                    match socket_map_copy.lock().await.get(id_bytes) {
                                        Some(s) => {
                                            match s.send(Message::Bytes(message_bytes.to_vec())) {
                                                Ok(_) => {
                                                    debug!("sent incoming message to new subsocket channel: {:?}", id_bytes)
                                                }
                                                Err(e) => {
                                                    error!("error sending msg to channel: {}", e)
                                                }
                                            };
                                        }
                                        None => {
                                            // TODO delete the new subsocket
                                            error!(
                                            "we can't find our newly created subsocket???: {:?}",
                                            id_bytes
                                        );
                                        }
                                    }
                                }
                                Err(_) => {
                                    // TODO delete the new subsocket
                                    error!(
                                        "peer manager could not handle subsocket for: {:?}",
                                        id_bytes
                                    );
                                }
                            };
                        }
                    };
                }
            }
            debug!("leaving multi socket connection reader");
            connected_copy.store(false, Ordering::Relaxed)
        });

        let read_channel_copy = self.read_from_sub_socket.clone();
        let conn_copy_send = self.conn.clone();
        let connected_copy_send = self.connected.clone();
        debug!("spawning multi socket channel reader");
        spawn_local(async move {
            loop {
                if let Ok(msg) = read_channel_copy.try_recv() {
                    match msg {
                        Message::Text(_) => (),
                        Message::Bytes(b) => conn_copy_send.send(b),
                    }
                }
                if !connected_copy_send.load(Ordering::Relaxed) {
                    break;
                }
                utils::sleep(50).await;
            }
        });
    }
}

pub(crate) fn schedule_descriptor_read(
    descriptor: WsSocketDescriptor,
    peer_manager: Arc<PeerManager>,
) {
    let mut descriptor = descriptor.clone();
    spawn_local(async move {
        while let Some(msg) = descriptor.read().await {
            if let Ok(msg_contents) = msg {
                match msg_contents {
                    Message::Text(t) => {
                        warn!(
                            "received text from websocket when we should only receive binary: {}",
                            t
                        )
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
        }

        // TODO when we detect an error, lock the writes and close connection.
        info!("WebSocket Closed")
    });
}

async fn create_new_subsocket(
    socket_map: Arc<Mutex<HashMap<Vec<u8>, Sender<Message>>>>,
    send_to_multi_socket: Sender<Message>,
    id: Vec<u8>,
) -> SubWsSocketDescriptor {
    let (send_to_sub_socket, read_from_multi_socket): (Sender<Message>, Receiver<Message>) =
        unbounded();

    socket_map
        .lock()
        .await
        .insert(id.clone(), send_to_sub_socket);

    SubWsSocketDescriptor::new(send_to_multi_socket.clone(), read_from_multi_socket, id)
}

pub(crate) struct SubWsSocketDescriptor {
    send_channel: Sender<Message>,
    read_channel: Receiver<Message>,
    pubkey_bytes: Vec<u8>,
    id: u64,
}
impl SubWsSocketDescriptor {
    pub fn new(
        send_channel: Sender<Message>,
        read_channel: Receiver<Message>,
        pubkey_bytes: Vec<u8>,
    ) -> Self {
        let id = ID_COUNTER.fetch_add(1, Ordering::AcqRel);
        Self {
            read_channel,
            send_channel,
            pubkey_bytes,
            id,
        }
    }
}

impl ReadDescriptor for SubWsSocketDescriptor {
    async fn read(&self) -> Option<Result<Message, gloo_net::websocket::WebSocketError>> {
        debug!("starting subsocket channel reader");
        loop {
            if let Ok(msg) = self
                .read_channel
                .try_recv()
                .map_err(|_| gloo_net::websocket::WebSocketError::ConnectionError)
            {
                return Some(Ok(msg));
            }
            utils::sleep(50).await;
        }
    }
}

impl peer_handler::SocketDescriptor for SubWsSocketDescriptor {
    fn send_data(&mut self, data: &[u8], _resume_read: bool) -> usize {
        let mut addr_prefix = Vec::from(self.pubkey_bytes.to_vec());
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
        debug!("I was supposed to disconnect but I don't really know how")
    }
}

unsafe impl Send for SubWsSocketDescriptor {}
unsafe impl Sync for SubWsSocketDescriptor {}

impl Clone for SubWsSocketDescriptor {
    fn clone(&self) -> Self {
        Self {
            read_channel: self.read_channel.clone(),
            send_channel: self.send_channel.clone(),
            pubkey_bytes: self.pubkey_bytes.clone(),
            id: self.id,
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
