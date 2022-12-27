use crate::node::PeerManager;
use crate::proxy::Proxy;
use crate::utils;
use crossbeam_channel::{unbounded, Receiver, Sender};
use futures::lock::Mutex;
use futures::{SinkExt, StreamExt};
use gloo_net::websocket::events::CloseEvent;
use gloo_net::websocket::Message;
use lightning::ln::peer_handler::{self, SocketDescriptor};
use log::{debug, error, info, trace, warn};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
enum MutinyProxyCommand {
    Disconnect { to: Vec<u8>, from: Vec<u8> },
}

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
    read_from_sub_socket: Receiver<Message>,
    send_to_multi_socket: Sender<Message>,
    socket_map: Arc<Mutex<HashMap<Vec<u8>, (SubWsSocketDescriptor, Sender<Message>)>>>,
    peer_manager: Arc<PeerManager>,
    connected: Arc<AtomicBool>,
}
impl MultiWsSocketDescriptor {
    pub fn new(conn: Arc<Proxy>, peer_manager: Arc<PeerManager>) -> Self {
        debug!("setting up multi websocket descriptor");

        let (send_to_multi_socket, read_from_sub_socket): (Sender<Message>, Receiver<Message>) =
            unbounded();

        let socket_map: Arc<Mutex<HashMap<Vec<u8>, (SubWsSocketDescriptor, Sender<Message>)>>> =
            Arc::new(Mutex::new(HashMap::new()));

        Self {
            conn,
            send_to_multi_socket,
            read_from_sub_socket,
            socket_map,
            peer_manager,
            connected: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    pub async fn reconnect(&mut self, conn: Arc<Proxy>) {
        debug!("setting up multi websocket descriptor");
        // if reconnecting master socket, disconnect and clear all subsockets
        for (_id, (subsocket, _sender)) in self.socket_map.lock().await.iter_mut() {
            // tell the subsocket to stop processing
            // and ldk to disconnect that peer
            subsocket.disconnect_socket();
            self.peer_manager
                .socket_disconnected(&WsSocketDescriptor::Mutiny(subsocket.clone()));
        }

        self.socket_map.lock().await.clear();
        self.conn = conn;
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
        debug!("spawning multi socket connection reader");
        spawn_local(async move {
            while let Some(msg) = conn_copy.read.lock().await.next().await {
                if let Ok(msg) = msg {
                    match msg {
                        Message::Text(msg) => {
                            // This is a text command from the server. Parse the type
                            // of command it is and act accordingly.
                            // parse and implement subsocket disconnections.
                            // TODO right now subsocket is very tied to a specific node,
                            // later we should share a single connection amongst all pubkeys and in
                            // which case "to" will be important to parse.
                            let command: MutinyProxyCommand =
                                serde_json::from_str(&msg).expect("could not parse"); // TODO remove
                            match command {
                                MutinyProxyCommand::Disconnect { to: _to, from } => {
                                    let mut locked_socket_map = socket_map_copy.lock().await;
                                    match locked_socket_map.get_mut(&from) {
                                        Some((subsocket, _sender)) => {
                                            debug!("disconnecting subsocket");
                                            subsocket.disconnect_socket();
                                            peer_manager_copy.socket_disconnected(
                                                &WsSocketDescriptor::Mutiny(subsocket.clone()),
                                            );
                                            locked_socket_map.remove(&from);
                                        }
                                        None => {
                                            debug!("tried to disconnect a subsocket that doesn't exist...");
                                        }
                                    }
                                }
                            };
                        }
                        Message::Bytes(msg) => {
                            debug!("received a binary message on multi socket...");
                            // This is a mutiny to mutiny connection with pubkey + bytes
                            // as the binary message. Parse the msg and see which pubkey
                            // it belongs to.
                            if msg.len() < PUBKEY_BYTES_LEN {
                                debug!("msg not long enough to have pubkey, ignoring...");
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
                                            debug!(
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
                                            debug!(
                                                "gave new subsocket to peer manager: {:?}",
                                                id_bytes
                                            );
                                            schedule_descriptor_read(
                                                inbound_subsocket,
                                                peer_manager_copy.clone(),
                                            );

                                            // now that we have the inbound connection, send the original
                                            // message to our new subsocket descriptor
                                            match socket_map_copy.lock().await.get(id_bytes) {
                                                Some((_subsocket, sender)) => {
                                                    match sender.send(Message::Bytes(
                                                        message_bytes.to_vec(),
                                                    )) {
                                                        Ok(_) => {
                                                            debug!("sent incoming message to new subsocket channel: {:?}", id_bytes)
                                                        }
                                                        Err(e) => {
                                                            error!(
                                                                "error sending msg to channel: {}",
                                                                e
                                                            )
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
                        Message::Text(_) => {
                            debug!("Nodes should not be sending text to the proxy, ignoring..");
                        }
                        Message::Bytes(b) => {
                            debug!("multi socket channel reader sending bytes to proxy");
                            conn_copy_send.send(b)
                        }
                    }
                }
                if !connected_copy_send.load(Ordering::Relaxed) {
                    break;
                }
                utils::sleep(50).await;
            }
            debug!("leaving multi socket channel reader");
        });
    }
}

pub(crate) fn schedule_descriptor_read(
    descriptor: WsSocketDescriptor,
    peer_manager: Arc<PeerManager>,
) {
    debug!("scheduling descriptor reader");
    let mut descriptor = descriptor;
    spawn_local(async move {
        while let Some(msg) = descriptor.read().await {
            match msg {
                Ok(msg_contents) => {
                    match msg_contents {
                        Message::Text(t) => {
                            trace!("received text command from websocket");
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
                    error!("got an error reading msg: {}", e);
                    break;
                }
            }
        }

        // TODO when we detect an error, lock the writes and close connection.
        // TODO this, or something, should trigger LDK disconnection
        info!("WebSocket Closed")
    });
}

async fn create_new_subsocket(
    socket_map: Arc<Mutex<HashMap<Vec<u8>, (SubWsSocketDescriptor, Sender<Message>)>>>,
    send_to_multi_socket: Sender<Message>,
    id: Vec<u8>,
) -> SubWsSocketDescriptor {
    let (send_to_sub_socket, read_from_multi_socket): (Sender<Message>, Receiver<Message>) =
        unbounded();

    let new_subsocket =
        SubWsSocketDescriptor::new(send_to_multi_socket, read_from_multi_socket, id.clone());

    socket_map
        .lock()
        .await
        .insert(id, (new_subsocket.clone(), send_to_sub_socket));

    new_subsocket
}

pub(crate) struct SubWsSocketDescriptor {
    send_channel: Sender<Message>,
    read_channel: Receiver<Message>,
    pubkey_bytes: Vec<u8>,
    id: u64,
    stop: Arc<AtomicBool>,
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
            stop: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl ReadDescriptor for SubWsSocketDescriptor {
    async fn read(&self) -> Option<Result<Message, gloo_net::websocket::WebSocketError>> {
        // TODO delete this debug, will be noisy
        debug!("starting subsocket channel reader");
        loop {
            if self.stop.load(Ordering::Relaxed) {
                debug!("stopping subsocket channel reader");
                return Some(Err(gloo_net::websocket::WebSocketError::ConnectionClose(
                    CloseEvent {
                        code: 0,
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
            debug!("ignoring request to send down stopped subsocket");
            return 0;
        }

        let mut addr_prefix = self.pubkey_bytes.to_vec();
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
        debug!("disconnecting socket from LDK");
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
            pubkey_bytes: self.pubkey_bytes.clone(),
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
