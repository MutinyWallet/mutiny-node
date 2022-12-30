use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State, TypedHeader,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use bitcoin_hashes::hex::FromHex;
use bytes::Bytes;
use futures::executor::block_on;
use futures::lock::Mutex;
use ln_websocket_proxy::MutinyProxyCommand;
use serde::Deserialize;
use serde_with::{serde_as, NoneAsEmptyString};
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tower_http::trace::{DefaultMakeSpan, TraceLayer};

const PUBKEY_BYTES_LEN: usize = 33;

pub(crate) type WSMap =
    Arc<Mutex<HashMap<bytes::Bytes, (mpsc::Sender<MutinyWSCommand>, broadcast::Sender<bool>)>>>;

// TODO make all of these required
// can remove serde_with/serde_as afterwards
#[serde_as]
#[derive(Deserialize)]
struct MutinyConnectionParams {
    #[serde_as(as = "NoneAsEmptyString")]
    _message: Option<String>,
    #[serde_as(as = "NoneAsEmptyString")]
    _session_id: Option<String>,
    #[serde_as(as = "NoneAsEmptyString")]
    _signature: Option<String>,
}

#[tokio::main]
async fn main() {
    println!("Running ln-websocket-proxy");
    tracing_subscriber::fmt::init();

    let producer_map: WSMap = Arc::new(Mutex::new(HashMap::new()));

    let app = Router::new()
        .route("/v1/:ip/:port", get(ws_handler))
        .route("/v1/mutiny/:identifier", get(mutiny_ws_handler))
        .with_state(producer_map)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::default().include_headers(true)),
        );

    let port = match env::var("LN_PROXY_PORT") {
        Ok(p) => p.parse().expect("port must be a u16 string"),
        Err(_) => 3001,
    };
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
    println!("Stopping websocket-tcp-proxy");
}

async fn ws_handler(
    Path((ip, port)): Path<(String, String)>,
    ws: WebSocketUpgrade,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
) -> impl IntoResponse {
    tracing::info!("ip: {}, port: {}", ip, port);
    if let Some(TypedHeader(user_agent)) = user_agent {
        tracing::info!("`{}` connected", user_agent.as_str());
    }

    ws.protocols(["binary"])
        .on_upgrade(move |socket| handle_socket(socket, ip, port))
}

fn format_addr_from_url(ip: String, port: String) -> String {
    format!("{}:{}", ip.replace('_', "."), port)
}

// Big help from https://github.com/HsuJv/axum-websockify
async fn handle_socket(mut socket: WebSocket, host: String, port: String) {
    let addr_str = format_addr_from_url(host, port);
    let addrs = addr_str.to_socket_addrs();

    if addrs.is_err() || addrs.as_ref().unwrap().len() == 0 {
        tracing::error!("Could not resolve addr {addr_str}");
        let _ = socket
            .send(Message::Text(format!("Could not resolve addr {addr_str}")))
            .await;
        return;
    }

    let mut addrs = addrs.unwrap();

    let server_stream = addrs.find_map(|addr| {
        let connection = block_on(TcpStream::connect(&addr));
        if let Err(error) = &connection {
            tracing::error!("Could not connect to {addr}: {error}");
        };

        connection.ok()
    });

    if server_stream.is_none() {
        tracing::error!("Could not connect to: {addr_str}");
        let _ = socket
            .send(Message::Text(format!("Could not connect to: {addr_str}")))
            .await;
        return;
    }

    let mut server_stream = server_stream.unwrap();

    let addr = server_stream.peer_addr().unwrap();

    let mut buf = [0u8; 65536]; // the max lightning message size is 65536

    loop {
        tokio::select! {
            res  = socket.recv() => {
                if let Some(msg) = res {
                    if let Ok(Message::Binary(msg)) = msg {
                        tracing::debug!("Received {}, sending to {addr}", &msg.len());
                        let _ = server_stream.write_all(&msg).await;
                    }
                } else {
                    tracing::info!("Client close");
                    return;
                }
            },
            res  = server_stream.read(&mut buf) => {
                match res {
                    Ok(n) => {
                        tracing::debug!("Read {:?} from {addr}", n);
                        if 0 != n {
                            let _ = socket.send(Message::Binary(buf[..n].to_vec())).await;
                        } else {
                            return ;
                        }
                    },
                    Err(e) => {
                        tracing::info!("Server close with err {:?}", e);
                        return;
                    }
                }
            },
        }
    }
}

async fn mutiny_ws_handler(
    params: Query<MutinyConnectionParams>,
    Path(identifier): Path<String>,
    State(state): State<WSMap>,
    ws: WebSocketUpgrade,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
) -> impl IntoResponse {
    tracing::info!("new mutiny websocket handler: {identifier}");
    if let Some(TypedHeader(user_agent)) = user_agent {
        tracing::info!("`{}` connected", user_agent.as_str());
    }

    ws.protocols(["binary"])
        .on_upgrade(move |socket| handle_mutiny_ws(socket, identifier, params, state))
}

#[derive(Debug)]
enum MutinyWSCommand {
    Send { id: Bytes, val: Bytes },
    Disconnect { id: Bytes },
}

/// handle_mutiny_ws will handle mutiny to mutiny (ws to ws) logic.
/// A node pubkey will have a connection URL like: /v1/mutiny/{identifier}
/// where identifier is either going to be arbitrary or based on their node
/// pubkey. Future iterations might want a single identifier for all their
/// nodes. This should be persistent enough to allow others to reconnect.
///
/// Owners:
/// Need to send a signed message with the private key in order to
/// verify that they are the owners. Afterwards, they will receive
/// all incoming messages. If owner is already registered, kill new one.
///
/// Sending:
/// Indicate which identifier you would like to message and the bytes to
/// send. This should be the first 33 bytes of the message. If the owner
/// is not connected or disconnections, the connection should be killed.
/// This proxy will replace the 33 bytes with the identifier of the sender.
///
/// Receiving:
/// You will receive a message with the first 33 bytes being the identifier
/// that has sent the message and the rest of the bytes being the message.
/// When replying to a received message, set the first 33 bytes to be the
/// destination that had sent to you. IE, keeping same first 33 bytes.
async fn handle_mutiny_ws(
    mut socket: WebSocket,
    identifier: String,
    _params: Query<MutinyConnectionParams>,
    state: WSMap,
) {
    // TODO do verification on the params and identifier
    // This is important so that only the node with the
    // private key can read and send messages through
    // this socket.
    #[allow(clippy::redundant_closure)]
    let owner_id_bytes = FromHex::from_hex(identifier.as_str())
        .map(|h: Vec<u8>| bytes::Bytes::from(h))
        .unwrap_or_default();
    if owner_id_bytes.is_empty() {
        tracing::error!("could not parse hex string identifier");
        return;
    }

    // Now create one consumer and a producer that other
    // mutiny websocket connections can reference to send
    // to later. The consumer here is to listen to events
    // that should be sent down the websocket that owns this.
    let (tx, mut rx) = mpsc::channel::<MutinyWSCommand>(32);

    // Create a broadcast channel that this websocket owner can post
    // to in order to indicate that the websocket owner went away and
    // that all previously connected peers need to force a disconnect.
    // The boolean is arbitrary, we just need to send something, consumers
    // should know who this is from and what it means.
    let (bc_tx, _bc_rx1) = broadcast::channel::<bool>(32);

    state
        .lock()
        .await
        .insert(owner_id_bytes.clone(), (tx.clone(), bc_tx.clone()));

    // keep track of the peers that this websocket owner is connected to
    let connected_peers = Arc::new(Mutex::new(HashSet::<bytes::Bytes>::new()));

    tracing::debug!("listening for {identifier} websocket or consumer channel",);
    loop {
        tokio::select! {
            // The websocket owner is sending a message to some peer
            // or got disconnected.
            res  = socket.recv() => {
                if let Some(msg) = res {
                    if let Ok(msg_wrapper) = msg {
                        match msg_wrapper {
                            Message::Text(msg) => {
                            let command: MutinyProxyCommand = match serde_json::from_str(&msg) {
                                Ok(c) => c,
                                Err(e) => {
                                    tracing::error!("couldn't parse text command from client, ignoring: {e}");
                                    continue;
                                }
                            };
                            match command {
                                MutinyProxyCommand::Disconnect { to, from: _from } => {
                                    // ignore the from and take it from our websocket owner
                                    // find out who we are supposed to send this to and get
                                    // producer
                                    let peer_id_bytes = bytes::Bytes::from(to);
                                    if let Some((peer_tx, _bc_tx)) = state.lock().await.get(&peer_id_bytes) {
                                        try_send_disconnect_ws_command(peer_tx.clone(), owner_id_bytes.clone()).await;
                                        connected_peers.lock().await.remove(&peer_id_bytes);
                                    } else {
                                        tracing::error!("peer tried to disconnect someone not connected to");
                                    }
                                }
                            };
                            },
                            Message::Binary(msg) => {
                                // parse the first 33 bytes to find the ID to send to
                                if msg.len() < PUBKEY_BYTES_LEN {
                                    tracing::error!("msg not long enough to have pubkey (had {}), ignoring...", msg.len());
                                    continue
                                }
                                let (id_bytes, message_bytes) = msg.split_at(PUBKEY_BYTES_LEN);
                                let peer_id_bytes = bytes::Bytes::from(id_bytes.to_vec());
                                tracing::debug!("received a ws msg from {identifier} to send to {:?}", peer_id_bytes);

                                // find the producer and send down it
                                if let Some((peer_tx, bc_tx)) = state.lock().await.get(&peer_id_bytes) {
                                    match peer_tx.send(MutinyWSCommand::Send { id: owner_id_bytes.clone(), val: bytes::Bytes::from(message_bytes.to_vec()) }).await {
                                        Ok(_) => {
                                            // Keep track that this websocket owner is connected to this
                                            // peer. We will need to know when to send a disconnect cmd
                                            // message back to the websocket owner if this peer goes
                                            // offline.
                                            tracing::debug!("successfully sent msg to {:?}", peer_id_bytes);
                                            listen_for_disconnections(connected_peers.clone(), peer_id_bytes.clone(), bc_tx.subscribe(), tx.clone()).await;
                                        },
                                        Err(e) => {
                                            tracing::error!("could not send message to peer identity: {}", e);
                                            // return a close command, we are having a problem sending
                                            // to the other peer's consumer
                                            try_send_disconnect_ws_command(tx.clone(), peer_id_bytes).await;
                                        },
                                    }
                                } else {
                                    // if no producer, return a close command
                                    tracing::error!("no producer found, sending disconnect");
                                    try_send_disconnect_ws_command(tx.clone(), peer_id_bytes).await;
                                }
                            },
                            _ => {
                                // don't care about pings or others...
                            },
                        };
                    }
                } else {
                    // Websocket owner closed the connection, let's remove the
                    // producer from state. When others try to access producer
                    // again, they will not find it and need to close the conn.
                    //
                    // we should accelerate the disconnection instead of
                    // rely on the next message sent causing a disconnection.
                    try_broadcast_disconnect(bc_tx);
                    state.lock().await.remove(&owner_id_bytes);
                    tracing::info!("Websocket owner closed the connection");
                    return;
                }
            },
            // some peer is trying to send a message to the websocket owner
            // or a disconnection happened and the websocket owner needs to
            // disconnect from that peer.
            res  = rx.recv() => {
                match res {
                    Some(message) => {
                        match message {
                            MutinyWSCommand::Send{id, val} => {
                                tracing::debug!("received a channel msg from {:?} to send to {identifier}", id);
                                // put in first 33 bytes as from ID
                                let mut concat_bytes = id[..].to_vec();
                                let mut val_bytes = val[..].to_vec();
                                concat_bytes.append(&mut val_bytes);
                                match socket.send(Message::Binary(concat_bytes)).await {
                                    Ok(_) => {
                                        // Some other peer has successfully sent a message to this
                                        // websocket owner. We should find the broadcast channel
                                        // for that peer and let this websocket owner listen for
                                        // when it needs to disconnect.
                                        // TODO, but maybe it's not really needed because the
                                        // websocket owner SHOULD send a message back for us to
                                        // consider them connected, in which case the other flow
                                        // should add the listener.
                                        tracing::debug!("sent channel msg down socket from {:?} to to {identifier}", id);
                                    },
                                    Err(e) => {
                                        // if we can't send down websocket, kill the connection
                                        // send a disconnection to all peers connected to this peer
                                        tracing::error!("could not send message to ws owner: {}", e);
                                        try_broadcast_disconnect(bc_tx);
                                        state.lock().await.remove(&owner_id_bytes);
                                        return;
                                    },
                                }
                            }
                            MutinyWSCommand::Disconnect{id} => {
                                tracing::debug!("received a channel msg from {:?} to disconnect from {identifier}", id);
                                match socket.send(Message::Text(serde_json::to_string(&MutinyProxyCommand::Disconnect{to: owner_id_bytes.to_vec(), from: id.to_vec()}).unwrap())).await {
                                    Ok(_) => (),
                                    Err(e) => {
                                        // if we can't send down websocket, kill the connection
                                        // send a disconnection to all peers connected to this peer
                                        tracing::error!("could not send message to ws owner: {}", e);
                                        try_broadcast_disconnect(bc_tx);
                                        state.lock().await.remove(&owner_id_bytes);
                                        return;
                                    },
                                }
                            }
                        };
                    },
                    None => {
                        // send a disconnection to all peers
                        // that are connected to this peer
                        tracing::info!("channel closed");
                        try_broadcast_disconnect(bc_tx);
                        state.lock().await.remove(&owner_id_bytes);
                        return;
                    }
                }
            },
        }
    }
}

async fn listen_for_disconnections(
    connected_peers: Arc<Mutex<HashSet<bytes::Bytes>>>,
    other_peer: bytes::Bytes,
    mut rx: broadcast::Receiver<bool>,
    tx: mpsc::Sender<MutinyWSCommand>,
) {
    let mut locked_connected_peers = connected_peers.lock().await;
    if locked_connected_peers.contains(&other_peer) {
        return;
    }
    locked_connected_peers.insert(other_peer.clone());
    let listening_connected_peers = connected_peers.clone();
    tokio::spawn(async move {
        match rx.recv().await {
            Ok(_) => {
                // we should send a disconnection message from
                // the other peer to the websocket owner
                // we'll use the websocket command flow since that'll
                // handle the flow just fine
                try_send_disconnect_ws_command(tx.clone(), other_peer.clone()).await;
            }
            Err(e) => {
                // we got an error? well disconnect anyways I guess, but log it!
                tracing::error!(
                    "got an error listening for broadcast messages from {:?}: {}",
                    other_peer,
                    e
                );
                try_send_disconnect_ws_command(tx.clone(), other_peer.clone()).await;
            }
        };
        // should only take one message to know to disconnect
        // so we should remove the peer from owner's connected list
        // this is needed so we can listen again!
        listening_connected_peers.lock().await.remove(&other_peer);
    });
}

fn try_broadcast_disconnect(bc_tx: broadcast::Sender<bool>) {
    match bc_tx.send(true) {
        Ok(_) => (),
        Err(e) => {
            // our best effort was made to inform others that we've
            // disconnected this peer. Log it and move on.
            // We really shouldn't see this happen, would indicate a problem
            // handling channels that we should fix.
            tracing::error!(
                "could not broadcast that we've disconnected websocket owner: {}",
                e
            );
        }
    };
}

async fn try_send_disconnect_ws_command(
    tx: mpsc::Sender<MutinyWSCommand>,
    other_peer: bytes::Bytes,
) {
    match tx
        .send(MutinyWSCommand::Disconnect { id: other_peer })
        .await
    {
        Ok(_) => (),
        Err(e) => {
            tracing::error!("could not send disconnect msg to self: {}", e);
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::format_addr_from_url;

    #[tokio::test]
    async fn test_format_addr_from_url() {
        assert_eq!(
            "127.0.0.1:9000",
            format_addr_from_url(String::from("127_0_0_1"), String::from("9000"))
        )
    }
}
