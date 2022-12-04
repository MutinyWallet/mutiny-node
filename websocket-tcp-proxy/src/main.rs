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
use futures::lock::Mutex;
use serde::{de, Deserialize, Deserializer};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::{env, fmt, str::FromStr};
use tokio::sync::mpsc::{self, Sender};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tower_http::trace::{DefaultMakeSpan, TraceLayer};

const PUBKEY_BYTES_LEN: usize = 33;

pub(crate) type WSMap = Arc<Mutex<HashMap<bytes::Bytes, Sender<MutinyWSCommand>>>>;

// TODO make all of these required
#[derive(Deserialize)]
struct MutinyConnectionParams {
    #[serde(default, deserialize_with = "empty_string_as_none")]
    _message: Option<String>,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    _session_id: Option<String>,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    _signature: Option<String>,
}

/// Serde deserialization decorator to map empty Strings to None,
fn empty_string_as_none<'de, D, T>(de: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: fmt::Display,
{
    let opt = Option::<String>::deserialize(de)?;
    match opt.as_deref() {
        None | Some("") => Ok(None),
        Some(s) => FromStr::from_str(s).map_err(de::Error::custom).map(Some),
    }
}

#[tokio::main]
async fn main() {
    println!("Running websocket-tcp-proxy");
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

    let port = match env::var("MUTINY_PROXY_PORT") {
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
async fn handle_socket(mut socket: WebSocket, ip: String, port: String) {
    let addr = format_addr_from_url(ip, port);
    let server_stream = TcpStream::connect(&addr).await;
    tracing::info!("Connect to remote {:#?}", server_stream);

    if server_stream.is_err() {
        tracing::error!("Connect to remote failed {:#?}", server_stream);
        let _ = socket
            .send(Message::Text(format!("{:#?}", server_stream)))
            .await;
        return;
    }

    let mut server_stream = server_stream.unwrap();

    let mut buf = [0u8; 16384]; // the max ssl record should be 16384 by default

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
    let owner_id_bytes: Vec<u8> = if let Ok(b) = FromHex::from_hex(identifier.as_str()) {
        b
    } else {
        // drop the connection if we didn't get a good pubkey hex
        tracing::error!("could not parse hex string identifier");
        return;
    };
    let owner_id_bytes = bytes::Bytes::from(owner_id_bytes);

    // Now create one consumer and a producer that other
    // mutiny websocket connections can reference to send
    // to later. The consumer here is to listen to events
    // that should be sent down the websocket that owns this.
    let (tx, mut rx) = mpsc::channel::<MutinyWSCommand>(32);
    state
        .lock()
        .await
        .insert(owner_id_bytes.clone(), tx.clone());

    tracing::debug!("listening for {identifier} websocket or consumer channel",);
    loop {
        tokio::select! {
            // The websocket owner is sending a message to some peer
            res  = socket.recv() => {
                if let Some(msg) = res {
                    if let Ok(Message::Binary(msg)) = msg {
                        // parse the first 33 bytes to find the ID to send to
                        if msg.len() < PUBKEY_BYTES_LEN{
                            tracing::error!("msg not long enough to have pubkey (had {}), ignoring...", msg.len());
                            continue
                        }
                        let (id_bytes, message_bytes) = msg.split_at(PUBKEY_BYTES_LEN);
                        let peer_id_bytes = bytes::Bytes::from(id_bytes.to_vec());
                        tracing::debug!("received a ws msg from {identifier} to send to {:?}", peer_id_bytes);

                        // find the producer and send down it
                        if let Some(peer_tx) = state.lock().await.get(&peer_id_bytes) {
                            match peer_tx.send(MutinyWSCommand::Send { id: owner_id_bytes.clone(), val: bytes::Bytes::from(message_bytes.to_vec()) }).await {
                                Ok(_) => (),
                                Err(e) => {
                                    tracing::error!("could not send message to peer identity: {}", e);
                                    // TODO return a close command, we are having a problem sending
                                    // to the other peer's consumer
                                },
                            }
                        } else {
                            // TODO if no producer, return a close command
                            tracing::error!("no producer found, ignoring");
                        }
                    }
                } else {
                    // Websocket owner closed the connection, let's remove the
                    // producer from state. When others try to access producer
                    // again, they will not find it and need to close the conn.
                    state.lock().await.remove(&owner_id_bytes);
                    tracing::info!("Websocket owner closed the connection");
                    return;
                }
            },
            // some peer is trying to send a message to the websocket owner
            res  = rx.recv() => {
                match res {
                    Some(message) => {
                        match message {
                            MutinyWSCommand::Send{id, val} => {
                                tracing::debug!("received an channel msg from {:?} to send to {identifier}", id);
                                // put in first 33 bytes as from ID
                                let mut concat_bytes = id[..].to_vec();
                                let mut val_bytes = val[..].to_vec();
                                concat_bytes.append(&mut val_bytes);
                                match socket.send(Message::Binary(concat_bytes)).await {
                                    Ok(_) => (),
                                    Err(e) => {
                                        // if we can't send down websocket, kill the connection
                                        tracing::error!("could not send message to ws owner: {}", e);
                                        state.lock().await.remove(&owner_id_bytes);
                                        return;
                                    },
                                }
                            }
                        };
                    },
                    None => {
                        tracing::info!("channel closed");
                        return;
                    }
                }
            },
        }
    }
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
