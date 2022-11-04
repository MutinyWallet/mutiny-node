use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, TypedHeader,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tower_http::trace::{DefaultMakeSpan, TraceLayer};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new().route("/v1/:ip/:port", get(ws_handler)).layer(
        TraceLayer::new_for_http().make_span_with(DefaultMakeSpan::default().include_headers(true)),
    );

    // TODO let this be configurable
    let addr = SocketAddr::from(([127, 0, 0, 1], 3001));
    tracing::info!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
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
