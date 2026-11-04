//! The hub's side of a relay's connection: HTTP/2, its session a WebSocket over the extended
//! CONNECT (RFC 8441), as `vk-hub/src/server.rs` serves it.

use std::future::Future;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::sync::oneshot;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};

pub use vk_peer::session::{Io, Ws};

/// The client preface every HTTP/2 connection starts with.
pub const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The hub's connection window, raised for a relay's submissions.
const CONNECTION_WINDOW: u32 = 4 << 20;

/// Serve a relay's HTTP/2 connection on `io`: its session's `CONNECT` answered 200 and its
/// WebSocket handed to the receiver, and every other request answered by `other`, an error
/// resetting its stream. The future
/// drives the connection until it closes, gracefully once `closing` is ready.
pub fn serve<H, F>(
    io: Box<dyn Io>,
    other: H,
    closing: impl Future<Output = ()> + Send + 'static,
) -> (impl Future<Output = ()> + Send, oneshot::Receiver<Ws>)
where
    H: Fn(Request<Incoming>) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<Response<Full<Bytes>>, std::io::Error>> + Send + 'static,
{
    let (tx, rx) = oneshot::channel();
    let tx = std::sync::Arc::new(std::sync::Mutex::new(Some(tx)));
    let service = service_fn(move |mut req: Request<Incoming>| {
        let (tx, other) = (tx.clone(), other.clone());
        async move {
            let session = req.method() == hyper::Method::CONNECT
                && req.uri().path() == vk_hub_proto::gitlab::SESSION_PATH
                && req
                    .extensions()
                    .get::<hyper::ext::Protocol>()
                    .is_some_and(|p| p.as_str() == "websocket");
            if !session {
                return other(req).await;
            }
            let Some(tx) = tx.lock().unwrap().take() else {
                return Ok(Response::builder()
                    .status(403)
                    .body(Full::new(Bytes::new()))
                    .unwrap());
            };
            let upgrade = hyper::upgrade::on(&mut req);
            tokio::spawn(async move {
                let Ok(upgraded) = upgrade.await else {
                    return;
                };
                let config = WebSocketConfig::default()
                    .max_message_size(Some(vk_hub_proto::MAX_MESSAGE))
                    .max_frame_size(Some(vk_hub_proto::MAX_MESSAGE));
                let io: Box<dyn Io> = Box::new(TokioIo::new(upgraded));
                let ws = WebSocketStream::from_raw_socket(io, Role::Server, Some(config)).await;
                let _ = tx.send(ws);
            });
            Ok(Response::new(Full::new(Bytes::new())))
        }
    });
    let mut builder = http2::Builder::new(TokioExecutor::new());
    builder
        .timer(TokioTimer::new())
        .enable_connect_protocol()
        .initial_connection_window_size(CONNECTION_WINDOW);
    let conn = async move {
        let conn = builder.serve_connection(TokioIo::new(io), service);
        tokio::pin!(conn);
        tokio::select! {
            _ = conn.as_mut() => return,
            () = closing => {}
        }
        conn.as_mut().graceful_shutdown();
        let _ = conn.await;
    };
    (conn, rx)
}

/// Whether `stream` starts with the HTTP/2 preface, as a plain listener tells a relay.
pub async fn is_h2(stream: &tokio::net::TcpStream) -> bool {
    let mut head = [0u8; H2_PREFACE.len()];
    loop {
        let Ok(n) = stream.peek(&mut head).await else {
            return false;
        };
        if n == 0 || !H2_PREFACE.starts_with(&head[..n]) {
            return false;
        }
        if n == H2_PREFACE.len() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

/// Accept a relay's connection on `listener` and take its session's WebSocket; the
/// connection's other requests are answered 404.
pub async fn accept(listener: &tokio::net::TcpListener) -> Ws {
    let (tcp, _) = listener.accept().await.unwrap();
    let (conn, ws) = serve(
        Box::new(tcp),
        |_| async {
            Ok(Response::builder()
                .status(404)
                .body(Full::new(Bytes::new()))
                .unwrap())
        },
        std::future::pending(),
    );
    tokio::spawn(conn);
    ws.await.expect("the relay opens its session")
}
