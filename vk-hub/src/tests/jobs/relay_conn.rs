//! A relay's one HTTP/2 connection: its session over the extended CONNECT, which authenticates
//! the connection for the relay's unsigned client API requests, and the connection's end with
//! the session.

use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Role;
use vk_hub_proto::client::{ClientError, ReservationTicket};
use vk_hub_proto::gitlab::{self as gl, HubRelayMsg};

use super::*;

type H2Body = http_body_util::combinators::BoxBody<bytes::Bytes, std::convert::Infallible>;

/// A relay's session on its connection's stream.
type Session = vk_peer::session::Ws;

/// One HTTP/2 connection to the hub, as a relay's.
#[derive(Clone)]
pub(in crate::tests) struct H2 {
    sender: hyper::client::conn::http2::SendRequest<H2Body>,
    authority: String,
}

impl H2 {
    /// `method path` with `headers` and `body`: its status and body.
    async fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
        body: Option<Value>,
    ) -> hyper::Result<(u16, bytes::Bytes)> {
        let mut req = hyper::Request::builder()
            .method(method)
            .uri(format!("https://{}{path}", self.authority));
        for (k, v) in headers {
            req = req.header(*k, v);
        }
        let body = body.map(|b| serde_json::to_vec(&b).unwrap());
        let body = match body {
            Some(b) => {
                req = req.header("content-type", "application/json");
                http_body_util::BodyExt::boxed(http_body_util::Full::new(bytes::Bytes::from(b)))
            }
            None => http_body_util::BodyExt::boxed(http_body_util::Empty::new()),
        };
        let resp = self
            .sender
            .clone()
            .send_request(req.body(body).unwrap())
            .await?;
        let status = resp.status().as_u16();
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await?
            .to_bytes();
        Ok((status, body))
    }

    /// `CONNECT` the relay session: its status, and the stream once answered 200.
    pub(in crate::tests) async fn connect(&self) -> (u16, Option<hyper::upgrade::Upgraded>) {
        let mut req = hyper::Request::builder()
            .method("CONNECT")
            .uri(format!("https://{}{}", self.authority, gl::SESSION_PATH))
            .header("sec-websocket-version", "13")
            .body(http_body_util::BodyExt::boxed(http_body_util::Empty::new()))
            .unwrap();
        req.extensions_mut()
            .insert(hyper::ext::Protocol::from_static("websocket"));
        let resp = self.sender.clone().send_request(req).await.unwrap();
        let status = resp.status().as_u16();
        if status != 200 {
            return (status, None);
        }
        (status, Some(hyper::upgrade::on(resp).await.unwrap()))
    }

    /// `POST /v1/capacity` for runner `test`, with `extra` fields and `headers`.
    async fn capacity(&self, extra: Value, headers: &[(&str, String)]) -> (u16, bytes::Bytes) {
        let mut body = json!({"runner": "test", "placement": placement()});
        if let (Some(body), Some(extra)) = (body.as_object_mut(), extra.as_object()) {
            body.extend(extra.clone());
        }
        self.send("POST", "/v1/capacity", headers, Some(body))
            .await
            .unwrap()
    }
}

/// An HTTP/2 connection to `addr`: over TLS offering `alpn`, with the connection's exporter,
/// or plain with prior knowledge.
pub(in crate::tests) async fn dial_h2(
    addr: SocketAddr,
    tls: bool,
) -> (H2, Option<[u8; TLS_EXPORTER_LEN]>) {
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (io, exported): (Box<dyn server::Stream>, _) = if tls {
        let stream =
            super::super::connector_alpn(&[&rustls::version::TLS13], &[gl::ALPN, b"http/1.1"])
                .connect(ServerName::try_from("localhost").unwrap(), tcp)
                .await
                .unwrap();
        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(gl::ALPN));
        let exported = stream
            .get_ref()
            .1
            .export_keying_material([0; TLS_EXPORTER_LEN], TLS_EXPORTER_LABEL, None)
            .unwrap();
        (Box::new(stream), Some(exported))
    } else {
        (Box::new(tcp), None)
    };
    let (sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io))
            .await
            .unwrap();
    tokio::spawn(conn);
    let h2 = H2 {
        sender,
        authority: format!("localhost:{}", addr.port()),
    };
    (h2, exported)
}

/// A hub placing jobs over TLS, or plain, and a relay enrolled with it, not connected.
async fn hub_and_relay(tag: &str, tls: bool) -> (std::path::PathBuf, SocketAddr, Arc<Hub>, String) {
    let dir = scratch(tag);
    let db = Arc::new(Db::open_memory().unwrap());
    let (addr, hub) = serve_undriven_on(
        db,
        &dir,
        Duration::from_secs(60),
        |hub| hub,
        tls.then(super::super::tls_acceptor),
    )
    .await;
    let key = enrolled_key(&hub);
    (dir, addr, hub, key)
}

/// The relay of credential `key` ([`enrolled_key`]): its ID and key pair.
fn relay_pair(key: &str) -> (String, Ed25519KeyPair) {
    let (id, seed) = key
        .strip_prefix("relay:")
        .and_then(|k| k.split_once(':'))
        .unwrap();
    let seed: [u8; 32] = vk_hub_proto::from_hex_lower(seed).unwrap();
    (
        id.to_string(),
        Ed25519KeyPair::from_seed_unchecked(&seed).unwrap(),
    )
}

async fn next_text(ws: &mut Session) -> String {
    loop {
        match ws.next().await.unwrap().unwrap() {
            Message::Text(t) => return t.as_str().to_string(),
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("unexpected frame {other:?}"),
        }
    }
}

/// Open the session of `key`'s relay on `h2`, speaking `ours`: what the hub answered the auth
/// with, and the session.
async fn open_session(
    h2: &H2,
    key: &str,
    ours: VersionRange,
    exported: Option<&[u8; TLS_EXPORTER_LEN]>,
) -> (HubMsg, Session) {
    let (status, upgraded) = h2.connect().await;
    assert_eq!(status, 200);
    let io: Box<dyn vk_peer::session::Io> = Box::new(TokioIo::new(upgraded.unwrap()));
    let ws = WebSocketStream::from_raw_socket(io, Role::Client, None).await;
    authenticate(ws, key, ours, exported).await
}

/// The handshake of `key`'s relay on `ws`, speaking `ours`: what the hub answered the auth
/// with, and the session.
async fn authenticate(
    mut ws: Session,
    key: &str,
    ours: VersionRange,
    exported: Option<&[u8; TLS_EXPORTER_LEN]>,
) -> (HubMsg, Session) {
    let (id, pair) = relay_pair(key);
    let incarnation = "1".repeat(32);
    let hello = serde_json::to_string(&super::super::hello(&id, &incarnation, ours)).unwrap();
    ws.send(Message::text(hello)).await.unwrap();
    let msg: HubMsg = serde_json::from_str(&next_text(&mut ws).await).unwrap();
    let HubMsg::Challenge {
        version,
        versions,
        nonce,
    } = msg
    else {
        return (msg, ws);
    };
    let nonce = vk_hub_proto::from_hex(&nonce).unwrap();
    let channel = match exported {
        Some(e) => vk_hub_proto::Channel::Tls(e),
        None => vk_hub_proto::Channel::Plaintext,
    };
    let message =
        vk_hub_proto::auth_message(&nonce, &id, &incarnation, ours, versions, version, channel);
    let auth = NodeMsg::Auth {
        signature: vk_hub_proto::to_hex(pair.sign(&message).as_ref()),
    };
    ws.send(Message::text(serde_json::to_string(&auth).unwrap()))
        .await
        .unwrap();
    let msg = serde_json::from_str(&next_text(&mut ws).await).unwrap();
    (msg, ws)
}

/// Keep reading `ws`, answering the hub's pings, and pass on its messages.
fn keep_reading(mut ws: Session) -> mpsc::UnboundedReceiver<Message> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(Ok(frame)) = ws.next().await {
            let closed = matches!(frame, Message::Close(_));
            if !matches!(frame, Message::Ping(_) | Message::Pong(_)) && tx.send(frame).is_err() {
                return;
            }
            if closed {
                return;
            }
        }
    });
    rx
}

/// A relay's session up on its HTTP/2 connection: the connection, the session's messages, and
/// the TLS exporter.
async fn session_up(
    addr: SocketAddr,
    key: &str,
    tls: bool,
) -> (H2, mpsc::UnboundedReceiver<Message>) {
    let (h2, exported) = dial_h2(addr, tls).await;
    let (welcome, ws) = open_session(
        &h2,
        key,
        VersionRange {
            min: 2,
            max: gl::CONNECTION,
        },
        exported.as_ref(),
    )
    .await;
    assert!(matches!(welcome, HubMsg::Welcome { .. }), "{welcome:?}");
    (h2, keep_reading(ws))
}

fn code(body: &[u8]) -> ErrorCode {
    serde_json::from_slice::<ClientError>(body).unwrap().code
}

/// Before its session, a relay's connection serves that session alone; the session, at version
/// 5, marks it as the relay's, and its requests are then served unsigned, side by side. A key,
/// a signature, a long poll or a second session is refused there.
#[tokio::test(flavor = "multi_thread")]
async fn a_relay_s_session_authenticates_its_connection() {
    let (dir, addr, hub, key) = hub_and_relay("relay-conn", true).await;
    let (h2, exported) = dial_h2(addr, true).await;
    let (status, body) = h2.capacity(json!({}), &[]).await;
    assert_eq!((status, code(&body)), (403, ErrorCode::Forbidden));

    let (welcome, ws) = open_session(
        &h2,
        &key,
        VersionRange {
            min: 2,
            max: gl::CONNECTION,
        },
        exported.as_ref(),
    )
    .await;
    assert!(matches!(welcome, HubMsg::Welcome { .. }), "{welcome:?}");
    let _session = keep_reading(ws);
    let row = hub.db.relay(relay_id(&key)).unwrap().unwrap();
    assert_eq!(row.protocol, Some(gl::CONNECTION));

    let answers = futures::future::join_all((0..8).map(|_| h2.capacity(json!({}), &[]))).await;
    for (status, body) in answers {
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    }

    let bearer = [("authorization", format!("Bearer {}", plain_key(&hub)))];
    let (status, body) = h2.capacity(json!({}), &bearer).await;
    assert_eq!((status, code(&body)), (403, ErrorCode::Forbidden));
    let path = "/v1/capacity";
    let signed = relay_headers(&key, "POST", path, b"{}", vk_hub_proto::Channel::Plaintext);
    let (status, body) = h2.capacity(json!({}), &signed).await;
    assert_eq!((status, code(&body)), (403, ErrorCode::Forbidden));

    let (status, body) = h2.capacity(json!({"wait_secs": 1}), &[]).await;
    assert_eq!((status, code(&body)), (400, ErrorCode::Invalid));
    let mut queued = relay_reservation_body(1, 0);
    queued["queue"] = json!(true);
    let (status, body) = h2
        .send("POST", "/v1/reservations", &[], Some(queued))
        .await
        .unwrap();
    assert_eq!(status, 202, "{}", String::from_utf8_lossy(&body));
    let ticket = serde_json::from_slice::<ReservationTicket>(&body)
        .unwrap()
        .ticket;
    let path = format!("/v1/reservations/tickets/{ticket}");
    let (status, _) = h2.send("GET", &path, &[], None).await.unwrap();
    assert_eq!(status, 202);
    let (status, body) = h2
        .send("GET", &format!("{path}?wait=1"), &[], None)
        .await
        .unwrap();
    assert_eq!((status, code(&body)), (400, ErrorCode::Invalid));
    // Not polled, it does not go idle: it ends with its session.
    crate::jobs::testing::age_tickets_and_step(&hub).await;
    let (status, _) = h2.send("GET", &path, &[], None).await.unwrap();
    assert_eq!(status, 202);

    assert_eq!(h2.connect().await.0, 403);
    let (status, _) = h2
        .send("POST", gl::ENROLL_PATH, &[], Some(json!({})))
        .await
        .unwrap();
    assert_eq!(status, 403);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// HTTP/2 is a relay's alone: a client offering `h2` stays on HTTP/1.1, and a relay that does
/// not speak version 5 is refused a session over HTTP/2.
#[tokio::test(flavor = "multi_thread")]
async fn http2_is_for_relays_at_version_5_alone() {
    let (dir, addr, _hub, key) = hub_and_relay("relay-conn-only", true).await;
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let stream = super::super::connector_alpn(&[&rustls::version::TLS13], &[b"h2", b"http/1.1"])
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));

    let (h2, exported) = dial_h2(addr, true).await;
    let released = VersionRange {
        min: 2,
        max: gl::RUNNERS,
    };
    let (refused, _) = open_session(&h2, &key, released, exported.as_ref()).await;
    assert!(
        matches!(
            refused,
            HubMsg::Refused {
                code: vk_hub_proto::RefusalCode::Version,
                ..
            }
        ),
        "{refused:?}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A plain listener tells a relay's HTTP/2 connection by its preface, and serves HTTP/1.1
/// beside it.
#[tokio::test(flavor = "multi_thread")]
async fn a_plain_listener_serves_a_relay_over_http2_with_prior_knowledge() {
    let (dir, addr, hub, key) = hub_and_relay("relay-conn-h2c", false).await;
    let (h2, _session) = session_up(addr, &key, false).await;
    let (status, body) = h2.capacity(json!({}), &[]).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let resp = api(
        addr,
        "POST",
        "/v1/capacity",
        Some(&plain_key(&hub)),
        Some(json!({"placement": placement()})),
    )
    .await;
    assert_eq!(resp.status, 200, "{resp:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Once its session ends, a relay's connection serves no new request and closes; the tickets
/// queued on it end with the session.
#[tokio::test(flavor = "multi_thread")]
async fn a_relay_s_connection_and_tickets_end_with_its_session() {
    let (dir, addr, _hub, key) = hub_and_relay("relay-conn-end", true).await;
    let (h2, mut session) = session_up(addr, &key, true).await;
    let mut queued = relay_reservation_body(1, 0);
    queued["queue"] = json!(true);
    let (status, body) = h2
        .send("POST", "/v1/reservations", &[], Some(queued))
        .await
        .unwrap();
    assert_eq!(status, 202, "{}", String::from_utf8_lossy(&body));
    let ticket = serde_json::from_slice::<ReservationTicket>(&body)
        .unwrap()
        .ticket;

    // Superseded by a newer session of the relay.
    let (newer, _newer_session) = session_up(addr, &key, true).await;
    let Some(Message::Text(text)) = session.recv().await else {
        panic!("the session was not told");
    };
    assert!(matches!(
        serde_json::from_str::<HubRelayMsg>(text.as_str()).unwrap(),
        HubRelayMsg::Refused {
            code: vk_hub_proto::RefusalCode::Superseded,
            ..
        }
    ));
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match h2.capacity_or_closed().await {
                None | Some(503) => break,
                Some(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .expect("the ended session's connection served on");
    tokio::time::timeout(Duration::from_secs(10), async {
        while !h2.sender.is_closed() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the ended session's connection stayed open");

    let path = format!("/v1/reservations/tickets/{ticket}");
    let (status, _) = newer.send("GET", &path, &[], None).await.unwrap();
    assert_eq!(status, 410);
    std::fs::remove_dir_all(&dir).unwrap();
}

impl H2 {
    /// A capacity request's status, or `None` once the connection takes no new request.
    async fn capacity_or_closed(&self) -> Option<u16> {
        let body = json!({"runner": "test", "placement": placement()});
        self.send("POST", "/v1/capacity", &[], Some(body))
            .await
            .ok()
            .map(|(status, _)| status)
    }
}

/// A hand-over closes every relay session, so their connections drain rather than hold it.
#[tokio::test(flavor = "multi_thread")]
async fn a_hand_over_closes_relay_sessions() {
    let (dir, addr, hub, key) = hub_and_relay("relay-conn-handover", true).await;
    let (h2, mut session) = session_up(addr, &key, true).await;
    let (status, _) = h2.capacity(json!({}), &[]).await;
    assert_eq!(status, 200);
    hub.handover.gate.close();
    let closed = tokio::time::timeout(Duration::from_secs(5), session.recv())
        .await
        .expect("the session was not closed");
    assert!(
        matches!(closed, None | Some(Message::Close(_))),
        "{closed:?}"
    );
    assert!(hub.handover.gate.drained(Duration::from_secs(5)).await);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The next notice on `session`.
async fn notice(session: &mut mpsc::UnboundedReceiver<Message>) -> HubRelayMsg {
    let msg = tokio::time::timeout(Duration::from_secs(5), session.recv())
        .await
        .expect("no notice came");
    let Some(Message::Text(text)) = msg else {
        panic!("not a notice: {msg:?}");
    };
    serde_json::from_str(text.as_str()).unwrap()
}

/// A relay's session tells it when its ticket ends and its job moves, not when it queues a
/// ticket; a finished, written job is told of again to the next session until it is settled.
#[tokio::test(flavor = "multi_thread")]
async fn a_relay_is_told_when_its_tickets_and_jobs_change() {
    let (dir, addr, _hub, key) = hub_and_relay("relay-conn-notices", false).await;
    let (h2, mut session) = session_up(addr, &key, false).await;

    let mut queued = relay_reservation_body(1, 0);
    queued["queue"] = json!(true);
    let (status, body) = h2
        .send("POST", "/v1/reservations", &[], Some(queued))
        .await
        .unwrap();
    assert_eq!(status, 202, "{}", String::from_utf8_lossy(&body));
    let ticket = serde_json::from_slice::<ReservationTicket>(&body)
        .unwrap()
        .ticket;
    let path = format!("/v1/reservations/tickets/{ticket}");
    let (status, _) = h2.send("DELETE", &path, &[], None).await.unwrap();
    assert_eq!(status, 204);
    assert_eq!(
        notice(&mut session).await,
        HubRelayMsg::Ticket {
            ticket: ticket.clone()
        }
    );

    let (status, body) = h2
        .send("POST", "/v1/jobs", &[], Some(job_body(2, None, 30)))
        .await
        .unwrap();
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let view = serde_json::from_slice::<JobView>(&body).unwrap();
    assert_eq!(
        notice(&mut session).await,
        HubRelayMsg::Job {
            job: view.id.clone(),
            revision: view.revision,
            output_len: 0,
        }
    );
    let cancel = format!("/v1/jobs/{}/cancel", view.id);
    let (status, body) = h2
        .send("POST", &cancel, &[], Some(json!({"mode": "graceful"})))
        .await
        .unwrap();
    assert_eq!(status, 202, "{}", String::from_utf8_lossy(&body));
    let HubRelayMsg::Job { revision, .. } = notice(&mut session).await else {
        panic!("not a job notice");
    };
    let (status, body) = h2
        .send("GET", &format!("/v1/jobs/{}", view.id), &[], None)
        .await
        .unwrap();
    assert_eq!(status, 200);
    let ended = serde_json::from_slice::<JobView>(&body).unwrap();
    assert_eq!(ended.state, JobState::Finished);
    assert_eq!(revision, ended.revision);

    // A new session is told of the job anew, from its stored row, and of the ended ticket.
    let (h2, mut session) = session_up(addr, &key, false).await;
    let mut heard = vec![notice(&mut session).await, notice(&mut session).await];
    heard.sort_by_key(|n| matches!(n, HubRelayMsg::Job { .. }));
    assert_eq!(
        heard,
        [
            HubRelayMsg::Ticket { ticket },
            HubRelayMsg::Job {
                job: view.id.clone(),
                revision: ended.revision,
                output_len: 0,
            }
        ]
    );
    let settle = format!("/v1/jobs/{}/settle", view.id);
    let (status, _) = h2.send("POST", &settle, &[], None).await.unwrap();
    assert_eq!(status, 204);

    // Settled, it is told of no more.
    let (_h2, mut session) = session_up(addr, &key, false).await;
    assert!(matches!(
        notice(&mut session).await,
        HubRelayMsg::Ticket { .. }
    ));
    let more = tokio::time::timeout(Duration::from_millis(500), session.recv()).await;
    assert!(more.is_err(), "{more:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `vk-peer`'s dial of a relay's connection, over TLS and plain: the session it opens
/// authenticates the connection its request sender is on.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_opens_a_relay_s_connection() {
    for tls in [true, false] {
        let (dir, addr, _hub, key) = hub_and_relay("relay-conn-peer", tls).await;
        let scheme = if tls { "https" } else { "http" };
        let hub = format!("{scheme}://localhost:{}", addr.port());
        let config = Arc::new(super::super::client_config(&[&rustls::version::TLS13], &[]));
        let conn = vk_peer::session::connect_relay::<http_body_util::Full<bytes::Bytes>>(
            &hub,
            &config,
            &hyper::client::conn::http2::Builder::new(TokioExecutor::new()),
            gl::SESSION_PATH,
        )
        .await
        .unwrap();
        assert_eq!(conn.exported.is_some(), tls);
        let ours = VersionRange {
            min: 2,
            max: gl::CONNECTION,
        };
        let (welcome, ws) = authenticate(conn.ws, &key, ours, conn.exported.as_ref()).await;
        assert!(matches!(welcome, HubMsg::Welcome { .. }), "{welcome:?}");
        let _session = keep_reading(ws);
        let body = serde_json::to_vec(&json!({"runner": "test", "placement": placement()}));
        let req = hyper::Request::post(format!("{scheme}://{}/v1/capacity", conn.authority))
            .header("content-type", "application/json")
            .body(http_body_util::Full::new(bytes::Bytes::from(body.unwrap())))
            .unwrap();
        let resp = conn.sender.clone().send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// A hub that answers a relay's dial with HTTP/1.1, or with HTTP/2 that does not take a
/// WebSocket over CONNECT, is one to upgrade.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_finds_a_hub_without_relay_connections_outdated() {
    let dial = |hub: String| async move {
        let config = Arc::new(super::super::client_config(&[&rustls::version::TLS13], &[]));
        vk_peer::session::connect_relay::<http_body_util::Full<bytes::Bytes>>(
            &hub,
            &config,
            &hyper::client::conn::http2::Builder::new(TokioExecutor::new()),
            gl::SESSION_PATH,
        )
        .await
        .err()
        .unwrap()
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = {
        let certs = CertificateDer::pem_slice_iter(TLS_CERT)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_slice(TLS_KEY).unwrap();
        config::acceptor(certs, key, config::UI_ALPN).unwrap()
    };
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            if let Ok(stream) = acceptor.accept(tcp).await {
                tokio::spawn(async move {
                    let _held = stream;
                    tokio::time::sleep(Duration::from_secs(10)).await;
                });
            }
        }
    });
    let e = dial(format!("https://localhost:{}", addr.port())).await;
    assert!(e.is::<vk_peer::session::Outdated>(), "{e:#}");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let svc = hyper::service::service_fn(|_req| async {
                Ok::<_, std::convert::Infallible>(hyper::Response::new(http_body_util::Full::new(
                    bytes::Bytes::new(),
                )))
            });
            tokio::spawn(
                hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tcp), svc),
            );
        }
    });
    let e = dial(format!("http://localhost:{}", addr.port())).await;
    assert!(e.is::<vk_peer::session::Outdated>(), "{e:#}");
}
