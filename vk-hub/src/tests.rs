//! The hub end to end over real sockets — enrollment, the session handshake, what a session
//! records — plus the CLI's own parsing and rendering.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message;
use vk_hub_proto::{
    EnrollRequest, EnrollResponse, Heartbeat, HubMsg, Inventory, NodeMsg, PROTOCOL, RefusalCode,
    TLS_EXPORTER_LABEL, TLS_EXPORTER_LEN, VersionRange,
};

use super::*;
use crate::server::{Hub, Reach};
use crate::store::{Db, Enrollment};

/// A test CA, and the `localhost` certificate it issued the hub, both valid until 2126.
const TLS_CA: &[u8] = include_bytes!("testdata/tls-ca.pem");
const TLS_CERT: &[u8] = include_bytes!("testdata/tls-cert.pem");
const TLS_KEY: &[u8] = include_bytes!("testdata/tls-key.pem");

/// A hub on an ephemeral loopback port, plain HTTP.
async fn start() -> (SocketAddr, Arc<Hub>) {
    serve_on(None).await
}

/// A hub on an ephemeral loopback port, over TLS with the test certificate.
async fn start_tls() -> (SocketAddr, Arc<Hub>) {
    let certs = CertificateDer::pem_slice_iter(TLS_CERT)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(TLS_KEY).unwrap();
    serve_on(Some(config::acceptor(certs, key).unwrap())).await
}

async fn serve_on(tls: Option<tokio_rustls::TlsAcceptor>) -> (SocketAddr, Arc<Hub>) {
    let listener = server::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let hub = Arc::new(Hub::new(Arc::new(Db::open_memory().unwrap()), None));
    tokio::spawn(server::serve(listener, tls, hub.clone()));
    (addr, hub)
}

/// A TLS client trusting the test CA, speaking only `versions`.
fn connector(versions: &[&'static rustls::SupportedProtocolVersion]) -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(TLS_CA) {
        roots.add(cert.unwrap()).unwrap();
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(versions)
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

fn keypair() -> Ed25519KeyPair {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}

fn token(hub: &Hub) -> String {
    hub.db
        .create_token(Duration::from_secs(60), "uid 0", now_secs())
        .unwrap()
        .0
}

/// `POST /v1/enroll`, by hand: the status and the body.
async fn post_enroll(addr: SocketAddr, body: &[u8]) -> (u16, Vec<u8>) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "POST {} HTTP/1.1\r\nHost: hub\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        vk_hub_proto::ENROLL_PATH,
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.unwrap();
    let split = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let status = std::str::from_utf8(&resp[9..12]).unwrap().parse().unwrap();
    (status, resp[split + 4..].to_vec())
}

async fn enroll(addr: SocketAddr, token: &str, key: &Ed25519KeyPair) -> (u16, Vec<u8>) {
    let public_key = key.public_key().as_ref();
    let ask = EnrollRequest {
        token: token.to_string(),
        public_key: vk_hub_proto::to_hex(public_key),
        signature: vk_hub_proto::to_hex(
            key.sign(&vk_hub_proto::enroll_message(token, public_key))
                .as_ref(),
        ),
        hostname: "ci-1".into(),
    };
    post_enroll(addr, &serde_json::to_vec(&ask).unwrap()).await
}

async fn enrolled(addr: SocketAddr, hub: &Hub, key: &Ed25519KeyPair) -> String {
    let (status, body) = enroll(addr, &token(hub), key).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    serde_json::from_slice::<EnrollResponse>(&body)
        .unwrap()
        .node_id
}

type Client = tokio_tungstenite::WebSocketStream<Box<dyn server::Stream>>;

async fn dial(addr: SocketAddr) -> Client {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    upgrade(addr, Box::new(stream)).await.unwrap()
}

/// [`dial`] over TLS, with the keying material the connection exports for its auth.
async fn dial_tls(addr: SocketAddr) -> (Client, [u8; TLS_EXPORTER_LEN]) {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let stream = connector(&[&rustls::version::TLS13])
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await
        .unwrap();
    let exported = stream
        .get_ref()
        .1
        .export_keying_material([0; TLS_EXPORTER_LEN], TLS_EXPORTER_LABEL, None)
        .unwrap();
    (upgrade(addr, Box::new(stream)).await.unwrap(), exported)
}

async fn upgrade(
    addr: SocketAddr,
    stream: Box<dyn server::Stream>,
) -> Result<Client, tokio_tungstenite::tungstenite::Error> {
    let url = format!("ws://{addr}{}", vk_hub_proto::NODE_PATH);
    Ok(tokio_tungstenite::client_async(url, stream).await?.0)
}

async fn send(ws: &mut Client, msg: &NodeMsg) {
    let text = serde_json::to_string(msg).unwrap();
    ws.send(Message::text(text)).await.unwrap();
}

async fn receive(ws: &mut Client) -> HubMsg {
    loop {
        match ws.next().await.unwrap().unwrap() {
            Message::Text(t) => return serde_json::from_str(t.as_str()).unwrap(),
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("unexpected frame {other:?}"),
        }
    }
}

fn hello(node_id: &str, incarnation: &str, versions: VersionRange) -> NodeMsg {
    NodeMsg::Hello {
        versions,
        node_id: node_id.to_string(),
        incarnation: incarnation.to_string(),
        vk_version: "test".into(),
    }
}

/// Hello, challenge, auth — signed with `signer` — and what the hub answered.
async fn open(
    ws: &mut Client,
    node_id: &str,
    incarnation: &str,
    signer: &Ed25519KeyPair,
) -> HubMsg {
    open_with(ws, node_id, incarnation, signer, Twist::default()).await
}

/// How [`open_with`] departs from what an honest node on plain TCP does.
#[derive(Default)]
struct Twist<'a> {
    /// Sign for this version rather than the one the hub chose.
    version: Option<u32>,
    /// Sign for a TLS connection that exported this.
    exported: Option<&'a [u8; TLS_EXPORTER_LEN]>,
    /// Rewrite the signature's hex before sending it.
    hex: Option<fn(String) -> String>,
}

/// [`open`], with `twist`.
async fn open_with(
    ws: &mut Client,
    node_id: &str,
    incarnation: &str,
    signer: &Ed25519KeyPair,
    twist: Twist<'_>,
) -> HubMsg {
    send(ws, &hello(node_id, incarnation, PROTOCOL)).await;
    let challenge = receive(ws).await;
    authenticate(ws, challenge, node_id, incarnation, signer, twist).await
}

/// Answer `challenge` and return what the hub answered to that.
async fn authenticate(
    ws: &mut Client,
    challenge: HubMsg,
    node_id: &str,
    incarnation: &str,
    signer: &Ed25519KeyPair,
    twist: Twist<'_>,
) -> HubMsg {
    let HubMsg::Challenge {
        version,
        versions,
        nonce,
    } = challenge
    else {
        panic!("expected a challenge, got {challenge:?}");
    };
    assert_eq!(version, PROTOCOL.max);
    assert_eq!(versions, PROTOCOL);
    let nonce = vk_hub_proto::from_hex(&nonce).unwrap();
    assert_eq!(nonce.len(), vk_hub_proto::CHALLENGE_LEN);
    let signature = signer.sign(&vk_hub_proto::auth_message(
        &nonce,
        node_id,
        incarnation,
        PROTOCOL,
        versions,
        twist.version.unwrap_or(version),
        twist
            .exported
            .map_or(vk_hub_proto::Channel::Plaintext, vk_hub_proto::Channel::Tls),
    ));
    let signature = vk_hub_proto::to_hex(signature.as_ref());
    send(
        ws,
        &NodeMsg::Auth {
            signature: twist.hex.map_or(signature.clone(), |f| f(signature)),
        },
    )
    .await;
    receive(ws).await
}

/// Read until the hub closes the connection, which it must do within `within`.
async fn closed(ws: &mut Client, within: Duration) {
    tokio::time::timeout(within, async {
        loop {
            match ws.next().await {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    .expect("the hub left the connection open");
}

/// Poll `cond` until it holds, for effects a session applies after its reply.
async fn eventually(mut cond: impl FnMut() -> bool) {
    for _ in 0..200 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition never held");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_enrolls_authenticates_and_reports() {
    let (addr, hub) = start().await;
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    let incarnation = "ab".repeat(16);
    let mut ws = dial(addr).await;
    assert_eq!(
        open(&mut ws, &node_id, &incarnation, &key).await,
        HubMsg::Welcome {
            heartbeat_secs: server::HEARTBEAT_SECS
        }
    );
    let inventory = Inventory {
        hostname: "ci-1.example".into(),
        ..Inventory::default()
    };
    send(&mut ws, &NodeMsg::Inventory(inventory.clone())).await;
    send(
        &mut ws,
        &NodeMsg::Heartbeat(Heartbeat {
            desired_concurrency: Some(3),
            ..Heartbeat::default()
        }),
    )
    .await;
    eventually(|| {
        hub.db
            .node(&node_id)
            .unwrap()
            .is_some_and(|row| row.heartbeat.is_some())
    })
    .await;
    let row = hub.db.node(&node_id).unwrap().unwrap();
    assert_eq!(row.inventory, Some(inventory));
    assert_eq!(row.hostname, "ci-1.example");
    assert_eq!(row.incarnation.as_deref(), Some(incarnation.as_str()));
    assert_eq!(hub.reach(&node_id), Reach::Connected);
    ws.close(None).await.unwrap();
    eventually(|| hub.reach(&node_id) == Reach::Unreachable).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn enrollment_needs_a_live_token_and_the_matching_key() {
    let (addr, hub) = start().await;
    let key = keypair();
    let other = keypair();
    // A signature by a different key than the one being enrolled.
    let token = token(&hub);
    let ask = EnrollRequest {
        token: token.clone(),
        public_key: vk_hub_proto::to_hex(key.public_key().as_ref()),
        signature: vk_hub_proto::to_hex(
            other
                .sign(&vk_hub_proto::enroll_message(
                    &token,
                    key.public_key().as_ref(),
                ))
                .as_ref(),
        ),
        hostname: "h".into(),
    };
    let (status, _) = post_enroll(addr, &serde_json::to_vec(&ask).unwrap()).await;
    assert_eq!(status, 403);
    // The token survived the forged attempt, and is spent by the real one.
    let (status, _) = enroll(addr, &token, &key).await;
    assert_eq!(status, 200);
    let (status, _) = enroll(addr, &token, &other).await;
    assert_eq!(status, 403);
    let (status, _) = post_enroll(addr, b"{not json").await;
    assert_eq!(status, 400);
    assert_eq!(hub.db.nodes().unwrap().len(), 1);
}

/// A node whose enrollment reply was lost joins again with a fresh token and the key it
/// already made, and is the same node.
#[tokio::test(flavor = "multi_thread")]
async fn enrolling_a_pinned_key_again_answers_with_its_node() {
    let (addr, hub) = start().await;
    let key = keypair();
    let first = enrolled(addr, &hub, &key).await;
    let again = enrolled(addr, &hub, &key).await;
    assert_eq!(first, again);
    assert_eq!(hub.db.nodes().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_removed_node_is_revoked_mid_session_and_refused_after() {
    let (addr, hub) = start().await;
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    let mut ws = dial(addr).await;
    assert!(matches!(
        open(&mut ws, &node_id, &"0a".repeat(16), &key).await,
        HubMsg::Welcome { .. }
    ));
    assert!(hub.db.remove_node(&node_id, "uid 0", now_secs()).unwrap());
    hub.revoke(&node_id);
    let HubMsg::Refused { code, .. } = receive(&mut ws).await else {
        panic!("expected a refusal");
    };
    assert_eq!(code, RefusalCode::Revoked);
    let mut ws = dial(addr).await;
    send(&mut ws, &hello(&node_id, &"0a".repeat(16), PROTOCOL)).await;
    let HubMsg::Refused { code, .. } = receive(&mut ws).await else {
        panic!("expected a refusal");
    };
    assert_eq!(code, RefusalCode::NotEnrolled);
    assert!(code.is_permanent());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_silent_peer_is_dropped_in_the_handshake_and_in_the_session() {
    let (addr, hub) = start().await;
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    // Connected and saying nothing: refused after one handshake step.
    let mut ws = dial(addr).await;
    let HubMsg::Refused { code, .. } = receive(&mut ws).await else {
        panic!("expected a refusal");
    };
    assert_eq!(code, RefusalCode::Protocol);
    // Authenticated, then not reading — so not even answering pings: dropped once
    // `MISSED_HEARTBEATS` heartbeats pass.
    let mut ws = dial(addr).await;
    assert!(matches!(
        open(&mut ws, &node_id, &"0b".repeat(16), &key).await,
        HubMsg::Welcome { .. }
    ));
    tokio::time::sleep(server::HEARTBEAT * (server::MISSED_HEARTBEATS + 1)).await;
    assert_eq!(hub.reach(&node_id), Reach::Unreachable);
    closed(&mut ws, Duration::from_secs(5)).await;
}

/// The auth is bound to the version the hub chose: a signature made for another does not
/// verify, so a peer in the middle cannot move the session to a version of its choosing.
#[tokio::test(flavor = "multi_thread")]
async fn an_auth_for_another_version_is_refused() {
    let (addr, hub) = start().await;
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    let mut ws = dial(addr).await;
    let twist = Twist {
        version: Some(PROTOCOL.max + 1),
        ..Twist::default()
    };
    let HubMsg::Refused { code, .. } =
        open_with(&mut ws, &node_id, &"0c".repeat(16), &key, twist).await
    else {
        panic!("expected a refusal");
    };
    assert_eq!(code, RefusalCode::BadSignature);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_is_refused_without_the_pinned_key_or_a_common_version() {
    let (addr, hub) = start().await;
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    let incarnation = "cd".repeat(16);

    let mut ws = dial(addr).await;
    let reply = open(&mut ws, &node_id, &incarnation, &keypair()).await;
    assert!(matches!(reply, HubMsg::Refused { .. }), "{reply:?}");

    let mut ws = dial(addr).await;
    send(
        &mut ws,
        &hello(&node_id, &incarnation, VersionRange { min: 90, max: 99 }),
    )
    .await;
    let HubMsg::Refused { code, reason } = receive(&mut ws).await else {
        panic!("expected a refusal");
    };
    assert_eq!(code, RefusalCode::Version);
    assert!(reason.contains("no common protocol version"), "{reason}");

    let mut ws = dial(addr).await;
    send(&mut ws, &hello(&"00".repeat(16), &incarnation, PROTOCOL)).await;
    let HubMsg::Refused { code, reason } = receive(&mut ws).await else {
        panic!("expected a refusal");
    };
    assert_eq!(code, RefusalCode::NotEnrolled);
    assert!(reason.contains("not enrolled"), "{reason}");
    assert_eq!(hub.reach(&node_id), Reach::Unreachable);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_newer_session_supersedes_the_older_one() {
    let (addr, hub) = start().await;
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    let mut first = dial(addr).await;
    assert!(matches!(
        open(&mut first, &node_id, &"01".repeat(16), &key).await,
        HubMsg::Welcome { .. }
    ));
    let mut second = dial(addr).await;
    assert!(matches!(
        open(&mut second, &node_id, &"02".repeat(16), &key).await,
        HubMsg::Welcome { .. }
    ));
    assert!(matches!(
        receive(&mut first).await,
        HubMsg::Refused {
            code: RefusalCode::Superseded,
            ..
        }
    ));
    // The old session's teardown must not take the new one's registration with it.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(hub.reach(&node_id), Reach::Connected);
    assert_eq!(
        hub.db.node(&node_id).unwrap().unwrap().incarnation,
        Some("02".repeat(16))
    );
}

/// Heartbeats and inventories faster than the hub asked for still end with the latest of
/// each stored.
#[tokio::test(flavor = "multi_thread")]
async fn the_latest_of_reports_past_the_rate_is_stored() {
    let (addr, hub) = start().await;
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    let mut ws = dial(addr).await;
    assert!(matches!(
        open(&mut ws, &node_id, &"13".repeat(16), &key).await,
        HubMsg::Welcome { .. }
    ));
    for n in 1..=3 {
        let heartbeat = Heartbeat {
            desired_concurrency: Some(n),
            ..Heartbeat::default()
        };
        send(&mut ws, &NodeMsg::Heartbeat(heartbeat)).await;
        let inventory = Inventory {
            hostname: format!("ci-{n}"),
            ..Inventory::default()
        };
        send(&mut ws, &NodeMsg::Inventory(inventory)).await;
    }
    eventually(|| {
        hub.db.node(&node_id).unwrap().is_some_and(|row| {
            row.hostname == "ci-3" && row.heartbeat.and_then(|h| h.desired_concurrency) == Some(3)
        })
    })
    .await;
}

/// Enrollment reads every hex field as lowercase only, so a key has one spelling to pin.
#[tokio::test(flavor = "multi_thread")]
async fn enrollment_takes_lowercase_hex_only() {
    let (addr, hub) = start().await;
    let key = keypair();
    let token = token(&hub);
    let public_key = vk_hub_proto::to_hex(key.public_key().as_ref());
    let signature = vk_hub_proto::to_hex(
        key.sign(&vk_hub_proto::enroll_message(
            &token,
            key.public_key().as_ref(),
        ))
        .as_ref(),
    );
    let ask = |public_key: &str, signature: &str| {
        serde_json::to_vec(&EnrollRequest {
            token: token.clone(),
            public_key: public_key.to_string(),
            signature: signature.to_string(),
            hostname: "h".into(),
        })
        .unwrap()
    };
    let (status, body) = post_enroll(addr, &ask(&public_key.to_uppercase(), &signature)).await;
    assert_eq!(status, 400);
    assert!(String::from_utf8_lossy(&body).contains("malformed public key"));
    let (status, body) = post_enroll(addr, &ask(&public_key, &signature.to_uppercase())).await;
    assert_eq!(status, 400);
    assert!(String::from_utf8_lossy(&body).contains("malformed signature"));
    // Neither spent the token.
    let (status, _) = post_enroll(addr, &ask(&public_key, &signature)).await;
    assert_eq!(status, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_oversize_enrollment_body_is_refused() {
    let (addr, hub) = start().await;
    let (status, _) = post_enroll(addr, &vec![b' '; vk_hub_proto::MAX_MESSAGE + 1]).await;
    assert_eq!(status, 413);
    assert!(hub.db.nodes().unwrap().is_empty());
}

/// A signature that is not lowercase hex of the right length is the node breaking the
/// protocol, which redialing may fix, not a key that does not match, which it cannot.
#[tokio::test(flavor = "multi_thread")]
async fn a_signature_not_in_lowercase_hex_is_a_protocol_error() {
    let (addr, hub) = start().await;
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    let twists: [fn(String) -> String; 3] = [
        |s| s.to_uppercase(),
        |s| s[2..].to_string(),
        |s| format!("{}zz", &s[2..]),
    ];
    for hex in twists {
        let mut ws = dial(addr).await;
        let twist = Twist {
            hex: Some(hex),
            ..Twist::default()
        };
        let reply = open_with(&mut ws, &node_id, &"0e".repeat(16), &key, twist).await;
        let HubMsg::Refused { code, .. } = reply else {
            panic!("expected a refusal, got {reply:?}");
        };
        assert_eq!(code, RefusalCode::Protocol);
        assert!(!code.is_permanent());
    }
}

/// Removed after the hub looked the node up and before it opened the session: there was no
/// session to revoke yet, and the handshake must not open one for a node that is gone.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_removed_during_its_handshake_is_revoked() {
    let (addr, hub) = start().await;
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    let incarnation = "0d".repeat(16);
    let mut ws = dial(addr).await;
    send(&mut ws, &hello(&node_id, &incarnation, PROTOCOL)).await;
    let challenge = receive(&mut ws).await;
    assert!(hub.db.remove_node(&node_id, "uid 0", now_secs()).unwrap());
    hub.revoke(&node_id);
    let reply = authenticate(
        &mut ws,
        challenge,
        &node_id,
        &incarnation,
        &key,
        Twist::default(),
    )
    .await;
    assert!(
        matches!(
            reply,
            HubMsg::Refused {
                code: RefusalCode::Revoked,
                ..
            }
        ),
        "{reply:?}"
    );
    assert_eq!(hub.reach(&node_id), Reach::Unreachable);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_oversize_frame_ends_the_session() {
    let (addr, hub) = start().await;
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    let mut ws = dial(addr).await;
    assert!(matches!(
        open(&mut ws, &node_id, &"0f".repeat(16), &key).await,
        HubMsg::Welcome { .. }
    ));
    // The hub may stop reading before the frame is through, so the send itself can fail.
    let _ = ws
        .send(Message::text("x".repeat(vk_hub_proto::MAX_MESSAGE + 1)))
        .await;
    closed(&mut ws, Duration::from_secs(5)).await;
    eventually(|| hub.reach(&node_id) == Reach::Unreachable).await;
}

/// With every handshake permit taken, an upgrade is answered 503 before the 101, so a peer
/// that never authenticates holds no more than the bound.
#[tokio::test(flavor = "multi_thread")]
async fn a_handshake_past_the_bound_is_answered_503() {
    let (addr, hub) = start().await;
    let free = u32::try_from(hub.handshakes.available_permits()).unwrap();
    let held = hub.handshakes.clone().try_acquire_many_owned(free).unwrap();
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    match upgrade(addr, Box::new(stream)).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            assert_eq!(resp.status(), 503);
        }
        Err(e) => panic!("expected a 503, got {e}"),
        Ok(_) => panic!("upgraded past the bound"),
    }
    drop(held);
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    let mut ws = dial(addr).await;
    assert!(matches!(
        open(&mut ws, &node_id, &"10".repeat(16), &key).await,
        HubMsg::Welcome { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tls_1_2_client_is_refused() {
    let (addr, _hub) = start_tls().await;
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let tls12 = connector(&[&rustls::version::TLS12])
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await;
    assert!(tls12.is_err());
    dial_tls(addr).await;
}

/// Over TLS a node signs the connection's exporter: the auth verifies on that connection,
/// and the same exporter presented on another — a relay terminating TLS — does not.
#[tokio::test(flavor = "multi_thread")]
async fn a_tls_session_is_bound_to_its_connection() {
    let (addr, hub) = start_tls().await;
    let key = keypair();
    let public_key = vk_hub_proto::to_hex(key.public_key().as_ref());
    let Enrollment::Enrolled { node_id } = hub
        .db
        .enroll(&token(&hub), &public_key, "ci-1", "peer p", now_secs())
        .unwrap()
    else {
        panic!("expected an enrollment");
    };
    let (mut ws, exported) = dial_tls(addr).await;
    let twist = Twist {
        exported: Some(&exported),
        ..Twist::default()
    };
    let reply = open_with(&mut ws, &node_id, &"11".repeat(16), &key, twist).await;
    assert!(matches!(reply, HubMsg::Welcome { .. }), "{reply:?}");

    let (mut other, _) = dial_tls(addr).await;
    let twist = Twist {
        exported: Some(&exported),
        ..Twist::default()
    };
    let reply = open_with(&mut other, &node_id, &"12".repeat(16), &key, twist).await;
    let HubMsg::Refused { code, reason } = reply else {
        panic!("expected a refusal, got {reply:?}");
    };
    assert_eq!(code, RefusalCode::BadSignature);
    assert!(reason.contains("pass TLS through"), "{reason}");
    assert_eq!(hub.reach(&node_id), Reach::Connected);
}

#[test]
fn times_read_as_people_write_them() {
    assert_eq!(utc(1_800_000_000), "2027-01-15T08:00:00Z");
    assert_eq!(ago(5000, 5000 - 3725), Duration::from_secs(3600));
}

#[test]
fn a_token_lives_at_most_thirty_days() {
    assert_eq!(parse_token_ttl("90s"), Ok(Duration::from_secs(90)));
    assert_eq!(parse_token_ttl("15m"), Ok(Duration::from_secs(900)));
    assert_eq!(parse_token_ttl("2h"), Ok(Duration::from_secs(7200)));
    assert_eq!(parse_token_ttl("30d"), Ok(store::MAX_TOKEN_TTL));
    for bad in [
        "",
        "h",
        "0s",
        "31d",
        "1w",
        "-1h",
        "1.5h",
        "99999999999999999999d",
        "5é",
        "é",
    ] {
        assert!(parse_token_ttl(bad).is_err(), "{bad:?}");
    }
    let err = parse_token_ttl("31d").unwrap_err();
    assert!(err.contains("a token lives between 1s and 30d"), "{err}");
    assert_eq!(human_duration(Duration::from_secs(7200)), "2h");
    assert_eq!(human_duration(Duration::from_secs(90)), "90s");
}

#[test]
fn a_link_lives_at_most_a_day() {
    assert_eq!(parse_login_ttl("10m"), Ok(Duration::from_secs(600)));
    assert_eq!(parse_login_ttl("24h"), Ok(store::MAX_LOGIN_TTL));
    for bad in ["25h", "2d", "0s", "10", "", "5é", "é"] {
        assert!(parse_login_ttl(bad).is_err(), "{bad:?}");
    }
    let err = parse_login_ttl("25h").unwrap_err();
    assert!(
        err.contains("a sign-in link lives between 1s and 1d"),
        "{err}"
    );
}

/// The `--ttl` help states the same bound the parser enforces.
#[test]
fn the_ttl_help_states_the_enforced_bound() {
    use clap::CommandFactory;
    let help = |path: &[&str]| {
        let mut cmd = Cli::command();
        for name in path {
            cmd = cmd.find_subcommand(name).unwrap().clone();
        }
        let ttl = cmd.get_arguments().find(|a| a.get_id() == "ttl").unwrap();
        ttl.get_help().unwrap().to_string()
    };
    for (path, max) in [
        (&["local", "login"][..], store::MAX_LOGIN_TTL),
        (&["token", "create"][..], store::MAX_TOKEN_TTL),
    ] {
        let help = help(path);
        let bound = format!("(at most {})", human_duration(max));
        assert!(help.contains(&bound), "{path:?}: {help} lacks {bound}");
    }
}

/// The cell under `column` in `line`, by where the header puts the column.
fn cell<'a>(header: &str, line: &'a str, column: &str) -> &'a str {
    let at = |name: &str| {
        header
            .find(&format!("{name} "))
            .or_else(|| header.find(name))
            .unwrap()
    };
    let start = at(column);
    let next = NODE_COLUMNS
        .iter()
        .map(|n| at(n))
        .filter(|&p| p > start)
        .min()
        .unwrap_or(line.len());
    line.get(start..next.min(line.len())).unwrap_or("").trim()
}

#[test]
fn random_bytes_are_as_many_as_asked() {
    assert!(random_bytes(0).unwrap().is_empty());
    let (a, b) = (random_bytes(300).unwrap(), random_bytes(300).unwrap());
    assert_eq!(a.len(), 300);
    assert_ne!(a, b);
}

#[test]
fn the_nodes_table_lines_up_and_marks_what_is_unknown() {
    let nodes = [
        ops::NodeView {
            id: "a".repeat(32),
            hostname: "ci-1".into(),
            connected: true,
            last_seen: Some(995),
            vk: Some("0.80.0".into()),
            cpus: Some(64),
            mem_total_mib: Some(512 * 1024),
            committed_mib: Some(8 * 1024),
            budget_mib: Some(400 * 1024),
        },
        ops::NodeView {
            id: "b".repeat(32),
            hostname: "ci-2".into(),
            ..ops::NodeView::default()
        },
    ];
    let table = render_nodes(&nodes, 1000);
    let lines: Vec<&str> = table.lines().collect();
    assert_eq!(lines.len(), 3, "{table}");
    let (header, a, b) = (lines[0], lines[1], lines[2]);
    assert!(header.starts_with("ID "));
    for (column, want) in [
        ("NAME", "ci-1"),
        ("REACH", "connected"),
        ("LAST SEEN", "5s ago"),
        ("ADMITTED", "8G/400G"),
    ] {
        assert_eq!(cell(header, a, column), want, "{column}\n{table}");
    }
    for (column, want) in [("REACH", "unreachable"), ("LAST SEEN", "never")] {
        assert_eq!(cell(header, b, column), want, "{column}\n{table}");
    }
    assert_eq!(ago(10_000, 10_000 - 7300), Duration::from_secs(7200));
}

#[test]
fn audit_times_are_utc() {
    assert_eq!(utc(0), "1970-01-01T00:00:00Z");
    assert_eq!(utc(951_782_400), "2000-02-29T00:00:00Z");
    assert_eq!(utc(1_790_755_279), "2026-09-30T08:01:19Z");
}
