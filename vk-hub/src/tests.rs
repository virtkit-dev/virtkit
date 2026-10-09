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
    serve_on(Some(tls_acceptor())).await
}

/// The hub's TLS acceptor, with the test certificate.
fn tls_acceptor() -> tokio_rustls::TlsAcceptor {
    let certs = CertificateDer::pem_slice_iter(TLS_CERT)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(TLS_KEY).unwrap();
    config::acceptor(certs, key).unwrap()
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
    /// Speak this range rather than [`PROTOCOL`].
    versions: Option<VersionRange>,
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
    send(
        ws,
        &hello(node_id, incarnation, twist.versions.unwrap_or(PROTOCOL)),
    )
    .await;
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
    let ours = twist.versions.unwrap_or(PROTOCOL);
    assert_eq!(Some(version), ours.negotiate(session::PROTOCOL));
    assert_eq!(versions, session::PROTOCOL);
    let nonce = vk_hub_proto::from_hex(&nonce).unwrap();
    assert_eq!(nonce.len(), vk_hub_proto::CHALLENGE_LEN);
    let signature = signer.sign(&vk_hub_proto::auth_message(
        &nonce,
        node_id,
        incarnation,
        ours,
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

const V1: VersionRange = VersionRange { min: 1, max: 1 };

/// A node speaking only version 1 gets a version-1 session, recorded on its row, and none of
/// its report's steering is stored; a node speaking version 2 gets that.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_runs_at_the_highest_version_both_speak() {
    let (addr, hub) = start().await;
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    let mut ws = dial(addr).await;
    let twist = Twist {
        versions: Some(V1),
        ..Twist::default()
    };
    assert!(matches!(
        open_with(&mut ws, &node_id, &"21".repeat(16), &key, twist).await,
        HubMsg::Welcome { .. }
    ));
    assert_eq!(hub.db.node(&node_id).unwrap().unwrap().protocol, Some(1));
    let report = vk_hub_proto::Report {
        workloads: Some(Vec::new()),
        state: Some(vk_hub_proto::NodeState::Draining),
        ..vk_hub_proto::Report::default()
    };
    send(&mut ws, &NodeMsg::Report(report.clone())).await;
    eventually(|| hub.db.node(&node_id).unwrap().unwrap().report.is_some()).await;
    assert_eq!(
        hub.db.node(&node_id).unwrap().unwrap().report,
        Some(vk_hub_proto::Report::default())
    );

    let mut ws = dial(addr).await;
    assert!(matches!(
        open(&mut ws, &node_id, &"22".repeat(16), &key).await,
        HubMsg::Welcome { .. }
    ));
    let row = hub.db.node(&node_id).unwrap().unwrap();
    assert_eq!(row.protocol, Some(vk_hub_proto::STEERING));
    send(&mut ws, &NodeMsg::Report(report)).await;
    eventually(|| {
        hub.db
            .node(&node_id)
            .unwrap()
            .unwrap()
            .report
            .and_then(|r| r.state)
            == Some(vk_hub_proto::NodeState::Draining)
    })
    .await;
}

/// An ack is version 2's: in a version-1 session it ends the session as a protocol error,
/// in a version-2 one it is taken.
#[tokio::test(flavor = "multi_thread")]
async fn an_ack_in_a_version_1_session_is_a_protocol_error() {
    let (addr, hub) = start().await;
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    let ack = NodeMsg::Ack(vk_hub_proto::CommandAck {
        id: "ef".repeat(16),
        outcome: vk_hub_proto::Outcome::Done,
    });

    let mut ws = dial(addr).await;
    assert!(matches!(
        open(&mut ws, &node_id, &"23".repeat(16), &key).await,
        HubMsg::Welcome { .. }
    ));
    send(&mut ws, &ack).await;
    send(&mut ws, &NodeMsg::Heartbeat(Heartbeat::default())).await;
    eventually(|| hub.db.node(&node_id).unwrap().unwrap().heartbeat.is_some()).await;
    assert_eq!(hub.reach(&node_id), Reach::Connected);

    let mut ws = dial(addr).await;
    let twist = Twist {
        versions: Some(V1),
        ..Twist::default()
    };
    assert!(matches!(
        open_with(&mut ws, &node_id, &"24".repeat(16), &key, twist).await,
        HubMsg::Welcome { .. }
    ));
    send(&mut ws, &ack).await;
    let HubMsg::Refused { code, reason } = receive(&mut ws).await else {
        panic!("expected a refusal");
    };
    assert_eq!(code, RefusalCode::Protocol);
    assert!(reason.contains("version-1 session"), "{reason}");
    closed(&mut ws, Duration::from_secs(5)).await;
}

/// A report of `applied`, as a version-2 node sends it.
fn applied(applied: Option<u64>) -> NodeMsg {
    NodeMsg::Report(vk_hub_proto::Report {
        applied: applied.map(|generation| vk_hub_proto::DesiredState {
            generation,
            ceiling: None,
            acquisition: vk_hub_proto::Acquisition::Run,
        }),
        state: Some(vk_hub_proto::NodeState::Ready),
        ..vk_hub_proto::Report::default()
    })
}

/// Desired state goes to a node that reports itself behind, a change made while it is
/// connected at once, and pending commands on every session until the node reports them
/// finished; the node's acks are answered, recorded and audited.
#[tokio::test(flavor = "multi_thread")]
async fn a_lagging_node_gets_desired_state_and_commands_until_they_are_done() {
    use vk_hub_proto::{Acquisition, CommandAck, Operation, Outcome};
    let (addr, hub) = start().await;
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    // Accepted before the node's first session: it has not said it cannot take them.
    let desired = ops::set_ceiling(&hub, "uid 0", &node_id, Some(3))
        .unwrap()
        .unwrap();
    let drain = ops::command(&hub, "uid 0", &node_id, Operation::Drain).unwrap();

    let mut ws = dial(addr).await;
    assert!(matches!(
        open(&mut ws, &node_id, &"0d".repeat(16), &key).await,
        HubMsg::Welcome { .. }
    ));
    send(&mut ws, &applied(None)).await;
    assert_eq!(receive(&mut ws).await, HubMsg::Desired(desired.clone()));
    assert_eq!(receive(&mut ws).await, HubMsg::Command(drain.clone()));
    let accepted = CommandAck {
        id: drain.id.clone(),
        outcome: Outcome::Accepted,
    };
    send(&mut ws, &NodeMsg::Ack(accepted.clone())).await;
    assert_eq!(receive(&mut ws).await, HubMsg::Recorded(accepted));
    // A change while connected is sent at once, the drain not again.
    ops::set_acquisition(&hub, "uid 0", &node_id, Acquisition::Stop).unwrap();
    let HubMsg::Desired(second) = receive(&mut ws).await else {
        panic!("expected desired state");
    };
    assert_eq!(
        (second.generation, second.ceiling, second.acquisition),
        (2, Some(3), Acquisition::Stop)
    );
    // Acked unknown commands are answered all the same, or the node would repeat them.
    let stray = CommandAck {
        id: "ee".repeat(16),
        outcome: Outcome::Done,
    };
    send(&mut ws, &NodeMsg::Ack(stray.clone())).await;
    assert_eq!(receive(&mut ws).await, HubMsg::Recorded(stray));
    ws.close(None).await.unwrap();

    // Reconnected still behind, with the drain under way: both again.
    let mut ws = dial(addr).await;
    open(&mut ws, &node_id, &"0d".repeat(16), &key).await;
    send(&mut ws, &applied(Some(1))).await;
    assert_eq!(receive(&mut ws).await, HubMsg::Desired(second));
    assert_eq!(receive(&mut ws).await, HubMsg::Command(drain.clone()));
    let done = CommandAck {
        id: drain.id.clone(),
        outcome: Outcome::Done,
    };
    send(&mut ws, &NodeMsg::Ack(done.clone())).await;
    assert_eq!(receive(&mut ws).await, HubMsg::Recorded(done));
    assert!(
        hub.db
            .pending_commands(&node_id, now_secs())
            .unwrap()
            .is_empty()
    );
    // Caught up, the node is sent nothing more.
    send(&mut ws, &applied(Some(2))).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(1500), receive(&mut ws))
            .await
            .is_err()
    );
    let events: Vec<String> = hub
        .db
        .audits(Some(&node_id), 100)
        .unwrap()
        .into_iter()
        .map(|r| r.event)
        .collect();
    assert!(
        events.iter().any(|e| e.ends_with("(drain): done")),
        "{events:?}"
    );
    assert!(events.iter().any(|e| e == "state ready"), "{events:?}");
}

/// A node on version 1 is never sent desired state or a command, even with both waiting for
/// it; once it has connected so, the hub refuses to steer it.
#[tokio::test(flavor = "multi_thread")]
async fn a_version_1_node_is_monitored_and_never_steered() {
    use vk_hub_proto::Operation;
    let (addr, hub) = start().await;
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    ops::set_ceiling(&hub, "uid 0", &node_id, Some(3)).unwrap();
    ops::command(&hub, "uid 0", &node_id, Operation::Quarantine).unwrap();

    let mut ws = dial(addr).await;
    let twist = Twist {
        versions: Some(V1),
        ..Twist::default()
    };
    assert!(matches!(
        open_with(&mut ws, &node_id, &"25".repeat(16), &key, twist).await,
        HubMsg::Welcome { .. }
    ));
    send(&mut ws, &applied(None)).await;
    // A change while connected is no more sent than what waited.
    let err = ops::set_ceiling(&hub, "uid 0", &node_id, Some(4)).unwrap_err();
    assert!(format!("{err:#}").contains("monitor"), "{err:#}");
    let err = ops::command(&hub, "uid 0", &node_id, Operation::Release).unwrap_err();
    assert!(format!("{err:#}").contains("update its vk"), "{err:#}");
    let err =
        ops::command(&hub, "uid 0", &node_id, Operation::Reset { images: false }).unwrap_err();
    assert!(err.is::<crate::store::MonitoringOnly>(), "{err:#}");
    hub.kick(&node_id);
    assert!(
        tokio::time::timeout(Duration::from_millis(1500), receive(&mut ws))
            .await
            .is_err()
    );
    let view = ops::node_views(&hub).unwrap().remove(0);
    assert!(view.monitoring_only());
    assert_eq!(view.protocol, Some(1));
}

/// A reset goes to the node as any command does, its images flag with it, and the audit log
/// names it in what was issued and in how it ended.
#[tokio::test(flavor = "multi_thread")]
async fn a_reset_is_sent_and_audited_by_name() {
    use vk_hub_proto::{CommandAck, Operation, Outcome};
    let (addr, hub) = start().await;
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    let mut ws = dial(addr).await;
    assert!(matches!(
        open(&mut ws, &node_id, &"27".repeat(16), &key).await,
        HubMsg::Welcome { .. }
    ));
    send(&mut ws, &applied(None)).await;
    let reset = ops::command(&hub, "uid 0", &node_id, Operation::Reset { images: true }).unwrap();
    assert_eq!(receive(&mut ws).await, HubMsg::Command(reset.clone()));
    for outcome in [
        Outcome::Accepted,
        Outcome::Failed {
            message: "validation failed: vk check: kvm".into(),
        },
    ] {
        let ack = CommandAck {
            id: reset.id.clone(),
            outcome,
        };
        send(&mut ws, &NodeMsg::Ack(ack.clone())).await;
        assert_eq!(receive(&mut ws).await, HubMsg::Recorded(ack));
    }
    let events: Vec<String> = hub
        .db
        .audits(Some(&node_id), 100)
        .unwrap()
        .into_iter()
        .map(|r| r.event)
        .collect();
    for want in [
        format!("uid 0 issued reset, images included (command {})", reset.id),
        format!(
            "command {} (reset, images included): failed: validation failed: vk check: kvm",
            reset.id
        ),
    ] {
        assert!(events.contains(&want), "{want}: {events:?}");
    }
}

/// A node that applied a generation past the hub's — the hub restored from a backup — is
/// sent the desired state as the generation after it.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_ahead_of_a_restored_hub_is_sent_the_next_generation() {
    let (addr, hub) = start().await;
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    ops::set_ceiling(&hub, "uid 0", &node_id, Some(5)).unwrap();
    let mut ws = dial(addr).await;
    assert!(matches!(
        open(&mut ws, &node_id, &"26".repeat(16), &key).await,
        HubMsg::Welcome { .. }
    ));
    send(&mut ws, &applied(Some(7))).await;
    let HubMsg::Desired(desired) = receive(&mut ws).await else {
        panic!("expected desired state");
    };
    assert_eq!((desired.generation, desired.ceiling), (8, Some(5)));
}

/// A hub with no desired state for a node — one that lost it — takes the node's as its own
/// and sends it nothing, rather than lift its ceiling with the defaults.
#[tokio::test(flavor = "multi_thread")]
async fn a_hub_without_desired_state_keeps_the_nodes() {
    use vk_hub_proto::{Acquisition, DesiredState};
    let (addr, hub) = start().await;
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    let mut ws = dial(addr).await;
    assert!(matches!(
        open(&mut ws, &node_id, &"27".repeat(16), &key).await,
        HubMsg::Welcome { .. }
    ));
    let theirs = DesiredState {
        generation: 7,
        ceiling: Some(2),
        acquisition: Acquisition::Stop,
    };
    send(
        &mut ws,
        &NodeMsg::Report(vk_hub_proto::Report {
            applied: Some(theirs.clone()),
            ..vk_hub_proto::Report::default()
        }),
    )
    .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(1500), receive(&mut ws))
            .await
            .is_err()
    );
    assert_eq!(
        hub.db.node(&node_id).unwrap().unwrap().desired,
        Some(theirs)
    );
    // A change goes on from the node's, acquisition still stopped.
    ops::set_ceiling(&hub, "uid 0", &node_id, Some(3)).unwrap();
    let HubMsg::Desired(desired) = receive(&mut ws).await else {
        panic!("expected desired state");
    };
    assert_eq!(
        desired,
        DesiredState {
            generation: 8,
            ceiling: Some(3),
            acquisition: Acquisition::Stop,
        }
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

/// A hub keeping releases in a fresh directory under `tag`, on an ephemeral loopback port: the
/// directory, the address and the hub.
async fn start_releases(
    tag: &str,
    tls: Option<tokio_rustls::TlsAcceptor>,
) -> (std::path::PathBuf, SocketAddr, Arc<Hub>) {
    let dir = std::env::temp_dir().join(format!("vk-hub-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let listener = server::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let hub = Arc::new(
        Hub::new(Arc::new(Db::open_memory().unwrap()), None).with_releases(dir.join("releases")),
    );
    tokio::spawn(server::serve(listener, tls, hub.clone()));
    (dir, addr, hub)
}

/// A fake `vk`: an x86-64 ELF header, then bytes that hold `version` as a string of its own.
fn fake_vk(version: &str) -> Vec<u8> {
    let mut bin = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x02\0\x3e\0".to_vec();
    bin.extend_from_slice(b"\0vk-driver ");
    bin.extend_from_slice(version.as_bytes());
    bin.extend_from_slice(&[0u8; 5000]);
    bin
}

/// Add `bin` to `hub` as `version`, from a file in `dir`.
fn add_release(
    hub: &Hub,
    dir: &std::path::Path,
    bin: &[u8],
    version: &str,
) -> anyhow::Result<store::Release> {
    let file = dir.join("vk");
    std::fs::write(&file, bin).unwrap();
    releases::add(hub, "uid 0", &file, version, None)
}

/// `GET <path>` with `headers` on `stream`, by hand: the status and the body.
async fn get_on(
    mut stream: Box<dyn server::Stream>,
    path: &str,
    headers: &[(&str, String)],
) -> (u16, Vec<u8>) {
    let mut head = format!("GET {path} HTTP/1.1\r\nHost: hub\r\nConnection: close\r\n");
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    // A TLS peer that closes without close_notify ends the read with an error; what came
    // before it is the response.
    let _ = stream.read_to_end(&mut resp).await;
    let split = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let status = std::str::from_utf8(&resp[9..12]).unwrap().parse().unwrap();
    (status, resp[split + 4..].to_vec())
}

/// [`get_on`] a new plain TCP connection.
async fn get_with(addr: SocketAddr, path: &str, headers: &[(&str, String)]) -> (u16, Vec<u8>) {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    get_on(Box::new(stream), path, headers).await
}

/// A TLS connection to the hub, and the keying material it exports for a node's signatures.
async fn tls_stream(addr: SocketAddr) -> (Box<dyn server::Stream>, [u8; TLS_EXPORTER_LEN]) {
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
    (Box::new(stream), exported)
}

/// The headers node `node_id` sends to download `sha256`, signed by `key` at `at` for
/// `channel`.
fn download_headers(
    key: &Ed25519KeyPair,
    node_id: &str,
    sha256: &str,
    at: u64,
    channel: vk_hub_proto::Channel<'_>,
) -> Vec<(&'static str, String)> {
    let digest = vk_hub_proto::from_hex_lower::<{ vk_hub_proto::SHA256_LEN }>(sha256).unwrap();
    let message = vk_hub_proto::download_message(node_id, &digest, at, channel);
    vec![
        (vk_hub_proto::NODE_HEADER, node_id.to_string()),
        (vk_hub_proto::TIME_HEADER, at.to_string()),
        (
            vk_hub_proto::SIGNATURE_HEADER,
            vk_hub_proto::to_hex(key.sign(&message).as_ref()),
        ),
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn a_release_is_an_x86_64_elf_holding_its_version_and_added_once() {
    let (dir, _, hub) = start_releases("release-add", None).await;
    let bin = fake_vk("0.84.0");
    let err = add_release(&hub, &dir, &bin, "0.84.1").unwrap_err();
    assert!(format!("{err:#}").contains("appears nowhere"), "{err:#}");
    let err = add_release(&hub, &dir, b"#!/bin/sh\necho 0.84.0\n", "0.84.0").unwrap_err();
    assert!(format!("{err:#}").contains("not an x86-64 ELF"), "{err:#}");
    let err = add_release(&hub, &dir, &bin, "0.84 0").unwrap_err();
    assert!(format!("{err:#}").contains("is not a version"), "{err:#}");
    // Past the size limit, refused before a byte is read: a sparse file costs nothing.
    let big = dir.join("big");
    std::fs::File::create(&big)
        .unwrap()
        .set_len(releases::MAX_RELEASE + 1)
        .unwrap();
    let err = releases::add(&hub, "uid 0", &big, "0.84.0", None).unwrap_err();
    assert!(format!("{err:#}").contains("past the"), "{err:#}");
    assert!(releases::add(&hub, "uid 0", &dir, "0.84.0", None).is_err());
    // A FIFO with no writer is refused at once rather than waited on.
    let fifo = dir.join("fifo");
    let c_fifo = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: `c_fifo` is a NUL-terminated path, valid for the call.
    assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);
    let err = releases::add(&hub, "uid 0", &fifo, "0.84.0", None).unwrap_err();
    assert!(format!("{err:#}").contains("not a regular file"), "{err:#}");
    std::fs::remove_file(&fifo).unwrap();

    let release = add_release(&hub, &dir, &bin, "0.84.0").unwrap();
    assert_eq!(release.row.size, bin.len() as u64);
    let held = dir.join("releases").join(&release.sha256);
    assert_eq!(std::fs::read(&held).unwrap(), bin);
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!((mode(&held), mode(&dir.join("releases"))), (0o600, 0o700));
    }
    // Added again as the same version — a retry whose answer was lost — it is the same one;
    // as another version, refused.
    assert_eq!(add_release(&hub, &dir, &bin, "0.84.0").unwrap(), release);
    let both = fake_vk("0.84.0 0.85.0");
    let other = add_release(&hub, &dir, &both, "0.85.0").unwrap();
    let err = add_release(&hub, &dir, &both, "0.84.0").unwrap_err();
    assert!(format!("{err:#}").contains("already held"), "{err:#}");

    // A signature must be one in shape, base64 of 64 bytes; whether it verifies is each
    // node's to judge. Held, it is part of the release: added again without it, or with
    // another, refused.
    let file = dir.join("vk");
    let signed = fake_vk("0.86.0");
    std::fs::write(&file, &signed).unwrap();
    let add = |signature: &str| {
        releases::add(&hub, "uid 0", &file, "0.86.0", Some(signature.to_string()))
    };
    for bad in [
        "abc!".to_string(),
        vk_hub_proto::to_base64(&[5; vk_hub_proto::SIGNATURE_LEN - 1]),
        vk_hub_proto::to_hex(&[5; vk_hub_proto::SIGNATURE_LEN]),
    ] {
        let err = add(&bad).unwrap_err();
        assert!(
            format!("{err:#}").contains("not an ed25519 signature"),
            "{err:#}"
        );
    }
    let signature = vk_hub_proto::to_base64(&[5; vk_hub_proto::SIGNATURE_LEN]);
    let held = add(&format!("{signature}\n")).unwrap();
    assert_eq!(held.row.signature.as_deref(), Some(signature.as_str()));
    assert_eq!(add(&signature).unwrap(), held);
    let err = add(&vk_hub_proto::to_base64(&[6; vk_hub_proto::SIGNATURE_LEN])).unwrap_err();
    assert!(
        format!("{err:#}").contains("with another signature"),
        "{err:#}"
    );
    let err = releases::add(&hub, "uid 0", &file, "0.86.0", None).unwrap_err();
    assert!(
        format!("{err:#}").contains("with another signature"),
        "{err:#}"
    );
    assert!(releases::remove(&hub, "uid 0", &held.sha256).unwrap());
    let listed: Vec<String> = hub
        .db
        .releases()
        .unwrap()
        .into_iter()
        .map(|r| r.sha256)
        .collect();
    assert_eq!(listed.len(), 2);
    assert!(releases::remove(&hub, "uid 0", &other.sha256).unwrap());
    assert!(!releases::remove(&hub, "uid 0", &other.sha256).unwrap());
    assert!(!dir.join("releases").join(&other.sha256).exists());
    // Nothing but the held release is left in the directory: no temporary file of an add.
    let left: Vec<_> = std::fs::read_dir(dir.join("releases"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(left, [std::ffi::OsString::from(&release.sha256)]);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_release_is_served_only_to_a_node_updating_to_it_that_signs_for_it() {
    let (dir, addr, hub) = start_releases("release-download", None).await;
    let bin = fake_vk("0.84.0");
    let sha = add_release(&hub, &dir, &bin, "0.84.0").unwrap().sha256;
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    let path = format!("{}{sha}", vk_hub_proto::RELEASE_PATH);
    let plain = vk_hub_proto::Channel::Plaintext;
    let signed = |key: &Ed25519KeyPair, at: u64| download_headers(key, &node_id, &sha, at, plain);
    // No update under way: refused, however well signed.
    assert_eq!(
        get_with(addr, &path, &signed(&key, now_secs())).await.0,
        403
    );

    ops::update(&hub, "uid 0", &node_id, &sha[..8], false).unwrap();
    let (status, body) = get_with(addr, &path, &signed(&key, now_secs())).await;
    assert_eq!(status, 200);
    assert_eq!(body, bin);
    assert_eq!(get_with(addr, &path, &[]).await.0, 401);
    assert_eq!(
        get_with(addr, &path, &signed(&keypair(), now_secs()))
            .await
            .0,
        403
    );
    let stale = now_secs() - vk_hub_proto::DOWNLOAD_SKEW_SECS - 5;
    assert_eq!(get_with(addr, &path, &signed(&key, stale)).await.0, 401);
    let ahead = now_secs() + vk_hub_proto::DOWNLOAD_SKEW_SECS + 5;
    assert_eq!(get_with(addr, &path, &signed(&key, ahead)).await.0, 401);
    // Signed for this release, presented for another.
    let other = format!("{}{}", vk_hub_proto::RELEASE_PATH, "cd".repeat(32));
    assert_eq!(
        get_with(addr, &other, &signed(&key, now_secs())).await.0,
        403
    );
    // A signature in uppercase hex is not one.
    let mut upper = signed(&key, now_secs());
    upper[2].1 = upper[2].1.to_uppercase();
    assert_eq!(get_with(addr, &path, &upper).await.0, 401);

    // Removal waits for the update, then takes the file too; the node's download with it.
    let err = releases::remove(&hub, "uid 0", &sha).unwrap_err();
    assert!(
        format!("{err:#}").contains("still being updated"),
        "{err:#}"
    );
    let command = hub
        .db
        .pending_commands(&node_id, now_secs())
        .unwrap()
        .remove(0);
    hub.db
        .record_ack(
            &node_id,
            &vk_hub_proto::CommandAck {
                id: command.id,
                outcome: vk_hub_proto::Outcome::Done,
            },
            now_secs(),
        )
        .unwrap();
    assert_eq!(
        get_with(addr, &path, &signed(&key, now_secs())).await.0,
        403
    );
    assert!(releases::remove(&hub, "uid 0", &sha).unwrap());
    assert!(!dir.join("releases").join(&sha).exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Over TLS a download is signed for the connection's exporter: presented on another
/// connection — a relay terminating TLS — the signature does not verify.
#[tokio::test(flavor = "multi_thread")]
async fn a_tls_download_is_bound_to_its_connection() {
    let (dir, addr, hub) = start_releases("release-tls", Some(tls_acceptor())).await;
    let bin = fake_vk("0.84.0");
    let sha = add_release(&hub, &dir, &bin, "0.84.0").unwrap().sha256;
    let key = keypair();
    let public_key = vk_hub_proto::to_hex(key.public_key().as_ref());
    let Enrollment::Enrolled { node_id } = hub
        .db
        .enroll(&token(&hub), &public_key, "ci-1", "peer p", now_secs())
        .unwrap()
    else {
        panic!("expected an enrollment");
    };
    ops::update(&hub, "uid 0", &node_id, &sha, false).unwrap();
    let path = format!("{}{sha}", vk_hub_proto::RELEASE_PATH);
    let (stream, exported) = tls_stream(addr).await;
    let headers = download_headers(
        &key,
        &node_id,
        &sha,
        now_secs(),
        vk_hub_proto::Channel::Tls(&exported),
    );
    let (other, _) = tls_stream(addr).await;
    assert_eq!(get_on(other, &path, &headers).await.0, 403);
    let plain = download_headers(
        &key,
        &node_id,
        &sha,
        now_secs(),
        vk_hub_proto::Channel::Plaintext,
    );
    let (third, _) = tls_stream(addr).await;
    assert_eq!(get_on(third, &path, &plain).await.0, 403);
    let (status, body) = get_on(stream, &path, &headers).await;
    assert_eq!(status, 200);
    assert_eq!(body, bin);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A release whose binary is missing or the wrong size is answered 404, and adding the same
/// bytes again puts it back: removing it first is refused while a node updates to it.
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_release_binary_is_not_served_until_added_again() {
    let (dir, addr, hub) = start_releases("release-lost", None).await;
    let bin = fake_vk("0.84.0");
    let release = add_release(&hub, &dir, &bin, "0.84.0").unwrap();
    let sha = release.sha256.clone();
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    ops::update(&hub, "uid 0", &node_id, &sha, false).unwrap();
    let path = format!("{}{sha}", vk_hub_proto::RELEASE_PATH);
    let plain = vk_hub_proto::Channel::Plaintext;
    let signed = || download_headers(&key, &node_id, &sha, now_secs(), plain);
    let held = dir.join("releases").join(&sha);

    std::fs::remove_file(&held).unwrap();
    let (status, body) = get_with(addr, &path, &signed()).await;
    assert_eq!(status, 404);
    assert!(String::from_utf8_lossy(&body).contains("missing"));
    assert_eq!(add_release(&hub, &dir, &bin, "0.84.0").unwrap(), release);
    assert_eq!(get_with(addr, &path, &signed()).await, (200, bin.clone()));

    std::fs::OpenOptions::new()
        .write(true)
        .open(&held)
        .unwrap()
        .set_len(100)
        .unwrap();
    let (status, body) = get_with(addr, &path, &signed()).await;
    assert_eq!(status, 404);
    assert!(String::from_utf8_lossy(&body).contains("wrong size"));
    assert_eq!(add_release(&hub, &dir, &bin, "0.84.0").unwrap(), release);
    assert_eq!(get_with(addr, &path, &signed()).await, (200, bin.clone()));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// An authenticated download gives up its pre-auth permit for a download slot, held while its
/// body is sent; with every slot taken, the next download is answered 503.
#[tokio::test(flavor = "multi_thread")]
async fn a_download_trades_its_pre_auth_permit_for_a_download_slot() {
    let (dir, addr, hub) = start_releases("release-slots", None).await;
    // Far larger than the socket buffers, so its download stays under way while the client
    // reads nothing: a sparse file, recorded as it is.
    let sha = "ab".repeat(32);
    let size = 1u64 << 30;
    std::fs::create_dir_all(dir.join("releases")).unwrap();
    std::fs::File::create(dir.join("releases").join(&sha))
        .unwrap()
        .set_len(size)
        .unwrap();
    let row = store::ReleaseRow {
        version: "0.84.0".into(),
        size,
        signature: None,
        added_at: now_secs(),
        added_by: "uid 0".into(),
    };
    hub.db.add_release(&sha, &row, "uid 0").unwrap();
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    ops::update(&hub, "uid 0", &node_id, &sha, false).unwrap();
    let path = format!("{}{sha}", vk_hub_proto::RELEASE_PATH);
    let plain = vk_hub_proto::Channel::Plaintext;
    let signed = || download_headers(&key, &node_id, &sha, now_secs(), plain);
    let others = u32::try_from(server::MAX_DOWNLOADS - 1).unwrap();
    let _others = hub
        .downloads
        .clone()
        .try_acquire_many_owned(others)
        .unwrap();

    let mut first = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut head = format!("GET {path} HTTP/1.1\r\nHost: hub\r\n");
    for (k, v) in signed() {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    first.write_all(head.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    while !resp.windows(4).any(|w| w == b"\r\n\r\n") {
        let mut buf = [0u8; 4096];
        let n = first.read(&mut buf).await.unwrap();
        assert_ne!(n, 0, "the hub closed before its response head");
        resp.extend_from_slice(&buf[..n]);
    }
    assert!(resp.starts_with(b"HTTP/1.1 200"), "{resp:?}");
    // The enrollment's permit comes back only once the hub has closed that connection.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while hub.connections.available_permits() != server::MAX_PRE_AUTH {
        assert!(
            std::time::Instant::now() < deadline,
            "a pre-auth permit was not given back"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(hub.downloads.available_permits(), 0);
    let (status, body) = get_with(addr, &path, &signed()).await;
    assert_eq!(status, 503);
    assert!(String::from_utf8_lossy(&body).contains("too many"));

    // The slot goes with the body, once the hub finds its peer gone.
    drop(first);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while hub.downloads.available_permits() == 0 {
        assert!(tokio::time::Instant::now() < deadline, "the slot was kept");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// An update names a release the hub holds, by digest and size, and goes only to a node that
/// can be steered.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_names_a_held_release_and_refuses_a_version_1_node() {
    let (dir, addr, hub) = start_releases("release-update", None).await;
    let bin = fake_vk("0.84.0");
    let file = dir.join("vk");
    std::fs::write(&file, &bin).unwrap();
    let signature = vk_hub_proto::to_base64(&[5; vk_hub_proto::SIGNATURE_LEN]);
    let release = releases::add(&hub, "uid 0", &file, "0.84.0", Some(signature.clone())).unwrap();
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    let err = ops::update(&hub, "uid 0", &node_id, &"cd".repeat(32), false).unwrap_err();
    assert!(format!("{err:#}").contains("no release"), "{err:#}");
    let err = ops::update(&hub, "uid 0", &node_id, "abc", false).unwrap_err();
    assert!(format!("{err:#}").contains("first 8 hex digits"), "{err:#}");
    let err = ops::update(&hub, "uid 0", &"00".repeat(16), &release.sha256, false).unwrap_err();
    assert!(err.is::<store::NotEnrolled>(), "{err:#}");
    let err = ops::command(
        &hub,
        "uid 0",
        &node_id,
        vk_hub_proto::Operation::Update {
            version: "0.84.0".into(),
            sha256: release.sha256.clone(),
            size: release.row.size,
            signature: None,
            force: false,
            within_secs: None,
        },
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("names a release"), "{err:#}");

    // A node not connected yet is taken at its word, and is sent it on connect, with the
    // release's signature for the node to check.
    let command = ops::update(&hub, "uid 0", &node_id, &release.sha256[..8], true).unwrap();
    assert_eq!(
        command.op,
        vk_hub_proto::Operation::Update {
            version: "0.84.0".into(),
            sha256: release.sha256.clone(),
            size: bin.len() as u64,
            signature: Some(signature),
            force: true,
            within_secs: None,
        }
    );
    let events: Vec<String> = hub
        .db
        .audits(Some(&node_id), 10)
        .unwrap()
        .into_iter()
        .map(|r| r.event)
        .collect();
    assert!(
        events.contains(&format!(
            "uid 0 issued update to vk 0.84.0 ({}) (command {})",
            &release.sha256[..12],
            command.id
        )),
        "{events:?}"
    );
    let mut ws = dial(addr).await;
    assert!(matches!(
        open(&mut ws, &node_id, &"31".repeat(16), &key).await,
        HubMsg::Welcome { .. }
    ));
    send(&mut ws, &applied(None)).await;
    let sent = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let HubMsg::Command(c) = receive(&mut ws).await {
                return c;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(sent, command);

    // A node on version 1 is refused it.
    let old = keypair();
    let old_id = enrolled(addr, &hub, &old).await;
    let mut ws = dial(addr).await;
    let twist = Twist {
        versions: Some(V1),
        ..Twist::default()
    };
    assert!(matches!(
        open_with(&mut ws, &old_id, &"32".repeat(16), &old, twist).await,
        HubMsg::Welcome { .. }
    ));
    let err = ops::update(&hub, "uid 0", &old_id, &release.sha256, false).unwrap_err();
    assert!(err.is::<store::MonitoringOnly>(), "{err:#}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A node of `hub` enrolled as `name`, with no session yet.
fn enroll_as(hub: &Hub, name: &str) -> String {
    let key = vk_hub_proto::to_hex(keypair().public_key().as_ref());
    match hub
        .db
        .enroll(&token(hub), &key, name, "peer", now_secs())
        .unwrap()
    {
        Enrollment::Enrolled { node_id } => node_id,
        other => panic!("expected an enrollment, got {other:?}"),
    }
}

/// Say on behalf of node `id` that it is ready, runs its runner itself and runs the `vk`
/// whose sha256 is `sha256`.
fn ready_on(hub: &Hub, id: &str, sha256: &str) {
    let mut inventory = Inventory {
        hostname: hub.db.node(id).unwrap().unwrap().hostname,
        ..Inventory::default()
    };
    inventory.versions.vk_sha256 = Some(sha256.into());
    hub.db
        .record_inventory(id, inventory, true, now_secs())
        .unwrap();
    hub.db
        .record_report(
            id,
            vk_hub_proto::Report {
                state: Some(vk_hub_proto::NodeState::Ready),
                runner: Some(vk_hub_proto::RunnerMode::Managed),
                ..vk_hub_proto::Report::default()
            },
            now_secs(),
        )
        .unwrap();
}

/// What node `id` says its one pending command came to.
fn ack_only(hub: &Hub, id: &str, outcome: vk_hub_proto::Outcome) -> vk_hub_proto::Command {
    let mut pending = hub.db.pending_commands(id, now_secs()).unwrap();
    assert_eq!(pending.len(), 1, "{pending:?}");
    let command = pending.remove(0);
    let ack = vk_hub_proto::CommandAck {
        id: command.id.clone(),
        outcome,
    };
    assert!(hub.db.record_ack(id, &ack, now_secs()).unwrap());
    command
}

fn rollout_plan(release: &str, canaries: bool, max_failures: u32) -> ops::RolloutPlan {
    ops::RolloutPlan {
        release: release.into(),
        nodes: ops::Selection::All,
        batch: 1,
        canary_per_profile: canaries,
        max_failures,
        node_timeout_secs: 600,
        drain_timeout_secs: 600,
        force: false,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rollout_updates_wave_by_wave_and_pauses_on_a_failure() {
    let (dir, _, hub) = start_releases("rollout", None).await;
    let release = add_release(&hub, &dir, &fake_vk("0.85.0"), "0.85.0").unwrap();
    let (a, b, c, old) = (
        enroll_as(&hub, "a"),
        enroll_as(&hub, "b"),
        enroll_as(&hub, "c"),
        enroll_as(&hub, "old"),
    );
    ready_on(&hub, &a, &"00".repeat(32));
    ready_on(&hub, &b, &"00".repeat(32));
    ready_on(&hub, &c, &release.sha256);
    // A node whose latest session ran version 1 is monitored only, and left out.
    assert!(
        hub.db
            .record_session(&old, "ab", 1, now_secs(), || true)
            .unwrap()
    );
    let plan = rollout_plan(&release.sha256[..8], true, 1);
    let rollout = ops::create_rollout(&hub, "uid 0", &plan).unwrap();
    let skipped = |id: &str| match &rollout
        .row
        .nodes
        .iter()
        .find(|n| n.id == id)
        .unwrap()
        .status
    {
        rollout::NodeStatus::Skipped { reason } => reason.clone(),
        other => panic!("{other:?}"),
    };
    assert!(skipped(&old).contains("protocol version 1"));
    assert!(skipped(&c).contains("already runs"));
    // One rollout at a time.
    let err = ops::create_rollout(&hub, "uid 0", &plan).unwrap_err();
    assert!(format!("{err:#}").contains("still running"), "{err:#}");
    let advance = || hub.db.advance_rollout(&rollout.id, now_secs(), 0).unwrap();
    // The canary: all share a profile, so one node, alone.
    let (_, issued) = advance();
    assert_eq!(issued.len(), 1);
    let first = issued[0].clone();
    let second = if first == a { b.clone() } else { a.clone() };
    assert!(
        hub.db
            .pending_commands(&second, now_secs())
            .unwrap()
            .is_empty()
    );
    // The update carries the node timeout as its deadline, and expires with the drain's.
    let command = hub
        .db
        .pending_commands(&first, now_secs())
        .unwrap()
        .remove(0);
    assert!(matches!(
        command.op,
        vk_hub_proto::Operation::Update {
            within_secs: Some(600),
            ..
        }
    ));
    assert!(command.expires_at <= now_secs() + 600);
    // An update of an operator's on the side is refused.
    let err = ops::update(&hub, "uid 0", &second, &release.sha256, false).unwrap_err();
    assert!(format!("{err:#}").contains("abort it first"), "{err:#}");
    assert_eq!(advance(), (false, vec![]));
    ack_only(&hub, &first, vk_hub_proto::Outcome::Done);
    // Done, but not yet running the release: waited for.
    assert!(advance().1.is_empty());
    ready_on(&hub, &first, &release.sha256);
    // Updated and back: the next wave starts.
    assert_eq!(advance().1, std::slice::from_ref(&second));
    ack_only(
        &hub,
        &second,
        vk_hub_proto::Outcome::Failed {
            message: "rolled back: validation failed".into(),
        },
    );
    advance();
    let (_, row) = hub.db.resolve_rollout(&rollout.id[..6]).unwrap();
    assert!(
        matches!(&row.state, rollout::RolloutState::Paused { reason } if reason.contains("rolled back")),
        "{row:?}"
    );
    // The release stays while its rollout is not over.
    let err = releases::remove(&hub, "uid 0", &release.sha256).unwrap_err();
    assert!(format!("{err:#}").contains("is paused"), "{err:#}");
    let resumed =
        ops::steer_rollout(&hub, "uid 0", &rollout.id, rollout::RolloutAction::Resume).unwrap();
    assert_eq!(resumed.row.state, rollout::RolloutState::Running);
    advance();
    let (_, row) = hub.db.resolve_rollout(&rollout.id).unwrap();
    assert_eq!(row.state, rollout::RolloutState::Done);
    let events: Vec<String> = hub
        .db
        .audits(None, 100)
        .unwrap()
        .into_iter()
        .map(|r| format!("{}: {}", r.actor, r.event))
        .collect();
    for want in [
        "started rollout",
        "4 node(s), 2 skipped from the start",
        "updated to vk 0.85.0",
        "paused: a node failed",
        "resumed rollout",
        "done: vk 0.85.0 on 1 node(s), 1 failed, 2 skipped",
    ] {
        assert!(
            events.iter().any(|e| e.contains(want)),
            "{want}: {events:?}"
        );
    }
    let err =
        ops::steer_rollout(&hub, "uid 0", &rollout.id, rollout::RolloutAction::Pause).unwrap_err();
    assert!(format!("{err:#}").contains("cannot be paused"), "{err:#}");
    // Over: the release can go.
    assert!(releases::remove(&hub, "uid 0", &release.sha256).unwrap());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn an_aborted_rollout_issues_nothing_more_and_frees_its_nodes() {
    let (dir, _, hub) = start_releases("rollout-abort", None).await;
    let release = add_release(&hub, &dir, &fake_vk("0.85.0"), "0.85.0").unwrap();
    let (a, b) = (enroll_as(&hub, "a"), enroll_as(&hub, "b"));
    ready_on(&hub, &a, &"00".repeat(32));
    ready_on(&hub, &b, &"00".repeat(32));
    let rollout =
        ops::create_rollout(&hub, "uid 0", &rollout_plan(&release.sha256, false, 0)).unwrap();
    let (_, issued) = hub.db.advance_rollout(&rollout.id, now_secs(), 0).unwrap();
    assert_eq!(issued, std::slice::from_ref(&a));
    let aborted = ops::steer_rollout(
        &hub,
        "uid 0",
        &rollout.id[..4],
        rollout::RolloutAction::Abort,
    )
    .unwrap();
    assert!(matches!(
        aborted.row.state,
        rollout::RolloutState::Aborted { .. }
    ));
    // The update under way finishes and is recorded; nothing more is issued.
    ack_only(&hub, &a, vk_hub_proto::Outcome::Done);
    ready_on(&hub, &a, &release.sha256);
    let (changed, issued) = hub.db.advance_rollout(&rollout.id, now_secs(), 0).unwrap();
    assert!(changed && issued.is_empty());
    let (_, row) = hub.db.resolve_rollout(&rollout.id).unwrap();
    assert!(matches!(
        row.nodes[0].status,
        rollout::NodeStatus::Succeeded { .. }
    ));
    assert_eq!(row.nodes[1].status, rollout::NodeStatus::Pending);
    // Its nodes are an operator's again.
    ops::update(&hub, "uid 0", &b, &release.sha256, false).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// An update still under way when its rollout is aborted keeps the release, and its failure is
/// recorded without counting against the rollout.
#[tokio::test(flavor = "multi_thread")]
async fn an_aborted_rollouts_straggler_keeps_its_release_and_fails_uncounted() {
    let (dir, _, hub) = start_releases("rollout-straggler", None).await;
    let release = add_release(&hub, &dir, &fake_vk("0.85.0"), "0.85.0").unwrap();
    let a = enroll_as(&hub, "a");
    ready_on(&hub, &a, &"00".repeat(32));
    let rollout =
        ops::create_rollout(&hub, "uid 0", &rollout_plan(&release.sha256, false, 0)).unwrap();
    let (_, issued) = hub.db.advance_rollout(&rollout.id, now_secs(), 0).unwrap();
    assert_eq!(issued, std::slice::from_ref(&a));
    ops::steer_rollout(&hub, "uid 0", &rollout.id, rollout::RolloutAction::Abort).unwrap();
    // Aborted, but a node is still updating to the release.
    let err = releases::remove(&hub, "uid 0", &release.sha256).unwrap_err();
    assert!(
        format!("{err:#}").contains("still being updated"),
        "{err:#}"
    );
    ack_only(
        &hub,
        &a,
        vk_hub_proto::Outcome::Failed {
            message: "rolled back: validation failed".into(),
        },
    );
    let (changed, issued) = hub.db.advance_rollout(&rollout.id, now_secs(), 0).unwrap();
    assert!(changed && issued.is_empty());
    let (_, row) = hub.db.resolve_rollout(&rollout.id).unwrap();
    assert!(matches!(
        &row.nodes[0].status,
        rollout::NodeStatus::Failed { reason, .. } if reason.contains("rolled back")
    ));
    assert_eq!(row.failures, 0);
    assert!(matches!(row.state, rollout::RolloutState::Aborted { .. }));
    assert!(releases::remove(&hub, "uid 0", &release.sha256).unwrap());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A canary is picked among the nodes the rollout can update: one it could not would leave
/// its profile without a canary.
#[tokio::test(flavor = "multi_thread")]
async fn a_canary_is_one_the_rollout_can_update() {
    let (dir, _, hub) = start_releases("rollout-canary", None).await;
    let release = add_release(&hub, &dir, &fake_vk("0.85.0"), "0.85.0").unwrap();
    let (a, b) = (enroll_as(&hub, "a"), enroll_as(&hub, "b"));
    ready_on(&hub, &a, &"00".repeat(32));
    ready_on(&hub, &b, &"00".repeat(32));
    hub.db
        .record_report(
            &a,
            vk_hub_proto::Report {
                state: Some(vk_hub_proto::NodeState::Ready),
                runner: Some(vk_hub_proto::RunnerMode::External),
                ..vk_hub_proto::Report::default()
            },
            now_secs(),
        )
        .unwrap();
    let mut plan = rollout_plan(&release.sha256, true, 0);
    plan.nodes = ops::Selection::Nodes(vec![a[..7].to_string()]);
    let err = ops::create_rollout(&hub, "uid 0", &plan).unwrap_err();
    assert!(format!("{err:#}").contains("first 8 hex digits"), "{err:#}");
    plan.nodes = ops::Selection::All;
    let rollout = ops::create_rollout(&hub, "uid 0", &plan).unwrap();
    let node = |id: &str| {
        rollout
            .row
            .nodes
            .iter()
            .find(|n| n.id == id)
            .unwrap()
            .clone()
    };
    assert!(
        matches!(&node(&a).status, rollout::NodeStatus::Skipped { reason } if reason.contains("external")),
        "{:?}",
        node(&a)
    );
    assert_eq!(node(&b).wave, 0);
    let (_, issued) = hub.db.advance_rollout(&rollout.id, now_secs(), 0).unwrap();
    assert_eq!(issued, std::slice::from_ref(&b));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// An update an operator issued before the rollout reached the node is left to finish: the
/// rollout skips the node rather than issue it a second, which it would refuse.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollout_skips_a_node_with_an_update_of_its_own() {
    let (dir, _, hub) = start_releases("rollout-own", None).await;
    let release = add_release(&hub, &dir, &fake_vk("0.85.0"), "0.85.0").unwrap();
    let a = enroll_as(&hub, "a");
    ready_on(&hub, &a, &"00".repeat(32));
    ops::update(&hub, "uid 0", &a, &release.sha256, false).unwrap();
    let rollout =
        ops::create_rollout(&hub, "uid 0", &rollout_plan(&release.sha256, false, 0)).unwrap();
    let (_, issued) = hub.db.advance_rollout(&rollout.id, now_secs(), 0).unwrap();
    assert!(issued.is_empty());
    let (_, row) = hub.db.resolve_rollout(&rollout.id).unwrap();
    assert!(
        matches!(&row.nodes[0].status, rollout::NodeStatus::Skipped { reason } if reason.contains("of its own")),
        "{row:?}"
    );
    assert_eq!(row.state, rollout::RolloutState::Done);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A hub restarted mid-rollout carries on from its database.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollout_survives_a_hub_restart() {
    let dir = std::env::temp_dir().join(format!("vk-hub-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("data").join("hub.db");
    let open = || {
        Hub::new(Arc::new(Db::open(&db_path).unwrap()), None).with_releases(dir.join("releases"))
    };
    let hub = open();
    let release = add_release(&hub, &dir, &fake_vk("0.85.0"), "0.85.0").unwrap();
    let ids = [enroll_as(&hub, "a"), enroll_as(&hub, "b")];
    for id in &ids {
        ready_on(&hub, id, &"00".repeat(32));
    }
    let rollout =
        ops::create_rollout(&hub, "uid 0", &rollout_plan(&release.sha256, false, 0)).unwrap();
    let (_, issued) = hub.db.advance_rollout(&rollout.id, now_secs(), 0).unwrap();
    assert_eq!(issued, [ids[0].clone()]);
    drop(hub);

    let hub = open();
    // Back after longer than both windows: the database's facts predate the downtime, so the
    // node has the grace to reconnect and report before it is judged.
    let later = now_secs() + 10_000;
    let not_before = later + rollout::GIVE_UP_GRACE_SECS;
    assert_eq!(
        hub.db
            .advance_rollout(&rollout.id, later, not_before)
            .unwrap(),
        (false, vec![])
    );
    let (_, row) = hub.db.resolve_rollout(&rollout.id).unwrap();
    assert!(
        matches!(row.nodes[0].status, rollout::NodeStatus::Updating { .. }),
        "{row:?}"
    );
    ack_only(&hub, &ids[0], vk_hub_proto::Outcome::Done);
    ready_on(&hub, &ids[0], &release.sha256);
    assert_eq!(
        hub.db
            .advance_rollout(&rollout.id, now_secs(), 0)
            .unwrap()
            .1,
        [ids[1].clone()]
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `vk-hub rollout status` names each node's wave and how its update went.
#[test]
fn a_rollout_status_shows_each_node_by_wave() {
    let row = rollout::RolloutRow {
        release: "ab".repeat(32),
        version: "0.85.0".into(),
        created_at: 1_800_000_000,
        created_by: "uid 0".into(),
        batch: 1,
        canary_per_profile: true,
        max_failures: 0,
        node_timeout_secs: 600,
        drain_timeout_secs: 600,
        force: false,
        state: rollout::RolloutState::Paused {
            reason: "a node failed: b".into(),
        },
        failures: 1,
        nodes: vec![
            rollout::RolloutNode {
                id: "n1".into(),
                hostname: "a".into(),
                profile: "big".into(),
                wave: 0,
                status: rollout::NodeStatus::Succeeded { at: 1_800_000_060 },
            },
            rollout::RolloutNode {
                id: "n2".into(),
                hostname: "b".into(),
                profile: "big".into(),
                wave: 1,
                status: rollout::NodeStatus::Failed {
                    reason: "rolled back".into(),
                    at: 1_800_000_120,
                },
            },
            rollout::RolloutNode {
                id: "n3".into(),
                hostname: "c".into(),
                profile: "big".into(),
                wave: 2,
                status: rollout::NodeStatus::Pending,
            },
        ],
    };
    let r = rollout::Rollout {
        id: "cafe".repeat(4),
        row,
    };
    let out = render_rollout(&r, 1_800_000_200);
    let lines: Vec<&str> = out.lines().collect();
    assert!(
        lines[0].contains("paused (a node failed: b) at wave 2"),
        "{out}"
    );
    assert!(
        lines[0].ends_with("1 pending, 1 succeeded, 1 failed"),
        "{out}"
    );
    assert!(lines[2].contains("wave 1  n2") && lines[2].contains("failed: rolled back"));
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
        (&["ui", "login"][..], store::MAX_LOGIN_TTL),
        (&["token", "create"][..], store::MAX_TOKEN_TTL),
    ] {
        let help = help(path);
        let bound = format!("(at most {})", human_duration(max));
        assert!(help.contains(&bound), "{path:?}: {help} lacks {bound}");
    }
}

/// `vk-hub accounts` lists by default; a grant needs `--role`, and grant and revoke take an
/// address, normalized, or `*`.
#[test]
fn accounts_arguments_parse() {
    let parse = |args: &[&str]| {
        let mut argv = vec!["vk-hub", "accounts"];
        argv.extend_from_slice(args);
        match Cli::try_parse_from(argv).map(|c| c.cmd) {
            Ok(Cmd::Accounts { cmd, .. }) => Ok(cmd),
            Ok(_) => panic!("not accounts"),
            Err(e) => Err(e.to_string()),
        }
    };
    assert!(matches!(parse(&[]), Ok(None)));
    assert!(matches!(parse(&["list"]), Ok(Some(AccountsCmd::List))));
    match parse(&["grant", "Alice@Example.com", "--role", "operator"]) {
        Ok(Some(AccountsCmd::Grant { email, role })) => {
            assert_eq!(
                (email.as_str(), role),
                ("alice@example.com", store::Role::Operator)
            );
        }
        other => panic!("{:?}", other.err()),
    }
    let err = parse(&["grant", "alice@example.com"]).unwrap_err();
    assert!(err.contains("--role"), "{err}");
    let err = parse(&["grant", "alice@example.com", "--role", "admin"]).unwrap_err();
    assert!(err.contains("expected viewer or operator"), "{err}");
    let err = parse(&["grant", "alice", "--role", "viewer"]).unwrap_err();
    assert!(err.contains("neither an email address nor *"), "{err}");
    assert!(matches!(
        parse(&["revoke", "BOB@example.com"]),
        Ok(Some(AccountsCmd::Revoke { email })) if email == "bob@example.com"
    ));
    assert!(matches!(
        parse(&["grant", "*", "--role", "viewer"]),
        Ok(Some(AccountsCmd::Grant { email, .. })) if email == "*"
    ));
}

/// The accounts table names each grant's address, role, and who made it when, and the
/// default role last.
#[test]
fn the_accounts_table_says_who_granted_each_role() {
    let row = |role, by: &str| store::AccountRow {
        role,
        granted_by: by.into(),
        granted_at: 0,
    };
    let accounts = [
        ("*".to_string(), row(store::Role::Viewer, "uid 0")),
        (
            "alice@example.com".to_string(),
            row(store::Role::Operator, "uid 1000"),
        ),
    ];
    assert_eq!(
        render_accounts(&accounts, None),
        "EMAIL              ROLE      GRANTED BY  AT\n\
         *                  viewer    uid 0       1970-01-01T00:00:00Z\n\
         alice@example.com  operator  uid 1000    1970-01-01T00:00:00Z\n"
    );
    assert_eq!(render_accounts(&[], None), "");
    // The default role, which admits whoever no grant names, comes last.
    assert_eq!(
        render_accounts(&accounts[1..], Some(store::Role::Viewer)),
        "EMAIL              ROLE      GRANTED BY           AT\n\
         alice@example.com  operator  uid 1000             1970-01-01T00:00:00Z\n\
         (default)          viewer    [oidc] default_role\n"
    );
    assert_eq!(
        render_accounts(&[], Some(store::Role::Viewer)),
        "EMAIL      ROLE    GRANTED BY           AT\n\
         (default)  viewer  [oidc] default_role\n"
    );
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

/// SYNC is ok only when the node applied the hub's state, not merely a state under its
/// generation.
#[test]
fn sync_compares_the_applied_state_not_only_its_generation() {
    use vk_hub_proto::{Acquisition, DesiredState, Report};
    let desired = DesiredState {
        generation: 3,
        ceiling: Some(4),
        acquisition: Acquisition::Run,
    };
    let view = |applied: DesiredState| ops::NodeView {
        protocol: Some(vk_hub_proto::STEERING),
        desired: Some(desired.clone()),
        report: Some(Report {
            applied: Some(applied),
            ..Report::default()
        }),
        ..ops::NodeView::default()
    };
    assert_eq!(steering_cells(&view(desired.clone()))[3], "ok");
    let other = DesiredState {
        ceiling: None,
        ..desired.clone()
    };
    assert_eq!(steering_cells(&view(other))[3], "differs");
}

#[test]
fn the_nodes_table_shows_desired_beside_observed_and_marks_a_lag() {
    use vk_hub_proto::{Acquisition, Concurrency, DesiredState, NodeState, Report};
    let nodes = [
        ops::NodeView {
            id: "a".repeat(32),
            hostname: "ci-1".into(),
            connected: true,
            last_seen: Some(995),
            vk: Some("0.84.0".into()),
            cpus: Some(64),
            mem_total_mib: Some(512 * 1024),
            committed_mib: Some(8 * 1024),
            budget_mib: Some(400 * 1024),
            protocol: Some(vk_hub_proto::STEERING),
            desired: Some(DesiredState {
                generation: 3,
                ceiling: Some(4),
                acquisition: Acquisition::Stop,
            }),
            report: Some(Report {
                applied: Some(DesiredState {
                    generation: 2,
                    ceiling: Some(6),
                    acquisition: Acquisition::Run,
                }),
                state: Some(NodeState::Draining),
                acquisition: Some(Acquisition::Run),
                concurrency: Some(Concurrency {
                    estimate: Some(9),
                    hub_ceiling: Some(6),
                    local_ceiling: None,
                    effective: Some(6),
                }),
                runner_state: Some(vk_hub_proto::RunnerState::Quitting),
                unsupported: vec!["stopping acquisition: external".into()],
                concurrency_error: Some("bad mem".into()),
                ..Report::default()
            }),
            pending_commands: 1,
            ..ops::NodeView::default()
        },
        ops::NodeView {
            id: "b".repeat(32),
            hostname: "ci-2".into(),
            ..ops::NodeView::default()
        },
        // On version 1, whatever the hub once asked of it.
        ops::NodeView {
            id: "c".repeat(32),
            hostname: "ci-3".into(),
            protocol: Some(1),
            desired: Some(DesiredState {
                generation: 1,
                ceiling: Some(2),
                acquisition: Acquisition::Run,
            }),
            report: Some(Report::default()),
            ..ops::NodeView::default()
        },
    ];
    let table = render_nodes(&nodes, 1000);
    let lines: Vec<&str> = table.lines().collect();
    assert_eq!(lines.len(), 6, "{table}");
    assert_eq!(
        lines[4],
        "ci-1: cannot comply: stopping acquisition: external"
    );
    assert_eq!(lines[5], "ci-1: cannot set its concurrency: bad mem");
    let (header, a, b, c) = (lines[0], lines[1], lines[2], lines[3]);
    assert!(header.starts_with("ID "));
    for (column, want) in [
        ("NAME", "ci-1"),
        ("REACH", "connected"),
        ("STATE", "draining, 1 pending"),
        ("ACQUIRE", "stop (node: run, quitting)"),
        ("CEILING", "4 (node: 6)"),
        ("CONC", "6"),
        ("SYNC", "behind (2<3)"),
        ("LAST SEEN", "5s ago"),
        ("ADMITTED", "8G/400G"),
        ("VMS", "-"),
    ] {
        assert_eq!(cell(header, a, column), want, "{column}\n{table}");
    }
    for (column, want) in [
        ("REACH", "unreachable"),
        ("STATE", "-"),
        ("ACQUIRE", "run"),
        ("CEILING", "-"),
        ("SYNC", "-"),
        ("LAST SEEN", "never"),
    ] {
        assert_eq!(cell(header, b, column), want, "{column}\n{table}");
    }
    for (column, want) in [
        ("STATE", "monitor only (v1)"),
        ("ACQUIRE", "-"),
        ("CEILING", "-"),
        ("SYNC", "-"),
    ] {
        assert_eq!(cell(header, c, column), want, "{column}\n{table}");
    }
    assert_eq!(ago(10_000, 10_000 - 7300), Duration::from_secs(7200));
}

/// STATE says how far an update under way has got, and that the last one was rolled back;
/// one done or given up before the switch adds nothing.
#[test]
fn the_nodes_table_shows_an_update_under_way_and_one_rolled_back() {
    use vk_hub_proto::{NodeState, Report, UpdatePhase, UpdateProgress};
    let node = |phase| ops::NodeView {
        id: "a".repeat(32),
        hostname: "ci-1".into(),
        protocol: Some(vk_hub_proto::STEERING),
        report: Some(Report {
            state: Some(NodeState::Maintenance),
            update: Some(UpdateProgress {
                command: "c1".repeat(16),
                version: "0.85.0".into(),
                sha256: "ab".repeat(32),
                phase,
                message: Some("vk check failed".into()),
            }),
            ..Report::default()
        }),
        ..ops::NodeView::default()
    };
    for (phase, want) in [
        (
            UpdatePhase::Draining,
            "maintenance, updating to 0.85.0: draining",
        ),
        (
            UpdatePhase::Downloading,
            "maintenance, updating to 0.85.0: downloading",
        ),
        (
            UpdatePhase::Validating,
            "maintenance, updating to 0.85.0: validating",
        ),
        (
            UpdatePhase::RolledBack,
            "maintenance, update to 0.85.0 rolled back",
        ),
        (UpdatePhase::Done, "maintenance"),
        (UpdatePhase::Failed, "maintenance"),
    ] {
        let table = render_nodes(&[node(phase)], 1000);
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(cell(lines[0], lines[1], "STATE"), want, "{table}");
    }
}

#[test]
fn a_ceiling_is_a_positive_number_or_none() {
    assert_eq!(parse_ceiling("none"), Ok(Ceiling(None)));
    assert_eq!(parse_ceiling("3"), Ok(Ceiling(Some(3))));
    let err = parse_ceiling("0").unwrap_err();
    assert!(err.contains("vk-hub nodes stop"), "{err}");
    assert!(parse_ceiling("-1").is_err());
}

/// `vk-hub workloads`: each node's VMs under its name, what each belongs to in words, the
/// memory it holds from the heartbeat, and a line for a node that has not said.
#[test]
fn the_workloads_table_names_what_each_vm_is_for() {
    use vk_hub_proto::{Workload, WorkloadKind};
    let bare = |id: &str, kind| Workload {
        id: id.into(),
        kind,
        state_dir: format!("/s/{id}"),
        label: None,
        project: None,
        job_name: None,
        job_id: None,
        workspace: None,
        environment: None,
        pid: None,
        cpus: None,
        mem_reserved_mib: None,
        started_at: None,
        ssh_alias: None,
        guest_workspace: None,
        job_url: None,
    };
    let job = Workload {
        project: Some("acme/web".into()),
        job_name: Some("test:unit".into()),
        job_id: Some("4242".into()),
        pid: Some(77),
        cpus: Some(4),
        mem_reserved_mib: Some(6144),
        started_at: Some(880),
        ..bare("aaaa", WorkloadKind::CiJob)
    };
    let dev = Workload {
        workspace: Some("/src/app".into()),
        environment: Some("dev".into()),
        mem_reserved_mib: Some(512),
        ..bare("bbbb", WorkloadKind::Dev)
    };
    let run = Workload {
        label: Some("alpine:3.20".into()),
        ..bare("cccc", WorkloadKind::Run)
    };
    let nodes = [
        ops::NodeWorkloads {
            id: "a".repeat(32),
            hostname: "ci-1".into(),
            connected: true,
            workloads: Some(store::Workloads {
                listed: vec![job, dev, run],
                omitted: 2,
                mem_bytes: [("aaaa".to_string(), 3 << 30)].into(),
            }),
            ..Default::default()
        },
        ops::NodeWorkloads {
            id: "b".repeat(32),
            hostname: "ci-2".into(),
            ..Default::default()
        },
    ];
    let table = render_workloads(&nodes);
    let lines: Vec<&str> = table.lines().collect();
    assert_eq!(lines.len(), 6, "{table}");
    assert!(lines[0].starts_with("NODE  KIND    ID    FOR"), "{table}");
    let words = |l: &str| {
        l.split("  ")
            .map(str::trim)
            .filter(|w| !w.is_empty())
            .map(String::from)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        words(lines[1]),
        [
            "ci-1",
            "ci-job",
            "aaaa",
            "acme/web test:unit #4242",
            "77",
            "4",
            "6G",
            "3G",
            "1970-01-01T00:14:40Z",
            "/s/aaaa"
        ],
        "{table}"
    );
    assert!(
        lines[2].contains("/src/app (dev)") && lines[2].contains("512M"),
        "{table}"
    );
    assert!(lines[3].contains("alpine:3.20"), "{table}");
    assert_eq!(lines[4], "ci-1: 2 more running, not listed");
    assert_eq!(lines[5], "ci-2: has not reported its workloads");
    // Wide characters take the columns they take on a terminal.
    let wide = crate::table(
        &["A", "B"],
        &[["漢字".into(), "x".into()], ["ab".into(), "y".into()]],
    );
    assert_eq!(wide, "A     B\n漢字  x\nab    y\n");
    // A list from a node not connected is told apart, and one left out of the reply says
    // where to find it.
    let stale = render_workloads(&[ops::NodeWorkloads {
        id: "c".repeat(32),
        hostname: "ci-3".into(),
        last_seen: Some(60),
        workloads: Some(store::Workloads::default()),
        withheld: 4,
        ..Default::default()
    }]);
    assert!(
        stale.contains("ci-3: not connected; as last seen at 1970-01-01T00:01:00Z\n"),
        "{stale}"
    );
    assert!(
        stale.contains(&format!(
            "ci-3: 4 listed, too many to show with every node's: see `vk-hub workloads --node {}`",
            "c".repeat(32)
        )),
        "{stale}"
    );
}

/// `vk-hub workloads --node` takes an ID, or a hostname only one node has.
#[test]
fn workloads_are_selected_by_id_or_unambiguous_hostname() {
    let hub = Hub::new(Arc::new(Db::open_memory().unwrap()), None);
    let enroll = |host: &str| {
        let (token, _) = hub
            .db
            .create_token(Duration::from_secs(60), "uid 0", 1)
            .unwrap();
        match hub
            .db
            .enroll(&token, &host.repeat(64), host, "peer p", 1)
            .unwrap()
        {
            store::Enrollment::Enrolled { node_id } => node_id,
            _ => panic!("expected an enrollment"),
        }
    };
    let (a, b, c) = (enroll("a"), enroll("b"), enroll("c"));
    hub.db
        .record_inventory(
            &c,
            vk_hub_proto::Inventory {
                hostname: "b".into(),
                ..Default::default()
            },
            true,
            2,
        )
        .unwrap();
    let ids = |sel: Option<&str>| -> Vec<String> {
        ops::workloads(&hub, sel, usize::MAX)
            .unwrap()
            .into_iter()
            .map(|n| n.id)
            .collect()
    };
    assert_eq!(ids(Some("a")), std::slice::from_ref(&a));
    assert_eq!(ids(Some(&b)), std::slice::from_ref(&b));
    assert_eq!(ids(None).len(), 3);
    let ambiguous = ops::workloads(&hub, Some("b"), usize::MAX).unwrap_err();
    assert!(format!("{ambiguous}").contains("several"), "{ambiguous}");
    assert!(ops::workloads(&hub, Some("nope"), usize::MAX).is_err());
    assert!(
        ops::workloads(&hub, None, usize::MAX)
            .unwrap()
            .iter()
            .all(|n| n.workloads.is_none())
    );

    // Every node's together past the limit come as counts; one node's still whole.
    let listed: Vec<vk_hub_proto::Workload> = (0..3)
        .map(|i| vk_hub_proto::Workload {
            id: format!("{i:016x}"),
            kind: vk_hub_proto::WorkloadKind::Run,
            state_dir: format!("/s/{i}"),
            label: None,
            project: None,
            job_name: None,
            job_id: None,
            workspace: None,
            environment: None,
            pid: None,
            cpus: None,
            mem_reserved_mib: None,
            started_at: Some(i),
            ssh_alias: None,
            guest_workspace: None,
            job_url: None,
        })
        .collect();
    hub.db
        .record_report(
            &a,
            vk_hub_proto::Report {
                workloads: Some(listed),
                ..vk_hub_proto::Report::default()
            },
            3,
        )
        .unwrap();
    let all = ops::workloads(&hub, None, usize::MAX).unwrap();
    let of_a = |all: &[ops::NodeWorkloads]| all.iter().find(|n| n.id == a).unwrap().clone();
    assert_eq!(of_a(&all).workloads.unwrap().listed.len(), 3);
    let counted = ops::workloads(&hub, None, 100).unwrap();
    let n = of_a(&counted);
    assert_eq!((n.withheld, n.workloads.unwrap().listed.len()), (3, 0));
    let one = ops::workloads(&hub, Some(&a), 100).unwrap();
    assert_eq!(
        (
            one[0].withheld,
            one[0].workloads.as_ref().unwrap().listed.len()
        ),
        (0, 3)
    );
}

#[test]
fn audit_times_are_utc() {
    assert_eq!(utc(0), "1970-01-01T00:00:00Z");
    assert_eq!(utc(951_782_400), "2000-02-29T00:00:00Z");
    assert_eq!(utc(1_790_755_279), "2026-09-30T08:01:19Z");
}

mod jobs;
