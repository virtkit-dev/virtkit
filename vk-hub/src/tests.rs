//! The hub end to end over real sockets — enrollment, the session handshake, what a session
//! records — plus the CLI's own parsing and rendering.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use ring::signature::{Ed25519KeyPair, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use vk_fleet_proto::{
    EnrollRequest, EnrollResponse, Heartbeat, HubMsg, Inventory, NodeMsg, PROTOCOL, RefusalCode,
    VersionRange,
};

use super::*;
use crate::server::{Hub, Reach};
use crate::store::Db;

/// A hub on an ephemeral loopback port, plain HTTP.
async fn start() -> (SocketAddr, Arc<Hub>) {
    let listener = server::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let hub = Arc::new(Hub::new(Arc::new(Db::open_memory().unwrap())));
    tokio::spawn(server::serve(listener, None, hub.clone()));
    (addr, hub)
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
        vk_fleet_proto::ENROLL_PATH,
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
        public_key: vk_fleet_proto::to_hex(public_key),
        signature: vk_fleet_proto::to_hex(
            key.sign(&vk_fleet_proto::enroll_message(token, public_key))
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

type Client = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

async fn dial(addr: SocketAddr) -> Client {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let url = format!("ws://{addr}{}", vk_fleet_proto::NODE_PATH);
    tokio_tungstenite::client_async(url, stream)
        .await
        .unwrap()
        .0
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
    open_signing(ws, node_id, incarnation, signer, None).await
}

/// [`open`], signing for `claimed_version` instead of the version the hub chose when given.
async fn open_signing(
    ws: &mut Client,
    node_id: &str,
    incarnation: &str,
    signer: &Ed25519KeyPair,
    claimed_version: Option<u32>,
) -> HubMsg {
    send(ws, &hello(node_id, incarnation, PROTOCOL)).await;
    let HubMsg::Challenge {
        version,
        versions,
        nonce,
    } = receive(ws).await
    else {
        panic!("expected a challenge");
    };
    assert_eq!(version, PROTOCOL.max);
    assert_eq!(versions, PROTOCOL);
    let nonce = vk_fleet_proto::from_hex(&nonce).unwrap();
    assert_eq!(nonce.len(), vk_fleet_proto::CHALLENGE_LEN);
    let signature = signer.sign(&vk_fleet_proto::auth_message(
        &nonce,
        node_id,
        incarnation,
        PROTOCOL,
        versions,
        claimed_version.unwrap_or(version),
        vk_fleet_proto::Channel::Plaintext,
    ));
    send(
        ws,
        &NodeMsg::Auth {
            signature: vk_fleet_proto::to_hex(signature.as_ref()),
        },
    )
    .await;
    receive(ws).await
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
            heartbeat_secs: server::HEARTBEAT.as_secs() as u32
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
        public_key: vk_fleet_proto::to_hex(key.public_key().as_ref()),
        signature: vk_fleet_proto::to_hex(
            other
                .sign(&vk_fleet_proto::enroll_message(
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
}

/// The auth is bound to the version the hub chose: a signature made for another does not
/// verify, so a peer in the middle cannot move the session to a version of its choosing.
#[tokio::test(flavor = "multi_thread")]
async fn an_auth_for_another_version_is_refused() {
    let (addr, hub) = start().await;
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    let mut ws = dial(addr).await;
    let HubMsg::Refused { code, .. } = open_signing(
        &mut ws,
        &node_id,
        &"0c".repeat(16),
        &key,
        Some(PROTOCOL.max + 1),
    )
    .await
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

#[test]
fn times_read_as_people_write_them() {
    assert_eq!(utc(0), "1970-01-01T00:00:00Z");
    assert_eq!(utc(1_800_000_000), "2027-01-15T08:00:00Z");
    assert_eq!(ago(5000, 5000 - 3725), Duration::from_secs(3600));
}

#[test]
fn ttls_parse_within_bounds() {
    assert_eq!(parse_ttl("90s"), Ok(Duration::from_secs(90)));
    assert_eq!(parse_ttl("15m"), Ok(Duration::from_secs(900)));
    assert_eq!(parse_ttl("2h"), Ok(Duration::from_secs(7200)));
    assert_eq!(parse_ttl("30d"), Ok(store::MAX_TOKEN_TTL));
    for bad in [
        "",
        "h",
        "0s",
        "31d",
        "1w",
        "-1h",
        "1.5h",
        "99999999999999999999d",
    ] {
        assert!(parse_ttl(bad).is_err(), "{bad:?}");
    }
    assert_eq!(human_duration(Duration::from_secs(7200)), "2h");
    assert_eq!(human_duration(Duration::from_secs(90)), "90s");
}

/// The cell under `column` in `line`, by where the header puts the column.
fn cell<'a>(header: &str, line: &'a str, column: &str) -> &'a str {
    let names = [
        "ID",
        "NAME",
        "REACH",
        "STATE",
        "ACQUIRE",
        "CEILING",
        "CONC",
        "SYNC",
        "LAST SEEN",
        "VK",
        "CPUS",
        "RAM",
        "ADMITTED",
    ];
    let at = |name: &str| {
        header
            .find(&format!("{name} "))
            .or_else(|| header.find(name))
            .unwrap()
    };
    let start = at(column);
    let next = names
        .iter()
        .map(|n| at(n))
        .filter(|&p| p > start)
        .min()
        .unwrap_or(line.len());
    line.get(start..next.min(line.len())).unwrap_or("").trim()
}

#[test]
fn the_nodes_table_shows_desired_beside_observed_and_marks_a_lag() {
    use vk_fleet_proto::{Acquisition, Concurrency, DesiredState, NodeState, Report};
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
            desired: Some(DesiredState {
                generation: 3,
                ceiling: Some(4),
                acquisition: Acquisition::Stop,
            }),
            report: Some(Report {
                applied_generation: Some(2),
                state: NodeState::Draining,
                acquisition: Acquisition::Run,
                concurrency: Some(Concurrency {
                    estimate: Some(9),
                    hub_ceiling: Some(6),
                    local_ceiling: None,
                    effective: Some(6),
                }),
                runner_state: Some(vk_fleet_proto::RunnerState::Quitting),
                unsupported: vec!["stopping acquisition: external".into()],
                concurrency_error: Some("bad mem".into()),
                ..Report::default()
            }),
            pending_commands: 1,
        },
        ops::NodeView {
            id: "b".repeat(32),
            hostname: "ci-2".into(),
            ..ops::NodeView::default()
        },
    ];
    let table = render_nodes(&nodes, 1000);
    let lines: Vec<&str> = table.lines().collect();
    assert_eq!(lines.len(), 5, "{table}");
    assert_eq!(
        lines[3],
        "ci-1: cannot comply: stopping acquisition: external"
    );
    assert_eq!(lines[4], "ci-1: cannot set its concurrency: bad mem");
    let (header, a, b) = (lines[0], lines[1], lines[2]);
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
    assert_eq!(ago(10_000, 10_000 - 7300), Duration::from_secs(7200));
}

#[test]
fn audit_times_are_utc() {
    assert_eq!(utc(0), "1970-01-01T00:00:00Z");
    assert_eq!(utc(951_782_400), "2000-02-29T00:00:00Z");
    assert_eq!(utc(1_790_755_279), "2026-09-30T08:01:19Z");
}

/// Desired state goes to a node that reports itself behind, and pending commands on every
/// session until the node reports them finished; the node's acks are recorded and audited.
#[tokio::test(flavor = "multi_thread")]
async fn a_lagging_node_gets_desired_state_and_commands_until_they_are_done() {
    use vk_fleet_proto::{Acquisition, CommandAck, Operation, Outcome, Report};
    let (addr, hub) = start().await;
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    let desired = hub
        .db
        .set_desired(
            &node_id,
            |d| d.ceiling = Some(3),
            "uid 0",
            "set a ceiling",
            1,
        )
        .unwrap()
        .unwrap();
    let drain = hub
        .db
        .issue_command(
            &node_id,
            Operation::Drain,
            Duration::from_secs(600),
            "uid 0",
            now_secs(),
        )
        .unwrap();
    let report = |applied| {
        NodeMsg::Report(Report {
            applied_generation: applied,
            ..Report::default()
        })
    };

    let mut ws = dial(addr).await;
    assert!(matches!(
        open(&mut ws, &node_id, &"0d".repeat(16), &key).await,
        HubMsg::Welcome { .. }
    ));
    send(&mut ws, &report(None)).await;
    assert_eq!(receive(&mut ws).await, HubMsg::Desired(desired.clone()));
    assert_eq!(receive(&mut ws).await, HubMsg::Command(drain.clone()));
    let accepted = CommandAck {
        id: drain.id.clone(),
        outcome: Outcome::Accepted,
    };
    send(&mut ws, &NodeMsg::Ack(accepted.clone())).await;
    assert_eq!(receive(&mut ws).await, HubMsg::Recorded(accepted));
    // A change while connected is sent at once.
    hub.db
        .set_desired(
            &node_id,
            |d| d.acquisition = Acquisition::Stop,
            "uid 0",
            "stopped acquisition",
            1,
        )
        .unwrap();
    hub.kick(&node_id);
    let HubMsg::Desired(second) = receive(&mut ws).await else {
        panic!("expected desired state");
    };
    assert_eq!(second.generation, 2);
    ws.close(None).await.unwrap();

    // Reconnected still behind, with the drain under way: both again.
    let mut ws = dial(addr).await;
    open(&mut ws, &node_id, &"0d".repeat(16), &key).await;
    send(&mut ws, &report(Some(1))).await;
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

/// A fake `vk`: an x86-64 ELF header, then bytes that hold `version` as a string of its own.
fn fake_vk(version: &str) -> Vec<u8> {
    let mut bin = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x02\0\x3e\0".to_vec();
    bin.extend_from_slice(b"\0vk-driver ");
    bin.extend_from_slice(version.as_bytes());
    bin.extend_from_slice(&[0u8; 5000]);
    bin
}

/// `GET <path>` with `headers`, by hand: the status and the body.
async fn get_with(addr: SocketAddr, path: &str, headers: &[(&str, String)]) -> (u16, Vec<u8>) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut head = format!("GET {path} HTTP/1.1\r\nHost: hub\r\nConnection: close\r\n");
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.unwrap();
    let split = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let status = std::str::from_utf8(&resp[9..12]).unwrap().parse().unwrap();
    (status, resp[split + 4..].to_vec())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_release_is_served_only_to_a_node_updating_to_it_that_signs_for_it() {
    let dir = std::env::temp_dir().join(format!("vk-hub-releases-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let listener = server::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let hub = Arc::new(
        Hub::new(Arc::new(Db::open_memory().unwrap())).with_releases(dir.join("releases")),
    );
    tokio::spawn(server::serve(listener, None, hub.clone()));

    let bin = fake_vk("0.81.0");
    let file = dir.join("vk");
    std::fs::write(&file, &bin).unwrap();
    // The version must be in it, and it must be an ELF.
    assert!(releases::add(&hub, "uid 0", &file, "0.81.1", None).is_err());
    std::fs::write(dir.join("script"), b"#!/bin/sh\necho 0.81.0\n").unwrap();
    assert!(releases::add(&hub, "uid 0", &dir.join("script"), "0.81.0", None).is_err());
    // A signature must at least be one, in base64; checking it is each node's to do.
    assert!(releases::add(&hub, "uid 0", &file, "0.81.0", Some("abc".into())).is_err());
    let signature = vk_fleet_proto::to_base64(&[5; vk_fleet_proto::SIGNATURE_LEN]);
    let release = releases::add(&hub, "uid 0", &file, "0.81.0", Some(signature.clone())).unwrap();
    assert_eq!(release.row.signature, Some(signature.clone()));
    assert_eq!(release.row.size, bin.len() as u64);
    // Added again as the same release — a retry whose answer was lost — it is the same one;
    // with another signature, or as another version, refused.
    let again = releases::add(&hub, "uid 0", &file, "0.81.0", Some(signature)).unwrap();
    assert_eq!(again, release);
    assert!(releases::add(&hub, "uid 0", &file, "0.81.0", None).is_err());
    let bin2 = fake_vk("0.81.0 0.82.0");
    std::fs::write(&file, &bin2).unwrap();
    let other = releases::add(&hub, "uid 0", &file, "0.82.0", None).unwrap();
    std::fs::write(&file, &bin).unwrap();
    assert!(releases::add(&hub, "uid 0", &file, "0.82.0", None).is_err());
    assert!(releases::remove(&hub, "uid 0", &other.sha256).unwrap());
    let sha = release.sha256.clone();

    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    let path = format!("{}{sha}", vk_fleet_proto::RELEASE_PATH);
    let signed = |key: &Ed25519KeyPair, at: u64| {
        let message = vk_fleet_proto::download_message(
            &node_id,
            &sha,
            at,
            vk_fleet_proto::Channel::Plaintext,
        );
        vec![
            (vk_fleet_proto::NODE_HEADER, node_id.clone()),
            (vk_fleet_proto::TIME_HEADER, at.to_string()),
            (
                vk_fleet_proto::SIGNATURE_HEADER,
                vk_fleet_proto::to_hex(key.sign(&message).as_ref()),
            ),
        ]
    };
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
    let stale = now_secs() - vk_fleet_proto::DOWNLOAD_SKEW_SECS - 5;
    assert_eq!(get_with(addr, &path, &signed(&key, stale)).await.0, 401);
    // Signed for another release, presented for this one.
    let other = format!("{}{}", vk_fleet_proto::RELEASE_PATH, "cd".repeat(32));
    assert_eq!(
        get_with(addr, &other, &signed(&key, now_secs())).await.0,
        403
    );

    // Removal waits for the update, then takes the file too.
    assert!(releases::remove(&hub, "uid 0", &sha).is_err());
    let command = hub
        .db
        .pending_commands(&node_id, now_secs())
        .unwrap()
        .remove(0);
    hub.db
        .record_ack(
            &node_id,
            &vk_fleet_proto::CommandAck {
                id: command.id,
                outcome: vk_fleet_proto::Outcome::Done,
            },
            now_secs(),
        )
        .unwrap();
    assert!(releases::remove(&hub, "uid 0", &sha).unwrap());
    assert!(!dir.join("releases").join(&sha).exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rollout_updates_wave_by_wave_and_pauses_on_a_failure() {
    let dir = std::env::temp_dir().join(format!("vk-hub-rollout-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let hub = Hub::new(Arc::new(Db::open_memory().unwrap())).with_releases(dir.join("releases"));
    std::fs::write(dir.join("vk"), fake_vk("0.81.0")).unwrap();
    let release = releases::add(&hub, "uid 0", &dir.join("vk"), "0.81.0", None).unwrap();
    let node = |name: &str, key: &str| {
        let (token, _) = hub
            .db
            .create_token(Duration::from_secs(60), "uid 0", 0)
            .unwrap();
        let store::Enrollment::Enrolled { node_id } = hub.db.enroll(&token, key, name, 1).unwrap()
        else {
            panic!("expected an enrollment");
        };
        node_id
    };
    let (a, b, c) = (node("a", "k1"), node("b", "k2"), node("c", "k3"));
    let on = |id: &str, sha: &str| {
        let mut inventory = Inventory {
            hostname: id.into(),
            ..Inventory::default()
        };
        inventory.versions.vk_sha256 = Some(sha.into());
        hub.db.record_inventory(id, inventory, 2).unwrap();
        hub.db
            .record_report(
                id,
                vk_fleet_proto::Report {
                    runner: vk_fleet_proto::RunnerMode::Managed,
                    ..vk_fleet_proto::Report::default()
                },
                2,
            )
            .unwrap();
    };
    on(&a, &"00".repeat(32));
    on(&b, &"00".repeat(32));
    on(&c, &release.sha256);
    let plan = ops::RolloutPlan {
        release: release.sha256[..8].into(),
        nodes: ops::Selection::All,
        batch: 1,
        canary_per_profile: true,
        max_failures: 1,
        node_timeout_secs: 600,
        drain_timeout_secs: 600,
        force: false,
    };
    let rollout = ops::create_rollout(&hub, "uid 0", &plan).unwrap();
    // One rollout at a time.
    assert!(ops::create_rollout(&hub, "uid 0", &plan).is_err());
    let command_of = |id: &str| hub.db.pending_commands(id, now_secs()).unwrap();
    let advance = || hub.db.advance_rollout(&rollout.id, now_secs()).unwrap();
    // The canary (all three share a profile; c already runs it): one node at a time.
    let (_, issued) = advance();
    assert_eq!(issued.len(), 1);
    let first = issued[0].clone();
    let second = if first == a { b.clone() } else { a.clone() };
    assert!(command_of(&second).is_empty());
    assert!(advance().1.is_empty());
    let cmd = command_of(&first).remove(0);
    hub.db
        .record_ack(
            &first,
            &vk_fleet_proto::CommandAck {
                id: cmd.id,
                outcome: vk_fleet_proto::Outcome::Done,
            },
            3,
        )
        .unwrap();
    on(&first, &release.sha256);
    // Updated and back: the next wave starts.
    assert_eq!(advance().1, std::slice::from_ref(&second));
    let cmd = command_of(&second).remove(0);
    hub.db
        .record_ack(
            &second,
            &vk_fleet_proto::CommandAck {
                id: cmd.id,
                outcome: vk_fleet_proto::Outcome::Failed {
                    message: "rolled back: validation failed".into(),
                },
            },
            4,
        )
        .unwrap();
    advance();
    let (_, row) = hub.db.resolve_rollout(&rollout.id[..6]).unwrap();
    assert!(
        matches!(row.state, rollout::RolloutState::Paused { .. }),
        "{row:?}"
    );
    // The release stays while its rollout is not over.
    assert!(releases::remove(&hub, "uid 0", &release.sha256).is_err());
    let resumed =
        ops::steer_rollout(&hub, "uid 0", &rollout.id, store::RolloutAction::Resume).unwrap();
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
        "1 already running it",
        "updated to vk 0.81.0",
        "paused: a node failed",
        "resumed rollout",
        "done: vk 0.81.0 on 1 node(s), 1 failed, 1 skipped",
    ] {
        assert!(
            events.iter().any(|e| e.contains(want)),
            "{want}: {events:?}"
        );
    }
    assert!(ops::steer_rollout(&hub, "uid 0", &rollout.id, store::RolloutAction::Pause).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A hub restarted mid-rollout carries on from its database, and a node the rollout still
/// has to update takes no update of an operator's meanwhile.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollout_survives_a_hub_restart() {
    let dir = std::env::temp_dir().join(format!("vk-hub-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("data").join("hub.db");
    let open =
        || Hub::new(Arc::new(Db::open(&db_path).unwrap())).with_releases(dir.join("releases"));
    let hub = open();
    std::fs::write(dir.join("vk"), fake_vk("0.81.0")).unwrap();
    let release = releases::add(&hub, "uid 0", &dir.join("vk"), "0.81.0", None).unwrap();
    let mut ids = Vec::new();
    for (name, key) in [("a", "k1"), ("b", "k2")] {
        let (token, _) = hub
            .db
            .create_token(Duration::from_secs(60), "uid 0", 0)
            .unwrap();
        let store::Enrollment::Enrolled { node_id } = hub.db.enroll(&token, key, name, 1).unwrap()
        else {
            panic!("expected an enrollment");
        };
        hub.db
            .record_report(
                &node_id,
                vk_fleet_proto::Report {
                    runner: vk_fleet_proto::RunnerMode::Managed,
                    ..vk_fleet_proto::Report::default()
                },
                2,
            )
            .unwrap();
        ids.push(node_id);
    }
    let plan = ops::RolloutPlan {
        release: release.sha256.clone(),
        nodes: ops::Selection::All,
        batch: 1,
        canary_per_profile: false,
        max_failures: 0,
        node_timeout_secs: 600,
        drain_timeout_secs: 600,
        force: false,
    };
    let rollout = ops::create_rollout(&hub, "uid 0", &plan).unwrap();
    let (_, issued) = hub.db.advance_rollout(&rollout.id, now_secs()).unwrap();
    assert_eq!(issued.len(), 1);
    let other = ids.iter().find(|id| **id != issued[0]).unwrap().clone();
    let err = ops::update(&hub, "uid 0", &other, &release.sha256, false).unwrap_err();
    assert!(format!("{err:#}").contains("rollout"), "{err:#}");
    // Nothing changed: nothing written.
    assert_eq!(
        hub.db.advance_rollout(&rollout.id, now_secs()).unwrap(),
        (false, vec![])
    );
    drop(hub);

    let hub = open();
    let first = &issued[0];
    let cmd = hub
        .db
        .pending_commands(first, now_secs())
        .unwrap()
        .remove(0);
    hub.db
        .record_ack(
            first,
            &vk_fleet_proto::CommandAck {
                id: cmd.id,
                outcome: vk_fleet_proto::Outcome::Done,
            },
            3,
        )
        .unwrap();
    let mut inventory = Inventory::default();
    inventory.versions.vk_sha256 = Some(release.sha256.clone());
    hub.db.record_inventory(first, inventory, 4).unwrap();
    assert_eq!(
        hub.db.advance_rollout(&rollout.id, now_secs()).unwrap().1,
        std::slice::from_ref(&other)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
