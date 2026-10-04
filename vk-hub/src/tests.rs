//! The hub end to end over real sockets — enrollment, the session handshake, what a session
//! records — plus the CLI's own parsing and rendering.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use ring::signature::{Ed25519KeyPair, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use vk_hub_proto::{
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
    let hub = Arc::new(Hub::new(Arc::new(Db::open_memory().unwrap()), None));
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
        .create_token(Duration::from_secs(60), now_secs())
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

type Client = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

async fn dial(addr: SocketAddr) -> Client {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let url = format!("ws://{addr}{}", vk_hub_proto::NODE_PATH);
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
    let nonce = vk_hub_proto::from_hex(&nonce).unwrap();
    assert_eq!(nonce.len(), vk_hub_proto::CHALLENGE_LEN);
    let signature = signer.sign(&vk_hub_proto::auth_message(
        &nonce,
        node_id,
        incarnation,
        PROTOCOL,
        versions,
        claimed_version.unwrap_or(version),
        vk_hub_proto::Channel::Plaintext,
    ));
    send(
        ws,
        &NodeMsg::Auth {
            signature: vk_hub_proto::to_hex(signature.as_ref()),
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
    assert!(hub.db.remove_node(&node_id).unwrap());
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
        "5é",
        "é",
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
        "LAST SEEN",
        "VK",
        "CPUS",
        "RAM",
        "ADMITTED",
        "VMS",
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
            ..ops::NodeView::default()
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
        ("VMS", "-"),
    ] {
        assert_eq!(cell(header, a, column), want, "{column}\n{table}");
    }
    for (column, want) in [("REACH", "unreachable"), ("LAST SEEN", "never")] {
        assert_eq!(cell(header, b, column), want, "{column}\n{table}");
    }
    assert_eq!(ago(10_000, 10_000 - 7300), Duration::from_secs(7200));
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
            workloads: Some(store::Workloads {
                listed: vec![job, dev, run],
                omitted: 2,
                mem_bytes: [("aaaa".to_string(), 3 << 30)].into(),
            }),
        },
        ops::NodeWorkloads {
            id: "b".repeat(32),
            hostname: "ci-2".into(),
            workloads: None,
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
}

/// `vk-hub workloads --node` takes an ID, or a hostname only one node has.
#[test]
fn workloads_are_selected_by_id_or_unambiguous_hostname() {
    let hub = Hub::new(Arc::new(Db::open_memory().unwrap()), None);
    let enroll = |host: &str| {
        let (token, _) = hub.db.create_token(Duration::from_secs(60), 1).unwrap();
        match hub.db.enroll(&token, &host.repeat(64), host, 1).unwrap() {
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
            2,
        )
        .unwrap();
    let ids = |sel: Option<&str>| -> Vec<String> {
        ops::workloads(&hub, sel)
            .unwrap()
            .into_iter()
            .map(|n| n.id)
            .collect()
    };
    assert_eq!(ids(Some("a")), [a]);
    assert_eq!(ids(Some(&b)), std::slice::from_ref(&b));
    assert_eq!(ids(None).len(), 3);
    let ambiguous = ops::workloads(&hub, Some("b")).unwrap_err();
    assert!(format!("{ambiguous}").contains("several"), "{ambiguous}");
    assert!(ops::workloads(&hub, Some("nope")).is_err());
    assert!(
        ops::workloads(&hub, None)
            .unwrap()
            .iter()
            .all(|n| n.workloads.is_none())
    );
}

#[test]
fn audit_times_are_utc() {
    assert_eq!(utc(0), "1970-01-01T00:00:00Z");
    assert_eq!(utc(951_782_400), "2000-02-29T00:00:00Z");
    assert_eq!(utc(1_790_755_279), "2026-09-30T08:01:19Z");
}
