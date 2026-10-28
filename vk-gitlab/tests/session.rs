//! The relay's session against a fake hub speaking `/v1/gitlab/session`, as
//! `vk-hub/src/relays.rs` does: the shared handshake, then the relay's inventory, report and
//! heartbeats, and the server's status and a refusal from the hub.

mod support;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use vk_gitlab::config::Config;
use vk_gitlab::relay;
use vk_gitlab::session::{self, Status};
use vk_hub_proto::gitlab::{
    HubRelayMsg, PROTOCOL, RELAY_PROTOCOL, RelayMsg, RunnerState, ServerState, ServerStatus,
};
use vk_hub_proto::{Channel, HubMsg, NodeMsg, RefusalCode};
use vk_peer::identity::Identity;

use support::gl::{eventually, temp_dir, within};

const RELAY_ID: &str = "fedcba9876543210fedcba9876543210";

type Ws = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

/// Read the relay's next text frame and ping while waiting, as a hub does. The relay
/// disconnects after three silent 1s heartbeat intervals, which a loaded host can
/// spend between frames.
async fn next(ws: &mut Ws) -> String {
    let mut ping = tokio::time::interval(std::time::Duration::from_millis(500));
    within("a frame from the relay", async {
        loop {
            tokio::select! {
                frame = ws.next() => match frame {
                    Some(Ok(Message::Text(t))) => return t.as_str().to_owned(),
                    Some(Ok(_)) => {}
                    other => panic!("the relay ended the session: {other:?}"),
                },
                _ = ping.tick() => ws.send(Message::Ping(Vec::new().into())).await.unwrap(),
            }
        }
    })
    .await
}

async fn send(ws: &mut Ws, msg: &impl serde::Serialize) {
    ws.send(Message::text(serde_json::to_string(msg).unwrap()))
        .await
        .unwrap();
}

/// The relay's next message past heartbeats.
async fn next_msg(ws: &mut Ws) -> RelayMsg {
    loop {
        match serde_json::from_str(&next(ws).await).unwrap() {
            RelayMsg::Heartbeat(_) => {}
            msg => return msg,
        }
    }
}

fn enroll(state: &Path, hub: &str) -> Vec<u8> {
    let dir = relay::dir(state);
    vk_peer::net::create_dir(&dir).unwrap();
    let identity = Identity::load_or_create(&dir).unwrap();
    std::fs::write(
        dir.join("enrollment.json"),
        format!(r#"{{"hub":"{hub}","relay_id":"{RELAY_ID}"}}"#),
    )
    .unwrap();
    identity.public_key().to_vec()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_reports_the_relay_and_takes_the_servers_status() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hub = format!("http://{}", listener.local_addr().unwrap());
    let state = temp_dir("session");
    let key = enroll(&state, &hub);
    let cfg = Config::parse(
        "concurrent = 3\n[gitlab]\nurl = \"https://gitlab.example.com/\"\n\
         [[runners]]\nname = \"ci\"\ntoken = \"glrt-SECRET\"\npool = \"p1\"\nlimit = 2\n",
        Path::new("/"),
    )
    .unwrap();
    let status = Status::new(&cfg, "s_0123456789ab", "relay-host");
    let relay = Arc::new(relay::open(&state).unwrap());
    let held = tokio::spawn(session::hold(relay, Arc::clone(&status)));

    let (tcp, _) = within("the relay to dial", listener.accept())
        .await
        .unwrap();
    let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
    let NodeMsg::Hello {
        versions,
        node_id,
        incarnation,
        vk_version,
    } = serde_json::from_str(&next(&mut ws).await).unwrap()
    else {
        panic!("not a hello");
    };
    assert_eq!((node_id.as_str(), versions), (RELAY_ID, RELAY_PROTOCOL));
    assert_eq!(vk_version, env!("CARGO_PKG_VERSION"));
    let nonce = [7u8; vk_hub_proto::CHALLENGE_LEN];
    send(
        &mut ws,
        &HubMsg::Challenge {
            version: 2,
            versions: PROTOCOL,
            nonce: vk_hub_proto::to_hex(&nonce),
        },
    )
    .await;
    let NodeMsg::Auth { signature } = serde_json::from_str(&next(&mut ws).await).unwrap() else {
        panic!("not an auth");
    };
    let message = vk_hub_proto::auth_message(
        &nonce,
        RELAY_ID,
        &incarnation,
        RELAY_PROTOCOL,
        PROTOCOL,
        2,
        Channel::Plaintext,
    );
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &key)
        .verify(&message, &vk_hub_proto::from_hex(&signature).unwrap())
        .expect("the auth is signed by the relay's key");
    send(&mut ws, &HubMsg::Welcome { heartbeat_secs: 1 }).await;

    let RelayMsg::Inventory(inventory) = next_msg(&mut ws).await else {
        panic!("not the inventory");
    };
    assert_eq!(inventory.server.url, "https://gitlab.example.com");
    assert_eq!(
        (inventory.hostname.as_str(), inventory.system_id.as_str()),
        ("relay-host", "s_0123456789ab")
    );
    assert_eq!(inventory.concurrent, 3);
    let runner = &inventory.runners[0];
    assert_eq!((runner.name.as_str(), runner.limit), ("ci", Some(2)));
    assert_eq!(runner.placement.pool, "p1");
    let json = serde_json::to_string(&inventory).unwrap();
    assert!(!json.contains("SECRET"), "{json}");
    let RelayMsg::Report(report) = next_msg(&mut ws).await else {
        panic!("not the report");
    };
    assert_eq!(report.runners[0].state, RunnerState::ServerPending);

    // The server's status is taken; a change of a runner's is reported.
    let approved = ServerStatus {
        state: ServerState::Approved,
        url: "https://gitlab.example.com".to_owned(),
        name: Some("gl".to_owned()),
    };
    send(&mut ws, &HubRelayMsg::Server(approved.clone())).await;
    eventually("the server approved", || status.approved()).await;
    status.runner("ci", |r| {
        r.state = RunnerState::Polling;
        r.runner.runner_id = Some(42);
    });
    let RelayMsg::Inventory(inventory) = next_msg(&mut ws).await else {
        panic!("not the inventory");
    };
    assert_eq!(inventory.runners[0].runner_id, Some(42));
    let RelayMsg::Report(report) = next_msg(&mut ws).await else {
        panic!("not the report");
    };
    assert_eq!(report.runners[0].state, RunnerState::Polling);
    let mut beats = 0;
    while beats == 0 {
        if let RelayMsg::Heartbeat(h) = serde_json::from_str(&next(&mut ws).await).unwrap() {
            assert_eq!(h.runners[0].name, "ci");
            beats += 1;
        }
    }

    // A relay the hub removed stops for good, and polls nothing.
    send(
        &mut ws,
        &HubRelayMsg::Refused {
            code: RefusalCode::Revoked,
            reason: "removed".to_owned(),
        },
    )
    .await;
    within("the session to end", held).await.unwrap();
    assert_eq!(status.server(), None);
    assert!(!status.approved());
    std::fs::remove_dir_all(&state).unwrap();
}

/// A relay of one runner, `ci`, dialing the hub `listener` is.
fn relay_for(
    listener: &TcpListener,
    what: &str,
) -> (std::path::PathBuf, Arc<Status>, Arc<relay::Relay>) {
    let hub = format!("http://{}", listener.local_addr().unwrap());
    let state = temp_dir(what);
    enroll(&state, &hub);
    let cfg = Config::parse(
        "concurrent = 3\n[gitlab]\nurl = \"https://gitlab.example.com/\"\n\
         [[runners]]\nname = \"ci\"\ntoken = \"glrt-x\"\npool = \"p1\"\n",
        Path::new("/"),
    )
    .unwrap();
    let status = Status::new(&cfg, "s_0123456789ab", "relay-host");
    let relay = Arc::new(relay::open(&state).unwrap());
    (state, status, relay)
}

/// Takes the relay's dial and hello; the hub's answer is the caller's.
async fn hello(listener: &TcpListener) -> (Ws, String) {
    let (tcp, _) = within("the relay to dial", listener.accept())
        .await
        .unwrap();
    let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
    let NodeMsg::Hello { incarnation, .. } = serde_json::from_str(&next(&mut ws).await).unwrap()
    else {
        panic!("not a hello");
    };
    (ws, incarnation)
}

/// Takes the relay into a session, unchecked, and its first inventory and report.
async fn welcome(listener: &TcpListener) -> Ws {
    let (mut ws, _) = hello(listener).await;
    send(
        &mut ws,
        &HubMsg::Challenge {
            version: 2,
            versions: PROTOCOL,
            nonce: vk_hub_proto::to_hex(&[7u8; vk_hub_proto::CHALLENGE_LEN]),
        },
    )
    .await;
    let NodeMsg::Auth { .. } = serde_json::from_str(&next(&mut ws).await).unwrap() else {
        panic!("not an auth");
    };
    send(&mut ws, &HubMsg::Welcome { heartbeat_secs: 1 }).await;
    assert!(matches!(next_msg(&mut ws).await, RelayMsg::Inventory(_)));
    assert!(matches!(next_msg(&mut ws).await, RelayMsg::Report(_)));
    ws
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hub_of_another_protocol_is_dialed_again_not_given_up() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (state, status, relay) = relay_for(&listener, "session-version");
    status.set_server(Some(ServerStatus {
        state: ServerState::Approved,
        url: "https://gitlab.example.com".to_owned(),
        name: Some("gl".to_owned()),
    }));
    let held = tokio::spawn(session::hold(relay, Arc::clone(&status)));
    let (mut ws, _) = hello(&listener).await;
    send(
        &mut ws,
        &HubMsg::Refused {
            code: RefusalCode::Version,
            reason: "no common protocol version".to_owned(),
        },
    )
    .await;
    // Not taking jobs the hub would refuse, but redialing, for an upgraded hub.
    eventually("the server forgotten", || !status.approved()).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !held.is_finished(),
        "a version refusal ended the relay's sessions for good"
    );
    held.abort();
    std::fs::remove_dir_all(&state).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_burst_of_changes_goes_out_coalesced_while_the_hub_pings() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (state, status, relay) = relay_for(&listener, "session-burst");
    let held = tokio::spawn(session::hold(relay, Arc::clone(&status)));
    let mut ws = welcome(&listener).await;
    // A change every few milliseconds for two seconds, ending with one admission listed.
    let burst = {
        let status = Arc::clone(&status);
        tokio::spawn(async move {
            for n in 0..400u32 {
                status.runner("ci", |r| r.requests = n % 2);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            status.runner("ci", |r| {
                r.requests = 1;
                r.request_admissions = vec!["a".repeat(32)];
            });
        })
    };
    // `next` pings the relay while it waits, as the hub does.
    let started = std::time::Instant::now();
    let mut beats = 0u64;
    while !burst.is_finished() {
        if let RelayMsg::Heartbeat(_) = serde_json::from_str(&next(&mut ws).await).unwrap() {
            beats += 1;
        }
    }
    // One a second, and one per 250 ms coalescing window: not one per change.
    let bound = 6 * started.elapsed().as_secs() + 6;
    assert!(
        beats <= bound,
        "{beats} heartbeats for 400 changes, past {bound}"
    );
    // The change that ended the burst is sent.
    loop {
        if let RelayMsg::Heartbeat(h) = serde_json::from_str(&next(&mut ws).await).unwrap()
            && h.runners[0].request_admissions == ["a".repeat(32)]
        {
            assert_eq!(h.runners[0].requests, 1);
            break;
        }
    }
    assert!(!held.is_finished(), "the session ended during the burst");
    held.abort();
    std::fs::remove_dir_all(&state).unwrap();
}
