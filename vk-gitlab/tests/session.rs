//! The relay's session against a fake hub speaking `/v1/gitlab/session`, as
//! `vk-hub/src/relays.rs` does: the shared handshake, then the relay's inventory, report and
//! heartbeats, the server's status and a refusal from the hub, and the hub's commands.

mod support;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use vk_gitlab::config::{Config, HubConfig};
use vk_gitlab::poll::ShutdownHandle;
use vk_gitlab::relay;
use vk_gitlab::session::{self, Status};
use vk_gitlab::update::Updater;
use vk_hub_proto::gitlab::{
    Command, HubRelayMsg, Operation, PROTOCOL, RELAY_PROTOCOL, RelayMsg, RunnerState, ServerState,
    ServerStatus, UPDATES,
};
use vk_hub_proto::{Channel, CommandAck, HubMsg, NodeMsg, Outcome, RefusalCode};
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

/// Hold the session of `relay`, enrolled in `state`, whose `[hub]` is `hub`.
fn hold(
    state: &Path,
    relay: Arc<relay::Relay>,
    status: &Arc<Status>,
    hub: HubConfig,
) -> tokio::task::JoinHandle<()> {
    let (handle, _shutdown) = ShutdownHandle::new();
    let updater = Updater::open(
        state,
        Arc::clone(&relay),
        hub,
        Arc::clone(status),
        Arc::new(handle),
    )
    .unwrap();
    tokio::spawn(session::hold(relay, Arc::clone(status), updater))
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
    let held = hold(&state, relay, &status, HubConfig::default());

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
            version: UPDATES,
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
        UPDATES,
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
    let (state, status, relay, _) = relay_with(listener, what, "");
    (state, status, relay)
}

/// [`relay_for`], with `hub` as its config's `[hub]` table, which it returns.
fn relay_with(
    listener: &TcpListener,
    what: &str,
    hub: &str,
) -> (
    std::path::PathBuf,
    Arc<Status>,
    Arc<relay::Relay>,
    HubConfig,
) {
    let url = format!("http://{}", listener.local_addr().unwrap());
    let state = temp_dir(what);
    enroll(&state, &url);
    let cfg = Config::parse(
        &format!(
            "concurrent = 3\n[gitlab]\nurl = \"https://gitlab.example.com/\"\n\
             [[runners]]\nname = \"ci\"\ntoken = \"glrt-x\"\npool = \"p1\"\n[hub]\n{hub}"
        ),
        Path::new("/"),
    )
    .unwrap();
    let status = Status::new(&cfg, "s_0123456789ab", "relay-host");
    let relay = Arc::new(relay::open(&state).unwrap());
    (state, status, relay, cfg.hub)
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
            version: UPDATES,
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
    let held = hold(&state, relay, &status, HubConfig::default());
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
    let held = hold(&state, relay, &status, HubConfig::default());
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

/// The relay's next ack of command `id`, past other messages.
async fn ack_of(ws: &mut Ws, id: &str) -> CommandAck {
    loop {
        if let RelayMsg::Ack(ack) = next_msg(ws).await
            && ack.id == id.repeat(32)
        {
            return ack;
        }
    }
}

fn update_command(id: &str, version: &str, expires_at: u64) -> HubRelayMsg {
    HubRelayMsg::Command(Command {
        id: id.repeat(32),
        expires_at,
        op: Operation::Update {
            version: version.to_owned(),
            sha256: "ab".repeat(32),
            size: 1,
            signature: None,
        },
    })
}

/// A relay says in its inventory whether the hub may update it; it refuses the commands its
/// `[hub]` does not take, answers each once, from its journal when sent again, and repeats an
/// answer until the hub has stored it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_hub_s_commands_are_answered_and_repeated_until_recorded() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (state, status, relay) = relay_for(&listener, "session-commands");
    let held = hold(&state, relay, &status, HubConfig::default());
    let mut ws = welcome(&listener).await;
    let far = vk_peer::now_secs() + 3600;
    send(&mut ws, &update_command("a", "99.0.0", far)).await;
    let ack = ack_of(&mut ws, "a").await;
    let Outcome::Refused { reason } = &ack.outcome else {
        panic!("{ack:?}");
    };
    assert!(
        reason.contains("[hub] allow does not list update"),
        "{reason}"
    );
    held.abort();
    std::fs::remove_dir_all(&state).unwrap();

    let (state, status, relay, hub) = relay_with(
        &listener,
        "session-commands-allowed",
        "allow = [\"update\"]\n",
    );
    let held = hold(&state, relay, &status, hub);
    let (mut ws, _) = hello(&listener).await;
    send(
        &mut ws,
        &HubMsg::Challenge {
            version: UPDATES,
            versions: PROTOCOL,
            nonce: vk_hub_proto::to_hex(&[7u8; vk_hub_proto::CHALLENGE_LEN]),
        },
    )
    .await;
    let NodeMsg::Auth { .. } = serde_json::from_str(&next(&mut ws).await).unwrap() else {
        panic!("not an auth");
    };
    send(&mut ws, &HubMsg::Welcome { heartbeat_secs: 1 }).await;
    let RelayMsg::Inventory(inventory) = next_msg(&mut ws).await else {
        panic!("not the inventory");
    };
    assert_eq!(inventory.allow, ["update"]);
    assert!(!inventory.requires_signed);
    assert!(matches!(next_msg(&mut ws).await, RelayMsg::Report(_)));

    // Expired, and older than the relay: refused.
    send(&mut ws, &update_command("b", "99.0.0", 1)).await;
    assert_eq!(ack_of(&mut ws, "b").await.outcome, Outcome::Expired);
    send(&mut ws, &update_command("c", "0.0.1", far)).await;
    let older = ack_of(&mut ws, "c").await;
    assert!(
        matches!(&older.outcome, Outcome::Refused { reason } if reason.contains("older")),
        "{older:?}"
    );
    // Sent again, it is answered from the journal, not run again.
    send(&mut ws, &update_command("c", "99.0.0", far)).await;
    assert_eq!(ack_of(&mut ws, "c").await, older);
    // Not recorded yet: repeated with the next change sent.
    status.runner("ci", |r| r.state = RunnerState::Unhealthy);
    assert_eq!(ack_of(&mut ws, "c").await, older);
    for id in ["b", "c"] {
        let outcome = if id == "b" {
            Outcome::Expired
        } else {
            older.outcome.clone()
        };
        send(
            &mut ws,
            &HubRelayMsg::Recorded(CommandAck {
                id: id.repeat(32),
                outcome,
            }),
        )
        .await;
    }
    // Recorded: a change sends the report, and no ack after it.
    tokio::time::sleep(Duration::from_millis(500)).await;
    status.runner("ci", |r| r.state = RunnerState::Polling);
    loop {
        match next_msg(&mut ws).await {
            RelayMsg::Report(r) if r.runners[0].state == RunnerState::Polling => break,
            RelayMsg::Ack(_) | RelayMsg::Report(_) | RelayMsg::Inventory(_) => {}
            other => panic!("{other:?}"),
        }
    }
    status.runner("ci", |r| r.state = RunnerState::Unhealthy);
    loop {
        match next_msg(&mut ws).await {
            RelayMsg::Report(r) if r.runners[0].state == RunnerState::Unhealthy => break,
            RelayMsg::Ack(ack) => panic!("repeated after it was recorded: {ack:?}"),
            _ => {}
        }
    }
    held.abort();
    std::fs::remove_dir_all(&state).unwrap();
}

/// A relay that is stopping takes no update: it would come back up on the release.
#[tokio::test]
async fn a_stopping_relay_takes_no_update() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (state, status, relay, hub) =
        relay_with(&listener, "session-stopping", "allow = [\"update\"]\n");
    let (handle, _shutdown) = ShutdownHandle::new();
    let handle = Arc::new(handle);
    let updater = Updater::open(&state, relay, hub, status, Arc::clone(&handle)).unwrap();
    handle.stop();
    let HubRelayMsg::Command(command) = update_command("d", "99.0.0", vk_peer::now_secs() + 3600)
    else {
        unreachable!();
    };
    let ack = updater.command(command).unwrap();
    assert_eq!(
        ack.outcome,
        Outcome::Refused {
            reason: "the relay is stopping".into()
        }
    );
    std::fs::remove_dir_all(&state).unwrap();
}

/// A hub from before updates, which meets the relay at version 2, is sent no ack: it could not
/// read one. The relay keeps it for a hub that can.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hub_from_before_updates_hears_no_ack() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (state, status, relay, hub) =
        relay_with(&listener, "session-old-hub", "allow = [\"update\"]\n");
    // An answer the hub has not stored: an expired command, journaled.
    let (handle, _shutdown) = ShutdownHandle::new();
    let journal = Updater::open(
        &state,
        Arc::clone(&relay),
        hub.clone(),
        Arc::clone(&status),
        Arc::new(handle),
    )
    .unwrap();
    let HubRelayMsg::Command(command) = update_command("e", "99.0.0", 1) else {
        unreachable!();
    };
    assert_eq!(journal.command(command).unwrap().outcome, Outcome::Expired);
    drop(journal);

    let held = hold(&state, relay, &status, hub);
    let (mut ws, _) = hello(&listener).await;
    send(
        &mut ws,
        &HubMsg::Challenge {
            version: 2,
            versions: vk_hub_proto::VersionRange { min: 1, max: 2 },
            nonce: vk_hub_proto::to_hex(&[7u8; vk_hub_proto::CHALLENGE_LEN]),
        },
    )
    .await;
    let NodeMsg::Auth { .. } = serde_json::from_str(&next(&mut ws).await).unwrap() else {
        panic!("not an auth");
    };
    send(&mut ws, &HubMsg::Welcome { heartbeat_secs: 1 }).await;
    status.runner("ci", |r| r.state = RunnerState::Unhealthy);
    loop {
        match next_msg(&mut ws).await {
            RelayMsg::Report(r) if r.runners[0].state == RunnerState::Unhealthy => break,
            RelayMsg::Ack(ack) => panic!("an ack to a version-2 hub: {ack:?}"),
            _ => {}
        }
    }
    // Nor does it take a command there: the session ends.
    send(&mut ws, &update_command("v2", "99.0.0", u64::MAX)).await;
    let ended = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match ws.next().await {
                None | Some(Err(_) | Ok(Message::Close(_))) => break,
                Some(Ok(Message::Text(t))) => {
                    assert!(!t.as_str().contains("\"ack\""), "an ack: {t}")
                }
                Some(Ok(_)) => {}
            }
        }
    });
    ended.await.expect("the session did not end");
    held.abort();

    // A hub that speaks updates hears it.
    let held = {
        let (_, status, relay, hub) = (
            (),
            Arc::clone(&status),
            Arc::new(relay::open(&state).unwrap()),
            HubConfig {
                allow: vec!["update".into()],
                ..HubConfig::default()
            },
        );
        hold(&state, relay, &status, hub)
    };
    let mut ws = welcome(&listener).await;
    assert_eq!(ack_of(&mut ws, "e").await.outcome, Outcome::Expired);
    held.abort();
    std::fs::remove_dir_all(&state).unwrap();
}

/// An update state that cannot be read does not keep the relay from running: it takes no
/// update, and leaves the file as it is.
#[tokio::test]
async fn an_unreadable_update_state_refuses_updates_only() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (state, status, relay, hub) =
        relay_with(&listener, "session-corrupt", "allow = [\"update\"]\n");
    let file = relay::dir(&state).join("update.json");
    std::fs::write(&file, b"{ not json").unwrap();
    let (handle, _shutdown) = ShutdownHandle::new();
    let updater = Updater::open(&state, relay, hub, status, Arc::new(handle)).unwrap();
    let HubRelayMsg::Command(command) = update_command("f", "99.0.0", vk_peer::now_secs() + 3600)
    else {
        unreachable!();
    };
    let ack = updater.command(command).unwrap();
    assert!(
        matches!(&ack.outcome, Outcome::Refused { reason } if reason.contains("update state cannot be used")),
        "{ack:?}"
    );
    // The hub's record of that answer is not kept either.
    updater.recorded(&ack).unwrap();
    assert_eq!(std::fs::read(&file).unwrap(), b"{ not json");
    std::fs::remove_dir_all(&state).unwrap();
}
