//! Registry enrollment with registry tokens, the shared handshake, reporting, steering,
//! commands, updates restricted to `vk-registry` releases, and removal.

use vk_hub_proto::registry::{
    self as reg, GcPolicy, HubRegistryMsg, Inventory, Operation, RegistryMsg, Report,
};
use vk_hub_proto::{CommandAck, Outcome, RefusalCode};

use super::*;
use crate::registries;
use crate::store::TokenKind;

fn registry_token(hub: &Hub) -> String {
    hub.db
        .create_token_for(
            TokenKind::Registry,
            Duration::from_secs(60),
            None,
            "uid 0",
            now_secs(),
        )
        .unwrap()
        .0
}

/// `POST <path>` with `body`, by hand: the status and the body.
async fn post(addr: SocketAddr, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: hub\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
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

fn ask(token: &str, key: &Ed25519KeyPair) -> Vec<u8> {
    let public_key = key.public_key().as_ref();
    serde_json::to_vec(&EnrollRequest {
        token: token.to_string(),
        public_key: vk_hub_proto::to_hex(public_key),
        signature: vk_hub_proto::to_hex(
            key.sign(&vk_hub_proto::enroll_message(token, public_key))
                .as_ref(),
        ),
        hostname: "reg-1".into(),
    })
    .unwrap()
}

async fn enrolled_registry(addr: SocketAddr, hub: &Hub, key: &Ed25519KeyPair) -> String {
    let (status, body) = post(addr, reg::ENROLL_PATH, &ask(&registry_token(hub), key)).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    serde_json::from_slice::<reg::EnrollResponse>(&body)
        .unwrap()
        .registry_id
}

async fn dial_registry(addr: SocketAddr) -> Client {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let url = format!("ws://{addr}{}", reg::SESSION_PATH);
    tokio_tungstenite::client_async(url, Box::new(stream) as Box<dyn server::Stream>)
        .await
        .unwrap()
        .0
}

/// Hello, challenge and auth as a registry; what the hub answered.
async fn open_registry(ws: &mut Client, id: &str, key: &Ed25519KeyPair) -> HubMsg {
    send(ws, &hello(id, &"1".repeat(32), reg::PROTOCOL)).await;
    let HubMsg::Challenge {
        version,
        versions,
        nonce,
    } = receive(ws).await
    else {
        panic!("expected a challenge");
    };
    assert_eq!((version, versions), (1, reg::PROTOCOL));
    let nonce = vk_hub_proto::from_hex(&nonce).unwrap();
    let signature = key.sign(&vk_hub_proto::auth_message(
        &nonce,
        id,
        &"1".repeat(32),
        reg::PROTOCOL,
        versions,
        version,
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

/// A registry's session, welcomed.
async fn session(addr: SocketAddr, id: &str, key: &Ed25519KeyPair) -> Client {
    let mut ws = dial_registry(addr).await;
    assert!(matches!(
        open_registry(&mut ws, id, key).await,
        HubMsg::Welcome { .. }
    ));
    ws
}

/// The code of the refusal that ends the session, past what came before it.
async fn refusal(ws: &mut Client) -> RefusalCode {
    loop {
        match tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .unwrap()
        {
            Some(Ok(Message::Text(t))) => {
                if let Ok(HubRegistryMsg::Refused { code, .. }) = serde_json::from_str(t.as_str()) {
                    return code;
                }
            }
            Some(Ok(_)) => {}
            _ => panic!("the session ended without a refusal"),
        }
    }
}

/// Hear nothing but pings for a second.
async fn quiet(ws: &mut Client) {
    let heard = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                other => return other,
            }
        }
    })
    .await;
    assert!(heard.is_err(), "heard {heard:?}");
}

async fn tell(ws: &mut Client, msg: &RegistryMsg) {
    ws.send(Message::text(serde_json::to_string(msg).unwrap()))
        .await
        .unwrap();
}

async fn hear(ws: &mut Client) -> HubRegistryMsg {
    loop {
        match tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
        {
            Message::Text(t) => return serde_json::from_str(t.as_str()).unwrap(),
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("unexpected frame {other:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_registry_enrolls_with_a_registry_token_only() {
    let (addr, hub) = start().await;
    let key = keypair();
    // A node's token does not enroll a registry, and is not spent by trying.
    let node_token = token(&hub);
    let (status, _) = post(addr, reg::ENROLL_PATH, &ask(&node_token, &key)).await;
    assert_eq!(status, 403);
    // Nor a registry's a node.
    let registry = registry_token(&hub);
    let (status, _) = enroll(addr, &registry, &key).await;
    assert_eq!(status, 403);
    let (status, body) = post(addr, reg::ENROLL_PATH, &ask(&registry, &key)).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let id = serde_json::from_slice::<reg::EnrollResponse>(&body)
        .unwrap()
        .registry_id;
    // Spent.
    let (status, _) = post(addr, reg::ENROLL_PATH, &ask(&registry, &key)).await;
    assert_eq!(status, 403);
    // The same key with a new token is the same registry.
    assert_eq!(enrolled_registry(addr, &hub, &key).await, id);
    assert_eq!(hub.db.registry(&id).unwrap().unwrap().hostname, "reg-1");
    assert!(hub.db.node(&id).unwrap().is_none());
    // The node token still enrolls a node.
    let (status, _) = enroll(addr, &node_token, &keypair()).await;
    assert_eq!(status, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_registry_reports_and_is_steered_over_its_session() {
    let (addr, hub) = start().await;
    let key = keypair();
    let id = enrolled_registry(addr, &hub, &key).await;

    // A node's session is not a registry's, nor the reverse.
    let mut ws = dial(addr).await;
    send(&mut ws, &hello(&id, &"2".repeat(32), PROTOCOL)).await;
    let HubMsg::Refused { code, .. } = receive(&mut ws).await else {
        panic!("a registry opened a node's session");
    };
    assert_eq!(code, RefusalCode::NotEnrolled);

    let mut ws = dial_registry(addr).await;
    assert!(matches!(
        open_registry(&mut ws, &id, &key).await,
        HubMsg::Welcome { .. }
    ));
    let inventory = Inventory {
        hostname: "reg-1".into(),
        version: "0.88.0".into(),
        mode: "accounts".into(),
        allow: vec![reg::ALLOW_READ_ONLY.into(), reg::ALLOW_GC.into()],
        ..Inventory::default()
    };
    tell(&mut ws, &RegistryMsg::Inventory(inventory.clone())).await;
    tell(&mut ws, &RegistryMsg::Report(Report::default())).await;
    eventually(|| {
        hub.db
            .registry(&id)
            .unwrap()
            .is_some_and(|r| r.inventory.as_ref() == Some(&inventory) && r.report.is_some())
    })
    .await;
    assert!(registries::views(&hub).unwrap()[0].connected);

    // Desired state reaches it once set.
    registries::read_only(&hub, "uid 0", &id, Some(true)).unwrap();
    let HubRegistryMsg::Desired(desired) = hear(&mut ws).await else {
        panic!("expected desired state");
    };
    assert_eq!(desired.read_only, Some(true));
    let schedule = GcPolicy {
        every_secs: 86_400,
        retention_days: 30,
        grace_days: 1,
    };
    assert!(
        registries::gc_schedule(
            &hub,
            "uid 0",
            &id,
            Some(GcPolicy {
                every_secs: 60,
                ..schedule
            })
        )
        .is_err()
    );
    registries::gc_schedule(&hub, "uid 0", &id, Some(schedule)).unwrap();
    let HubRegistryMsg::Desired(desired) = hear(&mut ws).await else {
        panic!("expected desired state");
    };
    assert_eq!(
        (desired.read_only, desired.gc),
        (Some(true), Some(schedule))
    );
    tell(
        &mut ws,
        &RegistryMsg::Report(Report {
            applied: Some(desired.generation),
            read_only: true,
            gc: Some(schedule),
            ..Report::default()
        }),
    )
    .await;

    // A command, its ack recorded and answered.
    let command = registries::gc(&hub, "uid 0", &id, 30, 1, true).unwrap();
    let HubRegistryMsg::Command(sent) = hear(&mut ws).await else {
        panic!("expected a command");
    };
    assert_eq!(sent, command);
    let ack = CommandAck {
        id: command.id.clone(),
        outcome: Outcome::Done,
    };
    tell(&mut ws, &RegistryMsg::Ack(ack.clone())).await;
    assert_eq!(hear(&mut ws).await, HubRegistryMsg::Recorded(ack));
    eventually(|| hub.db.registry_commands(&id).unwrap()[0].outcome == Some(Outcome::Done)).await;

    // An unknown release is refused.
    let err = registries::update(&hub, "uid 0", &id, "abcdabcd").unwrap_err();
    assert!(format!("{err:#}").contains("no release"), "{err:#}");

    // Removed: its session ends, refused.
    assert!(registries::remove(&hub, "uid 0", &id).unwrap());
    assert_eq!(refusal(&mut ws).await, RefusalCode::Revoked);
    let audit = hub.db.audits(Some(&id), 50).unwrap();
    assert!(
        audit.iter().any(|a| a.event.contains("removed registry")),
        "{audit:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_registry_downloads_only_the_vk_registry_release_it_updates_to() {
    let (dir, addr, hub) = start_releases("registry-release", None).await;
    let key = keypair();
    let id = enrolled_registry(addr, &hub, &key).await;
    let vk = add_release(&hub, &dir, &fake_vk("0.89.0"), "0.89.0").unwrap();
    let file = dir.join("vk-registry");
    std::fs::write(&file, fake_vk("0.90.0")).unwrap();
    let release = releases::add(&hub, "uid 0", &file, Some("vk-registry"), "0.90.0", None).unwrap();
    assert_eq!(release.row.program(), "vk-registry");

    // Nodes do not update to it, nor registries to a vk.
    let node = enrolled(addr, &hub, &keypair()).await;
    assert!(crate::ops::update(&hub, "uid 0", &node, &release.sha256, false).is_err());
    assert!(crate::ops::plan_rollout(&hub, &rollout_plan(&release.sha256, false, 0)).is_err());
    assert!(registries::update(&hub, "uid 0", &id, &vk.sha256).is_err());

    let headers = |sha: &str| {
        let digest = vk_hub_proto::from_hex_lower::<{ vk_hub_proto::SHA256_LEN }>(sha).unwrap();
        let at = now_secs();
        let message =
            vk_hub_proto::download_message(&id, &digest, at, vk_hub_proto::Channel::Plaintext);
        vec![
            (reg::REGISTRY_HEADER, id.clone()),
            (vk_hub_proto::TIME_HEADER, at.to_string()),
            (
                vk_hub_proto::SIGNATURE_HEADER,
                vk_hub_proto::to_hex(key.sign(&message).as_ref()),
            ),
        ]
    };
    let path = format!("{}{}", reg::RELEASE_PATH, release.sha256);
    // Not before an update to it is under way.
    let (status, _) = get_with(addr, &path, &headers(&release.sha256)).await;
    assert_eq!(status, 403);
    let command = registries::update(&hub, "uid 0", &id, &release.sha256[..8]).unwrap();
    assert!(
        matches!(command.op, Operation::Update { ref sha256, .. } if *sha256 == release.sha256)
    );
    let (status, body) = get_with(addr, &path, &headers(&release.sha256)).await;
    assert_eq!(status, 200);
    assert_eq!(body, fake_vk("0.90.0"));
    // A node's path does not serve it to a registry, nor is it removed under the update.
    let (status, _) = get_with(
        addr,
        &format!("{}{}", vk_hub_proto::RELEASE_PATH, release.sha256),
        &headers(&release.sha256),
    )
    .await;
    assert_eq!(status, 401);
    assert!(releases::remove(&hub, "uid 0", &release.sha256).is_err());
    // A second update waits for the first.
    assert!(registries::update(&hub, "uid 0", &id, &release.sha256).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn what_a_registry_says_is_stored_display_safe() {
    let (addr, hub) = start().await;
    let key = keypair();
    let id = enrolled_registry(addr, &hub, &key).await;
    let mut ws = session(addr, &id, &key).await;
    let inventory = Inventory {
        hostname: "reg\u{1b}[2J".into(),
        version: "1\u{202e}".into(),
        upstreams: vec!["u\n".into(); reg::MAX_NAMES + 1],
        ..Inventory::default()
    };
    tell(&mut ws, &RegistryMsg::Inventory(inventory)).await;
    let report = Report {
        last_gc: Some(reg::GcRun {
            command: Some("not an id".into()),
            error: Some("e\u{7}".into()),
            ..reg::GcRun::default()
        }),
        refused: vec!["gc\r".into()],
        ..Report::default()
    };
    tell(&mut ws, &RegistryMsg::Report(report)).await;
    eventually(|| {
        hub.db
            .registry(&id)
            .unwrap()
            .is_some_and(|r| r.report.is_some())
    })
    .await;
    let row = hub.db.registry(&id).unwrap().unwrap();
    assert_eq!(row.hostname, "reg[2J");
    let inventory = row.inventory.unwrap();
    assert_eq!(inventory.version, "1");
    assert_eq!(inventory.upstreams, vec!["u".to_string(); reg::MAX_NAMES]);
    let report = row.report.unwrap();
    let gc = report.last_gc.unwrap();
    assert_eq!((gc.command, gc.error.as_deref()), (None, Some("e")));
    assert_eq!(report.refused, vec!["gc".to_string()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_session_supersedes_the_first() {
    let (addr, hub) = start().await;
    let key = keypair();
    let id = enrolled_registry(addr, &hub, &key).await;
    let mut first = session(addr, &id, &key).await;
    let _second = session(addr, &id, &key).await;
    assert_eq!(refusal(&mut first).await, RefusalCode::Superseded);
}

#[tokio::test(flavor = "multi_thread")]
async fn commands_wait_for_a_report_and_go_once_per_session() {
    let (addr, hub) = start().await;
    let key = keypair();
    let id = enrolled_registry(addr, &hub, &key).await;
    let mut ws = session(addr, &id, &key).await;
    tell(&mut ws, &RegistryMsg::Inventory(Inventory::default())).await;
    let command = registries::gc(&hub, "uid 0", &id, 30, 1, false).unwrap();
    // Nothing before its first report.
    quiet(&mut ws).await;
    tell(&mut ws, &RegistryMsg::Report(Report::default())).await;
    assert_eq!(
        hear(&mut ws).await,
        HubRegistryMsg::Command(command.clone())
    );
    // A later sync sends the new desired state, not the command again.
    registries::read_only(&hub, "uid 0", &id, Some(true)).unwrap();
    let HubRegistryMsg::Desired(desired) = hear(&mut ws).await else {
        panic!("expected desired state");
    };
    let applied = Report {
        applied: Some(desired.generation),
        read_only: true,
        ..Report::default()
    };
    tell(&mut ws, &RegistryMsg::Report(applied.clone())).await;
    quiet(&mut ws).await;
    // Asking again what it already asks changes nothing.
    assert_eq!(
        registries::read_only(&hub, "uid 0", &id, Some(true)).unwrap(),
        None
    );
    // Unacknowledged, it goes again in the next session.
    drop(ws);
    let mut ws = session(addr, &id, &key).await;
    tell(&mut ws, &RegistryMsg::Report(applied)).await;
    assert_eq!(hear(&mut ws).await, HubRegistryMsg::Command(command));
}

fn db_registry(hub: &Hub) -> String {
    let crate::store::RegistryEnrollment::Enrolled { id } = hub
        .db
        .enroll_registry(&registry_token(hub), "aa", "reg-1", "peer p", 1)
        .unwrap()
    else {
        panic!("expected an enrollment");
    };
    id
}

#[tokio::test(flavor = "multi_thread")]
async fn commands_issued_in_one_second_keep_their_order() {
    let (_, hub) = start().await;
    let id = db_registry(&hub);
    let issued: Vec<String> = (1..=5)
        .map(|days| {
            let op = Operation::Gc {
                retention_days: days,
                grace_days: 1,
                dry_run: true,
            };
            hub.db
                .issue_registry_command(&id, op, Duration::from_secs(60), "uid 0", 100)
                .unwrap()
                .id
        })
        .collect();
    let listed: Vec<String> = hub
        .db
        .registry_commands(&id)
        .unwrap()
        .into_iter()
        .map(|r| r.command.id)
        .collect();
    assert_eq!(listed, issued);
}

/// An update the registry took but no longer reports running holds up no other.
#[tokio::test(flavor = "multi_thread")]
async fn a_stuck_update_does_not_block_the_next() {
    use vk_hub_proto::{UpdatePhase, UpdateProgress};
    let (_, hub) = start().await;
    let id = db_registry(&hub);
    let update = || Operation::Update {
        version: "0.90.0".into(),
        sha256: "ab".repeat(32),
        size: 1,
        signature: None,
    };
    let issue = || {
        hub.db
            .issue_registry_command(&id, update(), Duration::from_secs(60), "uid 0", 100)
    };
    let first = issue().unwrap();
    // Not taken yet: it blocks.
    assert!(issue().is_err());
    let accepted = CommandAck {
        id: first.id.clone(),
        outcome: Outcome::Accepted,
    };
    assert!(hub.db.record_registry_ack(&id, &accepted, 100).unwrap());
    let report = |phase: Option<UpdatePhase>| Report {
        update: phase.map(|phase| UpdateProgress {
            command: first.id.clone(),
            version: "0.90.0".into(),
            sha256: "ab".repeat(32),
            phase,
            message: None,
        }),
        ..Report::default()
    };
    let write = |r: Report| {
        hub.db
            .record_registry(&id, crate::store::RegistryWrite::Report(r), 100)
            .unwrap()
    };
    // Taken and reported running: it blocks.
    write(report(Some(UpdatePhase::Downloading)));
    assert!(issue().is_err());
    // Taken, then no longer reported: the next goes ahead.
    write(report(None));
    issue().unwrap();
}

/// An update the registry took but no longer reports when it opens a session is settled: it
/// goes no more and no longer holds its release.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_lost_by_the_registry_is_settled() {
    use vk_hub_proto::{UpdatePhase, UpdateProgress};
    let (dir, addr, hub) = start_releases("registry-lost-update", None).await;
    let key = keypair();
    let id = enrolled_registry(addr, &hub, &key).await;
    let file = dir.join("vk-registry");
    std::fs::write(&file, fake_vk("0.90.0")).unwrap();
    let release = releases::add(&hub, "uid 0", &file, Some("vk-registry"), "0.90.0", None).unwrap();
    let command = registries::update(&hub, "uid 0", &id, &release.sha256).unwrap();
    let running = Report {
        update: Some(UpdateProgress {
            command: command.id.clone(),
            version: "0.90.0".into(),
            sha256: release.sha256.clone(),
            phase: UpdatePhase::Downloading,
            message: None,
        }),
        ..Report::default()
    };

    let mut ws = session(addr, &id, &key).await;
    tell(&mut ws, &RegistryMsg::Report(Report::default())).await;
    assert_eq!(
        hear(&mut ws).await,
        HubRegistryMsg::Command(command.clone())
    );
    let accepted = CommandAck {
        id: command.id.clone(),
        outcome: Outcome::Accepted,
    };
    tell(&mut ws, &RegistryMsg::Ack(accepted.clone())).await;
    assert_eq!(hear(&mut ws).await, HubRegistryMsg::Recorded(accepted));
    // A later report not naming it yet settles nothing: the update may not have started.
    tell(&mut ws, &RegistryMsg::Report(Report::default())).await;
    quiet(&mut ws).await;
    assert_eq!(
        hub.db.registry_commands(&id).unwrap()[0].outcome,
        Some(Outcome::Accepted)
    );
    drop(ws);

    // A session opening on it running keeps it.
    let mut ws = session(addr, &id, &key).await;
    tell(&mut ws, &RegistryMsg::Report(running)).await;
    assert_eq!(
        hear(&mut ws).await,
        HubRegistryMsg::Command(command.clone())
    );
    assert!(releases::remove(&hub, "uid 0", &release.sha256).is_err());
    drop(ws);

    // One opening without it settles it.
    let mut ws = session(addr, &id, &key).await;
    tell(&mut ws, &RegistryMsg::Report(Report::default())).await;
    quiet(&mut ws).await;
    assert!(matches!(
        hub.db.registry_commands(&id).unwrap()[0].outcome,
        Some(Outcome::Failed { .. })
    ));
    let audit = hub.db.audits(Some(&id), 50).unwrap();
    assert!(
        audit
            .iter()
            .any(|a| a.event.contains("no longer reports this update")),
        "{audit:?}"
    );
    releases::remove(&hub, "uid 0", &release.sha256).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
