//! GitLab relay enrollment with relay tokens, the shared handshake, reporting, the status of
//! the relay's server as an operator approves it, and removal.

use vk_hub_proto::RefusalCode;
use vk_hub_proto::gitlab::{
    self as gl, Heartbeat, HubRelayMsg, Inventory, RelayMsg, Report, RunnerReport, RunnerState,
    Server, ServerState, ServerStatus,
};

use super::*;
use crate::relays;
use crate::store::TokenKind;

fn relay_token(hub: &Hub) -> String {
    hub.db
        .create_token_for(
            TokenKind::Gitlab,
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
        hostname: "relay-1".into(),
    })
    .unwrap()
}

async fn enrolled_relay(addr: SocketAddr, hub: &Hub, key: &Ed25519KeyPair) -> String {
    let (status, body) = post(addr, gl::ENROLL_PATH, &ask(&relay_token(hub), key)).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    serde_json::from_slice::<gl::EnrollResponse>(&body)
        .unwrap()
        .relay_id
}

async fn dial_relay(addr: SocketAddr) -> Client {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let url = format!("ws://{addr}{}", gl::SESSION_PATH);
    tokio_tungstenite::client_async(url, Box::new(stream) as Box<dyn server::Stream>)
        .await
        .unwrap()
        .0
}

/// Hello, challenge and auth as a relay; what the hub answered.
async fn open_relay(ws: &mut Client, id: &str, key: &Ed25519KeyPair) -> HubMsg {
    send(ws, &hello(id, &"1".repeat(32), gl::PROTOCOL)).await;
    let HubMsg::Challenge {
        version,
        versions,
        nonce,
    } = receive(ws).await
    else {
        panic!("expected a challenge");
    };
    assert_eq!((version, versions), (1, gl::PROTOCOL));
    let nonce = vk_hub_proto::from_hex(&nonce).unwrap();
    let signature = key.sign(&vk_hub_proto::auth_message(
        &nonce,
        id,
        &"1".repeat(32),
        gl::PROTOCOL,
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

async fn tell(ws: &mut Client, msg: &RelayMsg) {
    ws.send(Message::text(serde_json::to_string(msg).unwrap()))
        .await
        .unwrap();
}

async fn hear(ws: &mut Client) -> HubRelayMsg {
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

fn inventory(url: &str) -> Inventory {
    Inventory {
        version: "0.96.0".into(),
        hostname: "relay-1".into(),
        system_id: "s_0123456789ab".into(),
        concurrent: 4,
        server: Server {
            url: url.into(),
            ..Server::default()
        },
        runners: vec![],
    }
}

fn status(state: ServerState, name: Option<&str>) -> HubRelayMsg {
    HubRelayMsg::Server(ServerStatus {
        state,
        url: "https://gitlab.example.com".into(),
        name: name.map(str::to_string),
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_enrolls_with_a_relay_token_only() {
    let (addr, hub) = start().await;
    let key = keypair();
    // A node's token does not enroll a relay, and is not spent by trying.
    let node_token = token(&hub);
    let (status, _) = post(addr, gl::ENROLL_PATH, &ask(&node_token, &key)).await;
    assert_eq!(status, 403);
    // Nor a relay's a node.
    let relay = relay_token(&hub);
    let (status, _) = enroll(addr, &relay, &key).await;
    assert_eq!(status, 403);
    let (status, body) = post(addr, gl::ENROLL_PATH, &ask(&relay, &key)).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let id = serde_json::from_slice::<gl::EnrollResponse>(&body)
        .unwrap()
        .relay_id;
    // Spent.
    let (status, _) = post(addr, gl::ENROLL_PATH, &ask(&relay, &key)).await;
    assert_eq!(status, 403);
    // The same key with a new token is the same relay.
    assert_eq!(enrolled_relay(addr, &hub, &key).await, id);
    assert_eq!(hub.db.relay(&id).unwrap().unwrap().hostname, "relay-1");
    assert!(hub.db.node(&id).unwrap().is_none());
    // The node token still enrolls a node.
    let (status, _) = enroll(addr, &node_token, &keypair()).await;
    assert_eq!(status, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_reports_and_hears_its_server_approved() {
    let (addr, hub) = start().await;
    let key = keypair();
    let id = enrolled_relay(addr, &hub, &key).await;

    // A node's session is not a relay's.
    let mut ws = dial(addr).await;
    send(&mut ws, &hello(&id, &"2".repeat(32), PROTOCOL)).await;
    let HubMsg::Refused { code, .. } = receive(&mut ws).await else {
        panic!("a relay opened a node's session");
    };
    assert_eq!(code, RefusalCode::NotEnrolled);

    let mut ws = dial_relay(addr).await;
    assert!(matches!(
        open_relay(&mut ws, &id, &key).await,
        HubMsg::Welcome { .. }
    ));
    tell(
        &mut ws,
        &RelayMsg::Inventory(inventory("https://GitLab.example.com/")),
    )
    .await;
    assert_eq!(hear(&mut ws).await, status(ServerState::Pending, None));
    let report = Report {
        runners: vec![RunnerReport {
            name: "ci".into(),
            state: RunnerState::ServerPending,
            message: None,
        }],
    };
    tell(&mut ws, &RelayMsg::Report(report.clone())).await;
    tell(&mut ws, &RelayMsg::Heartbeat(Heartbeat::default())).await;
    eventually(|| {
        hub.db
            .relay(&id)
            .unwrap()
            .is_some_and(|r| r.report.as_ref() == Some(&report) && r.heartbeat.is_some())
    })
    .await;
    let views = relays::views(&hub).unwrap();
    assert!(views[0].connected);
    let pending = hub.db.pending_gitlabs().unwrap();
    assert_eq!(pending[0].url, "https://gitlab.example.com");

    // The same inventory again tells it nothing new.
    tell(
        &mut ws,
        &RelayMsg::Inventory(inventory("https://gitlab.example.com")),
    )
    .await;

    // Approved: it hears so at once.
    hub.db
        .add_gitlab("gl", "https://gitlab.example.com", "uid 0", now_secs())
        .unwrap();
    relays::server_changed(&hub, "https://gitlab.example.com").unwrap();
    assert_eq!(
        hear(&mut ws).await,
        status(ServerState::Approved, Some("gl"))
    );
    assert!(hub.db.pending_gitlabs().unwrap().is_empty());

    // Reporting another server does not move it: it is told it was rebound.
    tell(
        &mut ws,
        &RelayMsg::Inventory(inventory("https://other.example.com")),
    )
    .await;
    assert_eq!(hear(&mut ws).await, status(ServerState::Rebound, None));

    // Removed: its session ends, refused.
    assert!(relays::remove(&hub, "uid 0", &id).unwrap());
    let HubRelayMsg::Refused { code, .. } = hear(&mut ws).await else {
        panic!("expected a refusal");
    };
    assert_eq!(code, RefusalCode::Revoked);
    let audit = hub.db.audits(Some(&id), 50).unwrap();
    for event in [
        "bound to GitLab https://gitlab.example.com",
        "removed relay",
    ] {
        assert!(audit.iter().any(|a| a.event.contains(event)), "{audit:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_naming_no_plain_http_server_is_refused() {
    let (addr, hub) = start().await;
    let key = keypair();
    let id = enrolled_relay(addr, &hub, &key).await;
    let long = format!(
        "https://gl.example/{}",
        "a".repeat(vk_hub_proto::MAX_DISPLAY)
    );
    for url in ["ftp://gl", "https://gl.example/a\u{200b}", long.as_str()] {
        let mut ws = dial_relay(addr).await;
        assert!(matches!(
            open_relay(&mut ws, &id, &key).await,
            HubMsg::Welcome { .. }
        ));
        tell(&mut ws, &RelayMsg::Inventory(inventory(url))).await;
        let HubRelayMsg::Refused { code, .. } = hear(&mut ws).await else {
            panic!("expected a refusal for {url}");
        };
        assert_eq!(code, RefusalCode::Protocol, "{url}");
        assert_eq!(hub.db.relay(&id).unwrap().unwrap().server_url, None);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_past_the_hub_s_runner_or_request_limits_is_refused() {
    let (addr, hub) = start().await;
    let key = keypair();
    let id = enrolled_relay(addr, &hub, &key).await;
    let runner = |n: usize, request_concurrency| gl::Runner {
        name: format!("runner-{n}"),
        runner_id: Some(u64::try_from(n).unwrap() + 1),
        placement: Default::default(),
        limit: None,
        request_concurrency,
        verified: true,
    };
    let at_limits = |inventory: &mut Inventory| {
        inventory.runners = (0..gl::MAX_RUNNERS).map(|n| runner(n, 1)).collect();
        inventory.runners[0].request_concurrency = u32::try_from(gl::MAX_ADMISSIONS).unwrap();
    };
    let mut over_runners = inventory("https://gitlab.example.com");
    at_limits(&mut over_runners);
    over_runners.runners.push(runner(gl::MAX_RUNNERS, 1));
    let mut over_requests = inventory("https://gitlab.example.com");
    at_limits(&mut over_requests);
    over_requests.runners[0].request_concurrency += 1;
    for (what, over) in [("runners", over_runners), ("requests", over_requests)] {
        let mut ws = dial_relay(addr).await;
        assert!(matches!(
            open_relay(&mut ws, &id, &key).await,
            HubMsg::Welcome { .. }
        ));
        tell(&mut ws, &RelayMsg::Inventory(over)).await;
        let HubRelayMsg::Refused { code, .. } = hear(&mut ws).await else {
            panic!("expected a refusal past the {what} limit");
        };
        assert_eq!(code, RefusalCode::Protocol, "{what}");
        assert!(
            hub.db.relay(&id).unwrap().unwrap().inventory.is_none(),
            "{what}"
        );
    }
    // At the limits, the inventory is taken.
    let mut ws = dial_relay(addr).await;
    assert!(matches!(
        open_relay(&mut ws, &id, &key).await,
        HubMsg::Welcome { .. }
    ));
    let mut inventory = inventory("https://gitlab.example.com");
    at_limits(&mut inventory);
    tell(&mut ws, &RelayMsg::Inventory(inventory)).await;
    for _ in 0..1000 {
        let row = hub.db.relay(&id).unwrap().unwrap();
        if row
            .inventory
            .is_some_and(|i| i.runners.len() == gl::MAX_RUNNERS)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the inventory at the limits was not taken");
}
