//! An update of the built `vk-gitlab`, end to end: the daemon runs from an installed copy, a
//! fake hub sends it an update to a release of its own, serves the release, and sees the relay
//! stop its job requests, execute the release, come back in session as it, install it over the
//! installed copy and report the update done.

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use vk_hub_proto::gitlab::{CONNECTION, Command, HubRelayMsg, Operation, PROTOCOL, RelayMsg};
use vk_hub_proto::{CommandAck, HubMsg, NodeMsg, Outcome, UpdatePhase};
use vk_peer::identity::Identity;

use support::gl::{Gl, temp_dir, within};

const RELAY_ID: &str = "fedcba9876543210fedcba9876543210";
const COMMAND_ID: &str = "0123456789abcdef0123456789abcdef";

/// What the fake hub saw.
#[derive(Debug)]
enum Seen {
    /// A session opened by the relay's process of this incarnation.
    Session(String),
    Msg(RelayMsg),
}

/// The hub's side: a session per connection, which sends the update once, after the first
/// report of any session; and the release, to whoever asks.
async fn hub(
    listener: TcpListener,
    release: Arc<Vec<u8>>,
    command: Command,
    seen: mpsc::UnboundedSender<Seen>,
) {
    let sent = Arc::new(Mutex::new(false));
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let (release, command, seen, sent) = (
            Arc::clone(&release),
            command.clone(),
            seen.clone(),
            Arc::clone(&sent),
        );
        tokio::spawn(async move {
            if !support::relayconn::is_h2(&stream).await {
                serve_release(stream, &release).await;
                return;
            }
            let (conn, ws) = support::relayconn::serve(
                Box::new(stream),
                |_| async {
                    Ok(hyper::Response::builder()
                        .status(404)
                        .body(http_body_util::Full::new(bytes::Bytes::new()))
                        .unwrap())
                },
                std::future::pending(),
            );
            tokio::spawn(conn);
            if let Ok(ws) = ws.await {
                session(ws, command, seen, sent).await;
            }
        });
    }
}

async fn serve_release(mut stream: TcpStream, release: &[u8]) {
    let mut request = Vec::new();
    let mut buf = [0u8; 1024];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut buf).await.unwrap();
        if n == 0 {
            return;
        }
        request.extend_from_slice(&buf[..n]);
    }
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        release.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(release).await.unwrap();
    let _ = stream.shutdown().await;
}

async fn session(
    mut ws: support::relayconn::Ws,
    command: Command,
    seen: mpsc::UnboundedSender<Seen>,
    sent: Arc<Mutex<bool>>,
) {
    let text = |m: Option<Result<Message, _>>| match m {
        Some(Ok(Message::Text(t))) => Some(t.as_str().to_owned()),
        _ => None,
    };
    let Some(Ok(NodeMsg::Hello { incarnation, .. })) =
        text(ws.next().await).map(|t| serde_json::from_str(&t))
    else {
        return;
    };
    let challenge = HubMsg::Challenge {
        version: CONNECTION,
        versions: PROTOCOL,
        nonce: vk_hub_proto::to_hex(&[7u8; vk_hub_proto::CHALLENGE_LEN]),
    };
    let send = |msg: String| Message::text(msg);
    ws.send(send(serde_json::to_string(&challenge).unwrap()))
        .await
        .unwrap();
    // The auth is not checked: the relay is the one under test.
    let _ = ws.next().await;
    let welcome = HubMsg::Welcome { heartbeat_secs: 1 };
    ws.send(send(serde_json::to_string(&welcome).unwrap()))
        .await
        .unwrap();
    let _ = seen.send(Seen::Session(incarnation));
    let mut ping = tokio::time::interval(Duration::from_millis(300));
    loop {
        tokio::select! {
            _ = ping.tick() => {
                if ws.send(Message::Ping(Vec::new().into())).await.is_err() {
                    return;
                }
            }
            frame = ws.next() => {
                let t = match frame {
                    Some(Ok(Message::Text(t))) => t.as_str().to_owned(),
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                    _ => return,
                };
                let Ok(msg) = serde_json::from_str::<RelayMsg>(&t) else {
                    continue;
                };
                let reply = match &msg {
                    RelayMsg::Report(_) if !std::mem::replace(&mut *sent.lock().unwrap(), true) => {
                        Some(HubRelayMsg::Command(command.clone()))
                    }
                    RelayMsg::Ack(ack) => Some(HubRelayMsg::Recorded(ack.clone())),
                    _ => None,
                };
                let _ = seen.send(Seen::Msg(msg));
                if let Some(reply) = reply
                    && ws.send(send(serde_json::to_string(&reply).unwrap())).await.is_err()
                {
                    return;
                }
            }
        }
    }
}

fn sha256(bytes: &[u8]) -> String {
    vk_hub_proto::to_hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

/// The next ack the hub saw, past every other message.
async fn ack(seen: &mut mpsc::UnboundedReceiver<Seen>) -> CommandAck {
    loop {
        if let Seen::Msg(RelayMsg::Ack(ack)) = seen.recv().await.unwrap() {
            return ack;
        }
    }
}

/// A relay running from an installed copy of the built `vk-gitlab`, its fake hub, which sends
/// it an update to a release of its own, and what that hub sees.
struct Running {
    dir: std::path::PathBuf,
    hub_dir: std::path::PathBuf,
    installed: std::path::PathBuf,
    sha: String,
    seen: mpsc::UnboundedReceiver<Seen>,
    served: tokio::task::JoinHandle<()>,
    relay: std::process::Child,
    log: std::path::PathBuf,
    _gitlab: support::FakeGitLab,
}

impl Running {
    async fn start(name: &str) -> Self {
        let dir = temp_dir(name);
        let state = dir.join("state");
        vk_peer::net::create_dir(&state).unwrap();
        // The installed binary, and the release: the same program, other bytes.
        let built = std::fs::read(env!("CARGO_BIN_EXE_vk-gitlab")).unwrap();
        let installed = dir.join("vk-gitlab");
        std::fs::write(&installed, &built).unwrap();
        std::fs::set_permissions(
            &installed,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
        )
        .unwrap();
        let mut release = built;
        release.extend_from_slice(b"\0an update's release");
        let sha = sha256(&release);
        assert_ne!(sha256(&std::fs::read(&installed).unwrap()), sha);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let hub_dir = vk_gitlab::relay::dir(&state);
        vk_peer::net::create_dir(&hub_dir).unwrap();
        Identity::load_or_create(&hub_dir).unwrap();
        std::fs::write(
            hub_dir.join("enrollment.json"),
            format!(r#"{{"hub":"{url}","relay_id":"{RELAY_ID}"}}"#),
        )
        .unwrap();
        let gitlab = support::FakeGitLab::start(Arc::new(Gl::default()).handler()).await;
        let config = dir.join("config.toml");
        std::fs::write(
            &config,
            format!(
                "state_dir = \"{}\"\nsystem_id = \"s_0123456789ab\"\n[gitlab]\nurl = \"{}\"\n\
                 [[runners]]\nname = \"ci\"\ntoken = \"glrt-x\"\n[hub]\nallow = [\"update\"]\n",
                state.display(),
                gitlab.url
            ),
        )
        .unwrap();
        let command = Command {
            id: COMMAND_ID.into(),
            expires_at: vk_peer::now_secs() + 3600,
            op: Operation::Update {
                version: env!("CARGO_PKG_VERSION").into(),
                sha256: sha.clone(),
                size: release.len() as u64,
                signature: None,
            },
        };
        let (tx, seen) = mpsc::unbounded_channel();
        let served = tokio::spawn(hub(listener, Arc::new(release), command, tx));
        let log = dir.join("relay.log");
        let relay = std::process::Command::new(&installed)
            .args(["run", "--config"])
            .arg(&config)
            .stdout(std::process::Stdio::null())
            .stderr(std::fs::File::create(&log).unwrap())
            .spawn()
            .unwrap();
        Self {
            dir,
            hub_dir,
            installed,
            sha,
            seen,
            served,
            relay,
            log,
            _gitlab: gitlab,
        }
    }

    /// `what`, with what the relay logged.
    fn shown(&self, what: &str) -> String {
        format!(
            "{what}; the relay logged:\n{}",
            std::fs::read_to_string(&self.log).unwrap_or_default()
        )
    }

    /// The next session's incarnation.
    async fn session(&mut self) -> String {
        loop {
            if let Seen::Session(i) = self.seen.recv().await.unwrap() {
                return i;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_executes_its_release_and_installs_it_once_back_in_session() {
    let mut r = Running::start("update-e2e").await;
    let first = within("the first session", r.session()).await;
    let accepted = within("the update accepted", ack(&mut r.seen)).await;
    assert_eq!(
        accepted.outcome,
        Outcome::Accepted,
        "{}",
        r.shown("not accepted")
    );
    // The release takes over: a session of another incarnation, which reports it done.
    let second = tokio::time::timeout(Duration::from_secs(60), r.session())
        .await
        .unwrap_or_else(|_| panic!("{}", r.shown("no session from the release")));
    assert_ne!(first, second);
    // Its ack and its report, in either order.
    let seen = &mut r.seen;
    let ended = tokio::time::timeout(Duration::from_secs(30), async {
        let (mut done, mut reported) = (None, None);
        while done.is_none() || reported.is_none() {
            match seen.recv().await.unwrap() {
                Seen::Msg(RelayMsg::Ack(ack)) => done = Some(ack),
                Seen::Msg(RelayMsg::Report(r)) if r.update.is_some() => reported = r.update,
                _ => {}
            }
        }
        (done.unwrap(), reported.unwrap())
    })
    .await;
    let (done, reported) =
        ended.unwrap_or_else(|_| panic!("{}", r.shown("no ack or report of the update done")));
    assert_eq!(
        (done.id.as_str(), &done.outcome),
        (COMMAND_ID, &Outcome::Done),
        "{}",
        r.shown("not done")
    );
    assert_eq!(reported.phase, UpdatePhase::Done);
    // The same process, now the release, installed over the installed copy.
    assert_eq!(
        r.relay.try_wait().unwrap(),
        None,
        "{}",
        r.shown("the relay exited")
    );
    assert_eq!(sha256(&std::fs::read(&r.installed).unwrap()), r.sha);
    let kept: Vec<_> = std::fs::read_dir(r.hub_dir.join("releases"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(kept.contains(&r.sha), "{kept:?}");

    r.relay.kill().unwrap();
    r.relay.wait().unwrap();
    r.served.abort();
    let _ = std::fs::remove_dir_all(&r.dir);
}

/// A relay told to stop once it has accepted an update stops: it does not execute the release,
/// and leaves no trial for its next start to execute it from.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_stopping_during_an_update_leaves_no_trial() {
    let mut r = Running::start("update-e2e-stop").await;
    within("the first session", r.session()).await;
    let accepted = within("the update accepted", ack(&mut r.seen)).await;
    assert_eq!(
        accepted.outcome,
        Outcome::Accepted,
        "{}",
        r.shown("not accepted")
    );
    // SAFETY: kill(2) on the child's pid.
    assert_eq!(
        unsafe { libc::kill(r.relay.id() as libc::pid_t, libc::SIGTERM) },
        0
    );
    let exited = within("the relay to exit", async {
        loop {
            if let Some(status) = r.relay.try_wait().unwrap() {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(exited.success(), "{}", r.shown("the relay failed"));
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(r.hub_dir.join("update.json")).unwrap()).unwrap();
    assert!(state["trial"].is_null(), "{state}");
    // No session from the release, nor any other.
    while let Ok(seen) = r.seen.try_recv() {
        assert!(
            !matches!(seen, Seen::Session(_)),
            "{}",
            r.shown("a new session")
        );
    }
    assert_ne!(sha256(&std::fs::read(&r.installed).unwrap()), r.sha);
    r.served.abort();
    let _ = std::fs::remove_dir_all(&r.dir);
}
