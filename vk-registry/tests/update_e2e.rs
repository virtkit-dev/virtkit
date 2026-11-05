//! An update of the built `vk-registry` under a service manager, end to end: the registry runs
//! from an installed copy with `$NOTIFY_SOCKET` set, a fake hub sends it an update to a release
//! of its own, and the registry starts the release beside itself. A blob upload and a blob
//! download under way when it hands over finish whole, on the process they started on; a new
//! connection every few milliseconds is answered throughout; and once the transfers are done
//! the registry names the release the main process and exits, the release in session with the
//! hub, installed over the installed copy and the update reported done.

use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, mpsc};
use tokio_tungstenite::tungstenite::Message;
use vk_hub_proto::registry::{
    Command, HubRegistryMsg, Operation, PROTOCOL, RELEASE_PATH, RegistryMsg,
};
use vk_hub_proto::{CommandAck, HubMsg, NodeMsg, Outcome};
use vk_peer::identity::Identity;

const REGISTRY_ID: &str = "fedcba9876543210fedcba9876543210";
const COMMAND_ID: &str = "0123456789abcdef0123456789abcdef";

/// The size of the blob downloaded and of the one uploaded.
const BLOB: usize = 8 << 20;

/// What the transfers move at a time, and how often, until the release serves.
const STEP: usize = 64 << 10;
const PACE: Duration = Duration::from_millis(20);

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vk-registry-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn sha256(bytes: &[u8]) -> String {
    vk_hub_proto::to_hex(&Sha256::digest(bytes))
}

/// What the fake hub saw.
#[derive(Debug)]
enum Seen {
    /// A session opened by the registry's process of this incarnation.
    Session(String),
    Msg(Box<RegistryMsg>),
}

/// The hub's side: a session per connection, which sends the update once `go` is notified;
/// and the release, to whoever asks.
async fn hub(
    listener: TcpListener,
    release: Arc<Vec<u8>>,
    command: Command,
    go: Arc<Notify>,
    seen: mpsc::UnboundedSender<Seen>,
) {
    let sent = Arc::new(Mutex::new(false));
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let (release, command, go, seen, sent) = (
            Arc::clone(&release),
            command.clone(),
            Arc::clone(&go),
            seen.clone(),
            Arc::clone(&sent),
        );
        tokio::spawn(async move {
            let mut head = [0u8; 256];
            let n = stream.peek(&mut head).await.unwrap_or(0);
            if head[..n].starts_with(format!("GET {RELEASE_PATH}").as_bytes()) {
                serve_release(stream, &release).await;
            } else {
                session(stream, command, go, seen, sent).await;
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
    stream: TcpStream,
    command: Command,
    go: Arc<Notify>,
    seen: mpsc::UnboundedSender<Seen>,
    sent: Arc<Mutex<bool>>,
) {
    let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
        return;
    };
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
        version: PROTOCOL.max,
        versions: PROTOCOL,
        nonce: vk_hub_proto::to_hex(&[7u8; vk_hub_proto::CHALLENGE_LEN]),
    };
    let send = |msg: String| Message::text(msg);
    ws.send(send(serde_json::to_string(&challenge).unwrap()))
        .await
        .unwrap();
    // The auth is not checked: the registry is the one under test.
    let _ = ws.next().await;
    let welcome = HubMsg::Welcome { heartbeat_secs: 1 };
    ws.send(send(serde_json::to_string(&welcome).unwrap()))
        .await
        .unwrap();
    // Waiting on `go` before the test hears of the session, which then notifies it.
    let told = go.notified();
    tokio::pin!(told);
    let _ = seen.send(Seen::Session(incarnation));
    let first = !*sent.lock().unwrap();
    let mut ping = tokio::time::interval(Duration::from_millis(300));
    let mut told_done = !first;
    loop {
        tokio::select! {
            () = &mut told, if !told_done => {
                told_done = true;
                if !std::mem::replace(&mut *sent.lock().unwrap(), true) {
                    let msg = HubRegistryMsg::Command(command.clone());
                    if ws.send(send(serde_json::to_string(&msg).unwrap())).await.is_err() {
                        return;
                    }
                }
            }
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
                let Ok(msg) = serde_json::from_str::<RegistryMsg>(&t) else {
                    continue;
                };
                let reply = match &msg {
                    RegistryMsg::Ack(ack) => Some(HubRegistryMsg::Recorded(ack.clone())),
                    _ => None,
                };
                let _ = seen.send(Seen::Msg(Box::new(msg)));
                if let Some(reply) = reply
                    && ws.send(send(serde_json::to_string(&reply).unwrap())).await.is_err()
                {
                    return;
                }
            }
        }
    }
}

/// The next ack the hub saw, past every other message.
async fn ack(seen: &mut mpsc::UnboundedReceiver<Seen>) -> CommandAck {
    loop {
        if let Seen::Msg(msg) = seen.recv().await.unwrap()
            && let RegistryMsg::Ack(ack) = *msg
        {
            return ack;
        }
    }
}

async fn next_session(seen: &mut mpsc::UnboundedReceiver<Seen>) -> String {
    loop {
        if let Seen::Session(i) = seen.recv().await.unwrap() {
            return i;
        }
    }
}

/// The head of an HTTP response read off `stream`, and what of its body came with it.
async fn response_head(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        if let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&got[..end]).into_owned();
            return (head, got[end + 4..].to_vec());
        }
        let n = stream.read(&mut buf).await.unwrap();
        assert!(n > 0, "the connection closed before a response: {got:?}");
        got.extend_from_slice(&buf[..n]);
    }
}

/// Put `blob` into repository `r` in one request, and its digest.
async fn put_blob(addr: &str, blob: &[u8]) -> String {
    let digest = format!("sha256:{}", sha256(blob));
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"POST /v2/r/blobs/uploads/ HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let (head, _) = response_head(&mut s).await;
    let location = location(&head);
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(
        format!(
            "PUT {location}?digest={digest} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n",
            blob.len()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    s.write_all(blob).await.unwrap();
    let (head, _) = response_head(&mut s).await;
    assert!(head.starts_with("HTTP/1.1 201"), "{head}");
    digest
}

fn location(head: &str) -> String {
    head.lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("location")
                .then(|| v.trim().to_string())
        })
        .unwrap_or_else(|| panic!("no Location: {head}"))
}

/// Ask for `/v2/` on a connection of its own until `stop`, counting the answers, and panic on
/// any connection refused or closed unanswered.
async fn ask_constantly(addr: String, stop: Arc<AtomicBool>, answered: Arc<AtomicUsize>) {
    while !stop.load(Ordering::SeqCst) {
        let mut s = match TcpStream::connect(&addr).await {
            Ok(s) => s,
            Err(e) => panic!("a connection was refused: {e}"),
        };
        s.write_all(b"GET /v2/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut got = Vec::new();
        s.read_to_end(&mut got).await.unwrap();
        let text = String::from_utf8_lossy(&got);
        assert!(text.starts_with("HTTP/1.1 200"), "answered {text:?}");
        answered.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Whether process `pid` is alive.
fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 checks the process exists and sends nothing.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Read the service manager's messages off `socket` until one names a main process, then the
/// barrier after it, as systemd does: its pid. The barrier's descriptor, received with it and
/// dropped, is what ends the registry's wait.
fn main_pid(socket: &UnixDatagram) -> i32 {
    let mut buf = [0u8; 512];
    let mut pid = None;
    loop {
        let n = socket
            .recv(&mut buf)
            .expect("a message to the service manager");
        let msg = String::from_utf8_lossy(&buf[..n]).into_owned();
        if let Some(p) = msg.lines().find_map(|l| l.strip_prefix("MAINPID=")) {
            pid = Some(p.parse().unwrap());
        }
        if let Some(pid) = pid
            && msg.lines().any(|l| l == "BARRIER=1")
        {
            return pid;
        }
    }
}

/// The registry's process group, killed whole when dropped, the release started beside it
/// included: a test that fails leaves neither running.
struct Group(i32);

impl Drop for Group {
    fn drop(&mut self) {
        // SAFETY: kill takes a process group and a signal; a group already gone fails, as
        // intended.
        unsafe { libc::kill(-self.0, libc::SIGKILL) };
    }
}

/// A registry running from an installed copy, enrolled with a fake hub that sends it an update
/// to a release of its own once `go` is notified; under a service manager listening on
/// `notify` when given.
struct Setup {
    dir: PathBuf,
    installed: PathBuf,
    /// The release's sha256.
    sha: String,
    addr: String,
    go: Arc<Notify>,
    seen: mpsc::UnboundedReceiver<Seen>,
    served: tokio::task::JoinHandle<()>,
    log: PathBuf,
    registry: std::process::Child,
    _group: Group,
}

async fn setup(tag: &str, notify: Option<&std::path::Path>) -> Setup {
    let dir = temp_dir(tag);
    let root = dir.join("store");
    std::fs::create_dir_all(&root).unwrap();
    // The installed binary, and the release: the same program, other bytes.
    let built = std::fs::read(env!("CARGO_BIN_EXE_vk-registry")).unwrap();
    let installed = dir.join("vk-registry");
    std::fs::write(&installed, &built).unwrap();
    std::fs::set_permissions(
        &installed,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
    )
    .unwrap();
    let mut release = built;
    release.extend_from_slice(b"\0an update's release");
    let sha = sha256(&release);

    let hub_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", hub_listener.local_addr().unwrap());
    let hub_dir = root.join("hub");
    vk_peer::net::create_dir(&hub_dir).unwrap();
    Identity::load_or_create(&hub_dir).unwrap();
    std::fs::write(
        hub_dir.join("enrollment.json"),
        format!(r#"{{"hub":"{url}","registry_id":"{REGISTRY_ID}"}}"#),
    )
    .unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr = format!("127.0.0.1:{port}");
    let config = dir.join("config.toml");
    std::fs::write(
        &config,
        format!(
            "addr = \"{addr}\"\nroot = \"{}\"\n[hub]\nallow = [\"update\"]\n",
            root.display()
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
    let go = Arc::new(Notify::new());
    let (tx, seen) = mpsc::unbounded_channel();
    let served = tokio::spawn(hub(
        hub_listener,
        Arc::new(release),
        command,
        Arc::clone(&go),
        tx,
    ));
    let log = dir.join("registry.log");
    let mut registry = std::process::Command::new(&installed);
    registry
        .args(["serve", "--config"])
        .arg(&config)
        .env_remove("NOTIFY_SOCKET")
        .stdout(std::process::Stdio::null())
        .stderr(std::fs::File::create(&log).unwrap());
    if let Some(notify) = notify {
        registry.env("NOTIFY_SOCKET", notify);
    }
    let registry = {
        use std::os::unix::process::CommandExt;
        registry.process_group(0).spawn().unwrap()
    };
    let group = Group(i32::try_from(registry.id()).unwrap());
    Setup {
        dir,
        installed,
        sha,
        addr,
        go,
        seen,
        served,
        log,
        registry,
        _group: group,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_update_under_a_service_manager_cuts_no_transfer_and_refuses_no_connection() {
    let manager_dir = temp_dir("update-e2e-manager");
    let notify_path = manager_dir.join("notify");
    let manager = UnixDatagram::bind(&notify_path).unwrap();
    manager
        .set_read_timeout(Some(Duration::from_secs(120)))
        .unwrap();
    let Setup {
        dir,
        installed,
        sha,
        addr,
        go,
        mut seen,
        served,
        log,
        mut registry,
        _group,
    } = setup("update-e2e", Some(&notify_path)).await;
    let shown = |what: &str| {
        format!(
            "{what}; the registry logged:\n{}",
            std::fs::read_to_string(&log).unwrap_or_default()
        )
    };
    macro_rules! wait {
        ($secs:expr, $what:expr, $fut:expr) => {
            tokio::time::timeout(Duration::from_secs($secs), $fut)
                .await
                .unwrap_or_else(|_| panic!("{}", shown($what)))
        };
    }

    let first = wait!(60, "no session", next_session(&mut seen));
    // A blob to download, and one to upload: bytes that differ from one place to the next.
    let blob: Vec<u8> = (0..BLOB).map(|i| (i * 7 % 251) as u8).collect();
    let digest = put_blob(&addr, &blob).await;
    let upload: Vec<u8> = (0..BLOB).map(|i| (i * 13 % 241) as u8).collect();

    // Both transfers start on the registry, and move a step at a time until the release
    // serves; then they finish.
    let serving = Arc::new(AtomicBool::new(false));
    let mut down = TcpStream::connect(&addr).await.unwrap();
    down.write_all(format!("GET /v2/r/blobs/{digest} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let (head, mut downloaded) = response_head(&mut down).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let download = {
        let serving = Arc::clone(&serving);
        tokio::spawn(async move {
            let mut buf = vec![0u8; STEP];
            while downloaded.len() < BLOB {
                // Its last step waits for the release: the download spans the hand-over.
                while !serving.load(Ordering::SeqCst) {
                    tokio::time::sleep(PACE).await;
                    if downloaded.len() + STEP < BLOB {
                        break;
                    }
                }
                let n = down.read(&mut buf).await.unwrap();
                assert!(n > 0, "the download was cut at {} bytes", downloaded.len());
                downloaded.extend_from_slice(&buf[..n]);
            }
            downloaded
        })
    };
    let mut up = TcpStream::connect(&addr).await.unwrap();
    up.write_all(b"POST /v2/r/blobs/uploads/ HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
        .await
        .unwrap();
    let (head, _) = response_head(&mut up).await;
    let location = location(&head);
    let upload_digest = format!("sha256:{}", sha256(&upload));
    up.write_all(
        format!(
            "PUT {location}?digest={upload_digest} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            upload.len()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let uploaded = {
        let serving = Arc::clone(&serving);
        tokio::spawn(async move {
            let chunks = upload.chunks(STEP).count();
            for (i, chunk) in upload.chunks(STEP).enumerate() {
                // Its last step waits for the release: the upload spans the hand-over.
                while !serving.load(Ordering::SeqCst) {
                    tokio::time::sleep(PACE).await;
                    if i + 1 < chunks {
                        break;
                    }
                }
                up.write_all(chunk).await.unwrap();
            }
            response_head(&mut up).await.0
        })
    };

    let stop = Arc::new(AtomicBool::new(false));
    let answered = Arc::new(AtomicUsize::new(0));
    let asking = tokio::spawn(ask_constantly(
        addr.clone(),
        Arc::clone(&stop),
        Arc::clone(&answered),
    ));

    go.notify_waiters();
    let accepted = wait!(60, "the update not acked", ack(&mut seen));
    assert_eq!(accepted.outcome, Outcome::Accepted, "{}", shown("refused"));
    // The release serves: a session of another incarnation.
    let second = wait!(120, "no session from the release", next_session(&mut seen));
    assert_ne!(first, second);
    assert!(
        registry.try_wait().unwrap().is_none(),
        "{}",
        shown("the registry ended before its transfers did")
    );
    serving.store(true, Ordering::SeqCst);

    let downloaded = wait!(60, "the download did not finish", download).unwrap();
    assert!(downloaded == blob, "the download is not the blob");
    let head = wait!(60, "the upload did not finish", uploaded).unwrap();
    assert!(head.starts_with("HTTP/1.1 201"), "{}", shown(&head));

    // Its transfers done, the registry names the release the main process, and ends.
    let pid = tokio::task::spawn_blocking(move || main_pid(&manager))
        .await
        .unwrap();
    let status = wait!(30, "the registry did not end", async {
        loop {
            if let Some(status) = registry.try_wait().unwrap() {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    assert!(status.success(), "{}", shown(&format!("it ended {status}")));
    assert_ne!(pid, registry.id() as i32);
    assert!(alive(pid), "{}", shown("the release is not running"));

    // The release reports the update done, and installed itself over the installed copy.
    let done = wait!(60, "no ack of the update done", async {
        loop {
            let a = ack(&mut seen).await;
            if a.outcome != Outcome::Accepted {
                return a;
            }
        }
    });
    assert_eq!(
        (done.id.as_str(), &done.outcome),
        (COMMAND_ID, &Outcome::Done),
        "{}",
        shown("not done")
    );
    assert_eq!(sha256(&std::fs::read(&installed).unwrap()), sha);
    // What was uploaded across the update is served, by the release.
    let mut s = TcpStream::connect(&addr).await.unwrap();
    s.write_all(
        format!(
            "HEAD /v2/r/blobs/{upload_digest} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let (head, _) = response_head(&mut s).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    stop.store(true, Ordering::SeqCst);
    wait!(30, "the asking did not stop", asking).unwrap();
    assert!(answered.load(Ordering::SeqCst) > 0);
    // SAFETY: kill takes a pid and a signal.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    served.abort();
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&manager_dir);
}

/// Without a service manager listening, the registry executes the release in its place with
/// its listening socket: the same process, a session of another incarnation, and a new
/// connection every few milliseconds answered throughout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_update_elsewhere_executes_the_release_refusing_no_connection() {
    let Setup {
        dir,
        installed,
        sha,
        addr,
        go,
        mut seen,
        served,
        log,
        mut registry,
        _group,
    } = setup("update-e2e-exec", None).await;
    let shown = |what: &str| {
        format!(
            "{what}; the registry logged:\n{}",
            std::fs::read_to_string(&log).unwrap_or_default()
        )
    };
    macro_rules! wait {
        ($secs:expr, $what:expr, $fut:expr) => {
            tokio::time::timeout(Duration::from_secs($secs), $fut)
                .await
                .unwrap_or_else(|_| panic!("{}", shown($what)))
        };
    }
    let first = wait!(60, "no session", next_session(&mut seen));
    let stop = Arc::new(AtomicBool::new(false));
    let answered = Arc::new(AtomicUsize::new(0));
    let asking = tokio::spawn(ask_constantly(
        addr.clone(),
        Arc::clone(&stop),
        Arc::clone(&answered),
    ));
    go.notify_waiters();
    let accepted = wait!(60, "the update not acked", ack(&mut seen));
    assert_eq!(accepted.outcome, Outcome::Accepted, "{}", shown("refused"));
    let second = wait!(120, "no session from the release", next_session(&mut seen));
    assert_ne!(first, second);
    let done = wait!(60, "no ack of the update done", async {
        loop {
            let a = ack(&mut seen).await;
            if a.outcome != Outcome::Accepted {
                return a;
            }
        }
    });
    assert_eq!(done.outcome, Outcome::Done, "{}", shown("not done"));
    // The same process, now the release, installed over the installed copy.
    assert!(
        registry.try_wait().unwrap().is_none(),
        "{}",
        shown("the registry exited")
    );
    assert_eq!(sha256(&std::fs::read(&installed).unwrap()), sha);
    let before = answered.load(Ordering::SeqCst);
    wait!(30, "no connection answered by the release", async {
        while answered.load(Ordering::SeqCst) < before + 5 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
    stop.store(true, Ordering::SeqCst);
    wait!(30, "the asking did not stop", asking).unwrap();
    assert!(
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .contains("with the listening sockets"),
        "{}",
        shown("not executed with its sockets")
    );
    registry.kill().unwrap();
    registry.wait().unwrap();
    served.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A release that cannot take over — here, one that cannot read the config the registry was
/// started with, changed since — leaves the registry serving as it was: the same process, its
/// locks still held by their owners, no connection refused, and the update reported failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_release_that_cannot_take_over_leaves_the_registry_serving() {
    let manager_dir = temp_dir("update-e2e-untaken-manager");
    let notify_path = manager_dir.join("notify");
    let _manager = UnixDatagram::bind(&notify_path).unwrap();
    let Setup {
        dir,
        installed,
        sha,
        addr,
        go,
        mut seen,
        served,
        log,
        mut registry,
        _group,
    } = setup("update-e2e-untaken", Some(&notify_path)).await;
    let shown = |what: &str| {
        format!(
            "{what}; the registry logged:\n{}",
            std::fs::read_to_string(&log).unwrap_or_default()
        )
    };
    macro_rules! wait {
        ($secs:expr, $what:expr, $fut:expr) => {
            tokio::time::timeout(Duration::from_secs($secs), $fut)
                .await
                .unwrap_or_else(|_| panic!("{}", shown($what)))
        };
    }
    wait!(60, "no session", next_session(&mut seen));
    let lock = |action: &str, owner: Option<&str>| {
        let addr = addr.clone();
        let request = match owner {
            Some(o) => format!(
                "POST /lock/{action}?name=k&ttl=300 HTTP/1.1\r\nHost: x\r\nX-Vk-Lock-Owner: {o}\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            ),
            None => format!(
                "POST /lock/{action}?name=k&ttl=300 HTTP/1.1\r\nHost: x\r\nX-Vk-Lock-Holder: me\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            ),
        };
        async move {
            let mut s = TcpStream::connect(&addr).await.unwrap();
            s.write_all(request.as_bytes()).await.unwrap();
            let mut got = Vec::new();
            s.read_to_end(&mut got).await.unwrap();
            String::from_utf8_lossy(&got).into_owned()
        }
    };
    let acquired = lock("acquire", None).await;
    assert!(acquired.starts_with("HTTP/1.1 200"), "{acquired}");
    let owner = acquired
        .split("\"owner\":\"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .unwrap()
        .to_string();
    // The release reads the config afresh, and cannot.
    std::fs::write(dir.join("config.toml"), "not = [toml").unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let answered = Arc::new(AtomicUsize::new(0));
    let asking = tokio::spawn(ask_constantly(
        addr.clone(),
        Arc::clone(&stop),
        Arc::clone(&answered),
    ));
    go.notify_waiters();
    let accepted = wait!(60, "the update not acked", ack(&mut seen));
    assert_eq!(accepted.outcome, Outcome::Accepted, "{}", shown("refused"));
    let failed = wait!(120, "no ack of the update failed", async {
        loop {
            let a = ack(&mut seen).await;
            if a.outcome != Outcome::Accepted {
                return a;
            }
        }
    });
    assert!(
        matches!(failed.outcome, Outcome::Failed { .. }),
        "{}",
        shown(&format!("{:?}", failed.outcome))
    );
    assert!(
        registry.try_wait().unwrap().is_none(),
        "{}",
        shown("the registry exited")
    );
    assert_ne!(sha256(&std::fs::read(&installed).unwrap()), sha);
    // The lock table came back whole: its owner renews the lease.
    let renewed = lock("renew", Some(&owner)).await;
    assert!(
        renewed.starts_with("HTTP/1.1 200") && renewed.contains("\"renewed\":1"),
        "{renewed}"
    );
    let before = answered.load(Ordering::SeqCst);
    wait!(30, "no connection answered after", async {
        while answered.load(Ordering::SeqCst) < before + 5 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
    stop.store(true, Ordering::SeqCst);
    wait!(30, "the asking did not stop", asking).unwrap();
    registry.kill().unwrap();
    registry.wait().unwrap();
    served.abort();
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&manager_dir);
}
