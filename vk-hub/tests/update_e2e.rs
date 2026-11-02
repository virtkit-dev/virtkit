//! End-to-end self-update of the built `vk-hub`: an installed copy updates to the same program
//! with different bytes. Clients connecting throughout receive complete replies, including a
//! client that sends its request after the hub stops accepting. The process stays the same,
//! runs the release, passes its trial and replaces the installed copy. The release completes
//! a web UI sign-in started before the update, and takes the answer to a question asked
//! before it.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vk-hub-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run the built `vk-hub <args> --config <config>` and return stdout, or stderr on failure.
fn try_cli(config: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new(env!("CARGO_BIN_EXE_vk-hub"))
        .args(args)
        .arg("--config")
        .arg(config)
        .output()
        .unwrap();
    if !out.status.success() {
        return Err(format!(
            "vk-hub {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8(out.stdout).unwrap())
}

fn cli(config: &Path, args: &[&str]) -> String {
    try_cli(config, args).unwrap_or_else(|e| panic!("{e}"))
}

/// One request on a connection of its own: whether a whole answer came back.
fn ask(port: u16) -> Result<(), String> {
    let mut stream =
        TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: hub\r\nConnection: close\r\n\r\n")
        .map_err(|e| format!("write: {e}"))?;
    let mut answer = Vec::new();
    stream
        .read_to_end(&mut answer)
        .map_err(|e| format!("read: {e}"))?;
    whole(&answer).ok_or_else(|| format!("answered {:?}", String::from_utf8_lossy(&answer)))
}

/// `Some` when `answer` is a whole HTTP/1.1 response: its head, and the body its
/// `Content-Length` says.
fn whole(answer: &[u8]) -> Option<()> {
    let end = answer.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(answer.get(..end)?)
        .ok()?
        .to_ascii_lowercase();
    let body = answer.get(end + 4..)?;
    if !head.starts_with("http/1.1 ") {
        return None;
    }
    let header = |name: &str| {
        head.lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix(':').map(str::trim))
    };
    // The hub answers these with a length.
    let len = header("content-length")?;
    (len.parse::<usize>().ok()? == body.len()).then_some(())
}

/// `request`, the whole of it, on a connection of its own to `port`: the answer's head and
/// body.
fn http(port: u16, request: &str) -> (String, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).unwrap();
    let answer = String::from_utf8_lossy(&answer).into_owned();
    let (head, body) = answer.split_once("\r\n\r\n").unwrap_or((&answer, ""));
    (head.to_string(), body.to_string())
}

/// An htmx post of the web UI's form `body` to `path` on `port`, with the session cookie
/// `session`: the answer's head and body.
fn post(port: u16, path: &str, session: Option<&str>, body: &str) -> (String, String) {
    let cookie = session.map_or_else(String::new, |c| format!("Cookie: {c}\r\n"));
    http(
        port,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nSec-Fetch-Site: same-origin\r\n\
             HX-Request: true\r\n{cookie}Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
}

/// The value of the hidden field `name` in `html`.
fn field(html: &str, name: &str) -> String {
    let at = format!("name=\"{name}\" value=\"");
    let start = html
        .find(&at)
        .unwrap_or_else(|| panic!("no {name} in {html}"))
        + at.len();
    html[start..].split('"').next().unwrap().to_string()
}

/// Kills the hub however the test ends.
struct Hub(Child);

impl Drop for Hub {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn the_hub_updates_itself_without_refusing_a_connection() {
    let dir = temp_dir("update-e2e");
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    // The installed binary, and the release: the same program, other bytes.
    let built = std::fs::read(env!("CARGO_BIN_EXE_vk-hub")).unwrap();
    let installed = bin.join("vk-hub");
    std::fs::write(&installed, &built).unwrap();
    std::fs::set_permissions(
        &installed,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
    )
    .unwrap();
    let mut release = built;
    release.extend_from_slice(b"\0an update's release");
    let release_file = dir.join("vk-hub-release");
    std::fs::write(&release_file, &release).unwrap();

    // An OIDC provider for the web UI, on a port of its own; the UI is served plain, as behind
    // a proxy ending TLS.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let idp = runtime.block_on(vk_oidc::fake_idp::start(vk_oidc::fake_idp::Options {
        claims: serde_json::json!({
            "sub": "user-42", "email": "alice@example.com", "email_verified": true
        }),
        ..Default::default()
    }));
    let secret = dir.join("oidc-secret");
    std::fs::write(&secret, vk_oidc::fake_idp::CLIENT_SECRET).unwrap();
    std::fs::set_permissions(
        &secret,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
    )
    .unwrap();
    let ui_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    let config = dir.join("hub.toml");
    std::fs::write(
        &config,
        format!(
            "addr = \"127.0.0.1:0\"\ndata_dir = \"{}\"\nrelease_repository = \"none\"\n\
             ui_addr = \"127.0.0.1:{ui_port}\"\nui_url = \"https://127.0.0.1:{ui_port}\"\n\
             [update]\nallow = true\n\
             [oidc]\nissuer = \"http://{idp}\"\nclient_id = \"{}\"\nclient_secret_file = \"{}\"\n",
            dir.join("data").display(),
            vk_oidc::fake_idp::CLIENT_ID,
            secret.display()
        ),
    )
    .unwrap();
    let mut child = Command::new(&installed)
        .arg("serve")
        .arg("--config")
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let stderr = child.stderr.take().unwrap();
    let hub = Hub(child);
    // Its log, kept for a failure, and the port it serves nodes on.
    let log = Arc::new(Mutex::new(String::new()));
    let (port_tx, port_rx) = mpsc::channel();
    std::thread::spawn({
        let log = log.clone();
        move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if let Some(port) = line
                    .strip_prefix("vk-hub: serving nodes on http://127.0.0.1:")
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|p| p.parse::<u16>().ok())
                {
                    let _ = port_tx.send(port);
                }
                let mut log = log.lock().unwrap();
                log.push_str(&line);
                log.push('\n');
            }
        }
    });
    let port = port_rx
        .recv_timeout(Duration::from_secs(60))
        .unwrap_or_else(|_| panic!("the hub did not serve: {}", log.lock().unwrap()));

    let sha = cli(
        &config,
        &[
            "release",
            "add",
            release_file.to_str().unwrap(),
            "--version",
            env!("CARGO_PKG_VERSION"),
            "--program",
            "vk-hub",
        ],
    )
    .trim()
    .to_string();

    cli(
        &config,
        &[
            "accounts",
            "grant",
            "alice@example.com",
            "--role",
            "operator",
        ],
    );
    // A sign-in started before the update: its login cookie names its state.
    let (head, body) = http(
        ui_port,
        &format!(
            "GET /auth/login HTTP/1.1\r\nHost: 127.0.0.1:{ui_port}\r\n\
             Sec-Fetch-Site: same-origin\r\nConnection: close\r\n\r\n"
        ),
    );
    assert!(head.starts_with("HTTP/1.1 302"), "{head}\n{body}");
    let login = head
        .lines()
        .filter_map(|l| l.strip_prefix("set-cookie: "))
        .find(|c| c.starts_with("__Host-vk-hub-login="))
        .and_then(|c| c.split(';').next())
        .unwrap()
        .to_string();
    let state = login.split_once('=').unwrap().1.to_string();
    assert!(!state.is_empty(), "{head}");

    // A question asked before the update: revoking another's grant, from an operator's session.
    cli(
        &config,
        &["accounts", "grant", "bob@example.com", "--role", "viewer"],
    );
    let link = cli(&config, &["ui", "login", "--role", "operator"]);
    let token = link.trim().split_once("?t=").unwrap().1.to_string();
    let (head, body) = post(ui_port, "/login", None, &format!("t={token}"));
    let session = head
        .lines()
        .filter_map(|l| l.strip_prefix("set-cookie: "))
        .find(|c| c.starts_with("__Host-vk-hub="))
        .and_then(|c| c.split(';').next())
        .unwrap_or_else(|| panic!("no session: {head}\n{body}"))
        .to_string();
    let (_, page) = http(
        ui_port,
        &format!(
            "GET /users HTTP/1.1\r\nHost: 127.0.0.1:{ui_port}\r\nSec-Fetch-Site: same-origin\r\n\
             Cookie: {session}\r\nConnection: close\r\n\r\n"
        ),
    );
    let csrf = field(&page, "_csrf");
    let revoke = format!("_csrf={csrf}&op=revoke&email=bob%40example.com");
    let (head, asked) = post(ui_port, "/users", Some(&session), &revoke);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}\n{asked}");
    let confirmed = format!(
        "{revoke}&previous=viewer&confirm=yes&nonce={}",
        field(&asked, "nonce")
    );

    // A client asking all along, each request on a new connection.
    let stop = Arc::new(AtomicBool::new(false));
    let client = std::thread::spawn({
        let stop = stop.clone();
        move || {
            let (mut answered, mut failed) = (0usize, Vec::new());
            while !stop.load(Ordering::SeqCst) {
                match ask(port) {
                    Ok(()) => answered += 1,
                    Err(e) => failed.push(e),
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            (answered, failed)
        }
    });
    std::thread::sleep(Duration::from_millis(500));
    // A connection the hub accepts before it hands over, whose request comes only once it has
    // stopped accepting.
    let mut early = TcpStream::connect(("127.0.0.1", port)).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    cli(&config, &["update", "--release", &sha[..12]]);
    let started = Instant::now();
    while !log.lock().unwrap().contains("stopped accepting") {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the hub did not stop accepting: {}",
            log.lock().unwrap()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    early
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    early
        .write_all(b"GET / HTTP/1.1\r\nHost: hub\r\n\r\n")
        .unwrap();
    let mut answer = Vec::new();
    let _ = early.read_to_end(&mut answer);
    assert!(
        whole(&answer).is_some(),
        "a connection accepted before the hand-over was answered {:?}\n{}",
        String::from_utf8_lossy(&answer),
        log.lock().unwrap()
    );

    // Done once the release has served a while and installed itself.
    let started = Instant::now();
    let status = loop {
        let status = try_cli(&config, &["update"])
            .unwrap_or_else(|e| panic!("{e}\n{}", log.lock().unwrap()));
        if status.contains(" done") {
            break status;
        }
        assert!(
            !status.contains("failed") && !status.contains("rolled back"),
            "{status}\n{}",
            log.lock().unwrap()
        );
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "no update after two minutes: {status}\n{}",
            log.lock().unwrap()
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    // The sign-in started before the update, finished by the release.
    let (head, body) = http(
        ui_port,
        &format!(
            "GET /auth/callback?code=the-code&state={state} HTTP/1.1\r\n\
             Host: 127.0.0.1:{ui_port}\r\nSec-Fetch-Site: cross-site\r\nCookie: {login}\r\n\
             Connection: close\r\n\r\n"
        ),
    );
    assert!(
        head.starts_with("HTTP/1.1 200") && head.contains("set-cookie: __Host-vk-hub="),
        "{head}\n{body}\n{}",
        log.lock().unwrap()
    );
    // The question asked before the update, answered.
    let (head, body) = post(ui_port, "/users", Some(&session), &confirmed);
    assert!(
        head.starts_with("HTTP/1.1 200") && body.contains("Revoked the grant of bob@example.com"),
        "{head}\n{body}\n{}",
        log.lock().unwrap()
    );
    // Served by the release a while longer.
    std::thread::sleep(Duration::from_secs(1));
    stop.store(true, Ordering::SeqCst);
    let (answered, failed) = client.join().unwrap();
    let log = log.lock().unwrap().clone();
    assert!(failed.is_empty(), "refused or cut off: {failed:?}\n{log}");
    assert!(answered > 100, "only {answered} answers\n{log}");
    assert!(status.contains(env!("CARGO_PKG_VERSION")), "{status}");
    assert!(log.contains("executing vk-hub"), "{log}");
    assert!(
        log.contains("serving the nodes listener handed over"),
        "{log}"
    );
    assert!(log.contains("installed vk-hub"), "{log}");
    assert!(
        log.contains("finishing 1 of the 1 sign-in(s) under way handed over"),
        "{log}"
    );
    assert!(
        log.contains("taking over 1 question(s) asked before the update"),
        "{log}"
    );
    // The same process, now running the release, installed over the installed copy.
    assert_eq!(hub.0.id(), pid);
    assert_eq!(std::fs::read(&installed).unwrap(), release, "{log}");
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).unwrap();
    assert!(
        exe.starts_with(dir.join("data")),
        "{} runs, not the release",
        exe.display()
    );
    drop(hub);
    let _ = std::fs::remove_dir_all(&dir);
}
