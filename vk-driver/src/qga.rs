//! The qemu-ga channel of an agent-less guest (Windows): the guest agent reads and writes a
//! named virtio-console port, which the boot child bridges to a Unix socket on the host.
//!
//! The port is one end of a socketpair; [`crate::relay::serve_agent_socket`] shares the other
//! end among the socket's clients, one request at a time. The agent's protocol carries no
//! session, so a client starts with `guest-sync-delimited`, which also skips an answer still
//! in flight for an earlier one.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use anyhow::{Context, Result};

/// The port name qemu-ga opens (`\\.\Global\org.qemu.guest_agent.0` on Windows).
pub const PORT_NAME: &str = "org.qemu.guest_agent.0";

/// A connection to a guest's qemu-ga through its relayed socket. Synchronous: one request
/// in flight, each answered before the next. Connecting resynchronizes the stream
/// (`guest-sync-delimited`), dropping whatever an earlier client left unread.
pub struct Client {
    stream: UnixStream,
    buf: Vec<u8>,
    /// a request timed out: its late answer may still come, so resynchronize before the next
    stale: bool,
    /// the socket it was connected through, for [`Client::reconnect`]
    socket: std::path::PathBuf,
}

/// The connection to the agent failed: closed, broken, or unanswered in time. Unlike an
/// [`AgentError`], the agent did not answer the request, which a new connection may retry.
#[derive(Debug)]
pub struct Lost;

impl std::fmt::Display for Lost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("lost the guest agent connection")
    }
}

impl std::error::Error for Lost {}

/// `e`, marked as a [`Lost`] connection.
fn lost(e: impl Into<anyhow::Error>) -> anyhow::Error {
    e.into().context(Lost)
}

/// A `guest-sync-delimited` id unlikely to be another connection's, so that an answer to an
/// earlier sync cannot pass for the answer to this one.
pub(crate) fn sync_id() -> u64 {
    let id = (std::process::id() as u64) << 32
        | std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos() as u64);
    // JSON numbers are exact up to 2^53.
    id & ((1 << 53) - 1)
}

/// The request line of a `guest-sync-delimited` with `id`. Its leading 0xFF makes the agent
/// drop any partial request; the answer comes after a 0xFF of its own.
pub(crate) fn sync_request(id: u64) -> Vec<u8> {
    let mut line = vec![0xff];
    line.extend(
        serde_json::json!({ "execute": "guest-sync-delimited", "arguments": { "id": id } })
            .to_string()
            .bytes(),
    );
    line.push(b'\n');
    line
}

/// The JSON object on an answer line from the agent, if any. What precedes a 0xFF is an earlier
/// client's leftover, never valid JSON text (0xFF is not UTF-8).
pub(crate) fn answer(line: &[u8]) -> Option<serde_json::Value> {
    let line = match line.iter().rposition(|&b| b == 0xff) {
        Some(ff) => &line[ff + 1..],
        None => line,
    };
    serde_json::from_slice(line).ok()
}

/// Whether `line` answers the `guest-sync-delimited` with `id`.
pub(crate) fn is_synced(line: &[u8], id: u64) -> bool {
    answer(line).and_then(|a| a.get("return")?.as_u64()) == Some(id)
}

/// How long a request may wait for its answer unless the caller says otherwise.
pub const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// `guest-exec-status`.
#[derive(Debug, Default, serde::Deserialize)]
pub struct ExecStatus {
    pub exited: bool,
    #[serde(default)]
    pub exitcode: Option<i32>,
    /// what a command started with `capture_output` wrote to stderr, in base64
    #[serde(rename = "err-data", default)]
    pub err_data: Option<String>,
}

/// `guest-file-read`.
#[derive(Debug, serde::Deserialize)]
struct FileRead {
    count: usize,
    #[serde(rename = "buf-b64")]
    buf_b64: String,
    eof: bool,
}

/// A qemu-ga error answer (`{"error": {"class": …, "desc": …}}`).
#[derive(Debug)]
pub struct AgentError {
    pub class: String,
    pub desc: String,
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "qemu-ga: {} ({})", self.desc, self.class)
    }
}

impl std::error::Error for AgentError {}

impl Client {
    /// Connect to the agent behind `socket` and resynchronize, waiting up to `timeout` for
    /// it to answer: the socket appears once the VMM is up, the agent once the guest has
    /// booted. Connects again when the relay drops the connection, as it does a sync left
    /// unanswered while the guest boots.
    pub fn connect(socket: &Path, timeout: std::time::Duration) -> Result<Client> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let attempt = vk_core::unixpath::connect(socket)
                .with_context(|| format!("connecting to the guest agent at {}", socket.display()))
                .and_then(|stream| {
                    let mut client = Client {
                        stream,
                        buf: Vec::new(),
                        stale: false,
                        socket: socket.to_path_buf(),
                    };
                    client.sync(deadline.saturating_duration_since(std::time::Instant::now()))?;
                    Ok(client)
                });
            match attempt {
                Ok(client) => return Ok(client),
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Connect again through the same socket, as [`Client::connect`] does.
    pub fn reconnect(&mut self, timeout: std::time::Duration) -> Result<()> {
        *self = Client::connect(&self.socket, timeout)?;
        Ok(())
    }

    fn sync(&mut self, timeout: std::time::Duration) -> Result<()> {
        let id = sync_id();
        self.stream.write_all(&sync_request(id)).map_err(lost)?;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let reply = self
                .receive(deadline)
                .context("guest agent did not answer")?;
            if reply.get("return").and_then(serde_json::Value::as_u64) == Some(id) {
                self.stale = false;
                return Ok(());
            }
        }
    }

    fn send(&mut self, command: &str, arguments: Option<serde_json::Value>) -> Result<()> {
        let mut request = serde_json::json!({ "execute": command });
        if let Some(arguments) = arguments {
            request["arguments"] = arguments;
        }
        let mut line = serde_json::to_vec(&request)?;
        line.push(b'\n');
        self.stream.write_all(&line).map_err(lost)
    }

    /// The next JSON object the agent sends, by `deadline`: each ends with a newline.
    fn receive(&mut self, deadline: std::time::Instant) -> Result<serde_json::Value> {
        loop {
            while let Some(end) = self.buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=end).collect();
                if let Some(value) = answer(&line) {
                    return Ok(value);
                }
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return Err(lost(anyhow::anyhow!("no answer in time")));
            }
            self.stream.set_read_timeout(Some(left)).map_err(lost)?;
            let mut chunk = [0u8; 64 * 1024];
            match self.stream.read(&mut chunk) {
                Ok(0) => return Err(lost(anyhow::anyhow!("closed"))),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => return Err(lost(e)),
            }
        }
    }

    /// Run `command` and return its `return` value, or the agent's error. `timeout` includes
    /// waiting for the relay's turn. A request that times out may still run in the guest.
    pub fn call(
        &mut self,
        command: &str,
        arguments: Option<serde_json::Value>,
        timeout: std::time::Duration,
    ) -> Result<serde_json::Value> {
        if self.stale {
            self.sync(DEFAULT_TIMEOUT)?;
        }
        self.send(command, arguments)?;
        let reply = self
            .receive(std::time::Instant::now() + timeout)
            .inspect_err(|_| self.stale = true)?;
        if let Some(error) = reply.get("error") {
            let field = |k: &str| {
                error
                    .get(k)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            };
            return Err(AgentError {
                class: field("class"),
                desc: field("desc"),
            }
            .into());
        }
        Ok(reply
            .get("return")
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }

    /// Ask the guest to power off (`guest-shutdown`). The agent answers by acting, not with a
    /// reply, so this only sends the request; the relay ignores an error the agent answers.
    pub fn shutdown(&mut self) -> Result<()> {
        self.send(
            "guest-shutdown",
            Some(serde_json::json!({ "mode": "powerdown" })),
        )
    }

    /// Start `path` with `args` in the guest, as the agent's account (SYSTEM on Windows), and
    /// return its pid. With `capture_output`, the agent keeps its output for
    /// [`Client::exec_status`].
    pub fn exec(&mut self, path: &str, args: &[String], capture_output: bool) -> Result<i64> {
        let reply = self.call(
            "guest-exec",
            Some(serde_json::json!({
                "path": path,
                "arg": args,
                "capture-output": capture_output,
            })),
            DEFAULT_TIMEOUT,
        )?;
        reply
            .get("pid")
            .and_then(serde_json::Value::as_i64)
            .context("guest-exec returned no pid")
    }

    /// The status of the command `pid`. The agent forgets a command once it has said it exited,
    /// so when that answer is lost (it came too late), asking again gets an [`AgentError`].
    pub fn exec_status(&mut self, pid: i64) -> Result<ExecStatus> {
        let reply = self.call(
            "guest-exec-status",
            Some(serde_json::json!({ "pid": pid })),
            DEFAULT_TIMEOUT,
        )?;
        Ok(serde_json::from_value(reply)?)
    }

    /// [`Client::exec`] without output, waiting at most `timeout` for the agent's answer.
    pub fn exec_within(
        &mut self,
        path: &str,
        args: &[String],
        timeout: std::time::Duration,
    ) -> Result<i64> {
        let reply = self.call(
            "guest-exec",
            Some(serde_json::json!({ "path": path, "arg": args })),
            timeout,
        )?;
        reply
            .get("pid")
            .and_then(serde_json::Value::as_i64)
            .context("guest-exec returned no pid")
    }

    /// [`Client::exec_status`], waiting at most `timeout` for the agent's answer.
    pub fn exec_status_within(
        &mut self,
        pid: i64,
        timeout: std::time::Duration,
    ) -> Result<ExecStatus> {
        let reply = self.call(
            "guest-exec-status",
            Some(serde_json::json!({ "pid": pid })),
            timeout,
        )?;
        Ok(serde_json::from_value(reply)?)
    }

    /// Open `path` in the guest with an `fopen` mode, returning the agent's handle.
    pub fn file_open(&mut self, path: &str, mode: &str) -> Result<i64> {
        let reply = self.call(
            "guest-file-open",
            Some(serde_json::json!({ "path": path, "mode": mode })),
            DEFAULT_TIMEOUT,
        )?;
        reply.as_i64().context("guest-file-open returned no handle")
    }

    /// Up to `count` bytes from `handle`, and whether the end of the file was reached.
    pub fn file_read(&mut self, handle: i64, count: usize) -> Result<(Vec<u8>, bool)> {
        let reply = self.call(
            "guest-file-read",
            Some(serde_json::json!({ "handle": handle, "count": count })),
            DEFAULT_TIMEOUT,
        )?;
        let read: FileRead = serde_json::from_value(reply)?;
        let bytes = crate::sshagent::b64_decode(&read.buf_b64)
            .context("guest-file-read returned bad base64")?;
        if bytes.len() != read.count {
            anyhow::bail!(
                "guest-file-read returned {} bytes, said {}",
                bytes.len(),
                read.count
            );
        }
        Ok((bytes, read.eof))
    }

    /// Move `handle`'s position to `offset` bytes from the start of the file.
    pub fn file_seek(&mut self, handle: i64, offset: u64) -> Result<()> {
        self.call(
            "guest-file-seek",
            Some(serde_json::json!({ "handle": handle, "offset": offset, "whence": "set" })),
            DEFAULT_TIMEOUT,
        )
        .map(drop)
    }

    pub fn file_write(&mut self, handle: i64, bytes: &[u8]) -> Result<()> {
        let buf = crate::sshagent::b64_encode(bytes);
        let reply = self.call(
            "guest-file-write",
            Some(serde_json::json!({ "handle": handle, "buf-b64": buf })),
            DEFAULT_TIMEOUT,
        )?;
        let written = reply.get("count").and_then(serde_json::Value::as_u64);
        if written != Some(bytes.len() as u64) {
            anyhow::bail!(
                "guest-file-write wrote {written:?} of {} bytes",
                bytes.len()
            );
        }
        Ok(())
    }

    pub fn file_close(&mut self, handle: i64) -> Result<()> {
        self.call(
            "guest-file-close",
            Some(serde_json::json!({ "handle": handle })),
            DEFAULT_TIMEOUT,
        )
        .map(drop)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A guest agent on `port` answering each request with what `respond` makes of it.
    fn fake_agent(
        mut port: UnixStream,
        respond: impl Fn(&serde_json::Value) -> Vec<u8> + Send + 'static,
    ) {
        std::thread::spawn(move || {
            let mut line = Vec::new();
            let mut byte = [0u8; 1];
            while port.read_exact(&mut byte).is_ok() {
                match byte[0] {
                    // As qemu-ga, which answers a 0xFF it reads as a parse error.
                    0xff => {
                        line.clear();
                        if port.write_all(STRAY_FF).is_err() {
                            return;
                        }
                    }
                    b'\n' => {
                        let request = serde_json::from_slice(&line).unwrap_or_default();
                        line.clear();
                        let reply = respond(&request);
                        if reply == HANG_UP || port.write_all(&reply).is_err() {
                            return;
                        }
                    }
                    b => line.push(b),
                }
            }
        });
    }

    /// What qemu-ga answers a 0xFF with.
    pub(crate) const STRAY_FF: &[u8] =
        b"{\"error\": {\"class\": \"GenericError\", \"desc\": \"JSON parse error, stray '\\uFFFD'\"}}\n";

    /// What a fake agent's `respond` returns to close the connection instead of answering.
    pub(crate) const HANG_UP: &[u8] = b"\0hang up\0";

    /// A temporary directory, removed when dropped.
    pub(crate) struct TempDir(pub std::path::PathBuf);

    impl TempDir {
        pub(crate) fn new(name: &str) -> TempDir {
            let dir = std::env::temp_dir().join(format!("vk-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A socket at `path` where each connection gets a fake agent running `respond`, as a
    /// guest agent reached through a relay that may drop a connection.
    pub(crate) fn agent_socket(
        path: &Path,
        respond: impl Fn(&serde_json::Value) -> Vec<u8> + Send + Sync + 'static,
    ) {
        let listener = std::os::unix::net::UnixListener::bind(path).unwrap();
        let respond = std::sync::Arc::new(respond);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let respond = respond.clone();
                fake_agent(stream.unwrap(), move |request| respond(request));
            }
        });
    }

    /// What qemu-ga answers `guest-sync-delimited` with.
    pub(crate) fn synced(request: &serde_json::Value) -> Vec<u8> {
        let mut reply = vec![0xff];
        reply.extend(format!("{{\"return\": {}}}\n", request["arguments"]["id"]).bytes());
        reply
    }

    /// A [`Client`] on one end of a socketpair whose other end runs `respond` as the agent.
    pub(crate) fn client(
        respond: impl Fn(&serde_json::Value) -> Vec<u8> + Send + 'static,
    ) -> Client {
        let (port, stream) = UnixStream::pair().unwrap();
        fake_agent(port, respond);
        let mut client = Client {
            stream,
            buf: Vec::new(),
            stale: false,
            socket: std::path::PathBuf::new(),
        };
        client.sync(std::time::Duration::from_secs(5)).unwrap();
        client
    }

    #[test]
    fn clients_share_the_agent_request_by_request() {
        let dir = TempDir::new("qga-share");
        let sock = dir.0.join("qga.sock");
        let (port, host) = UnixStream::pair().unwrap();
        crate::relay::serve_agent_socket(&sock, host, "vk-qga-test").unwrap();
        // Echoes each request's arguments.
        fake_agent(port, |request| match request["execute"].as_str() {
            Some("guest-sync-delimited") => synced(request),
            _ => format!(
                "{}\n",
                serde_json::json!({ "return": request["arguments"] })
            )
            .into_bytes(),
        });

        // One that connects and never asks blocks no one.
        let _idle = vk_core::unixpath::connect(&sock).unwrap();
        let clients: Vec<_> = (0..2)
            .map(|client| {
                let sock = sock.clone();
                std::thread::spawn(move || {
                    let mut ga = Client::connect(&sock, DEFAULT_TIMEOUT).unwrap();
                    for n in 0..50 {
                        let asked = serde_json::json!({ "client": client, "n": n });
                        let answer = ga.call("echo", Some(asked.clone()), DEFAULT_TIMEOUT);
                        assert_eq!(answer.unwrap(), asked);
                    }
                })
            })
            .collect();
        for client in clients {
            client.join().unwrap();
        }
    }

    #[test]
    fn a_dropped_connection_is_lost_and_an_agent_error_is_not() {
        let mut ga = client(|request| match request["execute"].as_str() {
            Some("guest-sync-delimited") => synced(request),
            Some("refused") => {
                b"{\"error\": {\"class\": \"GenericError\", \"desc\": \"no\"}}\n".to_vec()
            }
            _ => HANG_UP.to_vec(),
        });
        let refused = ga.call("refused", None, DEFAULT_TIMEOUT).unwrap_err();
        assert!(refused.downcast_ref::<Lost>().is_none());
        let dropped = ga.call("guest-ping", None, DEFAULT_TIMEOUT).unwrap_err();
        assert!(dropped.downcast_ref::<Lost>().is_some(), "{dropped:#}");
    }

    #[test]
    fn a_sync_skips_what_an_earlier_client_left_in_flight() {
        let ga = |request: &serde_json::Value| match request["execute"].as_str() {
            Some("guest-sync-delimited") => {
                // A stale answer, then half of one, then this sync's own.
                let mut reply = b"{\"return\": 1}\n{\"return\": {\"pi".to_vec();
                reply.extend(synced(request));
                reply
            }
            _ => b"{\"return\": {}}\n".to_vec(),
        };
        let mut ga = client(ga);
        let pong = ga.call("guest-ping", None, DEFAULT_TIMEOUT).unwrap();
        assert_eq!(pong, serde_json::json!({}));
    }

    #[test]
    fn an_agent_error_comes_back_as_one() {
        let mut ga = client(|request| match request["execute"].as_str() {
            Some("guest-sync-delimited") => synced(request),
            _ => b"{\"error\": {\"class\": \"GenericError\", \"desc\": \"no file\"}}\n".to_vec(),
        });
        let e = ga.file_open(r"C:\nope", "rb").unwrap_err();
        let e = e.downcast_ref::<AgentError>().unwrap();
        assert_eq!(
            (e.class.as_str(), e.desc.as_str()),
            ("GenericError", "no file")
        );
    }

    #[test]
    fn a_file_read_decodes_its_base64_and_checks_its_count() {
        let mut ga = client(|request| match request["execute"].as_str() {
            Some("guest-sync-delimited") => synced(request),
            _ => {
                let count = request["arguments"]["count"].as_u64().unwrap();
                format!(
                    "{{\"return\": {{\"count\": {count}, \"buf-b64\": \"YWJj\", \"eof\": true}}}}\n"
                )
                .into_bytes()
            }
        });
        assert_eq!(ga.file_read(1, 3).unwrap(), (b"abc".to_vec(), true));
        assert!(ga.file_read(1, 4).is_err());
    }

    #[test]
    fn a_late_answer_is_not_taken_for_the_next_one() {
        let mut ga = client(|request| match request["execute"].as_str() {
            Some("guest-sync-delimited") => synced(request),
            Some("slow") => {
                std::thread::sleep(std::time::Duration::from_millis(300));
                b"{\"return\": \"slow\"}\n".to_vec()
            }
            _ => b"{\"return\": \"fast\"}\n".to_vec(),
        });
        let short = std::time::Duration::from_millis(50);
        assert!(ga.call("slow", None, short).is_err());
        let reply = ga.call("fast", None, DEFAULT_TIMEOUT).unwrap();
        assert_eq!(reply, "fast");
    }

    /// A qemu-ga of the host's own, listening on a socket in a directory of the test's.
    struct RealAgent {
        child: std::process::Child,
        socket: std::path::PathBuf,
    }

    impl Drop for RealAgent {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// qemu-ga started in `dir`, with the commands that stop or freeze the host blocked; `None`
    /// when it is not installed or does not start.
    fn real_agent(dir: &Path) -> Option<RealAgent> {
        let path = std::env::var_os("PATH").unwrap_or_default();
        let bin = std::env::split_paths(&path)
            .chain(["/usr/sbin".into(), "/sbin".into()])
            .map(|dir| dir.join("qemu-ga"))
            .find(|bin| bin.is_file())?;
        let conf = dir.join("qemu-ga.conf");
        std::fs::write(&conf, "").ok()?;
        let socket = dir.join("ga.sock");
        let child = std::process::Command::new(bin)
            .arg("--config")
            .arg(&conf)
            .args(["--method", "unix-listen", "--path"])
            .arg(&socket)
            .arg("--pidfile")
            .arg(dir.join("ga.pid"))
            .arg("--statedir")
            .arg(dir)
            .arg("--logfile")
            .arg(dir.join("ga.log"))
            .arg(
                "--block-rpcs=guest-shutdown,guest-suspend-disk,guest-suspend-ram,\
                 guest-suspend-hybrid,guest-fsfreeze-freeze,guest-fsfreeze-freeze-list,\
                 guest-set-time",
            )
            .spawn()
            .ok()?;
        let agent = RealAgent { child, socket };
        for _ in 0..50 {
            if UnixStream::connect(&agent.socket).is_ok() {
                return Some(agent);
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        None
    }

    #[test]
    fn a_real_qemu_ga_serves_clients_through_the_relay() {
        let dir = TempDir::new("qga-real");
        let Some(agent) = real_agent(&dir.0) else {
            eprintln!("skipped: no qemu-ga to run");
            return;
        };
        let pong = serde_json::json!({});
        // Directly: qemu-ga answers the 0xFF leading a sync with an error line of its own.
        let mut direct = Client::connect(&agent.socket, DEFAULT_TIMEOUT).unwrap();
        assert_eq!(
            direct.call("guest-ping", None, DEFAULT_TIMEOUT).unwrap(),
            pong
        );
        drop(direct);

        // qemu-ga takes a connection once the previous one has closed.
        let guest = UnixStream::connect(&agent.socket).unwrap();
        let relay = dir.0.join("qga.sock");
        crate::relay::serve_agent_socket(&relay, guest, "vk-qga-real").unwrap();
        let clients: Vec<_> = (0..2)
            .map(|n| {
                let relay = relay.clone();
                let file = dir.0.join(format!("file{n}"));
                let pong = pong.clone();
                std::thread::spawn(move || {
                    let mut ga = Client::connect(&relay, DEFAULT_TIMEOUT).unwrap();
                    for _ in 0..20 {
                        assert_eq!(ga.call("guest-ping", None, DEFAULT_TIMEOUT).unwrap(), pong);
                    }
                    let handle = ga.file_open(file.to_str().unwrap(), "w+").unwrap();
                    ga.file_write(handle, b"hello, agent").unwrap();
                    ga.file_seek(handle, 7).unwrap();
                    assert_eq!(ga.file_read(handle, 64).unwrap(), (b"agent".to_vec(), true));
                    ga.file_close(handle).unwrap();

                    let script = format!("echo {n} >&2; exit {n}");
                    let pid = ga.exec("/bin/sh", &["-c".into(), script], true).unwrap();
                    let status = loop {
                        let status = ga.exec_status(pid).unwrap();
                        if status.exited {
                            break status;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    };
                    assert_eq!(status.exitcode, Some(n));
                    let stderr = crate::sshagent::b64_decode(&status.err_data.unwrap()).unwrap();
                    assert_eq!(stderr, format!("{n}\n").as_bytes());
                })
            })
            .collect();
        for client in clients {
            client.join().unwrap();
        }

        // vk's own helpers, where they are not Windows' alone.
        let mut ga = Client::connect(&relay, DEFAULT_TIMEOUT).unwrap();
        let code = crate::winexec::run_program(&mut ga, "/bin/sh", &["-c", "exit 3"]).unwrap();
        assert_eq!(code, 3);
        let bytes: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let (local, remote, back) = (
            dir.0.join("local"),
            dir.0.join("remote"),
            dir.0.join("back"),
        );
        std::fs::write(&local, &bytes).unwrap();
        let remote = remote.to_str().unwrap();
        assert_eq!(
            crate::winexec::copy_in(&relay, &local, remote).unwrap(),
            200_000
        );
        assert_eq!(
            crate::winexec::copy_out(&relay, remote, &back).unwrap(),
            200_000
        );
        assert_eq!(std::fs::read(&back).unwrap(), bytes);

        // A shutdown the agent refuses (blocked here) leaves no answer to misroute.
        ga.shutdown().unwrap();
        assert_eq!(ga.call("guest-ping", None, DEFAULT_TIMEOUT).unwrap(), pong);
    }
}
