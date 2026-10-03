//! The qemu-ga channel of an agent-less guest (Windows): the guest agent reads and writes a
//! named virtio-console port, which the boot child bridges to a Unix socket on the host.
//!
//! The port is one end of a socketpair; [`serve`] relays the other end to whichever client is
//! connected to the socket, one at a time, the newest winning. What the guest writes with no
//! client connected is dropped, and the agent's protocol carries no session, so a client
//! starts with `guest-sync-delimited` to discard what an earlier client left in flight.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use anyhow::{Context, Result};

/// The port name qemu-ga opens (`\\.\Global\org.qemu.guest_agent.0` on Windows).
pub const PORT_NAME: &str = "org.qemu.guest_agent.0";

/// Bind `path` (replacing a stale socket from an earlier boot) and relay its client to `guest`
/// on a thread named `thread`, for the life of the process.
///
/// One client at a time; the newest wins. A new connection drops the previous client so a
/// hung or abandoned client cannot lock the channel. A client that stops reading is dropped
/// after [`CLIENT_WRITE_TIMEOUT`]. Guest output with no connected client is dropped; clients
/// resynchronize on connection.
pub fn serve(path: &Path, guest: UnixStream, thread: &str) -> Result<()> {
    let _ = std::fs::remove_file(path);
    let listener = vk_core::unixpath::bind(path)
        .with_context(|| format!("binding the guest agent socket {}", path.display()))?;
    std::thread::Builder::new()
        .name(thread.into())
        .spawn(move || relay(&listener, &guest))
        .context("spawning the guest agent relay")?;
    Ok(())
}

/// How long the relay waits on a client that does not read what the guest sends it.
const CLIENT_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

fn relay(listener: &std::os::unix::net::UnixListener, guest: &UnixStream) {
    let mut client: Option<UnixStream> = None;
    let mut buf = [0u8; 16 * 1024];
    let poll_in = |fd: i32| libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ready =
        |fd: &libc::pollfd| fd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0;
    loop {
        let mut fds = vec![poll_in(listener.as_raw_fd()), poll_in(guest.as_raw_fd())];
        if let Some(c) = &client {
            fds.push(poll_in(c.as_raw_fd()));
        }
        // SAFETY: valid pollfds on fds borrowed for the call.
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) } < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if fds.get(2).is_some_and(ready)
            && let Some(c) = &client
            && !copy(c, guest, &mut buf)
        {
            client = None;
        }
        if ready(&fds[1]) {
            match &client {
                Some(c) => {
                    if !copy(guest, c, &mut buf) {
                        client = None;
                    }
                }
                // Nobody to hand it to.
                None => {
                    if (&*guest).read(&mut buf).is_ok_and(|n| n == 0) {
                        return;
                    }
                }
            }
        }
        if ready(&fds[0])
            && let Ok((c, _)) = listener.accept()
            && c.set_write_timeout(Some(CLIENT_WRITE_TIMEOUT)).is_ok()
        {
            client = Some(c);
        }
    }
}

/// Move ready bytes from `from` to `to`; false at end of stream or on error.
fn copy(mut from: &UnixStream, mut to: &UnixStream, buf: &mut [u8]) -> bool {
    match from.read(buf) {
        Ok(0) | Err(_) => false,
        Ok(n) => to.write_all(&buf[..n]).is_ok(),
    }
}

/// A connection to a guest's qemu-ga through its [`serve`]d socket. Synchronous: one request
/// in flight, each answered before the next. Connecting resynchronizes the stream
/// (`guest-sync-delimited`), dropping whatever an earlier client left unread.
pub struct Client {
    stream: UnixStream,
    buf: Vec<u8>,
    /// a request timed out: its late answer may still come, so resynchronize before the next
    stale: bool,
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
    /// it to answer (it is not up until the guest has booted).
    pub fn connect(socket: &Path, timeout: std::time::Duration) -> Result<Client> {
        let stream = vk_core::unixpath::connect(socket)
            .with_context(|| format!("connecting to the guest agent at {}", socket.display()))?;
        let mut client = Client {
            stream,
            buf: Vec::new(),
            stale: false,
        };
        client.sync(timeout)?;
        Ok(client)
    }

    fn sync(&mut self, timeout: std::time::Duration) -> Result<()> {
        // A per-connection id, so an answer to an earlier client's sync cannot pass for ours.
        let id = (std::process::id() as u64) << 32
            | std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos() as u64);
        let id = id & ((1 << 53) - 1);
        // 0xFF makes the agent drop any partial request; the answer comes after a 0xFF of its own.
        self.stream.write_all(&[0xff])?;
        self.send(
            "guest-sync-delimited",
            Some(serde_json::json!({ "id": id })),
        )?;
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
        self.stream
            .write_all(&line)
            .context("writing to the guest agent")
    }

    /// The next JSON object the agent sends, by `deadline`. The agent ends each with a newline
    /// and, answering a sync, puts a 0xFF before it: what precedes that is an earlier
    /// client's leftover, never valid JSON text (0xFF is not UTF-8).
    fn receive(&mut self, deadline: std::time::Instant) -> Result<serde_json::Value> {
        loop {
            if let Some(end) = self.buf.iter().position(|&b| b == b'\n') {
                let mut line: Vec<u8> = self.buf.drain(..=end).collect();
                if let Some(ff) = line.iter().rposition(|&b| b == 0xff) {
                    line.drain(..=ff);
                }
                let text = String::from_utf8_lossy(&line);
                if text.trim().is_empty() {
                    continue;
                }
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(text.trim()) {
                    return Ok(value);
                }
                continue;
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                anyhow::bail!("timed out waiting for the guest agent");
            }
            self.stream.set_read_timeout(Some(left))?;
            let mut chunk = [0u8; 64 * 1024];
            match self.stream.read(&mut chunk) {
                Ok(0) => anyhow::bail!("the guest agent connection closed"),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => return Err(e).context("reading from the guest agent"),
            }
        }
    }

    /// Run `command` and return its `return` value, or the agent's error.
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
    /// reply, so this only sends the request.
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

    pub fn exec_status(&mut self, pid: i64) -> Result<ExecStatus> {
        let reply = self.call(
            "guest-exec-status",
            Some(serde_json::json!({ "pid": pid })),
            DEFAULT_TIMEOUT,
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

    #[test]
    fn clients_take_turns_on_the_guest_port() {
        let dir = std::env::temp_dir().join(format!("vk-qga-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("qga.sock");
        let (mut port, host) = UnixStream::pair().unwrap();
        serve(&sock, host, "vk-qga-test").unwrap();

        for round in 0..2 {
            let mut client = vk_core::unixpath::connect(&sock).unwrap();
            let request = format!("{{\"execute\":\"guest-ping\",\"id\":{round}}}\n");
            client.write_all(request.as_bytes()).unwrap();
            let mut got = vec![0u8; request.len()];
            port.read_exact(&mut got).unwrap();
            assert_eq!(got, request.as_bytes());

            port.write_all(b"{\"return\": {}}\n").unwrap();
            let mut reply = vec![0u8; 15];
            client.read_exact(&mut reply).unwrap();
            assert_eq!(reply, b"{\"return\": {}}\n");
            // The next round's client gets the port once this one hangs up.
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

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
                    0xff => line.clear(),
                    b'\n' => {
                        let request = serde_json::from_slice(&line).unwrap_or_default();
                        line.clear();
                        if port.write_all(&respond(&request)).is_err() {
                            return;
                        }
                    }
                    b => line.push(b),
                }
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
        };
        client.sync(std::time::Duration::from_secs(5)).unwrap();
        client
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

    #[test]
    fn a_client_that_stops_reading_is_dropped() {
        let dir = std::env::temp_dir().join(format!("vk-qga-stuck-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("qga.sock");
        let (mut port, host) = UnixStream::pair().unwrap();
        serve(&sock, host, "vk-qga-test").unwrap();

        // A client that asks, then never reads the flood the guest answers with.
        let mut stuck = vk_core::unixpath::connect(&sock).unwrap();
        stuck.write_all(b"first\n").unwrap();
        let mut got = [0u8; 6];
        port.read_exact(&mut got).unwrap();
        // More than both socket buffers hold: only dropping the client lets it all through.
        port.write_all(&vec![b'x'; 8 << 20]).unwrap();
        port.write_all(b"\n").unwrap();

        let mut client = vk_core::unixpath::connect(&sock).unwrap();
        client.write_all(b"second\n").unwrap();
        let mut got = [0u8; 7];
        port.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"second\n");
        port.write_all(b"reply\n").unwrap();
        // Possibly behind the end of the flood.
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut reply = Vec::new();
        let mut byte = [0u8; 1];
        while !reply.ends_with(b"reply\n") {
            client.read_exact(&mut byte).unwrap();
            reply.push(byte[0]);
        }
        drop(stuck);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_client_takes_the_port_from_one_that_hangs() {
        let dir = std::env::temp_dir().join(format!("vk-qga-preempt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("qga.sock");
        let (mut port, host) = UnixStream::pair().unwrap();
        serve(&sock, host, "vk-qga-test").unwrap();

        // A client that connects, asks, and then neither reads nor leaves.
        let mut stuck = vk_core::unixpath::connect(&sock).unwrap();
        stuck.write_all(b"first\n").unwrap();
        let mut got = [0u8; 6];
        port.read_exact(&mut got).unwrap();

        let mut client = vk_core::unixpath::connect(&sock).unwrap();
        client.write_all(b"second\n").unwrap();
        let mut got = [0u8; 7];
        port.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"second\n");
        port.write_all(b"reply\n").unwrap();
        let mut reply = [0u8; 6];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"reply\n");
        drop(stuck);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
