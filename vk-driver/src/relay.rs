//! The boot child relays a Unix socket to a socketpair whose other end the VMM holds.
//! This serves COM1's input (`vk console`) and, shared among its clients, a UEFI guest's
//! qemu-ga port ([`crate::qga`]).

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

/// Bind `path` (replacing a stale socket from an earlier boot) and relay its client to `guest`
/// on a thread named `thread`, for the life of the process.
///
/// One client at a time; the newest wins. A new connection drops the previous client so a
/// hung or abandoned client cannot lock the channel. A client that stops reading is dropped
/// after [`CLIENT_WRITE_TIMEOUT`]. Guest output with no connected client is dropped.
pub fn serve_socket(path: &Path, guest: UnixStream, thread: &str) -> Result<()> {
    let _ = std::fs::remove_file(path);
    let listener =
        vk_core::unixpath::bind(path).with_context(|| format!("binding {}", path.display()))?;
    std::thread::Builder::new()
        .name(thread.into())
        .spawn(move || relay(&listener, &guest))
        .context("spawning the socket relay")?;
    Ok(())
}

/// How long the relay waits on a client that does not read what the guest sends it.
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

fn relay(listener: &UnixListener, guest: &UnixStream) {
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

/// Bind `path` (replacing a stale socket from an earlier boot) and share qemu-ga's port `guest`
/// among its clients on a thread named `thread`, for the life of the process.
///
/// qemu-ga answers each JSON object it reads with one line, so clients take turns request by
/// request: a client's request goes to the agent once the previous one is answered, and its
/// answer to that client alone. A request is a line holding one JSON object, after any leading
/// 0xFF (which only makes the agent answer an extra error line); the relay answers any other
/// line with an error itself and ignores a blank one. A client that stays connected without
/// asking blocks no one; one that shuts down its sending side is still answered what it sent;
/// the answer to a client that left is dropped. A client that does not read its answer is
/// dropped after [`CLIENT_WRITE_TIMEOUT`]. At most [`MAX_CLIENTS`] are served at once.
///
/// After [`REPLY_TIMEOUT`] without an answer, the relay drops the client and resynchronizes
/// with the agent (`guest-sync-delimited`) before the next request, discarding late answers.
/// The request may still run late, once the guest reads what the port buffered. A [`NO_REPLY`]
/// command, answered by the agent only if it fails, is followed by such a sync at once.
///
/// Waiting for a turn counts against each client's timeout, so one slow request can make
/// others give up. A stop asking qemu-ga to shut down while another request holds the agent
/// exhausts its connect budget, leaving the VMM to be killed at the end of its grace.
pub fn serve_agent_socket(path: &Path, guest: UnixStream, thread: &str) -> Result<()> {
    let _ = std::fs::remove_file(path);
    let listener =
        vk_core::unixpath::bind(path).with_context(|| format!("binding {}", path.display()))?;
    std::thread::Builder::new()
        .name(thread.into())
        .spawn(move || Relay::new(&guest, REPLY_TIMEOUT).run(&listener))
        .context("spawning the guest agent relay")?;
    Ok(())
}

/// How long a request may hold the agent: as long as [`crate::qga::Client`] waits by default.
const REPLY_TIMEOUT: Duration = crate::qga::DEFAULT_TIMEOUT;

/// The most a client may have sent that has not gone to the agent yet. vk's largest request, a
/// 48 KiB `guest-file-write` in base64, is far below; qemu's JSON parser takes up to 64 MiB.
const MAX_REQUEST: usize = 256 << 10;

/// The longest answer line the relay holds: qemu-ga keeps up to 16 MiB of a command's output
/// for `guest-exec-status`, and base64 makes it a third larger.
const MAX_ANSWER: usize = 32 << 20;

/// How many clients the relay serves at once; it refuses more connections.
const MAX_CLIENTS: usize = 64;

/// The commands qemu-ga answers by acting, with no reply unless they fail.
const NO_REPLY: [&str; 4] = [
    "guest-shutdown",
    "guest-suspend-disk",
    "guest-suspend-ram",
    "guest-suspend-hybrid",
];

/// What the agent's next answer line is for.
#[derive(Clone, Copy, PartialEq)]
enum Awaiting {
    /// nothing: the next request may go
    Nothing,
    /// a request of the client with this key, or of none once it left
    Answer(Option<u64>),
    /// the relay's own `guest-sync-delimited` with this id; anything before its answer is dropped
    Sync(u64),
}

/// A client line, as the relay reads it.
enum Request<'a> {
    /// nothing to send: the agent would answer nothing
    Blank,
    /// one JSON object, to send as is
    Execute { json: &'a [u8], no_reply: bool },
    /// anything else, which the relay answers with this error in the agent's stead
    Invalid(String),
}

impl Request<'_> {
    fn parse(line: &[u8]) -> Request<'_> {
        let mut json = line;
        while let [0xff, rest @ ..] = json {
            json = rest;
        }
        let json = json.trim_ascii();
        if json.is_empty() {
            return Request::Blank;
        }
        match serde_json::from_slice::<serde_json::Value>(json) {
            Ok(serde_json::Value::Object(request)) => Request::Execute {
                json,
                no_reply: request
                    .get("execute")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|command| NO_REPLY.contains(&command)),
            },
            Ok(_) => Request::Invalid("a request must be a JSON object".into()),
            Err(e) => Request::Invalid(format!("a request must be one JSON object per line: {e}")),
        }
    }
}

/// A client of the relay.
struct Peer {
    stream: UnixStream,
    /// what it sent that has not gone to the agent yet
    pending: Vec<u8>,
    /// it shut down its sending side: it leaves once what it sent is answered
    eof: bool,
}

/// The state of [`serve_agent_socket`]'s relay.
struct Relay<'a> {
    guest: &'a UnixStream,
    timeout: Duration,
    clients: BTreeMap<u64, Peer>,
    next_key: u64,
    /// the client whose request went last, for round-robin turns
    last: u64,
    awaiting: Awaiting,
    /// when what the relay awaits is late
    deadline: Instant,
    /// the agent's output not yet split into lines
    from_guest: Vec<u8>,
}

impl<'a> Relay<'a> {
    fn new(guest: &'a UnixStream, timeout: Duration) -> Relay<'a> {
        Relay {
            guest,
            timeout,
            clients: BTreeMap::new(),
            next_key: 0,
            last: 0,
            awaiting: Awaiting::Nothing,
            deadline: Instant::now(),
            from_guest: Vec::new(),
        }
    }

    /// Serve the clients of `listener` until the agent's end closes or fails.
    fn run(mut self, listener: &UnixListener) {
        let mut buf = vec![0u8; 64 * 1024];
        while self.step(listener, &mut buf).is_ok() {}
    }

    fn step(&mut self, listener: &UnixListener, buf: &mut [u8]) -> std::io::Result<()> {
        self.next_request()?;
        // A client that has shut down its sending side leaves once it has nothing left to ask
        // and nothing to be answered.
        let awaiting = self.awaiting;
        self.clients.retain(|&key, peer| {
            !peer.eof || peer.pending.contains(&b'\n') || awaiting == Awaiting::Answer(Some(key))
        });

        let poll_in = |fd: i32| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let (keys, client_fds): (Vec<u64>, Vec<libc::pollfd>) = self
            .clients
            .iter()
            .filter(|(_, peer)| !peer.eof)
            .map(|(&key, peer)| (key, poll_in(peer.stream.as_raw_fd())))
            .unzip();
        let mut fds = vec![
            poll_in(listener.as_raw_fd()),
            poll_in(self.guest.as_raw_fd()),
        ];
        fds.extend(client_fds);
        let wait = match self.awaiting {
            Awaiting::Nothing => -1,
            _ => self
                .deadline
                .saturating_duration_since(Instant::now())
                .as_nanos()
                .div_ceil(1_000_000)
                .min(i32::MAX as u128) as i32,
        };
        // SAFETY: valid pollfds on fds borrowed for the call.
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, wait) } < 0 {
            let e = std::io::Error::last_os_error();
            return match e.kind() {
                std::io::ErrorKind::Interrupted => Ok(()),
                _ => Err(e),
            };
        }
        let ready =
            |fd: &libc::pollfd| fd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0;

        if ready(&fds[1]) {
            match self.guest.read(buf)? {
                0 => return Err(std::io::ErrorKind::UnexpectedEof.into()),
                n => self.on_agent_output(&buf[..n])?,
            }
        }
        // By key: answering may have dropped a client polled here.
        for (key, fd) in keys.into_iter().zip(&fds[2..]) {
            if ready(fd) && self.clients.contains_key(&key) {
                self.on_client_readable(key, buf);
            }
        }
        if ready(&fds[0])
            && let Ok((stream, _)) = listener.accept()
            && self.clients.len() < MAX_CLIENTS
            && stream.set_write_timeout(Some(CLIENT_WRITE_TIMEOUT)).is_ok()
        {
            self.next_key += 1;
            let peer = Peer {
                stream,
                pending: Vec::new(),
                eof: false,
            };
            self.clients.insert(self.next_key, peer);
        }
        self.on_timeout()
    }

    /// While the agent is free, send it the next request in turn.
    fn next_request(&mut self) -> std::io::Result<()> {
        while self.awaiting == Awaiting::Nothing
            && let Some((key, line)) = self.next_line()
        {
            match Request::parse(&line) {
                Request::Blank => {}
                Request::Invalid(desc) => {
                    let error = serde_json::json!({
                        "error": { "class": "GenericError", "desc": desc }
                    });
                    let reply = format!("{error}\n");
                    if let Some(peer) = self.clients.get(&key)
                        && (&peer.stream).write_all(reply.as_bytes()).is_err()
                    {
                        self.clients.remove(&key);
                    }
                }
                Request::Execute { json, no_reply } => {
                    self.guest.write_all(&[json, b"\n"].concat())?;
                    if no_reply {
                        self.resync()?;
                    } else {
                        self.awaiting = Awaiting::Answer(Some(key));
                        self.deadline = Instant::now() + self.timeout;
                    }
                }
            }
        }
        Ok(())
    }

    /// The next client in turn with a whole line, and that line.
    fn next_line(&mut self) -> Option<(u64, Vec<u8>)> {
        let has_line = |(_, peer): &(&u64, &Peer)| peer.pending.contains(&b'\n');
        let key = *self
            .clients
            .range(self.last + 1..)
            .chain(&self.clients)
            .find(has_line)?
            .0;
        let pending = &mut self.clients.get_mut(&key)?.pending;
        let end = pending.iter().position(|&b| b == b'\n')?;
        self.last = key;
        Some((key, pending.drain(..=end).collect()))
    }

    fn on_agent_output(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.from_guest.extend_from_slice(bytes);
        while let Some(end) = self.from_guest.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.from_guest.drain(..=end).collect();
            self.on_agent_line(&line);
        }
        if self.from_guest.len() > MAX_ANSWER {
            // Its end will read as a line nobody waits for.
            self.from_guest.clear();
            self.abandon()?;
        }
        Ok(())
    }

    fn on_agent_line(&mut self, line: &[u8]) {
        match self.awaiting {
            Awaiting::Answer(owner) => {
                if let Some(key) = owner
                    && let Some(peer) = self.clients.get(&key)
                    && (&peer.stream).write_all(line).is_err()
                {
                    self.clients.remove(&key);
                }
                self.awaiting = Awaiting::Nothing;
            }
            Awaiting::Sync(id) if crate::qga::is_synced(line, id) => {
                self.awaiting = Awaiting::Nothing;
            }
            // An answer nobody waits for any more.
            Awaiting::Sync(_) | Awaiting::Nothing => {}
        }
    }

    fn on_client_readable(&mut self, key: u64, buf: &mut [u8]) {
        let Some(peer) = self.clients.get_mut(&key) else {
            return;
        };
        let open = match (&peer.stream).read(buf) {
            Ok(0) => {
                peer.eof = true;
                true
            }
            Ok(n) => {
                peer.pending.extend_from_slice(&buf[..n]);
                peer.pending.len() <= MAX_REQUEST
            }
            Err(_) => false,
        };
        if !open {
            self.clients.remove(&key);
            if self.awaiting == Awaiting::Answer(Some(key)) {
                self.awaiting = Awaiting::Answer(None);
            }
        }
    }

    fn on_timeout(&mut self) -> std::io::Result<()> {
        if self.awaiting != Awaiting::Nothing && Instant::now() >= self.deadline {
            self.abandon()?;
        }
        Ok(())
    }

    /// Give up on what the agent was to answer: drop the client it was for, and resynchronize.
    fn abandon(&mut self) -> std::io::Result<()> {
        if let Awaiting::Answer(Some(key)) = self.awaiting {
            self.clients.remove(&key);
        }
        self.resync()
    }

    /// Send the agent a `guest-sync-delimited` that skips whatever it answers before.
    fn resync(&mut self) -> std::io::Result<()> {
        let id = crate::qga::sync_id();
        self.guest.write_all(&crate::qga::sync_request(id))?;
        self.awaiting = Awaiting::Sync(id);
        self.deadline = Instant::now() + self.timeout;
        Ok(())
    }
}

/// Move ready bytes from `from` to `to`; false at end of stream or on error.
fn copy(mut from: &UnixStream, mut to: &UnixStream, buf: &mut [u8]) -> bool {
    match from.read(buf) {
        Ok(0) | Err(_) => false,
        Ok(n) => to.write_all(&buf[..n]).is_ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clients_take_turns_on_the_port() {
        let dir = std::env::temp_dir().join(format!("vk-relay-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("relay.sock");
        let (mut port, host) = UnixStream::pair().unwrap();
        serve_socket(&sock, host, "vk-relay-test").unwrap();

        for round in 0..2 {
            let mut client = vk_core::unixpath::connect(&sock).unwrap();
            let request = format!("request {round}\n");
            client.write_all(request.as_bytes()).unwrap();
            let mut got = vec![0u8; request.len()];
            port.read_exact(&mut got).unwrap();
            assert_eq!(got, request.as_bytes());

            port.write_all(b"reply\n").unwrap();
            let mut reply = [0u8; 6];
            client.read_exact(&mut reply).unwrap();
            assert_eq!(&reply, b"reply\n");
            // The next round's client gets the port once this one hangs up.
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_client_that_stops_reading_is_dropped() {
        let dir = std::env::temp_dir().join(format!("vk-relay-stuck-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("relay.sock");
        let (mut port, host) = UnixStream::pair().unwrap();
        serve_socket(&sock, host, "vk-relay-test").unwrap();

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
        let dir = std::env::temp_dir().join(format!("vk-relay-preempt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("relay.sock");
        let (mut port, host) = UnixStream::pair().unwrap();
        serve_socket(&sock, host, "vk-relay-test").unwrap();

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

    /// The qemu-ga relay on a socket in `dir`, with `timeout` for answers, and its agent's end.
    fn shared(dir: &Path, timeout: Duration) -> (std::path::PathBuf, UnixStream) {
        let sock = dir.join("qga.sock");
        let listener = vk_core::unixpath::bind(&sock).unwrap();
        let (port, host) = UnixStream::pair().unwrap();
        std::thread::spawn(move || Relay::new(&host, timeout).run(&listener));
        (sock, port)
    }

    /// The request line running `command`.
    fn request(command: &str) -> Vec<u8> {
        format!("{{\"execute\":\"{command}\"}}\n").into_bytes()
    }

    /// The next line from `from`, newline included.
    fn line(mut from: &UnixStream) -> Vec<u8> {
        from.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        while !line.ends_with(b"\n") {
            from.read_exact(&mut byte).unwrap();
            line.push(byte[0]);
        }
        line
    }

    /// The `guest-sync-delimited` the relay sent the agent, read from `port`.
    fn relay_sync(port: &UnixStream) -> serde_json::Value {
        let line = line(port);
        assert_eq!(line[0], 0xff);
        let sync: serde_json::Value = serde_json::from_slice(&line[1..]).unwrap();
        assert_eq!(sync["execute"], "guest-sync-delimited");
        sync
    }

    #[test]
    fn the_answer_to_a_client_that_left_goes_to_no_one() {
        let dir = crate::qga::tests::TempDir::new("relay-left");
        let (sock, mut port) = shared(&dir.0, Duration::from_secs(5));

        let mut left = vk_core::unixpath::connect(&sock).unwrap();
        left.write_all(&request("a")).unwrap();
        assert_eq!(line(&port), request("a"));
        drop(left);
        let mut client = vk_core::unixpath::connect(&sock).unwrap();
        client.write_all(&request("b")).unwrap();
        // Its request waits for the answer to the first.
        port.write_all(b"answer a\n").unwrap();
        assert_eq!(line(&port), request("b"));
        port.write_all(b"answer b\n").unwrap();
        assert_eq!(line(&client), b"answer b\n");
    }

    #[test]
    fn an_unanswered_request_costs_its_client_and_the_relay_resyncs() {
        let dir = crate::qga::tests::TempDir::new("relay-unanswered");
        let (sock, mut port) = shared(&dir.0, Duration::from_millis(200));

        let mut stuck = vk_core::unixpath::connect(&sock).unwrap();
        stuck.write_all(&request("a")).unwrap();
        assert_eq!(line(&port), request("a"));
        let mut client = vk_core::unixpath::connect(&sock).unwrap();
        client.write_all(&request("b")).unwrap();

        let sync = relay_sync(&port);
        let mut gone = [0u8; 1];
        assert_eq!(stuck.read(&mut gone).unwrap(), 0);
        // The late answer, the error for the sync's 0xFF, then the sync's answer.
        port.write_all(b"answer a\n").unwrap();
        port.write_all(crate::qga::tests::STRAY_FF).unwrap();
        port.write_all(&crate::qga::tests::synced(&sync)).unwrap();
        assert_eq!(line(&port), request("b"));
        port.write_all(b"answer b\n").unwrap();
        assert_eq!(line(&client), b"answer b\n");
    }

    #[test]
    fn a_line_that_is_not_one_json_object_is_answered_by_the_relay() {
        let dir = crate::qga::tests::TempDir::new("relay-invalid");
        let (sock, mut port) = shared(&dir.0, Duration::from_secs(5));

        let mut client = vk_core::unixpath::connect(&sock).unwrap();
        // Blank lines get no answer, as from the agent.
        client
            .write_all(b"hello\n\n{\"execute\":\"a\"}{\"execute\":\"b\"}\n \xff\n[1]\n")
            .unwrap();
        for _ in 0..4 {
            let error: serde_json::Value = serde_json::from_slice(&line(&client)).unwrap();
            assert_eq!(error["error"]["class"], "GenericError");
        }
        // The agent saw none of it, and gets a client's sync without its 0xFF.
        let sync = crate::qga::sync_request(7);
        client.write_all(&sync).unwrap();
        assert_eq!(line(&port), sync[1..]);
        port.write_all(b"\xff{\"return\": 7}\n").unwrap();
        assert_eq!(line(&client), b"\xff{\"return\": 7}\n");
    }

    #[test]
    fn pipelined_requests_are_answered_in_turn() {
        let dir = crate::qga::tests::TempDir::new("relay-pipelined");
        let (sock, mut port) = shared(&dir.0, Duration::from_secs(5));

        let mut client = vk_core::unixpath::connect(&sock).unwrap();
        client
            .write_all(&[request("a"), request("b")].concat())
            .unwrap();
        assert_eq!(line(&port), request("a"));
        port.write_all(b"answer a\n").unwrap();
        assert_eq!(line(&port), request("b"));
        port.write_all(b"answer b\n").unwrap();
        assert_eq!(line(&client), b"answer a\n");
        assert_eq!(line(&client), b"answer b\n");
    }

    #[test]
    fn a_client_that_shut_down_its_sending_side_is_answered() {
        let dir = crate::qga::tests::TempDir::new("relay-half-closed");
        let (sock, mut port) = shared(&dir.0, Duration::from_secs(5));

        let mut client = vk_core::unixpath::connect(&sock).unwrap();
        client
            .write_all(&[request("a"), request("b")].concat())
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        for name in ["a", "b"] {
            assert_eq!(line(&port), request(name));
            port.write_all(format!("answer {name}\n").as_bytes())
                .unwrap();
            assert_eq!(line(&client), format!("answer {name}\n").as_bytes());
        }
        // Then the relay lets it go.
        let mut end = [0u8; 1];
        assert_eq!(client.read(&mut end).unwrap(), 0);
    }

    #[test]
    fn a_command_with_no_reply_frees_the_agent_at_once() {
        let dir = crate::qga::tests::TempDir::new("relay-no-reply");
        let (sock, mut port) = shared(&dir.0, Duration::from_secs(5));

        let mut stopping = vk_core::unixpath::connect(&sock).unwrap();
        stopping.write_all(&request("guest-shutdown")).unwrap();
        assert_eq!(line(&port), request("guest-shutdown"));
        let sync = relay_sync(&port);
        let mut client = vk_core::unixpath::connect(&sock).unwrap();
        client.write_all(&request("b")).unwrap();
        port.write_all(crate::qga::tests::STRAY_FF).unwrap();
        port.write_all(&crate::qga::tests::synced(&sync)).unwrap();
        assert_eq!(line(&port), request("b"));
        port.write_all(b"answer b\n").unwrap();
        assert_eq!(line(&client), b"answer b\n");
    }

    #[test]
    fn a_client_dropped_as_it_is_answered_does_not_stall_the_others() {
        let dir = crate::qga::tests::TempDir::new("relay-dropped");
        let (sock, mut port) = shared(&dir.0, Duration::from_secs(5));

        let mut stuck = vk_core::unixpath::connect(&sock).unwrap();
        let mut leaving = vk_core::unixpath::connect(&sock).unwrap();
        let _idle = vk_core::unixpath::connect(&sock).unwrap();
        let mut client = vk_core::unixpath::connect(&sock).unwrap();
        stuck.write_all(&request("a")).unwrap();
        assert_eq!(line(&port), request("a"));
        leaving.write_all(&request("b")).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        // An answer `stuck` does not read holds the relay for CLIENT_WRITE_TIMEOUT.
        let mut flood = port.try_clone().unwrap();
        std::thread::spawn(move || {
            flood.write_all(&[vec![b'x'; 4 << 20], b"\n".to_vec()].concat())
        })
        .join()
        .unwrap()
        .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        // Meanwhile the answer to `leaving` comes early and `leaving` leaves: the relay finds
        // both at once, and drops `leaving` as it answers it.
        port.write_all(b"answer b\n").unwrap();
        drop(leaving);
        assert_eq!(line(&port), request("b"));

        client.write_all(&request("c")).unwrap();
        assert_eq!(line(&port), request("c"));
        port.write_all(b"answer c\n").unwrap();
        assert_eq!(line(&client), b"answer c\n");
        drop(stuck);
    }
}
