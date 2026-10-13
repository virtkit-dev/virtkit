//! Service control protocol — the guest control client (the agent's
//! /run/vk/services filesystem bridge) and the host service manager speak this
//! over vsock. The guest dials host:CONTROL_PORT; the manager (listening on the VM's
//! per-port socket `<base>_<port>` for that port) starts/stops/queries the declared
//! service VMs. One newline-delimited JSON request, one reply. Scoped to the
//! VM by construction — only the VM's vsock reaches the control socket.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

/// vsock port the fleet manager accepts control connections on.
pub const CONTROL_PORT: u32 = 1099;

#[derive(Serialize, Deserialize, Debug)]
pub enum Request {
    List,
    Status {
        unit: String,
    },
    Start {
        unit: String,
    },
    Stop {
        unit: String,
    },
    Restart {
        unit: String,
    },
    /// Reboot the guest in place (keeping the VM process), as opposed to `Restart`,
    /// which stops the unit and starts it again (and may rebuild the image).
    Reboot {
        unit: String,
    },
    Logs {
        unit: String,
        lines: usize,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UnitStatus {
    pub name: String,
    /// "running" | "stopped"
    pub state: String,
    pub ip: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Reply {
    pub ok: bool,
    pub message: String,
    #[serde(default)]
    pub units: Vec<UnitStatus>,
}

/// What `vk service` asks the manager, one variant per subcommand.
#[derive(Debug, PartialEq, Eq)]
pub enum ServiceOp {
    Up(String),
    Down(String),
    Reboot(String),
    /// One service, or every one.
    Status(Option<String>),
}

/// Usage for `vk service` arguments parsed by [`ServiceOp::parse`].
pub const SERVICE_USAGE: &str = "usage: vk service up|down|reboot NAME | vk service status [NAME]";

impl ServiceOp {
    /// Parse the arguments after `vk service`.
    pub fn parse(args: &[String]) -> Option<ServiceOp> {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        Some(match args.as_slice() {
            ["up", name] => ServiceOp::Up(name.to_string()),
            ["down", name] => ServiceOp::Down(name.to_string()),
            ["reboot", name] => ServiceOp::Reboot(name.to_string()),
            ["status"] => ServiceOp::Status(None),
            ["status", name] => ServiceOp::Status(Some(name.to_string())),
            _ => return None,
        })
        .filter(|op| match op {
            ServiceOp::Up(n) | ServiceOp::Down(n) | ServiceOp::Reboot(n) => !n.starts_with('-'),
            ServiceOp::Status(n) => !n.as_deref().is_some_and(|n| n.starts_with('-')),
        })
    }

    /// Ask the manager. `up` streams its on-demand build's progress to stderr, so stdout
    /// carries only the result. `down` may take up to a minute while the guest powers off.
    pub async fn run(&self, client: &mut Client) -> Result<Reply> {
        let mut on_progress = |line: &str| eprintln!("{line}");
        match self {
            ServiceOp::Up(unit) => {
                let req = Request::Start { unit: unit.clone() };
                client.request_streamed(&req, &mut on_progress).await
            }
            ServiceOp::Down(unit) => client.request(&Request::Stop { unit: unit.clone() }).await,
            ServiceOp::Reboot(unit) => {
                client
                    .request(&Request::Reboot { unit: unit.clone() })
                    .await
            }
            ServiceOp::Status(Some(unit)) => {
                client
                    .request(&Request::Status { unit: unit.clone() })
                    .await
            }
            ServiceOp::Status(None) => client.request(&Request::List).await,
        }
    }
}

/// A response frame. Every request is answered by a frame stream: zero or more `Progress`
/// lines — a streamed op, e.g. `Start` forwarding an on-demand service build's output — then
/// exactly one terminal `Done` carrying the reply. A non-streaming op sends only `Done`.
#[derive(Serialize, Deserialize, Debug)]
pub enum Frame {
    Progress(String),
    Done(Reply),
}

impl Reply {
    /// Print as `vk service` does: the units, then the message — on stderr for a failure,
    /// with a stand-in when it has none, so a failure is never silent.
    pub fn print(&self) {
        for u in &self.units {
            println!("{:<16} {:<9} {}", u.name, u.state, u.ip);
        }
        if !self.ok {
            if self.message.is_empty() {
                eprintln!("the service manager reported a failure with no detail");
            } else {
                eprintln!("{}", self.message);
            }
        } else if !self.message.is_empty() {
            println!("{}", self.message);
        }
    }

    pub fn ok(message: impl Into<String>) -> Self {
        Reply {
            ok: true,
            message: message.into(),
            units: Vec::new(),
        }
    }
    pub fn err(message: impl Into<String>) -> Self {
        Reply {
            ok: false,
            message: message.into(),
            units: Vec::new(),
        }
    }
    pub fn list(units: Vec<UnitStatus>) -> Self {
        Reply {
            ok: true,
            message: String::new(),
            units,
        }
    }
}

/// Write one newline-delimited JSON message.
pub async fn write_msg<W: AsyncWriteExt + Unpin, T: Serialize>(w: &mut W, msg: &T) -> Result<()> {
    let mut line = serde_json::to_string(msg).context("encoding control message")?;
    line.push('\n');
    w.write_all(line.as_bytes()).await?;
    w.flush().await?;
    Ok(())
}

/// The longest control message either side reads: well past any reply, a unit's log tail
/// included, and a bound on what the guest's end of a request can make the host buffer.
pub const MAX_MSG: u64 = 16 << 20;

/// The longest request the service manager reads from a guest: a unit name and an
/// operation, a few hundred bytes at most.
pub const MAX_REQUEST: u64 = 64 << 10;

/// Read one newline-delimited JSON message, of at most [`MAX_MSG`] bytes.
pub async fn read_msg<R, T>(r: &mut R) -> Result<T>
where
    R: AsyncBufReadExt + Unpin,
    T: for<'de> Deserialize<'de>,
{
    read_msg_capped(r, MAX_MSG).await
}

/// [`read_msg`] with a `max`-byte limit for smaller messages, such as guest requests.
pub async fn read_msg_capped<R, T>(r: &mut R, max: u64) -> Result<T>
where
    R: AsyncBufReadExt + Unpin,
    T: for<'de> Deserialize<'de>,
{
    // Buffer bytes so a cut inside a multibyte character reports overflow, not invalid UTF-8.
    // Read one extra byte to distinguish a line of exactly `max` bytes from a longer one.
    let mut line = Vec::new();
    let n = (&mut *r).take(max + 1).read_until(b'\n', &mut line).await?;
    if n as u64 > max {
        anyhow::bail!("control message over {max} bytes");
    }
    if n == 0 {
        // A clean EOF: report it as an io::Error so callers can classify a peer hangup by
        // kind rather than by matching this string.
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "control peer closed the connection",
        )
        .into());
    }
    let line = std::str::from_utf8(&line).context("decoding control message")?;
    serde_json::from_str(line.trim_end()).context("decoding control message")
}

/// The guest side of the control protocol: a session client that keeps one
/// vsock connection to the service manager (host:CONTROL_PORT) across
/// requests and transparently reconnects — per-operation connection churn is
/// both slower and racy through a VMM's vsock forwarding.
#[derive(Default)]
pub struct Client {
    conn: Option<(
        BufReader<tokio::io::ReadHalf<tokio_vsock::VsockStream>>,
        tokio::io::WriteHalf<tokio_vsock::VsockStream>,
    )>,
}

impl Client {
    pub fn new() -> Client {
        Client::default()
    }

    /// Send `req` and return its reply, discarding any interim progress frames.
    pub async fn request(&mut self, req: &Request) -> Result<Reply> {
        self.request_streamed(req, &mut |_| {}).await
    }

    /// Send `req` and return its reply, forwarding each interim progress line to
    /// `on_progress` — a streamed op such as `Start` building a service on demand relays its
    /// build output this way. A dropped session (VMM forwarding hiccup, manager restart) is
    /// retried on a fresh connection; a retried streamed op replays its progress, which is
    /// harmless — the operation behind it (an idempotent build-then-boot) is safe to repeat.
    pub async fn request_streamed(
        &mut self,
        req: &Request,
        on_progress: &mut dyn FnMut(&str),
    ) -> Result<Reply> {
        let mut last = None;
        for _ in 0..3 {
            if self.conn.is_none() {
                let addr = tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_HOST, CONTROL_PORT);
                match tokio_vsock::VsockStream::connect(addr).await {
                    Ok(stream) => {
                        let (rd, wr) = tokio::io::split(stream);
                        self.conn = Some((BufReader::new(rd), wr));
                    }
                    Err(e) => {
                        last = Some(anyhow::Error::new(e).context(format!(
                            "connecting to the service manager (vsock host:{CONTROL_PORT})"
                        )));
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                }
            }
            let (rd, wr) = self.conn.as_mut().expect("connected above");
            match roundtrip(rd, wr, req, on_progress).await {
                Ok(reply) => return Ok(reply),
                Err(e) => {
                    self.conn = None;
                    last = Some(e);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
        Err(last.expect("at least one attempt ran"))
    }
}

async fn roundtrip(
    rd: &mut BufReader<tokio::io::ReadHalf<tokio_vsock::VsockStream>>,
    wr: &mut tokio::io::WriteHalf<tokio_vsock::VsockStream>,
    req: &Request,
    on_progress: &mut dyn FnMut(&str),
) -> Result<Reply> {
    write_msg(wr, req).await?;
    read_until_done(rd, on_progress).await
}

/// Read the response frame stream — interim `Progress` lines forwarded to `on_progress` — up
/// to the terminal `Done` carrying the reply. EOF or a decode error before `Done` (a peer that
/// dropped mid-stream) surfaces as an error from [`read_msg`].
async fn read_until_done<R>(rd: &mut R, on_progress: &mut dyn FnMut(&str)) -> Result<Reply>
where
    R: AsyncBufReadExt + Unpin,
{
    loop {
        match read_msg::<_, Frame>(rd).await? {
            Frame::Progress(line) => on_progress(&line),
            Frame::Done(reply) => return Ok(reply),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_op_parses_vk_service_args() {
        let parse =
            |a: &[&str]| ServiceOp::parse(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(parse(&["up", "db"]), Some(ServiceOp::Up("db".into())));
        assert_eq!(parse(&["down", "db"]), Some(ServiceOp::Down("db".into())));
        assert_eq!(
            parse(&["reboot", "db"]),
            Some(ServiceOp::Reboot("db".into()))
        );
        assert_eq!(parse(&["status"]), Some(ServiceOp::Status(None)));
        assert_eq!(
            parse(&["status", "db"]),
            Some(ServiceOp::Status(Some("db".into())))
        );
        for bad in [
            &[][..],
            &["up"],
            &["up", "a", "b"],
            &["up", "--help"],
            &["start", "db"],
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }

    /// A peer that never ends its line is cut off at the bound rather than buffered without end.
    #[tokio::test]
    async fn a_request_is_held_to_its_own_bound() {
        let long = vec![b'x'; MAX_REQUEST as usize + 2];
        let mut rd = BufReader::new(&long[..]);
        assert!(
            read_msg_capped::<_, Request>(&mut rd, MAX_REQUEST)
                .await
                .is_err()
        );
    }

    /// A request filling the bound exactly, newline included, is read; one byte more is not.
    #[tokio::test]
    async fn a_request_of_exactly_the_bound_is_accepted() {
        let req = serde_json::to_string(&Request::List).unwrap();
        let max = req.len() as u64 + 1;
        let line = format!("{req}\n");
        let mut rd = BufReader::new(line.as_bytes());
        assert!(matches!(
            read_msg_capped::<_, Request>(&mut rd, max).await.unwrap(),
            Request::List
        ));
        let line = format!("{req} \n");
        let mut rd = BufReader::new(line.as_bytes());
        let err = read_msg_capped::<_, Request>(&mut rd, max)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("over"), "{err}");
    }

    /// A cut landing inside a multibyte character is reported as over the bound.
    #[tokio::test]
    async fn a_cut_inside_a_character_is_over_the_bound() {
        let mut rd = BufReader::new("xé\n".as_bytes());
        let err = read_msg_capped::<_, Request>(&mut rd, 1)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("over"), "{err}");
    }

    #[tokio::test]
    async fn an_endless_message_is_refused_at_the_bound() {
        let endless = vec![b'x'; MAX_MSG as usize + 2];
        let mut rd = BufReader::new(&endless[..]);
        let err = read_msg::<_, Request>(&mut rd)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("over"), "{err}");
    }

    /// A frame stream — interim `Progress` lines then the terminal `Done` — forwards every
    /// progress line in order and returns the `Done` reply, stopping at `Done`.
    #[tokio::test]
    async fn read_until_done_forwards_progress_then_returns_reply() {
        let mut buf = Vec::new();
        write_msg(&mut buf, &Frame::Progress("step 1".into()))
            .await
            .unwrap();
        write_msg(&mut buf, &Frame::Progress("step 2".into()))
            .await
            .unwrap();
        write_msg(&mut buf, &Frame::Done(Reply::ok("started")))
            .await
            .unwrap();

        let mut rd = BufReader::new(std::io::Cursor::new(buf));
        let mut seen = Vec::new();
        let reply = read_until_done(&mut rd, &mut |l| seen.push(l.to_string()))
            .await
            .unwrap();

        assert_eq!(seen, ["step 1", "step 2"]);
        assert!(reply.ok);
        assert_eq!(reply.message, "started");
    }

    /// A peer that drops the connection before sending `Done` is an error, not a hang.
    #[tokio::test]
    async fn read_until_done_errors_when_stream_ends_before_done() {
        let mut buf = Vec::new();
        write_msg(&mut buf, &Frame::Progress("partial".into()))
            .await
            .unwrap();

        let mut rd = BufReader::new(std::io::Cursor::new(buf));
        let mut seen = Vec::new();
        let err = read_until_done(&mut rd, &mut |l| seen.push(l.to_string()))
            .await
            .unwrap_err();

        assert_eq!(seen, ["partial"]);
        assert!(err.to_string().contains("closed the connection"));
    }
}
