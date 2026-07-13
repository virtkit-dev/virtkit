//! Service control protocol — the guest control client (the agent's
//! /run/vk/services filesystem bridge) and the host service manager speak this
//! over vsock. The guest dials host:CONTROL_PORT; the manager (listening on the VM's
//! hybrid-vsock socket for that port) starts/stops/queries the declared
//! service VMs. One newline-delimited JSON request, one reply. Scoped to the
//! VM by construction — only the VM's vsock reaches the control socket.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// vsock port the fleet manager accepts control connections on.
pub const CONTROL_PORT: u32 = 1099;

#[derive(Serialize, Deserialize, Debug)]
pub enum Request {
    List,
    Status { unit: String },
    Start { unit: String },
    Stop { unit: String },
    Restart { unit: String },
    Logs { unit: String, lines: usize },
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

/// A response frame. Every request is answered by a frame stream: zero or more `Progress`
/// lines — a streamed op, e.g. `Start` forwarding an on-demand service build's output — then
/// exactly one terminal `Done` carrying the reply. A non-streaming op sends only `Done`.
#[derive(Serialize, Deserialize, Debug)]
pub enum Frame {
    Progress(String),
    Done(Reply),
}

impl Reply {
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

/// Read one newline-delimited JSON message.
pub async fn read_msg<R, T>(r: &mut R) -> Result<T>
where
    R: AsyncBufReadExt + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let mut line = String::new();
    if r.read_line(&mut line).await? == 0 {
        bail!("control peer closed the connection");
    }
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
