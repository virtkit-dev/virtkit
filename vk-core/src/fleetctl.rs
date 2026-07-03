//! Service control protocol — the guest control client (the agent's /run/vk
//! filesystem bridge) and the host service manager speak this over vsock. The
//! guest dials host:CONTROL_PORT; the manager (listening on the VM's
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

    pub async fn request(&mut self, req: &Request) -> Result<Reply> {
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
            match roundtrip(rd, wr, req).await {
                Ok(reply) => return Ok(reply),
                // a dead session (VMM forwarding hiccup, manager restart) is
                // retried on a fresh connection
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
) -> Result<Reply> {
    write_msg(wr, req).await?;
    read_msg(rd).await
}
