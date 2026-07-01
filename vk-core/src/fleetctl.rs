//! virtctl control protocol — the VM's `virtctl` client and the fleet
//! manager's server speak this over vsock. The VM dials host:CONTROL_PORT;
//! the manager (listening on the VM's hybrid-vsock socket for that port)
//! starts/stops/queries the declared service VMs. One newline-delimited JSON
//! request, one reply. The types + framing are shared; the client lives here, the
//! server loop in the fleet crate. Scoped to the VM by construction — only the
//! VM's vsock reaches the control socket.

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

/// `virtctl` — the VM CLI. Parse args into one request, send it to the manager
/// (vsock host:CONTROL_PORT), and render the reply. `argv` is the args after the
/// program name (e.g. ["start", "mysql"]).
pub async fn run_client(argv: &[String]) -> Result<()> {
    let req = parse_request(argv)?;
    let addr = tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_HOST, CONTROL_PORT);
    let stream = tokio_vsock::VsockStream::connect(addr)
        .await
        .with_context(|| format!("connecting to the fleet manager (vsock host:{CONTROL_PORT})"))?;
    let (rd, mut wr) = tokio::io::split(stream);
    write_msg(&mut wr, &req).await?;
    let mut rd = BufReader::new(rd);
    let reply: Reply = read_msg(&mut rd).await?;
    render(&reply);
    if reply.ok {
        Ok(())
    } else {
        bail!("{}", reply.message)
    }
}

fn parse_request(argv: &[String]) -> Result<Request> {
    let action = argv.first().map(String::as_str).unwrap_or("list");
    let unit = || {
        argv.get(1)
            .cloned()
            .with_context(|| format!("`virtctl {action}` needs a unit name"))
    };
    Ok(match action {
        "list" | "ls" => Request::List,
        "status" => match argv.get(1) {
            Some(u) => Request::Status { unit: u.clone() },
            None => Request::List,
        },
        "start" | "up" => Request::Start { unit: unit()? },
        "stop" | "down" => Request::Stop { unit: unit()? },
        "restart" => Request::Restart { unit: unit()? },
        "logs" => Request::Logs {
            unit: unit()?,
            lines: 50,
        },
        "-h" | "--help" | "help" => {
            bail!("usage: virtctl <list|status|start|stop|restart|logs> [unit]");
        }
        other => {
            bail!("unknown virtctl command {other:?} (list|status|start|stop|restart|logs [unit])")
        }
    })
}

fn render(reply: &Reply) {
    if !reply.units.is_empty() {
        println!("{:<12} {:<8} IP", "UNIT", "STATE");
        for u in &reply.units {
            println!("{:<12} {:<8} {}", u.name, u.state, u.ip);
        }
    }
    if !reply.message.is_empty() {
        println!("{}", reply.message);
    }
}
