//! Service control protocol — a guest control client and a host service
//! manager speak this over vsock. The guest dials host:CONTROL_PORT; the
//! manager (listening on the VM's hybrid-vsock socket for that port)
//! starts/stops/queries declared service VMs. One newline-delimited JSON
//! request, one reply. Scoped to the VM by construction — only the VM's vsock
//! reaches the control socket.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

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
