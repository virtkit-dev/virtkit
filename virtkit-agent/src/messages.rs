use core::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Wire protocol version, reported in [`Status`]. The host (virtkit) checks
/// the value the in-guest virtkit-agent reports against its own during the boot
/// readiness handshake and refuses to run on a mismatch — turning a stale guest
/// bundle (a virtkit-agent built before a breaking change) into a clear "rebuild the
/// bundle" error at boot instead of an opaque mid-command "connection lost".
///
/// Bump this on ANY change to how a [`Message`] serializes (adding, removing or
/// reordering a struct field, adding an enum variant, ...): rmp_serde encodes
/// structs as fixed-length arrays, so such changes are not wire compatible
/// across versions. A virtkit-agent predating this field decodes its `protocol` as 0.
pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum RunMode {
    Interactive,
    Background,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Message {
    CmdExec(CmdExec),
    CmdStatus,
    StartOK,
    StartErr {
        msg: String,
    },
    RespStatus {
        status: Status,
    },
    Data {
        fd: Fd,
        msg: Vec<u8>,
    },
    Close {
        fd: Fd,
        error: Option<String>,
    },
    ExecDone(CmdResult),
    /// The client's terminal was resized (tty mode only)
    Resize {
        rows: u16,
        cols: u16,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CmdExec {
    pub name: String,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub clear_env: bool,
    pub mode: RunMode,
    pub dir: Option<String>,
    /// Run the command on a pty instead of pipes (interactive mode only); stdout
    /// and stderr merge into the single terminal stream (sent as Fd::Stdout)
    pub tty: Option<Tty>,
    /// Drop to this Unix user before exec (None = run as the virtkit-agent user,
    /// or the CMDRUNNER_DEFAULT_RUN_USER fallback). Sets uid/gid/supplementary
    /// groups and HOME/USER/LOGNAME.
    #[serde(default)]
    pub user: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Tty {
    /// TERM of the client's terminal, exported to the command
    pub term: Option<String>,
    pub rows: u16,
    pub cols: u16,
}

impl fmt::Display for CmdExec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(name:{}, args:{:?}, {:?}{}{})",
            self.name,
            self.args,
            self.mode,
            if self.clear_env { ", clear_env" } else { "" },
            self.env.join(" ")
        )
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CmdResult {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::{PROTOCOL_VERSION, Status};

    #[test]
    fn default_status_reports_current_protocol() {
        assert_eq!(Status::default().protocol(), PROTOCOL_VERSION);
    }

    #[test]
    fn status_round_trips_with_protocol() {
        let s = Status::default();
        let bytes = rmp_serde::to_vec(&s).unwrap();
        let back: Status = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(back.protocol(), PROTOCOL_VERSION);
        assert_eq!(s, back);
    }

    /// A Status from a virtkit-agent predating the protocol field is, on the wire, a
    /// 4-element array (rmp_serde encodes structs positionally). It must still
    /// decode — with protocol() == 0 — so the host reports a clear skew error
    /// rather than failing to read the status at all.
    #[test]
    fn pre_protocol_status_decodes_as_zero() {
        let legacy: (u32, u64, u32, String) = (621, 1_781_346_012, 708_802_242, "0.1.0".into());
        let bytes = rmp_serde::to_vec(&legacy).unwrap();
        let status: Status = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(status.protocol(), 0);
        assert_ne!(status.protocol(), PROTOCOL_VERSION);
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Copy, Debug)]
pub enum Fd {
    Stdin,
    Stdout,
    Stderr,
}

impl fmt::Display for Fd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match &self {
                Fd::Stdin => "<stdin>",
                Fd::Stdout => "<stdout>",
                Fd::Stderr => "<stderr>",
            }
        )
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct Status {
    pid: u32,
    timestamp_sec: u64,
    timestamp_nano: u32,
    version: String,
    /// PROTOCOL_VERSION of the virtkit-agent that produced this Status. Trailing and
    /// serde(default) so a Status from a pre-protocol virtkit-agent still decodes
    /// (as 0) — letting the host report a clear skew error rather than failing to
    /// parse the status at all. See [`PROTOCOL_VERSION`].
    #[serde(default)]
    protocol: u32,
}

impl Status {
    /// Wire protocol version reported by this virtkit-agent (0 = predates versioning).
    pub fn protocol(&self) -> u32 {
        self.protocol
    }
}

impl Default for Status {
    fn default() -> Self {
        let pid = std::process::id();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let timestamp_sec = timestamp.as_secs();
        let timestamp_nano = timestamp.subsec_nanos();
        Status {
            pid,
            timestamp_sec,
            timestamp_nano,
            version: env!("CARGO_PKG_VERSION").to_string(),
            protocol: PROTOCOL_VERSION,
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(pid:{}, version:{}, protocol:{}, timestamp_sec:{}, timestamp_nano:{})",
            self.pid, self.version, self.protocol, self.timestamp_sec, self.timestamp_nano
        )
    }
}
