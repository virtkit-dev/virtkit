use std::fmt;
use std::path::PathBuf;

use anyhow::anyhow;

/// A virtkit-agent socket address, as given to `--socket`:
/// - `systemd://`: socket activation, unix or vsock listeners (serve only)
/// - `vsock://[cid:]port`: AF_VSOCK; without a cid, serve binds any cid and
///   connect targets the host (cid 2)
/// - `vsock-mux://path:port`: "hybrid vsock" of Cloud Hypervisor / Firecracker —
///   the unix socket the VMM exposes on the host, multiplexing guest vsock ports
///   behind a `CONNECT <port>` handshake (connect only)
/// - `tcp://host:port`: AF_INET(6); the only kind a stock TCP client (e.g. a
///   guest dockerd talking to a forwarded registry) can use as an endpoint
/// - anything else: path of a unix socket
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketAddr {
    Systemd,
    Unix(PathBuf),
    Vsock { cid: Option<u32>, port: u32 },
    VsockMux { path: PathBuf, port: u32 },
    Tcp(std::net::SocketAddr),
}

impl std::str::FromStr for SocketAddr {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<SocketAddr, anyhow::Error> {
        if s == "systemd://" {
            Ok(SocketAddr::Systemd)
        } else if let Some(rest) = s.strip_prefix("vsock://") {
            let (cid, port) = match rest.split_once(':') {
                Some((cid, port)) => (Some(parse_num(cid, "cid")?), port),
                None => (None, rest),
            };
            Ok(SocketAddr::Vsock {
                cid,
                port: parse_num(port, "port")?,
            })
        } else if let Some(rest) = s.strip_prefix("vsock-mux://") {
            let (path, port) = rest
                .rsplit_once(':')
                .ok_or_else(|| anyhow!("vsock-mux:// expects <path>:<port>"))?;
            Ok(SocketAddr::VsockMux {
                path: path.into(),
                port: parse_num(port, "port")?,
            })
        } else if let Some(rest) = s.strip_prefix("tcp://") {
            Ok(SocketAddr::Tcp(rest.parse().map_err(|_| {
                anyhow!("invalid tcp address '{rest}' (expected host:port)")
            })?))
        } else {
            Ok(SocketAddr::Unix(s.into()))
        }
    }
}

fn parse_num(s: &str, what: &str) -> Result<u32, anyhow::Error> {
    s.parse()
        .map_err(|_| anyhow!("invalid vsock {what} '{s}' (expected a number)"))
}

impl fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocketAddr::Systemd => write!(f, "systemd://"),
            SocketAddr::Unix(path) => write!(f, "{}", path.display()),
            SocketAddr::Vsock { cid: None, port } => write!(f, "vsock://{port}"),
            SocketAddr::Vsock {
                cid: Some(cid),
                port,
            } => write!(f, "vsock://{cid}:{port}"),
            SocketAddr::VsockMux { path, port } => {
                write!(f, "vsock-mux://{}:{port}", path.display())
            }
            SocketAddr::Tcp(addr) => write!(f, "tcp://{addr}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SocketAddr;

    fn parse(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parse_systemd() {
        assert_eq!(parse("systemd://"), SocketAddr::Systemd);
    }

    #[test]
    fn parse_unix_path() {
        assert_eq!(
            parse("/run/virtkit-agent/runner.socket"),
            SocketAddr::Unix("/run/virtkit-agent/runner.socket".into())
        );
    }

    #[test]
    fn parse_vsock() {
        assert_eq!(
            parse("vsock://4444"),
            SocketAddr::Vsock {
                cid: None,
                port: 4444
            }
        );
        assert_eq!(
            parse("vsock://3:4444"),
            SocketAddr::Vsock {
                cid: Some(3),
                port: 4444
            }
        );
        assert!("vsock://x".parse::<SocketAddr>().is_err());
        assert!("vsock://3:".parse::<SocketAddr>().is_err());
    }

    #[test]
    fn parse_vsock_mux() {
        assert_eq!(
            parse("vsock-mux:///tmp/vsock.sock:4444"),
            SocketAddr::VsockMux {
                path: "/tmp/vsock.sock".into(),
                port: 4444
            }
        );
        assert!("vsock-mux:///tmp/vsock.sock".parse::<SocketAddr>().is_err());
    }

    #[test]
    fn parse_tcp() {
        assert_eq!(
            parse("tcp://127.0.0.1:5000"),
            SocketAddr::Tcp("127.0.0.1:5000".parse().unwrap())
        );
        assert!("tcp://127.0.0.1".parse::<SocketAddr>().is_err());
        assert!("tcp://notanaddr".parse::<SocketAddr>().is_err());
    }

    #[test]
    fn display_roundtrip() {
        for s in [
            "systemd://",
            "/tmp/x.socket",
            "vsock://4444",
            "vsock://3:4444",
            "vsock-mux:///tmp/vsock.sock:4444",
            "tcp://127.0.0.1:5000",
        ] {
            assert_eq!(parse(s).to_string(), s);
        }
    }
}
