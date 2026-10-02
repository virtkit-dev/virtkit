use std::fmt;
use std::path::PathBuf;

use anyhow::anyhow;

/// A virtkit-agent socket address, as given to `--socket`:
/// - `systemd://`: socket activation, unix or vsock listeners (serve only)
/// - `vsock://[cid:]port`: AF_VSOCK; without a cid, serve binds any cid and
///   connect targets the host (cid 2)
/// - `vsock-auto://path:port`: the VMM's dedicated host→guest socket
///   `<path>_<port>` (connect only)
/// - `tcp://host:port`: AF_INET(6); the only kind a stock TCP client (e.g. a
///   guest dockerd talking to a forwarded registry) can use as an endpoint
/// - anything else: path of a unix socket
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketAddr {
    Systemd,
    Unix(PathBuf),
    Vsock { cid: Option<u32>, port: u32 },
    VsockAuto { path: PathBuf, port: u32 },
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
        } else if s.starts_with("vsock-mux://") {
            // Otherwise this parses as a unix socket path and fails later with a less helpful error.
            Err(anyhow!(
                "vsock-mux:// is no longer supported (cloud-hypervisor was removed); \
                 use vsock-auto://<path>:<port>"
            ))
        } else if let Some(rest) = s.strip_prefix("vsock-auto://") {
            let (path, port) = rest
                .rsplit_once(':')
                .ok_or_else(|| anyhow!("vsock-auto:// expects <path>:<port>"))?;
            Ok(SocketAddr::VsockAuto {
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

/// Splits a `tcp://host:port` value into `(host, port)`, rejecting an empty host.
/// Returns `None` when `s` has no `tcp://` prefix. Shared by `parse_publish_to`
/// (clap validation) and `resolve_connect_target` (async DNS resolution) so the
/// two don't drift apart on what counts as a valid `tcp://` value.
pub fn split_tcp_url(s: &str) -> Option<Result<(&str, u16), anyhow::Error>> {
    let hostport = s.strip_prefix("tcp://")?;
    Some((|| {
        let (host, port) = hostport
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("tcp:// expects <host>:<port>, got {s:?}"))?;
        if host.is_empty() {
            return Err(anyhow!("tcp:// expects a non-empty host, got {s:?}"));
        }
        let port: u16 = port
            .parse()
            .map_err(|_| anyhow!("invalid port {port:?} in {s:?}"))?;
        Ok((host, port))
    })())
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
            SocketAddr::VsockAuto { path, port } => {
                write!(f, "vsock-auto://{}:{port}", path.display())
            }
            SocketAddr::Tcp(addr) => write!(f, "tcp://{addr}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SocketAddr, split_tcp_url};

    fn parse(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn split_tcp_url_returns_none_for_a_non_tcp_scheme() {
        assert!(split_tcp_url("vsock://4444").is_none());
    }

    #[test]
    fn split_tcp_url_splits_host_and_port() {
        assert_eq!(
            split_tcp_url("tcp://runner:443").unwrap().unwrap(),
            ("runner", 443)
        );
    }

    #[test]
    fn split_tcp_url_rejects_an_empty_host() {
        let err = split_tcp_url("tcp://:443").unwrap().unwrap_err();
        assert!(err.to_string().contains("non-empty host"), "{err}");
    }

    #[test]
    fn split_tcp_url_rejects_a_bad_port() {
        let err = split_tcp_url("tcp://runner:notaport").unwrap().unwrap_err();
        assert!(err.to_string().contains("invalid port"), "{err}");
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
    fn vsock_mux_is_refused_by_name() {
        let err = "vsock-mux:///tmp/vsock.sock:4444"
            .parse::<SocketAddr>()
            .unwrap_err()
            .to_string();
        assert!(err.contains("vsock-auto://"), "{err}");
    }

    #[test]
    fn parse_vsock_auto() {
        assert_eq!(
            parse("vsock-auto:///tmp/vsock.sock:4444"),
            SocketAddr::VsockAuto {
                path: "/tmp/vsock.sock".into(),
                port: 4444
            }
        );
        assert!(
            "vsock-auto:///tmp/vsock.sock"
                .parse::<SocketAddr>()
                .is_err()
        );
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
            "vsock-auto:///tmp/vsock.sock:4444",
            "tcp://127.0.0.1:5000",
        ] {
            assert_eq!(parse(s).to_string(), s);
        }
    }
}
