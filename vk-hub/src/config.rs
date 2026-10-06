//! `hub.toml`: where the hub listens, its TLS certificate, and where it keeps its data.
//!
//! ```toml
//! addr = "0.0.0.0:8443"
//! tls_cert = "/etc/vk-hub/cert.pem"
//! tls_key = "/etc/vk-hub/key.pem"
//! data_dir = "/var/lib/vk-hub"
//! # The web UI: off unless `ui_addr` is set.
//! ui_addr = "0.0.0.0:8444"
//! ui_url = "https://hub.example.com:8444"  # what browsers reach it as
//! ui_tls_cert = "/etc/vk-hub/ui-cert.pem"  # default: tls_cert/tls_key
//! ui_tls_key = "/etc/vk-hub/ui-key.pem"
//! # Where `vk-hub release fetch` downloads releases from; "none" turns fetching off.
//! release_repository = "https://github.com/virtkit-dev/virtkit"
//!
//! # Sign-in to the web UI through an OIDC provider; off unless set.
//! [oidc]
//! issuer = "https://login.example.com/app/1"
//! client_id = "vk-hub"
//! client_secret_file = "/etc/vk-hub/oidc-secret"
//! ```
//!
//! Every key is optional. Sessions bind to the TLS 1.3 exporter. Plain HTTP is allowed only
//! on loopback: enrollment tokens travel in the request body and plaintext sessions have
//! no channel binding, so sessions on an open network need TLS. Only TLS 1.3 is supported.
//! The web UI's listener is held to the same rule — its session cookie is a bearer
//! credential — and serves its own certificate or the node listener's; `ui_url` may be
//! `http://` only for a loopback host. Even on loopback, plain http shares the session cookie
//! with every other http service on that host, whatever its port — browsers keep cookies
//! apart by host, not port — so a UI opened on a machine that serves anything else on
//! loopback wants TLS too.
//!
//! `[oidc]` needs the web UI, reached over https: the provider sends browsers back to
//! `<ui_url>/auth/callback`, which is the redirect URI to register with it. Who may sign in,
//! and as what, is granted with `vk-hub accounts`, not here.

use std::fs::File;
use std::io::BufReader;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use tokio_rustls::TlsAcceptor;

/// Where the hub listens when the config names no address: loopback only, since with no TLS
/// that is the one place it may serve.
pub const DEFAULT_ADDR: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 8443);

/// The resolved configuration.
#[derive(Debug)]
pub struct HubConfig {
    pub addr: SocketAddr,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub data_dir: PathBuf,
    pub ui: Option<UiConfig>,
    /// Where releases are fetched from; `None` with fetching off.
    pub release_source: Option<crate::fetch::Source>,
}

/// The web UI's listener.
#[derive(Debug)]
pub struct UiConfig {
    pub addr: SocketAddr,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// The UI's origin as browsers reach it, `scheme://host[:port]` with no trailing slash:
    /// what sign-in links start with and what a state-changing request's `Origin` must be.
    pub url: String,
    /// Sign-in through an OIDC provider, besides the links.
    pub oidc: Option<OidcConfig>,
}

/// `[oidc]`, checked. The secret is read when the hub starts serving, not here: every
/// `vk-hub` command loads this file, and only `serve` needs the secret.
#[derive(Debug)]
pub struct OidcConfig {
    /// Without a trailing slash.
    pub issuer: String,
    pub client_id: String,
    pub client_secret_file: PathBuf,
}

/// The file as written. `deny_unknown_fields` so a misspelt `tls_cert` fails at startup
/// rather than serving plain HTTP the operator believed was TLS.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    addr: Option<String>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    data_dir: Option<PathBuf>,
    ui_addr: Option<String>,
    ui_url: Option<String>,
    ui_tls_cert: Option<PathBuf>,
    ui_tls_key: Option<PathBuf>,
    release_repository: Option<String>,
    oidc: Option<FileOidc>,
}

/// `[oidc]` as written; `deny_unknown_fields` for the same reason.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileOidc {
    issuer: String,
    client_id: String,
    client_secret_file: PathBuf,
}

impl HubConfig {
    /// Read `path`, or the defaults when there is none.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let file = match path {
            Some(path) => {
                let text = std::fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?;
                toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?
            }
            None => FileConfig::default(),
        };
        Self::from_file(file)
    }

    fn from_file(f: FileConfig) -> Result<Self> {
        let addr = match f.addr {
            Some(a) => a.parse().with_context(|| format!("parsing addr {a:?}"))?,
            None => DEFAULT_ADDR,
        };
        let data_dir = match f.data_dir {
            Some(dir) => dir,
            None => default_data_dir()?,
        };
        if f.tls_cert.is_none() && f.tls_key.is_none() && !addr.ip().is_loopback() {
            bail!(
                "addr {addr} is not loopback and no TLS is configured: enrollment tokens and \
                 node sessions would cross the network in cleartext; set tls_cert/tls_key or \
                 bind a loopback address"
            );
        }
        let ui = match f.ui_addr {
            Some(a) => {
                let addr: SocketAddr = a
                    .parse()
                    .with_context(|| format!("parsing ui_addr {a:?}"))?;
                let (tls_cert, tls_key) = if f.ui_tls_cert.is_some() || f.ui_tls_key.is_some() {
                    (f.ui_tls_cert, f.ui_tls_key)
                } else {
                    (f.tls_cert.clone(), f.tls_key.clone())
                };
                let tls = tls_cert.is_some() || tls_key.is_some();
                if !tls && !addr.ip().is_loopback() {
                    bail!(
                        "ui_addr {addr} is not loopback and no TLS is configured: web UI \
                         sessions would cross the network in cleartext; set ui_tls_cert/\
                         ui_tls_key or tls_cert/tls_key, or bind a loopback address"
                    );
                }
                let url = match f.ui_url {
                    Some(url) => {
                        let origin = parse_origin(&url)?;
                        if tls && origin.starts_with("http://") {
                            bail!(
                                "ui_url {url:?}: the web UI's listener serves TLS, so browsers \
                                 reach it over https"
                            );
                        }
                        origin
                    }
                    None if addr.ip().is_unspecified() => bail!(
                        "ui_addr {addr} names no host a browser can reach; set ui_url to the \
                         address the UI is reached at"
                    ),
                    None => {
                        parse_origin(&format!("{}://{addr}", if tls { "https" } else { "http" }))?
                    }
                };
                let oidc = match f.oidc {
                    Some(o) => {
                        if !url.starts_with("https://") {
                            bail!("[oidc] needs the web UI reached over https: ui_url is {url:?}");
                        }
                        Some(oidc_config(o)?)
                    }
                    None => None,
                };
                Some(UiConfig {
                    addr,
                    tls_cert,
                    tls_key,
                    url,
                    oidc,
                })
            }
            None if f.ui_url.is_some() || f.ui_tls_cert.is_some() || f.ui_tls_key.is_some() => {
                bail!("ui_url, ui_tls_cert and ui_tls_key need ui_addr, which turns the web UI on")
            }
            None if f.oidc.is_some() => {
                bail!("[oidc] signs people in to the web UI, which ui_addr turns on")
            }
            None => None,
        };
        let release_source = match f.release_repository.as_deref() {
            None => Some(crate::fetch::Source::virtkit()),
            Some("none") => None,
            Some(url) => Some(crate::fetch::Source::parse(url)?),
        };
        Ok(HubConfig {
            addr,
            tls_cert: f.tls_cert,
            tls_key: f.tls_key,
            data_dir,
            ui,
            release_source,
        })
    }

    /// The hub's database.
    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("hub.db")
    }

    /// Where release binaries are kept.
    pub fn releases_dir(&self) -> PathBuf {
        self.data_dir.join("releases")
    }

    /// The admin socket `vk-hub token` and `vk-hub nodes` reach the running hub through.
    pub fn admin_socket(&self) -> PathBuf {
        self.data_dir.join("admin.sock")
    }

    /// The TLS acceptor, or `None` for plain HTTP. The cert and key go together.
    pub fn build_tls(&self) -> Result<Option<TlsAcceptor>> {
        build_tls(
            self.tls_cert.as_deref(),
            self.tls_key.as_deref(),
            "tls_cert and tls_key",
        )
    }
}

impl UiConfig {
    /// The web UI's TLS acceptor, or `None` for plain HTTP.
    pub fn build_tls(&self) -> Result<Option<TlsAcceptor>> {
        build_tls(
            self.tls_cert.as_deref(),
            self.tls_key.as_deref(),
            "ui_tls_cert and ui_tls_key",
        )
    }
}

/// `[oidc]`, checked: the issuer as `vk-registry` checks its own.
fn oidc_config(o: FileOidc) -> Result<OidcConfig> {
    vk_oidc::check_base_url("[oidc] issuer", &o.issuer)?;
    if o.client_id.is_empty() {
        bail!("[oidc] client_id may not be empty");
    }
    Ok(OidcConfig {
        issuer: o.issuer.trim_end_matches('/').to_string(),
        client_id: o.client_id,
        client_secret_file: o.client_secret_file,
    })
}

/// `url` as an origin — `http` or `https`, a host and maybe a port, and no path — in the form
/// a browser's `Origin` takes: lowercase, no trailing slash, no default port. `http` is only
/// for a loopback host.
fn parse_origin(url: &str) -> Result<String> {
    let bad = || {
        anyhow::anyhow!(
            "ui_url {url:?}: expected http(s)://host[:port], with no path — the address \
             browsers reach the web UI at"
        )
    };
    let lower = url.to_ascii_lowercase();
    let trimmed = lower.strip_suffix('/').unwrap_or(&lower);
    let (scheme, rest) = trimmed.split_once("://").ok_or_else(bad)?;
    let default_port = match scheme {
        "https" => 443,
        "http" => 80,
        _ => return Err(bad()),
    };
    let (host, port) = match rest.strip_prefix('[') {
        Some(v6) => {
            let (inner, after) = v6.split_once(']').ok_or_else(bad)?;
            // Written back as a browser serializes it, so the origin compares equal. An
            // IPv4-mapped address is refused: a browser writes it in hex, std in dotted form.
            let ip: Ipv6Addr = inner
                .parse()
                .ok()
                .filter(|ip: &Ipv6Addr| ip.to_ipv4_mapped().is_none())
                .ok_or_else(bad)?;
            let port = match after {
                "" => None,
                p => Some(p.strip_prefix(':').ok_or_else(bad)?),
            };
            (format!("[{ip}]"), port)
        }
        None => {
            let (host, port) = match rest.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (rest, None),
            };
            if host.is_empty()
                || !host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-.".contains(c))
            {
                return Err(bad());
            }
            // A browser reads a host whose last label is a number as an IPv4 address, in
            // shorthand (`127.1`) or hex as well; only the dotted-quad form, which it writes
            // back as is, is taken.
            let mut labels = host.split('.').rev();
            let last = match labels.next() {
                Some("") => labels.next().unwrap_or(""),
                l => l.unwrap_or(""),
            };
            let numeric = !last.is_empty()
                && (last.bytes().all(|b| b.is_ascii_digit())
                    || last
                        .strip_prefix("0x")
                        .is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit())));
            if numeric && host.parse::<Ipv4Addr>().is_err() {
                return Err(bad());
            }
            (host.to_string(), port)
        }
    };
    let port = match port {
        None => None,
        Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => match p.parse::<u16>()
        {
            Ok(0) | Err(_) => return Err(bad()),
            Ok(n) if n == default_port => None,
            Ok(n) => Some(n),
        },
        Some(_) => return Err(bad()),
    };
    let loopback = host == "localhost"
        || host == "[::1]"
        || host.parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_loopback());
    if scheme == "http" && !loopback {
        bail!(
            "ui_url {url:?}: plain http is for a loopback host only; the session cookie would \
             cross the network in cleartext — use https"
        );
    }
    Ok(match port {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    })
}

fn build_tls(cert: Option<&Path>, key: Option<&Path>, what: &str) -> Result<Option<TlsAcceptor>> {
    let (cert, key) = match (cert, key) {
        (Some(c), Some(k)) => (c, k),
        (None, None) => return Ok(None),
        _ => bail!("{what} must be set together"),
    };
    acceptor(load_certs(cert)?, load_key(key)?).map(Some)
}

/// The acceptor for `certs` and `key`. TLS 1.3 only: a session signs the connection's
/// exporter, which TLS 1.2 ties to the handshake only with the extended master secret
/// (RFC 7627).
pub(crate) fn acceptor(
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<TlsAcceptor> {
    let mut sc = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .context("building the TLS server config")?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .context("building the TLS server config")?;
    sc.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(sc)))
}

/// `$XDG_DATA_HOME/virtkit/hub`, else `~/.local/share/virtkit/hub` — beside the registry's
/// default store.
fn default_data_dir() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(xdg).join("virtkit/hub"));
    }
    let home = std::env::var_os("HOME").context("neither XDG_DATA_HOME nor HOME is set")?;
    Ok(PathBuf::from(home).join(".local/share/virtkit/hub"))
}

fn load_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    use rustls::pki_types::pem::PemObject;
    let mut r =
        BufReader::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
    rustls::pki_types::CertificateDer::pem_reader_iter(&mut r)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("reading certificates from {}", path.display()))
}

fn load_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    use rustls::pki_types::pem::PemObject;
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    crate::warn_if_file_mode(
        &file,
        path,
        0o077,
        "TLS private key",
        "it is group/world-accessible — restrict it to 0600",
    );
    rustls::pki_types::PrivateKeyDer::from_pem_reader(&mut BufReader::new(file))
        .with_context(|| format!("reading a private key from {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<HubConfig> {
        HubConfig::from_file(toml::from_str(text)?)
    }

    #[test]
    fn every_key_is_read_and_an_unknown_one_is_an_error() {
        let cfg = parse(
            "addr = \"0.0.0.0:9000\"\ntls_cert = \"/c.pem\"\ntls_key = \"/k.pem\"\n\
             data_dir = \"/srv/hub\"\n",
        )
        .unwrap();
        assert_eq!(cfg.addr, "0.0.0.0:9000".parse().unwrap());
        assert_eq!(cfg.db_path(), Path::new("/srv/hub/hub.db"));
        assert_eq!(cfg.admin_socket(), Path::new("/srv/hub/admin.sock"));
        assert!(parse("tls_crt = \"/c.pem\"\n").is_err());
    }

    #[test]
    fn releases_are_fetched_from_virtkit_unless_configured_otherwise() {
        let source =
            |text: &str| parse(text).map(|c| c.release_source.map(|s| s.url().to_string()));
        assert_eq!(
            source("data_dir = \"/d\"\n").unwrap().as_deref(),
            Some(crate::fetch::DEFAULT_SOURCE)
        );
        assert_eq!(
            source("release_repository = \"https://ghe.example/ops/vk/\"\n")
                .unwrap()
                .as_deref(),
            Some("https://ghe.example/ops/vk")
        );
        assert_eq!(source("release_repository = \"none\"\n").unwrap(), None);
        let err = source("release_repository = \"http://github.com/a/b\"\n").unwrap_err();
        assert!(format!("{err:#}").contains("expected https://"), "{err:#}");
    }

    #[test]
    fn plain_http_is_refused_off_loopback() {
        let err = parse("addr = \"0.0.0.0:9000\"\ndata_dir = \"/d\"\n").unwrap_err();
        assert!(format!("{err:#}").contains("cleartext"), "{err:#}");
        assert!(parse("addr = \"127.0.0.1:9000\"\ndata_dir = \"/d\"\n").is_ok());
        assert!(parse("addr = \"[::1]:9000\"\ndata_dir = \"/d\"\n").is_ok());
        assert_eq!(parse("data_dir = \"/d\"\n").unwrap().addr, DEFAULT_ADDR);
    }

    #[test]
    fn the_web_ui_is_off_unless_asked_for_and_held_to_the_same_rules() {
        assert!(parse("data_dir = \"/d\"\n").unwrap().ui.is_none());
        let ui = parse("ui_addr = \"127.0.0.1:8444\"\ndata_dir = \"/d\"\n")
            .unwrap()
            .ui
            .unwrap();
        assert_eq!(ui.url, "http://127.0.0.1:8444");
        // Plain HTTP off loopback, for the UI too.
        let err = parse("ui_addr = \"0.0.0.0:8444\"\nui_url = \"http://h:8444\"\n").unwrap_err();
        assert!(format!("{err:#}").contains("cleartext"), "{err:#}");
        // The node listener's pair serves the UI unless it has its own; a wildcard address
        // needs the URL browsers use.
        let ui = parse(
            "addr = \"0.0.0.0:8443\"\ntls_cert = \"/c.pem\"\ntls_key = \"/k.pem\"\n\
             ui_addr = \"0.0.0.0:8444\"\nui_url = \"https://Hub.example:8444/\"\n",
        )
        .unwrap()
        .ui
        .unwrap();
        assert_eq!(ui.tls_cert.as_deref(), Some(Path::new("/c.pem")));
        assert_eq!(ui.url, "https://hub.example:8444");
        assert!(
            parse("ui_addr = \"0.0.0.0:8444\"\ntls_cert = \"/c\"\ntls_key = \"/k\"\n").is_err()
        );
        for bad in [
            "hub.example",
            "https://hub.example/ui",
            "ftp://h",
            "https://",
        ] {
            assert!(
                parse(&format!("ui_addr = \"127.0.0.1:1\"\nui_url = \"{bad}\"\n")).is_err(),
                "{bad}"
            );
        }
        assert!(parse("ui_url = \"http://127.0.0.1:1\"\n").is_err());
        // An http URL for a listener that serves TLS, its own pair or the node listener's.
        for tls in [
            "ui_tls_cert = \"/c\"\nui_tls_key = \"/k\"\n",
            "tls_cert = \"/c\"\ntls_key = \"/k\"\naddr = \"127.0.0.1:8443\"\n",
        ] {
            let err = parse(&format!(
                "ui_addr = \"127.0.0.1:8444\"\nui_url = \"http://127.0.0.1:8444\"\n{tls}"
            ))
            .unwrap_err();
            assert!(format!("{err:#}").contains("serves TLS"), "{err:#}");
        }
        // Origins as browsers write them: default ports dropped; http for loopback only.
        let url = |u: &str| parse_origin(u).map_err(|e| format!("{e:#}"));
        assert_eq!(
            url("HTTPS://Hub.example:443/").unwrap(),
            "https://hub.example"
        );
        assert_eq!(
            url("https://hub.example:08444").unwrap(),
            "https://hub.example:8444"
        );
        assert_eq!(url("http://127.0.0.1:80").unwrap(), "http://127.0.0.1");
        assert_eq!(
            url("http://127.9.0.1:8444").unwrap(),
            "http://127.9.0.1:8444"
        );
        assert_eq!(
            url("http://localhost:8444").unwrap(),
            "http://localhost:8444"
        );
        assert_eq!(url("http://[::1]:8444").unwrap(), "http://[::1]:8444");
        assert_eq!(url("https://[fd00::1]:443").unwrap(), "https://[fd00::1]");
        // IP literals as a browser writes them back, or refused when it would write them
        // otherwise.
        assert_eq!(url("https://[fd00:0::1]").unwrap(), "https://[fd00::1]");
        assert_eq!(url("http://[0:0::1]:8444").unwrap(), "http://[::1]:8444");
        for odd in [
            "https://127.1",
            "https://0x7f000001",
            "https://10.0.0.010",
            "https://a.1",
            "https://[::ffff:127.0.0.1]",
            "https://[::ffff:7f00:1]",
        ] {
            assert!(url(odd).unwrap_err().contains("expected"), "{odd}");
        }
        for plain in [
            "http://hub.example",
            "http://10.0.0.1:8444",
            "http://[fd00::1]",
        ] {
            assert!(
                url(plain).unwrap_err().contains("loopback host only"),
                "{plain}"
            );
        }
        for bad in [
            "https://h:0",
            "https://h:99999",
            "https://h:x",
            "https://[::1",
            "https://h:1:2",
        ] {
            assert!(url(bad).unwrap_err().contains("expected"), "{bad}");
        }
        // The one derived from a loopback address with TLS.
        let ui = parse("ui_addr = \"127.0.0.1:443\"\nui_tls_cert = \"/c\"\nui_tls_key = \"/k\"\n")
            .unwrap()
            .ui
            .unwrap();
        assert_eq!(ui.url, "https://127.0.0.1");
    }

    const UI_HTTPS: &str = "ui_addr = \"127.0.0.1:8444\"\nui_url = \"https://hub.example\"\n\
                            ui_tls_cert = \"/c\"\nui_tls_key = \"/k\"\n";

    fn oidc(table: &str) -> Result<OidcConfig> {
        let cfg = parse(&format!(
            "{UI_HTTPS}[oidc]\nissuer = \"https://login.example.com/app/1/\"\n\
             client_id = \"vk-hub\"\nclient_secret_file = \"/s\"\n{table}"
        ))?;
        Ok(cfg.ui.unwrap().oidc.unwrap())
    }

    #[test]
    fn oidc_needs_the_web_ui_over_https() {
        let err = |r: Result<OidcConfig>| format!("{:#}", r.unwrap_err());
        let o = oidc("").unwrap();
        assert_eq!(o.issuer, "https://login.example.com/app/1");
        assert_eq!(o.client_id, "vk-hub");
        assert_eq!(o.client_secret_file, Path::new("/s"));
        assert!(parse(&format!("{UI_HTTPS}[oidc]\nissuer = \"https://i\"\n")).is_err());
        // Roles are granted with `vk-hub accounts`: lists of them here are unknown keys.
        for key in ["operators", "viewers", "admins"] {
            let e = err(oidc(&format!("{key} = [\"a@b\"]\n")));
            assert!(e.contains("unknown field"), "{key}: {e}");
        }
        // The issuer, held to vk-registry's rules.
        let issuer = |i: &str| {
            parse(&format!(
                "{UI_HTTPS}[oidc]\nissuer = \"{i}\"\nclient_id = \"c\"\n\
                 client_secret_file = \"/s\"\n"
            ))
            .map_err(|e| format!("{e:#}"))
        };
        assert!(
            issuer("http://login.example.com")
                .unwrap_err()
                .contains("must be https")
        );
        assert!(
            issuer("https://login.example.com/?a=b")
                .unwrap_err()
                .contains("base URL")
        );
        assert!(issuer("http://127.0.0.1:9000").is_ok());
        let no_client = parse(&format!(
            "{UI_HTTPS}[oidc]\nissuer = \"https://i\"\nclient_id = \"\"\n\
             client_secret_file = \"/s\"\n"
        ));
        assert!(format!("{:#}", no_client.unwrap_err()).contains("client_id"));
        // Without the web UI, or with it over plain http.
        let table = "[oidc]\nissuer = \"https://i\"\nclient_id = \"c\"\n\
                     client_secret_file = \"/s\"\n";
        let e = format!("{:#}", parse(table).unwrap_err());
        assert!(e.contains("ui_addr"), "{e}");
        let e = format!(
            "{:#}",
            parse(&format!("ui_addr = \"127.0.0.1:8444\"\n{table}")).unwrap_err()
        );
        assert!(e.contains("over https"), "{e}");
    }

    #[test]
    fn half_a_tls_pair_is_refused() {
        let cfg = parse("tls_cert = \"/c.pem\"\ndata_dir = \"/d\"\n").unwrap();
        let Err(err) = cfg.build_tls() else {
            panic!("half a TLS pair was accepted");
        };
        assert!(format!("{err:#}").contains("together"), "{err:#}");
    }
}
