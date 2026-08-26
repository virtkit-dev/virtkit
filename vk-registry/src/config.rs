//! Server configuration: listen address, store root, relay upstreams, TLS, and client
//! auth.
//!
//! The listen address and store root usually come from the CLI; the TOML config file
//! carries the relay `[[upstream]]` entries, the TLS cert/key, and the auth credentials
//! (and may name addr/root, for the flags that were not passed). No upstreams ⇒ a plain
//! local registry; no TLS ⇒ plain HTTP; no auth ⇒ open. A central, network-exposed
//! deployment sets all three.

use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use tokio_rustls::TlsAcceptor;

use crate::auth::Auth;
use crate::lock::LockManager;
use crate::relay::Upstream;
use crate::{ServerState, Store};

/// Resolved server configuration, ready to turn into a [`ServerState`] (+ a TLS acceptor).
pub struct ServerConfig {
    pub addr: SocketAddr,
    pub root: PathBuf,
    pub upstreams: Vec<UpstreamSpec>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// Static bearer token file; when set, clients authenticate with it.
    pub token_file: Option<PathBuf>,
    /// HTTP Basic username (+ `password_file`); an alternative to `token_file`.
    pub username: Option<String>,
    pub password_file: Option<PathBuf>,
}

/// What a config file states about the server it would start, as stated — see
/// [`ServerConfig::file_view`].
pub struct FileView {
    /// the address it sets, if it sets one
    pub addr: Option<SocketAddr>,
    /// the store it names, if it names one
    pub root: Option<PathBuf>,
    /// whether it turns TLS on (both `tls_cert` and `tls_key`)
    pub tls: bool,
}

/// One upstream, as declared in the config file (before its HTTP client is built).
pub struct UpstreamSpec {
    pub prefix: String,
    pub url: String,
    pub username: Option<String>,
    pub password_file: Option<PathBuf>,
    pub ca_file: Option<PathBuf>,
}

#[derive(Deserialize)]
struct FileConfig {
    addr: Option<String>,
    root: Option<PathBuf>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    token_file: Option<PathBuf>,
    username: Option<String>,
    password_file: Option<PathBuf>,
    #[serde(default)]
    upstream: Vec<FileUpstream>,
}

#[derive(Deserialize)]
struct FileUpstream {
    /// repo-name prefix selecting this upstream; omitted/empty = catch-all
    #[serde(default)]
    prefix: String,
    url: String,
    username: Option<String>,
    password_file: Option<PathBuf>,
    ca_file: Option<PathBuf>,
}

/// Where the server listens when neither a flag nor a config file names an address.
/// Loopback: a store served to the world is a deliberate act, not a default.
pub const DEFAULT_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);

impl ServerConfig {
    /// A plain local registry: no upstreams, no TLS, no auth.
    pub fn local(addr: SocketAddr, root: PathBuf) -> Self {
        ServerConfig {
            addr,
            root,
            upstreams: Vec::new(),
            tls_cert: None,
            tls_key: None,
            token_file: None,
            username: None,
            password_file: None,
        }
    }

    /// The store root alone, for the commands that operate on a store without serving it
    /// (`status`, `gc`). The root is resolved in [`ServerConfig::load`]'s order — an
    /// explicit `--root` first, then the config file's, then the shared default — so a
    /// store configured for the server is the one they report on and sweep, instead of a
    /// default store the server never touches. Only the root is taken: a file whose
    /// `addr`/TLS/auth keys `serve` would reject still answers where the store is.
    pub fn root_of(config: Option<&Path>, root: Option<PathBuf>) -> Result<PathBuf> {
        if let Some(r) = root {
            return Ok(r);
        }
        if let Some(path) = config
            && let Some(r) = read_file(path)?.root
        {
            return Ok(r);
        }
        crate::default_root()
    }

    /// What a `serve` config file states, for whoever has to describe the server it will
    /// start without starting one — `install-service`, building a unit around it. `None`
    /// where the file says nothing, so a caller can tell a setting it named from a default
    /// standing in for it, which [`ServerConfig::load`] deliberately cannot.
    ///
    /// One read, so an address and a store taken from the same file are taken from the same
    /// contents of it.
    pub fn file_view(path: &Path) -> Result<FileView> {
        let f = read_file(path)?;
        Ok(FileView {
            addr: parse_addr(f.addr)?,
            root: f.root,
            // Both keys, the pair `build_tls` insists on: a half-configured one is `serve`'s
            // error to raise, not this caller's.
            tls: f.tls_cert.is_some() && f.tls_key.is_some(),
        })
    }

    /// Load from a TOML file. An explicitly passed `addr`/`root` outranks the file's; the
    /// address falls back to [`DEFAULT_ADDR`] and the store root to the shared default when
    /// neither names one.
    pub fn load(path: &Path, addr: Option<SocketAddr>, root: Option<PathBuf>) -> Result<Self> {
        let f = read_file(path)?;
        // Parsed even when a flag outranks it: a typo in the key is worth an error rather
        // than silence, and the caller may have passed no flag on the next run.
        let file_addr = parse_addr(f.addr)?;
        let addr = addr.or(file_addr).unwrap_or(DEFAULT_ADDR);
        let root = match root.or(f.root) {
            Some(r) => r,
            None => crate::default_root()?,
        };
        let upstreams = f
            .upstream
            .into_iter()
            .map(|u| UpstreamSpec {
                prefix: u.prefix,
                url: u.url.trim_end_matches('/').to_string(),
                username: u.username,
                password_file: u.password_file,
                ca_file: u.ca_file,
            })
            .collect();
        Ok(ServerConfig {
            addr,
            root,
            upstreams,
            tls_cert: f.tls_cert,
            tls_key: f.tls_key,
            token_file: f.token_file,
            username: f.username,
            password_file: f.password_file,
        })
    }

    /// Build the TLS acceptor from the configured cert/key, or `None` for plain HTTP.
    /// The two must be set together.
    pub fn build_tls(&self) -> Result<Option<TlsAcceptor>> {
        let (cert, key) = match (&self.tls_cert, &self.tls_key) {
            (Some(c), Some(k)) => (c, k),
            (None, None) => return Ok(None),
            _ => bail!("tls_cert and tls_key must be set together"),
        };
        let certs = load_certs(cert)?;
        let key = load_key(key)?;
        let mut sc = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("building the TLS server config")?;
        sc.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Some(TlsAcceptor::from(Arc::new(sc))))
    }

    /// The client-auth scheme: a bearer token file takes precedence, else Basic from a
    /// username + password file, else open.
    fn build_auth(&self) -> Result<Auth> {
        if self.token_file.is_some() && self.username.as_ref().is_some_and(|u| !u.is_empty()) {
            bail!(
                "configure either token_file or username/password_file for client auth, not both"
            );
        }
        if let Some(tf) = &self.token_file {
            let token = std::fs::read_to_string(tf)
                .with_context(|| format!("reading {}", tf.display()))?
                .trim()
                .to_string();
            if token.is_empty() {
                bail!("token file {} is empty", tf.display());
            }
            return Ok(Auth::Bearer { token });
        }
        if let Some(user) = self.username.as_ref().filter(|u| !u.is_empty()) {
            let pf = self
                .password_file
                .as_ref()
                .context("username set but no password_file")?;
            let pass = std::fs::read_to_string(pf)
                .with_context(|| format!("reading {}", pf.display()))?
                .trim_end()
                .to_string();
            return Ok(Auth::Basic {
                user: user.clone(),
                pass,
            });
        }
        Ok(Auth::None)
    }

    /// Build the shared runtime state: open the store, build each upstream's HTTP client
    /// (reading its password file), the lock manager, and the auth scheme. TLS is set
    /// separately by the serve path.
    pub fn into_state(self) -> Result<ServerState> {
        let auth = self.build_auth()?;
        // Auth over plain HTTP on a routable address would put the bearer token / Basic
        // password on the wire in cleartext; refuse it rather than silently expose creds.
        if auth.enabled() && self.tls_cert.is_none() && !self.addr.ip().is_loopback() {
            bail!(
                "client auth is enabled without TLS on non-loopback address {} — credentials \
                 would be sent in cleartext; set tls_cert/tls_key or bind a loopback address",
                self.addr
            );
        }
        let store = Arc::new(Store::new(self.root)?);
        let upstreams = self
            .upstreams
            .into_iter()
            .map(UpstreamSpec::build)
            .collect::<Result<Vec<_>>>()?;
        Ok(ServerState {
            store,
            upstreams,
            locks: LockManager::new(),
            auth,
            tls: None,
        })
    }
}

impl UpstreamSpec {
    fn build(self) -> Result<Upstream> {
        let mut b = reqwest::Client::builder();
        if let Some(ca) = &self.ca_file {
            let pem = std::fs::read(ca).with_context(|| format!("reading {}", ca.display()))?;
            b = b.add_root_certificate(
                reqwest::Certificate::from_pem(&pem).context("parsing an upstream CA")?,
            );
        }
        let client = b.build().context("building an upstream HTTP client")?;
        let password = match &self.password_file {
            Some(p) => Some(
                std::fs::read_to_string(p)
                    .with_context(|| format!("reading {}", p.display()))?
                    .trim_end()
                    .to_string(),
            ),
            None => None,
        };
        Ok(Upstream {
            prefix: self.prefix,
            base: self.url,
            username: self.username.filter(|u| !u.is_empty()),
            password,
            client,
        })
    }
}

/// The `addr` key of a config file, parsed. Shared by [`ServerConfig::load`] and
/// [`ServerConfig::file_view`], so a bad address reads the same whichever asks.
fn parse_addr(addr: Option<String>) -> Result<Option<SocketAddr>> {
    addr.map(|a| a.parse().with_context(|| format!("parsing addr {a:?}")))
        .transpose()
}

/// Read + parse a config file, named in the error whichever way it fails. Shared by
/// [`ServerConfig::load`] and [`ServerConfig::root_of`], so `serve` and the store commands
/// read the same file the same way.
fn read_file(path: &Path) -> Result<FileConfig> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

fn load_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let mut r =
        BufReader::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::CertificateDer::pem_reader_iter(&mut r)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("reading certificates from {}", path.display()))
}

fn load_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    crate::warn_if_file_mode(
        &file,
        path,
        0o077,
        "TLS private key",
        "it is group/world-accessible — restrict it to 0600",
    );
    let mut r = BufReader::new(file);
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::PrivateKeyDer::from_pem_reader(&mut r)
        .with_context(|| format!("reading a private key from {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a config file states, for a unit built around it: the address and store it
    /// names, and whether it turns TLS on. `None` where it says nothing, which is the part
    /// `load` cannot report — it substitutes the shared default and the caller can no longer
    /// tell the two apart.
    #[test]
    fn a_file_view_reports_what_the_file_states_and_what_it_leaves_open() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-view-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let write = |name: &str, body: &str| {
            let p = dir.join(name);
            std::fs::write(&p, body).unwrap();
            p
        };

        let tls = write(
            "tls.toml",
            "addr = \"0.0.0.0:443\"\ntls_cert = \"/c.pem\"\ntls_key = \"/k.pem\"\n",
        );
        let v = ServerConfig::file_view(&tls).unwrap();
        assert_eq!(v.addr, Some("0.0.0.0:443".parse().unwrap()));
        assert_eq!(v.root, None);
        assert!(v.tls);
        // and it agrees with the address `serve` itself will listen on
        assert_eq!(
            ServerConfig::load(&tls, None, None).unwrap().addr,
            v.addr.unwrap()
        );

        // a file that states neither: the view says so, where `load` would hand back the
        // built-in address and the shared default store as if the file had named them
        let bare = write("bare.toml", "username = \"ci\"\n");
        let v = ServerConfig::file_view(&bare).unwrap();
        assert_eq!((v.addr, v.root, v.tls), (None, None, false));
        assert_eq!(
            ServerConfig::load(&bare, None, None).unwrap().addr,
            DEFAULT_ADDR
        );

        // one TLS key without the other is not TLS here: `serve` is what refuses the pair,
        // so describing a unit must not be the thing that fails on it
        let half = write("half.toml", "tls_cert = \"/c.pem\"\n");
        assert!(!ServerConfig::file_view(&half).unwrap().tls);
        assert!(
            ServerConfig::load(&half, None, None)
                .unwrap()
                .build_tls()
                .is_err()
        );

        // an unreadable file is an error, not an empty view
        assert!(ServerConfig::file_view(&dir.join("absent.toml")).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An address passed on the command line outranks the config file's, the order
    /// `--root` already followed: the file is the standing configuration, a flag is this
    /// run's override of it.
    #[test]
    fn an_explicit_addr_outranks_the_config_file() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-addr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let write = |name: &str, body: &str| {
            let p = dir.join(name);
            std::fs::write(&p, body).unwrap();
            p
        };
        let flag: SocketAddr = "127.0.0.1:6000".parse().unwrap();

        let named = write("named.toml", "addr = \"0.0.0.0:443\"\n");
        assert_eq!(
            ServerConfig::load(&named, Some(flag), None).unwrap().addr,
            flag
        );
        // and the file still supplies it for the run that passes no flag
        assert_eq!(
            ServerConfig::load(&named, None, None).unwrap().addr,
            "0.0.0.0:443".parse::<SocketAddr>().unwrap()
        );

        // neither names one: the built-in default
        let bare = write("bare.toml", "username = \"ci\"\n");
        assert_eq!(
            ServerConfig::load(&bare, None, None).unwrap().addr,
            DEFAULT_ADDR
        );

        // an unparseable `addr` is an error even on the run whose flag outranks it, so a
        // typo in the file surfaces instead of waiting for the run that relies on it
        let bad = write("bad.toml", "addr = \"h:t:t:p\"\n");
        assert!(ServerConfig::load(&bad, Some(flag), None).is_err());
        assert!(ServerConfig::load(&bad, None, None).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The store root `status`/`gc` resolve, in the order `serve` resolves it: an explicit
    /// `--root` first, then the config file's, then the shared default. The file is what
    /// used to be skipped — leaving those two commands on a default store the server never
    /// touches.
    #[test]
    fn root_of_prefers_the_flag_then_the_file() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-cfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("registry.toml");
        std::fs::write(&path, "root = \"/srv/store\"\n").unwrap();

        assert_eq!(
            ServerConfig::root_of(Some(&path), Some(PathBuf::from("/flag"))).unwrap(),
            PathBuf::from("/flag")
        );
        assert_eq!(
            ServerConfig::root_of(Some(&path), None).unwrap(),
            PathBuf::from("/srv/store")
        );
        // a file that sets no root falls through to the default, as it does for `serve`
        let bare = dir.join("bare.toml");
        std::fs::write(&bare, "addr = \"127.0.0.1:5001\"\n").unwrap();
        assert_eq!(
            ServerConfig::root_of(Some(&bare), None).unwrap(),
            crate::default_root().unwrap()
        );
        assert_eq!(
            ServerConfig::load(&bare, None, None).unwrap().root,
            ServerConfig::root_of(Some(&bare), None).unwrap()
        );
        assert_eq!(
            ServerConfig::root_of(None, None).unwrap(),
            crate::default_root().unwrap()
        );
        // and a config file that is not there is an error, not a silent default
        assert!(ServerConfig::root_of(Some(&dir.join("absent.toml")), None).is_err());

        // The same file resolves the same root through `serve`'s own loader, with and
        // without the flag: the two must not drift into sweeping different stores.
        assert_eq!(
            ServerConfig::load(&path, None, None).unwrap().root,
            ServerConfig::root_of(Some(&path), None).unwrap()
        );
        assert_eq!(
            ServerConfig::load(&path, None, Some(PathBuf::from("/flag")))
                .unwrap()
                .root,
            ServerConfig::root_of(Some(&path), Some(PathBuf::from("/flag"))).unwrap()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
