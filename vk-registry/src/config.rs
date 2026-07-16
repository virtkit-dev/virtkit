//! Server configuration: listen address, store root, relay upstreams, TLS, and client
//! auth.
//!
//! The listen address and store root usually come from the CLI; the TOML config file
//! carries the relay `[[upstream]]` entries, the TLS cert/key, and the auth credentials
//! (and may override addr/root). No upstreams ⇒ a plain local registry; no TLS ⇒ plain
//! HTTP; no auth ⇒ open. A central, network-exposed deployment sets all three.

use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
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

    /// Load from a TOML file. The CLI `addr` and optional `root` override the file; the
    /// store root falls back to the shared default when neither sets it.
    pub fn load(path: &Path, addr: SocketAddr, root: Option<PathBuf>) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let f: FileConfig =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        let addr = match f.addr {
            Some(a) => a.parse().with_context(|| format!("parsing addr {a:?}"))?,
            None => addr,
        };
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

fn load_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let mut r =
        BufReader::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::CertificateDer::pem_reader_iter(&mut r)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("reading certificates from {}", path.display()))
}

fn load_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                eprintln!(
                    "vk-registry: warning: TLS private key {} is group/world-accessible \
                     (mode {:o}); restrict it to 0600",
                    path.display(),
                    mode & 0o7777
                );
            }
        }
    }
    let mut r =
        BufReader::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::PrivateKeyDer::from_pem_reader(&mut r)
        .with_context(|| format!("reading a private key from {}", path.display()))
}
