//! `hub.toml`: where the hub listens, its TLS certificate, and where it keeps its data.
//!
//! ```toml
//! addr = "0.0.0.0:8443"
//! tls_cert = "/etc/vk-hub/cert.pem"
//! tls_key = "/etc/vk-hub/key.pem"
//! data_dir = "/var/lib/vk-hub"
//! ```
//!
//! Every key is optional. With no TLS the hub serves plain HTTP, which it accepts only on a
//! loopback address: enrollment tokens travel in the request body, and an authenticated
//! session carries no channel binding, so a node's session on an open network needs TLS.

use std::fs::File;
use std::io::BufReader;
use std::net::{Ipv4Addr, SocketAddr};
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
        Ok(HubConfig {
            addr,
            tls_cert: f.tls_cert,
            tls_key: f.tls_key,
            data_dir,
        })
    }

    /// The hub's database.
    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("hub.db")
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

fn build_tls(cert: Option<&Path>, key: Option<&Path>, what: &str) -> Result<Option<TlsAcceptor>> {
    let (cert, key) = match (cert, key) {
        (Some(c), Some(k)) => (c, k),
        (None, None) => return Ok(None),
        _ => bail!("{what} must be set together"),
    };
    let mut sc = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(load_certs(cert)?, load_key(key)?)
        .context("building the TLS server config")?;
    sc.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Some(TlsAcceptor::from(Arc::new(sc))))
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
    fn plain_http_is_refused_off_loopback() {
        let err = parse("addr = \"0.0.0.0:9000\"\ndata_dir = \"/d\"\n").unwrap_err();
        assert!(format!("{err:#}").contains("cleartext"), "{err:#}");
        assert!(parse("addr = \"127.0.0.1:9000\"\ndata_dir = \"/d\"\n").is_ok());
        assert!(parse("addr = \"[::1]:9000\"\ndata_dir = \"/d\"\n").is_ok());
        assert_eq!(parse("data_dir = \"/d\"\n").unwrap().addr, DEFAULT_ADDR);
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
