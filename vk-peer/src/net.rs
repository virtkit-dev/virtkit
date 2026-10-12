//! Reaching the hub: its URL, TLS, enrollment, and the files a peer keeps beside its key.

use std::io::{BufRead, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use vk_hub_proto::{EnrollRequest, ErrorBody};

/// The most a token or a peer's own file is read to.
pub const MAX_INPUT: u64 = 1 << 20;

/// Where `join` reads the enrollment token from.
pub enum TokenSource {
    /// Given on the command line, where other local users can read it in the process list.
    Literal(String),
    Stdin,
    File(PathBuf),
}

impl TokenSource {
    /// Whether the token was given on the command line, where other local users can read it
    /// in the process list: the caller warns.
    pub fn on_command_line(&self) -> bool {
        matches!(self, TokenSource::Literal(_))
    }

    /// The token, one line of text without whitespace.
    pub fn read(&self) -> Result<String> {
        let text = match self {
            TokenSource::Literal(token) => token.clone(),
            // One line, so a token piped from a terminal or a process that keeps its end
            // open is taken without waiting for EOF.
            TokenSource::Stdin => {
                let mut line = String::new();
                std::io::stdin()
                    .lock()
                    .take(MAX_INPUT)
                    .read_line(&mut line)
                    .context("reading the token on stdin")?;
                line
            }
            TokenSource::File(path) => {
                let mut text = String::new();
                std::fs::File::open(path)
                    .and_then(|f| f.take(MAX_INPUT).read_to_string(&mut text))
                    .with_context(|| format!("reading the token from {}", path.display()))?;
                text
            }
        };
        let token = text.trim();
        if token.is_empty() || token.contains(char::is_whitespace) {
            bail!("expected one enrollment token, as `vk-hub token create` prints it");
        }
        Ok(token.to_string())
    }
}

/// Another `vk node` holds the state dir's lock.
#[derive(Debug)]
pub struct Locked(pub String);

impl std::fmt::Display for Locked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Locked {}

/// Hold `<dir>/<file>` locked for as long as the returned file lives, trying `tries` times
/// 100 ms apart; [`Locked`] names `who` holds it otherwise.
pub fn lock_tries(dir: &Path, file: &str, tries: u32, who: &str) -> Result<std::fs::File> {
    let path = dir.join(file);
    let file = std::fs::File::options()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|e| anyhow::Error::new(e).context(format!("opening {}", path.display())))?;
    for attempt in 0..tries {
        // SAFETY: the fd is owned by `file`, which outlives the call; flock returns 0 or -1.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(file);
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::WouldBlock {
            return Err(e).with_context(|| format!("locking {}", path.display()));
        }
        if attempt + 1 < tries {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    Err(anyhow::Error::new(Locked(format!(
        "another `{who}` is running on {} — one at a time per state dir",
        dir.display()
    ))))
}

/// The certificates of a PEM bundle, refusing one that holds none.
pub fn roots_from_pem(pem: &[u8], origin: &Path) -> Result<rustls::RootCertStore> {
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls::pki_types::CertificateDer::pem_slice_iter(pem) {
        let cert =
            cert.with_context(|| format!("reading certificates from {}", origin.display()))?;
        roots
            .add(cert)
            .with_context(|| format!("adding a CA certificate from {}", origin.display()))?;
    }
    if roots.is_empty() {
        bail!("{} holds no certificate", origin.display());
    }
    Ok(roots)
}

/// Verify sessions against the CA copied at `join` alone, if supplied: a private-CA hub
/// must not also be trusted through public roots. Otherwise use the platform verifier,
/// like `vk`'s other HTTPS clients.
pub fn client_tls(ca: Option<&Path>) -> Result<Arc<rustls::ClientConfig>> {
    // TLS 1.3 only: the auth signs the connection's exporter, which TLS 1.2 ties to the
    // handshake only with the extended master secret (RFC 7627).
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .context("building the TLS client config")?;
    let config = match ca {
        Some(path) => {
            let pem = read_nofollow(path)?;
            builder
                .with_root_certificates(roots_from_pem(&pem, path)?)
                .with_no_client_auth()
        }
        None => {
            use rustls_platform_verifier::BuilderVerifierExt;
            builder
                .with_platform_verifier()
                .context("loading the platform's TLS verifier")?
                .with_no_client_auth()
        }
    };
    Ok(Arc::new(config))
}

/// The hub's URL without a trailing slash, checked: `https`, or `http` to a loopback hub —
/// the hub refuses cleartext off loopback, and a node should not send its enrollment token
/// that way either — and nothing but scheme, host and port.
pub fn normalize_hub_url(hub: &str) -> Result<String> {
    let url = reqwest::Url::parse(hub).with_context(|| format!("parsing the hub URL {hub:?}"))?;
    let host = url.host_str().context("the hub URL has no host")?;
    let loopback = host == "localhost"
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        "http" => bail!("{hub}: a hub off loopback is reached over https"),
        other => bail!("{hub}: expected an https URL, not {other}"),
    }
    if url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("{hub}: give the hub's base URL, scheme://host[:port]");
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

/// A file of the node's, up to [`MAX_INPUT`], refusing a symlink in its place. A missing one
/// is an `io::Error` of kind `NotFound` at the root of the chain.
pub fn read_nofollow(path: &Path) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    std::fs::File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .and_then(|f| f.take(MAX_INPUT).read_to_end(&mut buf))
        .map_err(|e| anyhow::Error::new(e).context(format!("reading {}", path.display())))?;
    Ok(buf)
}

pub fn is_not_found(e: &anyhow::Error) -> bool {
    e.downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}

/// `dir`, `0700` — it holds the node's private key — and [`check_private`].
pub fn create_dir(dir: &Path) -> Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    check_private(dir)
}

/// Check that `dir` is private to this process's effective uid, using [`check_private_to`].
pub fn check_private(dir: &Path) -> Result<()> {
    // SAFETY: `geteuid` reads this process's own id and cannot fail.
    check_private_to(dir, unsafe { libc::geteuid() })
}

/// That `dir` is a directory of `uid`'s that nobody else can enter, judged off a descriptor
/// opened without following a symlink. A missing one is an `io::Error` of kind `NotFound` at
/// the root of the chain.
pub fn check_private_to(dir: &Path, uid: u32) -> Result<()> {
    let meta = std::fs::File::from(vk_fs::open_dir_nofollow(dir)?)
        .metadata()
        .with_context(|| format!("statting {}", dir.display()))?;
    if meta.uid() != uid || meta.mode() & 0o077 != 0 {
        bail!(
            "{} must belong to uid {uid} and be private to it (chmod 700); it is uid {} with \
             mode {:o}",
            dir.display(),
            meta.uid(),
            meta.mode() & 0o7777
        );
    }
    Ok(())
}

/// `POST <hub><path>` with the enrollment request `ask`, answering with what the hub sent back.
pub async fn enroll<R: serde::de::DeserializeOwned>(
    hub: &str,
    path: &str,
    ca_pem: Option<&[u8]>,
    ask: &EnrollRequest,
) -> Result<R> {
    // TLS 1.3 like the session, and no redirect: the token goes to the hub named and nowhere
    // else.
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .tls_version_min(reqwest::tls::Version::TLS_1_3);
    if let Some(pem) = ca_pem {
        let certs =
            reqwest::Certificate::from_pem_bundle(pem).context("reading the CA certificates")?;
        builder = builder.tls_certs_only(certs);
    }
    let client = builder.build().context("building the HTTPS client")?;
    let url = format!("{hub}{path}");
    let mut resp = client
        .post(&url)
        .json(ask)
        .send()
        .await
        .with_context(|| format!("enrolling with {hub}"))?;
    let status = resp.status();
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.context("reading the hub's answer")? {
        if body.len().saturating_add(chunk.len()) > vk_hub_proto::MAX_MESSAGE {
            bail!(
                "the hub's answer is larger than {} bytes",
                vk_hub_proto::MAX_MESSAGE
            );
        }
        body.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        let why = serde_json::from_slice::<ErrorBody>(&body)
            .map(|e| vk_hub_proto::display_safe(&e.error))
            .unwrap_or_else(|_| format!("HTTP {status}"));
        bail!("the hub refused the enrollment: {why}");
    }
    serde_json::from_slice(&body).context("the hub's enrollment answer is malformed")
}
