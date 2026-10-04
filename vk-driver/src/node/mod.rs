//! `vk node`: this host as a member of a fleet managed by a `vk-hub` (experimental).
//!
//! `vk node join` generates the node's ed25519 identity, passes the `vk check` gate, and
//! enrolls with the hub using a single-use token; `vk node run` then holds a session with the
//! hub for as long as it runs — inventory at the start and whenever it changes, a heartbeat
//! every few seconds — and redials with backoff whenever the session is lost, until SIGTERM
//! or SIGINT closes it cleanly or the hub refuses it for good.
//!
//! Everything the node keeps is under `<state_dir>/node/`, a `0700` directory: `key.pk8`
//! (the private key, `0600`), `enrollment.json` (the hub's URL and the node ID it assigned),
//! `ca.pem` (the CA the hub is verified against, copied at `join` when one was given) and
//! `lock`, which one `vk node` process at a time holds. A `join` whose answer was lost keeps
//! the key it made and joins again with a new token: the hub answers a key it already pinned
//! with the node it pinned it to.
//!
//! Both HTTP paths go straight to the hub, never through `HTTP(S)_PROXY`: the session is a
//! raw socket a proxy variable cannot reach, and enrollment follows the same route rather
//! than handing its token to a proxy.

mod identity;
mod inventory;
mod session;

use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use vk_hub_proto::{EnrollRequest, EnrollResponse, ErrorBody};

use crate::config::Config;
use identity::Identity;

const ENROLLMENT_FILE: &str = "enrollment.json";
const CA_FILE: &str = "ca.pem";
const LOCK_FILE: &str = "lock";

/// The first redial's delay, and the ceiling doubling reaches. A hub restart brings every
/// node back within seconds; a hub down for longer is not helped by being dialed more often.
const BACKOFF: (Duration, Duration) = (Duration::from_secs(1), Duration::from_secs(60));

/// A session that lasted this long was a working one, so the next failure starts the backoff
/// over rather than continuing it.
const STABLE_SESSION: Duration = Duration::from_secs(60);

/// A token or a CA bundle is a few kilobytes at most; this bounds what a wrong file costs.
const MAX_INPUT: u64 = 1 << 20;

/// What `join` leaves for `run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrollment {
    pub hub: String,
    pub node_id: String,
    /// Whether the hub is verified against `ca.pem` alone rather than the system's roots.
    #[serde(default)]
    pub ca: bool,
}

/// Where `join` reads the enrollment token from.
pub enum TokenSource {
    /// Given on the command line, where other local users can read it in the process list.
    Literal(String),
    Stdin,
    File(PathBuf),
}

impl TokenSource {
    fn read(&self) -> Result<String> {
        let mut text = String::new();
        match self {
            TokenSource::Literal(token) => {
                text.clone_from(token);
                token.len()
            }
            TokenSource::Stdin => std::io::stdin()
                .take(MAX_INPUT)
                .read_to_string(&mut text)
                .context("reading the token on stdin")?,
            TokenSource::File(path) => std::fs::File::open(path)
                .and_then(|f| f.take(MAX_INPUT).read_to_string(&mut text))
                .with_context(|| format!("reading the token from {}", path.display()))?,
        };
        let token = text.trim();
        if token.is_empty() || token.contains(char::is_whitespace) {
            bail!("expected one enrollment token, as `vk-hub token create` prints it");
        }
        Ok(token.to_string())
    }
}

/// `<state_dir>/node`.
fn dir(cfg: &Config) -> PathBuf {
    cfg.state_dir().join("node")
}

/// `vk node join`.
pub async fn join(cfg: &Config, hub: &str, token: &TokenSource, ca: Option<&Path>) -> Result<()> {
    let dir = dir(cfg);
    create_dir(&dir)?;
    let _lock = lock(&dir)?;
    match read_enrollment(&dir) {
        Ok(existing) => bail!(
            "this host is already enrolled as node {} with {} — remove {} to enroll it again, \
             as a new node",
            existing.node_id,
            existing.hub,
            dir.display()
        ),
        Err(e) if is_not_found(&e) => {}
        Err(e) => return Err(e),
    }
    let hub = normalize_hub_url(hub)?;
    let token = token.read()?;
    let failed: Vec<String> = inventory::checks(cfg)
        .into_iter()
        .filter(|c| !c.ok)
        .map(|c| format!("{}: {}", c.name, c.detail))
        .collect();
    if !failed.is_empty() {
        bail!(
            "this host fails `vk check`, so it cannot join a fleet:\n  {}",
            failed.join("\n  ")
        );
    }
    // Copied, so the node does not depend on a file elsewhere staying where it was, and
    // checked now rather than on the first `run`.
    let ca_pem = match ca {
        Some(path) => {
            let mut pem = Vec::new();
            std::fs::File::open(path)
                .and_then(|f| f.take(MAX_INPUT).read_to_end(&mut pem))
                .with_context(|| format!("reading {}", path.display()))?;
            roots_from_pem(&pem, path)?;
            Some(pem)
        }
        None => None,
    };
    let identity = Identity::load_or_create(&dir)?;
    let public_key = identity.public_key();
    let ask = EnrollRequest {
        token: token.clone(),
        public_key: vk_hub_proto::to_hex(public_key),
        signature: identity.sign(&vk_hub_proto::enroll_message(&token, public_key)),
        hostname: std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|h| h.trim().to_string())
            .unwrap_or_default(),
    };
    let node_id = enroll(&hub, ca_pem.as_deref(), &ask).await?;
    if let Some(pem) = &ca_pem {
        let path = dir.join(CA_FILE);
        vk_fs::write_atomic(&path, pem, 0o600)
            .with_context(|| format!("writing {}", path.display()))?;
    }
    let enrollment = Enrollment {
        hub: hub.clone(),
        node_id: node_id.clone(),
        ca: ca_pem.is_some(),
    };
    let json = serde_json::to_vec_pretty(&enrollment).context("encoding the enrollment")?;
    let path = dir.join(ENROLLMENT_FILE);
    vk_fs::write_atomic(&path, &json, 0o600)
        .with_context(|| format!("writing {}", path.display()))?;
    println!("vk node: enrolled with {hub} as node {node_id}; start it with `vk node run`");
    Ok(())
}

/// `POST /v1/enroll`, answering with the node ID the hub assigned.
async fn enroll(hub: &str, ca_pem: Option<&[u8]>, ask: &EnrollRequest) -> Result<String> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .no_proxy();
    if let Some(pem) = ca_pem {
        let certs =
            reqwest::Certificate::from_pem_bundle(pem).context("reading the CA certificates")?;
        builder = builder.tls_certs_only(certs);
    }
    let client = builder.build().context("building the HTTPS client")?;
    let url = format!("{hub}{}", vk_hub_proto::ENROLL_PATH);
    let resp = client
        .post(&url)
        .json(ask)
        .send()
        .await
        .with_context(|| format!("enrolling with {hub}"))?;
    let status = resp.status();
    let body = resp.bytes().await.context("reading the hub's answer")?;
    if !status.is_success() {
        let why = serde_json::from_slice::<ErrorBody>(&body)
            .map(|e| vk_hub_proto::display_safe(&e.error))
            .unwrap_or_else(|_| format!("HTTP {status}"));
        bail!("the hub refused the enrollment: {why}");
    }
    let answer: EnrollResponse =
        serde_json::from_slice(&body).context("the hub's enrollment answer is malformed")?;
    if !vk_hub_proto::valid_id(&answer.node_id) {
        bail!(
            "the hub assigned a malformed node ID {:?}",
            vk_hub_proto::display_safe(&answer.node_id)
        );
    }
    Ok(answer.node_id)
}

/// `vk node run`: hold a session with the hub, redialing until told to stop. Fails on a local
/// problem no redial can fix — no enrollment, an unreadable key — and when the hub refuses
/// the node for good (removed, or not the key it pinned).
pub async fn run(cfg: Config) -> Result<()> {
    let dir = dir(&cfg);
    let _lock = lock(&dir).map_err(|e| {
        if is_not_found(&e) {
            e.context("this host is not enrolled — run `vk node join <hub-url> --token -`")
        } else {
            e
        }
    })?;
    let enrollment = read_enrollment(&dir).map_err(|e| {
        if is_not_found(&e) {
            e.context("this host is not enrolled — run `vk node join <hub-url> --token -`")
        } else {
            e
        }
    })?;
    let identity = Identity::load(&dir).with_context(|| {
        format!(
            "loading the node's identity ({})",
            identity::key_path(&dir).display()
        )
    })?;
    let tls = client_tls(enrollment.ca.then(|| dir.join(CA_FILE)).as_deref())?;
    let incarnation = vk_hub_proto::to_hex(&random_bytes(vk_hub_proto::ID_BYTES)?);
    eprintln!(
        "vk node: node {} of {}, incarnation {incarnation}",
        enrollment.node_id, enrollment.hub
    );
    let mut stop = stop_on_signal()?;
    let mut gatherer = session::Gatherer::spawn(Arc::new(cfg));
    let node = session::Node {
        enrollment,
        identity,
        incarnation,
        tls,
    };
    hold_sessions(&node, &mut gatherer, &mut stop).await
}

/// Sessions back to back, with backoff between them, until the node is told to stop or the
/// hub refuses it for good.
async fn hold_sessions(
    node: &session::Node,
    gatherer: &mut session::Gatherer,
    stop: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let mut backoff = BACKOFF.0;
    loop {
        let started = Instant::now();
        match session::run(node, gatherer, stop).await {
            Ok(()) => {
                eprintln!("vk node: stopped");
                return Ok(());
            }
            Err(e) if e.is::<session::Permanent>() => return Err(e),
            Err(e) => eprintln!("vk node: {e:#}"),
        }
        if started.elapsed() >= STABLE_SESSION {
            backoff = BACKOFF.0;
        }
        let delay = jittered(backoff);
        eprintln!("vk node: reconnecting in {}s", delay.as_secs());
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            _ = stop.wait_for(|&s| s) => {
                eprintln!("vk node: stopped");
                return Ok(());
            }
        }
        backoff = (backoff * 2).min(BACKOFF.1);
    }
}

/// A flag raised by the first SIGTERM or SIGINT, for the session to close on.
fn stop_on_signal() -> Result<tokio::sync::watch::Receiver<bool>> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).context("handling SIGTERM")?;
    let mut int = signal(SignalKind::interrupt()).context("handling SIGINT")?;
    let (raise, stop) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
        // Nobody left to tell only when `run` has already returned.
        let _ = raise.send(true);
    });
    Ok(stop)
}

/// Hold `<dir>/lock` for as long as the returned file lives: one `vk node` process per state
/// dir, since two would supersede each other's sessions at the hub, or pair a key with an
/// enrollment made for another.
fn lock(dir: &Path) -> Result<std::fs::File> {
    let path = dir.join(LOCK_FILE);
    let file = std::fs::File::options()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|e| anyhow::Error::new(e).context(format!("opening {}", path.display())))?;
    // SAFETY: the fd is owned by `file`, which outlives the call; flock returns 0 or -1.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::WouldBlock {
            bail!(
                "another `vk node` is running on {} — one at a time per state dir",
                dir.display()
            );
        }
        return Err(e).with_context(|| format!("locking {}", path.display()));
    }
    Ok(file)
}

/// `d` plus up to a quarter more, so a fleet that lost its hub together does not redial it
/// in lockstep.
fn jittered(d: Duration) -> Duration {
    let spread = random_bytes(2)
        .map(|b| u32::from(u16::from_le_bytes([b[0], b[1]])))
        .unwrap_or(0);
    d + d / 4 * spread / u32::from(u16::MAX)
}

/// The certificates of a PEM bundle, refusing one that holds none.
fn roots_from_pem(pem: &[u8], origin: &Path) -> Result<rustls::RootCertStore> {
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

/// The TLS client configuration sessions dial with: the CA copied at `join` alone when there
/// was one — a hub with a private CA should not also be trusted on a public certificate —
/// else the platform's verifier, as `vk`'s other HTTPS clients use.
fn client_tls(ca: Option<&Path>) -> Result<Arc<rustls::ClientConfig>> {
    let config = match ca {
        Some(path) => {
            let pem = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
            rustls::ClientConfig::builder()
                .with_root_certificates(roots_from_pem(&pem, path)?)
                .with_no_client_auth()
        }
        None => {
            use rustls_platform_verifier::ConfigVerifierExt;
            rustls::ClientConfig::with_platform_verifier()
                .context("loading the platform's TLS verifier")?
        }
    };
    Ok(Arc::new(config))
}

/// The hub's URL without a trailing slash, checked: `https`, or `http` to a loopback hub —
/// the hub refuses cleartext off loopback, and a node should not send its enrollment token
/// that way either — and nothing but scheme, host and port.
fn normalize_hub_url(hub: &str) -> Result<String> {
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

fn read_enrollment(dir: &Path) -> Result<Enrollment> {
    let path = dir.join(ENROLLMENT_FILE);
    let text = std::fs::read(&path)
        .map_err(|e| anyhow::Error::new(e).context(format!("reading {}", path.display())))?;
    serde_json::from_slice(&text).with_context(|| format!("parsing {}", path.display()))
}

fn is_not_found(e: &anyhow::Error) -> bool {
    e.downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}

/// `dir`, `0700` — it holds the node's private key.
fn create_dir(dir: &Path) -> Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))
}

fn random_bytes(n: usize) -> Result<Vec<u8>> {
    use ring::rand::SecureRandom;
    let mut buf = vec![0u8; n];
    ring::rand::SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| anyhow!("the system random number generator failed"))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-node-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn hub_urls_are_https_or_loopback_http_and_bare() {
        assert_eq!(
            normalize_hub_url("https://hub.example.com/").unwrap(),
            "https://hub.example.com"
        );
        assert_eq!(
            normalize_hub_url("https://hub:8443").unwrap(),
            "https://hub:8443"
        );
        assert_eq!(
            normalize_hub_url("http://127.0.0.1:8443").unwrap(),
            "http://127.0.0.1:8443"
        );
        assert!(normalize_hub_url("http://[::1]:8443").is_ok());
        assert!(normalize_hub_url("http://localhost:8443").is_ok());
        for bad in [
            "http://hub.example.com",
            "ftp://hub",
            "https://hub/v1",
            "https://u@hub",
            "https://:p@hub",
            "https://hub/?x=1",
            "https://hub/#top",
            "hub:8443",
        ] {
            assert!(normalize_hub_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn jitter_stays_within_a_quarter() {
        for _ in 0..100 {
            let d = jittered(Duration::from_secs(8));
            assert!(
                d >= Duration::from_secs(8) && d <= Duration::from_secs(10),
                "{d:?}"
            );
        }
    }

    #[test]
    fn an_enrollment_round_trips_and_a_missing_one_is_not_found() {
        let dir = scratch("enroll");
        assert!(is_not_found(&read_enrollment(&dir).unwrap_err()));
        let e = Enrollment {
            hub: "https://hub".into(),
            node_id: "ab".repeat(16),
            ca: true,
        };
        std::fs::write(dir.join(ENROLLMENT_FILE), serde_json::to_vec(&e).unwrap()).unwrap();
        assert_eq!(read_enrollment(&dir).unwrap(), e);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn one_vk_node_holds_a_state_dir_at_a_time() {
        let dir = scratch("lock");
        let held = lock(&dir).unwrap();
        let err = lock(&dir).unwrap_err();
        assert!(format!("{err:#}").contains("another `vk node`"), "{err:#}");
        drop(held);
        lock(&dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_token_file_holds_exactly_one_token() {
        let dir = scratch("token");
        let path = dir.join("t");
        std::fs::write(&path, "vkh_abc\n").unwrap();
        assert_eq!(TokenSource::File(path.clone()).read().unwrap(), "vkh_abc");
        for bad in ["", "\n", "vkh_a vkh_b\n"] {
            std::fs::write(&path, bad).unwrap();
            assert!(TokenSource::File(path.clone()).read().is_err(), "{bad:?}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_ca_bundle_without_a_certificate_is_refused() {
        let err = roots_from_pem(b"not a certificate\n", Path::new("x.pem")).unwrap_err();
        assert!(format!("{err:#}").contains("no certificate"), "{err:#}");
    }
}
