//! Per-VM credential-injecting registry proxy.
//!
//! When enabled (per-VM `vk run --registry-proxy`, or runner-wide `[registry] proxy_guests`
//! for the executor), `vk` runs this HTTP reverse proxy on a Unix socket of the host and
//! forwards the guest to it (the switch redirects a sentinel address — `registry.vk` — to
//! it; see switch.rs). The guest's registry client talks plain, credential-free HTTP to it;
//! the proxy adds the credential it was given on the way to the real (central) registry. So
//! the job never holds the secret, and the proxy is never exposed on a network interface:
//! the guest reaches it through the switch's per-VM redirect only.
//!
//! The socket is an abstract one ([`ProxySocket`]), a namespace with no permissions, so each
//! end requires the other's uid to be its own: the proxy serves no other peer, which keeps
//! the credential from the host's other users, and the switch forwards a guest to no other
//! listener ([`connect`]). The overflow uid, which the kernel reports for any user it cannot
//! map into the asking user namespace, passes at neither end: a `vk` running as it gets no
//! proxy.
//!
//! Bodies stream both ways (`bytes_stream`), so pushing/pulling multi-GB layers through
//! the proxy never buffers a whole blob in memory, and no response has a deadline: a lock
//! acquire long-polls for as long as the registry holds it.
//!
//! The registry restarting — refusing connections, cutting them, or turning requests away — is
//! ridden out as other registry transfers ride it out ([`crate::registry::with_request_retry`]),
//! sharing their note of a registry found unreachable: a request that gets no answer, or is
//! turned away, is sent again when a second one does what the first would have
//! ([`repeatable`]), its body held for that up to [`MAX_HELD`]; once the retries are spent, the
//! guest gets the registry's last refusal, or a 502 when the last attempt got no answer. A
//! blob or manifest addressed by digest resumes from the first unsent byte if its response
//! is cut short ([`Resume`]). Other truncated responses reach the guest cut short: once
//! status and headers have been sent, the guest's client must start over.
//!
//! What the proxy lends decides what it forwards ([`Scope`]). The node's own credential is
//! not scoped, so it reaches the OCI API only (`/v2/`). A job's registry token, which the hub
//! scoped to the job's namespaces (`[registry] guest_credential = "job"`), also reaches the
//! lock API (`/lock/`) and plain files through `/files/`, WebDAV (`/dav/files/`) and S3
//! (`/s3/`, for sccache with `SCCACHE_S3_NO_CREDENTIALS=true`). The registry enforces the
//! token's grants on each. A job meant to have a token and given none gets a proxy that forwards
//! nothing. A job no hub placed, under `guest_credential = "job-or-node"`, gets the token the
//! hub gives the node for its runner's guests on the same paths, read again for each request so
//! a renewal reaches a running job; while the node holds none, the proxy forwards nothing.
//!
//! A job's token may come with areas ([`Area`]): `job/<alias>` in an OCI, file or S3 path, or
//! before the `:` of a lock name, stands for the area's prefix, so a guest names a fixed path
//! whatever its project or protection. No other query parameter is mapped, an OCI mount's
//! `from=` among them. Only requests are rewritten: the registry answers with the real names
//! (an upload's `Location`, a lock's holders), which the proxy forwards too. A `PROPFIND`'s
//! hrefs are the exception, mapped back to the alias, since a WebDAV client resolves a listing
//! against the root it asked for.
//!
//! A credential lent for some areas only ([`Scope::Areas`], [`ProxyCfg::for_areas`]) is not
//! one the registry scopes, so the proxy does: it forwards the `/v2/` ping, reading and
//! writing manifests and blobs in the repositories under an area's prefix, reading and
//! writing sccache's S3 objects under one, and taking, renewing and releasing locks whose
//! every name is under one ([`confined`]). Each request
//! is checked once resolved and mapped, and sent with the headers those requests use and no
//! other; a redirect is returned to the guest rather than followed, since the request it
//! leads to would be sent with the credential, unchecked. Every refusal is logged on the
//! host. The proxy confines the names a request uses, not what the registry serves under
//! them: see [`Scope::Areas`].

use std::convert::Infallible;
use std::os::linux::net::SocketAddrExt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use futures::TryStreamExt;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{UnixListener, UnixStream};

use vk_hub_proto::dispatch::Area;
use vk_hub_proto::token::{ALIAS_ROOT, servable_prefix, under, valid_component, valid_prefix};

use crate::oci::Creds;
use vk_registry::hostlock;

/// The proxy's streaming response body: not `Sync` because [`Resume`] holds the request
/// for the remaining bytes across an await.
type ProxyBody = UnsyncBoxBody<Bytes, std::io::Error>;

/// The name the guest reaches the proxy at.
pub const GUEST_HOST: &str = "registry.vk";

/// The plain files' path, and the methods forwarded under it: vk-registry's for `/dav/files/`.
const DAV_FILES: &str = "/dav/files/";
const DAV_FILES_METHODS: &[&str] = &[
    "GET", "HEAD", "PROPFIND", "PUT", "MKCOL", "DELETE", "OPTIONS",
];

/// Forward the methods vk-registry supports under `/files/`.
const FILES: &str = "/files/";
const FILES_METHODS: &[&str] = &["GET", "HEAD", "PUT", "DELETE"];

/// `/s3/<bucket>/<key>` and `/files/<bucket>/<key>` address the same stored tag.
/// Forward every method so the registry can return S3 errors for unsupported operations.
const S3: &str = "/s3/";

/// Which of the registry's paths the proxy forwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// The OCI API only, `/v2/`: what an unscoped credential may be lent for.
    Oci,
    /// A job token reaches `/v2/`, `/lock/`, `/files/`, `/dav/files/` and `/s3/` under its
    /// registry grants.
    Job,
    /// Nothing: a job that should have had a token and has none.
    Deny,
    /// The `/v2/` ping, and OCI requests, locks and `/s3/` objects within the proxy's areas
    /// only ([`confined`]): a credential the registry does not scope, lent for those areas.
    ///
    /// This confines the repository and lock names a guest uses, and nothing else. A
    /// registry serves such a credential any blob or manifest of its store by digest,
    /// through whichever repository asks, so the store must hold the areas' content only:
    /// lent for a store shared with other repositories, the credential reads their content
    /// by digest too.
    Areas,
}

impl Scope {
    /// The path prefixes forwarded, below the upstream's own path.
    fn paths(self) -> &'static [&'static str] {
        match self {
            Scope::Oci => &["/v2/"],
            Scope::Job => &["/v2/", "/lock/", FILES, DAV_FILES, S3],
            Scope::Deny => &[],
            Scope::Areas => &["/v2/", "/lock/", S3],
        }
    }
}

/// What the proxy forwards to and injects.
pub struct ProxyCfg {
    /// The upstream's base URL, optionally with a path prefix (no trailing slash).
    upstream: String,
    /// The parsed upstream, whose origin every forwarded request must keep
    base: reqwest::Url,
    /// `base`'s path, without a trailing `/`: what every forwarded path starts with, before
    /// one of the scope's paths
    root: String,
    scope: Scope,
    /// The areas whose aliases are mapped, under [`Scope::Job`] and [`Scope::Areas`]. Under
    /// [`Scope::Areas`] they are also all the credential is lent for.
    areas: Vec<Area>,
    /// The credential injected into every forwarded request, so the job stays
    /// credential-free — and the trust anchor `client` was built against.
    pub creds: Creds,
    /// Where the token the node lends its runner's guests is read for each request, injected
    /// in place of `creds`' ([`ProxyCfg::for_guests`]).
    guests: Option<crate::node::registry_access::Source>,
    pub client: reqwest::Client,
}

impl ProxyCfg {
    /// Build from the `vk run --registry-proxy` flags: `upstream` is the base URL,
    /// optionally with a path prefix, `creds` both what to inject and what TLS to trust.
    pub fn from_parts(upstream: &str, creds: Creds) -> Result<Self> {
        Self::build(upstream.trim_end_matches('/').to_string(), creds)
    }

    /// Build from the runner's `[registry]` config (the executor path): the central
    /// registry's base URL, and the section's own credential — a bearer token when one is
    /// configured, else the Basic pair. Never the node's token from its hub: a guest could
    /// exercise everything it grants.
    pub fn from_registry(rg: &crate::config::Registry) -> Result<Self> {
        Self::build(Self::upstream_of(rg)?, Creds::from_registry_own(rg)?)
    }

    fn upstream_of(rg: &crate::config::Registry) -> Result<String> {
        Ok(rg
            .base_url()
            .context("the registry proxy needs a remote [registry]")?
            .0)
    }

    /// Build for a placed job under `[registry] guest_credential = "job"`: the runner's
    /// `[registry]` as upstream and trust anchor, injecting the job's `token` and nothing of
    /// the section's own credential; with no token, a proxy that forwards nothing.
    pub fn for_job(rg: &crate::config::Registry, token: Option<&str>) -> Result<Self> {
        // Built field by field, so no credential the section holds, now or later, is lent.
        let creds = Creds {
            username: None,
            password: None,
            token: token.map(str::to_string),
            ca_pem: None,
            insecure: rg.insecure,
        }
        .with_ca_file(rg.ca_file.as_deref())?;
        let mut cfg = Self::build(Self::upstream_of(rg)?, creds)?;
        cfg.scope = match token {
            Some(_) => Scope::Job,
            None => Scope::Deny,
        };
        Ok(cfg)
    }

    /// Build for a job no hub placed under `[registry] guest_credential = "job-or-node"`: the
    /// runner's `[registry]` as upstream and trust anchor, injecting the token the hub gives the
    /// node for its runner's guests, as it stands at each request, and nothing of the section's
    /// own credential nor the node's own token; for a registry the hub does not name, a proxy
    /// that forwards nothing.
    pub fn for_guests(rg: &crate::config::Registry) -> Result<Self> {
        let mut cfg = Self::for_job(rg, None)?;
        if let Some(source) = &rg.node_access {
            cfg.scope = Scope::Job;
            cfg.guests = Some(source.clone());
        }
        Ok(cfg)
    }

    /// Set [`Self::for_job`]'s areas to those [`usable_areas`] keeps. Log each rejected area
    /// to the host's stderr without failing the job; its other paths still work.
    /// `VK_REGISTRY_AREAS` also omits rejected areas. [`Self::for_areas`]'s areas stay as
    /// it checked them: they are what its credential is lent for.
    pub fn with_areas(mut self, areas: &[Area]) -> Self {
        if self.scope == Scope::Areas {
            return self;
        }
        self.areas = usable_areas(areas, |a, why| {
            eprintln!(
                "virtkit: registry proxy: skipping the job's area {:?} at {:?}: {why}",
                a.alias, a.prefix
            )
        })
        .into_iter()
        .cloned()
        .collect();
        self
    }

    /// Build to lend `creds` within `areas` only ([`Scope::Areas`]): `upstream` is the
    /// registry's base URL, `creds` both what to inject and what TLS to trust. An area
    /// [`usable_areas`] rejects is an error, as is a prefix the registry serves no
    /// repository under ([`servable_prefix`]): nothing else names what the credential is
    /// lent for.
    pub fn for_areas(upstream: &str, creds: Creds, areas: &[Area]) -> Result<Self> {
        let mut rejected = None;
        let kept = usable_areas(areas, |a, why| {
            rejected.get_or_insert_with(|| format!("area {:?} at {:?}: {why}", a.alias, a.prefix));
        });
        if let Some(rejected) = rejected {
            bail!("the registry proxy cannot serve {rejected}");
        }
        if let Some(a) = kept.iter().find(|a| !servable_prefix(&a.prefix)) {
            bail!(
                "the registry proxy cannot serve area {:?} at {:?}: the registry serves no \
                 repository under the prefix",
                a.alias,
                a.prefix
            );
        }
        // No redirect is followed: the request it leads to would be sent with the
        // credential without having passed the area checks. The guest gets the redirect
        // itself. Nor does any HTTP proxy the environment names see the credential: the
        // registry is one this process serves itself, on loopback ([`crate::sharedcache`]).
        let mut cfg = Self::build_with(
            upstream.trim_end_matches('/').to_string(),
            creds,
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy(),
        )?;
        cfg.scope = Scope::Areas;
        cfg.areas = kept.into_iter().cloned().collect();
        Ok(cfg)
    }

    fn build(upstream: String, creds: Creds) -> Result<Self> {
        Self::build_with(upstream, creds, reqwest::Client::builder())
    }

    /// [`Self::build`], its client made by `b` with the trust `creds` adds.
    fn build_with(upstream: String, creds: Creds, mut b: reqwest::ClientBuilder) -> Result<Self> {
        let base = reqwest::Url::parse(&upstream)
            .with_context(|| format!("parsing the registry proxy upstream {upstream:?}"))?;
        anyhow::ensure!(
            matches!(base.scheme(), "http" | "https")
                && base.has_host()
                && base.query().is_none()
                && base.fragment().is_none(),
            "the registry proxy upstream {upstream:?} is not an http(s) URL"
        );
        // `--insecure` means plain HTTP on every OCI path, never "accept any certificate":
        // that would hand the injected credential to whoever can terminate the TLS link. A
        // private CA goes through `--ca`.
        if creds.insecure && base.scheme() == "https" {
            bail!(
                "--registry-proxy {upstream} with --insecure: --insecure means a plain HTTP \
                 registry, so give an http:// upstream, or --ca for a TLS one signed by a \
                 private CA"
            );
        }
        let root = base.path().trim_end_matches('/').to_string();
        if let Some(pem) = &creds.ca_pem {
            b = b.add_root_certificate(
                reqwest::Certificate::from_pem(pem).context("parsing the registry CA")?,
            );
        }
        Ok(ProxyCfg {
            upstream,
            base,
            root,
            scope: Scope::Oci,
            areas: Vec::new(),
            creds,
            guests: None,
            client: b.build().context("building the registry proxy client")?,
        })
    }
}

/// The areas of `areas` a job's proxy maps, in order, each other one told to `skipped` with why:
/// an alias that is not one repository name component or repeats an earlier one, or a prefix
/// that is not a repository name or lies under [`ALIAS_ROOT`], where it would be mapped again.
/// The hub sends none of those; the proxy and `VK_REGISTRY_AREAS` both leave them out, so a job
/// is never told of an alias its proxy does not map.
pub fn usable_areas(areas: &[Area], mut skipped: impl FnMut(&Area, &str)) -> Vec<&Area> {
    let mut kept: Vec<&Area> = Vec::new();
    for a in areas {
        let why = if !valid_component(&a.alias) {
            Some("the alias is not a repository name component")
        } else if !valid_prefix(&a.prefix) || under(ALIAS_ROOT, &a.prefix) {
            Some("the prefix is not a repository name, or lies under job/")
        } else if kept.iter().any(|b| b.alias == a.alias) {
            Some("an earlier area has the alias")
        } else {
            None
        };
        match why {
            Some(why) => skipped(a, why),
            None => kept.push(a),
        }
    }
    kept
}

/// The proxy's abstract Unix socket, written `@virtkit-regproxy-<32 lowercase hex digits>`
/// as the switch takes it on its command line. The digits are random, so the name cannot be
/// guessed and bound before the proxy binds it. It is no secret afterward (a command line is
/// readable by the host's other users): what keeps them out is the check each end makes of
/// the other's uid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxySocket {
    name: String,
}

impl ProxySocket {
    const PREFIX: &str = "virtkit-regproxy-";

    /// A name with 128 bits of `/dev/urandom`.
    pub(crate) fn random() -> Result<Self> {
        let name = format!(
            "{}{}{}",
            Self::PREFIX,
            crate::scratch::random_nonce()?,
            crate::scratch::random_nonce()?
        );
        Ok(Self { name })
    }

    fn addr(&self) -> std::io::Result<std::os::unix::net::SocketAddr> {
        std::os::unix::net::SocketAddr::from_abstract_name(&self.name)
    }
}

impl std::fmt::Display for ProxySocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "@{}", self.name)
    }
}

impl std::str::FromStr for ProxySocket {
    type Err = anyhow::Error;

    /// Only what [`ProxySocket::random`] produces, as `Display` writes it.
    fn from_str(s: &str) -> Result<Self> {
        let digits = s
            .strip_prefix('@')
            .and_then(|name| name.strip_prefix(Self::PREFIX));
        match digits {
            Some(d)
                if d.len() == 32 && d.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) =>
            {
                Ok(Self {
                    name: s[1..].to_string(),
                })
            }
            _ => bail!("want @{}<32 lowercase hex digits>", Self::PREFIX),
        }
    }
}

/// The uid the kernel reports in place of one that has no mapping in the user namespace
/// asking (`/proc/sys/kernel/overflowuid`, 65534 unless the host changed it), read once.
/// It names no user: every peer from outside the namespace's mappings reads as it.
fn overflow_uid() -> u32 {
    static UID: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *UID.get_or_init(|| {
        std::fs::read_to_string("/proc/sys/kernel/overflowuid")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(65534)
    })
}

/// Whether the other end of a proxy connection, running as `peer` (`None` when the kernel
/// does not say), is the user `me`. Never when `me` is the `overflow` uid: a peer the kernel
/// cannot name reads as that uid too.
fn same_user(peer: Option<u32>, me: u32, overflow: u32) -> bool {
    me != overflow && peer == Some(me)
}

/// How a refusal names the other end of a connection.
fn uid_label(peer: Option<u32>) -> String {
    peer.map_or_else(|| "an unknown user".to_string(), |uid| format!("uid {uid}"))
}

/// The uid this process runs as, which each end of a proxy connection requires of the other.
pub fn euid() -> u32 {
    // SAFETY: geteuid(2) has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// [`euid`], for a proxy to serve as. Refused when it is the overflow uid, under which the
/// proxy could not tell its own user from another ([`same_user`]).
fn serving_uid() -> Result<u32> {
    let me = euid();
    if me == overflow_uid() {
        bail!(
            "the registry proxy cannot run as uid {me}: the kernel also reports that uid for \
             users it cannot identify"
        );
    }
    Ok(me)
}

/// Bind a proxy socket under a fresh name, not yet accepting.
fn bind() -> Result<(ProxySocket, std::os::unix::net::UnixListener)> {
    let socket = ProxySocket::random()?;
    let listener = std::os::unix::net::UnixListener::bind_addr(&socket.addr()?)
        .context("binding the registry proxy")?;
    listener.set_nonblocking(true)?;
    Ok((socket, listener))
}

/// Serve on the current runtime and return the socket the switch redirects to.
pub async fn spawn(cfg: ProxyCfg) -> Result<ProxySocket> {
    let me = serving_uid()?;
    let (socket, listener) = bind()?;
    let listener = UnixListener::from_std(listener).context("adopting the registry proxy")?;
    tokio::spawn(serve_on(listener, Arc::new(cfg), me));
    Ok(socket)
}

/// Like [`spawn`], but from a synchronous context (the executor's `spawn_switch`): binds
/// synchronously and serves on a dedicated thread + runtime for the process's lifetime.
/// Returns once that thread serves the socket, or with what kept it from serving.
pub fn spawn_blocking(cfg: ProxyCfg) -> Result<ProxySocket> {
    let me = serving_uid()?;
    let (socket, listener) = bind()?;
    let (ready, started) = std::sync::mpsc::channel::<Result<()>>();
    std::thread::Builder::new()
        .name("regproxy".to_string())
        .spawn(move || {
            // A failed send means `spawn_blocking` is gone, and with it whoever would have
            // used the proxy.
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let e = anyhow::Error::new(e).context("building the registry proxy runtime");
                    let _ = ready.send(Err(e));
                    return;
                }
            };
            rt.block_on(async move {
                match UnixListener::from_std(listener) {
                    Ok(listener) => {
                        let _ = ready.send(Ok(()));
                        serve_on(listener, Arc::new(cfg), me).await;
                    }
                    Err(e) => {
                        let e = anyhow::Error::new(e).context("adopting the registry proxy");
                        let _ = ready.send(Err(e));
                    }
                }
            });
        })
        .context("starting the registry proxy thread")?;
    started
        .recv()
        .context("the registry proxy thread ended before serving")??;
    Ok(socket)
}

/// The first and the longest pause between two dials of a proxy whose backlog is full.
const DIAL_BACKOFF: (Duration, Duration) = (Duration::from_millis(1), Duration::from_millis(100));

/// Connect to the proxy listening on `socket`, for the switch to carry a guest's flow to.
/// A proxy whose backlog is full is dialed again for up to `within`; a socket nothing listens
/// on is refused at once. Refused too unless the listener runs as `me`, the caller's own uid
/// ([`same_user`]): another user could bind the name once the proxy is gone, and would be
/// handed the guest's requests to answer.
pub async fn connect(
    socket: &ProxySocket,
    me: u32,
    within: Duration,
) -> std::io::Result<UnixStream> {
    use std::io::{Error, ErrorKind};
    let addr = socket.addr()?;
    let deadline = tokio::time::Instant::now() + within;
    let mut pause = DIAL_BACKOFF.0;
    let stream = loop {
        match hostlock::dial(&addr)? {
            hostlock::Dial::Connected(stream) => break stream,
            hostlock::Dial::Absent => {
                return Err(Error::new(
                    ErrorKind::ConnectionRefused,
                    "nothing listens on the registry proxy's socket",
                ));
            }
            hostlock::Dial::Busy => {
                let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                if left.is_zero() {
                    return Err(Error::new(
                        ErrorKind::TimedOut,
                        format!(
                            "the registry proxy took no connection for {}s",
                            within.as_secs()
                        ),
                    ));
                }
                tokio::time::sleep(pause.min(left)).await;
                pause = (pause * 2).min(DIAL_BACKOFF.1);
            }
        }
    };
    let peer = hostlock::peer_uid(&stream);
    let overflow = overflow_uid();
    if !same_user(peer, me, overflow) {
        let why = if me == overflow {
            format!(
                "uid {me} is also what the kernel reports for users it cannot identify, so the \
                 registry proxy's listener cannot be told from another user's"
            )
        } else {
            format!(
                "the registry proxy's socket is held by {}, not this user",
                uid_label(peer)
            )
        };
        return Err(Error::new(ErrorKind::PermissionDenied, why));
    }
    stream.set_nonblocking(true)?;
    UnixStream::from_std(stream)
}

/// How long the accept loop waits after its `failures`-th failure in a row (from 0): 10 ms,
/// doubling up to a second.
fn accept_backoff(failures: u32) -> Duration {
    Duration::from_millis(10u64.saturating_mul(1 << failures.min(7)).min(1000))
}

/// Serve `cfg` to the connections `listener` takes from the user `me`.
async fn serve_on(listener: UnixListener, cfg: Arc<ProxyCfg>, me: u32) {
    static REFUSED: std::sync::Once = std::sync::Once::new();
    let overflow = overflow_uid();
    let mut failures = 0u32;
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            // The listener outlives a failed accept: the host out of descriptors or memory,
            // or a connection gone before it was taken. Wait, so that a lasting shortage is
            // not spun on, and log the first failure of a run.
            Err(e) => {
                if failures == 0 {
                    eprintln!("virtkit: registry proxy: accepting a connection: {e}; retrying");
                }
                tokio::time::sleep(accept_backoff(failures)).await;
                failures = failures.saturating_add(1);
                continue;
            }
        };
        failures = 0;
        // Before anything is read: another user's process gets nothing of the credential.
        let peer = stream.peer_cred().ok().map(|c| c.uid());
        if !same_user(peer, me, overflow) {
            REFUSED.call_once(|| {
                eprintln!(
                    "virtkit: registry proxy: refused a connection from {}: it serves its own \
                     user only",
                    uid_label(peer)
                );
            });
            continue;
        }
        let cfg = cfg.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| handle(req, cfg.clone()));
            let _ = http1::Builder::new().serve_connection(io, svc).await;
        });
    }
}

async fn handle(
    req: Request<Incoming>,
    cfg: Arc<ProxyCfg>,
) -> Result<Response<ProxyBody>, Infallible> {
    Ok(forward(req, &cfg).await.unwrap_or_else(|e| {
        // Keep the detail host-side; the guest is untrusted and must not learn the
        // upstream URL / internal error chain.
        eprintln!("virtkit: registry proxy: {e:#}");
        let body = Full::new(Bytes::from_static(b"registry proxy: upstream error"))
            .map_err(|never| match never {})
            .boxed_unsync();
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(body)
            .expect("building the proxy error response")
    }))
}

/// The upstream URL a guest's request target names, or `None` when, once resolved, it is not
/// under one of the scope's paths below the upstream's own. Checked after resolving, not on
/// the text: the URL parser resolves `..` and its percent-encoded spellings (`%2e%2e`), so
/// `/v2/../lock/acquire` starts with `/v2/` and still reaches `/lock/acquire`, carrying the
/// credential.
fn upstream_url(cfg: &ProxyCfg, path_and_query: &str) -> Option<reqwest::Url> {
    let scoped = |p: &str| {
        cfg.scope
            .paths()
            .iter()
            .find(|s| p.starts_with(*s))
            .copied()
    };
    let prefix = scoped(path_and_query)?;
    // An encoded separator stays encoded through the parser, so `/v2/..%2Flock` passes the
    // check below — and reaches `/lock` through a front proxy that decodes `%2F`/`%5C` once
    // before normalizing. No repository or reference has one, so the path may not carry it.
    // A raw `\` is already read as `/` for http(s) and caught below; refusing it here too is
    // belt-and-braces for a front proxy that sees the text before that.
    let path = path_and_query
        .split_once('?')
        .map_or(path_and_query, |(p, _)| p);
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") || path.contains('\\') {
        return None;
    }
    let url = reqwest::Url::parse(&format!("{}{path_and_query}", cfg.upstream)).ok()?;
    let resolved = url.path().strip_prefix(cfg.root.as_str())?;
    (url.origin() == cfg.base.origin() && resolved.starts_with(prefix)).then_some(url)
}

/// What a request becomes under the proxy's areas.
#[derive(Debug, PartialEq, Eq)]
enum Mapped<'a> {
    /// Nothing under [`ALIAS_ROOT`]: forwarded as it is.
    Unchanged,
    /// The path and query to forward instead, below the upstream's own path, and the area.
    To(String, &'a Area),
    /// `job/…` naming no area of this proxy.
    Unknown,
}

/// `url` (an accepted upstream URL) under `cfg`'s areas: `job/<alias>` at the start of an
/// OCI, file, WebDAV or S3 path, or of a lock name's path part, becomes the area's prefix.
fn map_aliases<'a>(cfg: &'a ProxyCfg, url: &reqwest::Url) -> Mapped<'a> {
    if !matches!(cfg.scope, Scope::Job | Scope::Areas) {
        return Mapped::Unchanged;
    }
    let Some(path) = url.path().strip_prefix(cfg.root.as_str()) else {
        return Mapped::Unchanged;
    };
    let query = url.query().map(|q| format!("?{q}")).unwrap_or_default();
    if path.starts_with("/lock/") {
        return match map_lock_names(&cfg.areas, url.query().unwrap_or_default()) {
            Ok(None) => Mapped::Unchanged,
            Ok(Some((q, area))) => Mapped::To(format!("{path}?{q}"), area),
            Err(()) => Mapped::Unknown,
        };
    }
    for base in ["/v2/", FILES, DAV_FILES, S3] {
        let Some(rest) = path.strip_prefix(base) else {
            continue;
        };
        return match map_name(&cfg.areas, rest, '/') {
            Ok(None) => Mapped::Unchanged,
            Ok(Some((name, area))) => Mapped::To(format!("{base}{name}{query}"), area),
            Err(()) => Mapped::Unknown,
        };
    }
    Mapped::Unchanged
}

/// `name` with a leading `job/<alias>`, followed by its end or `end`, replaced by the alias's
/// prefix: `Ok(None)` when it does not start at [`ALIAS_ROOT`], `Err` for no such alias.
fn map_name<'a>(
    areas: &'a [Area],
    name: &str,
    end: char,
) -> Result<Option<(String, &'a Area)>, ()> {
    let Some(rest) = name.strip_prefix(ALIAS_ROOT) else {
        return Ok(None);
    };
    // Another component, as `jobs/…`, is not under the root; `job` alone names no area.
    let rest = match rest.strip_prefix('/') {
        Some(rest) => rest,
        None if rest.starts_with(|c| c != end) => return Ok(None),
        None => return Err(()),
    };
    let cut = rest.find(['/', end]).unwrap_or(rest.len());
    let (alias, tail) = rest.split_at(cut);
    let area = areas.iter().find(|a| a.alias == alias).ok_or(())?;
    Ok(Some((format!("{}{tail}", area.prefix), area)))
}

/// A lock request's query with each `name=` under [`ALIAS_ROOT`] mapped, decoded as the
/// registry decodes it and encoded again; every other pair is kept as it came, in order.
/// `Ok(None)` when no name was mapped. The area returned is the first mapped name's. One
/// name under [`ALIAS_ROOT`] naming no area refuses the whole query, however many others map.
fn map_lock_names<'a>(areas: &'a [Area], query: &str) -> Result<Option<(String, &'a Area)>, ()> {
    let mut first = None;
    let mut pairs = Vec::new();
    for pair in query.split('&') {
        let mapped = match pair.split_once('=') {
            Some(("name", v)) => map_name(areas, &vk_registry::percent_decode(v), ':')?,
            _ => None,
        };
        match mapped {
            Some((name, area)) => {
                first.get_or_insert(area);
                pairs.push(format!("name={}", vk_registry::percent_encode(&name)));
            }
            None => pairs.push(pair.to_string()),
        }
    }
    Ok(first.map(|area| (pairs.join("&"), area)))
}

/// The lock requests forwarded within an area, all `POST`, and the numeric parameters each
/// takes beside its names.
const AREA_LOCKS: &[(&str, &[&str])] = &[
    ("/lock/acquire", &["ttl", "wait"]),
    ("/lock/renew", &["ttl"]),
    ("/lock/release", &[]),
];

/// The request headers forwarded under [`Scope::Areas`]: those [`confined`]'s requests
/// use. A header that could have a server between the proxy and the registry route the
/// request elsewhere, or read it as another method, is not among them.
const AREA_HEADERS: &[&str] = &[
    "accept",
    "accept-encoding",
    "content-encoding",
    "content-range",
    "content-type",
    "docker-content-digest",
    // with `range`, or a resumed read could splice another object's bytes onto its start
    "if-range",
    "range",
    "user-agent",
    "x-amz-content-sha256",
    "x-amz-date",
    "x-vk-lock-holder",
    "x-vk-lock-owner",
];

/// `url` (an accepted upstream URL, its aliases mapped) as [`Scope::Areas`] forwards it, or
/// `None` when the credential is not lent for it. Forwarded are:
/// - `GET`/`HEAD` of `/v2/` itself, which names no repository;
/// - the requests [`area_oci_query`] takes, on a repository under an area's prefix, an
///   upload the registry answered with its real name included;
/// - the S3 object requests [`area_s3_object`] takes, with no query or an empty one;
/// - `POST` to one of [`AREA_LOCKS`] with at least one name, every name under an area's
///   prefix.
///
/// The query is written again from what was checked.
fn confined(
    cfg: &ProxyCfg,
    method: &Method,
    headers: &hyper::HeaderMap,
    url: &reqwest::Url,
) -> Option<reqwest::Url> {
    let path = url.path().strip_prefix(cfg.root.as_str())?;
    let asked = url.query().unwrap_or_default();
    let query = if let Some(rest) = path.strip_prefix("/v2/") {
        area_oci_query(&cfg.areas, method, rest, asked)?
    } else if let Some(object) = path.strip_prefix(S3) {
        let taken = asked.is_empty() && area_s3_object(&cfg.areas, method, headers, object);
        taken.then(String::new)?
    } else {
        let (_, params) = AREA_LOCKS.iter().find(|(lock, _)| *lock == path)?;
        if *method != Method::POST {
            return None;
        }
        area_lock_query(&cfg.areas, params, asked)?
    };
    let mut url = url.clone();
    url.set_query((!query.is_empty()).then_some(query.as_str()));
    Some(url)
}

/// Whether `name` is a repository name at or under an area's prefix, cut at a component:
/// the repository's own name, not that of its plain files' repository.
fn in_areas(areas: &[Area], name: &str) -> bool {
    name.split('/').all(valid_component) && areas.iter().any(|a| under(&a.prefix, name))
}

/// The query to forward (empty for none) with `method` on the OCI path `rest` (what follows
/// `/v2/`), or `None` when [`Scope::Areas`] refuses the request. Taken are, on a repository
/// [`in_areas`]:
/// - `GET`/`HEAD`/`PUT` of `manifests/<reference>`;
/// - `GET`/`HEAD` of `blobs/<digest>`;
/// - `POST` to `blobs/uploads/`, then `PATCH` of `blobs/uploads/<id>`, and `PUT` of it with
///   the blob's `digest=`;
///
/// and `GET`/`HEAD` of the ping, an empty `rest`. No other query is taken: an OCI mount's
/// `mount=` and `from=` would name a repository nothing checked.
fn area_oci_query(areas: &[Area], method: &Method, rest: &str, query: &str) -> Option<String> {
    let reads = matches!(*method, Method::GET | Method::HEAD);
    let bare = query.is_empty();
    let none = |taken: bool| taken.then(String::new);
    if rest.is_empty() {
        return none(reads && bare);
    }
    let (name, tail) = oci_repository(rest)?;
    if !in_areas(areas, name) {
        return None;
    }
    let one = |segment: &str| !segment.is_empty() && !segment.contains('/');
    if let Some(reference) = tail.strip_prefix("manifests/") {
        return none(one(reference) && bare && (reads || *method == Method::PUT));
    }
    let blob = tail.strip_prefix("blobs/")?;
    match blob.strip_prefix("uploads/") {
        Some("") => none(*method == Method::POST && bare),
        Some(id) if one(id) => match *method {
            Method::PATCH => none(bare),
            Method::PUT => {
                let digest = vk_registry::percent_decode(query.strip_prefix("digest=")?);
                vk_registry::digest_hex(&digest)?;
                Some(format!("digest={}", vk_registry::percent_encode(&digest)))
            }
            _ => None,
        },
        Some(_) => None,
        None => none(reads && bare && vk_registry::digest_hex(blob).is_some()),
    }
}

/// Whether [`Scope::Areas`] takes `method` with `headers` on the S3 object `object` (what
/// follows `/s3/`). An S3 `GET`, `HEAD` or single-request `PUT` addresses the plain file
/// `/dav/files/<bucket>/<key>`: the store must be able to name it, and the key's directory,
/// the bucket included, must be [`in_areas`]. Reject residual `%` escapes so decoding cannot
/// change the checked name; sccache's keys need none.
///
/// The headers are held to vk-registry's own S3 rules, as received: a precondition or a
/// header for another operation (a copy, say) that the proxy dropped instead would turn the
/// request into an unconditional whole write. A `Connection` option naming a forwarded
/// header is refused too, since removing it after this check would send a request other
/// than the one checked.
fn area_s3_object(
    areas: &[Area],
    method: &Method,
    headers: &hyper::HeaderMap,
    object: &str,
) -> bool {
    let scoped = connection_scoped(headers);
    let Some((dir, _)) = object.rsplit_once('/') else {
        return false;
    };
    matches!(*method, Method::GET | Method::HEAD | Method::PUT)
        && vk_registry::s3_admissible_headers(headers)
        && !scoped
            .iter()
            .any(|name| AREA_HEADERS.contains(&name.as_str()))
        && !object.contains('%')
        && vk_registry::valid_plain_file(object)
        && in_areas(areas, dir)
}

/// An OCI path (what follows `/v2/`) cut at its first `/manifests/`, `/blobs/` or `/tags/`:
/// the shortest repository it can name, and the rest from that marker on. vk-registry cuts
/// at the last marker of the route it matches, so the name it reads is this one or lies
/// beneath it. `None` for a path with none of them, or with a `%` left once the URL is
/// resolved: no repository, tag, digest or upload has one, and what it decodes to is not
/// what was checked.
fn oci_repository(rest: &str) -> Option<(&str, &str)> {
    if rest.contains('%') {
        return None;
    }
    let cut = ["/manifests/", "/blobs/", "/tags/"]
        .iter()
        .filter_map(|marker| rest.find(marker))
        .min()?;
    Some((&rest[..cut], &rest[cut + 1..]))
}

/// A lock request's query as [`Scope::Areas`] forwards it, or `None` when it is refused.
/// Each `name=`, decoded as the registry decodes it, must be `<path>:<key>` with the path
/// [`in_areas`], and is encoded again; there must be at least one. Any other pair must be
/// one of `params`, once, with a number for value (`ttl=30`): no other spelling of `name`
/// goes unchecked, whatever keys a registry comes to read.
fn area_lock_query(areas: &[Area], params: &[&str], query: &str) -> Option<String> {
    let mut names = 0;
    let mut seen = Vec::new();
    let mut pairs = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        match pair.split_once('=')? {
            ("name", v) => {
                let name = vk_registry::percent_decode(v);
                let (path, key) = name.split_once(':')?;
                if key.is_empty() || !in_areas(areas, path) {
                    return None;
                }
                names += 1;
                pairs.push(format!("name={}", vk_registry::percent_encode(&name)));
            }
            (k, v) if params.contains(&k) && !seen.contains(&k) => {
                if !v.bytes().all(|b| b.is_ascii_digit()) || v.parse::<u64>().is_err() {
                    return None;
                }
                seen.push(k);
                pairs.push(pair.to_string());
            }
            _ => return None,
        }
    }
    (names > 0).then(|| pairs.join("&"))
}

/// What a proxy lending for its areas only answers a request outside them.
const OUTSIDE_AREAS: &[u8] = b"registry proxy: only the registry's ping, and manifests, blobs, \
                               S3 objects and locks under this proxy's areas, are proxied";

/// The most of a refused request's target that is logged, in characters.
const MAX_LOGGED_TARGET: usize = 256;

/// A 403 with `msg`.
fn forbidden(msg: &'static [u8]) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(
            Full::new(Bytes::from_static(msg))
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .expect("building a refusal")
}

/// Maps a `PROPFIND` multistatus's hrefs under an area's prefix back to its alias, as the
/// body streams: `<D:href>/dav/files/<prefix>` followed by `/` or `<` (the end of the href)
/// becomes `<D:href>/dav/files/job/<alias>`. A prefix is lowercase alphanumerics and `._-/`,
/// which neither XML nor the registry's percent-encoding changes, so the bytes are the text.
/// The literal `<D:href>` is how vk-registry's WebDAV listing writes it.
struct HrefMap {
    from: Vec<u8>,
    to: Vec<u8>,
    /// Bytes not sent yet: the tail a match could still start in.
    carry: Vec<u8>,
}

impl HrefMap {
    fn new(area: &Area) -> Self {
        let href = |p: &str| format!("<D:href>{DAV_FILES}{p}").into_bytes();
        HrefMap {
            from: href(&area.prefix),
            to: href(&format!("{ALIAS_ROOT}/{}", area.alias)),
            carry: Vec::new(),
        }
    }

    /// The bytes of `chunk` that can be sent now, mapped; a tail as long as the pattern waits
    /// for the next chunk, which holds the byte after a match.
    fn push(&mut self, chunk: &[u8]) -> Bytes {
        self.carry.extend_from_slice(chunk);
        self.emit(self.carry.len().saturating_sub(self.from.len()))
    }

    /// The rest, mapped, once the body has ended.
    fn finish(&mut self) -> Bytes {
        self.emit(self.carry.len())
    }

    /// The carry up to `upto`, mapped; a match starting before `upto` is taken whole.
    fn emit(&mut self, upto: usize) -> Bytes {
        let mut out = Vec::with_capacity(upto);
        let mut i = 0;
        while i < upto {
            let rest = &self.carry[i..];
            if rest.starts_with(&self.from)
                && matches!(rest.get(self.from.len()), Some(b'/' | b'<'))
            {
                out.extend_from_slice(&self.to);
                i += self.from.len();
            } else {
                out.push(self.carry[i]);
                i += 1;
            }
        }
        self.carry.drain(..i.min(self.carry.len()));
        Bytes::from(out)
    }

    /// `body` with its hrefs mapped; a chunk that leaves nothing to send yet yields no frame.
    fn over<S>(self, body: S) -> impl futures::Stream<Item = reqwest::Result<Bytes>>
    where
        S: futures::Stream<Item = reqwest::Result<Bytes>> + Send + 'static,
    {
        use futures::StreamExt;
        futures::stream::unfold((Box::pin(body), Some(self)), |(mut body, map)| async move {
            let mut map = map?;
            loop {
                match body.next().await {
                    Some(Ok(chunk)) => {
                        let out = map.push(&chunk);
                        if !out.is_empty() {
                            return Some((Ok(out), (body, Some(map))));
                        }
                    }
                    Some(Err(e)) => return Some((Err(e), (body, None))),
                    None => {
                        let out = map.finish();
                        return (!out.is_empty()).then_some((Ok(out), (body, None)));
                    }
                }
            }
        })
    }
}

/// Headers that must not be copied across the proxy (connection-scoped, credential-bearing,
/// or ones we set ourselves).
fn is_skipped(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "authorization"
            | "proxy-authorization"
            | "cookie"
            | "content-length"
            | "connection"
            | "keep-alive"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// The header names `headers`' `Connection` lists, lowercased: that connection's own, so
/// never copied across the proxy.
fn connection_scoped(headers: &hyper::HeaderMap) -> Vec<String> {
    headers
        .get_all(hyper::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect()
}

async fn forward(req: Request<Incoming>, cfg: &ProxyCfg) -> Result<Response<ProxyBody>> {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    // The proxy signs requests with a credential, so confine it to the paths its scope lends
    // that credential for: the OCI distribution API surface (`/v2/…`) for the host's own,
    // the lock API and plain files too for a job's token. A guest-chosen path outside them —
    // a foreign authority smuggled via `//host`, or the `/lock/` control plane under the
    // host's credential — is refused rather than authenticated on the guest's behalf.
    let method = req.method().clone();
    // A refusal, which a proxy lending for its areas only also logs: nothing else tells the
    // host what its guest was denied.
    let refuse = |msg: &'static [u8]| {
        if cfg.scope == Scope::Areas {
            let target: String = path_and_query.chars().take(MAX_LOGGED_TARGET).collect();
            eprintln!("virtkit: registry proxy: refused {method} {target:?}");
        }
        forbidden(msg)
    };
    let Some(url) = upstream_url(cfg, &path_and_query) else {
        return Ok(refuse(match cfg.scope {
            Scope::Oci => b"registry proxy: only /v2/ registry paths are proxied",
            Scope::Job => {
                b"registry proxy: only /v2/, /lock/, /files/, /dav/files/ and /s3/ are proxied"
            }
            Scope::Deny => b"registry proxy: this job has no registry credential",
            Scope::Areas => OUTSIDE_AREAS,
        }));
    };
    // The guests' token as it stands now, so a renewal reaches a job already running.
    let guest_token = match &cfg.guests {
        None => None,
        Some(source) => match source.live_guest(vk_peer::now_secs()) {
            Ok(Some(token)) => Some(token),
            Ok(None) => {
                return Ok(forbidden(
                    b"registry proxy: this node holds no registry credential for its jobs",
                ));
            }
            Err(e) => {
                eprintln!("virtkit: registry proxy: {e:#}");
                return Ok(forbidden(
                    b"registry proxy: this node's registry credential has expired",
                ));
            }
        },
    };
    // Plain files take the verbs vk-registry serves there, and no MOVE or COPY, whose
    // `Destination` names the proxy rather than the registry.
    let unserved = if path_and_query.starts_with(DAV_FILES) {
        !DAV_FILES_METHODS.contains(&method.as_str())
    } else {
        path_and_query.starts_with(FILES) && !FILES_METHODS.contains(&method.as_str())
    };
    if unserved {
        let body = Full::new(Bytes::from_static(
            b"registry proxy: this method is not proxied for plain files",
        ))
        .map_err(|never| match never {})
        .boxed_unsync();
        let allow = if path_and_query.starts_with(DAV_FILES) {
            DAV_FILES_METHODS.join(", ")
        } else {
            FILES_METHODS.join(", ")
        };
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(hyper::header::ALLOW, allow)
            .body(body)?);
    }
    // The aliases, mapped on the resolved URL, which then goes through the same checks
    // again: the prefix is the hub's, but the rest of the path is still the guest's.
    let (url, area) = match map_aliases(cfg, &url) {
        Mapped::Unchanged => (url, None),
        Mapped::To(target, area) => match upstream_url(cfg, &target) {
            Some(url) => (url, Some(area)),
            None => return Ok(refuse(b"registry proxy: an area's path is refused")),
        },
        Mapped::Unknown => {
            return Ok(refuse(match cfg.scope {
                Scope::Areas => b"registry proxy: no area has that alias",
                _ => b"registry proxy: this job has no area of that alias",
            }));
        }
    };
    // A credential lent for its areas only goes nowhere else: checked last, on what would
    // be sent.
    let url = match cfg.scope {
        Scope::Areas => match confined(cfg, &method, req.headers(), &url) {
            Some(url) => url,
            None => return Ok(refuse(OUTSIDE_AREAS)),
        },
        _ => url,
    };
    let path = url.path().strip_prefix(cfg.root.as_str()).unwrap_or("");
    // A listing's hrefs go back to the alias the guest asked for (see the module's doc).
    let listing = method.as_str() == "PROPFIND" && path.starts_with(DAV_FILES);
    let hrefs = area.filter(|_| listing).map(HrefMap::new);
    // OCI writes and WebDAV PROPFIND always stream a body upstream, even when empty.
    // Forward other bodies for the registry to validate: dropping a MKCOL body
    // would create the collection instead of rejecting the request (RFC 4918 §9.3).
    let (parts, incoming) = req.into_parts();
    let bodyful = matches!(method, Method::POST | Method::PUT | Method::PATCH)
        || method.as_str() == "PROPFIND"
        || !hyper::body::Body::is_end_stream(&incoming);
    let scoped = connection_scoped(&parts.headers);
    let headers: Vec<_> = parts
        .headers
        .iter()
        .filter(|(k, _)| {
            let name = k.as_str();
            !is_skipped(name)
                && !scoped.iter().any(|s| s == name)
                && (cfg.scope != Scope::Areas || AREA_HEADERS.contains(&name))
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    // File PUT requires the guest's declared length, which streaming would discard.
    let declared = hyper::body::Body::size_hint(&incoming).exact();
    let sent = match (repeatable(&method, path), bodyful) {
        (true, false) => Outgoing::Whole(Bytes::new()),
        (true, true) => held(incoming, MAX_HELD).await?,
        (false, false) => Outgoing::Once(None),
        (false, true) => Outgoing::Once(Some(streamed(incoming))),
    };
    let streamed_len = match &sent {
        Outgoing::Once(Some(_)) => declared,
        _ => None,
    };
    let request = |body: Option<reqwest::Body>| {
        let mut rb = cfg.client.request(method.clone(), url.clone());
        for (k, v) in &headers {
            rb = rb.header(k, v);
        }
        rb = match &guest_token {
            Some(token) => rb.bearer_auth(token),
            None => cfg.creds.apply(rb),
        };
        match (body, streamed_len) {
            (Some(body), Some(len)) => rb.header(hyper::header::CONTENT_LENGTH, len).body(body),
            (Some(body), None) => rb.body(body),
            (None, _) => rb,
        }
    };
    let what = format!("proxy {method} {}", url.path());
    let resp = match sent {
        // Sent again until the upstream answers, as other registry transfers are.
        Outgoing::Whole(bytes) => {
            crate::registry::with_request_retry(&what, || {
                request(bodyful.then(|| bytes.clone().into())).send()
            })
            .await
        }
        // Not safe to repeat, or read once from the guest: sent once.
        Outgoing::Once(body) => request(body).send().await,
    }
    .context("forwarding to the upstream registry")?;
    let status = resp.status();
    let headers_out = resp.headers().clone();
    // A digest's bytes, cut short, resume where they stopped (see [`Resume`]).
    let resume = (method == Method::GET
        && status == StatusCode::OK
        && digest_addressed(path)
        && !parts.headers.contains_key(hyper::header::RANGE)
        && !headers_out.contains_key(hyper::header::CONTENT_ENCODING))
    .then(|| resp.content_length())
    .flatten();
    // stream the upstream response back without buffering (blob pulls).
    let stream = resp.bytes_stream();
    let body = match (hrefs, resume) {
        (Some(map), _) => StreamBody::new(
            map.over(stream)
                .map_ok(Frame::data)
                .map_err(|e| std::io::Error::other(e.to_string())),
        )
        .boxed_unsync(),
        (None, Some(total)) => {
            // The same GET, from the first byte not sent.
            let get = request(None);
            let what_resumed = what.clone();
            let again = move |from: u64| {
                let ranged = get
                    .try_clone()
                    .map(|rb| rb.header(hyper::header::RANGE, format!("bytes={from}-")));
                let what = what.clone();
                async move {
                    crate::registry::with_anyhow_retry(&what, || {
                        let attempt = ranged.as_ref().and_then(|rb| rb.try_clone());
                        async move {
                            attempt
                                .context("cloning the resume request")?
                                .send()
                                .await
                                .and_then(crate::registry::turned_away)
                                .map_err(anyhow::Error::from)
                        }
                    })
                    .await
                }
            };
            let digest = headers_out.get(DIGEST_HEADER).cloned();
            StreamBody::new(
                Resume::new(stream, total, digest, what_resumed)
                    .over(again)
                    .map_ok(Frame::data),
            )
            .boxed_unsync()
        }
        (None, None) => StreamBody::new(
            stream
                .map_ok(Frame::data)
                .map_err(|e| std::io::Error::other(e.to_string())),
        )
        .boxed_unsync(),
    };

    let mut out = Response::builder().status(status);
    let scoped = connection_scoped(&headers_out);
    for (k, v) in headers_out.iter() {
        // An empty HEAD body cannot supply the upstream Content-Length.
        let kept = !is_skipped(k.as_str())
            || (method == Method::HEAD && *k == hyper::header::CONTENT_LENGTH);
        if kept && !scoped.iter().any(|s| s == k.as_str()) {
            out = out.header(k, v);
        }
    }
    out.body(body).map_err(Into::into)
}

/// Maximum guest request body buffered for retries. Matches vk-registry's 16 MiB
/// manifest cap, including cache snapshots with one layer per chunk, and leaves ample
/// room for a listing query or small file.
const MAX_HELD: usize = 16 << 20;

/// An upstream request with its whole body held for safe retries, or a single attempt
/// with an optional streamed body.
enum Outgoing {
    Whole(Bytes),
    Once(Option<reqwest::Body>),
}

/// Whether a request to `path`, relative to the upstream root, can be repeated after
/// a refused connection, a connection cut before the response, or a 503/429.
/// Repeating it must have the same effect even if the first request reached the registry:
/// reads, manifest PUTs by tag or digest, whole-file PUTs, and upload starts (which leave
/// the first upload unused). Excludes upload chunks (`PATCH`), upload completion (`PUT`
/// under `blobs/uploads/`, whose upload is then gone), deletions, collection creation,
/// and all `/lock/` requests regardless of method. A retried PUT lands last, like a
/// later PUT from another writer.
fn repeatable(method: &Method, path: &str) -> bool {
    if path.starts_with("/lock/") {
        return false;
    }
    let oci = path.strip_prefix("/v2/");
    match method.as_str() {
        "GET" | "HEAD" | "OPTIONS" | "PROPFIND" => true,
        "PUT" => {
            oci.is_some_and(|p| p.rsplit('/').nth(1) == Some("manifests"))
                || path.starts_with(FILES)
                || path.starts_with(DAV_FILES)
                || path.starts_with(S3)
        }
        "POST" => oci.is_some_and(|p| p.ends_with("/blobs/uploads/")),
        _ => false,
    }
}

/// Whether `path`, below the upstream's own, names content by its digest — a blob, or a manifest
/// by digest — whose bytes are the same whenever they are read.
fn digest_addressed(path: &str) -> bool {
    let Some(oci) = path.strip_prefix("/v2/") else {
        return false;
    };
    let mut parts = oci.rsplit('/');
    let (Some(reference), Some(kind)) = (parts.next(), parts.next()) else {
        return false;
    };
    matches!(kind, "blobs" | "manifests")
        && reference
            .split_once(':')
            .is_some_and(|(algorithm, hex)| !algorithm.is_empty() && !hex.is_empty())
}

/// `incoming`, held whole when it ends within `limit` bytes; past it, what was read then the
/// rest, streamed.
async fn held(mut incoming: Incoming, limit: usize) -> Result<Outgoing> {
    if hyper::body::Body::size_hint(&incoming).lower() > limit as u64 {
        return Ok(Outgoing::Once(Some(streamed(incoming))));
    }
    let (mut read, mut size) = (Vec::new(), 0);
    while size <= limit {
        let Some(frame) = incoming.frame().await else {
            return Ok(Outgoing::Whole(Bytes::from(read.concat())));
        };
        let frame = frame.context("reading the guest's request body")?;
        if let Ok(data) = frame.into_data() {
            size += data.len();
            read.push(data);
        }
    }
    let rest = incoming
        .into_data_stream()
        .map_err(|e| std::io::Error::other(e.to_string()));
    let read = futures::stream::iter(read.into_iter().map(Ok::<_, std::io::Error>));
    let all = futures::StreamExt::chain(read, rest);
    Ok(Outgoing::Once(Some(reqwest::Body::wrap_stream(all))))
}

/// `incoming`, streamed upstream without buffering (blob uploads).
fn streamed(incoming: Incoming) -> reqwest::Body {
    reqwest::Body::wrap_stream(
        incoming
            .into_data_stream()
            .map_err(|e| std::io::Error::other(e.to_string())),
    )
}

/// The header a registry names a blob's or manifest's digest in.
const DIGEST_HEADER: &str = "docker-content-digest";

/// Resume limit for the whole body. Each resume uses the usual registry transfer retries;
/// multiple resumes allow for repeated registry restarts mid-pull.
const MAX_RESUMES: u32 = 5;

/// A digest's bytes, `total` of them, streamed to the guest from the upstream: cut short, they are
/// asked for again from the first byte not sent, with a `Range` the upstream may honour (`206`)
/// or not (`200`, the bytes already sent then skipped). Content addressed by its digest is the
/// same bytes every time, which the guest checks against the digest anyway; an answer of
/// another length, or naming another digest when both answers name one, ends the body with
/// an error, as the cut would have.
struct Resume<S> {
    body: std::pin::Pin<Box<S>>,
    total: u64,
    /// The digest the first answer named, if it did.
    digest: Option<hyper::header::HeaderValue>,
    /// The request, for the log.
    what: String,
}

impl<S> Resume<S>
where
    S: futures::Stream<Item = reqwest::Result<Bytes>> + Send + 'static,
{
    fn new(body: S, total: u64, digest: Option<hyper::header::HeaderValue>, what: String) -> Self {
        Resume {
            body: Box::pin(body),
            total,
            digest,
            what,
        }
    }

    /// The bytes, asking `again(from)` for the rest when they are cut short.
    fn over<F, Fut>(
        self,
        again: F,
    ) -> impl futures::Stream<Item = std::io::Result<Bytes>> + Send + 'static
    where
        F: Fn(u64) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<reqwest::Response>> + Send,
    {
        use futures::StreamExt;
        type Body =
            std::pin::Pin<Box<dyn futures::Stream<Item = reqwest::Result<Bytes>> + Send + 'static>>;
        let Resume {
            body,
            total,
            digest,
            what,
        } = self;
        let state = (body as Body, 0u64, 0u64, 0u32);
        futures::stream::unfold(Some((state, again)), move |state| {
            let digest = digest.clone();
            let what = what.clone();
            async move {
                let ends = |why: String| {
                    eprintln!("virtkit: registry: {what}: {why}");
                    Some((Err(std::io::Error::other(why)), None))
                };
                let ((mut body, mut sent, mut skip, mut resumes), again) = state?;
                loop {
                    let cut = match body.next().await {
                        Some(Ok(mut chunk)) => {
                            let skipped = skip.min(chunk.len() as u64);
                            skip -= skipped;
                            let chunk = chunk.split_off(skipped as usize);
                            if chunk.is_empty() {
                                continue;
                            }
                            sent += chunk.len() as u64;
                            return Some((Ok(chunk), Some(((body, sent, skip, resumes), again))));
                        }
                        None if sent >= total => return None,
                        None => anyhow::anyhow!("the upstream ended the body early"),
                        Some(Err(e)) if crate::registry::transfer_retried(&e) => e.into(),
                        Some(Err(e)) => return ends(format!("{e:#}")),
                    };
                    // A failure after all bytes were sent loses no guest data.
                    if sent >= total {
                        return None;
                    }
                    if resumes >= MAX_RESUMES {
                        return ends(format!(
                            "resumed {resumes} times, cut again after {sent} of {total} \
                             bytes: {cut:#}"
                        ));
                    }
                    resumes += 1;
                    eprintln!(
                        "virtkit: registry: {what}: cut after {sent} of {total} bytes \
                         ({cut:#}); resuming"
                    );
                    let resumed = match again(sent).await {
                        Ok(resp) => resp,
                        Err(e) => return ends(format!("resuming: {e:#}")),
                    };
                    match resumed_at(&resumed, sent, total, digest.as_ref()) {
                        Ok(from) => {
                            skip = sent - from;
                            body = Box::pin(resumed.bytes_stream());
                        }
                        Err(why) => return ends(format!("not resuming: {why}")),
                    }
                }
            }
        })
    }
}

/// Start offset of `resp`, requested from `sent`: `sent` for a matching `206` Content-Range,
/// or 0 for a complete `200`. Return a reason for any other response, a different length,
/// or a digest differing from `digest`.
fn resumed_at(
    resp: &reqwest::Response,
    sent: u64,
    total: u64,
    digest: Option<&hyper::header::HeaderValue>,
) -> std::result::Result<u64, String> {
    if let (Some(first), Some(now)) = (digest, resp.headers().get(DIGEST_HEADER))
        && first != now
    {
        return Err(format!(
            "the upstream now names digest {now:?}, not {first:?}"
        ));
    }
    if resp.headers().contains_key(hyper::header::CONTENT_ENCODING) {
        return Err("the upstream now encodes the body".into());
    }
    match resp.status() {
        StatusCode::OK if resp.content_length() == Some(total) => Ok(0),
        StatusCode::PARTIAL_CONTENT => {
            let range = resp
                .headers()
                .get(hyper::header::CONTENT_RANGE)
                .and_then(|v| v.to_str().ok());
            let expected = format!("bytes {sent}-{}/{total}", total.saturating_sub(1));
            let len = resp.content_length();
            if range == Some(expected.as_str()) && len == Some(total.saturating_sub(sent)) {
                Ok(sent)
            } else {
                Err(format!(
                    "the upstream answered range {range:?} of {len:?} bytes, not {expected:?}"
                ))
            }
        }
        status => Err(format!(
            "the upstream answered {status} with {:?} bytes, not {total}",
            resp.content_length()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    // A fake upstream that records the Authorization header + path and query of the last
    // request and replies 200 with a marker body. It runs on its own dedicated thread + runtime
    // (like the proxy's `spawn_blocking` and the vk-registry e2e servers) so its accept
    // loop never competes with the test's runtime threads — which caused acceptance stalls
    // and flakes when many of these servers ran concurrently under `cargo test`.
    fn fake_upstream() -> (SocketAddr, Arc<std::sync::Mutex<(String, String)>>) {
        fake_upstream_replying(b"ok")
    }

    /// [`fake_upstream`], replying `body` to every request.
    fn fake_upstream_replying(
        body: &'static [u8],
    ) -> (SocketAddr, Arc<std::sync::Mutex<(String, String)>>) {
        let seen = Arc::new(std::sync::Mutex::new((String::new(), String::new())));
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let s = seen.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = TcpListener::from_std(listener).unwrap();
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    let s = s.clone();
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let svc = service_fn(move |req: Request<Incoming>| {
                            let s = s.clone();
                            async move {
                                let auth = req
                                    .headers()
                                    .get(hyper::header::AUTHORIZATION)
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("")
                                    .to_string();
                                let path = req.uri().path_and_query().unwrap().to_string();
                                *s.lock().unwrap() = (auth, path);
                                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                                    body,
                                ))))
                            }
                        });
                        let _ = http1::Builder::new().serve_connection(io, svc).await;
                    });
                }
            });
        });
        (addr, seen)
    }

    /// What keeps a [`proxy_on_tcp`] serving. Its thread, like [`fake_upstream`]'s, is its
    /// own; dropping this ends it with the proxy and the port, and fails the test if a
    /// connection could not be carried.
    struct Served {
        stop: Option<tokio::sync::oneshot::Sender<()>>,
        thread: Option<std::thread::JoinHandle<Result<()>>>,
    }

    impl Drop for Served {
        fn drop(&mut self) {
            drop(self.stop.take());
            let ended = self.thread.take().unwrap().join();
            if !std::thread::panicking() {
                ended.unwrap().unwrap();
            }
        }
    }

    /// A proxy for `cfg` behind a loopback port, for the tests' HTTP clients: each connection
    /// is carried to the proxy's socket, dialed as the switch dials it. Returns the port's
    /// address and what serves it.
    fn proxy_on_tcp(cfg: ProxyCfg) -> (SocketAddr, Served) {
        proxy_on_tcp_as(cfg, euid())
    }

    /// [`proxy_on_tcp`], the proxy serving the user `me` rather than its own.
    fn proxy_on_tcp_as(cfg: ProxyCfg, me: u32) -> (SocketAddr, Served) {
        let (socket, proxy) = bind().unwrap();
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, mut stopped) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            // Dropping the runtime ends the proxy and the flows still open.
            rt.block_on(async move {
                tokio::spawn(serve_on(UnixListener::from_std(proxy)?, Arc::new(cfg), me));
                let listener = TcpListener::from_std(listener)?;
                loop {
                    let mut client = tokio::select! {
                        _ = &mut stopped => return Ok(()),
                        accepted = listener.accept() => accepted?.0,
                    };
                    let mut proxy = connect(&socket, euid(), Duration::from_secs(10)).await?;
                    tokio::spawn(async move {
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut proxy).await;
                    });
                }
            })
        });
        let served = Served {
            stop: Some(stop),
            thread: Some(thread),
        };
        (addr, served)
    }

    #[test]
    fn only_the_same_user_is_on_the_other_end() {
        assert!(same_user(Some(1000), 1000, 65534));
        assert!(same_user(Some(0), 0, 65534));
        assert!(!same_user(Some(1001), 1000, 65534));
        // Root is another user too.
        assert!(!same_user(Some(0), 1000, 65534));
        assert!(!same_user(None, 1000, 65534));
        // The overflow uid is every user the kernel cannot name, at either end.
        assert!(!same_user(Some(65534), 65534, 65534));
        assert!(!same_user(Some(65534), 1000, 65534));
        assert!(same_user(Some(65534), 65534, 4242));
        assert!(!same_user(Some(4242), 4242, 4242));
    }

    #[test]
    fn a_socket_round_trips_and_parses_strictly() {
        let socket = ProxySocket::random().unwrap();
        let text = socket.to_string();
        assert_eq!(text.len(), "@virtkit-regproxy-".len() + 32);
        assert_eq!(text.parse::<ProxySocket>().unwrap(), socket);
        assert_ne!(ProxySocket::random().unwrap(), socket);
        let digits = "0123456789abcdef0123456789abcdef";
        for bad in [
            String::new(),
            "127.0.0.1:5000".to_string(),
            format!("virtkit-regproxy-{digits}"),
            format!("@virtkit-pull-{digits}"),
            format!("@virtkit-regproxy-{}", &digits[1..]),
            format!("@virtkit-regproxy-{digits}0"),
            format!("@virtkit-regproxy-{}", digits.to_uppercase()),
            format!("@virtkit-regproxy-{}/", &digits[1..]),
        ] {
            assert!(bad.parse::<ProxySocket>().is_err(), "{bad:?}");
        }
    }

    /// A socket nothing listens on refuses the dial at once, whatever time it was given.
    #[tokio::test]
    async fn a_socket_without_a_proxy_refuses_the_dial() {
        let socket = ProxySocket::random().unwrap();
        let asked = std::time::Instant::now();
        let err = connect(&socket, euid(), Duration::from_secs(30))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
        assert!(asked.elapsed() < Duration::from_secs(5));
    }

    /// A listener on a fresh proxy socket with no backlog, and the connections that fill it.
    fn full_listener() -> (
        ProxySocket,
        std::os::unix::net::UnixListener,
        Vec<std::os::unix::net::UnixStream>,
    ) {
        use std::os::fd::FromRawFd;
        let socket = ProxySocket::random().unwrap();
        let addr = socket.addr().unwrap();
        let (sa, len) = hostlock::abstract_sockaddr(&addr).unwrap();
        // SAFETY: plain socket calls on a fresh descriptor, owned by the listener returned;
        // `sa` and `len` describe exactly the address filled in.
        let listener = unsafe {
            let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            assert!(fd >= 0);
            assert_eq!(
                libc::bind(fd, (&raw const sa).cast(), len as libc::socklen_t),
                0
            );
            assert_eq!(libc::listen(fd, 0), 0);
            std::os::unix::net::UnixListener::from_raw_fd(fd)
        };
        let mut queued = Vec::new();
        while let hostlock::Dial::Connected(c) = hostlock::dial(&addr).unwrap() {
            queued.push(c);
            assert!(queued.len() < 8, "a backlog of 0 never filled");
        }
        (socket, listener, queued)
    }

    /// A proxy that is there but behind on its accepts is waited for, not taken for absent.
    #[tokio::test]
    async fn a_dial_waits_for_a_full_backlog_to_drain() {
        let (socket, listener, queued) = full_listener();
        assert!(matches!(
            hostlock::dial(&socket.addr().unwrap()).unwrap(),
            hostlock::Dial::Busy
        ));
        let accepting = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            let taken: Vec<_> = (0..queued.len())
                .map(|_| listener.accept().unwrap().0)
                .collect();
            // The dial waited for is the next one in.
            (listener.accept().unwrap().0, taken, queued)
        });
        connect(&socket, euid(), Duration::from_secs(30))
            .await
            .unwrap();
        accepting.join().unwrap();
    }

    /// The wait for a full backlog ends at the caller's deadline.
    #[tokio::test]
    async fn a_dial_gives_up_on_a_backlog_that_stays_full() {
        let (socket, _listener, _queued) = full_listener();
        let err = connect(&socket, euid(), Duration::from_millis(50))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    /// The dial checks the listener's uid: one that is not the caller's is not connected to.
    #[tokio::test]
    async fn a_dial_refuses_a_listener_of_another_user() {
        let (socket, _listener) = bind().unwrap();
        let other = euid().wrapping_add(1);
        let err = connect(&socket, other, Duration::from_secs(30))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        // The overflow uid is refused as the caller's own too.
        let err = connect(&socket, overflow_uid(), Duration::from_secs(30))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        connect(&socket, euid(), Duration::from_secs(30))
            .await
            .unwrap();
    }

    /// The proxy checks its client's uid: a connection from any other is closed with nothing
    /// read from it, sent to it, or forwarded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_connection_from_another_user_is_served_nothing() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream();
        let (proxy, served) = proxy_on_tcp_as(basic_cfg(up_addr), euid().wrapping_add(1));
        let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
        client
            .write_all(b"GET /v2/ HTTP/1.1\r\nHost: registry.vk\r\n\r\n")
            .await
            .unwrap();
        let mut answer = Vec::new();
        // A reset is as good as an end: either way the proxy closed without answering.
        let _ = client.read_to_end(&mut answer).await;
        assert!(answer.is_empty(), "{answer:?}");
        assert_eq!(*seen.lock().unwrap(), (String::new(), String::new()));
        drop(served);

        // The same request, to a proxy serving this user.
        let (proxy, _served) = proxy_on_tcp(basic_cfg(up_addr));
        let r = reqwest::get(format!("http://{proxy}/v2/")).await.unwrap();
        assert!(r.status().is_success());
        assert_eq!(seen.lock().unwrap().1, "/v2/");
    }

    /// The executor's proxy answers as soon as it is returned.
    #[test]
    fn a_proxy_spawned_from_a_thread_is_serving_when_returned() {
        use std::io::{Read, Write};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cfg = ProxyCfg::build("http://127.0.0.1:1".to_string(), Creds::anonymous()).unwrap();
        let socket = spawn_blocking(cfg).unwrap();
        let mut client =
            std::os::unix::net::UnixStream::connect_addr(&socket.addr().unwrap()).unwrap();
        client
            .write_all(b"GET /outside HTTP/1.1\r\nHost: registry.vk\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut answer = String::new();
        client.read_to_string(&mut answer).unwrap();
        assert!(answer.starts_with("HTTP/1.1 4"), "{answer}");
    }

    #[test]
    fn the_accept_loop_backs_off_up_to_a_second() {
        assert_eq!(accept_backoff(0), Duration::from_millis(10));
        assert_eq!(accept_backoff(1), Duration::from_millis(20));
        assert_eq!(accept_backoff(6), Duration::from_millis(640));
        assert_eq!(accept_backoff(7), Duration::from_secs(1));
        assert_eq!(accept_backoff(u32::MAX), Duration::from_secs(1));
    }

    /// A proxy to the upstream at `up_addr` that injects the Basic pair `robot:s3cret`.
    fn basic_cfg(up_addr: SocketAddr) -> ProxyCfg {
        ProxyCfg::build(
            format!("http://{up_addr}"),
            Creds {
                username: Some("robot".to_string()),
                password: Some("s3cret".to_string()),
                ..Creds::anonymous()
            },
        )
        .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn injects_basic_auth_and_forwards_path() {
        // reqwest (rustls-no-provider) needs a crypto provider before a client builds.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream();
        let (proxy, _served) = proxy_on_tcp(basic_cfg(up_addr));

        // the "guest" hits the proxy with NO credentials.
        let r = reqwest::Client::new()
            .get(format!("http://{proxy}/v2/app/manifests/latest"))
            .send()
            .await
            .unwrap();
        assert!(r.status().is_success());
        assert_eq!(r.text().await.unwrap(), "ok");

        let (auth, path) = seen.lock().unwrap().clone();
        assert_eq!(
            path, "/v2/app/manifests/latest",
            "path must be forwarded as resolved"
        );
        // Basic base64("robot:s3cret") = cm9ib3Q6czNjcmV0
        assert_eq!(
            auth, "Basic cm9ib3Q6czNjcmV0",
            "the proxy must inject Basic auth"
        );
    }

    /// A `[registry]` gated by a bearer token — a vk-registry in `mode = "accounts"`, whose
    /// API keys are exactly that — is what the proxy has to lend the guest. It used to
    /// inject nothing at all for one, since it only ever knew about the Basic pair.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn injects_a_bearer_token_ahead_of_the_basic_pair() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream();
        let cfg = ProxyCfg::build(
            format!("http://{up_addr}"),
            Creds {
                // Both set: the token wins, as it does on every other client path.
                username: Some("robot".to_string()),
                password: Some("s3cret".to_string()),
                token: Some("vkr_x".to_string()),
                ..Creds::anonymous()
            },
        )
        .unwrap();
        let (proxy, _served) = proxy_on_tcp(cfg);

        let r = reqwest::Client::new()
            .get(format!("http://{proxy}/v2/app/manifests/latest"))
            .send()
            .await
            .unwrap();
        assert!(r.status().is_success());

        let (auth, _) = seen.lock().unwrap().clone();
        assert_eq!(
            auth, "Bearer vkr_x",
            "the proxy must inject the bearer token"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refuses_paths_outside_v2() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream();
        let (proxy, _served) = proxy_on_tcp(basic_cfg(up_addr));

        // a path outside /v2/ (here the lock control plane) is refused with 403 and never
        // reaches the upstream — the host credential is never lent to it.
        let r = reqwest::Client::new()
            .get(format!("http://{proxy}/lock/acquire?name=x"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 403);
        assert_eq!(
            seen.lock().unwrap().0,
            "",
            "a non-/v2/ request must not be forwarded upstream"
        );
    }

    fn registry(up_addr: SocketAddr) -> crate::config::Registry {
        crate::config::Registry {
            repo: format!("{up_addr}/team"),
            username: "robot".into(),
            password_file: Some("/nonexistent/password".into()),
            insecure: true,
            ..crate::config::Registry::for_share(
                String::new(),
                true,
                None,
                String::new(),
                None,
                None,
                None,
            )
        }
    }

    async fn status_and_auth(
        proxy: SocketAddr,
        method: &str,
        target: &str,
        seen: &std::sync::Mutex<(String, String)>,
    ) -> (u16, String, String) {
        *seen.lock().unwrap() = (String::new(), String::new());
        let r = reqwest::Client::new()
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                format!("http://{proxy}{target}"),
            )
            .header("authorization", "Bearer guest-forged")
            .send()
            .await
            .unwrap();
        let (auth, path) = seen.lock().unwrap().clone();
        (r.status().as_u16(), auth, path)
    }

    /// A job of the node's own runner gets the guests' token on the job token's paths, read
    /// again for each request; while the node holds none, or once it expired, nothing is
    /// forwarded, and neither the section's credential nor the node's own token ever is.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_runner_job_gets_the_guests_token_as_it_stands() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream();
        let dir = std::env::temp_dir().join(format!("vk-regproxy-guests-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let origin = format!("http://{up_addr}");
        let held = |guest: Option<&str>, expires_at: u64| {
            crate::node::registry_access::tests::held_for_guests(&dir, &origin, guest, expires_at)
        };
        let far = vk_peer::now_secs() + 3600;
        let mut rg = registry(up_addr);
        // A registry the hub does not name: nothing.
        let none = ProxyCfg::for_guests(&rg).unwrap();
        assert_eq!(none.scope, Scope::Deny);
        rg.node_access = Some(held(None, far));
        let (proxy, _served) = proxy_on_tcp(ProxyCfg::for_guests(&rg).unwrap());
        let get = "/v2/build-cache/app/manifests/latest";
        let (status, auth, _) = status_and_auth(proxy, "GET", get, &seen).await;
        assert_eq!((status, auth.as_str()), (403, ""));
        held(Some("vkt_guest_one"), far);
        for (method, target) in [("GET", get), ("POST", "/lock/acquire?name=build-cache:k")] {
            let (status, auth, _) = status_and_auth(proxy, method, target, &seen).await;
            assert_eq!(
                (status, auth.as_str()),
                (200, "Bearer vkt_guest_one"),
                "{method} {target}"
            );
        }
        // Renewed while the job runs.
        held(Some("vkt_guest_two"), far + 1);
        let (_, auth, _) = status_and_auth(proxy, "GET", get, &seen).await;
        assert_eq!(auth, "Bearer vkt_guest_two");
        held(Some("vkt_guest_two"), 1);
        let (status, auth, _) = status_and_auth(proxy, "GET", get, &seen).await;
        assert_eq!((status, auth.as_str()), (403, ""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// OCI, lock, file, WebDAV and S3 requests use the job token in place of guest credentials.
    /// The proxy never reads the registry section's credential.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_job_token_reaches_locks_and_files_too() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream();
        let cfg = ProxyCfg::for_job(&registry(up_addr), Some("vkt_job")).unwrap();
        assert_eq!(cfg.scope, Scope::Job);
        let (proxy, _served) = proxy_on_tcp(cfg);
        for (method, target) in [
            ("GET", "/v2/p/gl/42/app/manifests/latest"),
            ("POST", "/lock/acquire?name=p/gl/42:k"),
            ("PROPFIND", "/dav/files/p/gl/42/x"),
            ("PUT", "/dav/files/p/gl/42/x"),
            ("GET", "/files/p/gl/42/x"),
            ("HEAD", "/files/p/gl/42/x"),
            ("PUT", "/files/p/gl/42/x"),
            ("DELETE", "/files/p/gl/42/x"),
            ("GET", "/s3/p/gl/42/x"),
            ("HEAD", "/s3/p/gl/42/x"),
            ("PUT", "/s3/p/gl/42/x"),
            ("DELETE", "/s3/p/gl/42/x"),
        ] {
            let (status, auth, path) = status_and_auth(proxy, method, target, &seen).await;
            assert_eq!(status, 200, "{method} {target}");
            assert_eq!(auth, "Bearer vkt_job", "{method} {target}");
            assert_eq!(path, target);
        }
        for target in [
            "/dav/repos/p",
            "/settings/keys",
            "/dav/files/../../settings/keys",
            "/dav/files/%2e%2e/%2e%2e/browse",
            "/files/../settings/keys",
            "/files/%2e%2e/browse",
            "/s3",
            "/s3?list-type=2",
            "/s3/../settings/keys",
            "/s3/p/%2e%2e/%2e%2e/browse",
            "/s3/p%2F..%2F..%2Fbrowse",
        ] {
            let (status, _, path) = status_and_auth(proxy, "GET", target, &seen).await;
            assert_eq!(status, 403, "{target}");
            assert_eq!(path, "", "{target} must not be forwarded");
        }
    }

    fn area(alias: &str, prefix: &str) -> Area {
        Area {
            alias: alias.into(),
            prefix: prefix.into(),
        }
    }

    /// `job/<alias>` reaches the area's prefix, for OCI, plain files and locks; a path not
    /// under `job/` is forwarded as it is, and an alias the job lacks is refused unforwarded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_job_reaches_its_areas_by_alias() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream();
        let cfg = ProxyCfg::for_job(&registry(up_addr), Some("vkt_job"))
            .unwrap()
            .with_areas(&[area("task-cache", "task-cache/gl/42/protected")]);
        let (proxy, _served) = proxy_on_tcp(cfg);
        for (method, target, want) in [
            (
                "GET",
                "/v2/job/task-cache/manifests/latest",
                "/v2/task-cache/gl/42/protected/manifests/latest",
            ),
            (
                "GET",
                "/v2/job/task-cache/ns/blobs/sha256:aa",
                "/v2/task-cache/gl/42/protected/ns/blobs/sha256:aa",
            ),
            (
                "PUT",
                "/dav/files/job/task-cache/a/b",
                "/dav/files/task-cache/gl/42/protected/a/b",
            ),
            (
                "PROPFIND",
                "/dav/files/job/task-cache",
                "/dav/files/task-cache/gl/42/protected",
            ),
            (
                "GET",
                "/files/job/task-cache/a/b",
                "/files/task-cache/gl/42/protected/a/b",
            ),
            (
                "PUT",
                "/s3/job/task-cache/a/b",
                "/s3/task-cache/gl/42/protected/a/b",
            ),
            (
                "POST",
                "/lock/acquire?name=job%2Ftask-cache%3Ak&ttl=30",
                "/lock/acquire?name=task-cache%2Fgl%2F42%2Fprotected%3Ak&ttl=30",
            ),
            ("GET", "/v2/jobs/x/manifests/1", "/v2/jobs/x/manifests/1"),
            (
                "GET",
                "/v2/task-cache/gl/42/protected/manifests/1",
                "/v2/task-cache/gl/42/protected/manifests/1",
            ),
        ] {
            let (status, auth, path) = status_and_auth(proxy, method, target, &seen).await;
            assert_eq!(status, 200, "{method} {target}");
            assert_eq!(auth, "Bearer vkt_job", "{method} {target}");
            assert_eq!(path, want, "{method} {target}");
        }
        for target in [
            "/v2/job/other/manifests/1",
            "/v2/job/manifests/1",
            "/v2/job",
            "/dav/files/job/",
            "/files/job/other/k",
            "/s3/job/other/k",
            "/lock/acquire?name=job/other:k",
            "/lock/acquire?name=job:k",
        ] {
            let (status, _, path) = status_and_auth(proxy, "GET", target, &seen).await;
            assert_eq!(status, 403, "{target}");
            assert_eq!(path, "", "{target} must not be forwarded");
        }
    }

    /// Lock names are mapped as the registry decodes them, in order, the other pairs kept.
    #[test]
    fn lock_names_map_their_path_part() {
        let areas = [area("task-cache", "task-cache/gl/42/protected")];
        assert_eq!(
            map_lock_names(&areas, "name=p%2Fgl%2F42%3Ak&ttl=30"),
            Ok(None)
        );
        let (q, a) = map_lock_names(
            &areas,
            "name=job%2Ftask-cache%2Fgcc-13%3Abuild%3Aabc&name=other%3Ak&ttl=30",
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            q,
            "name=task-cache%2Fgl%2F42%2Fprotected%2Fgcc-13%3Abuild%3Aabc&name=other%3Ak&ttl=30"
        );
        assert_eq!(a.alias, "task-cache");
        let (q, _) = map_lock_names(&areas, "name=job/task-cache:k")
            .unwrap()
            .unwrap();
        assert_eq!(q, "name=task-cache%2Fgl%2F42%2Fprotected%3Ak");
        assert_eq!(map_lock_names(&areas, "name=job%2Fnope%3Ak"), Err(()));
    }

    /// Invalid areas are skipped; valid areas are kept, taking the first for each alias.
    #[test]
    fn invalid_areas_are_skipped() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let job = || ProxyCfg::for_job(&registry("127.0.0.1:1".parse().unwrap()), Some("t"));
        for areas in [
            vec![area("Bad", "p")],
            vec![area("a/b", "p")],
            vec![area("a", "")],
            vec![area("a", "job/x")],
        ] {
            assert_eq!(
                job().unwrap().with_areas(&areas).areas,
                Vec::new(),
                "{areas:?}"
            );
        }
        let kept = job().unwrap().with_areas(&[
            area("a", "p/x"),
            area("Bad", "p"),
            area("a", "q"),
            area("b", "q"),
        ]);
        assert_eq!(kept.areas, [area("a", "p/x"), area("b", "q")]);
    }

    /// Send `method` `target` to `proxy` without client normalization and return the status.
    async fn raw_status(proxy: SocketAddr, method: &str, target: &str) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut conn = tokio::net::TcpStream::connect(proxy).await.unwrap();
        conn.write_all(
            format!("{method} {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let mut reply = Vec::new();
        conn.read_to_end(&mut reply).await.unwrap();
        let status = reply.get(9..12).expect("a status line");
        std::str::from_utf8(status).unwrap().parse().unwrap()
    }

    /// An alias does not open a way out: `..` after it resolves before mapping, as on any other
    /// path, and an encoded separator is refused before mapping.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_alias_does_not_escape_its_scope() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream();
        let cfg = ProxyCfg::for_job(&registry(up_addr), Some("vkt_job"))
            .unwrap()
            .with_areas(&[area("task-cache", "task-cache/gl/42/protected")]);
        let (proxy, _served) = proxy_on_tcp(cfg);
        let status = raw_status(proxy, "GET", "/dav/files/job/task-cache/../../other").await;
        assert_eq!(status, 200);
        assert_eq!(seen.lock().unwrap().1, "/dav/files/other");
        *seen.lock().unwrap() = (String::new(), String::new());
        let status = raw_status(proxy, "GET", "/v2/job/task-cache/..%2F..%2Flock/x").await;
        assert_eq!(status, 403);
        assert_eq!(seen.lock().unwrap().1, "", "nothing forwarded");
    }

    /// A listing reached through the alias comes back under the alias; one reached by the real
    /// path, and any other response, keeps the real names.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_a_listing_through_the_alias_is_mapped_back() {
        const LISTING: &str = "<D:multistatus><D:href>/dav/files/task-cache/gl/42/protected/\
                               </D:href><D:href>/dav/files/task-cache/gl/42/protected/a\
                               </D:href></D:multistatus>";
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, _) = fake_upstream_replying(LISTING.as_bytes());
        let cfg = ProxyCfg::for_job(&registry(up_addr), Some("vkt_job"))
            .unwrap()
            .with_areas(&[area("task-cache", "task-cache/gl/42/protected")]);
        let (proxy, _served) = proxy_on_tcp(cfg);
        let body = |method: &'static str, target: &'static str| async move {
            reqwest::Client::new()
                .request(
                    reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                    format!("http://{proxy}{target}"),
                )
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap()
        };
        assert_eq!(
            body("PROPFIND", "/dav/files/job/task-cache").await,
            "<D:multistatus><D:href>/dav/files/job/task-cache/</D:href>\
             <D:href>/dav/files/job/task-cache/a</D:href></D:multistatus>"
        );
        for (method, target) in [
            ("PROPFIND", "/dav/files/task-cache/gl/42/protected"),
            ("GET", "/dav/files/job/task-cache/a"),
        ] {
            assert_eq!(body(method, target).await, LISTING, "{method} {target}");
        }
    }

    /// A listing's hrefs under the area's prefix go back to the alias, wherever the chunks
    /// split; others, and a prefix that only starts a longer component, are left alone.
    #[test]
    fn listing_hrefs_map_back_to_the_alias() {
        let body = "<D:href>/dav/files/t/gl/1/</D:href><D:href>/dav/files/t/gl/1/a</D:href>\
                    <D:href>/dav/files/t/gl/10/a</D:href><D:href>/dav/files/t/gl/1</D:href>";
        let want = "<D:href>/dav/files/job/c/</D:href><D:href>/dav/files/job/c/a</D:href>\
                    <D:href>/dav/files/t/gl/10/a</D:href><D:href>/dav/files/job/c</D:href>";
        for size in [1, 2, 7, 25, body.len()] {
            let mut map = HrefMap::new(&area("c", "t/gl/1"));
            let mut out = Vec::new();
            for chunk in body.as_bytes().chunks(size) {
                out.extend_from_slice(&map.push(chunk));
            }
            out.extend_from_slice(&map.finish());
            assert_eq!(String::from_utf8(out).unwrap(), want, "chunks of {size}");
        }
    }

    /// A job meant to have a token and given none gets a proxy that lends nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_job_without_a_token_gets_nothing() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream();
        let cfg = ProxyCfg::for_job(&registry(up_addr), None).unwrap();
        assert_eq!(cfg.scope, Scope::Deny);
        let (proxy, _served) = proxy_on_tcp(cfg);
        let (status, _, path) =
            status_and_auth(proxy, "GET", "/v2/app/manifests/latest", &seen).await;
        assert_eq!(status, 403);
        assert_eq!(path, "");
    }

    #[test]
    fn a_target_is_checked_once_resolved() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cfg = |up: &str| ProxyCfg::build(up.to_string(), Creds::anonymous()).unwrap();
        let up = cfg("http://reg.example:5000");
        let ok = |t: &str| upstream_url(&up, t).map(|u| u.to_string());
        assert_eq!(
            ok("/v2/app/manifests/latest").as_deref(),
            Some("http://reg.example:5000/v2/app/manifests/latest")
        );
        for escape in [
            "/v2/../lock/acquire?name=x",
            "/v2/%2e%2e/lock/acquire",
            "/v2/.%2E/lock/acquire",
            "/v2/a/../../lock/release",
            "/v2/..%2Flock/acquire",
            "/v2/..%2flock/acquire",
            "/v2/..%5Clock/acquire",
            "/v2/..\\lock/acquire",
            "//evil.example/v2/x",
            "/lock/acquire",
        ] {
            assert_eq!(ok(escape), None, "{escape}");
        }
        // An upstream mounted under a prefix keeps the guest beneath that prefix's /v2/.
        let reg = cfg("https://h.example/reg");
        let prefixed = |t: &str| upstream_url(&reg, t);
        assert!(prefixed("/v2/app/tags/list").is_some());
        assert!(prefixed("/v2/../admin").is_none());
        // The node's credential reaches neither the locks nor the files.
        assert_eq!(ok("/dav/files/x"), None);
        assert_eq!(ok("/s3/b/x"), None);
        // A job token's paths are checked once resolved as well, each against its own.
        let mut job = cfg("http://reg.example:5000");
        job.scope = Scope::Job;
        let ok = |t: &str| upstream_url(&job, t).map(|u| u.to_string());
        for fine in [
            "/lock/acquire?name=p:k",
            "/dav/files/p/x",
            "/s3/p/x",
            "/v2/p/tags/list",
        ] {
            assert!(ok(fine).is_some(), "{fine}");
        }
        for escape in [
            "/lock/../settings",
            "/dav/files/..%2fx",
            "/v2/../dav/repos/x",
            "/dav/files/../../x",
            "/dav/files/../repos/x",
            "/s3/../dav/repos/x",
            "/s3/p/..%2f..%2fx",
            "/lock/%2e%2e/browse",
        ] {
            assert_eq!(ok(escape), None, "{escape}");
        }
    }

    #[test]
    fn a_bad_upstream_fails_at_construction() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        for bad in [
            "reg.example:5000",
            "ftp://reg.example",
            "unix:/run/reg.sock",
            "http://reg.example/reg?x=1",
            "http://reg.example/reg#x",
        ] {
            assert!(
                ProxyCfg::build(bad.to_string(), Creds::anonymous()).is_err(),
                "{bad}"
            );
        }
    }

    /// Send the guest's raw request target without client-side normalization.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refuses_a_target_that_resolves_outside_v2() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream();
        let (proxy, _served) = proxy_on_tcp(basic_cfg(up_addr));
        for target in [
            "/v2/../lock/acquire?name=x",
            "/v2/%2e%2e/lock/acquire?name=x",
        ] {
            let mut conn = tokio::net::TcpStream::connect(proxy).await.unwrap();
            conn.write_all(
                format!("GET {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
            let mut reply = Vec::new();
            conn.read_to_end(&mut reply).await.unwrap();
            assert!(
                reply.starts_with(b"HTTP/1.1 403"),
                "{target}: {:?}",
                String::from_utf8_lossy(&reply)
            );
        }
        assert_eq!(
            seen.lock().unwrap().0,
            "",
            "a target resolving outside /v2/ must not be forwarded upstream"
        );
    }

    /// Raw request targets cannot escape their scope through URL resolution.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_job_token_refuses_a_raw_target_resolving_elsewhere() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream();
        let (proxy, _served) =
            proxy_on_tcp(ProxyCfg::for_job(&registry(up_addr), Some("vkt_job")).unwrap());
        for target in [
            "/lock/../settings/keys",
            "/dav/files/../../browse",
            "/dav/files/%2e%2e/%2e%2e/browse",
            "/v2/../dav/repos/x",
        ] {
            let mut conn = tokio::net::TcpStream::connect(proxy).await.unwrap();
            conn.write_all(
                format!("GET {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
            let mut reply = Vec::new();
            conn.read_to_end(&mut reply).await.unwrap();
            assert!(
                reply.starts_with(b"HTTP/1.1 403"),
                "{target}: {:?}",
                String::from_utf8_lossy(&reply)
            );
        }
        assert_eq!(seen.lock().unwrap().0, "", "nothing forwarded");
    }

    /// Forward only supported `/files/` and WebDAV methods. Preserve PROPFIND and MKCOL bodies.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn plain_files_take_the_registrys_verbs_and_their_bodies() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = body_upstream();
        let (proxy, _served) =
            proxy_on_tcp(ProxyCfg::for_job(&registry(up_addr), Some("vkt_job")).unwrap());
        let client = reqwest::Client::new();
        for method in ["MOVE", "COPY", "PROPPATCH", "LOCK", "POST"] {
            let r = client
                .request(
                    reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                    format!("http://{proxy}/dav/files/p/x"),
                )
                .header("destination", "http://registry.vk/dav/files/p/y")
                .send()
                .await
                .unwrap();
            assert_eq!(r.status().as_u16(), 405, "{method}");
        }
        for method in ["PROPFIND", "MKCOL", "OPTIONS", "MOVE", "POST"] {
            let r = client
                .request(
                    reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                    format!("http://{proxy}/files/p/x"),
                )
                .send()
                .await
                .unwrap();
            assert_eq!(r.status().as_u16(), 405, "{method} under /files/");
            assert_eq!(r.headers()["allow"], "GET, HEAD, PUT, DELETE", "{method}");
        }
        assert_eq!(*seen.lock().unwrap(), Vec::<u8>::new(), "nothing forwarded");
        let r = client
            .request(
                reqwest::Method::from_bytes(b"PROPFIND").unwrap(),
                format!("http://{proxy}/dav/files/p/x"),
            )
            .header("depth", "1")
            .body("<propfind/>")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        assert_eq!(*seen.lock().unwrap(), b"<propfind/>".to_vec());
        let r = client
            .request(
                reqwest::Method::from_bytes(b"MKCOL").unwrap(),
                format!("http://{proxy}/dav/files/p/x"),
            )
            .body("<mkcol/>")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        assert_eq!(*seen.lock().unwrap(), b"<mkcol/>".to_vec());
    }

    /// A PUT too large to buffer for retries retains the length `/files/` requires.
    /// HEAD retains the upstream file length.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_streamed_put_keeps_its_length_and_a_head_its_size() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, took) = scripted_upstream(vec![
            answer(0, b""),
            Act::Write(
                b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\nConnection: close\r\n\r\n".to_vec(),
            ),
        ]);
        let (proxy, _served) =
            proxy_on_tcp(ProxyCfg::for_job(&registry(up_addr), Some("vkt_job")).unwrap());
        let client = reqwest::Client::new();
        let big = vec![7u8; MAX_HELD + 1];
        let r = client
            .put(format!("http://{proxy}/files/p/x"))
            .body(big.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        {
            let took = took.lock().unwrap();
            let (head, body) = &took[0];
            assert!(
                head.contains(&format!("content-length: {}", big.len())),
                "{head}"
            );
            assert!(!head.contains("transfer-encoding"), "{head}");
            assert_eq!(body.len(), big.len());
        }
        let r = client
            .head(format!("http://{proxy}/files/p/x"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        assert_eq!(r.headers()["content-length"], "1234");
    }

    /// An upstream that records the body of the last request it took.
    fn body_upstream() -> (SocketAddr, Arc<std::sync::Mutex<Vec<u8>>>) {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let s = seen.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = TcpListener::from_std(listener).unwrap();
                while let Ok((stream, _)) = listener.accept().await {
                    let s = s.clone();
                    tokio::spawn(async move {
                        let svc = service_fn(move |req: Request<Incoming>| {
                            let s = s.clone();
                            async move {
                                let body = req.into_body().collect().await.unwrap().to_bytes();
                                *s.lock().unwrap() = body.to_vec();
                                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                                    b"ok",
                                ))))
                            }
                        });
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), svc)
                            .await;
                    });
                }
            });
        });
        (addr, seen)
    }

    /// Actions for [`scripted_upstream`], one request per connection. The last action
    /// repeats.
    #[derive(Clone)]
    enum Act {
        /// Close it once the request's head is read, answering nothing.
        Close,
        /// Write these bytes, then close it.
        Write(Vec<u8>),
    }

    /// A request [`scripted_upstream`] took: its head and its body.
    type Took = Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>>;

    /// Execute `script` in connection order and record each request.
    fn scripted_upstream(script: Vec<Act>) -> (SocketAddr, Took) {
        use std::io::{Read, Write};
        let took = Took::default();
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let t = took.clone();
        std::thread::spawn(move || {
            for (i, conn) in listener.incoming().enumerate() {
                let Ok(mut conn) = conn else { break };
                let mut req = Vec::new();
                let mut buf = [0u8; 4096];
                let head_end = loop {
                    if let Some(at) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                        break Some(at + 4);
                    }
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => break None,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                };
                let Some(head_end) = head_end else { continue };
                let head = String::from_utf8_lossy(&req[..head_end]).to_ascii_lowercase();
                let len = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                let chunked = head.contains("transfer-encoding: chunked");
                while if chunked {
                    !req[head_end..].ends_with(b"0\r\n\r\n")
                } else {
                    req.len() < head_end + len
                } {
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let body = if chunked {
                    dechunked(&req[head_end..])
                } else {
                    req[head_end..].to_vec()
                };
                t.lock().unwrap().push((head, body));
                match script.get(i).or(script.last()) {
                    Some(Act::Write(bytes)) => {
                        let _ = conn.write_all(bytes);
                    }
                    Some(Act::Close) | None => {}
                }
            }
        });
        (addr, took)
    }

    /// The data of a chunked body.
    fn dechunked(mut raw: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let at = raw.windows(2).position(|w| w == b"\r\n").unwrap();
            let size = usize::from_str_radix(std::str::from_utf8(&raw[..at]).unwrap(), 16).unwrap();
            if size == 0 {
                return out;
            }
            out.extend_from_slice(&raw[at + 2..at + 2 + size]);
            raw = &raw[at + 2 + size + 2..];
        }
    }

    /// A `200` of `body`, `Content-Length` saying `len`, digest-addressed.
    fn answer(len: usize, body: &[u8]) -> Act {
        answer_named(len, body, "sha256:ab")
    }

    /// [`answer`], naming `digest`.
    fn answer_named(len: usize, body: &[u8], digest: &str) -> Act {
        let mut bytes = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nDocker-Content-Digest: {digest}\r\n\
             Connection: close\r\n\r\n"
        )
        .into_bytes();
        bytes.extend_from_slice(body);
        Act::Write(bytes)
    }

    fn blob() -> Vec<u8> {
        (0..100_000u32).map(|i| (i % 251) as u8).collect()
    }

    /// A request safe to repeat is sent again while the upstream answers nothing, as when it
    /// restarts: the guest gets the answer once it comes, its body as sent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_request_safe_to_repeat_is_sent_again_until_answered() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, took) = scripted_upstream(vec![Act::Close, answer(2, b"ok")]);
        let (proxy, _served) = proxy_on_tcp(basic_cfg(up_addr));
        let client = reqwest::Client::new();
        let r = client
            .put(format!("http://{proxy}/v2/app/manifests/latest"))
            .body("{\"manifest\":1}")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        assert_eq!(r.text().await.unwrap(), "ok");
        let took = took.lock().unwrap().clone();
        assert_eq!(took.len(), 2, "{took:?}");
        for (head, body) in &took {
            assert!(head.starts_with("put /v2/app/manifests/latest "), "{head}");
            assert!(head.contains("authorization: basic"), "{head}");
            assert_eq!(body, b"{\"manifest\":1}");
        }
    }

    /// Upload chunks are sent once: repeating one finds the upload advanced. Bodyless
    /// deletions are also sent once: repeating one finds nothing to delete.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_upload_chunk_or_a_deletion_is_sent_once() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::new();
        for (method, target, body) in [
            (reqwest::Method::PATCH, "/v2/app/blobs/uploads/u1", "chunk"),
            (reqwest::Method::DELETE, "/v2/app/manifests/sha256:ab", ""),
        ] {
            let (up_addr, took) = scripted_upstream(vec![Act::Close, answer(2, b"ok")]);
            let (proxy, _served) = proxy_on_tcp(basic_cfg(up_addr));
            let r = client
                .request(method.clone(), format!("http://{proxy}{target}"))
                .body(body)
                .send()
                .await
                .unwrap();
            assert_eq!(r.status().as_u16(), 502, "{method}");
            assert_eq!(took.lock().unwrap().len(), 1, "{method}");
        }
    }

    /// Which requests are sent again, and which bodies resume.
    #[test]
    fn what_is_sent_again_and_resumed() {
        let get = Method::GET;
        let put = Method::PUT;
        let post = Method::POST;
        assert!(repeatable(&get, "/v2/app/blobs/sha256:ab"));
        assert!(repeatable(&Method::HEAD, "/v2/app/manifests/latest"));
        assert!(repeatable(&put, "/v2/app/manifests/latest"));
        assert!(repeatable(&put, "/v2/team/app/manifests/sha256:ab"));
        assert!(repeatable(&put, "/dav/files/p/x"));
        assert!(repeatable(&put, "/files/p/x"));
        assert!(!repeatable(&Method::DELETE, "/files/p/x"));
        assert!(repeatable(&put, "/s3/p/x"));
        assert!(!repeatable(&Method::DELETE, "/s3/p/x"));
        assert!(repeatable(&post, "/v2/app/blobs/uploads/"));
        assert!(!repeatable(&put, "/v2/app/blobs/uploads/u1"));
        assert!(!repeatable(&Method::PATCH, "/v2/app/blobs/uploads/u1"));
        assert!(!repeatable(&Method::DELETE, "/v2/app/manifests/sha256:ab"));
        assert!(!repeatable(&post, "/lock/acquire"));
        assert!(!repeatable(&get, "/lock/acquire"));
        assert!(!repeatable(
            &Method::from_bytes(b"MKCOL").unwrap(),
            "/dav/files/p/x"
        ));
        assert!(digest_addressed("/v2/app/blobs/sha256:ab"));
        assert!(digest_addressed("/v2/team/app/manifests/sha256:ab"));
        assert!(!digest_addressed("/v2/app/manifests/latest"));
        assert!(!digest_addressed("/v2/app/blobs/uploads/u1"));
        assert!(!digest_addressed("/dav/files/sha256:ab"));
    }

    /// A blob cut short resumes where it stopped, from an upstream that honours `Range` or
    /// from one that sends it whole again; the guest gets every byte once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_blob_cut_short_resumes_where_it_stopped() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let blob = blob();
        let cut = answer(blob.len(), &blob[..30_000]);
        let mut ranged = format!(
            "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\n\
             Content-Range: bytes 30000-{}/{}\r\nConnection: close\r\n\r\n",
            blob.len() - 30_000,
            blob.len() - 1,
            blob.len()
        )
        .into_bytes();
        ranged.extend_from_slice(&blob[30_000..]);
        for rest in [Act::Write(ranged), answer(blob.len(), &blob)] {
            let (up_addr, took) = scripted_upstream(vec![cut.clone(), rest]);
            let (proxy, _served) = proxy_on_tcp(basic_cfg(up_addr));
            let r = reqwest::Client::new()
                .get(format!("http://{proxy}/v2/app/blobs/sha256:ab"))
                .send()
                .await
                .unwrap();
            assert_eq!(r.status().as_u16(), 200);
            assert!(
                r.bytes().await.unwrap() == blob,
                "the guest got another body"
            );
            let took = took.lock().unwrap().clone();
            assert_eq!(took.len(), 2);
            assert!(!took[0].0.contains("range:"), "{}", took[0].0);
            assert!(took[1].0.contains("range: bytes=30000-"), "{}", took[1].0);
            assert!(took[1].0.contains("authorization: basic"), "{}", took[1].0);
        }
    }

    /// Responses not addressed by digest remain truncated; a resumed response with another
    /// length also fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_a_digest_resumes_and_only_into_the_same_bytes() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let blob = blob();
        let cut = answer(blob.len(), &blob[..30_000]);
        let (up_addr, took) = scripted_upstream(vec![cut.clone(), answer(blob.len(), &blob)]);
        let (proxy, _served) = proxy_on_tcp(basic_cfg(up_addr));
        let r = reqwest::Client::new()
            .get(format!("http://{proxy}/v2/app/manifests/latest"))
            .send()
            .await
            .unwrap();
        assert!(r.bytes().await.is_err());
        assert_eq!(took.lock().unwrap().len(), 1);

        let (up_addr, took) = scripted_upstream(vec![cut, answer(5, b"other")]);
        let (proxy, _served) = proxy_on_tcp(basic_cfg(up_addr));
        let r = reqwest::Client::new()
            .get(format!("http://{proxy}/v2/app/blobs/sha256:ab"))
            .send()
            .await
            .unwrap();
        assert!(r.bytes().await.is_err());
        assert_eq!(took.lock().unwrap().len(), 2);
    }

    /// A request turned away is sent again until the registry takes it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_request_turned_away_is_sent_again() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let busy = Act::Write(
            b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\nContent-Length: 4\r\n\
              Connection: close\r\n\r\nbusy"
                .to_vec(),
        );
        let (up_addr, took) = scripted_upstream(vec![busy, answer(2, b"ok")]);
        let (proxy, _served) = proxy_on_tcp(basic_cfg(up_addr));
        let r = reqwest::get(format!("http://{proxy}/v2/app/manifests/latest"))
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        assert_eq!(r.text().await.unwrap(), "ok");
        assert_eq!(took.lock().unwrap().len(), 2);
    }

    /// Bodies over the buffering limit stream upstream whole, once, even when the request
    /// would otherwise be retried.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_body_past_what_is_held_is_sent_once_whole() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, took) = scripted_upstream(vec![Act::Close, answer(2, b"ok")]);
        let (proxy, _served) = proxy_on_tcp(basic_cfg(up_addr));
        let big: Vec<u8> = (0..MAX_HELD + 10).map(|i| (i % 253) as u8).collect();
        // Streamed by the guest, so its size is known only once read.
        let chunks: Vec<std::io::Result<Vec<u8>>> =
            big.chunks(1 << 16).map(|c| Ok(c.to_vec())).collect();
        let r = reqwest::Client::new()
            .put(format!("http://{proxy}/v2/app/manifests/latest"))
            .body(reqwest::Body::wrap_stream(futures::stream::iter(chunks)))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 502);
        let took = took.lock().unwrap().clone();
        assert_eq!(took.len(), 1);
        assert!(took[0].1 == big, "the upstream got another body");
    }

    /// Resumes are bounded and reject a different range or digest. Guest range requests
    /// are not resumed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_digest_resumes_within_bounds() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let blob = blob();
        let cut = answer(blob.len(), &blob[..30_000]);
        let get = |proxy: SocketAddr, range: bool| async move {
            let mut rb =
                reqwest::Client::new().get(format!("http://{proxy}/v2/app/blobs/sha256:ab"));
            if range {
                rb = rb.header("range", "bytes=0-");
            }
            rb.send().await.unwrap().bytes().await
        };

        let (up_addr, took) = scripted_upstream(vec![cut.clone()]);
        let (proxy, _served) = proxy_on_tcp(basic_cfg(up_addr));
        assert!(get(proxy, false).await.is_err());
        assert_eq!(took.lock().unwrap().len(), 1 + MAX_RESUMES as usize);

        let wrong_range = Act::Write(
            format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Length: 10\r\n\
                 Content-Range: bytes 0-9/{}\r\nConnection: close\r\n\r\n0123456789",
                blob.len()
            )
            .into_bytes(),
        );
        let other_digest = answer_named(blob.len(), &blob, "sha256:cd");
        for rest in [wrong_range, other_digest] {
            let (up_addr, took) = scripted_upstream(vec![cut.clone(), rest]);
            let (proxy, _served) = proxy_on_tcp(basic_cfg(up_addr));
            assert!(get(proxy, false).await.is_err());
            assert_eq!(took.lock().unwrap().len(), 2);
        }

        let (up_addr, took) = scripted_upstream(vec![cut, answer(blob.len(), &blob)]);
        let (proxy, _served) = proxy_on_tcp(basic_cfg(up_addr));
        assert!(get(proxy, true).await.is_err());
        assert_eq!(took.lock().unwrap().len(), 1);
    }

    /// `--insecure` is plain HTTP, as everywhere else: it never turns certificate checks off.
    #[test]
    fn insecure_is_plain_http_and_never_unverified_tls() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let insecure = Creds {
            insecure: true,
            ..Creds::anonymous()
        };
        for upstream in ["https://reg.example", "HTTPS://reg.example"] {
            let err = ProxyCfg::from_parts(upstream, insecure.clone())
                .err()
                .expect("an https upstream with --insecure is refused")
                .to_string();
            assert!(err.contains("--ca"), "{upstream}: {err}");
        }
        assert!(ProxyCfg::from_parts("http://reg.example:5000", insecure).is_ok());
    }

    /// Drop guest authentication headers and cookies. Forward the S3 date, payload hash
    /// and content type.
    #[test]
    fn credentials_are_dropped_and_s3_headers_kept() {
        for name in ["authorization", "proxy-authorization", "cookie"] {
            assert!(is_skipped(name), "{name}");
        }
        for name in ["x-amz-date", "x-amz-content-sha256", "content-type"] {
            assert!(!is_skipped(name), "{name}");
        }
    }

    /// The proxy copies no hop-by-hop header, nor any a `Connection` names, from a guest's
    /// request or from a registry's response.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn headers_a_connection_names_stay_on_it() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let answer = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Up-Kept: 1\r\n\
                       X-Up-Dropped: 1\r\nKeep-Alive: timeout=5\r\n\
                       Connection: X-Up-Dropped, close\r\n\r\nok";
        let (up_addr, took) = scripted_upstream(vec![Act::Write(answer.to_vec())]);
        let (proxy, _served) = proxy_on_tcp(basic_cfg(up_addr));
        let r = reqwest::Client::new()
            .get(format!("http://{proxy}/v2/app/manifests/latest"))
            .header("x-kept", "1")
            .header("x-dropped", "1")
            .header("proxy-connection", "keep-alive")
            .header("connection", "X-Dropped")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        assert!(r.headers().contains_key("x-up-kept"));
        assert!(!r.headers().contains_key("x-up-dropped"));
        assert!(!r.headers().contains_key("keep-alive"));
        let took = took.lock().unwrap();
        let head = &took[0].0;
        assert!(head.contains("\r\nx-kept: 1\r\n"), "{head}");
        assert!(!head.contains("x-dropped"), "{head}");
        assert!(!head.contains("proxy-connection"), "{head}");
    }

    /// A digest, as the registry spells one.
    const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn areas_cfg(up_addr: SocketAddr) -> ProxyCfg {
        ProxyCfg::for_areas(
            &format!("http://{up_addr}/"),
            Creds {
                token: Some("vkr_build".to_string()),
                ..Creds::anonymous()
            },
            &[area("task-cache", "team/dev/task-cache")],
        )
        .unwrap()
    }

    /// The credential reaches the ping, which names no area, and the manifests, blobs, S3
    /// objects and locks of its areas, by alias or by the real name the registry answers with.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_credential_lent_for_areas_reaches_them() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream();
        let cfg = areas_cfg(up_addr);
        assert_eq!(cfg.scope, Scope::Areas);
        let (proxy, _served) = proxy_on_tcp(cfg);
        let blob = format!("/blobs/{DIGEST}");
        let finish = format!(
            "/blobs/uploads/1-2-ab?digest={}",
            DIGEST.replace(':', "%3A")
        );
        let at = |name: &str, tail: &str| format!("/v2/{name}{tail}");
        for (method, target, want) in [
            ("GET", "/v2/".to_string(), "/v2/".to_string()),
            ("HEAD", "/v2/".to_string(), "/v2/".to_string()),
            ("GET", "/v2/?".to_string(), "/v2/".to_string()),
            (
                "HEAD",
                at("job/task-cache/ns", &blob),
                at("team/dev/task-cache/ns", &blob),
            ),
            (
                "GET",
                at("job/task-cache", &blob),
                at("team/dev/task-cache", &blob),
            ),
            (
                "POST",
                at("job/task-cache/ns", "/blobs/uploads/"),
                at("team/dev/task-cache/ns", "/blobs/uploads/"),
            ),
            // An upload goes on at the real name its `Location` gave.
            (
                "PATCH",
                at("team/dev/task-cache/ns", "/blobs/uploads/1-2-ab"),
                at("team/dev/task-cache/ns", "/blobs/uploads/1-2-ab"),
            ),
            (
                "PUT",
                at("team/dev/task-cache/ns", &finish),
                at("team/dev/task-cache/ns", &finish),
            ),
            // However the digest's `:` is written, it is forwarded encoded.
            (
                "PUT",
                at("job/task-cache/ns", &finish.replace("%3A", ":")),
                at("team/dev/task-cache/ns", &finish),
            ),
            (
                "PUT",
                at("job/task-cache/ns", "/manifests/key"),
                at("team/dev/task-cache/ns", "/manifests/key"),
            ),
            (
                "GET",
                at("job/task-cache", "/manifests/latest"),
                at("team/dev/task-cache", "/manifests/latest"),
            ),
            (
                "HEAD",
                at("job/task-cache/ns", &format!("/manifests/{DIGEST}")),
                at("team/dev/task-cache/ns", &format!("/manifests/{DIGEST}")),
            ),
            (
                "POST",
                "/lock/acquire?name=job%2Ftask-cache%2Fns%3Ak&ttl=30&wait=0".to_string(),
                "/lock/acquire?name=team%2Fdev%2Ftask-cache%2Fns%3Ak&ttl=30&wait=0".to_string(),
            ),
            (
                "POST",
                "/lock/renew?name=team/dev/task-cache:k&ttl=30".to_string(),
                "/lock/renew?name=team%2Fdev%2Ftask-cache%3Ak&ttl=30".to_string(),
            ),
            (
                "POST",
                "/lock/release?name=job/task-cache:a&name=team/dev/task-cache/x:b".to_string(),
                "/lock/release?name=team%2Fdev%2Ftask-cache%3Aa&name=team%2Fdev%2Ftask-cache%2Fx%3Ab"
                    .to_string(),
            ),
            // sccache's startup probe and a sharded key, as its S3 backend names them.
            (
                "PUT",
                "/s3/job/task-cache/.sccache_check".to_string(),
                "/s3/team/dev/task-cache/.sccache_check".to_string(),
            ),
            (
                "GET",
                "/s3/job/task-cache/a/b/c/A1.b_c-d".to_string(),
                "/s3/team/dev/task-cache/a/b/c/A1.b_c-d".to_string(),
            ),
            (
                "HEAD",
                "/s3/team/dev/task-cache/a/key".to_string(),
                "/s3/team/dev/task-cache/a/key".to_string(),
            ),
            (
                "PUT",
                "/s3/job/task-cache/a/b/c/key?".to_string(),
                "/s3/team/dev/task-cache/a/b/c/key".to_string(),
            ),
        ] {
            let (status, auth, path) = status_and_auth(proxy, method, &target, &seen).await;
            assert_eq!(status, 200, "{method} {target}");
            assert_eq!(auth, "Bearer vkr_build", "{method} {target}");
            assert_eq!(path, want, "{method} {target}");
        }
    }

    /// Outside its areas the credential goes nowhere: other repositories, the plain files'
    /// repositories of its own areas, the registry's other APIs, and a lock request with one
    /// name outside. Nor does it go with a request the scope does not list, whatever
    /// repository it names: none of these reaches the registry.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_credential_lent_for_areas_stays_within_them() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream();
        let (proxy, _served) = proxy_on_tcp(areas_cfg(up_addr));
        let within = |tail: &str| format!("/v2/job/task-cache/ns{tail}");
        let mut refused: Vec<(&str, String)> = [
            ("POST", "/v2/"),
            ("GET", "/v2/?n=1"),
            ("GET", "/v2/_catalog"),
            ("GET", "/v2/other/manifests/latest"),
            ("GET", "/v2/team/dev/manifests/latest"),
            ("GET", "/v2/team/dev/task-cache-2/manifests/latest"),
            ("GET", "/v2/job/other/manifests/1"),
            ("GET", "/v2/job/task-cache"),
            ("GET", "/v2/job/task-cache/"),
            // The repositories behind an area's plain files are not the area's.
            ("GET", "/v2/files/team/dev/task-cache/manifests/latest"),
            ("PUT", "/v2/files/team/dev/task-cache/x/manifests/latest"),
            ("POST", "/v2/files/team/dev/task-cache/blobs/uploads/"),
            ("GET", "/v2/files/job/task-cache/manifests/latest"),
            ("GET", "/dav/files/job/task-cache/x"),
            ("PROPFIND", "/dav/files/team/dev/task-cache"),
            ("PUT", "/dav/files/team/dev/task-cache/x"),
            ("GET", "/dav/repos/team/dev/task-cache"),
            ("POST", "/vk/manifests/exists?name=team/dev/task-cache"),
            ("GET", "/settings/keys"),
            ("GET", "/"),
            ("POST", "/lock/status?name=job/task-cache:k"),
            ("POST", "/lock/fail?name=job/task-cache:k"),
            ("POST", "/lock/fail-status?name=job/task-cache:k"),
            ("POST", "/lock/acquire/x?name=job/task-cache:k"),
            ("GET", "/lock/acquire?name=job/task-cache:k"),
            ("PUT", "/lock/release?name=job/task-cache:k"),
            ("POST", "/lock/acquire"),
            ("POST", "/lock/acquire?ttl=30"),
            ("POST", "/lock/acquire?name=other:k"),
            ("POST", "/lock/acquire?name=job/other:k"),
            ("POST", "/lock/acquire?name=job/task-cache"),
            ("POST", "/lock/acquire?name=job/task-cache:"),
            ("POST", "/lock/acquire?name=team/dev:k"),
            ("POST", "/lock/acquire?name=team/dev/task-cache-2:k"),
            ("POST", "/lock/acquire?name=files/team/dev/task-cache:k"),
            ("POST", "/lock/acquire?name=job/task-cache:k&name=other:k"),
            ("POST", "/lock/acquire?name=other:k&name=job/task-cache:k"),
            ("POST", "/lock/acquire?name=job/task-cache:k&%6eame=other:k"),
            ("POST", "/lock/acquire?name=job/task-cache:k&NAME=other:k"),
            ("POST", "/lock/acquire?name=job/task-cache:k&ttl=3%30"),
            ("POST", "/lock/acquire?name=job/task-cache:k&name"),
            // A parameter the request does not take, however plain.
            ("POST", "/lock/acquire?name=job/task-cache:k&Name=5"),
            ("POST", "/lock/acquire?name=job/task-cache:k&names=5"),
            ("POST", "/lock/acquire?name=job/task-cache:k&TTL=30"),
            ("POST", "/lock/acquire?name=job/task-cache:k&owner=5"),
            ("POST", "/lock/renew?name=job/task-cache:k&wait=5"),
            ("POST", "/lock/release?name=job/task-cache:k&ttl=30"),
            ("POST", "/lock/acquire?name=job/task-cache:k&ttl=soon"),
            ("POST", "/lock/acquire?name=job/task-cache:k&ttl=-1"),
            ("POST", "/lock/acquire?name=job/task-cache:k&ttl=30&ttl=40"),
            (
                "POST",
                "/lock/acquire?name=job/task-cache/..%2F..%2Fother:k",
            ),
            (
                "POST",
                "/lock/acquire?name=team/dev/task-cache/../../other:k",
            ),
        ]
        .into_iter()
        .map(|(method, target)| (method, target.to_string()))
        .collect();
        refused.extend([
            ("GET", format!("/v2/team/dev/task-cachex/blobs/{DIGEST}")),
            // However a registry cuts the name, it is not under the area.
            (
                "GET",
                "/v2/other/blobs/team/dev/task-cache/manifests/x".to_string(),
            ),
            // Requests the scope does not list, in a repository of the area.
            ("OPTIONS", within("/manifests/x")),
            ("PROPFIND", within("/manifests/x")),
            ("DELETE", within("/manifests/x")),
            ("POST", within("/manifests/x")),
            ("PATCH", within("/manifests/x")),
            ("GET", within("/manifests/x?ns=other")),
            ("GET", within("/manifests/")),
            ("GET", within("/manifests/x/y")),
            ("GET", within("/tags/list")),
            ("GET", within("/referrers/x")),
            ("GET", within("/blobs/sha256:aa")),
            ("GET", within("/blobs/uploads")),
            ("PUT", within(&format!("/blobs/{DIGEST}"))),
            ("DELETE", within(&format!("/blobs/{DIGEST}"))),
            ("GET", within(&format!("/blobs/{DIGEST}?x=1"))),
            ("GET", within("/blobs/uploads/")),
            ("GET", within("/blobs/uploads/1-2-ab")),
            ("DELETE", within("/blobs/uploads/1-2-ab")),
            ("POST", within("/blobs/uploads/1-2-ab")),
            ("PATCH", within("/blobs/uploads/1-2-ab/x")),
            ("PATCH", within("/blobs/uploads/1-2-ab?digest=x")),
            ("PUT", within("/blobs/uploads/1-2-ab")),
            ("PUT", within("/blobs/uploads/1-2-ab?digest=sha256:aa")),
            (
                "PUT",
                within(&format!("/blobs/uploads/1-2-ab?digest={DIGEST}&from=other")),
            ),
            (
                "PUT",
                within(&format!("/blobs/uploads/1-2-ab?from=other&digest={DIGEST}")),
            ),
            // A mount names its source, another repository, in the query.
            (
                "POST",
                within(&format!("/blobs/uploads/?mount={DIGEST}&from=other")),
            ),
            ("POST", within(&format!("/blobs/uploads/?mount={DIGEST}"))),
            ("POST", within("/blobs/uploads/?from=other")),
            ("POST", within(&format!("/blobs/uploads/?digest={DIGEST}"))),
        ]);
        let s3 = |key: &str| format!("/s3/job/task-cache/{key}");
        refused.extend([
            ("GET", "/s3/".to_string()),
            ("GET", "/s3/team".to_string()),
            ("PUT", "/s3/team/x".to_string()),
            ("GET", "/s3/team/dev/x".to_string()),
            ("GET", "/s3/team/dev/task-cache-2/x".to_string()),
            ("GET", "/s3/other/team/dev/task-cache/x".to_string()),
            ("GET", "/s3/files/team/dev/task-cache/x".to_string()),
            ("GET", "/s3/job/other/x".to_string()),
            ("GET", "/s3/job/task-cache".to_string()),
            ("GET", s3("")),
            ("PUT", s3("a/")),
            ("GET", s3("a//x")),
            ("GET", s3("A/x")),
            ("GET", s3("a b/x")),
            ("GET", s3("tags/x")),
            ("GET", s3("a/blobs")),
            ("GET", s3(&format!("{}x", "a/".repeat(12)))),
            ("GET", s3(&"a".repeat(256))),
            ("GET", s3("x%41")),
            ("GET", s3("a%2Fb")),
            ("GET", s3("x?list-type=2")),
            ("GET", s3("x?acl")),
            ("PUT", s3("x?partNumber=1&uploadId=1")),
            ("POST", s3("x?uploads")),
            ("POST", s3("x")),
            ("DELETE", s3("x")),
            ("OPTIONS", s3("x")),
            ("PROPFIND", s3("x")),
            (
                "GET",
                "/s3/job/task-cache/?list-type=2&prefix=a".to_string(),
            ),
        ]);
        for (method, target) in refused {
            let (status, _, path) = status_and_auth(proxy, method, &target, &seen).await;
            assert_eq!(status, 403, "{method} {target}");
            assert_eq!(path, "", "{method} {target} must not be forwarded");
        }
        let r = reqwest::get(format!("http://{proxy}/v2/other/manifests/latest"))
            .await
            .unwrap();
        assert_eq!(r.bytes().await.unwrap(), OUTSIDE_AREAS);
    }

    /// Of a guest's headers, the registry gets those the areas' requests use: none that
    /// names another route or method to a server in between, and none the guest's
    /// `Connection` keeps to its own connection. The credential is the proxy's.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_credential_lent_for_areas_goes_with_the_headers_its_requests_use() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, took) = scripted_upstream(vec![answer(2, b"ok")]);
        let (proxy, _served) = proxy_on_tcp(areas_cfg(up_addr));
        let r = reqwest::Client::new()
            .post(format!("http://{proxy}/lock/acquire?name=job/task-cache:k"))
            .header("x-vk-lock-holder", "job 7")
            .header("x-vk-lock-owner", "tok")
            .header("accept-encoding", "zstd")
            .header("content-encoding", "zstd")
            .header("content-type", "text/plain")
            .header("x-http-method-override", "DELETE")
            .header("x-original-url", "/lock/status?name=other:k")
            .header("x-forwarded-host", "evil.example")
            .header("x-vk-lock-pipeline", "9")
            .header("forwarded", "host=evil.example")
            .header("connection", "x-vk-lock-owner, keep-alive")
            .header("authorization", "Bearer guest-forged")
            .body("held")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        let took = took.lock().unwrap();
        let head = &took[0].0;
        assert!(head.starts_with("post /lock/acquire?name="), "{head}");
        let mut names: Vec<&str> = head
            .lines()
            .skip(1)
            .filter_map(|l| l.split_once(':'))
            .map(|(name, _)| name)
            .collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "accept",
                "accept-encoding",
                "authorization",
                "content-encoding",
                "content-length",
                "content-type",
                "host",
                "x-vk-lock-holder",
            ],
            "{head}"
        );
        assert!(
            head.contains("authorization: bearer vkr_build\r\n"),
            "{head}"
        );
        assert_eq!(took[0].1, b"held");
    }

    /// S3 writes pass the payload hash and signing date. A header the registry's S3 view
    /// refuses (a copy, an additional checksum, encryption, a precondition, a partial write,
    /// a content coding, a streaming or ambiguous payload), or a `Connection` option that
    /// would drop a forwarded header, is refused before the request reaches the registry.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_s3_object_within_an_area_goes_with_its_requests_headers() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, took) = scripted_upstream(vec![answer(0, b"")]);
        let (proxy, _served) = proxy_on_tcp(areas_cfg(up_addr));
        let target = format!("http://{proxy}/s3/job/task-cache/a/b/c/key");
        let sha = "c".repeat(64);
        let r = reqwest::Client::new()
            .put(&target)
            .header("x-amz-date", "20261125T000000Z")
            .header("x-amz-content-sha256", &sha)
            .header("content-type", "application/octet-stream")
            .header("x-forwarded-host", "evil.example")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=guest")
            .body("object")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        {
            let took = took.lock().unwrap();
            let head = &took[0].0;
            assert!(
                head.starts_with("put /s3/team/dev/task-cache/a/b/c/key "),
                "{head}"
            );
            let mut names: Vec<&str> = head
                .lines()
                .skip(1)
                .filter_map(|l| l.split_once(':'))
                .map(|(name, _)| name)
                .collect();
            names.sort_unstable();
            assert_eq!(
                names,
                [
                    "accept",
                    "authorization",
                    "content-length",
                    "content-type",
                    "host",
                    "x-amz-content-sha256",
                    "x-amz-date",
                ],
                "{head}"
            );
            assert!(
                head.contains("authorization: bearer vkr_build\r\n"),
                "{head}"
            );
            assert!(head.contains(&format!("x-amz-content-sha256: {sha}\r\n")));
            assert_eq!(took[0].1, b"object");
        }

        let (up_addr, seen) = fake_upstream();
        let (proxy, _served) = proxy_on_tcp(areas_cfg(up_addr));
        let target = format!("http://{proxy}/s3/job/task-cache/a/key");
        let sha = sha.as_str();
        for headers in [
            &[("x-amz-copy-source", "/team/dev/task-cache/a/other")][..],
            &[("x-amz-server-side-encryption", "AES256")],
            &[("x-amz-checksum-crc32", "AAAAAA==")],
            &[("content-md5", "1B2M2Y8AsgTpgAmY7PhCfg==")],
            &[("if-none-match", "*")],
            &[("if-match", "\"0\"")],
            &[("if-unmodified-since", "Thu, 26 Nov 2026 00:00:00 GMT")],
            &[("content-range", "bytes 0-5/6")],
            &[("content-encoding", "aws-chunked")],
            &[("content-encoding", "gzip")],
            &[("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")],
            &[("x-amz-content-sha256", "nope")],
            &[("x-amz-content-sha256", sha), ("x-amz-content-sha256", sha)],
            &[
                ("x-amz-content-sha256", sha),
                ("connection", "x-amz-content-sha256"),
            ],
            &[
                ("content-type", "text/plain"),
                ("connection", "Content-Type"),
            ],
        ] {
            let mut rb = reqwest::Client::new().put(&target).body("object");
            for (name, value) in headers {
                rb = rb.header(*name, *value);
            }
            let r = rb.send().await.unwrap();
            assert_eq!(r.status().as_u16(), 403, "{headers:?}");
            assert_eq!(
                seen.lock().unwrap().1,
                "",
                "{headers:?} must not be forwarded"
            );
        }
    }

    /// No spelling of a target leaves the areas: `..` and its escapes resolve before the
    /// check, an escaped separator or any other escape left in an OCI path is refused, the
    /// target names no other authority, and a query lets no path outside through.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_raw_target_does_not_leave_the_areas() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream();
        let (proxy, _served) = proxy_on_tcp(areas_cfg(up_addr));
        for (method, target) in [
            ("GET", "/v2/job/task-cache/../../other/manifests/x"),
            ("GET", "/v2/job/task-cache/%2e%2e/%2E%2e/other/manifests/x"),
            ("GET", "/v2/team/dev/task-cache/../other/manifests/x"),
            ("GET", "/v2/team/dev/task-cache/..%2Fother/manifests/x"),
            ("GET", "/v2/team/dev/task-cache/..%5Cother/manifests/x"),
            ("GET", "/v2/job/task-cache%2Fx/manifests/y"),
            ("GET", "/v2/team/dev/task-cache/manifests/a%3Fb"),
            ("GET", "/v2/team/dev/task-cach%65/manifests/x"),
            ("GET", "/v2/team/dev/task-cache/x/blobs/%252e%252e"),
            ("GET", "//evil.example/v2/job/task-cache/manifests/x"),
            ("GET", "/v2//team/dev/task-cache/manifests/x"),
            ("GET", "/v2/job//task-cache/manifests/x"),
            (
                "GET",
                "/v2/other/manifests/x?/v2/job/task-cache/manifests/x",
            ),
            ("GET", "/v2/other/manifests/x?name=job/task-cache:k"),
            (
                "POST",
                "/v2/job/task-cache/../../../lock/status?name=job/task-cache:k",
            ),
            ("POST", "/lock/acquire/../status?name=job/task-cache:k"),
            ("POST", "/lock/../vk/manifests/exists?name=job/task-cache"),
            ("POST", "/lock/%2e%2e/dav/files/job/task-cache/x"),
            ("POST", "/lock/acquire%3Fname=job/task-cache:k"),
            ("POST", "/lock/acquire?name=job/task-cache:k&name=%6fther:k"),
        ] {
            assert_eq!(raw_status(proxy, method, target).await, 403, "{target}");
            assert_eq!(seen.lock().unwrap().1, "", "{target} must not be forwarded");
        }
        // A `..` that stays within the areas is the path it resolves to.
        let target = "/v2/job/task-cache/a/../b/manifests/x";
        assert_eq!(raw_status(proxy, "GET", target).await, 200);
        assert_eq!(
            seen.lock().unwrap().1,
            "/v2/team/dev/task-cache/b/manifests/x"
        );
    }

    #[test]
    fn an_oci_path_names_its_shortest_repository() {
        for (rest, want) in [
            ("a/b/manifests/latest", Some(("a/b", "manifests/latest"))),
            ("a/b/blobs/sha256:aa", Some(("a/b", "blobs/sha256:aa"))),
            ("a/b/blobs/uploads/", Some(("a/b", "blobs/uploads/"))),
            ("a/b/tags/list", Some(("a/b", "tags/list"))),
            ("a/blobs/b/manifests/x", Some(("a", "blobs/b/manifests/x"))),
            (
                "a/manifests/b/blobs/uploads/c",
                Some(("a", "manifests/b/blobs/uploads/c")),
            ),
            ("/manifests/x", Some(("", "manifests/x"))),
            ("a/b", None),
            ("a/b/manifests", None),
            ("_catalog", None),
            ("a/b/manifests/x%2e", None),
            ("a%2eb/manifests/x", None),
        ] {
            assert_eq!(oci_repository(rest), want, "{rest}");
        }
    }

    /// A lock request's query is written again from its checked pairs, or refused whole.
    #[test]
    fn a_lock_query_is_rebuilt_from_what_was_checked() {
        let areas = [area("task-cache", "team/dev/task-cache")];
        let q = |query: &str| area_lock_query(&areas, &["ttl", "wait"], query);
        assert_eq!(
            q("name=team%2Fdev%2Ftask-cache%2Fns%3Ak&ttl=30&wait=0").as_deref(),
            Some("name=team%2Fdev%2Ftask-cache%2Fns%3Ak&ttl=30&wait=0")
        );
        assert_eq!(
            q("ttl=30&&name=team/dev/task-cache:a+b").as_deref(),
            Some("ttl=30&name=team%2Fdev%2Ftask-cache%3Aa%20b")
        );
        // What another parser would split is one name here, and one name upstream.
        assert_eq!(
            q("name=team/dev/task-cache:k;name=other:k").as_deref(),
            Some("name=team%2Fdev%2Ftask-cache%3Ak%3Bname%3Dother%3Ak")
        );
        assert_eq!(
            q("name=team/dev/task-cache:k%26name%3Dother:k").as_deref(),
            Some("name=team%2Fdev%2Ftask-cache%3Ak%26name%3Dother%3Ak")
        );
        for refused in [
            "",
            "ttl=30",
            "name=",
            "name=other:k",
            "name=team/dev/task-cache",
            "name=team/dev/task-cache:k&name=other:k",
            "name=other:k&name=team/dev/task-cache:k",
            "name=team/dev/task-cache:k&%6eame=other:k",
            "name=team/dev/task-cache:k&Name=other:k",
            "name=team/dev/task-cache:k&x=a%26name%3Dother:k",
            "name=team/dev/task-cache:k&x=a+b",
            "name=team/dev/task-cache:k&ttl",
            "name=team%2Fdev%2Ftask-cache%2F..%2F..%2Fother:k",
            "name=Team/dev/task-cache:k",
            "name=files/team/dev/task-cache:k",
            // A key the request does not take, though nothing in it needs decoding.
            "name=team/dev/task-cache:k&Name=5",
            "name=team/dev/task-cache:k&NAME=5",
            "name=team/dev/task-cache:k&names=5",
            "name=team/dev/task-cache:k&x=1",
            "name=team/dev/task-cache:k&Ttl=30",
            "name=team/dev/task-cache:k&ttl=",
            "name=team/dev/task-cache:k&ttl=soon",
            "name=team/dev/task-cache:k&ttl=+5",
            "name=team/dev/task-cache:k&ttl=-5",
            "name=team/dev/task-cache:k&ttl=1.5",
            "name=team/dev/task-cache:k&ttl=99999999999999999999",
            "name=team/dev/task-cache:k&ttl=30&ttl=30",
        ] {
            assert_eq!(q(refused), None, "{refused}");
        }
        // Each request takes its own parameters.
        let renew = |query: &str| area_lock_query(&areas, &["ttl"], query);
        assert!(renew("name=team/dev/task-cache:k&ttl=30").is_some());
        assert_eq!(renew("name=team/dev/task-cache:k&wait=5"), None);
        let release = |query: &str| area_lock_query(&areas, &[], query);
        assert!(release("name=team/dev/task-cache:k").is_some());
        assert_eq!(release("name=team/dev/task-cache:k&ttl=30"), None);
    }

    /// An area the proxy could not map, or whose prefix the registry serves no repository
    /// under, fails the construction: the credential would be lent for something other than
    /// what was asked.
    #[test]
    fn an_unusable_area_fails_at_construction() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cfg = |areas: &[Area]| {
            ProxyCfg::for_areas("http://reg.example:5000", Creds::anonymous(), areas)
        };
        let deep = ["a"; 17].join("/");
        for bad in [
            area("task/cache", "dev/task-cache"),
            area("task-cache", "Dev/task-cache"),
            area("task-cache", "dev/../x"),
            area("task-cache", ""),
            area("task-cache", "job/task-cache"),
            area("task-cache", "files/dev/task-cache"),
            area("task-cache", "dev/blobs"),
            area("task-cache", "manifests/dev"),
            area("task-cache", "dev/tags/task-cache"),
            area("task-cache", &deep),
        ] {
            assert!(cfg(std::slice::from_ref(&bad)).is_err(), "{bad:?}");
        }
        assert!(cfg(&[area("a", "p"), area("a", "q")]).is_err());
        assert!(cfg(&[area("a", &deep[..31])]).is_ok());
        let ok = cfg(&[area("a", "p/x"), area("b", "q")]).unwrap();
        assert_eq!(ok.areas, [area("a", "p/x"), area("b", "q")]);
        // With no area, only the ping.
        let none = cfg(&[]).unwrap();
        let url = |t: &str| upstream_url(&none, t).unwrap();
        let no_headers = hyper::HeaderMap::new();
        assert!(confined(&none, &Method::GET, &no_headers, &url("/v2/")).is_some());
        assert!(confined(&none, &Method::GET, &no_headers, &url("/v2/a/manifests/x")).is_none());
    }

    /// The areas a credential is lent for are those it was built with: a job's areas do not
    /// replace them.
    #[test]
    fn a_credential_lent_for_areas_keeps_them() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cfg = areas_cfg("127.0.0.1:1".parse().unwrap()).with_areas(&[area("other", "other")]);
        assert_eq!(cfg.areas, [area("task-cache", "team/dev/task-cache")]);
        let url = |t: &str| upstream_url(&cfg, t).unwrap();
        let no_headers = hyper::HeaderMap::new();
        assert!(
            confined(
                &cfg,
                &Method::GET,
                &no_headers,
                &url("/v2/other/manifests/x")
            )
            .is_none()
        );
        let inside = url("/v2/team/dev/task-cache/manifests/x");
        assert!(confined(&cfg, &Method::GET, &no_headers, &inside).is_some());
    }

    /// A redirect goes back to the guest as the registry sent it: the proxy sends nothing
    /// where it points.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_credential_lent_for_areas_follows_no_redirect() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let redirect =
            b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /lock/status?name=other:k\r\n\
                         Content-Length: 0\r\nConnection: close\r\n\r\n";
        let (up_addr, took) = scripted_upstream(vec![Act::Write(redirect.to_vec())]);
        let (proxy, _served) = proxy_on_tcp(areas_cfg(up_addr));
        let guest = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let r = guest
            .get(format!(
                "http://{proxy}/v2/job/task-cache/ns/blobs/{DIGEST}"
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 307);
        assert_eq!(r.headers()["location"], "/lock/status?name=other:k");
        let took = took.lock().unwrap();
        assert_eq!(took.len(), 1, "the redirect is not followed");
        let forwarded = format!("get /v2/team/dev/task-cache/ns/blobs/{DIGEST} ");
        assert!(took[0].0.starts_with(&forwarded));
    }

    /// A vk-registry over a store of its own, gated by a bearer token. Dropping it stops the
    /// server and removes the store.
    struct LocalRegistry {
        addr: SocketAddr,
        stop: Option<tokio::sync::oneshot::Sender<()>>,
        thread: Option<std::thread::JoinHandle<()>>,
        _dir: crate::testtmp::Scratch,
    }

    impl Drop for LocalRegistry {
        fn drop(&mut self) {
            drop(self.stop.take());
            let ended = self.thread.take().unwrap().join();
            if !std::thread::panicking() {
                ended.unwrap();
            }
        }
    }

    /// A [`LocalRegistry`] gated by `token`, its store in a new private directory `name`.
    fn local_registry(name: &str, token: &str) -> LocalRegistry {
        let dir = crate::testtmp::Scratch::dir(name);
        let token_file = dir.join("token");
        std::fs::write(&token_file, token).unwrap();
        let mut cfg =
            vk_registry::ServerConfig::local("127.0.0.1:5000".parse().unwrap(), dir.join("store"));
        cfg.token_file = Some(token_file);
        let state = Arc::new(cfg.into_state().expect("a local config starts"));
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            // Dropping the runtime ends the connections still open.
            rt.block_on(async move {
                let listener = TcpListener::from_std(listener).unwrap();
                tokio::select! {
                    _ = stopped => {}
                    served = vk_registry::serve_on(listener, state) => served.unwrap(),
                }
            });
        });
        LocalRegistry {
            addr,
            stop: Some(stop),
            thread: Some(thread),
            _dir: dir,
        }
    }

    /// The requests a task cache makes (task v4.14.0's), against a real registry: the ping,
    /// a chunk probed, pushed as a zstd frame and pulled as one, a manifest by tag, and a
    /// lock taken, renewed and released, with no credential of the guest's own. All name the
    /// alias but the upload's end, which goes to the `Location` the registry gave.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_task_cache_works_through_its_area() {
        use sha2::Digest;

        let _ = rustls::crypto::ring::default_provider().install_default();
        let served = local_registry("regproxy-task-cache", "s3cret");
        let registry = served.addr;
        let cfg = ProxyCfg::for_areas(
            &format!("http://{registry}"),
            Creds {
                token: Some("s3cret".to_string()),
                ..Creds::anonymous()
            },
            &[area("task-cache", "dev/task-cache")],
        )
        .unwrap();
        let (proxy, _served) = proxy_on_tcp(cfg);
        let base = format!("http://{proxy}");
        let guest = reqwest::Client::new();
        // Asked directly, the registry wants the credential.
        let direct = guest
            .get(format!(
                "http://{registry}/v2/dev/task-cache/ns/manifests/key"
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(direct.status().as_u16(), 401);

        let ping = guest.get(format!("{base}/v2/")).send().await.unwrap();
        assert_eq!(ping.status().as_u16(), 200);
        assert_eq!(ping.headers()[vk_registry::TRANSPARENT_ZSTD_HEADER], "1");

        // A chunk, named by the digest of its bytes and sent as a zstd frame.
        let chunk = b"a task's output ".repeat(256);
        let digest: String = sha2::Sha256::digest(&chunk)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let digest = format!("sha256:{digest}");
        let frame = zstd::encode_all(&chunk[..], 3).unwrap();
        let blob = format!("{base}/v2/job/task-cache/ns/blobs/{digest}");
        let probe = guest.head(&blob).send().await.unwrap();
        assert_eq!(probe.status().as_u16(), 404);
        let started = guest
            .post(format!("{base}/v2/job/task-cache/ns/blobs/uploads/"))
            .send()
            .await
            .unwrap();
        assert_eq!(started.status().as_u16(), 202);
        // The registry answers with the real name, which the proxy takes too.
        let location = started.headers()["location"].to_str().unwrap().to_string();
        assert!(
            location.starts_with("/v2/dev/task-cache/ns/blobs/uploads/"),
            "{location}"
        );
        let pushed = guest
            .put(format!("{base}{location}"))
            .query(&[("digest", &digest)])
            .header("content-encoding", "zstd")
            .body(frame.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(pushed.status().as_u16(), 201);
        assert_eq!(guest.head(&blob).send().await.unwrap().status(), 200);
        let pulled = guest
            .get(&blob)
            .header("accept-encoding", "zstd")
            .send()
            .await
            .unwrap();
        assert_eq!(pulled.status().as_u16(), 200);
        assert_eq!(pulled.headers()["content-encoding"], "zstd");
        assert_eq!(pulled.bytes().await.unwrap(), frame);
        let plain = guest.get(&blob).send().await.unwrap();
        assert!(!plain.headers().contains_key("content-encoding"));
        assert_eq!(plain.bytes().await.unwrap(), chunk);

        const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": MANIFEST,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": digest, "size": chunk.len(),
            },
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": digest, "size": chunk.len(),
            }],
        })
        .to_string();
        let tag = format!("{base}/v2/job/task-cache/ns/manifests/key");
        assert_eq!(guest.get(&tag).send().await.unwrap().status(), 404);
        let put = guest
            .put(&tag)
            .header("content-type", MANIFEST)
            .body(manifest.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(put.status().as_u16(), 201);
        let got = guest.get(&tag).send().await.unwrap();
        assert_eq!(got.status().as_u16(), 200);
        assert_eq!(got.text().await.unwrap(), manifest);

        let lock = |action: &str, pairs: &[(&str, &str)]| {
            guest
                .post(format!("{base}/lock/{action}"))
                .query(&[("name", "job/task-cache/ns:key")])
                .query(pairs)
        };
        let acquire = || {
            lock("acquire", &[("ttl", "30"), ("wait", "0")])
                .header("x-vk-lock-holder", "a guest")
                .send()
        };
        let taken = acquire().await.unwrap();
        assert_eq!(taken.status().as_u16(), 200);
        let taken: serde_json::Value = taken.json().await.unwrap();
        assert_eq!(taken["names"], serde_json::json!(["dev/task-cache/ns:key"]));
        let owner = taken["owner"].as_str().unwrap().to_string();
        assert_eq!(acquire().await.unwrap().status().as_u16(), 409);
        let renewed = lock("renew", &[("ttl", "30")])
            .header("x-vk-lock-owner", &owner)
            .send()
            .await
            .unwrap();
        assert_eq!(renewed.status().as_u16(), 200);
        let released = lock("release", &[])
            .header("x-vk-lock-owner", &owner)
            .send()
            .await
            .unwrap();
        assert_eq!(released.status().as_u16(), 200);
        assert_eq!(acquire().await.unwrap().status().as_u16(), 200);

        // Under any other name the proxy refuses the same requests.
        for (method, target) in [
            (reqwest::Method::GET, "/v2/other/manifests/key".to_string()),
            (reqwest::Method::GET, format!("/v2/other/blobs/{digest}")),
            (
                reqwest::Method::POST,
                "/lock/status?name=job/task-cache/ns:key".into(),
            ),
            (reqwest::Method::POST, "/lock/acquire?name=other:key".into()),
            (reqwest::Method::GET, "/dav/files/dev/task-cache/".into()),
        ] {
            let r = guest
                .request(method.clone(), format!("{base}{target}"))
                .send()
                .await
                .unwrap();
            assert_eq!(r.status().as_u16(), 403, "{method} {target}");
        }
    }
}
