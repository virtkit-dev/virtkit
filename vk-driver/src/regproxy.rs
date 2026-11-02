//! Per-VM credential-injecting registry proxy.
//!
//! When enabled (per-VM `vk run --registry-proxy`, or runner-wide `[registry] proxy_guests`
//! for the executor), `vk` runs this HTTP reverse proxy on the host loopback and forwards
//! the guest to it (the switch redirects a sentinel address — `registry.vk` — to it; see
//! switch.rs). The guest's registry client talks plain, credential-free HTTP to it; the
//! proxy adds the runner's registry credential on the way to the real (central) registry.
//! So the job never holds the secret, and the proxy is never exposed on a network
//! interface — only reachable through the switch's per-VM redirect.
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
//! lock API (`/lock/`) and plain files (`/dav/files/`): the registry enforces the token's
//! grants on each. A job meant to have a token and given none gets a proxy that forwards
//! nothing.
//!
//! A job's token may come with areas ([`Area`]): `job/<alias>` in an OCI or plain-file path, or
//! before the `:` of a lock name, stands for the area's prefix, so a guest names a fixed path
//! whatever its project or protection. No other query parameter is mapped, an OCI mount's
//! `from=` among them. Only requests are rewritten: the registry answers with the real names
//! (an upload's `Location`, a lock's holders), which the proxy forwards too. A `PROPFIND`'s
//! hrefs are the exception, mapped back to the alias, since a WebDAV client resolves a listing
//! against the root it asked for.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

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
use tokio::net::TcpListener;

use vk_hub_proto::dispatch::Area;
use vk_hub_proto::token::{ALIAS_ROOT, under, valid_component, valid_prefix};

use crate::oci::Creds;

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

/// Which of the registry's paths the proxy forwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// The OCI API only, `/v2/`: what an unscoped credential may be lent for.
    Oci,
    /// `/v2/`, `/lock/` and `/dav/files/`: a job token's, whose grants the registry enforces.
    Job,
    /// Nothing: a job that should have had a token and has none.
    Deny,
}

impl Scope {
    /// The path prefixes forwarded, below the upstream's own path.
    fn paths(self) -> &'static [&'static str] {
        match self {
            Scope::Oci => &["/v2/"],
            Scope::Job => &["/v2/", "/lock/", DAV_FILES],
            Scope::Deny => &[],
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
    /// The job's areas, mapped under [`Scope::Job`] only.
    areas: Vec<Area>,
    /// The credential injected into every forwarded request, so the job stays
    /// credential-free — and the trust anchor `client` was built against.
    pub creds: Creds,
    pub client: reqwest::Client,
}

impl ProxyCfg {
    /// Build from the `vk run --registry-proxy` flags: `upstream` is the base URL,
    /// optionally with a path prefix, `creds` both what to inject and what TLS to trust.
    pub fn from_parts(upstream: &str, creds: Creds) -> Result<Self> {
        Self::build(upstream.trim_end_matches('/').to_string(), creds)
    }

    /// Build from the runner's `[registry]` config (the executor path): the central
    /// registry's base URL, and the credential every other `[registry]` client resolves —
    /// a bearer token when one is configured, else the Basic pair.
    pub fn from_registry(rg: &crate::config::Registry) -> Result<Self> {
        Self::build(Self::upstream_of(rg)?, Creds::from_registry(rg)?)
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

    /// Set [`Self::for_job`]'s areas to those [`usable_areas`] keeps. Log each rejected area
    /// to the host's stderr without failing the job; its other paths still work.
    /// `VK_REGISTRY_AREAS` also omits rejected areas.
    pub fn with_areas(mut self, areas: &[Area]) -> Self {
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

    fn build(upstream: String, creds: Creds) -> Result<Self> {
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
        let mut b = reqwest::Client::builder();
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

/// Bind an ephemeral loopback port and serve the proxy on the current runtime, returning
/// the bound address (handed to the switch as the redirect target).
pub async fn spawn(cfg: ProxyCfg) -> Result<SocketAddr> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("binding the registry proxy")?;
    let addr = listener.local_addr()?;
    tokio::spawn(serve_on(listener, Arc::new(cfg)));
    Ok(addr)
}

/// Like [`spawn`], but from a synchronous context (the executor's `spawn_switch`): binds
/// synchronously and serves on a dedicated thread + runtime for the process's lifetime.
pub fn spawn_blocking(cfg: ProxyCfg) -> Result<SocketAddr> {
    // A loopback TCP port: any process on the host can use the credential through it, as it
    // could the node's own. A 0600 unix socket would confine it to this user.
    let listener =
        std::net::TcpListener::bind(("127.0.0.1", 0)).context("binding the registry proxy")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("building the registry proxy runtime");
        rt.block_on(async move {
            match TcpListener::from_std(listener) {
                Ok(l) => serve_on(l, Arc::new(cfg)).await,
                Err(e) => eprintln!("registry proxy: adopting the listener: {e}"),
            }
        });
    });
    Ok(addr)
}

async fn serve_on(listener: TcpListener, cfg: Arc<ProxyCfg>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
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

/// What a request becomes under the job's areas.
#[derive(Debug, PartialEq, Eq)]
enum Mapped<'a> {
    /// Nothing under [`ALIAS_ROOT`]: forwarded as it is.
    Unchanged,
    /// The path and query to forward instead, below the upstream's own path, and the area.
    To(String, &'a Area),
    /// `job/…` naming no area of this job.
    Unknown,
}

/// `url` (an accepted upstream URL) under `cfg`'s areas: `job/<alias>` at the start of an
/// OCI or plain-file path, or of a lock name's path part, becomes the area's prefix.
fn map_aliases<'a>(cfg: &'a ProxyCfg, url: &reqwest::Url) -> Mapped<'a> {
    if cfg.scope != Scope::Job {
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
    for base in ["/v2/", DAV_FILES] {
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
            | "transfer-encoding"
    )
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
    let Some(url) = upstream_url(cfg, &path_and_query) else {
        return Ok(forbidden(match cfg.scope {
            Scope::Oci => b"registry proxy: only /v2/ registry paths are proxied",
            Scope::Job => b"registry proxy: only /v2/, /lock/ and /dav/files/ are proxied",
            Scope::Deny => b"registry proxy: this job has no registry credential",
        }));
    };
    let method = req.method().clone();
    // Plain files take the verbs vk-registry serves there, and no MOVE or COPY, whose
    // `Destination` names the proxy rather than the registry.
    if path_and_query.starts_with(DAV_FILES) && !DAV_FILES_METHODS.contains(&method.as_str()) {
        let body = Full::new(Bytes::from_static(
            b"registry proxy: this method is not proxied under /dav/files/",
        ))
        .map_err(|never| match never {})
        .boxed_unsync();
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(body)?);
    }
    // The job's aliases, mapped on the resolved URL, which then goes through the same checks
    // again: the prefix is the hub's, but the rest of the path is still the guest's.
    let (url, area) = match map_aliases(cfg, &url) {
        Mapped::Unchanged => (url, None),
        Mapped::To(target, area) => match upstream_url(cfg, &target) {
            Some(url) => (url, Some(area)),
            None => return Ok(forbidden(b"registry proxy: an area's path is refused")),
        },
        Mapped::Unknown => {
            return Ok(forbidden(
                b"registry proxy: this job has no area of that alias",
            ));
        }
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
    let headers: Vec<_> = parts
        .headers
        .iter()
        .filter(|(k, _)| !is_skipped(&k.as_str().to_ascii_lowercase()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let sent = match (repeatable(&method, path), bodyful) {
        (true, false) => Outgoing::Whole(Bytes::new()),
        (true, true) => held(incoming, MAX_HELD).await?,
        (false, false) => Outgoing::Once(None),
        (false, true) => Outgoing::Once(Some(streamed(incoming))),
    };
    let request = |body: Option<reqwest::Body>| {
        let mut rb = cfg.client.request(method.clone(), url.clone());
        for (k, v) in &headers {
            rb = rb.header(k, v);
        }
        rb = cfg.creds.apply(rb);
        match body {
            Some(body) => rb.body(body),
            None => rb,
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
    for (k, v) in headers_out.iter() {
        if !is_skipped(&k.as_str().to_ascii_lowercase()) {
            out = out.header(k, v);
        }
    }
    out.body(body).map_err(Into::into)
}

/// The most of a guest's request body held to be sent again: an OCI manifest's 4 MiB, which
/// registries cap manifests at, and far more than a listing's query or a small file.
const MAX_HELD: usize = 4 << 20;

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
                || path.starts_with(DAV_FILES)
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
        let proxy = spawn_blocking(basic_cfg(up_addr)).unwrap();

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
        let proxy = spawn_blocking(cfg).unwrap();

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
        let proxy = spawn_blocking(basic_cfg(up_addr)).unwrap();

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

    /// A job's token reaches the lock API and plain files as well as `/v2/`, injected in
    /// place of whatever the guest sent; the section's own credential is never read.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_job_token_reaches_locks_and_files_too() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = fake_upstream();
        let cfg = ProxyCfg::for_job(&registry(up_addr), Some("vkt_job")).unwrap();
        assert_eq!(cfg.scope, Scope::Job);
        let proxy = spawn_blocking(cfg).unwrap();
        for (method, target) in [
            ("GET", "/v2/p/gl/42/app/manifests/latest"),
            ("POST", "/lock/acquire?name=p/gl/42:k"),
            ("PROPFIND", "/dav/files/p/gl/42/x"),
            ("PUT", "/dav/files/p/gl/42/x"),
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
        let proxy = spawn_blocking(cfg).unwrap();
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
        let proxy = spawn_blocking(cfg).unwrap();
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
        let proxy = spawn_blocking(cfg).unwrap();
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
        let proxy = spawn_blocking(cfg).unwrap();
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
        // A job token's paths are checked once resolved as well, each against its own.
        let mut job = cfg("http://reg.example:5000");
        job.scope = Scope::Job;
        let ok = |t: &str| upstream_url(&job, t).map(|u| u.to_string());
        for fine in [
            "/lock/acquire?name=p:k",
            "/dav/files/p/x",
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
        let proxy = spawn_blocking(basic_cfg(up_addr)).unwrap();
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
        let proxy = spawn_blocking(ProxyCfg::for_job(&registry(up_addr), Some("vkt_job")).unwrap())
            .unwrap();
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

    /// Under /dav/files/ only the verbs the registry serves there pass, and a PROPFIND's or a
    /// MKCOL's body reaches the registry.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn plain_files_take_the_registrys_verbs_and_their_bodies() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (up_addr, seen) = body_upstream();
        let proxy = spawn_blocking(ProxyCfg::for_job(&registry(up_addr), Some("vkt_job")).unwrap())
            .unwrap();
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
        let proxy = spawn_blocking(basic_cfg(up_addr)).unwrap();
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
            let proxy = spawn_blocking(basic_cfg(up_addr)).unwrap();
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
            let proxy = spawn_blocking(basic_cfg(up_addr)).unwrap();
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
        let proxy = spawn_blocking(basic_cfg(up_addr)).unwrap();
        let r = reqwest::Client::new()
            .get(format!("http://{proxy}/v2/app/manifests/latest"))
            .send()
            .await
            .unwrap();
        assert!(r.bytes().await.is_err());
        assert_eq!(took.lock().unwrap().len(), 1);

        let (up_addr, took) = scripted_upstream(vec![cut, answer(5, b"other")]);
        let proxy = spawn_blocking(basic_cfg(up_addr)).unwrap();
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
        let proxy = spawn_blocking(basic_cfg(up_addr)).unwrap();
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
        let proxy = spawn_blocking(basic_cfg(up_addr)).unwrap();
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
        let proxy = spawn_blocking(basic_cfg(up_addr)).unwrap();
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
            let proxy = spawn_blocking(basic_cfg(up_addr)).unwrap();
            assert!(get(proxy, false).await.is_err());
            assert_eq!(took.lock().unwrap().len(), 2);
        }

        let (up_addr, took) = scripted_upstream(vec![cut, answer(blob.len(), &blob)]);
        let proxy = spawn_blocking(basic_cfg(up_addr)).unwrap();
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
}
