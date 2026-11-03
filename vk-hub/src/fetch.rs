//! `vk-hub release fetch` and `/updates`' fetch form download a [`Program`]'s
//! binary (`vk`, `vk-registry`, `vk-gitlab` or `vk-hub`) from a GitHub virtkit release and
//! hold it as if supplied to `release add`.
//!
//! `vk-selfupdate` resolves and checks the release as `vk update` does, except for
//! running the binary: https for the API and assets, no redirect leaving https
//! ([`vk_selfupdate::client`]), the program's asset at most 512 MiB, and a sha256 matching
//! `<asset>.sha256`. The tag must match the requested version. [`releases::adopt`] applies the
//! usual release checks: an x86-64 ELF with that version as a standalone string. The hub runs
//! none on fetching it ([`releases`]); the node, registry or relay, or for `vk-hub` the hub's
//! own update, runs its `--version` smoke test.
//!
//! What this proves is that the hub holds the bytes the repository published as that version,
//! intact: not who built them. A release whose binary and sidecar were replaced together — a
//! compromised repository or account — passes. A release key's signature is what a node can
//! trust instead: a fetched release carries none, as official releases are not signed yet, so
//! a node, registry or relay that requires one refuses it, as it refuses an unsigned `release
//! add`.
//!
//! A fetch takes one program or several; several are fetched one after another at the same
//! version, the latest pinned once up front, and one failing does not stop the others.
//! One fetch runs at a time, in the background; its progress and outcome are kept for the
//! pages and audited. Asking which release is the latest is one request at a time too, and
//! answered from the last answer for [`CHECK_INTERVAL`]: the API allows an unauthenticated
//! caller 60 requests an hour.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::server::Hub;
use crate::store::{Program, Release};
use crate::{local, releases};

/// What `release_repository` is unless the config says otherwise.
pub const DEFAULT_SOURCE: &str = "https://github.com/virtkit-dev/virtkit";

/// How long a fetch's requests may take in all: `vk-selfupdate` bounds each read to 30
/// seconds, not a download that trickles. Checking what arrived is not counted: it is the
/// hub's own disk, and a release half adopted when the time ran out would be held all the
/// same.
#[cfg(not(test))]
const FETCH_TIMEOUT: Duration = Duration::from_secs(30 * 60);
#[cfg(test)]
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// How long asking for the latest release may take.
pub(crate) const CHECK_TIMEOUT: Duration = Duration::from_secs(60);

/// How long to reuse the latest-release check's answer or failure.
const CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Where releases are fetched from: a repository on github.com, or on a GitHub Enterprise
/// Server, whose REST API is `/api/v3` under its host.
#[derive(Clone, Debug)]
pub struct Source {
    /// As configured, normalized: `https://host/owner/repo`.
    url: String,
    repo: vk_selfupdate::Repository,
}

impl Source {
    /// `url`, `https://<host>/<owner>/<repo>`, checked. Only https: what is fetched is held
    /// for nodes to run, and its digest comes from the same place.
    pub fn parse(url: &str) -> Result<Source> {
        let bad = || {
            anyhow::anyhow!(
                "release_repository {url:?}: expected https://<host>/<owner>/<repo>, such as \
                 {DEFAULT_SOURCE}, or \"none\""
            )
        };
        let rest = url.strip_prefix("https://").ok_or_else(bad)?;
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        let mut parts = rest.split('/');
        let (Some(host), Some(owner), Some(name), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(bad());
        };
        let host = host.to_ascii_lowercase();
        let host_ok = !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
            && !host.starts_with(['.', '-', ':']);
        if !host_ok {
            return Err(bad());
        }
        let api = if host == "github.com" {
            "https://api.github.com".to_string()
        } else {
            format!("https://{host}/api/v3")
        };
        let repo = vk_selfupdate::Repository::new(&api, &format!("{owner}/{name}"))
            .map_err(|e| bad().context(e))?;
        Ok(Source {
            url: format!("https://{host}/{owner}/{name}"),
            repo,
        })
    }

    /// virtkit's own repository on github.com.
    pub fn virtkit() -> Source {
        Source {
            url: DEFAULT_SOURCE.to_string(),
            repo: vk_selfupdate::Repository::virtkit(),
        }
    }

    /// The repository `virtkit-dev/virtkit` on a test's own API at `api`, over plain http.
    #[cfg(test)]
    pub fn at(api: &str) -> Source {
        Source {
            url: format!("{api}/virtkit-dev/virtkit"),
            repo: vk_selfupdate::Repository::new(api, "virtkit-dev/virtkit").unwrap(),
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}

/// A fetch, as the pages show it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchStatus {
    /// The version asked for; `None` for the latest.
    pub asked: Option<String>,
    pub by: String,
    pub started_at: u64,
    /// Each program fetched, in order.
    pub items: Vec<FetchItem>,
}

impl FetchStatus {
    pub fn running(&self) -> bool {
        self.items.iter().any(|i| i.phase.running())
    }
}

/// One program's binary within a fetch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchItem {
    pub program: Program,
    pub phase: Phase,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum Phase {
    /// Behind an earlier program of the same fetch.
    Waiting,
    /// Asking the repository which release that is.
    Resolving,
    /// Downloading and checking its binary.
    Downloading {
        version: String,
    },
    Done {
        version: String,
        sha256: String,
        at: u64,
    },
    Failed {
        reason: String,
        at: u64,
    },
}

impl Phase {
    pub fn running(&self) -> bool {
        matches!(
            self,
            Phase::Waiting | Phase::Resolving | Phase::Downloading { .. }
        )
    }
}

/// What the hub keeps of fetching: where from, and the latest fetch and check.
pub struct Fetches {
    /// `None`: fetching is off.
    source: Option<Source>,
    status: Mutex<Option<FetchStatus>>,
    /// The latest release the repository named when last asked, and when.
    latest: Mutex<Option<(String, u64)>>,
    /// When the repository was last asked which release is the latest, and the version it
    /// named or why asking failed; held while asking, so one request is out at a time.
    checked: tokio::sync::Mutex<Option<(tokio::time::Instant, Result<String, String>)>>,
}

impl Fetches {
    pub fn new(source: Option<Source>) -> Self {
        Fetches {
            source,
            status: Mutex::new(None),
            latest: Mutex::new(None),
            checked: tokio::sync::Mutex::new(None),
        }
    }

    pub fn source(&self) -> Option<&Source> {
        self.source.as_ref()
    }

    /// The latest fetch, if any since the hub started.
    pub fn status(&self) -> Option<FetchStatus> {
        lock(&self.status).clone()
    }

    /// The latest release the repository named, and when it was asked.
    pub fn latest(&self) -> Option<(String, u64)> {
        lock(&self.latest).clone()
    }
}

/// Entries replaced whole: nothing half-written for a panic to leave behind.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A fetch refused because another is under way.
#[derive(Debug)]
pub struct Busy;

impl std::fmt::Display for Busy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a release is being fetched already; wait for it to end")
    }
}

impl std::error::Error for Busy {}

/// `version` as asked — a version, `v<version>`, or `latest` — as [`start`] takes it: `None`
/// for the latest.
pub fn wanted(version: &str) -> Result<Option<String>> {
    let version = version.trim();
    if version.is_empty() || version == "latest" {
        return Ok(None);
    }
    let version = version.strip_prefix('v').unwrap_or(version);
    releases::check_version(version)?;
    Ok(Some(version.to_string()))
}

/// Fetch `version` (`None` means latest) of each of `programs` as `actor` in the background,
/// one after another. Resolve the handle with each program's outcome, in order, and keep
/// them for the pages.
pub fn start(
    hub: &Arc<Hub>,
    actor: &str,
    programs: &[Program],
    version: Option<String>,
) -> Result<tokio::task::JoinHandle<Vec<Result<Release>>>> {
    let Some(source) = hub.fetches.source().cloned() else {
        bail!("fetching releases is off: the hub's release_repository is \"none\"");
    };
    if programs.is_empty() {
        bail!("no program to fetch");
    }
    hub.releases_dir()?;
    // Held until the fetch ends, whoever started it: an update of the hub would cut it.
    let long = hub.handover.long_call()?;
    let what = version.as_deref().unwrap_or("latest").to_string();
    {
        let mut status = lock(&hub.fetches.status);
        if status.as_ref().is_some_and(FetchStatus::running) {
            return Err(Busy.into());
        }
        *status = Some(FetchStatus {
            asked: version.clone(),
            by: actor.to_string(),
            started_at: crate::now_secs(),
            items: programs
                .iter()
                .map(|&program| FetchItem {
                    program,
                    phase: Phase::Waiting,
                })
                .collect(),
        });
    }
    let names = programs
        .iter()
        .map(|p| p.name())
        .collect::<Vec<_>>()
        .join(", ");
    let started = format!(
        "{actor} started fetching {names} {what} from {}",
        source.url()
    );
    eprintln!("vk-hub: {started}");
    hub.touch();
    let (hub, actor, programs) = (hub.clone(), actor.to_string(), programs.to_vec());
    Ok(tokio::spawn(async move {
        let _long = long;
        let mut results = Vec::with_capacity(programs.len());
        // The version every program is fetched at; several come from one release, so the
        // latest is pinned once.
        let pinned: Result<Option<String>, String> = match local::audit(&hub, &actor, started).await
        {
            Err(e) => Err(format!("{e:#}")),
            Ok(()) => match version {
                Some(v) => Ok(Some(v)),
                None if programs.len() == 1 => Ok(None),
                None => {
                    set_phase(&hub, 0, Phase::Resolving);
                    latest(&hub)
                        .await
                        .map(Some)
                        .map_err(|e| format!("finding the latest release: {e:#}"))
                }
            },
        };
        for (index, &program) in programs.iter().enumerate() {
            let result = match &pinned {
                Ok(version) => {
                    fetch(&hub, index, &actor, &source, program, version.as_deref()).await
                }
                Err(e) => Err(anyhow::anyhow!("{e}")),
            };
            let now = crate::now_secs();
            let phase = match &result {
                Ok(r) => Phase::Done {
                    version: r.row.version.clone(),
                    sha256: r.sha256.clone(),
                    at: now,
                },
                Err(e) => {
                    let reason = vk_hub_proto::display_safe(&format!("{e:#}"));
                    let event = format!(
                        "{actor} failed to fetch {program} {what} from {}: {reason}",
                        source.url()
                    );
                    eprintln!("vk-hub: {event}");
                    if let Err(e) = local::audit(&hub, &actor, event).await {
                        eprintln!("vk-hub: writing the audit log: {e:#}");
                    }
                    Phase::Failed { reason, at: now }
                }
            };
            set_phase(&hub, index, phase);
            results.push(result);
        }
        results
    }))
}

/// Set the phase of the running fetch's `index`th program, for the pages.
fn set_phase(hub: &Hub, index: usize, phase: Phase) {
    if let Some(item) = lock(&hub.fetches.status)
        .as_mut()
        .and_then(|s| s.items.get_mut(index))
    {
        item.phase = phase;
    }
    hub.touch();
}

/// Whether a release is held already, or the file its download goes to.
enum Holding {
    Held(Release),
    Staged(releases::Staged),
}

async fn fetch(
    hub: &Arc<Hub>,
    index: usize,
    actor: &str,
    source: &Source,
    program: Program,
    version: Option<&str>,
) -> Result<Release> {
    set_phase(hub, index, Phase::Resolving);
    let deadline = tokio::time::Instant::now() + FETCH_TIMEOUT;
    let client = vk_selfupdate::client(concat!("vk-hub/", env!("CARGO_PKG_VERSION")))?;
    let asset = program.name();
    let resolved = within(
        deadline,
        vk_selfupdate::artifacts_in(&client, &source.repo, version, &[asset]),
    )
    .await?;
    let Some(artifact) = resolved.artifacts.into_iter().find(|a| a.name == asset) else {
        bail!(
            "release {} publishes no {asset}",
            vk_hub_proto::display_safe(&resolved.version)
        );
    };
    let found = resolved.version;
    if let Some(want) = version
        && found != want
    {
        bail!(
            "asked for {want}, the repository answered with release {}",
            vk_hub_proto::display_safe(&found)
        );
    }
    releases::check_version(&found)?;
    set_phase(
        hub,
        index,
        Phase::Downloading {
            version: found.clone(),
        },
    );
    let (held, sha256, version) = (hub.clone(), artifact.sha256.clone(), found.clone());
    let holding = tokio::task::spawn_blocking(move || holding(&held, sha256, program, &version))
        .await
        .context("looking for the release")??;
    let staged = match holding {
        Holding::Held(release) => return Ok(release),
        Holding::Staged(staged) => staged,
    };
    within(
        deadline,
        vk_selfupdate::fetch(
            &client,
            &artifact.url,
            &artifact.sha256,
            staged.path(),
            0o600,
        ),
    )
    .await
    .with_context(|| format!("downloading {program} {found}"))?;
    let (held, actor, version) = (hub.clone(), actor.to_string(), found.clone());
    let release = tokio::task::spawn_blocking(move || {
        releases::adopt(&held, &actor, staged, program, &version, None)
    })
    .await
    .context("adding the release")??;
    // `vk-selfupdate` checked the download against the digest; the same file was read again.
    if release.sha256 != artifact.sha256 {
        bail!("the file held changed after it was checked against the published digest");
    }
    Ok(release)
}

/// Release `sha256` if it is held already as `version` of `program`, its file intact: nothing
/// to download. Otherwise a name to download it to; a missing or wrong-size file is downloaded
/// again, and `adopt` restores it.
fn holding(hub: &Hub, sha256: String, program: Program, version: &str) -> Result<Holding> {
    let held = releases::path(hub.releases_dir()?, &sha256);
    if let Some(row) = hub.db.release(&sha256)?
        && row.is(program)
        && row.version == version
        && row.signature.is_none()
        && std::fs::metadata(&held).is_ok_and(|m| m.is_file() && m.len() == row.size)
    {
        return Ok(Holding::Held(Release { sha256, row }));
    }
    Ok(Holding::Staged(releases::Staged::name(hub, "fetch")?))
}

/// `request`'s outcome, or an error once `deadline` has passed.
async fn within<T>(
    deadline: tokio::time::Instant,
    request: impl Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout_at(deadline, request)
        .await
        .unwrap_or_else(|_| {
            Err(anyhow::anyhow!(
                "it took longer than {}",
                crate::human_duration(FETCH_TIMEOUT)
            ))
        })
}

/// The latest release the repository names, kept for the pages.
pub async fn latest(hub: &Hub) -> Result<String> {
    let Some(source) = hub.fetches.source() else {
        bail!("fetching releases is off: the hub's release_repository is \"none\"");
    };
    let mut checked = hub.fetches.checked.lock().await;
    if let Some((at, answer)) = checked.as_ref()
        && at.elapsed() < CHECK_INTERVAL
    {
        return answer
            .clone()
            .map_err(|e| anyhow::anyhow!("{e} (asked {}s ago)", at.elapsed().as_secs()));
    }
    let answer = ask_latest(source).await;
    *checked = Some((
        tokio::time::Instant::now(),
        answer.as_ref().map_err(|e| format!("{e:#}")).cloned(),
    ));
    let version = answer?;
    *lock(&hub.fetches.latest) = Some((version.clone(), crate::now_secs()));
    hub.touch();
    Ok(version)
}

/// Ask `source` which release is the latest, whatever programs it publishes.
async fn ask_latest(source: &Source) -> Result<String> {
    let client = vk_selfupdate::client(concat!("vk-hub/", env!("CARGO_PKG_VERSION")))?;
    let resolved = tokio::time::timeout(
        CHECK_TIMEOUT,
        vk_selfupdate::artifacts_in(&client, &source.repo, None, &[]),
    )
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "{} did not answer within {}",
            source.url(),
            crate::human_duration(CHECK_TIMEOUT)
        )
    })??;
    Ok(vk_hub_proto::display_safe(&resolved.version))
}

#[cfg(test)]
pub mod tests {
    use std::convert::Infallible;
    use std::net::SocketAddr;

    use bytes::Bytes;
    use futures::StreamExt;
    use http_body_util::combinators::BoxBody;
    use http_body_util::{BodyExt, Full, StreamBody};
    use hyper::body::{Frame, Incoming};
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::store::Db;

    /// Fetch `program`'s `version` alone as `uid 7`, and its outcome.
    async fn one(hub: &Arc<Hub>, program: Program, version: Option<String>) -> Result<Release> {
        start(hub, "uid 7", &[program], version)
            .unwrap()
            .await
            .unwrap()
            .pop()
            .unwrap()
    }

    /// A stand-in for a `vk` release: an x86-64 ELF header, and `version` as `vk --version`
    /// prints it.
    pub fn fake_vk(version: &str) -> Vec<u8> {
        let mut bin = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x02\0\x3e\0".to_vec();
        bin.extend_from_slice(&[0u8; 64]);
        bin.extend_from_slice(format!("\0vk-driver {version} (test)\0").as_bytes());
        bin
    }

    /// What a fake GitHub serves for one release.
    #[derive(Clone)]
    pub struct FakeRelease {
        pub tag: String,
        /// The `vk` asset's bytes; none published when empty.
        pub vk: Vec<u8>,
        /// The digest its sidecar publishes; `vk`'s own unless a test says otherwise.
        pub sha256: String,
        /// The download sends half of `vk`, then nothing more.
        pub stall: bool,
        /// The `vk-registry` asset's bytes, published beside `vk` with their own digest.
        pub registry: Option<Vec<u8>>,
    }

    impl FakeRelease {
        pub fn new(tag: &str, vk: Vec<u8>) -> Self {
            let sha256 = vk_hub_proto::to_hex(&Sha256::digest(&vk));
            FakeRelease {
                tag: tag.into(),
                vk,
                sha256,
                stall: false,
                registry: None,
            }
        }
    }

    /// A fake GitHub API and download host for `release`, the latest and the only one, on
    /// an ephemeral loopback port: the API root to give [`Source::at`].
    pub async fn fake_github(release: FakeRelease) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let release = release.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let resp = serve(addr, req.uri().path(), &release);
                        async move { Ok::<_, Infallible>(resp) }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        format!("http://{addr}")
    }

    fn serve(
        addr: SocketAddr,
        path: &str,
        r: &FakeRelease,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let reply = |status: u16, body: Vec<u8>| {
            Response::builder()
                .status(status)
                .body(Full::new(Bytes::from(body)).boxed())
                .unwrap()
        };
        let repo = "/repos/virtkit-dev/virtkit/releases";
        let registry_sidecar = |bin: &[u8]| {
            format!(
                "{}  vk-registry\n",
                vk_hub_proto::to_hex(&Sha256::digest(bin))
            )
        };
        if path == format!("{repo}/latest") || path == format!("{repo}/tags/{}", r.tag) {
            let sidecar = format!("{}  vk\n", r.sha256);
            let registry = r.registry.as_ref().map_or(String::new(), |bin| {
                format!(
                    r#",{{"name":"vk-registry","browser_download_url":"http://{addr}/dl/vk-registry","size":{}}},
                    {{"name":"vk-registry.sha256","browser_download_url":"http://{addr}/dl/vk-registry.sha256","size":{}}}"#,
                    bin.len(),
                    registry_sidecar(bin).len()
                )
            });
            let vk = format!(
                r#"{{"name":"vk","browser_download_url":"http://{addr}/dl/vk","size":{size}}},
                    {{"name":"vk.sha256","browser_download_url":"http://{addr}/dl/vk.sha256","size":{sidecar_size}}}"#,
                size = r.vk.len(),
                sidecar_size = sidecar.len(),
            );
            let assets = match (r.vk.is_empty(), registry.strip_prefix(',')) {
                (true, Some(registry)) => registry.to_string(),
                (true, None) => String::new(),
                (false, _) => format!("{vk}{registry}"),
            };
            let json = format!(r#"{{"tag_name":"{tag}","assets":[{assets}]}}"#, tag = r.tag);
            return reply(200, json.into_bytes());
        }
        match path {
            "/dl/vk" if r.stall => {
                let half = Bytes::copy_from_slice(&r.vk[..r.vk.len() / 2]);
                let body = futures::stream::once(async { Ok(Frame::data(half)) })
                    .chain(futures::stream::pending());
                Response::new(BodyExt::boxed(StreamBody::new(body)))
            }
            "/dl/vk" => reply(200, r.vk.clone()),
            "/dl/vk.sha256" => reply(200, format!("{}  vk\n", r.sha256).into_bytes()),
            "/dl/vk-registry" if r.registry.is_some() => {
                reply(200, r.registry.clone().unwrap_or_default())
            }
            "/dl/vk-registry.sha256" if r.registry.is_some() => reply(
                200,
                registry_sidecar(r.registry.as_deref().unwrap_or_default()).into_bytes(),
            ),
            _ => reply(404, br#"{"message":"Not Found"}"#.to_vec()),
        }
    }

    /// A hub keeping releases in a scratch directory and fetching from `api`.
    pub fn hub_fetching_from(api: &str, tag: &str) -> (Arc<Hub>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "vk-hub-fetch-{tag}-{}-{}",
            std::process::id(),
            crate::random_hex(4).unwrap()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let hub = Hub::new(Arc::new(Db::open_memory().unwrap()), None)
            .with_releases(dir.join("releases"))
            .with_release_source(Some(Source::at(api)));
        (Arc::new(hub), dir)
    }

    fn installed() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    /// Only nothing staged is left in the releases directory: what is there is releases.
    fn assert_nothing_staged(dir: &std::path::Path) {
        let left: Vec<_> = std::fs::read_dir(dir.join("releases"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.starts_with('.'))
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[test]
    fn a_source_is_an_https_repository() {
        let s = Source::parse("https://github.com/virtkit-dev/virtkit/").unwrap();
        assert_eq!(s.url(), DEFAULT_SOURCE);
        assert_eq!(s.repo, vk_selfupdate::Repository::virtkit());
        let s = Source::parse("https://GHE.example.com/ops/virtkit").unwrap();
        assert_eq!(s.repo.api(), "https://ghe.example.com/api/v3");
        assert_eq!(s.repo.name(), "ops/virtkit");
        for bad in [
            "http://github.com/virtkit-dev/virtkit",
            "https://github.com/virtkit-dev",
            "https://github.com/virtkit-dev/virtkit/releases",
            "https://github.com/../virtkit",
            "https://github.com/a/b?x=1",
            "https://user@github.com/a/b",
            "https://github.com/a/b#c",
            "github.com/a/b",
            "",
        ] {
            assert!(Source::parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(wanted("latest").unwrap(), None);
        assert_eq!(wanted(" ").unwrap(), None);
        assert_eq!(wanted("v0.85.0").unwrap().as_deref(), Some("0.85.0"));
        assert!(wanted("0.85.0/../x").is_err());
    }

    /// The latest release's `vk` is downloaded, checked against its sidecar and held, audited
    /// as the actor; asking again finds it held, and restores its file if it went missing.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_release_is_fetched_checked_and_held() {
        installed();
        let bin = fake_vk("0.85.0");
        let api = fake_github(FakeRelease::new("v0.85.0", bin.clone())).await;
        let (hub, dir) = hub_fetching_from(&api, "ok");
        assert_eq!(latest(&hub).await.unwrap(), "0.85.0");
        let release = one(&hub, Program::Vk, None).await.unwrap();
        assert_eq!(release.row.version, "0.85.0");
        assert_eq!(release.row.signature, None);
        assert_eq!(release.sha256, vk_hub_proto::to_hex(&Sha256::digest(&bin)));
        let held = std::fs::read(releases::path(&dir.join("releases"), &release.sha256)).unwrap();
        assert_eq!(held, bin);
        assert_nothing_staged(&dir);
        assert!(matches!(
            hub.fetches.status().unwrap().items[0].phase,
            Phase::Done { .. }
        ));
        let again = one(&hub, Program::Vk, Some("0.85.0".into())).await.unwrap();
        assert_eq!(again, release);
        // A held release whose file went missing is downloaded again, restoring it.
        std::fs::remove_file(releases::path(&dir.join("releases"), &release.sha256)).unwrap();
        let restored = one(&hub, Program::Vk, None).await.unwrap();
        assert_eq!(restored, release);
        let held = std::fs::read(releases::path(&dir.join("releases"), &release.sha256)).unwrap();
        assert_eq!(held, bin);
        assert_nothing_staged(&dir);
        let events: Vec<String> = hub
            .db
            .audits(None, 10)
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .collect();
        let short = crate::store::short(&release.sha256);
        for want in [
            format!("uid 7 started fetching vk latest from {api}/virtkit-dev/virtkit"),
            format!("uid 7 added release {short} as vk 0.85.0"),
            format!("uid 7 started fetching vk 0.85.0 from {api}/virtkit-dev/virtkit"),
        ] {
            assert!(events.contains(&want), "{want}: {events:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Several programs are fetched one after another from the latest release, pinned once;
    /// one the release does not publish fails on its own and the others are still held.
    #[tokio::test(flavor = "multi_thread")]
    async fn several_programs_are_fetched_from_one_release_and_fail_alone() {
        installed();
        let mut release = FakeRelease::new("v0.85.0", fake_vk("0.85.0"));
        let mut registry = fake_vk("0.85.0");
        registry.extend_from_slice(b"vk-registry\0");
        release.registry = Some(registry);
        let api = fake_github(release).await;
        let (hub, dir) = hub_fetching_from(&api, "several");
        let programs = [Program::Vk, Program::Gitlab, Program::Registry];
        let results = start(&hub, "uid 7", &programs, None)
            .unwrap()
            .await
            .unwrap();
        assert_eq!(results.len(), 3);
        assert!(results[0].as_ref().unwrap().row.is(Program::Vk));
        let err = results[1].as_ref().unwrap_err();
        assert!(
            format!("{err:#}").contains("publishes no vk-gitlab"),
            "{err:#}"
        );
        assert!(results[2].as_ref().unwrap().row.is(Program::Registry));
        let status = hub.fetches.status().unwrap();
        assert!(!status.running());
        let phases: Vec<_> = status.items.iter().map(|i| (i.program, &i.phase)).collect();
        assert!(
            matches!(
                phases.as_slice(),
                [
                    (Program::Vk, Phase::Done { version: a, .. }),
                    (Program::Gitlab, Phase::Failed { .. }),
                    (Program::Registry, Phase::Done { version: b, .. }),
                ] if a == "0.85.0" && b == "0.85.0"
            ),
            "{phases:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A `vk-registry` is fetched from the same release as its own asset, and held as a
    /// registry's release; a release publishing none is refused, saying so.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_registry_release_is_fetched_as_its_own_asset() {
        installed();
        let mut registry = fake_vk("0.85.0");
        registry.extend_from_slice(b"vk-registry\0");
        let mut release = FakeRelease::new("v0.85.0", fake_vk("0.85.0"));
        release.registry = Some(registry.clone());
        let api = fake_github(release).await;
        let (hub, dir) = hub_fetching_from(&api, "registry");
        let held = one(&hub, Program::Registry, None).await.unwrap();
        assert!(held.row.is(Program::Registry), "{held:?}");
        assert_eq!(
            held.sha256,
            vk_hub_proto::to_hex(&Sha256::digest(&registry))
        );
        let status = hub.fetches.status().unwrap();
        assert_eq!(status.items[0].program, Program::Registry);
        let vk = one(&hub, Program::Vk, None).await.unwrap();
        assert!(vk.row.is(Program::Vk), "{vk:?}");
        assert_eq!(hub.db.releases().unwrap().len(), 2);
        let events: Vec<String> = hub
            .db
            .audits(None, 10)
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .collect();
        let want =
            format!("uid 7 started fetching vk-registry latest from {api}/virtkit-dev/virtkit");
        assert!(events.contains(&want), "{events:?}");
        let _ = std::fs::remove_dir_all(&dir);

        let api = fake_github(FakeRelease::new("v0.85.0", fake_vk("0.85.0"))).await;
        let (hub, dir) = hub_fetching_from(&api, "no-registry");
        let err = one(&hub, Program::Registry, None).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("publishes no vk-registry"),
            "{err:#}"
        );
        let _ = std::fs::remove_dir_all(&dir);

        // A release publishing only a vk-registry has a latest version all the same.
        let mut release = FakeRelease::new("v0.86.0", Vec::new());
        release.registry = Some(fake_vk("0.86.0"));
        let api = fake_github(release).await;
        let (hub, dir) = hub_fetching_from(&api, "registry-only");
        assert_eq!(latest(&hub).await.unwrap(), "0.86.0");
        let held = one(&hub, Program::Registry, None).await.unwrap();
        assert_eq!(held.row.version, "0.86.0");
        let err = one(&hub, Program::Vk, None).await.unwrap_err();
        assert!(format!("{err:#}").contains("publishes no vk"), "{err:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A download that does not hash to its published digest, a binary that is not the
    /// version its tag says, and a version the repository does not have are each refused,
    /// audited, and leave nothing behind.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_mismatched_release_is_refused() {
        installed();
        let mut tampered = FakeRelease::new("v0.85.0", fake_vk("0.85.0"));
        tampered.sha256 = vk_hub_proto::to_hex(&Sha256::digest(b"something else"));
        let mislabelled = FakeRelease::new("v0.85.0", fake_vk("0.84.0"));
        for (case, release, asked, want) in [
            ("digest", tampered, None, "does not match the locked digest"),
            ("version", mislabelled, None, "appears nowhere in it"),
            (
                "missing",
                FakeRelease::new("v0.85.0", fake_vk("0.85.0")),
                Some("0.86.0"),
                "no release v0.86.0",
            ),
        ] {
            let api = fake_github(release).await;
            let (hub, dir) = hub_fetching_from(&api, case);
            let err = one(&hub, Program::Vk, asked.map(str::to_string))
                .await
                .unwrap_err();
            assert!(format!("{err:#}").contains(want), "{case}: {err:#}");
            assert!(hub.db.releases().unwrap().is_empty(), "{case}");
            if dir.join("releases").exists() {
                assert_nothing_staged(&dir);
            }
            let Phase::Failed { reason, .. } = hub.fetches.status().unwrap().items.remove(0).phase
            else {
                panic!("{case}: not failed");
            };
            assert!(reason.contains(want), "{case}: {reason}");
            let audit = hub.db.audits(None, 10).unwrap();
            assert!(
                audit
                    .iter()
                    .any(|r| r.event.starts_with("uid 7 failed to fetch vk")),
                "{case}: {audit:?}"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// A download that stalls is given up at the fetch's deadline, audited, and leaves
    /// nothing behind: not the staged file, nor `vk-selfupdate`'s own.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stalled_download_is_given_up_and_leaves_nothing_behind() {
        installed();
        let mut stalled = FakeRelease::new("v0.85.0", fake_vk("0.85.0"));
        stalled.stall = true;
        let api = fake_github(stalled).await;
        let (hub, dir) = hub_fetching_from(&api, "stall");
        let err = one(&hub, Program::Vk, None).await.unwrap_err();
        assert!(format!("{err:#}").contains("took longer than"), "{err:#}");
        assert!(hub.db.releases().unwrap().is_empty());
        assert_nothing_staged(&dir);
        assert!(matches!(
            hub.fetches.status().unwrap().items[0].phase,
            Phase::Failed { .. }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Asking which release is the latest again within [`CHECK_INTERVAL`] gets the last
    /// answer, or the last failure, without asking the repository.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_latest_release_is_asked_for_at_most_once_an_interval() {
        installed();
        let api = fake_github(FakeRelease::new("v0.85.0", fake_vk("0.85.0"))).await;
        let (hub, dir) = hub_fetching_from(&api, "check");
        assert_eq!(latest(&hub).await.unwrap(), "0.85.0");
        // Were it asked again, this would be the answer.
        hub.fetches.checked.lock().await.as_mut().unwrap().1 = Ok("0.84.0".into());
        assert_eq!(latest(&hub).await.unwrap(), "0.84.0");
        hub.fetches.checked.lock().await.as_mut().unwrap().1 = Err("refused".into());
        let err = latest(&hub).await.unwrap_err();
        assert!(format!("{err:#}").starts_with("refused (asked "), "{err:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// One fetch at a time, and none at all with fetching off.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_second_fetch_waits_for_the_first_and_none_runs_when_off() {
        installed();
        let api = fake_github(FakeRelease::new("v0.85.0", fake_vk("0.85.0"))).await;
        let (hub, dir) = hub_fetching_from(&api, "busy");
        let first = start(&hub, "uid 7", &[Program::Vk], None).unwrap();
        let second = start(&hub, "uid 7", &[Program::Vk], None);
        // Unless the first was already over.
        if !matches!(
            hub.fetches.status().unwrap().items[0].phase,
            Phase::Done { .. }
        ) {
            assert!(second.unwrap_err().is::<Busy>());
        }
        first.await.unwrap().pop().unwrap().unwrap();
        let off = Arc::new(
            Hub::new(Arc::new(Db::open_memory().unwrap()), None)
                .with_releases(dir.join("off"))
                .with_release_source(None),
        );
        let err = start(&off, "uid 7", &[Program::Vk], None).unwrap_err();
        assert!(format!("{err:#}").contains("off"), "{err:#}");
        assert!(latest(&off).await.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
