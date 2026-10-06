//! `vk-hub release fetch`: the hub downloads the `vk` of a virtkit release published on GitHub
//! and holds it as if `release add` had been given it.
//!
//! The release is resolved, and its `vk` downloaded and checked, by `vk-selfupdate` — the code
//! `vk update` replaces a binary with — so a fetch passes the same gates an update does short
//! of running the binary: the API and the assets over https, no redirect leaving it
//! ([`vk_selfupdate::client`]), the release's `vk` asset at most 512 MiB, and the bytes
//! hashing to the sha256 the release publishes beside them in `vk.sha256`. The tag must be
//! the version asked for, and [`releases::adopt`] then checks what every release added is
//! checked for: an x86-64 ELF holding that version as a string of its own. The hub never runs
//! it ([`releases`]); each node's `--version` is the smoke test.
//!
//! What this proves is that the hub holds the bytes the repository published as that version,
//! intact: not who built them. A release whose binary and sidecar were replaced together — a
//! compromised repository or account — passes. A release key's signature is what a node can
//! trust instead: a fetched release carries none, as official releases are not signed yet, so
//! a node that requires one refuses it, as it refuses an unsigned `release add`.
//!
//! One fetch runs at a time, in the background, and is audited. Asking which release is the
//! latest is one request at a time too, and answered from the last answer for
//! [`CHECK_INTERVAL`]: the API allows an unauthenticated caller 60 requests an hour.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::server::Hub;
use crate::store::Release;
use crate::{local, releases};

/// What `release_repository` is unless the config says otherwise.
pub const DEFAULT_SOURCE: &str = "https://github.com/virtkit-dev/virtkit";

/// The release asset fetched: `vk`, the static linux-x86_64 binary.
const ASSET: &str = "vk";

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

/// A fetch: what was asked for, by whom, and how far it got.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchStatus {
    /// The version asked for; `None` for the latest.
    pub asked: Option<String>,
    pub by: String,
    pub started_at: u64,
    pub phase: Phase,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum Phase {
    /// Asking the repository which release that is.
    Resolving,
    /// Downloading and checking its `vk`.
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
        matches!(self, Phase::Resolving | Phase::Downloading { .. })
    }
}

/// What the hub keeps of fetching: where from, and the latest fetch and check.
pub struct Fetches {
    /// `None`: fetching is off.
    source: Option<Source>,
    status: Mutex<Option<FetchStatus>>,
    /// When the repository was last asked which release is the latest, and the version it
    /// named or why asking failed; held while asking, so one request is out at a time.
    checked: tokio::sync::Mutex<Option<(tokio::time::Instant, Result<String, String>)>>,
}

impl Fetches {
    pub fn new(source: Option<Source>) -> Self {
        Fetches {
            source,
            status: Mutex::new(None),
            checked: tokio::sync::Mutex::new(None),
        }
    }

    pub fn source(&self) -> Option<&Source> {
        self.source.as_ref()
    }

    /// The latest fetch, if any since the hub started.
    #[cfg(test)]
    pub fn status(&self) -> Option<FetchStatus> {
        lock(&self.status).clone()
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

/// Start fetching `version`'s `vk` — the latest release's for `None` — as `actor`, in the
/// background; what it comes to resolves the handle.
pub fn start(
    hub: &Arc<Hub>,
    actor: &str,
    version: Option<String>,
) -> Result<tokio::task::JoinHandle<Result<Release>>> {
    let Some(source) = hub.fetches.source().cloned() else {
        bail!("fetching releases is off: the hub's release_repository is \"none\"");
    };
    hub.releases_dir()?;
    let what = version.as_deref().unwrap_or("latest").to_string();
    {
        let mut status = lock(&hub.fetches.status);
        if status.as_ref().is_some_and(|s| s.phase.running()) {
            return Err(Busy.into());
        }
        *status = Some(FetchStatus {
            asked: version.clone(),
            by: actor.to_string(),
            started_at: crate::now_secs(),
            phase: Phase::Resolving,
        });
    }
    let started = format!("{actor} started fetching vk {what} from {}", source.url());
    eprintln!("vk-hub: {started}");
    hub.touch();
    let (hub, actor) = (hub.clone(), actor.to_string());
    Ok(tokio::spawn(async move {
        let result = match local::audit(&hub, &actor, started).await {
            Ok(()) => fetch(&hub, &actor, &source, version.as_deref()).await,
            Err(e) => Err(e),
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
                    "{actor} failed to fetch vk {what} from {}: {reason}",
                    source.url()
                );
                eprintln!("vk-hub: {event}");
                if let Err(e) = local::audit(&hub, &actor, event).await {
                    eprintln!("vk-hub: writing the audit log: {e:#}");
                }
                Phase::Failed { reason, at: now }
            }
        };
        if let Some(status) = lock(&hub.fetches.status).as_mut() {
            status.phase = phase;
        }
        hub.touch();
        result
    }))
}

/// Set the running fetch's phase.
fn phase(hub: &Hub, phase: Phase) {
    if let Some(status) = lock(&hub.fetches.status).as_mut() {
        status.phase = phase;
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
    actor: &str,
    source: &Source,
    version: Option<&str>,
) -> Result<Release> {
    let deadline = tokio::time::Instant::now() + FETCH_TIMEOUT;
    let client = vk_selfupdate::client(concat!("vk-hub/", env!("CARGO_PKG_VERSION")))?;
    let resolved = within(
        deadline,
        vk_selfupdate::artifacts_in(&client, &source.repo, version, &[ASSET]),
    )
    .await?;
    let Some(artifact) = resolved.artifacts.into_iter().find(|a| a.name == ASSET) else {
        bail!(
            "release {} publishes no {ASSET}",
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
    phase(
        hub,
        Phase::Downloading {
            version: found.clone(),
        },
    );
    let (held, sha256, version) = (hub.clone(), artifact.sha256.clone(), found.clone());
    let holding = tokio::task::spawn_blocking(move || holding(&held, sha256, &version))
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
    .with_context(|| format!("downloading vk {found}"))?;
    let (held, actor, version) = (hub.clone(), actor.to_string(), found.clone());
    let release =
        tokio::task::spawn_blocking(move || releases::adopt(&held, &actor, staged, &version, None))
            .await
            .context("adding the release")??;
    // `vk-selfupdate` checked the download against the digest; the same file was read again.
    if release.sha256 != artifact.sha256 {
        bail!("the file held changed after it was checked against the published digest");
    }
    Ok(release)
}

/// Release `sha256` if it is held already as `version`, its file intact: nothing to download.
/// Otherwise a name to download it to; a missing or wrong-size file is downloaded again, and
/// `adopt` restores it.
fn holding(hub: &Hub, sha256: String, version: &str) -> Result<Holding> {
    let held = releases::path(hub.releases_dir()?, &sha256);
    if let Some(row) = hub.db.release(&sha256)?
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

/// The latest release the repository names.
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
    answer
}

/// Ask `source` which release is the latest.
async fn ask_latest(source: &Source) -> Result<String> {
    let client = vk_selfupdate::client(concat!("vk-hub/", env!("CARGO_PKG_VERSION")))?;
    let resolved = tokio::time::timeout(
        CHECK_TIMEOUT,
        vk_selfupdate::artifacts_in(&client, &source.repo, None, &[ASSET]),
    )
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "{} did not answer within {}",
            source.url(),
            crate::human_duration(CHECK_TIMEOUT)
        )
    })??;
    if resolved.artifacts.is_empty() {
        bail!(
            "the latest release, {}, publishes no {ASSET}",
            vk_hub_proto::display_safe(&resolved.version)
        );
    }
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
        /// The `vk` asset's bytes.
        pub vk: Vec<u8>,
        /// The digest its sidecar publishes; `vk`'s own unless a test says otherwise.
        pub sha256: String,
        /// The download sends half of `vk`, then nothing more.
        pub stall: bool,
    }

    impl FakeRelease {
        pub fn new(tag: &str, vk: Vec<u8>) -> Self {
            let sha256 = vk_hub_proto::to_hex(&Sha256::digest(&vk));
            FakeRelease {
                tag: tag.into(),
                vk,
                sha256,
                stall: false,
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
        if path == format!("{repo}/latest") || path == format!("{repo}/tags/{}", r.tag) {
            let sidecar = format!("{}  vk\n", r.sha256);
            let json = format!(
                r#"{{"tag_name":"{tag}","assets":[
                    {{"name":"vk","browser_download_url":"http://{addr}/dl/vk","size":{size}}},
                    {{"name":"vk.sha256","browser_download_url":"http://{addr}/dl/vk.sha256","size":{sidecar_size}}}]}}"#,
                tag = r.tag,
                size = r.vk.len(),
                sidecar_size = sidecar.len(),
            );
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
        let release = start(&hub, "uid 7", None).unwrap().await.unwrap().unwrap();
        assert_eq!(release.row.version, "0.85.0");
        assert_eq!(release.row.signature, None);
        assert_eq!(release.sha256, vk_hub_proto::to_hex(&Sha256::digest(&bin)));
        let held = std::fs::read(releases::path(&dir.join("releases"), &release.sha256)).unwrap();
        assert_eq!(held, bin);
        assert_nothing_staged(&dir);
        assert!(matches!(
            hub.fetches.status().unwrap().phase,
            Phase::Done { .. }
        ));
        let again = start(&hub, "uid 7", Some("0.85.0".into()))
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(again, release);
        // A held release whose file went missing is downloaded again, restoring it.
        std::fs::remove_file(releases::path(&dir.join("releases"), &release.sha256)).unwrap();
        let restored = start(&hub, "uid 7", None).unwrap().await.unwrap().unwrap();
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
            let err = start(&hub, "uid 7", asked.map(str::to_string))
                .unwrap()
                .await
                .unwrap()
                .unwrap_err();
            assert!(format!("{err:#}").contains(want), "{case}: {err:#}");
            assert!(hub.db.releases().unwrap().is_empty(), "{case}");
            if dir.join("releases").exists() {
                assert_nothing_staged(&dir);
            }
            let Phase::Failed { reason, .. } = hub.fetches.status().unwrap().phase else {
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
        let err = start(&hub, "uid 7", None)
            .unwrap()
            .await
            .unwrap()
            .unwrap_err();
        assert!(format!("{err:#}").contains("took longer than"), "{err:#}");
        assert!(hub.db.releases().unwrap().is_empty());
        assert_nothing_staged(&dir);
        assert!(matches!(
            hub.fetches.status().unwrap().phase,
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
        let first = start(&hub, "uid 7", None).unwrap();
        let second = start(&hub, "uid 7", None);
        // Unless the first was already over.
        if !matches!(hub.fetches.status().unwrap().phase, Phase::Done { .. }) {
            assert!(second.unwrap_err().is::<Busy>());
        }
        first.await.unwrap().unwrap();
        let off = Arc::new(
            Hub::new(Arc::new(Db::open_memory().unwrap()), None)
                .with_releases(dir.join("off"))
                .with_release_source(None),
        );
        let err = start(&off, "uid 7", None).unwrap_err();
        assert!(format!("{err:#}").contains("off"), "{err:#}");
        assert!(latest(&off).await.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
