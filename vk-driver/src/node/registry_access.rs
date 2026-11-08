//! The node's own access to the registry the hub names it (`docs/registry-hub.md`, *4d: node
//! tokens*): what the hub last sent ([`vk_hub_proto::HubMsg::RegistryAccess`]), kept in
//! `<state_dir>/node/registry-access.json` (`0600`, replaced whole by rename) with the hub and
//! node ID it came from, so that a restarted node and every other `vk` on the host use it while
//! it is live, the hub reachable or not. It is bound to the registry's ID, URL and CA: a config
//! takes it only when its `[registry]` is the one the hub names, at that URL and pinning that
//! CA ([`Source`]). A clear, a new `join`, a permanent refusal or a change of the registry the
//! hub names removes it. Past its expiry it is an error, never a reason to go anonymous.

use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use vk_hub_proto::NodeRegistryAccess;

pub(crate) use super::state::Issuer;

const FILE: &str = "registry-access.json";

/// `registry-access.json`: the access, and the enrollment it was sent to.
#[derive(Clone, Serialize, Deserialize)]
struct Saved {
    hub: String,
    node_id: String,
    #[serde(flatten)]
    access: NodeRegistryAccess,
}

/// That `access` is one a node keeps: a registry ID, an origin with no path, a token, an expiry
/// after its issue.
fn check(access: &NodeRegistryAccess) -> Result<()> {
    if !vk_hub_proto::valid_id(&access.registry_id) {
        bail!("malformed registry ID");
    }
    let authority = access
        .origin
        .strip_prefix("https://")
        .or_else(|| access.origin.strip_prefix("http://"));
    if !authority.is_some_and(|a| {
        !a.is_empty() && !a.contains('/') && a.bytes().all(|b| b.is_ascii_graphic())
    }) {
        bail!("malformed registry URL");
    }
    if access
        .ca_sha256
        .as_ref()
        .is_some_and(|h| h.len() != 64 || vk_hub_proto::from_hex(h).is_none())
    {
        bail!("malformed CA digest");
    }
    let well_formed = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_graphic());
    if !well_formed(&access.token)
        || access
            .guest_token
            .as_deref()
            .is_some_and(|t| !well_formed(t))
    {
        bail!("malformed token");
    }
    if access.expires_at <= access.issued_at {
        bail!("access expiring before it is issued");
    }
    Ok(())
}

/// Keep `access`, sent by `issuer`, in the node dir `dir`, replacing what it held.
pub fn store(dir: &Path, issuer: &Issuer, access: &NodeRegistryAccess) -> Result<()> {
    check(access).context("the hub sent registry access the node cannot keep")?;
    let saved = Saved {
        hub: issuer.hub.clone(),
        node_id: issuer.node_id.clone(),
        access: access.clone(),
    };
    let json = serde_json::to_vec_pretty(&saved).context("encoding the registry access")?;
    let path = dir.join(FILE);
    vk_fs::write_atomic(&path, &json, 0o600).with_context(|| format!("writing {}", path.display()))
}

/// Drop the access kept in the node dir `dir`, if any.
pub fn clear(dir: &Path) -> Result<()> {
    let path = dir.join(FILE);
    match std::fs::remove_file(&path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(e).with_context(|| format!("removing {}", path.display()))
        }
        _ => Ok(()),
    }
}

/// The node's token for its registry, while live. Its `Debug` leaves the token out.
#[derive(Clone, PartialEq, Eq)]
pub struct NodeToken {
    pub registry_id: String,
    pub token: String,
    /// Seconds since the epoch.
    pub expires_at: u64,
}

impl std::fmt::Debug for NodeToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeToken")
            .field("registry_id", &self.registry_id)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// The access the node holds has expired: it has not heard from the hub in time to renew it.
#[derive(Debug)]
pub struct Expired {
    pub registry_id: String,
    pub expired_at: u64,
}

impl std::fmt::Display for Expired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "this node's registry credential for registry {} expired at {} (seconds since the \
             epoch); reconnect the node to its hub (`vk node run`) to renew it",
            self.registry_id, self.expired_at
        )
    }
}

impl std::error::Error for Expired {}

/// Where a config's `[registry]` finds the node's access, and what it must be bound to: the
/// hub and node of the host's enrollment, the registry's URL and its CA, as the config names
/// them. Read again whenever the file changed, so a long-lived reader sees a renewal.
#[derive(Clone)]
pub struct Source(Arc<Bound>);

/// What a [`Source`] is bound to, and the file as last read.
struct Bound {
    path: PathBuf,
    issuer: Issuer,
    origin: String,
    /// The CA the config pins, which the hub's settings name by its SHA-256
    /// ([`super::hub_settings::ca_file`]): `None` for the system's roots.
    ca_file: Option<PathBuf>,
    dir: PathBuf,
    cache: Mutex<Option<Cached>>,
}

/// The file's version, and what it held then.
type Cached = (FileKey, Option<Saved>);

impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Source")
            .field("path", &self.0.path)
            .field("origin", &self.0.origin)
            .finish_non_exhaustive()
    }
}

/// What tells one version of the file from the next: it is replaced by rename, so a new one is
/// a new inode.
#[derive(Clone, Copy, PartialEq, Eq)]
struct FileKey {
    dev: u64,
    ino: u64,
    mtime: i64,
    mtime_nsec: i64,
    size: u64,
}

impl Source {
    /// The access in the node dir `dir`, for a `[registry]` the hub named, reached at `origin`
    /// with its CA at `ca_file` (`None` for the system's roots), on a host enrolled by
    /// `issuer`.
    pub fn new(dir: &Path, issuer: Issuer, origin: String, ca_file: Option<PathBuf>) -> Self {
        Source(Arc::new(Bound {
            path: dir.join(FILE),
            issuer,
            origin,
            ca_file,
            dir: dir.to_path_buf(),
            cache: Mutex::default(),
        }))
    }

    /// The registry's origin (`<scheme>://<host>[:<port>]`) this access is for.
    pub fn origin(&self) -> &str {
        &self.0.origin
    }

    /// The CA the registry is trusted with there; `None` for the system's roots.
    pub fn ca_file(&self) -> Option<&Path> {
        self.0.ca_file.as_deref()
    }

    /// The node's live token at `now`: `None` when it holds none for this registry, at this
    /// URL with this CA, from this enrollment; [`Expired`] once the one it holds has expired.
    pub fn live(&self, now: u64) -> Result<Option<NodeToken>> {
        Ok(self.live_access(now)?.map(|access| NodeToken {
            registry_id: access.registry_id,
            token: access.token,
            expires_at: access.expires_at,
        }))
    }

    /// The token the node lends its runner's guests at `now`, as [`Source::live`] reads the
    /// node's own: `None` too when the hub granted guests nothing.
    pub fn live_guest(&self, now: u64) -> Result<Option<String>> {
        Ok(self.live_access(now)?.and_then(|access| access.guest_token))
    }

    /// The access held at `now`, as [`Source::live`] takes it.
    fn live_access(&self, now: u64) -> Result<Option<NodeRegistryAccess>> {
        let bound = &*self.0;
        let Some(saved) = self.read()? else {
            return Ok(None);
        };
        let access = &saved.access;
        // The hub's settings pin a CA in the node dir under a name its digest gives.
        let ca_file = access
            .ca_sha256
            .as_deref()
            .map(|h| super::hub_settings::ca_file(&bound.dir, h));
        if (saved.hub.as_str(), saved.node_id.as_str())
            != (bound.issuer.hub.as_str(), bound.issuer.node_id.as_str())
            || access.origin != bound.origin
            || ca_file.as_deref().map(Path::file_name)
                != bound.ca_file.as_deref().map(Path::file_name)
        {
            return Ok(None);
        }
        if now >= access.expires_at {
            return Err(Expired {
                registry_id: access.registry_id.clone(),
                expired_at: access.expires_at,
            }
            .into());
        }
        Ok(Some(saved.access))
    }

    /// The file as it is now, parsed again only when it changed.
    fn read(&self) -> Result<Option<Saved>> {
        let bound = &*self.0;
        let file = match std::fs::File::options()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&bound.path)
        {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            file => file.with_context(|| format!("opening {}", bound.path.display()))?,
        };
        let meta = file
            .metadata()
            .with_context(|| format!("statting {}", bound.path.display()))?;
        let key = FileKey {
            dev: meta.dev(),
            ino: meta.ino(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            size: meta.size(),
        };
        let mut cache = bound.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((cached, saved)) = cache.as_ref()
            && *cached == key
        {
            return Ok(saved.clone());
        }
        let saved = parse(file, &bound.path)?;
        *cache = Some((key, saved.clone()));
        Ok(saved)
    }
}

/// The access `file`, read at `path`: `None` when it is not one this node kept.
fn parse(file: std::fs::File, path: &Path) -> Result<Option<Saved>> {
    use std::io::Read;
    let mut text = Vec::new();
    file.take(vk_peer::net::MAX_INPUT)
        .read_to_end(&mut text)
        .with_context(|| format!("reading {}", path.display()))?;
    let saved: Saved =
        serde_json::from_slice(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(check(&saved.access).is_ok().then_some(saved))
}

/// The source of the node's access for `cfg`, whose `[registry]` the hub's settings name: on
/// a host enrolled under its state dir, for the registry's URL and CA as the config has them.
/// `None` for a host not enrolled, as far as this user can tell, or a registry with no URL.
pub fn source(cfg: &crate::config::Config) -> Option<Source> {
    let dir = cfg.state_dir().join("node");
    let enrollment = super::read_enrollment(&dir).ok()?;
    let registry = cfg.registry.as_ref()?;
    let (origin, _) = registry.base_url()?;
    let issuer = Issuer {
        hub: enrollment.hub,
        node_id: enrollment.node_id,
    };
    Some(Source::new(&dir, issuer, origin, registry.ca_file.clone()))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    /// A source over the node dir `dir` holding `token` until `expires_at` for
    /// `https://reg.example.com` (a `[registry]` of `reg.example.com/…`), replacing what it
    /// held: what another module's test reads the node's token from.
    pub(crate) fn held(dir: &Path, token: &str, expires_at: u64) -> Source {
        store(dir, &issuer("n1"), &access(token, expires_at, None)).unwrap();
        Source::new(dir, issuer("n1"), ORIGIN.into(), None)
    }

    /// [`held`], with `guest` the token for the node's runner's guests, at `origin`.
    pub(crate) fn held_for_guests(
        dir: &Path,
        origin: &str,
        guest: Option<&str>,
        expires_at: u64,
    ) -> Source {
        let access = NodeRegistryAccess {
            origin: origin.into(),
            guest_token: guest.map(String::from),
            ..access("vkt_node", expires_at, None)
        };
        store(dir, &issuer("n1"), &access).unwrap();
        Source::new(dir, issuer("n1"), origin.into(), None)
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("vk-registry-access-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    pub(crate) fn issuer(node_id: &str) -> Issuer {
        Issuer {
            hub: "https://hub.example.com".into(),
            node_id: node_id.into(),
        }
    }

    const ORIGIN: &str = "https://reg.example.com";

    fn access(token: &str, expires_at: u64, ca: Option<&str>) -> NodeRegistryAccess {
        NodeRegistryAccess {
            registry_id: "ab".repeat(16),
            origin: ORIGIN.into(),
            ca_sha256: ca.map(String::from),
            generation: 1,
            issued_at: expires_at.saturating_sub(3600),
            expires_at,
            grants: Vec::new(),
            token: token.into(),
            guest_token: None,
            guest_grants: Vec::new(),
        }
    }

    /// Kept `0600`, read while live, replaced whole and seen by a reader that read the one
    /// before, an error once expired, and gone once cleared.
    #[test]
    fn access_is_kept_private_renewed_for_readers_and_refused_once_expired() {
        let dir = scratch("kept");
        let source = Source::new(&dir, issuer("n1"), ORIGIN.into(), None);
        assert_eq!(source.live(10).unwrap(), None);
        store(&dir, &issuer("n1"), &access("vkt_one", 5000, None)).unwrap();
        let mode = std::fs::metadata(dir.join(FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let live = source.live(4000).unwrap().unwrap();
        assert_eq!(live.token, "vkt_one");
        assert!(!format!("{live:?} {source:?}").contains("vkt_"));
        assert_eq!(source.live_guest(4000).unwrap(), None);
        // Renewed: the same reader sees the new token, and its guests theirs.
        let renewed = NodeRegistryAccess {
            guest_token: Some("vkt_guest".into()),
            ..access("vkt_two", 9000, None)
        };
        store(&dir, &issuer("n1"), &renewed).unwrap();
        assert_eq!(source.live(8000).unwrap().unwrap().token, "vkt_two");
        assert_eq!(source.live_guest(8000).unwrap().unwrap(), "vkt_guest");
        assert!(source.live_guest(9000).unwrap_err().is::<Expired>());
        // Expired: an error naming what to do, never `None`.
        let e = source.live(9000).unwrap_err();
        assert!(e.is::<Expired>(), "{e:#}");
        assert!(format!("{e:#}").contains("reconnect the node"));
        // A restarted reader reads it from the file alone.
        let fresh = Source::new(&dir, issuer("n1"), ORIGIN.into(), None);
        assert_eq!(fresh.live(8000).unwrap().unwrap().token, "vkt_two");
        clear(&dir).unwrap();
        clear(&dir).unwrap();
        assert_eq!(source.live(8000).unwrap(), None);
    }

    /// Access kept for another enrollment, registry URL or CA is not this config's.
    #[test]
    fn access_bound_elsewhere_is_none() {
        let dir = scratch("bound");
        let ca = "cd".repeat(32);
        store(&dir, &issuer("n1"), &access("vkt_x", 5000, Some(&ca))).unwrap();
        let ca_file = Some(super::super::hub_settings::ca_file(&dir, &ca));
        let ok = Source::new(&dir, issuer("n1"), ORIGIN.into(), ca_file.clone());
        assert!(ok.live(10).unwrap().is_some());
        for other in [
            Source::new(&dir, issuer("n2"), ORIGIN.into(), ca_file.clone()),
            Source::new(
                &dir,
                issuer("n1"),
                "https://other.example.com".into(),
                ca_file,
            ),
            Source::new(&dir, issuer("n1"), ORIGIN.into(), None),
            Source::new(
                &dir,
                issuer("n1"),
                ORIGIN.into(),
                Some(super::super::hub_settings::ca_file(&dir, &"ef".repeat(32))),
            ),
        ] {
            assert_eq!(other.live(10).unwrap(), None);
        }
    }

    #[test]
    fn malformed_access_is_not_kept() {
        let dir = scratch("malformed");
        let good = access("vkt_x", 5000, None);
        for bad in [
            NodeRegistryAccess {
                registry_id: "../x".into(),
                ..good.clone()
            },
            NodeRegistryAccess {
                origin: "https://reg.example.com/path".into(),
                ..good.clone()
            },
            NodeRegistryAccess {
                origin: "ftp://reg".into(),
                ..good.clone()
            },
            NodeRegistryAccess {
                token: "a b".into(),
                ..good.clone()
            },
            NodeRegistryAccess {
                guest_token: Some(String::new()),
                ..good.clone()
            },
            NodeRegistryAccess {
                ca_sha256: Some("zz".into()),
                ..good.clone()
            },
            NodeRegistryAccess {
                issued_at: 5000,
                ..good.clone()
            },
        ] {
            assert!(store(&dir, &issuer("n1"), &bad).is_err());
        }
        assert!(!dir.join(FILE).exists());
    }
}
