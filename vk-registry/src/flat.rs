//! Prefixes bound to flat stores (`[[flat]]`): the plain files below `files/<prefix>/` live
//! in a [`FlatStore`] at `<store root>/flat/<prefix with / as +>/` instead of the tag store.
//! A key is the decoded path below `files/`, such as `sccache/a/b/c/<hash>`. `/s3/` reads
//! and writes it, and `/files/` reads and deletes it, under the grants of its parent
//! repository, as [`crate::objects`] authorizes a tagged object. `/files/` takes no `PUT`
//! there, and `/files/sha256/<hex>`, `/v2/` and `/browse` do not see flat objects.
//!
//! A flat area has no directories, so `a/b` and `a/b/c` can both be objects. Its objects
//! are stored verbatim and served without `ETag` or `Last-Modified`: their mtime records
//! use, not change. Tags left under a newly bound prefix are no longer served there and
//! expire under gc's retention.
//!
//! All [`crate::Store`]s in a process share one [`FlatStore`] per area. Serving sets its cap,
//! eviction target and durability at bind time. Collecting sets them on first open.
//! Inspection preserves an open store's policy.

use std::collections::HashMap;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, Weak};

use anyhow::{Context, Result, bail};
use hyper::body::Incoming;
use hyper::header::{
    ACCEPT_RANGES, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, HeaderValue,
    X_CONTENT_TYPE_OPTIONS,
};
use hyper::{Request, Response, StatusCode};
use tokio::io::AsyncWriteExt;

use crate::flatstore::{EvictReport, FlatStore, Options, Policy, Usage};
use crate::objects::{self, MAX_OBJECT, Part};
use crate::staging::{DrainError, drain_into};
use crate::{Authz, Body, accounts, error_response};

/// The directory under the store root that holds the areas.
const AREAS_DIR: &str = "flat";

/// Marks a binding with no size limit. An uncapped store leaves eviction to a capped peer.
pub const UNCAPPED: u64 = u64::MAX;

/// The default of [`FlatBinding::evict_to`].
pub const DEFAULT_EVICT_TO: f64 = 0.9;

/// A prefix bound to a flat store, with that store's settings.
#[derive(Clone, Debug, PartialEq)]
pub struct FlatBinding {
    /// A repository prefix below `files/`: `sccache` binds `files/sccache/…`.
    pub prefix: String,
    /// The area's size cap in bytes.
    pub cap: u64,
    /// Evict down to this fraction of the cap once over it.
    pub evict_to: f64,
    /// Sync each object's bytes before publishing it.
    pub durable: bool,
}

impl FlatBinding {
    /// `prefix` capped at `cap` bytes, with the default settings.
    pub fn new(prefix: &str, cap: u64) -> FlatBinding {
        FlatBinding {
            prefix: prefix.to_string(),
            cap,
            evict_to: DEFAULT_EVICT_TO,
            durable: false,
        }
    }

    /// A binding the hub asks for ([`vk_hub_proto::registry::DesiredState::flat`]).
    pub fn of_setting(s: &vk_hub_proto::registry::FlatSetting) -> FlatBinding {
        FlatBinding {
            prefix: s.prefix.clone(),
            cap: s.cap,
            evict_to: s
                .evict_to_percent
                .map_or(DEFAULT_EVICT_TO, |p| f64::from(p) / 100.0),
            durable: s.durable.unwrap_or(false),
        }
    }

    /// The area's directory name: `+` is in no repository name component.
    fn dir_name(&self) -> String {
        self.prefix.replace('/', "+")
    }
}

/// Require disjoint, servable prefixes outside `sha256`. `files/<prefix>` must fit the
/// prefix length limit and leave room for a leaf within the repository component limit.
/// Each cap must be positive and `evict_to` within `0..=1`.
pub fn check(bindings: &[FlatBinding]) -> Result<()> {
    for (i, b) in bindings.iter().enumerate() {
        let p = &b.prefix;
        if !vk_hub_proto::registry::valid_flat_prefix(p) {
            bail!(
                "[[flat]] prefix = {p:?} is not a directory below files/ (lowercase \
                 components, at most {} in all with files/ and a leaf, not under sha256 or \
                 files)",
                crate::MAX_NAME_SEGMENTS
            );
        }
        if b.cap == 0 {
            bail!("[[flat]] prefix = {p:?} has a cap of 0 bytes");
        }
        if !(0.0..=1.0).contains(&b.evict_to) {
            bail!(
                "[[flat]] prefix = {p:?} has evict_to = {}, not within 0..=1",
                b.evict_to
            );
        }
        if let Some(other) = bindings[..i]
            .iter()
            .find(|o| vk_hub_proto::registry::flat_prefixes_overlap(p, &o.prefix))
        {
            bail!(
                "[[flat]] prefix = {p:?} overlaps prefix = {:?}: an object can live in one \
                 area only",
                other.prefix
            );
        }
    }
    Ok(())
}

pub use vk_hub_proto::registry::parse_size;

/// How a process uses the areas it binds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Use {
    /// Open or create every area at binding and enforce its cap in the background.
    Serve,
    /// Open existing areas on demand for [`Areas::evict`]. Enforce the cap in the
    /// background while open.
    Collect,
    /// Open existing areas on demand to report usage without evicting objects.
    Inspect,
}

/// The areas a [`crate::Store`] binds.
pub struct Areas {
    areas: Vec<Area>,
}

/// One bound prefix and its store, once opened.
pub(crate) struct Area {
    binding: FlatBinding,
    /// The prefix's components.
    segs: Vec<String>,
    root: PathBuf,
    usage: Use,
    store: Mutex<Option<Arc<FlatStore>>>,
}

/// Usage and size cap for one bound prefix.
#[derive(Debug)]
pub struct AreaUsage {
    pub prefix: String,
    pub cap: u64,
    /// `None` while the area does not exist.
    pub usage: Result<Option<Usage>>,
}

/// What evicting an area did.
#[derive(Debug)]
pub struct Evicted {
    pub prefix: String,
    pub cap: u64,
    pub outcome: Result<Eviction>,
}

/// An area's eviction pass, or why there was none.
#[derive(Debug)]
pub enum Eviction {
    /// The area does not exist yet.
    Absent,
    /// Another process holds `evict.lock`, or this instance opened the area for inspection.
    Elsewhere,
    Done(EvictReport),
}

impl Areas {
    /// No areas.
    pub(crate) fn none() -> Areas {
        Areas { areas: Vec::new() }
    }

    /// Bind `bindings` under `store_root`, which must exist. [`Use::Serve`] opens every area.
    pub(crate) fn new(store_root: &Path, bindings: Vec<FlatBinding>, usage: Use) -> Result<Areas> {
        check(&bindings)?;
        // Path aliases must share the same area instances.
        let base = std::fs::canonicalize(store_root)
            .with_context(|| format!("resolving {}", store_root.display()))?
            .join(AREAS_DIR);
        let areas = Areas {
            areas: bindings
                .into_iter()
                .map(|binding| Area {
                    segs: binding.prefix.split('/').map(str::to_string).collect(),
                    root: base.join(binding.dir_name()),
                    binding,
                    usage,
                    store: Mutex::new(None),
                })
                .collect(),
        };
        if usage == Use::Serve {
            // Open every area, a new one uncapped, before giving any store its policy. An open
            // failure leaves every store under its previous cap, and a new one under none.
            for area in &areas.areas {
                area.open(false)?;
            }
            for area in &areas.areas {
                area.apply()?;
            }
        }
        Ok(areas)
    }

    pub fn is_empty(&self) -> bool {
        self.areas.is_empty()
    }

    /// Find the area whose prefix is a strict ancestor of the object path `segs`.
    pub(crate) fn find(&self, segs: &[String]) -> Option<&Area> {
        self.areas
            .iter()
            .find(|a| segs.len() > a.segs.len() && segs.starts_with(&a.segs))
    }

    /// Count usage in every area, loading all shards and refreshing missing or stale stats.
    pub fn usage(&self) -> Vec<AreaUsage> {
        self.areas
            .iter()
            .map(|a| {
                let store = a.store();
                AreaUsage {
                    prefix: a.binding.prefix.clone(),
                    cap: a.cap(&store),
                    usage: store.and_then(|s| s.map(|s| s.usage()).transpose()),
                }
            })
            .collect()
    }

    /// Run an eviction pass on each area this process can evict, which also reaps abandoned
    /// uploads. Skip areas bound for [`Use::Inspect`].
    pub fn evict(&self) -> Vec<Evicted> {
        self.areas
            .iter()
            .map(|a| {
                let store = a.store();
                Evicted {
                    prefix: a.binding.prefix.clone(),
                    cap: a.cap(&store),
                    outcome: store.and_then(|s| {
                        let Some(s) = s else {
                            return Ok(Eviction::Absent);
                        };
                        if a.usage == Use::Inspect {
                            return Ok(Eviction::Elsewhere);
                        }
                        Ok(s.evict()?.map_or(Eviction::Elsewhere, Eviction::Done))
                    }),
                }
            })
            .collect()
    }
}

impl Area {
    /// The area's store: opened by [`Use::Serve`] at binding, otherwise on first use and
    /// only if it exists.
    fn store(&self) -> Result<Option<Arc<FlatStore>>> {
        self.open(self.usage != Use::Inspect)
    }

    /// As [`Area::store`]. On this binding's first open, `set` applies its policy to an
    /// existing instance.
    fn open(&self, set: bool) -> Result<Option<Arc<FlatStore>>> {
        let mut held = self.store.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(s) = &*held {
            return Ok(Some(Arc::clone(s)));
        }
        if self.usage != Use::Serve {
            match std::fs::symlink_metadata(&self.root) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e).with_context(|| format!("stat {}", self.root.display())),
            }
        }
        let store = shared(&self.root, self.policy(), set)
            .with_context(|| format!("opening the flat store of {}", self.binding.prefix))?;
        *held = Some(Arc::clone(&store));
        Ok(Some(store))
    }

    /// Inspection opens new instances without a cap, as does an [`UNCAPPED`] binding.
    fn policy(&self) -> Policy {
        let b = &self.binding;
        Policy {
            cap: (self.usage != Use::Inspect && b.cap != UNCAPPED).then_some(b.cap),
            evict_to: b.evict_to,
            durable: b.durable,
        }
    }

    /// Apply the binding's policy to its open store.
    fn apply(&self) -> Result<()> {
        let held = self.store.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(s) = &*held
            && self.usage != Use::Inspect
            && s.policy() != self.policy()
        {
            s.set_policy(self.policy())?;
        }
        Ok(())
    }

    /// Report the open store's current cap, which another binding in this process can change.
    /// For an uncapped store, inspection reports the binding's cap and other uses report
    /// [`UNCAPPED`]. If the store is absent or failed to open, report the binding's cap.
    fn cap(&self, store: &Result<Option<Arc<FlatStore>>>) -> u64 {
        match store {
            Ok(Some(s)) => match s.policy().cap {
                Some(cap) => cap,
                None if self.usage == Use::Inspect => self.binding.cap,
                None => UNCAPPED,
            },
            _ => self.binding.cap,
        }
    }

    /// The area's store for a request: [`Use::Serve`] opened it.
    fn serving(&self) -> Result<Arc<FlatStore>> {
        self.store()?
            .with_context(|| format!("the flat store of {} is not open", self.binding.prefix))
    }
}

/// Share one instance per `root` in this process. Existing instances take `policy` only when
/// `set`; new ones use it, but for its cap when not `set`.
fn shared(root: &Path, policy: Policy, set: bool) -> Result<Arc<FlatStore>> {
    static OPEN: Mutex<Option<HashMap<PathBuf, Weak<FlatStore>>>> = Mutex::new(None);
    let mut open = OPEN.lock().unwrap_or_else(PoisonError::into_inner);
    let open = open.get_or_insert_with(HashMap::new);
    open.retain(|_, w| w.strong_count() > 0);
    if let Some(store) = open.get(root).and_then(Weak::upgrade) {
        if set && store.policy() != policy {
            store.set_policy(policy)?;
        }
        return Ok(store);
    }
    let store = Arc::new(FlatStore::open(
        root,
        Options {
            cap: policy.cap.filter(|_| set),
            evict_to: policy.evict_to,
            durable: policy.durable,
            ..Options::default()
        },
    )?);
    open.insert(root.to_path_buf(), Arc::downgrade(&store));
    Ok(store)
}

/// The object key of `segs`, a path below `files/`.
fn key(segs: &[String]) -> String {
    segs.join("/")
}

/// The repository whose grants cover the object at `segs`: its parent.
fn parent(segs: &[String]) -> String {
    let mut name = String::from(vk_hub_proto::token::FILES_REPO);
    for s in &segs[..segs.len() - 1] {
        name.push('/');
        name.push_str(s);
    }
    name
}

fn allowed(authz: &Authz<'_>, action: accounts::Action, repo: &str) -> bool {
    crate::authorize_or_forbidden(authz, action, repo).is_none()
}

/// After admission, `GET` and `HEAD` return 404 for a missing object, a trailing slash,
/// or no read access to the parent. Single ranges follow [`crate::objects::get`].
/// Both methods attempt to refresh mtime when its age reaches [`Options::refresh`].
pub(crate) async fn get(
    area: &Area,
    authz: &Authz<'_>,
    segs: Vec<String>,
    trailing_slash: bool,
    href: &str,
    head: bool,
    range: Option<String>,
) -> Result<Response<Body>> {
    if trailing_slash || !allowed(authz, accounts::Action::Read, &parent(&segs)) {
        return Ok(objects::not_found(href));
    }
    let store = area.serving()?;
    let href = href.to_string();
    tokio::task::spawn_blocking(move || {
        let Some(obj) = store.get(key(&segs).as_bytes())? else {
            return Ok(objects::not_found(&href));
        };
        serve(obj, head, range.as_deref(), &href)
    })
    .await
    .context("a flat read panicked")?
}

/// The response serving `obj`, whole or the part `range` asks for.
fn serve(
    obj: crate::flatstore::Object,
    head: bool,
    range: Option<&str>,
    href: &str,
) -> Result<Response<Body>> {
    let mut file = obj.file;
    let len = obj.meta.size;
    let (status, first, count) = match range.map_or(Part::Whole, |r| objects::part(r, len)) {
        Part::Whole => (StatusCode::OK, 0, len),
        Part::Bytes(first, last) => (StatusCode::PARTIAL_CONTENT, first, last - first + 1),
        Part::Unsatisfiable => return Ok(objects::unsatisfiable(len)),
    };
    let mut builder = Response::builder()
        .status(status)
        .header(X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(CONTENT_TYPE, "application/octet-stream")
        // Prevent uploaded content from rendering on the `/browse` origin.
        .header(CONTENT_DISPOSITION, "attachment")
        .header(ACCEPT_RANGES, "bytes")
        .header(CONTENT_LENGTH, count.to_string());
    if status == StatusCode::PARTIAL_CONTENT {
        let last = first + count - 1;
        builder = builder.header(
            CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes {first}-{last}/{len}"))?,
        );
    }
    if head {
        return builder
            .body(crate::body_of(bytes::Bytes::new()))
            .map_err(Into::into);
    }
    file.seek(SeekFrom::Start(first))
        .with_context(|| format!("seeking in {href}"))?;
    builder
        .body(crate::stream_body(file.take(count), href))
        .map_err(Into::into)
}

/// Stream a whole-object replacement after the route authorizes writes to the parent.
/// Return 201 or 204 on success, or 405 for a trailing slash. Apply the size cap from
/// [`crate::objects::put`] and verify the SHA-256 when `expected` is supplied.
pub(crate) async fn put(
    area: &Area,
    segs: Vec<String>,
    trailing_slash: bool,
    href: &str,
    expected: Option<String>,
    req: Request<Incoming>,
) -> Result<Response<Body>> {
    if objects::declared_over_cap(&req) {
        return Ok(objects::too_big(href));
    }
    if trailing_slash {
        return objects::drain_then(req, objects::not_an_object(href), href).await;
    }
    let store = area.serving()?;
    let upload = store.upload()?;
    let mut file = tokio::fs::File::from_std(upload.writer()?);
    let written = drain_into(&mut file, req.into_body(), MAX_OBJECT).await;
    let flushed = file
        .flush()
        .await
        .map_err(|e| DrainError::Failed(anyhow::Error::from(e).context("writing an object")));
    drop(file);
    let hex = match written.and_then(|w| flushed.map(|()| w)) {
        Ok((_, hex)) => hex,
        Err(DrainError::OverCap) => return Ok(objects::too_big(href)),
        Err(DrainError::Failed(e)) => return Err(e),
    };
    if expected.is_some_and(|e| e != hex) {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            "the body does not match its x-amz-content-sha256",
        ));
    }
    let existed = tokio::task::spawn_blocking(move || {
        let key = key(&segs);
        let existed = store.contains(key.as_bytes())?;
        upload.commit(key.as_bytes())?;
        anyhow::Ok(existed)
    })
    .await
    .context("publishing a flat object panicked")??;
    Ok(if existed {
        objects::no_content()
    } else {
        objects::created()
    })
}

/// Remove the object at `segs`: 204, or 404 when it is missing, when the path ends in a slash
/// or when the caller may not read its parent repository; 403 when it may read but not write.
pub(crate) async fn delete(
    area: &Area,
    authz: &Authz<'_>,
    segs: Vec<String>,
    trailing_slash: bool,
    href: &str,
) -> Result<Response<Body>> {
    let repo = parent(&segs);
    if trailing_slash || !allowed(authz, accounts::Action::Read, &repo) {
        return Ok(objects::not_found(href));
    }
    if !allowed(authz, accounts::Action::Write, &repo) {
        return Ok(accounts::forbidden());
    }
    let store = area.serving()?;
    let href = href.to_string();
    tokio::task::spawn_blocking(move || {
        Ok(if store.delete(key(&segs).as_bytes())? {
            objects::no_content()
        } else {
            objects::not_found(&href)
        })
    })
    .await
    .context("a flat deletion panicked")?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(prefix: &str) -> FlatBinding {
        FlatBinding::new(prefix, 1 << 20)
    }

    /// Prefixes are servable directories below `files/`, apart from one another.
    #[test]
    fn bindings_are_checked() {
        check(&[b("sccache"), b("dev/sccache"), b("a.b/c-d")]).unwrap();
        for bad in [
            vec![b("Bad")],
            vec![b("files/x")],
            vec![b("sha256")],
            vec![b("sha256/x")],
            vec![b("a/tags")],
            vec![b("a//b")],
            vec![b("")],
            vec![b(&vec!["x"; 15].join("/"))],
            vec![b("a"), b("a")],
            vec![b("a"), b("a/b")],
            vec![b("a/b"), b("a")],
            vec![FlatBinding::new("a", 0)],
            vec![FlatBinding {
                evict_to: 1.5,
                ..b("a")
            }],
        ] {
            assert!(check(&bad).is_err(), "{bad:?}");
        }
        // Only complete components overlap.
        check(&[b("a"), b("ab"), b("a-b/c")]).unwrap();
        check(&[b(&vec!["x"; 14].join("/"))]).unwrap();
    }

    #[test]
    fn sizes_take_binary_suffixes() {
        assert_eq!(parse_size("123"), Some(123));
        assert_eq!(parse_size("4K"), Some(4096));
        assert_eq!(parse_size("2m"), Some(2 << 20));
        assert_eq!(parse_size(" 50G "), Some(50 << 30));
        assert_eq!(parse_size("1T"), Some(1 << 40));
        for bad in ["", "G", "1.5G", "-1", "1GB", "1 G", "99999999999T"] {
            assert_eq!(parse_size(bad), None, "{bad}");
        }
    }

    /// A key lies strictly below a prefix, on component boundaries; the area's directory
    /// spells the prefix with `+`.
    #[test]
    fn keys_below_a_prefix_find_its_area() {
        let dir = crate::testtmp::root().join("flat-find");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let areas = Areas::new(&dir, vec![b("dev/sccache")], Use::Collect).unwrap();
        let s = |p: &str| p.split('/').map(str::to_string).collect::<Vec<_>>();
        assert!(areas.find(&s("dev/sccache/a/b")).is_some());
        assert!(areas.find(&s("dev/sccache/x")).is_some());
        for miss in ["dev/sccache", "dev", "dev/sccache2/x", "dev/other/x"] {
            assert!(areas.find(&s(miss)).is_none(), "{miss}");
        }
        let area = areas.find(&s("dev/sccache/x")).unwrap();
        assert!(
            area.root.ends_with("flat/dev+sccache"),
            "{}",
            area.root.display()
        );
        // Collecting opens nothing that is not there.
        assert!(area.store().unwrap().is_none());
        assert!(!dir.join("flat").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Serving bindings share an instance and update its policy. Inspection preserves it.
    #[test]
    fn a_process_opens_an_area_once() {
        let dir = crate::testtmp::root().join("flat-once");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let one = Areas::new(&dir, vec![b("a")], Use::Serve).unwrap();
        let two = Areas::new(&dir.join("."), vec![b("a")], Use::Serve).unwrap();
        let store = one.areas[0].store().unwrap().unwrap();
        assert!(Arc::ptr_eq(&store, &two.areas[0].store().unwrap().unwrap()));
        let three = Areas::new(&dir, vec![FlatBinding::new("a", 2)], Use::Serve).unwrap();
        assert!(Arc::ptr_eq(
            &store,
            &three.areas[0].store().unwrap().unwrap()
        ));
        assert_eq!(store.policy().cap, Some(2));
        let four = Areas::new(&dir, vec![FlatBinding::new("a", 3)], Use::Inspect).unwrap();
        assert!(Arc::ptr_eq(
            &store,
            &four.areas[0].store().unwrap().unwrap()
        ));
        assert_eq!(store.policy().cap, Some(2));
        assert!(matches!(four.evict()[0].outcome, Ok(Eviction::Elsewhere)));
        assert_eq!(four.usage()[0].cap, 2, "the cap in force");
        // A failed open preserves the existing store's cap.
        std::fs::write(dir.join("flat/b"), b"not a store").unwrap();
        let bad = vec![FlatBinding::new("a", 1), FlatBinding::new("b", 1)];
        assert!(Areas::new(&dir, bad, Use::Serve).is_err());
        assert_eq!(store.policy().cap, Some(2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_uncapped_binding_leaves_eviction_to_a_capped_peer() {
        let dir = crate::testtmp::root().join("flat-uncapped");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let areas = Areas::new(&dir, vec![FlatBinding::new("a", UNCAPPED)], Use::Serve).unwrap();
        let store = areas.areas[0].serving().unwrap();
        assert_eq!(store.policy().cap, None);
        for k in ["k1", "k2", "k3"] {
            store.put(k.as_bytes(), &mut &[0u8; 100][..]).unwrap();
        }
        // Wait past the interval when a capped instance would try to take the role.
        std::thread::sleep(std::time::Duration::from_millis(1500));
        assert!(!store.is_evictor());
        let peer = FlatStore::open(
            &areas.areas[0].root,
            Options {
                cap: Some(150),
                evict_to: 1.0,
                ..Options::default()
            },
        )
        .unwrap();
        assert!(peer.evict().unwrap().is_some(), "the peer takes the role");
        assert!(peer.usage().unwrap().bytes <= 150);
        // Another binding in this process reports the cap in force.
        let capped = Areas::new(&dir, vec![FlatBinding::new("a", 1)], Use::Collect).unwrap();
        assert_eq!(capped.usage()[0].cap, 1);
        areas.areas[0].apply().unwrap();
        assert_eq!(capped.usage()[0].cap, UNCAPPED, "the cap in force");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
