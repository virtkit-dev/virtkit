//! The plain-file area of the pool, `files/`, as objects in directories, below any wire
//! protocol. Directories map to repositories under `files/`; each object is a tag on a
//! single-layer raw-file manifest, as written by `/upload`, whose layer holds the file bytes.
//! A write streams to `uploads/` while hashing ([`stage`]), then promotes the blob and writes
//! the manifest and tag under the namespace lock ([`commit`]). Each wire protocol over this
//! layer keeps its own status codes and bodies: WebDAV under `/dav/files/` (`crate::dav`) and
//! S3 under `/s3/` (`crate::s3`). Entries expire under gc's tag retention and blob grace
//! windows.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::{Authz, STREAM_CHUNK, Store, accounts};

/// The repository every object and directory lives under.
pub(crate) const FILES_REPO: &str = "files";

/// Maximum object size, checked both against a declared length and while streaming.
pub(crate) const MAX_OBJECT: u64 = 4 << 30;

/// Minimum idle age before a read refreshes the tag's mtime — the "last used" record the
/// gc's retention keys on — so a cache read is a metadata write at most once an hour.
const TOUCH_AFTER: Duration = Duration::from_secs(3600);

/// Longest a directory's removal waits for the exclusive store lock, released between
/// attempts, before answering 503.
pub(crate) const DELETE_LOCK_WAIT: Duration = Duration::from_secs(30);

/// Serialize `files/` checks and namespace changes (object tags, new directories, deletions)
/// in this server so a write of an object and of a directory at the same path cannot both
/// succeed. Acquire before the store lock, never while holding it. `/v2/` writes into
/// `files/` do not take this lock.
static NAMESPACE: Mutex<()> = Mutex::new(());

/// The namespace held, in this process and against any other serving the store: a registry
/// and the release it hands over to serve it together for a while.
pub(crate) struct Namespace {
    _process: std::sync::MutexGuard<'static, ()>,
    _store: crate::LockGuard,
}

/// Hold [`NAMESPACE`], then the store's namespace lock. Accept a poisoned mutex: it guards
/// no data that a panic could leave inconsistent.
pub(crate) fn namespace(store: &Store) -> Result<Namespace> {
    let process = NAMESPACE.lock().unwrap_or_else(PoisonError::into_inner);
    Ok(Namespace {
        _process: process,
        _store: store.lock_namespace()?,
    })
}

/// What a `files/` path names once the store has been looked at.
pub(crate) enum Node {
    /// A repository under `files/`, or a path component above one: a directory.
    Dir(String),
    /// A tag on a raw-file manifest: an object.
    Object(Object),
    /// A tag on any other manifest — an image pushed over `/v2/` into a `files/`
    /// repository. Absent to reads; a write there is refused, so nothing here replaces or
    /// deletes it.
    Foreign(String),
}

/// An object's tag and what its manifest says about the layer.
pub(crate) struct Object {
    pub(crate) repo: String,
    pub(crate) tag: String,
    /// the layer blob's hex
    pub(crate) layer: String,
    /// the layer's canonical length
    pub(crate) size: u64,
    /// the tag's mtime
    pub(crate) modified: SystemTime,
    /// the manifest's annotations: what a front stored beside the bytes
    pub(crate) annotations: BTreeMap<String, String>,
}

impl Node {
    /// The repository this node authorizes as.
    pub(crate) fn repo(&self) -> &str {
        match self {
            Node::Dir(r) | Node::Foreign(r) => r,
            Node::Object(o) => &o.repo,
        }
    }
}

/// The repository a run of path components names: `files/<segs…>`.
pub(crate) fn repo_name(segs: &[String]) -> String {
    let mut name = String::from(FILES_REPO);
    for s in segs {
        name.push('/');
        name.push_str(s);
    }
    name
}

/// The repository and tag an object at `segs` would have: the last component is the tag.
pub(crate) fn object_of(segs: &[String]) -> Option<(String, &str)> {
    let (leaf, parents) = segs.split_last()?;
    (!parents.is_empty()).then(|| (repo_name(parents), leaf.as_str()))
}

/// What is at `segs`: a directory, an object, a foreign tag, or nothing. A directory is any
/// path under `repos/files/` that is one — a repository, or the parent a nested repository's
/// name created — so the tree reads as the client wrote it.
pub(crate) fn resolve(store: &Store, segs: &[String]) -> Result<Option<Node>> {
    let dir = repo_name(segs);
    if store.repo_dir_exists(&dir) {
        return Ok(Some(Node::Dir(dir)));
    }
    let Some((repo, tag)) = object_of(segs) else {
        return Ok(None);
    };
    let Some((manifest_hex, modified)) = store.tag_target(&repo, tag) else {
        return Ok(None);
    };
    let layer = match store.get_blob(&manifest_hex)? {
        Some(manifest) => crate::raw_file_parts(&manifest),
        None => None,
    };
    Ok(Some(match layer {
        Some((layer, size, annotations)) => Node::Object(Object {
            repo,
            tag: tag.to_string(),
            layer,
            size,
            modified,
            annotations,
        }),
        None => Node::Foreign(repo),
    }))
}

/// Whether an ancestor of `segs` is a tag. Writing below one would make its path a directory
/// too, and [`resolve`] would then find the directory and hide the tag. A top-level name is
/// always a directory.
pub(crate) fn under_object(store: &Store, segs: &[String]) -> Result<bool> {
    for n in 2..segs.len() {
        if matches!(
            resolve(store, &segs[..n])?,
            Some(Node::Object(_) | Node::Foreign(_))
        ) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether this caller may `action` on `repo`.
pub(crate) fn allowed(authz: &Authz<'_>, action: accounts::Action, repo: &str) -> bool {
    crate::authorize_or_forbidden(authz, action, repo).is_none()
}

/// Refresh the tag of an object just served once it has been idle past [`TOUCH_AFTER`]: a
/// read is a use, which is what keeps the tag from the gc's retention, and a hot entry is
/// not a metadata write per hit.
pub(crate) fn touch_if_idle(store: &Store, obj: &Object) {
    if SystemTime::now()
        .duration_since(obj.modified)
        .is_ok_and(|idle| idle > TOUCH_AFTER)
    {
        store.touch_tag(&obj.repo, &obj.tag);
    }
}

/// Why `segs` cannot take an object.
pub(crate) enum Unwritable {
    /// a single component: a top-level name is always a directory
    TopLevel,
    /// a directory is there
    Directory,
    /// a foreign tag is there
    Foreign,
    /// a tag is above it
    UnderObject,
}

/// Why `segs` cannot take an object, or `None` when a write may proceed. Checked before a
/// body is staged when the answer is already known, and again by [`commit`] under
/// [`NAMESPACE`] before the tag is written.
pub(crate) fn unwritable(store: &Store, segs: &[String]) -> Result<Option<Unwritable>> {
    if object_of(segs).is_none() {
        return Ok(Some(Unwritable::TopLevel));
    }
    Ok(match resolve(store, segs)? {
        Some(Node::Dir(_)) => Some(Unwritable::Directory),
        Some(Node::Foreign(_)) => Some(Unwritable::Foreign),
        _ if under_object(store, segs)? => Some(Unwritable::UnderObject),
        _ => None,
    })
}

/// Why a streamed body stopped short.
pub(crate) enum PutError {
    /// the body crossed the cap — decided while reading
    TooLarge,
    /// the read or the write failed
    Failed(anyhow::Error),
}

/// A staging file under `uploads/`, unlinked when dropped unless its bytes were promoted —
/// including when the handler's future is dropped with the connection mid-body.
struct Staging {
    path: PathBuf,
    armed: bool,
}

impl Drop for Staging {
    fn drop(&mut self) {
        if self.armed {
            // Gone already (a promotion that renamed it, or a discard) is the goal; any
            // other failure leaves it to the gc's sweep of idle uploads.
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// A body written whole to a staging file and hashed, not yet in the pool. Dropping it
/// removes the file, so a caller that refuses what it sees here simply lets it go.
pub(crate) struct Staged {
    /// the body's length
    pub(crate) size: u64,
    /// the body's sha256 hex
    pub(crate) hex: String,
    staging: Staging,
}

/// Stream `body` into a staging file under `uploads/`, hashing it on the way, up to
/// [`MAX_OBJECT`]; `tap` sees every byte as it goes, for a front's own digests. Memory use is
/// bounded by the coalescing buffer whatever the size.
pub(crate) async fn stage<B>(
    store: &Store,
    body: B,
    tap: &mut impl FnMut(&[u8]),
) -> std::result::Result<Staged, PutError>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let (path, file) = store.stage_file().map_err(PutError::Failed)?;
    stage_into(path, file, body, tap).await
}

/// [`stage`] into `file`, a private file just created at `path`, which is then the
/// [`Staged`]'s: unlinked if it is dropped.
pub(crate) async fn stage_into<B>(
    path: PathBuf,
    file: std::fs::File,
    body: B,
    tap: &mut impl FnMut(&[u8]),
) -> std::result::Result<Staged, PutError>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let staging = Staging { path, armed: true };
    let mut file = tokio::fs::File::from_std(file);
    let written = drain_into(&mut file, body, MAX_OBJECT, tap).await;
    let flushed = file
        .flush()
        .await
        .map_err(|e| PutError::Failed(anyhow::Error::from(e).context("writing an object")));
    drop(file);
    let (size, hex) = written.and_then(|w| flushed.map(|()| w))?;
    Ok(Staged { size, hex, staging })
}

impl Staged {
    /// A staging file `path` its caller wrote whole, `size` bytes whose SHA-256 is `hex`:
    /// unlinked if it is dropped, as one [`stage`] wrote.
    pub(crate) fn written(path: PathBuf, size: u64, hex: String) -> Self {
        Staged {
            size,
            hex,
            staging: Staging { path, armed: true },
        }
    }

    /// Rename the bytes to `dest`, replacing what is there, rather than promote them: for a
    /// front that keeps them outside the pool for a while, such as an S3 part.
    pub(crate) fn rename_to(mut self, dest: &std::path::Path) -> Result<()> {
        std::fs::rename(&self.staging.path, dest)
            .with_context(|| format!("renaming into {}", dest.display()))?;
        self.staging.armed = false;
        Ok(())
    }
}

/// What [`commit`] did.
pub(crate) enum Written {
    /// the object is new
    Created,
    /// the object replaced one at the same path
    Replaced,
    /// the path changed while the body streamed and no longer takes an object; nothing was
    /// written
    Refused(Unwritable),
    /// [`Commit::precondition`] refused the object found there, or its absence; nothing was
    /// written. `found` says whether an object was there.
    PreconditionFailed { found: bool },
}

/// Whether a [`commit`] goes ahead, given the object at its path or `None`.
pub(crate) type Precondition = Box<dyn FnOnce(Option<&Object>) -> bool + Send>;

/// What a front asks of a [`commit`] beyond the bytes.
#[derive(Default)]
pub(crate) struct Commit {
    /// written on the object's manifest
    pub(crate) annotations: BTreeMap<String, String>,
    /// checked under the locks the tag is written under, so no other write of this server
    /// comes between the check and the write
    pub(crate) precondition: Option<Precondition>,
    /// promoted as the bytes came, with no compression pass, so that ranges of it are read
    /// by seeking (see [`crate::StagedBlob::uncompressed`]); otherwise compressed when that
    /// pays
    pub(crate) uncompressed: bool,
}

/// Promote a [`stage`]d body into the pool and tag it at `segs` as a raw file, re-checking
/// [`unwritable`], then `how`'s precondition, under [`NAMESPACE`] and the shared store lock
/// first. Off the runtime: staging compresses, and a large object would otherwise block a
/// tokio worker for seconds. The locks are taken inside, after that pass — the store lock as
/// the relay takes it.
pub(crate) async fn commit(
    store: Arc<Store>,
    segs: Vec<String>,
    staged: Staged,
    how: Commit,
) -> Result<Written> {
    tokio::task::spawn_blocking(move || -> Result<Written> {
        let Staged {
            size,
            hex,
            mut staging,
        } = staged;
        let promotion = if how.uncompressed {
            crate::StagedBlob::uncompressed(&staging.path)
        } else {
            store.stage_promotion(&hex, &staging.path)?
        };
        let _namespace = namespace(&store)?;
        // shared store lock (vs. an exclusive gc) across the promote and the manifest that
        // references it; see Store::lock_shared. Another write may have changed the path
        // while the body streamed, so it is checked again.
        let checked = store
            .lock_shared()
            .and_then(|lock| Ok((lock, admit(&store, &segs, how.precondition)?)));
        let (_lock, existed) = match checked {
            Ok((lock, Ok(existed))) => (lock, existed),
            Ok((_, Err(refused))) => {
                promotion.discard();
                return Ok(refused);
            }
            Err(e) => {
                promotion.discard();
                return Err(e);
            }
        };
        store.promote_staged(&hex, promotion)?;
        staging.armed = false;
        let (repo, tag) = object_of(&segs).context("a write past its checks names an object")?;
        store.put_raw_file_annotated(&repo, tag, &hex, size, None, &how.annotations)?;
        Ok(if existed {
            Written::Replaced
        } else {
            Written::Created
        })
    })
    .await
    .context("the object's promotion panicked")?
}

/// Whether a write at `segs` goes ahead, checked under the locks it is written under:
/// `Ok(existed)`, or the [`Written`] refusal — [`unwritable`] first, then `precondition` on
/// the object found there.
fn admit(
    store: &Store,
    segs: &[String],
    precondition: Option<Precondition>,
) -> Result<std::result::Result<bool, Written>> {
    let existing = match resolve(store, segs)? {
        Some(Node::Object(obj)) => Some(obj),
        _ => None,
    };
    if let Some(why) = unwritable(store, segs)? {
        return Ok(Err(Written::Refused(why)));
    }
    if let Some(precondition) = precondition
        && !precondition(existing.as_ref())
    {
        return Ok(Err(Written::PreconditionFailed {
            found: existing.is_some(),
        }));
    }
    Ok(Ok(existing.is_some()))
}

/// The [`namespace`] and the shared store lock, held together in that order as a write of
/// `files/` holds them: what [`link`] is called under, across whatever its caller read the
/// layer it tags from.
pub(crate) struct Held {
    _namespace: Namespace,
    _store: crate::LockGuard,
}

/// Take [`Held`]'s locks.
pub(crate) fn hold(store: &Store) -> Result<Held> {
    let namespace = namespace(store)?;
    Ok(Held {
        _namespace: namespace,
        _store: store.lock_shared()?,
    })
}

/// Tag `layer`, a blob of `size` bytes already in the pool, at `segs` as a raw file: what
/// [`commit`] does for bytes that need no staging, such as a copy of another object. The
/// caller holds the locks (`_held`) and has checked that the blob is there; [`unwritable`]
/// and `how`'s precondition are checked here, and the layer's membership in the destination
/// repository is recorded with the tag, as a commit records it. `how.uncompressed` says
/// nothing here: the blob keeps the form it is stored in.
pub(crate) fn link(
    store: &Store,
    _held: &Held,
    segs: &[String],
    layer: &str,
    size: u64,
    how: Commit,
) -> Result<Written> {
    let existed = match admit(store, segs, how.precondition)? {
        Ok(existed) => existed,
        Err(refused) => return Ok(refused),
    };
    let (repo, tag) = object_of(segs).context("a write past its checks names an object")?;
    store.put_raw_file_annotated(&repo, tag, layer, size, None, &how.annotations)?;
    Ok(if existed {
        Written::Replaced
    } else {
        Written::Created
    })
}

/// Stream `body` to `out`, coalescing small frames and enforcing `cap`, including for chunked
/// bodies; `(bytes written, sha256 hex)` on success. `tap` sees each frame's bytes as they are
/// hashed, before they are written. `out` may be a sink when draining a refused request. The
/// generic body allows tests with a small cap.
pub(crate) async fn drain_into<B>(
    out: &mut (impl AsyncWrite + Unpin),
    mut body: B,
    cap: u64,
    tap: &mut impl FnMut(&[u8]),
) -> std::result::Result<(u64, String), PutError>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let mut buf: Vec<u8> = Vec::with_capacity(STREAM_CHUNK);
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let io = |e: std::io::Error| PutError::Failed(anyhow::Error::from(e).context("writing"));
    while let Some(frame) = body.frame().await {
        let frame = frame
            .map_err(|e| PutError::Failed(anyhow::Error::from(e).context("reading a PUT body")))?;
        // Trailers carry no content; a body that has them simply ends after them.
        let Ok(data) = frame.into_data() else {
            continue;
        };
        total = total.saturating_add(data.len() as u64);
        if total > cap {
            return Err(PutError::TooLarge);
        }
        hasher.update(&data);
        tap(&data);
        // A frame already worth a write goes straight out rather than through the
        // coalescing buffer, which is there for the small ones.
        if buf.is_empty() && data.len() >= STREAM_CHUNK {
            out.write_all(&data).await.map_err(io)?;
            continue;
        }
        buf.extend_from_slice(&data);
        if buf.len() >= STREAM_CHUNK {
            out.write_all(&buf).await.map_err(io)?;
            buf.clear();
        }
    }
    if !buf.is_empty() {
        out.write_all(&buf).await.map_err(io)?;
    }
    Ok((total, crate::hex_of(&hasher.finalize())))
}

/// Read and discard `body` up to `cap` bytes, and the frame that crosses it. For a refusal
/// answered before the caller is known, which must not make the server read a whole
/// upload: a body that ends within them is answered rather than reset, and what is left of a
/// longer one closes the connection after the answer, as every refusal of a request with a
/// body does.
pub(crate) async fn drain_up_to<B>(body: B, cap: u64)
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    // Past `cap`, or unreadable: either way there is nothing more to read.
    let _ = drain_into(&mut tokio::io::sink(), body, cap, &mut |_| {}).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The namespace held here is held against another process's open of the store: the
    /// lock file another descriptor cannot take until it is released.
    #[test]
    fn the_namespace_is_held_against_other_processes() {
        use std::os::fd::AsRawFd;
        let dir = std::env::temp_dir().join(format!("vk-reg-files-ns-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        let try_lock = || {
            let file = std::fs::File::open(dir.join(".files.lock")).unwrap();
            // SAFETY: flock on a descriptor `file` owns.
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
        };
        let held = namespace(&store).unwrap();
        assert!(!try_lock());
        drop(held);
        assert!(try_lock());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Verify the streaming size cap with a small limit and multiple frames, and the digest
    /// of what went through.
    #[tokio::test]
    async fn a_body_over_the_cap_stops_being_written() {
        let dir = std::env::temp_dir().join(format!("vk-reg-files-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("staged");

        // Several frames, so the cap is crossed part way through rather than at the first.
        let frames = || {
            let chunks: Vec<std::result::Result<hyper::body::Frame<Bytes>, std::io::Error>> = (0
                ..4)
                .map(|_| Ok(hyper::body::Frame::data(Bytes::from(vec![1u8; 100]))))
                .collect();
            http_body_util::StreamBody::new(futures::stream::iter(chunks))
        };

        let mut file = tokio::fs::File::create(&path).await.unwrap();
        assert!(matches!(
            drain_into(&mut file, frames(), 250, &mut |_| {}).await,
            Err(PutError::TooLarge)
        ));
        drop(file);
        // Refused where the count crossed, so the partial file is bounded by the cap plus
        // the frame that crossed it — never the whole body.
        let staged = std::fs::metadata(&path).unwrap().len();
        assert!(staged <= 300, "wrote {staged} bytes past a 250-byte cap");

        // Exactly at the cap is not over it, and the digest is the body's.
        let mut file = tokio::fs::File::create(&path).await.unwrap();
        let mut tapped = 0;
        let (n, hex) = drain_into(&mut file, frames(), 400, &mut |b| tapped += b.len())
            .await
            .ok()
            .unwrap();
        file.flush().await.unwrap();
        drop(file);
        assert_eq!((n, tapped), (400, 400));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 400);
        assert_eq!(hex, crate::sha256_hex_raw(&vec![1u8; 400]));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A commit writes the annotations it is given on the manifest, and its precondition sees
    /// what is at the path, under the locks: refused, nothing is tagged and the staging file
    /// goes.
    #[tokio::test]
    async fn a_commit_carries_annotations_and_honours_its_precondition() {
        let dir = std::env::temp_dir().join(format!("vk-reg-files-commit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(Store::new(dir.clone()).unwrap());
        let body = |b: &'static [u8]| {
            let frame: std::result::Result<_, std::io::Error> =
                Ok(hyper::body::Frame::data(Bytes::from_static(b)));
            http_body_util::StreamBody::new(futures::stream::iter([frame]))
        };
        let segs = vec!["b".to_string(), "k".to_string()];
        let write = async |b: &'static [u8], how: Commit| {
            let staged = stage(&store, body(b), &mut |_| {}).await.ok().unwrap();
            commit(Arc::clone(&store), segs.clone(), staged, how)
                .await
                .unwrap()
        };
        let absent =
            || -> Option<Precondition> { Some(Box::new(|o: Option<&Object>| o.is_none())) };
        let annotations = BTreeMap::from([("org.example.k".to_string(), "v".to_string())]);

        let how = Commit {
            annotations: annotations.clone(),
            precondition: absent(),
            ..Commit::default()
        };
        assert!(matches!(write(b"one", how).await, Written::Created));
        let (hex, _) = store.tag_target("files/b", "k").unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&store.get_blob(&hex).unwrap().unwrap()).unwrap();
        assert_eq!(manifest["annotations"]["org.example.k"], "v");
        assert!(crate::raw_file_layer(&serde_json::to_vec(&manifest).unwrap()).is_some());

        let how = Commit {
            precondition: absent(),
            ..Commit::default()
        };
        assert!(matches!(
            write(b"two", how).await,
            Written::PreconditionFailed { found: true }
        ));
        assert_eq!(store.tag_target("files/b", "k").unwrap().0, hex);
        let staged = std::fs::read_dir(dir.join("uploads"))
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_type().unwrap().is_file())
            .count();
        assert_eq!(staged, 0, "the refused body's staging file is gone");

        let layer = crate::sha256_hex_raw(b"one");
        let how = Commit {
            precondition: Some(Box::new(move |o: Option<&Object>| {
                o.is_some_and(|o| o.layer == layer && o.size == 3)
            })),
            ..Commit::default()
        };
        assert!(matches!(write(b"three", how).await, Written::Replaced));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A link tags a layer already in the pool elsewhere, recording it a member of the
    /// destination so it is readable there, and is refused as a commit is.
    #[tokio::test]
    async fn a_link_tags_a_layer_already_held_as_a_commit_would() {
        let dir = std::env::temp_dir().join(format!("vk-reg-files-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(Store::new(dir.clone()).unwrap());
        let frame: std::result::Result<_, std::io::Error> =
            Ok(hyper::body::Frame::data(Bytes::from_static(b"one")));
        let body = http_body_util::StreamBody::new(futures::stream::iter([frame]));
        let staged = stage(&store, body, &mut |_| {}).await.ok().unwrap();
        let layer = staged.hex.clone();
        let src = vec!["b".to_string(), "k".to_string()];
        let written = commit(Arc::clone(&store), src, staged, Commit::default()).await;
        assert!(matches!(written.unwrap(), Written::Created));
        let segs = |s: &[&str]| s.iter().map(|s| s.to_string()).collect::<Vec<_>>();

        let held = hold(&store).unwrap();
        let annotations = BTreeMap::from([("org.example.k".to_string(), "v".to_string())]);
        let how = Commit {
            annotations,
            ..Commit::default()
        };
        let dst = segs(&["c", "d", "copy"]);
        let written = link(&store, &held, &dst, &layer, 3, how).unwrap();
        assert!(matches!(written, Written::Created));
        assert!(store.repo_has_blob("files/c/d", &layer));
        let Some(Node::Object(obj)) = resolve(&store, &dst).unwrap() else {
            panic!("an object at the link");
        };
        assert_eq!((obj.layer.as_str(), obj.size), (layer.as_str(), 3));
        assert_eq!(obj.annotations["org.example.k"], "v");

        let absent = Commit {
            precondition: Some(Box::new(|o: Option<&Object>| o.is_none())),
            ..Commit::default()
        };
        let written = link(&store, &held, &dst, &layer, 3, absent).unwrap();
        assert!(matches!(written, Written::PreconditionFailed { .. }));
        let below = segs(&["b", "k", "x"]);
        let written = link(&store, &held, &below, &layer, 3, Commit::default()).unwrap();
        assert!(matches!(written, Written::Refused(Unwritable::UnderObject)));
        let written = link(&store, &held, &dst, &layer, 3, Commit::default()).unwrap();
        assert!(matches!(written, Written::Replaced));
        drop(held);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A commit asked to keep its bytes uncompressed promotes them plain, however well they
    /// would compress; otherwise compressible bytes are stored as a zstd frame.
    #[tokio::test]
    async fn an_uncompressed_commit_is_promoted_plain() {
        let dir = std::env::temp_dir().join(format!("vk-reg-files-plain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(Store::new(dir.clone()).unwrap());
        let write = async |name: &str, data: Vec<u8>, uncompressed: bool| {
            let frame: std::result::Result<_, std::io::Error> =
                Ok(hyper::body::Frame::data(Bytes::from(data)));
            let body = http_body_util::StreamBody::new(futures::stream::iter([frame]));
            let staged = stage(&store, body, &mut |_| {}).await.ok().unwrap();
            let hex = staged.hex.clone();
            let segs = vec!["b".to_string(), name.to_string()];
            let how = Commit {
                uncompressed,
                ..Commit::default()
            };
            let written = commit(Arc::clone(&store), segs, staged, how).await;
            assert!(matches!(written.unwrap(), Written::Created));
            hex
        };
        let data = b"compressible ".repeat(4096);
        let plain = write("plain", data.clone(), true).await;
        assert!(store.blob_path(&plain).is_file());
        assert!(!store.zstd_blob_path(&plain).is_file());
        let mut other = data.clone();
        other.push(b'!');
        let packed = write("packed", other, false).await;
        assert!(store.zstd_blob_path(&packed).is_file());
        assert!(!store.blob_path(&packed).is_file());
        assert_eq!(store.get_blob(&plain).unwrap().unwrap(), data);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn paths_map_onto_repositories_and_tags() {
        let segs = |s: &[&str]| s.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(repo_name(&segs(&[])), "files");
        assert_eq!(
            repo_name(&segs(&["sccache", "a", "b"])),
            "files/sccache/a/b"
        );
        assert!(
            object_of(&segs(&["sccache"])).is_none(),
            "a top-level name is a directory"
        );
        let key = segs(&["sccache", "a", "b", "abcdef"]);
        let (repo, tag) = object_of(&key).unwrap();
        assert_eq!((repo.as_str(), tag), ("files/sccache/a/b", "abcdef"));
    }
}
