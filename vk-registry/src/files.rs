//! The plain-file area of the pool, `files/`, as objects in directories, below any wire
//! protocol. Directories map to repositories under `files/`; each object is a tag on a
//! single-layer raw-file manifest, as written by `/upload`, whose layer holds the file bytes.
//! A write streams to `uploads/` while hashing ([`stage`]), then promotes the blob and writes
//! the manifest and tag under the namespace lock ([`commit`]). Each wire protocol over this
//! layer keeps its own status codes and bodies: WebDAV under `/dav/files/` (`crate::dav`)
//! today, an S3 view in later work. Entries expire under gc's tag retention and blob grace
//! windows.

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
        Some(manifest) => crate::raw_file_layer(&manifest),
        None => None,
    };
    Ok(Some(match layer {
        Some((layer, size)) => Node::Object(Object {
            repo,
            tag: tag.to_string(),
            layer,
            size,
            modified,
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
/// [`MAX_OBJECT`]. Memory use is bounded by the coalescing buffer whatever the size.
pub(crate) async fn stage<B>(store: &Store, body: B) -> std::result::Result<Staged, PutError>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let (path, file) = store.stage_file().map_err(PutError::Failed)?;
    let staging = Staging { path, armed: true };
    let mut file = tokio::fs::File::from_std(file);
    let written = drain_into(&mut file, body, MAX_OBJECT).await;
    let flushed = file
        .flush()
        .await
        .map_err(|e| PutError::Failed(anyhow::Error::from(e).context("writing an object")));
    drop(file);
    let (size, hex) = written.and_then(|w| flushed.map(|()| w))?;
    Ok(Staged { size, hex, staging })
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
}

/// Promote a [`stage`]d body into the pool and tag it at `segs` as a raw file, re-checking
/// [`unwritable`] under [`NAMESPACE`] and the shared store lock first. Off the runtime:
/// staging compresses, and a large object would otherwise block a tokio worker for seconds.
/// The locks are taken inside, after that pass — the store lock as the relay takes it.
pub(crate) async fn commit(
    store: Arc<Store>,
    segs: Vec<String>,
    staged: Staged,
) -> Result<Written> {
    tokio::task::spawn_blocking(move || -> Result<Written> {
        let Staged {
            size,
            hex,
            mut staging,
        } = staged;
        let promotion = store.stage_promotion(&hex, &staging.path)?;
        let _namespace = namespace(&store)?;
        // shared store lock (vs. an exclusive gc) across the promote and the manifest that
        // references it; see Store::lock_shared. Another write may have changed the path
        // while the body streamed, so it is checked again.
        let checked = store.lock_shared().and_then(|lock| {
            let existed = matches!(resolve(&store, &segs)?, Some(Node::Object(_)));
            Ok((lock, unwritable(&store, &segs)?, existed))
        });
        let (_lock, existed) = match checked {
            Ok((lock, None, existed)) => (lock, existed),
            Ok((_, Some(why), _)) => {
                promotion.discard();
                return Ok(Written::Refused(why));
            }
            Err(e) => {
                promotion.discard();
                return Err(e);
            }
        };
        store.promote_staged(&hex, promotion)?;
        staging.armed = false;
        let (repo, tag) = object_of(&segs).context("a write past its checks names an object")?;
        store.put_raw_file(&repo, tag, &hex, size, None)?;
        Ok(if existed {
            Written::Replaced
        } else {
            Written::Created
        })
    })
    .await
    .context("the object's promotion panicked")?
}

/// Stream `body` to `out`, coalescing small frames and enforcing `cap`, including for chunked
/// bodies; `(bytes written, sha256 hex)` on success. `out` may be a sink when draining a
/// refused request. The generic body allows tests with a small cap.
pub(crate) async fn drain_into<B>(
    out: &mut (impl AsyncWrite + Unpin),
    mut body: B,
    cap: u64,
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
    let _ = drain_into(&mut tokio::io::sink(), body, cap).await;
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
            drain_into(&mut file, frames(), 250).await,
            Err(PutError::TooLarge)
        ));
        drop(file);
        // Refused where the count crossed, so the partial file is bounded by the cap plus
        // the frame that crossed it — never the whole body.
        let staged = std::fs::metadata(&path).unwrap().len();
        assert!(staged <= 300, "wrote {staged} bytes past a 250-byte cap");

        // Exactly at the cap is not over it, and the digest is the body's.
        let mut file = tokio::fs::File::create(&path).await.unwrap();
        let (n, hex) = drain_into(&mut file, frames(), 400).await.ok().unwrap();
        file.flush().await.unwrap();
        drop(file);
        assert_eq!(n, 400);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 400);
        assert_eq!(hex, crate::sha256_hex_raw(&vec![1u8; 400]));

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
