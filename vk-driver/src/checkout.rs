//! Host-side git checkout for the GitLab executor's `[gitlab] host_checkout` mode.
//!
//! `prepare` checks the job's sources out ON THE HOST and shares the tree into the guest, so
//! the git credential (embedded by GitLab in `CI_REPOSITORY_URL`) never enters the guest and
//! the host has the tree to build a git-defined image (see the `ci-boots-git-defined-images`
//! design). virtkit runs `git` itself with fixed arguments — never a configured hook command,
//! which would be an injection surface for the runner user. Only `http(s)` URLs are accepted:
//! an `ext::`/`file::` transport would let a crafted `CI_REPOSITORY_URL` run an arbitrary
//! remote helper (a git-remote-ext RCE). The token-bearing URL is never rendered into an error
//! or log — only its redacted form — so a git failure cannot spill the credential into the
//! runner's job trace.
//!
//! A checkout is kept and reused by later jobs on the same slot, so it is a cache and is
//! reclaimed like one — on [`crate::cachelock`]'s protocol, the same one the materialized image
//! bases use. That matters most where a checkout is worth caching at all: a `checkout_dir` on a
//! tmpfs, where an abandoned tree costs host RAM that the runner's own concurrency is measured
//! against.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};

/// Hold a checkout across the clone and the job that uses it, so the idle sweep cannot remove
/// the tree while prepare is updating it or a supervisor is sharing it into a guest.
pub(crate) fn acquire_use_lock(dest: &Path) -> Result<crate::cachelock::Guard> {
    let s = sidecars(dest)?;
    // The lock and markers name a private, token-bearing checkout, so create their directory
    // 0700 from the start rather than chmod'ing it afterwards. An explicit `checkout_dir` may
    // belong to another executor, but `Config::checkout_root` places both our slots and this
    // metadata beneath a private subtree of it.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&s.dir)
        .with_context(|| format!("creating {}", s.dir.display()))?;
    // A checkout is held for a whole job, so its idle window starts when the last prepare or
    // supervisor lets go — not when a long-running job first took it.
    crate::cachelock::acquire_shared(&s.lock, &s.used, crate::cachelock::IdleFrom::Release)
}

/// Create the checkout directory and record the identity of what it created, while the caller
/// holds its use lock. Recorded before anything fills the tree, so a prepare killed part-way
/// through a clone still leaves a remnant the idle sweep can find. [`tree_at`] rechecks the
/// record immediately before removal, so bookkeeping detached from an externally removed tree
/// cannot authorize removing a replacement that has appeared at the same path since.
pub(crate) fn claim(dest: &Path) -> Result<()> {
    let s = sidecars(dest)?;
    // A checkout's `.git/config` holds the job's token-bearing remote, so the tree is private
    // from the moment it exists rather than from the chmod after its first clone.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dest)
        .with_context(|| format!("creating {}", dest.display()))?;
    let sx = statx(dest, IDENTITY)
        .with_context(|| format!("reading checkout identity {}", dest.display()))?;
    if !is_dir(&sx) {
        bail!("host checkout {} is not a directory", dest.display());
    }
    // Staged and renamed into place, so the record is either absent or whole: a kill between
    // a truncate and its write would otherwise leave an empty record no tree can ever match,
    // holding the tree out of the sweep until the same slot and project is claimed again.
    let tmp = s.id.with_extension("tree-id.new");
    let mut marker = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("opening {}", tmp.display()))?;
    writeln!(marker, "{}", tree_id(&sx)).with_context(|| format!("writing {}", tmp.display()))?;
    drop(marker);
    std::fs::rename(&tmp, &s.id).with_context(|| format!("recording {}", s.id.display()))
}

/// How a checkout directory is told apart from a later one at the same path: its device, inode
/// and birth time, all out of the one `statx(2)` that also says it is a directory — an inode from
/// one call paired with a birth time from another would describe no single tree. The inode alone
/// would not do: ext4 hands a directory removed and recreated at the same path the very inode it
/// just freed. The birth time is in turn only as fine as the kernel's timestamp granularity, so
/// two directories created inside one tick share one — a tree that has sat out its idle window is
/// far older than that. Written and compared as one opaque line, never parsed back into fields.
fn tree_id(sx: &Statx) -> String {
    // A filesystem that records no birth time leaves the check as strong as device and inode
    // alone. Recorded rather than assumed, so a record made with one never matches one made
    // without.
    let born = match sx.stx_mask & STATX_BTIME {
        0 => "-".to_string(),
        _ => format!("{}.{:09}", sx.stx_btime.tv_sec, sx.stx_btime.tv_nsec),
    };
    format!(
        "{}:{} {} {born}",
        sx.stx_dev_major, sx.stx_dev_minor, sx.stx_ino
    )
}

fn is_dir(sx: &Statx) -> bool {
    u32::from(sx.stx_mode) & libc::S_IFMT == libc::S_IFDIR
}

/// One `statx(2)` on `dest`, never following a final symlink. Used in place of
/// `symlink_metadata` because `Metadata::created()` answers "not available on this platform" on
/// the musl target virtkit ships, which would leave [`tree_id`] nothing but a device and inode to
/// go on — no discrimination at all on a filesystem that reuses them.
fn statx(dest: &Path, mask: u32) -> std::io::Result<Statx> {
    use std::os::unix::ffi::OsStrExt;

    let path = std::ffi::CString::new(dest.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut buf = std::mem::MaybeUninit::<Statx>::uninit();
    // SAFETY: the kernel writes one `struct statx` through `buf`, which is exactly that size and
    // outlives the call, and reads `path` (NUL-terminated, alive here) only for its duration.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_statx,
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
            mask,
            buf.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so the kernel initialized the struct.
    Ok(unsafe { buf.assume_init() })
}

/// What [`tree_id`] asks `statx(2)` for. The reply reports which of them were really filled.
const IDENTITY: u32 = STATX_TYPE | STATX_INO | STATX_BTIME;
const STATX_TYPE: u32 = 0x0001;
const STATX_INO: u32 = 0x0100;
const STATX_BTIME: u32 = 0x0800;

/// The kernel's `struct statx_timestamp` (`linux/stat.h`).
#[repr(C)]
struct StatxTimestamp {
    tv_sec: i64,
    tv_nsec: u32,
    _reserved: i32,
}

/// The kernel's `struct statx` (`linux/stat.h`), mirrored here because `libc` defines it only for
/// musl builds configured with `RUST_LIBC_UNSTABLE_MUSL_V1_2_3`, which virtkit's is not. Every
/// field is laid out because `statx(2)` fills the whole struct, whatever is read back out of it.
#[repr(C)]
#[allow(
    dead_code,
    reason = "an ABI mirror: the kernel writes every field, this reads a handful"
)]
struct Statx {
    stx_mask: u32,
    stx_blksize: u32,
    stx_attributes: u64,
    stx_nlink: u32,
    stx_uid: u32,
    stx_gid: u32,
    stx_mode: u16,
    _spare0: [u16; 1],
    stx_ino: u64,
    stx_size: u64,
    stx_blocks: u64,
    stx_attributes_mask: u64,
    stx_atime: StatxTimestamp,
    stx_btime: StatxTimestamp,
    stx_ctime: StatxTimestamp,
    stx_mtime: StatxTimestamp,
    stx_rdev_major: u32,
    stx_rdev_minor: u32,
    stx_dev_major: u32,
    stx_dev_minor: u32,
    stx_mnt_id: u64,
    stx_dio_mem_align: u32,
    stx_dio_offset_align: u32,
    _spare3: [u64; 12],
}

/// What sits at a checkout's path, relative to the bookkeeping that dates it.
enum Tree {
    /// The directory [`claim`] recorded, so this is the tree the idle window was measured for.
    Same,
    /// Nothing is there any more: removed from outside virtkit, leaving nothing to reclaim.
    Gone,
    /// A different directory, or one whose identity was never recorded — another executor's
    /// tree, or a replacement made after ours went away.
    Other,
}

/// Whether `id` still names the directory now at `dest`. Anything unreadable, unrecorded or
/// mismatched answers [`Tree::Other`]: keeping a tree one sweep too long costs a re-clone, while
/// guessing costs someone else's checkout.
fn tree_at(dest: &Path, id: &Path) -> Tree {
    let sx = match statx(dest, IDENTITY) {
        Ok(sx) => sx,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Tree::Gone,
        // Unreadable for any other reason is not proof the tree is gone.
        Err(_) => return Tree::Other,
    };
    if !is_dir(&sx) {
        return Tree::Other;
    }
    match std::fs::read_to_string(id) {
        Ok(recorded) if recorded.trim() == tree_id(&sx) => Tree::Same,
        _ => Tree::Other,
    }
}

/// Reclaim virtkit-created checkouts under `root` that no job is using and that have been idle
/// for at least `idle`. Only a tree whose bookkeeping still names it qualifies; an explicit
/// `checkout_dir` also puts this whole root in a private namespace, outside sibling trees
/// belonging to another GitLab executor.
pub(crate) fn gc_idle(root: &Path, idle: Duration) {
    let now = SystemTime::now();
    for (dest, Sidecars { lock, used, id, .. }) in checkouts(root) {
        crate::cachelock::try_reclaim(&lock, &used, idle, now, || {
            match tree_at(&dest, &id) {
                // Not the tree this bookkeeping dates, so removing it is not ours to do — and
                // nothing ties the markers to the stranger standing in its place, so retiring
                // them on its account would be a guess of the same kind. Both stay.
                Tree::Other => return,
                // Removed in the window between this sweep listing the tree and reaching it —
                // the same race the `NotFound` arm below covers on the far side of the check.
                // Nothing is left to protect, so retire the markers as our own removal would.
                Tree::Gone => {
                    retire(&used, &id);
                    return;
                }
                Tree::Same => {}
            }
            println!("virtkit: evicting idle host checkout {}", dest.display());
            let removed = match std::fs::remove_dir_all(&dest) {
                Ok(()) => true,
                Err(e) => e.kind() == std::io::ErrorKind::NotFound,
            };
            // Retire the markers with the tree they date, so a slot's metadata does not
            // accumulate one file per project the runner has ever built — but only once the tree
            // is really gone. A removal that failed part-way (a job left behind a directory it
            // cannot unlink from) has to stay a candidate, or the remnant holds host memory no
            // later sweep can find. The lock stays either way: it is the inode a new user of this
            // destination blocks on.
            if removed {
                retire(&used, &id);
            }
        });
    }
}

/// Drop the markers that date a destination, keeping the lock a new user blocks on. Only ever
/// called under the reclaim's exclusive lock, so no acquisition can be part-way through.
fn retire(used: &Path, id: &Path) {
    let _ = std::fs::remove_file(used);
    let _ = std::fs::remove_file(id);
}

/// A checkout's bookkeeping, at
/// `<root>/.virtkit/<slot>/<project>.{inuse,used,tree-id}`. It sits in the root's own metadata
/// tree rather than inside the checkout, so a sweep can lock a destination before its first clone
/// ever exists, and can remove the whole tree without unlinking the inode the next user will
/// synchronize on.
struct Sidecars {
    /// The private per-slot directory holding them.
    dir: PathBuf,
    lock: PathBuf,
    used: PathBuf,
    /// Names the filesystem identity of the checkout this bookkeeping dates.
    id: PathBuf,
}

fn sidecars(dest: &Path) -> Result<Sidecars> {
    let slot_dir = dest
        .parent()
        .with_context(|| format!("checkout {} has no slot directory", dest.display()))?;
    let root = slot_dir
        .parent()
        .with_context(|| format!("checkout {} has no root", dest.display()))?;
    let slot = slot_dir
        .file_name()
        .with_context(|| format!("checkout {} has no slot", dest.display()))?;
    let project = dest
        .file_name()
        .with_context(|| format!("checkout {} has no name", dest.display()))?;
    let dir = root.join(".virtkit").join(slot);
    let sidecar = |ext: &str| {
        let mut name = project.to_os_string();
        name.push(ext);
        dir.join(name)
    };
    Ok(Sidecars {
        lock: sidecar(".inuse"),
        used: sidecar(".used"),
        id: sidecar(".tree-id"),
        dir,
    })
}

/// Every reclaimable checkout under `root`, with its bookkeeping. A checkout is exactly two
/// directories below the root (`<concurrent slot>/<project>`, see [`crate::jobctx::JobCtx`]), and
/// must carry both a `.used` marker and the identity [`claim`] recorded for it — so a tree
/// virtkit never made is never a candidate.
fn checkouts(root: &Path) -> Vec<(PathBuf, Sidecars)> {
    let mut out = Vec::new();
    for slot in subdirectories(root) {
        for dest in subdirectories(&slot) {
            let Ok(s) = sidecars(&dest) else {
                continue;
            };
            if s.used.is_file() && s.id.is_file() {
                out.push((dest, s));
            }
        }
    }
    out
}

/// The directories directly under `dir`, skipping dotted names — which is what keeps the sweep
/// out of the `.virtkit` metadata tree beside the slots.
fn subdirectories(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| {
            !e.file_name().as_encoded_bytes().starts_with(b".")
                && e.file_type().is_ok_and(|t| t.is_dir())
        })
        .map(|e| e.path())
        .collect()
}

/// Clone-or-fetch `url` into the existing `dest` ([`claim`] creates it) and hard-checkout `sha`.
/// Idempotent: a populated `dest` is fetched and re-pointed at `sha` rather than re-cloned (so a
/// reused per-slot dir amortises the clone). `ref_name` (the branch/tag) is fetched first so a
/// bare commit resolves without server-side `uploadpack.allowAnySHA1InWant`. The tree is
/// cleaned to match a fresh CI checkout. Submodules and LFS are not handled here — add them if
/// a job needs them.
pub fn ensure(url: &str, ref_name: &str, sha: &str, dest: &Path) -> Result<()> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        bail!(
            "refusing to clone {}: only http(s) URLs are allowed for host_checkout",
            redact_url(url)
        );
    }
    if sha.is_empty() || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid commit sha {sha:?}");
    }
    // `ref_name` is `--`-guarded below, so it can never be read as an option; validating it
    // against git's own ref-name rules is defence-in-depth against a crafted refspec (a glob
    // or `remote:local` pair) fetching extra refs into the reused per-slot repo.
    if !ref_name.is_empty() && !ref_name_ok(ref_name) {
        bail!("invalid ref name {ref_name:?}");
    }

    if dest.join(".git").is_dir() {
        // Re-point at the current URL (the embedded token rotates per job), then fetch.
        git(
            dest,
            &["remote", "set-url", "origin", url],
            "remote set-url",
        )?;
    } else {
        // Clone without checkout; the explicit detach below pins the exact commit.
        // `--filter=blob:none` makes this a blobless partial clone: commits and trees
        // transfer but historical file blobs do not — the checkout below lazily fetches
        // only the blobs of the one pinned commit. The filter is recorded on the remote,
        // so the reused-slot `fetch` below stays blobless too.
        let dest_s = dest.to_str().context("checkout dir is not utf-8")?;
        run(
            Command::new("git").args([
                "clone",
                "--quiet",
                "--no-checkout",
                "--filter=blob:none",
                "--",
                url,
                dest_s,
            ]),
            "clone",
        )?;
    }
    // The checkout's `.git/config` records the token-bearing remote URL; keep the tree private
    // to the runner user so a co-tenant on the host cannot read the credential at rest.
    std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("securing {}", dest.display()))?;
    // Fetch the ref tip so `sha` is reachable, then detach onto exactly that commit. `--`
    // guards a ref that begins with '-'; `sha` is validated hex above. `--quiet` drops git's
    // transfer summary (the "From <url>" / "forced update" block) from the job trace —
    // virtkit already prints its own `host checkout of <sha>` line.
    if ref_name.is_empty() {
        git(dest, &["fetch", "--quiet", "--prune", "origin"], "fetch")?;
    } else {
        git(
            dest,
            &["fetch", "--quiet", "--prune", "origin", "--", ref_name],
            "fetch",
        )?;
    }
    // Detach onto exactly `sha`. HEAD is moved with `update-ref` rather than
    // `git checkout --detach`: this per-slot repo is always on a detached HEAD, and after a
    // force-pushed branch the prior HEAD commit is unreachable, so `checkout` would spill a
    // noisy "you are leaving N commits behind" orphan warning into the job trace. Moving HEAD
    // by ref skips that detection; `reset --hard` then syncs the index + working tree (lazily
    // fetching the pinned commit's blobs from the blobless promisor remote). `sha` is
    // validated hex above, so it cannot be read as an option even without a `--` guard.
    git(dest, &["update-ref", "--no-deref", "HEAD", sha], "detach")?;
    git(dest, &["reset", "--hard", sha], "reset")?;
    git(dest, &["clean", "-ffdx"], "clean")?;
    Ok(())
}

/// A git ref name safe to pass as a fetch argument: git's own rules already forbid these in a
/// branch/tag, so rejecting them cannot turn away a legitimate ref. `/` stays allowed
/// (`feature/x`); a leading `-`/`+` and refspec/glob metacharacters are refused.
fn ref_name_ok(r: &str) -> bool {
    !r.starts_with('-')
        && !r.starts_with('+')
        && r.chars().all(|c| {
            !c.is_control() && !matches!(c, ':' | '?' | '*' | '[' | '\\' | '~' | '^' | ' ')
        })
}

/// Strip `user[:password]@` userinfo from an http(s) URL so the embedded job token never
/// reaches a log or error. A URL without userinfo is returned unchanged.
fn redact_url(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => match rest.split_once('@') {
            Some((_userinfo, host)) => format!("{scheme}://<redacted>@{host}"),
            // No `@` means no `user:token@` userinfo, so there is no credential to hide.
            None => url.to_string(),
        },
        None => "<redacted>".to_string(),
    }
}

/// Run `git -C <dir> <args…>`, erroring on a non-zero exit. `what` is a fixed, secret-free
/// label for diagnostics — the command (which may carry the token-bearing URL) is never
/// rendered.
fn git(dir: &Path, args: &[&str], what: &str) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(dir).args(args);
    run(&mut cmd, what)
}

fn run(cmd: &mut Command, what: &str) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("spawning git {what}"))?;
    if !status.success() {
        bail!("git {what} failed ({status})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_url_strips_the_embedded_token() {
        assert_eq!(
            redact_url("https://gitlab-ci-token:secrettoken@gitlab.example.com/g/p.git"),
            "https://<redacted>@gitlab.example.com/g/p.git"
        );
        // No userinfo: nothing to hide, returned unchanged.
        assert_eq!(
            redact_url("https://gitlab.example.com/g/p.git"),
            "https://gitlab.example.com/g/p.git"
        );
        // A non-URL never echoes back verbatim.
        assert_eq!(redact_url("gitlab-ci-token:secret"), "<redacted>");
    }

    #[test]
    fn ref_name_rejects_injection_but_keeps_real_branches() {
        for ok in [
            "main",
            "feature/foo",
            "release-1.2.3",
            "v1.0",
            "user/fix.bug",
        ] {
            assert!(ref_name_ok(ok), "{ok:?} is a legitimate ref");
        }
        for bad in [
            "-upload-pack=x",
            "+refs/heads/*",
            "evil:refs/heads/x",
            "a b",
            "glob*",
            "q?",
            "ca^ret",
            "ti~lde",
            "back\\slash",
        ] {
            assert!(!ref_name_ok(bad), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn ensure_refuses_non_http_and_bad_sha_before_touching_git() {
        let dest = Path::new("/nonexistent/vk-checkout-test");
        // A non-http(s) transport (git-remote-ext RCE vector) is refused, and the error is
        // redacted — never echoing the raw ref back verbatim.
        let err = ensure("ext::sh -c whoami", "main", "abcdef", dest).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("only http(s)"), "got: {msg}");
        assert!(!msg.contains("ext::sh"), "raw ext URL leaked: {msg}");
        // A non-hex sha is refused before any git runs.
        assert!(ensure("https://h/p.git", "main", "deadbeefZZ", dest).is_err());
        // An option-injection ref is refused before any git runs.
        assert!(ensure("https://h/p.git", "-x", "deadbeef", dest).is_err());
    }

    /// A checkout root with two slot/project trees in it, one of them ours to reclaim.
    fn root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("vk-checkout-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    /// Sweep with a zero window until `dest` is gone — retried for the reason
    /// [`crate::cachelock::reclaimed_eventually`] documents.
    fn evict_eventually(root: &Path, dest: &Path) {
        assert!(
            crate::cachelock::reclaimed_eventually(|| {
                gc_idle(root, Duration::ZERO);
                !dest.exists()
            }),
            "checkout {} was not reclaimed within the timeout",
            dest.display()
        );
    }

    #[test]
    fn gc_reclaims_only_idle_checkouts_that_are_ours() {
        let base = root("gc");
        let root = base.join("vk");
        let ours = root.join("0").join("live-project");
        // Our own shape, inside the swept root, but with no bookkeeping at all: a directory
        // virtkit never made is not a candidate even where it is allowed to look.
        let unmarked = root.join("1").join("docker-project");
        // And a tree another GitLab executor put beside our private namespace in `/builds`,
        // which the sweep never even walks.
        let sibling = base.join("2").join("docker-project");
        std::fs::create_dir_all(unmarked.join(".git")).unwrap();
        std::fs::create_dir_all(sibling.join(".git")).unwrap();

        // A held reference protects the tree even against a zero idle window.
        let guard = acquire_use_lock(&ours).unwrap();
        claim(&ours).unwrap();
        gc_idle(&root, Duration::ZERO);
        assert!(ours.exists(), "a checkout in use must not be reclaimed");

        // Releasing dates the tree. A window it is inside keeps it; a zero window reclaims it.
        drop(guard);
        gc_idle(&root, Duration::from_secs(3600));
        assert!(ours.exists(), "a just-released checkout stays cached");
        evict_eventually(&root, &ours);
        assert!(
            unmarked.exists(),
            "a tree virtkit never made is not a candidate"
        );
        assert!(
            sibling.exists(),
            "a shared checkout root may hold another executor's trees"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn the_lock_creates_the_private_root_0700() {
        // In production the lock is taken before the clone creates any tree, so a root that
        // does not exist yet — the private `vk` subtree of an explicit `checkout_dir` — is
        // born 0700 from the metadata dir's recursive creation, never chmod'd after the fact.
        let root = root("mode");
        let guard = acquire_use_lock(&root.join("0").join("project")).unwrap();
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        drop(guard);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_tree_is_swept_only_once_its_identity_is_recorded() {
        // What a prepare killed between taking its reference and claiming the destination leaves
        // behind, and what every checkout made before this bookkeeping existed looks like: held
        // out of the sweep rather than guessed to be ours.
        let root = root("unclaimed");
        let dest = root.join("0").join("project");
        std::fs::create_dir_all(dest.join(".git")).unwrap();
        drop(acquire_use_lock(&dest).unwrap());

        assert!(checkouts(&root).is_empty());
        gc_idle(&root, Duration::ZERO);
        assert!(dest.exists(), "a `.used` marker alone is not proof of ours");

        // And how such a tree rejoins the sweep, which is the upgrade path for the unmoved
        // default root: the next job on that slot and project claims the tree it finds.
        let guard = acquire_use_lock(&dest).unwrap();
        claim(&dest).unwrap();
        drop(guard);
        assert_eq!(
            checkouts(&root).len(),
            1,
            "claiming it makes it a candidate"
        );
        evict_eventually(&root, &dest);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_sidecars_outlive_the_tree_they_name() {
        // The lock has to be an inode a new user can still block on while the tree it names is
        // being removed, so it lives beside the root's slots rather than inside the checkout.
        let root = root("sidecars");
        let dest = root.join("0").join("project");
        let guard = acquire_use_lock(&dest).unwrap();
        claim(&dest).unwrap();
        let Sidecars {
            dir,
            lock,
            used,
            id,
        } = sidecars(&dest).unwrap();
        assert_eq!(dir, root.join(".virtkit").join("0"));
        assert_eq!(lock.parent(), Some(dir.as_path()));
        assert_eq!(used.parent(), Some(dir.as_path()));
        assert_eq!(id.parent(), Some(dir.as_path()));
        assert!(!lock.starts_with(&dest));
        // The tree is private from creation: its `.git/config` will carry the job's token.
        assert_eq!(
            std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // And that metadata tree is private, since its names describe token-bearing checkouts.
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        drop(guard);

        evict_eventually(&root, &dest);
        assert!(lock.exists(), "the synchronization inode stays stable");
        // The markers go with the tree, so a slot's metadata does not grow a file per project
        // forever — and the reclaimed tree is not a candidate again either way.
        assert!(!used.exists());
        assert!(!id.exists());
        assert!(checkouts(&root).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_replacement_tree_is_never_reclaimed() {
        // The bookkeeping outlives the tree it names, so a directory that reappears at the same
        // path after an external removal would inherit an idle window measured for another tree.
        // Both ways a replacement can arrive have to be recognized as a stranger.
        let root = root("replacement");
        let moved_in = root.join("0").join("moved-in");
        let recreated = root.join("0").join("recreated");
        for dest in [&moved_in, &recreated] {
            let guard = acquire_use_lock(dest).unwrap();
            claim(dest).unwrap();
            drop(guard);
        }

        // Built elsewhere while ours still held its inode, then moved into place: a different
        // inode on any filesystem.
        let elsewhere = root.join("0").join("elsewhere");
        std::fs::create_dir_all(elsewhere.join(".git")).unwrap();
        std::fs::remove_dir_all(&moved_in).unwrap();
        std::fs::rename(&elsewhere, &moved_in).unwrap();

        // Removed and recreated in place, which is the same inode straight back on ext4 — told
        // apart by the birth time recorded beside it.
        std::fs::remove_dir_all(&recreated).unwrap();
        std::fs::create_dir_all(recreated.join(".git")).unwrap();

        gc_idle(&root, Duration::ZERO);
        assert!(moved_in.exists(), "a tree moved into our path is not ours");
        assert!(recreated.exists(), "a tree remade at our path is not ours");
        // The bookkeeping stays put too: nothing ties it to the stranger either way.
        for dest in [&moved_in, &recreated] {
            let s = sidecars(dest).unwrap();
            assert!(s.used.is_file() && s.id.is_file());
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_statx_mirror_matches_the_kernel_abi() {
        // `statx(2)` fills a fixed 256-byte struct. A mirror that drifted from it would have the
        // kernel write past the buffer, or the birth time read out of the wrong offset.
        assert_eq!(std::mem::size_of::<StatxTimestamp>(), 16);
        assert_eq!(std::mem::size_of::<Statx>(), 256);
        // Matching sizes do not put the two fields that are read back where the kernel writes
        // them: a mirror that widened one member and shortened the reserved tail would still be
        // 256 bytes and silently read the wrong offset.
        assert_eq!(std::mem::offset_of!(Statx, stx_mask), 0x00);
        assert_eq!(std::mem::offset_of!(Statx, stx_ino), 0x20);
        assert_eq!(std::mem::offset_of!(Statx, stx_btime), 0x50);
        assert_eq!(std::mem::offset_of!(Statx, stx_dev_major), 0x88);

        // And the call has to actually answer: a wrong syscall number or mask silently degrades
        // every identity record to a device and inode, which ext4 hands straight to a
        // replacement. Both tmpfs and ext4 — anything a `checkout_dir` realistically is —
        // record a birth time.
        let root = root("statx");
        std::fs::create_dir_all(&root).unwrap();
        let sx = statx(&root, IDENTITY).unwrap();
        assert!(is_dir(&sx));
        assert!(
            sx.stx_mask & STATX_BTIME != 0,
            "statx reported no birth time for {}",
            root.display()
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_recorded_identity_names_one_tree_and_no_other() {
        // The three answers the sweep acts on, tested here rather than through `gc_idle`: it
        // finds its candidates by walking directories, so a tree that is already gone is one
        // only this classifier ever sees.
        let root = root("identity");
        let dest = root.join("0").join("project");
        let guard = acquire_use_lock(&dest).unwrap();
        claim(&dest).unwrap();
        drop(guard);
        let s = sidecars(&dest).unwrap();
        assert!(matches!(tree_at(&dest, &s.id), Tree::Same));

        std::fs::remove_dir_all(&dest).unwrap();
        assert!(matches!(tree_at(&dest, &s.id), Tree::Gone));

        // Remade at the same path: a fresh inode on a tmpfs, and on ext4 the very inode just
        // freed, told apart by the birth time recorded with it.
        std::fs::create_dir_all(&dest).unwrap();
        assert!(matches!(tree_at(&dest, &s.id), Tree::Other));

        // A record half-written by a killed prepare says nothing about any tree.
        std::fs::write(&s.id, b"12 34").unwrap();
        assert!(matches!(tree_at(&dest, &s.id), Tree::Other));

        // Neither does bookkeeping that never got one.
        std::fs::remove_file(&s.id).unwrap();
        assert!(matches!(tree_at(&dest, &s.id), Tree::Other));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn claim_refuses_a_destination_that_is_not_a_directory() {
        // `claim` records what its non-following `statx` sees, which is what the sweep
        // compares against.
        // A symlink at the destination would have it record the target's identity and then hand
        // the sweep a path it must not follow, so it is refused outright.
        let root = root("symlink");
        let dest = root.join("0").join("project");
        let target = root.join("0").join("target");
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, &dest).unwrap();

        let err = format!("{:#}", claim(&dest).unwrap_err());
        assert!(err.contains("is not a directory"), "got: {err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_checkout_root_that_does_not_exist_yet_sweeps_clean() {
        // The first prepare on a runner sweeps before the root has ever been created.
        gc_idle(&root("absent"), Duration::ZERO);
    }

    #[test]
    fn a_tree_that_cannot_be_removed_stays_a_candidate() {
        // A job can leave a directory its own user cannot unlink from — a build tool that drops
        // read-only output, with `checkout_overlay = false` so guest writes reach the host tree.
        // The eviction then fails part-way, and the remnant has to stay reclaimable: dropping its
        // marker would hide it, and the host memory it holds, from every later sweep.
        if unsafe { libc::geteuid() } == 0 {
            return; // root ignores the write bit, so there would be no failure to observe
        }
        let root = root("stuck");
        let dest = root.join("0").join("project");
        let stuck = dest.join("build-output");
        std::fs::create_dir_all(&stuck).unwrap();
        std::fs::write(stuck.join("artifact"), b"x").unwrap();
        std::fs::set_permissions(&stuck, std::fs::Permissions::from_mode(0o555)).unwrap();
        let guard = acquire_use_lock(&dest).unwrap();
        claim(&dest).unwrap();
        drop(guard);

        gc_idle(&root, Duration::ZERO);
        assert!(stuck.exists(), "the unremovable directory is still there");
        let s = sidecars(&dest).unwrap();
        assert!(s.used.is_file(), "the markers outlive a failed removal");
        assert!(s.id.is_file());
        assert_eq!(
            checkouts(&root).len(),
            1,
            "and the tree is still a candidate"
        );

        // Once the obstruction is gone the next sweep finishes the job.
        std::fs::set_permissions(&stuck, std::fs::Permissions::from_mode(0o755)).unwrap();
        evict_eventually(&root, &dest);
        assert!(!s.used.exists());
        assert!(!s.id.exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}
