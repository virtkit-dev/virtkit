//! Default cache location and migration from `$XDG_DATA_HOME/virtkit` (normally
//! `~/.local/share/virtkit`) to `$XDG_CACHE_HOME/virtkit` (normally `~/.cache/virtkit`).
//!
//! Releases through 0.116 kept the build store, image caches (`registry/`, `docker/`,
//! `build/`) and Windows build cache (`windows/`) in the data directory. On first use,
//! [`resolve`] handles each legacy cache according to what it finds at the two paths:
//!
//! - On the same filesystem, `renameat2(RENAME_EXCHANGE)` swaps the directory with a
//!   symlink to its new path. Without exchange support, migration renames the directory,
//!   then makes the link; a move interrupted in between makes the link on the next try.
//! - Across filesystems, nothing is copied: the old directory stays where it is, and the
//!   new path links to it.
//! - For a user symlink at the old path, the new path links to its target.
//! - If both paths hold separate directories, migration keeps both, uses the new one
//!   and warns.
//! - A move that fails leaves the cache where it is, and it is used there.
//!
//! Older binaries can reach a moved cache once its link exists. They do not take part in
//! migration locking. A cache cleared at its new location is recreated there.
//! [`keep_in_place`] exempts configured paths in this process. [`locate`] reports the
//! location without moving the cache.

use std::ffi::{CString, OsStr, OsString};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// The build store's directory, under either base.
pub const REGISTRY: &str = "registry";
/// In each base: held across a move, so that two `vk`s never move one cache at once.
const MOVE_LOCK: &str = ".move.lock";
/// How long [`resolve`] waits for another process's move.
const MOVE_WAIT: Duration = if cfg!(test) {
    Duration::from_millis(300)
} else {
    Duration::from_secs(10)
};
/// In the data dir: a server's durable state when it serves the default store.
const SERVER_HOME: &str = "registry-server";

/// `$XDG_DATA_HOME/virtkit`, else `~/.local/share/virtkit`: where virtkit keeps what it must
/// not lose, and where older releases kept their caches.
pub fn data_base() -> Option<PathBuf> {
    base_in(env, "XDG_DATA_HOME", ".local/share")
}

/// The default cache root, `$XDG_CACHE_HOME/virtkit` or `~/.cache/virtkit`.
pub fn cache_base() -> Option<PathBuf> {
    base_in(env, "XDG_CACHE_HOME", ".cache")
}

/// The environment, or in this crate's tests a home of their own: what they resolve by
/// default never touches the caches of whoever runs them.
#[cfg(not(test))]
fn env(var: &str) -> Option<OsString> {
    std::env::var_os(var)
}

#[cfg(test)]
fn env(var: &str) -> Option<OsString> {
    (var == "HOME").then(|| crate::testtmp::root().join("home").into_os_string())
}

/// `virtkit` under `$<xdg>`, else under `~/<in_home>`, reading the environment from `var`.
/// A relative value is ignored, as the XDG base directory spec asks: it would name another
/// directory from every working directory.
fn base_in(var: impl Fn(&str) -> Option<OsString>, xdg: &str, in_home: &str) -> Option<PathBuf> {
    let absolute = |v: OsString| Some(PathBuf::from(v)).filter(|p| p.is_absolute());
    if let Some(dir) = var(xdg).and_then(absolute) {
        return Some(dir.join("virtkit"));
    }
    var("HOME")
        .and_then(absolute)
        .map(|home| home.join(in_home).join("virtkit"))
}

/// Where a cache is.
#[derive(Debug, PartialEq, Eq)]
pub enum Home {
    /// Under the cache base.
    New(PathBuf),
    /// Under the data base: not moved yet, or kept there.
    Old(PathBuf),
}

impl Home {
    pub fn path(&self) -> &Path {
        match self {
            Home::New(p) | Home::Old(p) => p,
        }
    }

    pub fn into_path(self) -> PathBuf {
        match self {
            Home::New(p) | Home::Old(p) => p,
        }
    }

    fn join(&self, name: &str) -> Home {
        match self {
            Home::New(p) => Home::New(p.join(name)),
            Home::Old(p) => Home::Old(p.join(name)),
        }
    }
}

/// Locations a configuration names, which no lookup in this process moves.
static KEPT: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Exempt configured cache paths from migration in this process. Match existing paths
/// by identity and missing paths by parent directory and name.
pub fn keep_in_place(paths: impl IntoIterator<Item = PathBuf>) {
    KEPT.lock().unwrap_or_else(|e| e.into_inner()).extend(paths);
}

fn kept(extra: &[PathBuf]) -> Vec<PathBuf> {
    let mut all = KEPT.lock().unwrap_or_else(|e| e.into_inner()).clone();
    all.extend_from_slice(extra);
    all
}

/// Resolve the default cache `name`, moving it from the data dir first if an older release
/// left it there. `keep`: locations to leave in place, besides [`keep_in_place`]'s.
pub fn resolve(name: &str, keep: &[PathBuf]) -> Result<Home> {
    Ok(match bases()? {
        Bases::Both { old, new } => settle(&old, &new, name, &kept(keep)),
        Bases::One(home) => home.join(name),
    })
}

/// Locate the default cache without migrating it: under the data base until it moved.
pub fn locate(name: &str, keep: &[PathBuf]) -> Result<Home> {
    Ok(match bases()? {
        Bases::Both { old, new } => locate_in(&old, &new, name, &kept(keep)),
        Bases::One(home) => home.join(name),
    })
}

/// [`resolve`] each of the caches `names`, and answer their common base: the data base if
/// one of them is kept or left there, else the cache base. In the data base, a cache only
/// the cache base holds is then reached by a link to it.
pub fn resolve_base(names: &[&str], keep: &[PathBuf]) -> Result<Home> {
    Ok(match bases()? {
        Bases::Both { old, new } => resolve_base_in(&old, &new, names, &kept(keep)),
        Bases::One(home) => home,
    })
}

fn resolve_base_in(old: &Path, new: &Path, names: &[&str], keep: &[PathBuf]) -> Home {
    let settled: Vec<_> = names.iter().map(|n| settle(old, new, n, keep)).collect();
    let base = one_base(old.to_path_buf(), new.to_path_buf(), &settled);
    if matches!(base, Home::Old(_)) {
        for (name, home) in names.iter().zip(&settled) {
            if matches!(home, Home::New(_)) {
                link_back(old, new, name);
            }
        }
    }
    base
}

/// Link `<old>/<name>` to `<new>/<name>` where only the latter is there: a user of the data
/// base would otherwise make a second cache beside it.
fn link_back(old: &Path, new: &Path, name: &str) {
    let (from, to) = (old.join(name), new.join(name));
    let missing =
        matches!(from.symlink_metadata(), Err(e) if e.kind() == std::io::ErrorKind::NotFound);
    if !missing || !to.is_dir() {
        return;
    }
    if let Err(e) = std::os::unix::fs::symlink(&to, &from) {
        report(
            Outcome::Unlinked(String::new()),
            &from,
            &to,
            "virtkit: warning: vk uses the image caches in the data dir, but could not link \
             {old} to {new} ({detail})",
            &e.to_string(),
        );
    }
}

/// [`resolve_base`], moving nothing: the data base while one of the caches is still there.
/// A cache only the cache base holds is missed there until [`resolve_base`] links it.
pub fn locate_base(names: &[&str], keep: &[PathBuf]) -> Result<Home> {
    Ok(match bases()? {
        Bases::Both { old, new } => {
            let keep = kept(keep);
            let located: Vec<_> = names
                .iter()
                .map(|n| locate_in(&old, &new, n, &keep))
                .collect();
            one_base(old, new, &located)
        }
        Bases::One(home) => home,
    })
}

fn one_base(old: PathBuf, new: PathBuf, homes: &[Home]) -> Home {
    if homes.iter().all(|h| matches!(h, Home::New(_))) {
        Home::New(new)
    } else {
        Home::Old(old)
    }
}

/// Where a server whose store is `root` keeps `item` (`accounts`, `hub`) of its durable state.
/// The default store keeps each under `$XDG_DATA_HOME/virtkit/registry-server`, even with one
/// directory for both bases; one only the store holds, as an older release left it, is used
/// there until [`adopt_server_state`] moves it. Other stores keep each at `<root>/<item>`.
pub fn server_dir(root: &Path, item: &str) -> PathBuf {
    match (data_base(), cache_base()) {
        (Some(data), Some(cache)) => server_dir_in(&data, &cache, root, item),
        _ => root.join(item),
    }
}

fn server_dir_in(data: &Path, cache: &Path, root: &Path, item: &str) -> PathBuf {
    let in_store = root.join(item);
    let default = [data.join(REGISTRY), cache.join(REGISTRY)];
    if !default.iter().any(|d| same_entry(root, d)) {
        return in_store;
    }
    let kept = data.join(SERVER_HOME).join(item);
    // Only a state that is not there gives way: one that cannot be read is opened, and fails.
    let absent = matches!(std::fs::symlink_metadata(&kept), Err(e) if e.kind() == std::io::ErrorKind::NotFound);
    if absent && std::fs::symlink_metadata(&in_store).is_ok() {
        report(
            Outcome::DurableInCache,
            &in_store,
            &kept,
            "virtkit: note: {old} holds registry server state inside the store; move it to \
             {new} while no server runs",
            "",
        );
        return in_store;
    }
    kept
}

/// What a server of the default store keeps of its own: [`server_dir`]'s items.
const SERVER_STATE: [&str; 2] = ["accounts", "hub"];

/// For `vk-registry serve` of the default store, which its user owns: move the durable state
/// an older release's server left in the store (`accounts/`, `hub/`) to
/// `$XDG_DATA_HOME/virtkit/registry-server`, where [`server_dir`] looks first, so the store
/// is a cache again. Each moves by one rename, only on the same filesystem and while no
/// process holds its accounts db; otherwise it is left, and used, where it is, with a note.
pub fn adopt_server_state(root: &Path) {
    if let (Some(data), Some(cache)) = (data_base(), cache_base()) {
        adopt_in(&data, &cache, root);
    }
}

fn adopt_in(data: &Path, cache: &Path, root: &Path) {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let default = [data.join(REGISTRY), cache.join(REGISTRY)];
    if !default.iter().any(|d| same_entry(root, d)) {
        return;
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    if std::fs::metadata(root).map_or(true, |m| m.uid() != me) {
        return;
    }
    let home = data.join(SERVER_HOME);
    for item in SERVER_STATE {
        let (from, to) = (root.join(item), home.join(item));
        let is_dir = std::fs::symlink_metadata(&from).is_ok_and(|m| m.is_dir());
        if !is_dir || std::fs::symlink_metadata(&to).is_ok() {
            continue;
        }
        // The db a running server holds says it is in use: redb keeps an exclusive flock on
        // it, which is held here across the rename so that no server opens it meanwhile.
        let db = from.join("accounts.db");
        let _held = match std::fs::File::open(&db) {
            Ok(f) => {
                // SAFETY: flock(2) on a descriptor `f` keeps open; LOCK_NB never waits.
                if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                    report(
                        Outcome::DurableInCache,
                        &from,
                        &to,
                        "virtkit: note: {old} holds registry server state inside the store, and \
                         a running server holds it; move it to {new} while none runs",
                        "",
                    );
                    continue;
                }
                Some(vk_fs::LockFile::new(f))
            }
            Err(_) => None,
        };
        let moved = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&home)
            .and_then(|()| rename_noreplace(root, &home, item));
        match moved {
            Ok(()) => report(
                Outcome::Moved,
                &from,
                &to,
                "virtkit: moved a registry server's durable state from {old} to {new}",
                "",
            ),
            Err(e) => report(
                Outcome::DurableInCache,
                &from,
                &to,
                "virtkit: note: {old} holds registry server state inside the store, and could \
                 not be moved to {new} ({detail}); move it there while no server runs",
                &e.to_string(),
            ),
        }
    }
}

/// `<from_dir>/<name>` renamed to `<to_dir>/<name>`, never replacing what is there.
fn rename_noreplace(from_dir: &Path, to_dir: &Path, name: &str) -> std::io::Result<()> {
    let (from, to) = (open_dir(from_dir)?, open_dir(to_dir)?);
    let name = OsStr::new(name);
    rename_at(from.as_fd(), name, to.as_fd(), name, libc::RENAME_NOREPLACE)
}

/// The two bases, or the only one there is.
enum Bases {
    Both { old: PathBuf, new: PathBuf },
    One(Home),
}

impl Bases {
    fn of(old: Option<PathBuf>, new: Option<PathBuf>) -> Result<Bases> {
        Ok(match (old, new) {
            // The same directory: nothing to move.
            (Some(old), Some(new)) if same_entry(&old, &new) => Bases::One(Home::New(new)),
            (Some(old), Some(new)) => Bases::Both { old, new },
            (None, Some(new)) => Bases::One(Home::New(new)),
            (Some(old), None) => Bases::One(Home::Old(old)),
            (None, None) => {
                bail!("set XDG_CACHE_HOME, XDG_DATA_HOME or HOME to locate the cache")
            }
        })
    }
}

fn bases() -> Result<Bases> {
    Bases::of(data_base(), cache_base())
}

/// [`relocate`] cache `name` from `old_base` to `new_base`, say what it did, and where to use
/// it: the new path, unless the old one is kept.
fn settle(old_base: &Path, new_base: &Path, name: &str, keep: &[PathBuf]) -> Home {
    let (old, new) = (old_base.join(name), new_base.join(name));
    if keep.iter().any(|k| same_entry(k, &old)) {
        return Home::Old(old);
    }
    let outcome = relocate(old_base, new_base, name);
    let (line, detail) = match &outcome {
        Outcome::Settled | Outcome::DurableInCache => (None, ""),
        Outcome::Moved => (
            Some("virtkit: moved {old} to {new}, leaving a link behind"),
            "",
        ),
        Outcome::Linked => (
            Some("virtkit: {new} now links to the cache {old} holds"),
            "",
        ),
        Outcome::Unlinked(e) => (
            Some(
                "virtkit: warning: moved {old} to {new}, but could not leave a link behind \
                 ({detail})",
            ),
            e.as_str(),
        ),
        Outcome::Both => (
            Some(
                "virtkit: warning: {old} and {new} are separate caches; vk uses {new} and leaves \
                 {old} as it is, as it may hold what {new} lacks",
            ),
            "",
        ),
        Outcome::Obstructed(what) => (Some("virtkit: warning: {new} {detail}"), what.as_str()),
        Outcome::Failed(e) => (
            Some(
                "virtkit: warning: could not move {old} to {new} ({detail}); vk uses {old} as \
                 it is",
            ),
            e.as_str(),
        ),
    };
    if let Some(line) = line {
        report(outcome.kind(), &old, &new, line, detail);
    }
    // A move that failed leaves the cache where it was, which is used rather than a new
    // empty one beside it.
    if matches!(outcome, Outcome::Failed(_)) && old.symlink_metadata().is_ok() {
        return Home::Old(old);
    }
    Home::New(new)
}

/// Fill in `{old}`, `{new}` and `{detail}` and report each outcome kind once per destination
/// per process, so a note cannot suppress a later warning.
fn report(kind: Outcome, old: &Path, new: &Path, line: &str, detail: &str) {
    if first_time(kind, new) {
        eprintln!("{}", fill(line, old, new, detail));
    }
}

/// `line` with its `{old}`, `{new}` and `{detail}` replaced, in one pass: what is filled in is
/// never scanned again, so a path holding `{new}` comes out as it is.
fn fill(line: &str, old: &Path, new: &Path, detail: &str) -> String {
    let (old, new) = (old.display().to_string(), new.display().to_string());
    let keys = [
        ("{old}", old.as_str()),
        ("{new}", new.as_str()),
        ("{detail}", detail),
    ];
    let mut out = String::new();
    let mut rest = line;
    while let Some(at) = rest.find('{') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        match keys.iter().find(|(k, _)| rest.starts_with(k)) {
            Some((k, v)) => {
                out.push_str(v);
                rest = &rest[k.len()..];
            }
            None => {
                out.push('{');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Whether this process has yet to say anything of `kind` about `new`.
fn first_time(kind: Outcome, new: &Path) -> bool {
    static TOLD: Mutex<Vec<(PathBuf, Outcome)>> = Mutex::new(Vec::new());
    let mut told = TOLD.lock().unwrap_or_else(|e| e.into_inner());
    if told.iter().any(|(p, k)| p == new && *k == kind) {
        return false;
    }
    told.push((new.to_path_buf(), kind));
    true
}

/// What [`relocate`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    /// Nothing to move: nothing at the old path, or both paths name one directory.
    Settled,
    /// The directory moved to the new path, and the old path links to it.
    Moved,
    /// The new path links to where the old one leads.
    Linked,
    /// The directory moved to the new path, but no link took its place.
    Unlinked(String),
    /// Two separate directories: the new one is used.
    Both,
    /// What is at the new path cannot be the cache.
    Obstructed(String),
    /// Left where it is.
    Failed(String),
    /// [`server_dir`]'s note.
    DurableInCache,
}

impl Outcome {
    /// The outcome without its detail, for [`report`].
    fn kind(&self) -> Outcome {
        match self {
            Outcome::Unlinked(_) => Outcome::Unlinked(String::new()),
            Outcome::Obstructed(_) => Outcome::Obstructed(String::new()),
            Outcome::Failed(_) => Outcome::Failed(String::new()),
            other => other.clone(),
        }
    }
}

/// `(st_dev, st_ino)`.
type Ident = (u64, u64);

/// What a cache's old path holds.
#[derive(Debug)]
enum OldEntry {
    Missing,
    /// Nothing, but a move renamed the directory away and has yet to leave its link
    /// ([`pending`]).
    LinkPending,
    /// A link: `to_new` when it leads to the new path (by the identity of the directory it
    /// leads into and its name, so whether or not that exists); `dir` when it leads to one.
    Link {
        target: PathBuf,
        to_new: bool,
        dir: Option<Ident>,
    },
    Dir(Ident),
    /// Something else, or what could not be read, said.
    Other(String),
}

/// What a cache's new path holds.
#[derive(Debug)]
enum NewEntry {
    Missing,
    /// The link to itself a move puts there before its exchange, left by one that died.
    Marker,
    /// A link, leading to a directory or not.
    Link(Option<Ident>),
    Dir(Ident),
    Other(String),
}

/// Open base directories anchor entry operations if a base is renamed. Symlink targets
/// and the paths returned use the absolute paths below.
struct Opened {
    old: OwnedFd,
    new: OwnedFd,
    new_id: Ident,
    /// The absolute paths of the cache, for the links.
    old_path: PathBuf,
    new_path: PathBuf,
}

impl Opened {
    fn open(old_base: &Path, new_base: &Path, name: &str) -> std::io::Result<Opened> {
        let (old, new) = (open_dir(old_base)?, open_dir(new_base)?);
        let new_id = ident(fstat(new.as_fd())?);
        Ok(Opened {
            old,
            new,
            new_id,
            old_path: std::path::absolute(old_base)?.join(name),
            new_path: std::path::absolute(new_base)?.join(name),
        })
    }

    fn old_entry(&self, name: &OsStr) -> OldEntry {
        match lstat_at(self.old.as_fd(), name) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if lstat_at(self.old.as_fd(), &pending(name)).is_ok() {
                    OldEntry::LinkPending
                } else {
                    OldEntry::Missing
                }
            }
            Err(e) => OldEntry::Other(format!("cannot be read ({e})")),
            Ok(st) if is_link(&st) => match readlink_at(self.old.as_fd(), name) {
                Ok(target) => OldEntry::Link {
                    to_new: names(self.old.as_fd(), &target, self.new_id, name),
                    dir: dir_at(self.old.as_fd(), &target),
                    target,
                },
                Err(e) => OldEntry::Other(format!("cannot be read ({e})")),
            },
            Ok(st) if is_dir(&st) => OldEntry::Dir(ident(st)),
            Ok(_) => OldEntry::Other("is not a directory".into()),
        }
    }

    fn new_entry(&self, name: &OsStr) -> NewEntry {
        match lstat_at(self.new.as_fd(), name) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => NewEntry::Missing,
            Err(e) => NewEntry::Other(format!("cannot be read ({e})")),
            Ok(st) if is_link(&st) => match readlink_at(self.new.as_fd(), name) {
                Ok(target) if target == self.new_path => NewEntry::Marker,
                Ok(target) => NewEntry::Link(dir_at(self.new.as_fd(), &target)),
                Err(e) => NewEntry::Other(format!("cannot be read ({e})")),
            },
            Ok(st) if is_dir(&st) => NewEntry::Dir(ident(st)),
            Ok(_) => NewEntry::Other("is not a directory".into()),
        }
    }
}

/// What to do about a cache, judged from its two paths.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// Answer this.
    Done(Outcome),
    /// Remove the marker a dead move left, and look again.
    ClearMarker,
    /// Link the new path to `target`, where the old link leads.
    Follow(PathBuf),
    /// Move the old directory to the new path.
    Move,
    /// Leave the link a move renamed the directory away without.
    Relink,
}

/// The one table [`relocate`] acts on and [`locate_in`] reads.
fn decide(old: &OldEntry, new: &NewEntry) -> Step {
    use NewEntry as N;
    use OldEntry as O;
    match (old, new) {
        (_, N::Marker) => Step::ClearMarker,
        (O::LinkPending, _) => Step::Relink,
        (O::Other(what), _) => Step::Done(Outcome::Failed(format!("it {what}"))),
        (_, N::Other(what)) => Step::Done(Outcome::Obstructed(what.clone())),
        // Nothing to move, or moved already: a cache cleared from the new path since is
        // made again there by its user.
        (O::Missing, _) | (O::Link { to_new: true, .. }, _) => Step::Done(Outcome::Settled),
        (O::Link { target, .. }, N::Missing) => Step::Follow(target.clone()),
        (O::Link { dir: o, .. }, N::Dir(n) | N::Link(Some(n))) if o.as_ref() == Some(n) => {
            Step::Done(Outcome::Settled)
        }
        (O::Dir(_), N::Missing) => Step::Move,
        (O::Dir(o), N::Link(Some(n))) if o == n => Step::Done(Outcome::Settled),
        (_, N::Link(None)) => Step::Done(Outcome::Obstructed(
            "is a link that does not lead to a directory".into(),
        )),
        (O::Link { .. } | O::Dir(_), N::Dir(_) | N::Link(Some(_))) => Step::Done(Outcome::Both),
    }
}

/// Choose a location without migration: the old path until the cache moved or the new path
/// links to it.
fn locate_in(old_base: &Path, new_base: &Path, name: &str, keep: &[PathBuf]) -> Home {
    let (old, new) = (old_base.join(name), new_base.join(name));
    if keep.iter().any(|k| same_entry(k, &old)) {
        return Home::Old(old);
    }
    let Ok(at) = Opened::open(old_base, new_base, name) else {
        // If either base cannot be opened, prefer an existing old entry.
        return if old.symlink_metadata().is_ok() {
            Home::Old(old)
        } else {
            Home::New(new)
        };
    };
    let n = OsStr::new(name);
    match decide(&at.old_entry(n), &at.new_entry(n)) {
        Step::Move | Step::Follow(_) | Step::ClearMarker => Home::Old(old),
        Step::Done(_) | Step::Relink => Home::New(new),
    }
}

/// Move cache `name` from `old_base` to `new_base` where it is there to move: see the module
/// doc.
fn relocate(old_base: &Path, new_base: &Path, name: &str) -> Outcome {
    // The common cases, with no lock: nothing ever there, or moved already.
    let missing = |p: PathBuf| matches!(p.symlink_metadata(), Err(e) if e.kind() == std::io::ErrorKind::NotFound);
    if missing(old_base.join(name)) && missing(old_base.join(pending(OsStr::new(name)))) {
        return Outcome::Settled;
    }
    if let Ok(at) = Opened::open(old_base, new_base, name) {
        let n = OsStr::new(name);
        if decide(&at.old_entry(n), &at.new_entry(n)) == Step::Done(Outcome::Settled) {
            return Outcome::Settled;
        }
    }
    match relocate_locked(old_base, new_base, name) {
        Ok(outcome) => outcome,
        Err(e) => Outcome::Failed(format!("{e:#}")),
    }
}

fn relocate_locked(old_base: &Path, new_base: &Path, name: &str) -> Result<Outcome> {
    std::fs::create_dir_all(new_base)
        .with_context(|| format!("creating {}", new_base.display()))?;
    let at = Opened::open(old_base, new_base, name)
        .with_context(|| format!("opening {} and {}", old_base.display(), new_base.display()))?;
    let Some(_moving) = move_locks(&at)? else {
        bail!("another vk is moving it");
    };
    let n = OsStr::new(name);
    loop {
        let step = decide(&at.old_entry(n), &at.new_entry(n));
        let done = match &step {
            Step::Done(outcome) => Ok(outcome.clone()),
            Step::ClearMarker => {
                unlink_at(at.new.as_fd(), n).context("removing a dead move's marker")?;
                continue;
            }
            Step::Follow(target) => {
                // A relative link leads from the directory it is in, not from the new one.
                let target = at.old_path.parent().unwrap_or(old_base).join(target);
                symlink_at(&target, at.new.as_fd(), n).map(|()| Outcome::Linked)
            }
            Step::Move => {
                // One a move that died before its rename left: the directory is still here.
                match unlink_at(at.old.as_fd(), &pending(n)) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                        Err(e).context("removing a dead move's pending link")?
                    }
                    _ => {}
                }
                exchange(&at, n)
            }
            Step::Relink => Ok(leave_link(&at, n)),
        };
        return done.with_context(|| format!("{step:?} for {}", at.new_path.display()));
    }
}

/// Exchange the old directory with a link to its new path. Where the filesystem cannot
/// exchange, rename it and make the link after; across filesystems, link the new path to the
/// old directory instead.
fn exchange(at: &Opened, name: &OsStr) -> std::io::Result<Outcome> {
    // Create the link at its own target before the exchange. If interrupted here, the
    // next move recognizes the self-link and removes it.
    symlink_at(&at.new_path, at.new.as_fd(), name)?;
    #[cfg(test)]
    tests::at_exchange(at);
    let exchanged = rename_at(
        at.old.as_fd(),
        name,
        at.new.as_fd(),
        name,
        libc::RENAME_EXCHANGE,
    );
    let Err(e) = exchanged else {
        return Ok(Outcome::Moved);
    };
    unlink_at(at.new.as_fd(), name)?;
    match e.raw_os_error() {
        // Another filesystem: nothing is copied; the old directory stays and the new path
        // leads to it.
        Some(libc::EXDEV) => {
            symlink_at(&at.old_path, at.new.as_fd(), name)?;
            Ok(Outcome::Linked)
        }
        // Without exchange support, rename first, then link. A plain rename replaces at
        // most an empty directory at the new path. The pending marker lets the next move
        // leave the link if this one dies in between.
        Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP) => {
            let pending = pending(name);
            symlink_at(&at.new_path, at.old.as_fd(), &pending)?;
            if let Err(e) = rename_plain(at.old.as_fd(), name, at.new.as_fd(), name) {
                let _ = unlink_at(at.old.as_fd(), &pending);
                return Err(e);
            }
            Ok(leave_link(at, name))
        }
        _ => Err(e),
    }
}

/// In the old base: present while a move that renamed `name` away has yet to link it.
fn pending(name: &OsStr) -> OsString {
    let mut marker = OsString::from(".");
    marker.push(name);
    marker.push(".link");
    marker
}

/// Link the old path to the new one, never replacing what an older binary made there
/// meanwhile, and drop the pending marker.
fn leave_link(at: &Opened, name: &OsStr) -> Outcome {
    let linked = symlink_at(&at.new_path, at.old.as_fd(), name);
    let _ = unlink_at(at.old.as_fd(), &pending(name));
    match linked {
        Ok(()) => Outcome::Moved,
        Err(e) => Outcome::Unlinked(e.to_string()),
    }
}

/// The lock file `name` in `dir`, made if missing, never through a link.
fn open_lock(dir: BorrowedFd<'_>, name: &OsStr) -> Result<vk_fs::LockFile> {
    let c = cstr(name)?;
    // SAFETY: the descriptor is live and the name is NUL-terminated and outlives the call.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("opening {name:?}"));
    }
    // SAFETY: `fd` is a fresh descriptor this call owns.
    Ok(vk_fs::LockFile::new(std::fs::File::from(unsafe {
        OwnedFd::from_raw_fd(fd)
    })))
}

/// Lock both bases: processes may share only one of them. A move holds both across a few
/// system calls. Both acquisitions share one [`MOVE_WAIT`] deadline and return `None` on
/// timeout.
fn move_locks(at: &Opened) -> Result<Option<[vk_fs::LockFile; 2]>> {
    let deadline = Instant::now() + MOVE_WAIT;
    let take = |dir: BorrowedFd<'_>| -> Result<Option<vk_fs::LockFile>> {
        let file = open_lock(dir, OsStr::new(MOVE_LOCK))?;
        loop {
            // SAFETY: the fd is owned by `file`, open across the call; LOCK_NB never waits.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Some(file));
            }
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::WouldBlock {
                return Err(e).context("locking the move lock");
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    let [first, second] = lock_order(at)?;
    let Some(first) = take(first)? else {
        return Ok(None);
    };
    let Some(second) = take(second)? else {
        return Ok(None);
    };
    Ok(Some([first, second]))
}

/// The two bases in the order their locks are taken: by identity, so that two movers never
/// wait on each other crosswise, even with their bases swapped.
fn lock_order(at: &Opened) -> Result<[BorrowedFd<'_>; 2]> {
    let old_id = ident(fstat(at.old.as_fd()).context("reading the data base")?);
    let (old, new) = (at.old.as_fd(), at.new.as_fd());
    Ok(if old_id < at.new_id {
        [old, new]
    } else {
        [new, old]
    })
}

/// Whether `a` and `b` name one directory entry: by identity when both exist, else by the
/// identity of their directories and their last names.
fn same_entry(a: &Path, b: &Path) -> bool {
    if let (Ok(x), Ok(y)) = (std::fs::metadata(a), std::fs::metadata(b)) {
        use std::os::unix::fs::MetadataExt;
        return (x.dev(), x.ino()) == (y.dev(), y.ino());
    }
    let parent = |p: &Path| {
        std::path::absolute(p)
            .ok()
            .and_then(|p| Some((p.parent()?.to_path_buf(), p.file_name()?.to_os_string())))
    };
    match (parent(a), parent(b)) {
        (Some((pa, na)), Some((pb, nb))) => na == nb && same_entry_dir(&pa, &pb),
        _ => false,
    }
}

fn same_entry_dir(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(x), Ok(y)) => (x.dev(), x.ino()) == (y.dev(), y.ino()),
        _ => a == b,
    }
}

/// Whether the link text `target`, read in `from`, names entry `name` of the directory
/// `dir`: by the identity of the directory it leads into, so whether or not the entry exists.
fn names(from: BorrowedFd<'_>, target: &Path, dir: Ident, name: &OsStr) -> bool {
    if target.file_name() != Some(name) {
        return false;
    }
    let parent = match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    stat_at(from, parent).is_ok_and(|st| ident(st) == dir)
}

/// The identity of the directory the link text `target`, read in `from`, leads to.
fn dir_at(from: BorrowedFd<'_>, target: &Path) -> Option<Ident> {
    stat_at(from, target).ok().filter(is_dir).map(ident)
}

fn cstr(s: &OsStr) -> std::io::Result<CString> {
    CString::new(s.as_bytes()).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))
}

fn open_dir(path: &Path) -> std::io::Result<OwnedFd> {
    let c = cstr(path.as_os_str())?;
    // SAFETY: the name is NUL-terminated and outlives the call; the descriptor is owned below.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor this call owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn stat_flags(
    dir: BorrowedFd<'_>,
    name: &OsStr,
    flags: libc::c_int,
) -> std::io::Result<libc::stat> {
    let c = cstr(name)?;
    // SAFETY: `stat` is plain old data, for which all-zero bytes are a valid value.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is live, the name NUL-terminated, and `st` writable.
    if unsafe { libc::fstatat(dir.as_raw_fd(), c.as_ptr(), &mut st, flags) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(st)
}

fn lstat_at(dir: BorrowedFd<'_>, name: &OsStr) -> std::io::Result<libc::stat> {
    stat_flags(dir, name, libc::AT_SYMLINK_NOFOLLOW)
}

fn stat_at(dir: BorrowedFd<'_>, path: &Path) -> std::io::Result<libc::stat> {
    stat_flags(dir, path.as_os_str(), 0)
}

fn fstat(fd: BorrowedFd<'_>) -> std::io::Result<libc::stat> {
    stat_flags(fd, OsStr::new(""), libc::AT_EMPTY_PATH)
}

fn ident(st: libc::stat) -> Ident {
    (st.st_dev, st.st_ino)
}

fn is_dir(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

fn is_link(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFLNK
}

fn readlink_at(dir: BorrowedFd<'_>, name: &OsStr) -> std::io::Result<PathBuf> {
    let c = cstr(name)?;
    // One byte more than any target the kernel stores, so a full buffer means a cut one.
    let mut buf = vec![0u8; 4097];
    // SAFETY: the descriptor is live, the name NUL-terminated, and `buf` writable for its length.
    let n = unsafe {
        libc::readlinkat(
            dir.as_raw_fd(),
            c.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    let n = usize::try_from(n).map_err(|_| std::io::Error::last_os_error())?;
    if n >= buf.len() {
        return Err(std::io::Error::from_raw_os_error(libc::ENAMETOOLONG));
    }
    buf.truncate(n);
    Ok(PathBuf::from(OsString::from_vec(buf)))
}

fn symlink_at(target: &Path, dir: BorrowedFd<'_>, name: &OsStr) -> std::io::Result<()> {
    let (t, c) = (cstr(target.as_os_str())?, cstr(name)?);
    // SAFETY: both names are NUL-terminated and outlive the call; the descriptor is live.
    if unsafe { libc::symlinkat(t.as_ptr(), dir.as_raw_fd(), c.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn unlink_at(dir: BorrowedFd<'_>, name: &OsStr) -> std::io::Result<()> {
    let c = cstr(name)?;
    // SAFETY: the descriptor is live and the name NUL-terminated and outlives the call.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// `renameat2(2)`, as the raw system call: not every libc wraps it.
fn rename_at(
    from_dir: BorrowedFd<'_>,
    from: &OsStr,
    to_dir: BorrowedFd<'_>,
    to: &OsStr,
    flags: libc::c_uint,
) -> std::io::Result<()> {
    #[cfg(test)]
    if let Some(errno) = tests::injected() {
        return Err(std::io::Error::from_raw_os_error(errno));
    }
    let (from, to) = (cstr(from)?, cstr(to)?);
    // SAFETY: both names are NUL-terminated and outlive the call; the descriptors are live.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            from_dir.as_raw_fd(),
            from.as_ptr(),
            to_dir.as_raw_fd(),
            to.as_ptr(),
            flags,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// `renameat(2)`, for a kernel or filesystem without `renameat2`'s exchange.
fn rename_plain(
    from_dir: BorrowedFd<'_>,
    from: &OsStr,
    to_dir: BorrowedFd<'_>,
    to: &OsStr,
) -> std::io::Result<()> {
    let (from, to) = (cstr(from)?, cstr(to)?);
    // SAFETY: both names are NUL-terminated and outlive the call; the descriptors are live.
    if unsafe {
        libc::renameat(
            from_dir.as_raw_fd(),
            from.as_ptr(),
            to_dir.as_raw_fd(),
            to.as_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::fs::File;
    use std::os::unix::fs::symlink;

    type Hook = Box<dyn FnOnce(&Opened)>;

    thread_local! {
        /// The errnos the next exchanges fail with, in order.
        static FAIL: RefCell<Vec<i32>> = const { RefCell::new(Vec::new()) };
        /// What another process does between the marker and the exchange.
        static HOOK: RefCell<Option<Hook>> = RefCell::new(None);
    }

    pub(super) fn injected() -> Option<i32> {
        FAIL.with_borrow_mut(|f| (!f.is_empty()).then(|| f.remove(0)))
    }

    pub(super) fn at_exchange(opened: &Opened) {
        if let Some(hook) = HOOK.take() {
            hook(opened);
        }
    }

    fn fail_next(errno: i32) {
        FAIL.with_borrow_mut(|f| f.push(errno));
    }

    /// Isolated data and cache bases. Only the data base exists at first.
    struct Fx {
        root: PathBuf,
        old: PathBuf,
        new: PathBuf,
    }

    impl Fx {
        fn new(tag: &str) -> Fx {
            let root = crate::testtmp::root().join(format!("cachehome-{tag}"));
            let _ = std::fs::remove_dir_all(&root);
            let old = root.join("data/virtkit");
            let new = root.join("cache/virtkit");
            std::fs::create_dir_all(&old).unwrap();
            Fx { root, old, new }
        }

        /// A cache in the data base holding a file.
        fn populate(&self, name: &str) -> PathBuf {
            let dir = self.old.join(name);
            std::fs::create_dir_all(dir.join("blobs")).unwrap();
            std::fs::write(dir.join("blobs/x"), b"cached").unwrap();
            dir
        }

        fn settle(&self, name: &str) -> Home {
            settle(&self.old, &self.new, name, &[])
        }

        fn locate(&self, name: &str) -> Home {
            locate_in(&self.old, &self.new, name, &[])
        }
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path.join("blobs/x")).unwrap()
    }

    fn is_link(path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
    }

    fn is_real_dir(path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
    }

    #[test]
    fn a_fresh_install_uses_the_cache_dir_and_creates_nothing() {
        let b = Fx::new("fresh");
        assert_eq!(b.settle("build"), Home::New(b.new.join("build")));
        assert!(!b.new.exists(), "nothing to move, nothing made");
        assert!(!b.old.join("build").exists());
    }

    #[test]
    fn a_cache_in_the_data_dir_moves_and_leaves_a_link() {
        let b = Fx::new("move");
        let old = b.populate("build");
        assert_eq!(b.locate("build"), Home::Old(old.clone()), "not moved yet");
        assert!(!b.new.exists(), "a look moves nothing");
        assert_eq!(b.settle("build"), Home::New(b.new.join("build")));
        assert!(is_real_dir(&b.new.join("build")));
        assert_eq!(std::fs::read_link(&old).unwrap(), b.new.join("build"));
        assert_eq!(read(&old), "cached", "the old path still reaches the cache");
        assert_eq!(b.locate("build"), Home::New(b.new.join("build")));
        assert_eq!(b.settle("build"), Home::New(b.new.join("build")));
        assert!(is_link(&old) && is_real_dir(&b.new.join("build")));
    }

    /// Clearing the cache dir, or one cache in it, leaves the old path's link dangling: the
    /// new path is used, for its user to make the cache again there, and is never made a link
    /// to itself.
    #[test]
    fn a_cleared_cache_is_made_again_at_the_new_path() {
        let b = Fx::new("cleared");
        let old = b.populate("build");
        assert_eq!(b.settle("build"), Home::New(b.new.join("build")));
        std::fs::remove_dir_all(&b.new).unwrap();
        for _ in 0..2 {
            assert_eq!(b.settle("build"), Home::New(b.new.join("build")));
            assert!(!is_link(&b.new.join("build")));
            std::fs::create_dir_all(b.new.join("build")).unwrap();
            assert!(old.join(".").is_dir(), "the old link leads to it again");
            std::fs::remove_dir_all(b.new.join("build")).unwrap();
        }
    }

    #[test]
    fn a_link_the_user_made_is_followed_not_moved() {
        let b = Fx::new("user-link");
        let elsewhere = b.root.join("elsewhere");
        std::fs::create_dir_all(elsewhere.join("blobs")).unwrap();
        std::fs::write(elsewhere.join("blobs/x"), b"cached").unwrap();
        // absolute
        symlink(&elsewhere, b.old.join("windows")).unwrap();
        assert_eq!(b.locate("windows"), Home::Old(b.old.join("windows")));
        assert_eq!(b.settle("windows"), Home::New(b.new.join("windows")));
        assert_eq!(
            std::fs::read_link(b.new.join("windows")).unwrap(),
            elsewhere
        );
        assert_eq!(
            std::fs::read_link(b.old.join("windows")).unwrap(),
            elsewhere
        );
        assert!(is_real_dir(&elsewhere));
        assert_eq!(b.settle("windows"), Home::New(b.new.join("windows")));
        // relative: resolved from the data dir, not from the cache dir
        symlink("../../elsewhere", b.old.join(REGISTRY)).unwrap();
        assert_eq!(b.settle(REGISTRY), Home::New(b.new.join(REGISTRY)));
        assert_eq!(read(&b.new.join(REGISTRY)), "cached");
        assert_eq!(
            std::fs::read_link(b.old.join(REGISTRY)).unwrap(),
            Path::new("../../elsewhere"),
            "the user's link is left as it was"
        );
    }

    /// Across filesystems nothing is copied: the new path links to the old directory.
    #[test]
    fn another_filesystem_gets_a_link_never_a_copy() {
        let b = Fx::new("exdev");
        let old = b.populate("docker");
        fail_next(libc::EXDEV);
        assert_eq!(b.settle("docker"), Home::New(b.new.join("docker")));
        assert!(is_real_dir(&old), "the data stays where it is");
        assert_eq!(std::fs::read_link(b.new.join("docker")).unwrap(), old);
        assert_eq!(read(&b.new.join("docker")), "cached");
        assert_eq!(b.locate("docker"), Home::New(b.new.join("docker")));
        // Settled from then on: no rename is tried again.
        fail_next(libc::EPERM);
        assert_eq!(b.settle("docker"), Home::New(b.new.join("docker")));
        assert_eq!(FAIL.with_borrow_mut(std::mem::take), [libc::EPERM]);
    }

    /// Where the filesystem cannot exchange, or the kernel has no `renameat2` at all, a plain
    /// rename moves the cache and the link follows; no second `renameat2` is tried.
    #[test]
    fn without_an_exchange_the_cache_is_renamed_then_linked() {
        for errno in [libc::EINVAL, libc::ENOSYS, libc::EOPNOTSUPP] {
            let b = Fx::new(&format!("no-exchange-{errno}"));
            let old = b.populate("build");
            fail_next(errno);
            fail_next(libc::EPERM);
            assert_eq!(b.settle("build"), Home::New(b.new.join("build")));
            assert_eq!(FAIL.with_borrow_mut(std::mem::take), [libc::EPERM]);
            assert!(is_real_dir(&b.new.join("build")));
            assert_eq!(std::fs::read_link(&old).unwrap(), b.new.join("build"));
            assert_eq!(read(&old), "cached");
            assert!(
                !is_link(&b.old.join(".build.link")),
                "no pending marker left"
            );
        }
    }

    /// An interruption after the fallback rename leaves the cache intact at its new path,
    /// and the next move leaves the link it had yet to.
    #[test]
    fn a_move_that_died_before_its_link_keeps_the_cache() {
        let b = Fx::new("unlinked");
        let old = b.populate("build");
        std::fs::create_dir_all(&b.new).unwrap();
        let new = b.new.join("build");
        symlink(&new, b.old.join(".build.link")).unwrap();
        std::fs::rename(&old, &new).unwrap();
        assert_eq!(b.locate("build"), Home::New(new.clone()));
        assert_eq!(b.settle("build"), Home::New(new.clone()));
        assert_eq!(std::fs::read_link(&old).unwrap(), new);
        assert_eq!(read(&old), "cached");
        assert!(!is_link(&b.old.join(".build.link")));
        // Without the marker, nothing says the old path ever held it: nothing is made there.
        let b = Fx::new("unlinked-unmarked");
        let old = b.populate("build");
        std::fs::create_dir_all(&b.new).unwrap();
        std::fs::rename(&old, b.new.join("build")).unwrap();
        assert_eq!(b.settle("build"), Home::New(b.new.join("build")));
        assert!(!is_link(&old));
    }

    /// A pending marker a move left before its rename is cleared, and the move done.
    #[test]
    fn a_pending_marker_before_the_rename_is_cleared() {
        let b = Fx::new("pending-stale");
        let old = b.populate("build");
        std::fs::create_dir_all(&b.new).unwrap();
        symlink(b.new.join("build"), b.old.join(".build.link")).unwrap();
        assert_eq!(b.settle("build"), Home::New(b.new.join("build")));
        assert!(is_link(&old) && is_real_dir(&b.new.join("build")));
        assert!(!is_link(&b.old.join(".build.link")));
    }

    /// A move that died after its marker is taken up again.
    #[test]
    fn a_move_that_died_at_its_marker_is_taken_up_again() {
        let b = Fx::new("crashed");
        let old = b.populate("build");
        std::fs::create_dir_all(&b.new).unwrap();
        let new = b.new.join("build");
        symlink(&new, &new).unwrap();
        assert_eq!(b.locate("build"), Home::Old(old.clone()));
        assert_eq!(b.settle("build"), Home::New(new.clone()));
        assert!(is_real_dir(&new) && is_link(&old));
    }

    /// A move that fails leaves the cache, which is used where it is until a move succeeds.
    #[test]
    fn a_failed_move_leaves_the_cache_where_it_is() {
        let b = Fx::new("failed");
        let old = b.populate("build");
        fail_next(libc::EPERM);
        assert_eq!(b.settle("build"), Home::Old(old.clone()));
        assert!(is_real_dir(&old) && read(&old) == "cached");
        assert!(!b.new.join("build").exists(), "no marker left behind");
        assert_eq!(b.settle("build"), Home::New(b.new.join("build")));
        assert!(is_link(&old));
    }

    /// Two directories: both left, and the new one used.
    #[test]
    fn two_caches_are_both_left_and_the_new_one_used() {
        let b = Fx::new("both");
        let old = b.populate("build");
        std::fs::create_dir_all(b.new.join("build")).unwrap();
        assert_eq!(b.locate("build"), Home::New(b.new.join("build")));
        assert_eq!(b.settle("build"), Home::New(b.new.join("build")));
        assert!(is_real_dir(&old) && is_real_dir(&b.new.join("build")));
        assert_eq!(read(&old), "cached");
    }

    /// A file, or a link to nothing, at the new path is reported, and the old cache left.
    #[test]
    fn an_obstructed_new_path_leaves_the_old_cache_alone() {
        let b = Fx::new("obstructed");
        let old = b.populate("build");
        std::fs::create_dir_all(&b.new).unwrap();
        std::fs::write(b.new.join("build"), b"").unwrap();
        assert_eq!(b.settle("build"), Home::New(b.new.join("build")));
        assert!(is_real_dir(&old) && b.new.join("build").is_file());
        std::fs::remove_file(b.new.join("build")).unwrap();
        symlink(b.root.join("gone"), b.new.join("build")).unwrap();
        assert_eq!(b.settle("build"), Home::New(b.new.join("build")));
        assert_eq!(read(&old), "cached");
    }

    /// Replacing the old base during the exchange leaves the replacement directory untouched.
    #[test]
    fn a_base_renamed_midway_does_not_redirect_the_move() {
        let b = Fx::new("renamed");
        b.populate("build");
        let data = b.old.parent().unwrap().to_path_buf();
        let decoy = b.old.join("build");
        HOOK.set(Some(Box::new(move |_| {
            std::fs::rename(&data, data.with_file_name("data-moved")).unwrap();
            std::fs::create_dir_all(&decoy).unwrap();
        })));
        assert_eq!(b.settle("build"), Home::New(b.new.join("build")));
        assert_eq!(read(&b.new.join("build")), "cached");
        assert!(is_real_dir(&b.old.join("build")), "the decoy is left alone");
        let moved = b.root.join("data-moved/virtkit/build");
        assert_eq!(std::fs::read_link(moved).unwrap(), b.new.join("build"));
    }

    /// The move lock is taken in both bases: a mover sharing only the data base with another
    /// waits for it, and past the wait leaves the cache where it is.
    #[test]
    fn movers_sharing_one_base_wait_for_each_other() {
        let b = Fx::new("move-lock");
        let old = b.populate("build");
        let held = File::create(b.old.join(MOVE_LOCK)).unwrap();
        // SAFETY: the fd is open across the call.
        assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX) }, 0);
        assert!(matches!(
            relocate(&b.old, &b.new, "build"),
            Outcome::Failed(_)
        ));
        assert!(is_real_dir(&old));
        drop(held);
        assert_eq!(relocate(&b.old, &b.new, "build"), Outcome::Moved);
    }

    /// Two movers whose bases are swapped take their locks in one order.
    #[test]
    fn movers_with_swapped_bases_lock_in_one_order() {
        let b = Fx::new("lock-order");
        std::fs::create_dir_all(&b.new).unwrap();
        let first = |old: &Path, new: &Path| {
            let at = Opened::open(old, new, "build").unwrap();
            ident(fstat(lock_order(&at).unwrap()[0]).unwrap())
        };
        assert_eq!(first(&b.old, &b.new), first(&b.new, &b.old));
    }

    /// With one cache left in the data base, its base is used for all of them: one only the
    /// cache base holds is linked there, and one neither holds is left for its user to make.
    #[test]
    fn a_base_left_in_the_data_dir_reaches_every_cache() {
        let b = Fx::new("mixed");
        b.populate("docker");
        std::fs::create_dir_all(b.new.join(REGISTRY)).unwrap();
        std::fs::write(b.new.join(REGISTRY).join("x"), b"new").unwrap();
        fail_next(libc::EPERM);
        let names = [REGISTRY, "docker", "build"];
        assert_eq!(
            resolve_base_in(&b.old, &b.new, &names, &[]),
            Home::Old(b.old.clone())
        );
        assert_eq!(
            std::fs::read(b.old.join(REGISTRY).join("x")).unwrap(),
            b"new"
        );
        assert!(is_real_dir(&b.old.join("docker")));
        assert!(!b.old.join("build").exists() && !is_link(&b.old.join("build")));
        // Once the last one moves, the cache base is used, and the link leads there still.
        assert_eq!(
            resolve_base_in(&b.old, &b.new, &names, &[]),
            Home::New(b.new.clone())
        );
        assert!(is_link(&b.old.join("docker")) && is_link(&b.old.join(REGISTRY)));
    }

    /// What is filled into a line is never scanned again.
    #[test]
    fn a_line_is_filled_in_once() {
        assert_eq!(
            fill(
                "{old} to {new} ({detail}) {x}",
                Path::new("/a{new}"),
                Path::new("/b"),
                "{old}"
            ),
            "/a{new} to /b ({old}) {x}"
        );
    }

    /// A location a configuration names is used where it is.
    #[test]
    fn a_kept_location_is_never_moved() {
        let b = Fx::new("kept");
        let old = b.populate(REGISTRY);
        let keep = [old.clone(), b.old.join("docker")];
        assert_eq!(
            settle(&b.old, &b.new, REGISTRY, &keep),
            Home::Old(old.clone())
        );
        assert_eq!(
            settle(&b.old, &b.new, "docker", &keep),
            Home::Old(b.old.join("docker"))
        );
        assert_eq!(
            locate_in(&b.old, &b.new, REGISTRY, &keep),
            Home::Old(old.clone())
        );
        assert!(is_real_dir(&old) && !b.new.exists());
        let homes = [
            settle(&b.old, &b.new, REGISTRY, &keep),
            settle(&b.old, &b.new, "build", &keep),
        ];
        assert_eq!(
            one_base(b.old.clone(), b.new.clone(), &homes),
            Home::Old(b.old.clone())
        );
    }

    /// Two kinds of outcome for one cache are each said once; the first never hides the other.
    #[test]
    fn each_kind_of_outcome_is_said_once() {
        let b = Fx::new("told");
        let new = b.new.join("build");
        assert!(first_time(Outcome::Moved, &new));
        assert!(!first_time(Outcome::Moved, &new));
        assert!(
            first_time(Outcome::Both, &new),
            "a later warning still shows"
        );
        assert!(first_time(Outcome::Failed("a".into()).kind(), &new));
        assert!(!first_time(Outcome::Failed("b".into()).kind(), &new));
    }

    /// The default store prefers the data directory for each item and reuses state found
    /// only inside the store. Other stores keep their own state.
    #[test]
    fn a_default_store_keeps_its_server_state_in_the_data_dir() {
        let b = Fx::new("server");
        let store = b.new.join(REGISTRY);
        std::fs::create_dir_all(&store).unwrap();
        let named = b.root.join("named");
        assert_eq!(
            server_dir_in(&b.old, &b.new, &named, "accounts"),
            named.join("accounts")
        );
        let kept = b.old.join(SERVER_HOME).join("accounts");
        assert_eq!(server_dir_in(&b.old, &b.new, &store, "accounts"), kept);
        // Through the old path too.
        symlink(&store, b.old.join(REGISTRY)).unwrap();
        assert_eq!(
            server_dir_in(&b.old, &b.new, &b.old.join(REGISTRY), "accounts"),
            kept
        );
        // An older release's, in the store: used there.
        std::fs::create_dir_all(store.join("accounts")).unwrap();
        std::fs::write(store.join("accounts/accounts.db"), b"db").unwrap();
        assert_eq!(
            server_dir_in(&b.old, &b.new, &store, "accounts"),
            store.join("accounts")
        );
        // One in the data dir wins over one an older release made in the store later.
        std::fs::create_dir_all(&kept).unwrap();
        assert_eq!(server_dir_in(&b.old, &b.new, &store, "accounts"), kept);
        // One that cannot be read is not taken for absent: opening it says why.
        // SAFETY: geteuid has no preconditions and cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            use std::os::unix::fs::PermissionsExt;
            let home = b.old.join(SERVER_HOME);
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o000)).unwrap();
            let found = server_dir_in(&b.old, &b.new, &store, "accounts");
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(found, kept);
        }
        // One directory for both bases still keeps the state out of the store.
        let one = b.root.join("one");
        let store = one.join(REGISTRY);
        std::fs::create_dir_all(&store).unwrap();
        assert_eq!(
            server_dir_in(&one, &one, &store, "hub"),
            one.join(SERVER_HOME).join("hub")
        );
    }

    /// A legacy accounts database moves with the default store and remains readable
    /// through either path.
    #[test]
    fn an_accounts_db_an_older_release_kept_survives_the_move() {
        let b = Fx::new("accounts");
        let store = b.populate(REGISTRY);
        let db = crate::accounts::Db::open(&store.join("accounts/accounts.db")).unwrap();
        db.set_repo_caption("team/app", "kept").unwrap();
        drop(db);
        let root = settle(&b.old, &b.new, REGISTRY, &[]).into_path();
        assert_eq!(root, b.new.join(REGISTRY));
        for root in [&root, &store] {
            let found = server_dir_in(&b.old, &b.new, root, "accounts").join("accounts.db");
            assert_eq!(found, root.join("accounts/accounts.db"));
            let db = crate::accounts::Db::open(&found).unwrap();
            assert_eq!(
                db.repo_caption("team/app").unwrap().as_deref(),
                Some("kept")
            );
        }
    }

    /// `serve` of the default store moves the state an older release's server left in it to
    /// the data dir, by one rename; not one a running server holds, nor across filesystems,
    /// nor a store it was given.
    #[test]
    fn a_server_moves_its_state_out_of_the_default_store() {
        let b = Fx::new("adopt");
        let store = b.new.join(REGISTRY);
        for item in SERVER_STATE {
            std::fs::create_dir_all(store.join(item)).unwrap();
            std::fs::write(store.join(item).join("kept"), item).unwrap();
        }
        let named = b.root.join("named");
        std::fs::create_dir_all(named.join("hub")).unwrap();
        adopt_in(&b.old, &b.new, &named);
        assert!(
            is_real_dir(&named.join("hub")),
            "a store it was given keeps its state"
        );

        // The accounts db a running server holds stays; the hub moves.
        let db = store.join("accounts/accounts.db");
        std::fs::write(&db, b"db").unwrap();
        let running = File::open(&db).unwrap();
        // SAFETY: flock(2) on a descriptor `running` keeps open.
        assert_eq!(
            unsafe { libc::flock(running.as_raw_fd(), libc::LOCK_EX) },
            0
        );
        adopt_in(&b.old, &b.new, &store);
        let home = b.old.join(SERVER_HOME);
        assert!(is_real_dir(&store.join("accounts")));
        assert_eq!(
            std::fs::read_to_string(home.join("hub/kept")).unwrap(),
            "hub"
        );
        assert!(!store.join("hub").exists());
        assert_eq!(
            server_dir_in(&b.old, &b.new, &store, "hub"),
            home.join("hub")
        );
        assert_eq!(
            server_dir_in(&b.old, &b.new, &store, "accounts"),
            store.join("accounts")
        );

        // Across filesystems it stays too, then moves once it can.
        drop(running);
        fail_next(libc::EXDEV);
        adopt_in(&b.old, &b.new, &store);
        assert!(is_real_dir(&store.join("accounts")));
        adopt_in(&b.old, &b.new, &store);
        assert!(!store.join("accounts").exists());
        assert_eq!(
            std::fs::read(home.join("accounts/accounts.db")).unwrap(),
            b"db"
        );
        assert_eq!(
            server_dir_in(&b.old, &b.new, &store, "accounts"),
            home.join("accounts")
        );
    }

    #[test]
    fn the_bases_follow_the_xdg_variables_else_home() {
        let env = |vars: &'static [(&'static str, &'static str)]| {
            move |v: &str| {
                vars.iter()
                    .find(|(k, _)| *k == v)
                    .map(|(_, val)| OsString::from(val))
            }
        };
        let home = env(&[("HOME", "/h")]);
        assert_eq!(
            base_in(home, "XDG_DATA_HOME", ".local/share"),
            Some(PathBuf::from("/h/.local/share/virtkit"))
        );
        assert_eq!(
            base_in(home, "XDG_CACHE_HOME", ".cache"),
            Some(PathBuf::from("/h/.cache/virtkit"))
        );
        let xdg = env(&[
            ("HOME", "/h"),
            ("XDG_DATA_HOME", "/d"),
            ("XDG_CACHE_HOME", "/c"),
        ]);
        assert_eq!(
            base_in(xdg, "XDG_DATA_HOME", ".local/share"),
            Some(PathBuf::from("/d/virtkit"))
        );
        assert_eq!(
            base_in(xdg, "XDG_CACHE_HOME", ".cache"),
            Some(PathBuf::from("/c/virtkit"))
        );
        let empty = env(&[("HOME", "/h"), ("XDG_CACHE_HOME", "")]);
        assert_eq!(
            base_in(empty, "XDG_CACHE_HOME", ".cache"),
            Some(PathBuf::from("/h/.cache/virtkit"))
        );
        // Relative values are ignored, as the spec asks.
        let relative = env(&[("HOME", "/h"), ("XDG_CACHE_HOME", "c")]);
        assert_eq!(
            base_in(relative, "XDG_CACHE_HOME", ".cache"),
            Some(PathBuf::from("/h/.cache/virtkit"))
        );
        assert_eq!(
            base_in(env(&[("HOME", "h")]), "XDG_CACHE_HOME", ".cache"),
            None
        );
        assert_eq!(base_in(env(&[]), "XDG_CACHE_HOME", ".cache"), None);
    }

    #[test]
    fn one_directory_for_both_bases_moves_nothing() {
        let b = Fx::new("same");
        assert!(matches!(
            Bases::of(Some(b.old.clone()), Some(b.old.clone())).unwrap(),
            Bases::One(Home::New(_))
        ));
        assert!(Bases::of(None, None).is_err());
    }
}
