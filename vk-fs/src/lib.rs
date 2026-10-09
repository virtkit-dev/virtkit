//! Filesystem objects created private and published whole.
//!
//! The rules this exists to keep in one place, rather than re-derived at each call site:
//!
//! - **Mode at creation, never the umask.** The umask is process-wide, so reaching for it to
//!   set one object's mode sets every file another thread creates meanwhile. Ask `mkdir` and
//!   `open` for the mode instead, and remember a umask can only *clear* what they ask for —
//!   so an object is never laxer than requested, only sometimes stripped of bits it needs.
//! - **Publish by `rename`, never by unlink-then-create.** A reader either sees the old
//!   object or the new one, never the moment in between where the name leads nowhere.
//! - **Resolve a directory once, then work relative to the descriptor.** A pathname is a
//!   question re-asked at every syscall, and the answer can change between two of them; a
//!   descriptor is the answer, kept. See [`open_dir`] and [`openat_dir`].
//! - **Act on a name only where the name cannot become someone else's.** Where that cannot
//!   be established, leave the object rather than remove something unidentified —
//!   [`dir_admits_only_us`] is the test, and it is the caller's directory that decides.
//!
//! [`bind_private`] applies all four to unix sockets; [`write_atomic`] applies the first
//! three to files (and [`write_atomic_unsynced`] too, without the fsync, and [`write_new`],
//! never over an existing name). `vk-core` uses it (as [`bind_private_any_length`]) for the
//! agent's exec channel and `vk-registry` for its admin socket; both require the published
//! name to refer only to a socket already restricted to `0600`.
//!
//! [`open_dir`], [`open_dir_nofollow`] and [`open_dir_in`] expose the third rule to callers
//! that anchor their own `*at()` operations, and [`reopen_dir`] and [`dir_names`] read or lock
//! a directory so held.
//!
//! [`entry_in`] exposes the fourth to callers walking a path, links included: it says whether
//! an entry could have been put there, or swapped since, by another user.
//!
//! [`chown_tree`] keeps the third when root transfers a tree to a user who may already write
//! in it. Entries are opened from their parent's descriptor and changed through their own,
//! so name swaps cannot redirect the changes. [`remove_tree_in`] removes a tree the same way,
//! the very directory its caller opened, a link always as itself, nothing past a mount and
//! nothing another user owns.

use anyhow::{Context, anyhow, bail};
use std::ffi::{CString, OsStr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

/// The `sockaddr_un::sun_path` limit, including its terminator. Public so callers can test
/// the boundary enforced here without duplicating the value.
pub const SUN_PATH_MAX: usize = 108;

/// Staging names to try before giving up. Each is picked afresh, so one being taken takes a
/// remarkable coincidence — or someone who guessed it — and either way the way past is
/// another name rather than clearing a directory this did not make.
const STAGING_ATTEMPTS: u32 = 8;

/// Bind a unix socket that is `0600` from the moment anything can reach it.
/// Requires procfs mounted at `/proc`, whose descriptor links give `bind` a short path to
/// the staging directory without resolving the caller's path again.
///
/// `bind` honours the ambient umask, and neither obvious repair works: `fchmod` on the
/// listener changes the sockfs inode, not the directory entry anyone connects through, and
/// a `chmod` one syscall later leaves the socket connectable — and group-reachable — under
/// its final name in between. Setting the umask around the bind closes that window and opens
/// a worse one: the umask is process-wide, so every file *another thread* creates meanwhile
/// is created with it too, which is how a concurrent writer ends up with unreadable files
/// and directories missing the execute bit.
///
/// So bind inside a `0700` staging directory of its own and rename it onto `path`. The name
/// a client connects to only ever refers to a `0600` socket, and the rename replaces what is
/// at `path` in one step instead of unlinking it first, so the address is never briefly
/// bound to nothing. A *live* server loses the name as readily as a dead one: callers own
/// their socket path, as they did when this unlinked it.
///
/// The directory holding `path` is resolved once, and everything else happens relative to
/// that descriptor — `mkdirat` to make the staging directory, `openat` to enter it, `rename`
/// out of it, `unlinkat` to take it back down. `mkdir`'s `0700` is what makes it private: a
/// umask can only clear bits, so the directory is never laxer, only sometimes stripped of
/// the owner bits it needs to be usable, which an anchored `chmod` puts back.
///
/// Two costs, both borne by the caller's path: it must live in a directory that admits a
/// subdirectory and not just a socket, and where that directory lets other users swap names
/// in it, the staging directory is left behind empty rather than removed by a name that may
/// no longer be this call's — see [`dir_admits_only_us`]. What is left is inert: the next
/// bind picks its own name and never one already standing, so leavings do not accumulate
/// into a bind that fails for a socket path that is free.
pub fn bind_private(path: &Path) -> Result<UnixListener, anyhow::Error> {
    bind_private_from(path, staging_names(), PathLen::MustFit)
}

/// [`bind_private`] at a path of any length. Clients use a directory descriptor
/// (`vk_core::unixpath`); connecting by pathname fails when it exceeds `sun_path`.
pub fn bind_private_any_length(path: &Path) -> Result<UnixListener, anyhow::Error> {
    bind_private_from(path, staging_names(), PathLen::AnyLength)
}

/// Which socket paths [`bind_private_from`] accepts.
#[derive(Clone, Copy)]
enum PathLen {
    /// Only a path clients can pass to `connect` as it is.
    MustFit,
    /// Any, as long as its final name is reachable through a directory descriptor.
    AnyLength,
}

/// Maximum filename length in `/proc/self/fd/<fd>/<name>` for any `i32` descriptor.
/// Reserve the NUL included in [`SUN_PATH_MAX`], the prefix, 10 descriptor digits, and
/// the separator. Mirrors `vk_core::unixpath`, which this crate cannot depend on.
const MAX_NAME_VIA_DIR: usize = SUN_PATH_MAX - 1 - "/proc/self/fd/".len() - 10 - 1;

/// The staging names one bind will try, in order.
///
/// Nothing derived from the pid: a pid is reused — the agent is PID 1 in a fresh namespace
/// on every boot — so a name built from one lands on whatever the last process of that pid
/// left behind. Where those leavings are kept rather than removed (see
/// [`dir_admits_only_us`]) a fixed set of candidates is used up, and a bind fails for a
/// socket path nothing holds. A name picked instead from `/dev/urandom` collides with
/// neither, and costs nothing: what `bind` is called on is the `/proc/self/fd` anchor,
/// never this.
fn staging_names() -> impl FnMut() -> Result<String, anyhow::Error> {
    use std::io::Read;

    || {
        let mut bytes = [0u8; 8];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut bytes))
            .context("reading /dev/urandom for a staging directory name")?;
        Ok(format!(
            ".{}",
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ))
    }
}

/// [`bind_private`] with injectable staging names for collision tests and `len` selecting
/// the paths clients can reach.
fn bind_private_from(
    path: &Path,
    mut next_name: impl FnMut() -> Result<String, anyhow::Error>,
    len: PathLen,
) -> Result<UnixListener, anyhow::Error> {
    let Some(final_name) = path.file_name() else {
        bail!("{path:?} is not a path a socket can be bound at");
    };
    // `bind` sees the short `/proc/self/fd` path; `renameat` sees a descriptor and filename.
    // Neither validates the client's address. Before publishing, check that the full path
    // fits for direct clients, or the filename fits after a directory descriptor otherwise.
    match len {
        PathLen::MustFit => {
            let len = path.as_os_str().len();
            if len >= SUN_PATH_MAX {
                bail!(
                    "{path:?} is too long for a unix socket: it is {len} bytes and \
                     {SUN_PATH_MAX} is the limit — bind it on a shorter path"
                );
            }
        }
        PathLen::AnyLength => {
            let len = final_name.len();
            if len > MAX_NAME_VIA_DIR {
                bail!(
                    "{path:?} cannot be a unix socket: its {len}-byte name is too long to \
                     reach through a directory descriptor, {MAX_NAME_VIA_DIR} is the most"
                );
            }
        }
    }
    let final_name = cstr(final_name)?;
    let parent = path.parent().unwrap_or(Path::new("."));
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    // The one name this resolves. A symlink here is the caller's own arrangement — `/run`
    // for `/var/run` — so it is followed; everything after is relative to what it led to,
    // and no later step can be sent somewhere else by a change to any of these components.
    let parent_fd = open_dir(parent)?;
    let cleanable = dir_admits_only_us(parent_fd.as_fd());
    for _ in 0..STAGING_ATTEMPTS {
        let name = cstr(OsStr::new(&next_name()?))?;
        // SAFETY: both pointers are NUL-terminated and outlive the call.
        if unsafe { libc::mkdirat(parent_fd.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            let e = std::io::Error::last_os_error();
            // Whatever holds this name, this call did not make it, so it is not this call's
            // to clear — deleting one to make room is how a name becomes someone's lever.
            // Take the next name instead.
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(anyhow!(e).context(format!("creating a staging directory in {parent:?}")));
        }
        return publish_into(parent_fd.as_fd(), &name, &final_name, path, cleanable);
    }
    bail!("found no free staging name beside {path:?} in {STAGING_ATTEMPTS} tries")
}

/// Stage a `0600` socket in the directory `name` names under `parent_fd`, rename it onto
/// `final_name` there, and take the staging directory back down when `cleanable` says the
/// name is still this call's to act on.
fn publish_into(
    parent_fd: BorrowedFd<'_>,
    name: &CString,
    final_name: &CString,
    path: &Path,
    cleanable: bool,
) -> Result<UnixListener, anyhow::Error> {
    // Reached through `parent_fd`, and `O_NOFOLLOW` refuses a symlink left in place of the
    // directory just made. `O_PATH` because its mode may not permit an ordinary open: a wide
    // umask can strip the owner bits `mkdir` asked for, and this has to put them back.
    let staging = openat_dir(parent_fd, name);
    let remove_staging = || {
        if cleanable {
            // Cleanup is best-effort: failure leaves only the private, inert directory this
            // call made and cannot invalidate either the published listener or the primary
            // error being returned.
            // SAFETY: the pointer is NUL-terminated and outlives the call.
            let _ =
                unsafe { libc::unlinkat(parent_fd.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
        }
    };
    let staging = match staging {
        Ok(fd) => fd,
        Err(e) => {
            remove_staging();
            return Err(e);
        }
    };
    let anchor = PathBuf::from(format!("/proc/self/fd/{}", staging.as_raw_fd()));
    let staged = anchor.join("s");
    let published = std::fs::set_permissions(&anchor, std::fs::Permissions::from_mode(0o700))
        .with_context(|| {
            format!(
                "accessing the staging directory for {path:?} through {anchor:?} (requires \
                 procfs mounted at /proc)"
            )
        })
        .and_then(|()| {
            let listener = UnixListener::bind(&staged)
                .with_context(|| format!("binding a staged socket for {path:?}"))?;
            std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("restricting the staged socket for {path:?} to 0600"))?;
            // SAFETY: all four arguments are live descriptors and NUL-terminated names.
            let rc = unsafe {
                libc::renameat(
                    staging.as_raw_fd(),
                    c"s".as_ptr(),
                    parent_fd.as_raw_fd(),
                    final_name.as_ptr(),
                )
            };
            if rc != 0 {
                return Err(anyhow!(std::io::Error::last_os_error())
                    .context(format!("publishing the socket at {path:?}")));
            }
            Ok(listener)
        });
    // A staged socket the rename never moved, unlinked through the staging descriptor so
    // nothing outside the directory this call made is ever named.
    // On success the rename already moved this name; on failure this is best-effort cleanup
    // that must not hide the more useful publication error.
    // SAFETY: the descriptor is live and the name is NUL-terminated.
    let _ = unsafe { libc::unlinkat(staging.as_raw_fd(), c"s".as_ptr(), 0) };
    remove_staging();
    published
}

/// Whether the directory `fd` refers to admits its entries being swapped by another user —
/// the question every removal by name turns on, since a name proves nothing about what it
/// leads to by the time it is used.
///
/// Two ways it cannot. No group or other write, so no one else may touch the names at all;
/// or the sticky bit, where an entry may only be removed or renamed by whoever made it. Both
/// need the directory itself to belong to this user or to root, since its owner is bound by
/// neither. `/run/<user>` is the first, `/tmp` the second. Anything else — a directory
/// shared with another user, or belonging to one — is answered `false`, and the staging
/// directory is then left in place rather than removed through a name that may have become
/// someone else's.
fn dir_admits_only_us(fd: BorrowedFd<'_>) -> bool {
    // SAFETY: `stat` is plain old data, for which all-zero bytes are a valid value.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is open for the borrow and `st` is a writable `stat`.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return false;
    }
    // The *effective* id: it is what the kernel checks when this creates and removes.
    // SAFETY: `geteuid` reads this process's own id and cannot fail.
    admits_only(st.st_uid, st.st_mode, None, unsafe { libc::geteuid() })
}

/// Shared ownership rule for [`dir_admits_only_us`] and [`entry_in`], given the directory's
/// owner and mode and the effective user `ours`. `entry` is an existing entry's owner, or
/// `None` for an entry this user will create. In a sticky directory, another user cannot
/// move this user's entry, but can replace their own.
fn admits_only(
    dir_uid: libc::uid_t,
    dir_mode: libc::mode_t,
    entry: Option<libc::uid_t>,
    ours: libc::uid_t,
) -> bool {
    let by_us_or_root = |uid| uid == ours || uid == 0;
    by_us_or_root(dir_uid)
        && (dir_mode & (libc::S_IWGRP | libc::S_IWOTH) == 0
            || dir_mode & libc::S_ISVTX != 0 && entry.is_none_or(by_us_or_root))
}

/// A name [`entry_in`] found.
#[derive(Debug)]
pub struct Entry {
    /// What the entry says, unresolved, when it is a symlink.
    pub link: Option<PathBuf>,
    /// Whether no other user can have put the entry there or swap it for another: its
    /// directory belongs to this user or root and either no one else may write it, or it is
    /// sticky and the entry belongs to this user or root. `false` means what the name leads
    /// to is anyone's choice.
    pub ours: bool,
}

/// The entry at `name` in the directory `dir`, without following it: whether another user can
/// have made or swapped it, and, for a symlink, its target. `name` is one name: not empty, `.`
/// or `..`, and without a `/`.
///
/// Type, owner and target all come from one descriptor on the entry itself, so a swap between
/// the questions cannot pair one link's owner with another's target.
pub fn entry_in(dir: BorrowedFd<'_>, name: &OsStr) -> Result<Entry, anyhow::Error> {
    if name == "." || name == ".." {
        bail!("{name:?} is not an entry of its own");
    }
    let c_name = one_name(name)?;
    // SAFETY: the descriptor is live and the name is NUL-terminated and outlives the call.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c_name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(anyhow!(std::io::Error::last_os_error()).context(format!("opening {name:?}")));
    }
    // SAFETY: `fd` is a fresh descriptor this call owns.
    let entry = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: `stat` is plain old data, for which all-zero bytes are a valid value.
    let (mut st, mut dir_st): (libc::stat, libc::stat) = unsafe { std::mem::zeroed() };
    // SAFETY: `entry` is open and `st` is a writable `stat`.
    let entry_stat = unsafe { libc::fstat(entry.as_raw_fd(), &mut st) };
    // SAFETY: `dir` is open for the borrow and `dir_st` is a writable `stat`.
    if entry_stat != 0 || unsafe { libc::fstat(dir.as_raw_fd(), &mut dir_st) } != 0 {
        return Err(
            anyhow!(std::io::Error::last_os_error()).context(format!("inspecting {name:?}"))
        );
    }
    // SAFETY: `geteuid` reads this process's own id and cannot fail.
    let ours = admits_only(dir_st.st_uid, dir_st.st_mode, Some(st.st_uid), unsafe {
        libc::geteuid()
    });
    if st.st_mode & libc::S_IFMT != libc::S_IFLNK {
        return Ok(Entry { link: None, ours });
    }
    // One byte more than any target the kernel stores, so a full buffer means a truncated one.
    let mut buf = vec![0u8; 4097];
    // SAFETY: the descriptor is live, the empty name is NUL-terminated, and `buf` is writable
    // for its whole length. An empty name reads the link the descriptor itself is on.
    let n = unsafe {
        libc::readlinkat(
            entry.as_raw_fd(),
            c"".as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    let Ok(n) = usize::try_from(n) else {
        return Err(
            anyhow!(std::io::Error::last_os_error()).context(format!("reading the link {name:?}"))
        );
    };
    if n >= buf.len() {
        bail!("the link {name:?} is longer than a path can be");
    }
    buf.truncate(n);
    Ok(Entry {
        link: Some(PathBuf::from(std::ffi::OsString::from_vec(buf))),
        ours,
    })
}

/// `name` as a NUL-terminated string, refused unless it is one name: not empty, and without
/// a `/` that would make the kernel walk further than the directory given.
fn one_name(name: &OsStr) -> Result<CString, anyhow::Error> {
    if name.is_empty() || name.as_bytes().contains(&b'/') {
        bail!("{name:?} is not a single name");
    }
    cstr(name)
}

/// A path as a NUL-terminated string, for the `libc` calls that take one.
fn cstr(name: &OsStr) -> Result<CString, anyhow::Error> {
    CString::new(name.as_bytes()).with_context(|| format!("{name:?} has an interior NUL"))
}

/// Open a directory as an `O_PATH` descriptor: a location to resolve from, whose own mode
/// cannot refuse the open the way an `O_RDONLY` one would.
///
/// A final symlink is followed to support caller-provided layouts such as `/var/run` → `/run`.
/// Use [`open_dir_nofollow`] where such a link means something has gone wrong.
///
/// `O_PATH` cannot travel through `OpenOptions::custom_flags` on musl, which defines
/// `O_ACCMODE` as `03|O_SEARCH` with `O_SEARCH == O_PATH`: std masks custom flags with
/// `!O_ACCMODE`, dropping the bit, and what runs is an ordinary `O_RDONLY` open — the one
/// thing a directory missing its read bit refuses.
pub fn open_dir(dir: &Path) -> Result<OwnedFd, anyhow::Error> {
    open_dir_flags(dir, 0)
}

/// [`open_dir`], refusing a symlink at the final component.
///
/// `O_DIRECTORY` is what makes it refuse: `O_PATH | O_NOFOLLOW` alone would hand back a
/// descriptor on the link itself rather than failing.
pub fn open_dir_nofollow(dir: &Path) -> Result<OwnedFd, anyhow::Error> {
    open_dir_flags(dir, libc::O_NOFOLLOW)
}

fn open_dir_flags(dir: &Path, extra: libc::c_int) -> Result<OwnedFd, anyhow::Error> {
    let c_dir = cstr(dir.as_os_str())?;
    // SAFETY: the pointer is NUL-terminated and outlives the call; the descriptor it returns
    // is handed straight to `OwnedFd`, which closes it.
    let fd = unsafe {
        libc::open(
            c_dir.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | extra,
        )
    };
    if fd < 0 {
        return Err(anyhow!(std::io::Error::last_os_error()).context(format!("opening {dir:?}")));
    }
    // SAFETY: `fd` is a fresh descriptor this call owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Write `contents` at `path` through a private staging file in the same directory and
/// publish it by `rename`: a reader sees the previous file or the whole new one, never a
/// half-written one, and the mode is right from the moment the file exists.
///
/// All operations use one directory descriptor, so path changes cannot redirect them.
/// Each staging name comes from `/dev/urandom`; `O_EXCL` skips occupied names without
/// removing them, as in [`bind_private`]. On failure, cleanup unlinks the staging name
/// without [`dir_admits_only_us`]: it runs only on errors, and callers here own the directory.
///
/// The directory is not fsynced: the file's own contents are, so a crash between the two
/// costs the rename, not the data. Callers that need the name itself to survive a power cut
/// want more than this.
pub fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> Result<(), anyhow::Error> {
    write_atomic_from(
        path,
        contents,
        mode,
        Durability::Synced,
        Publish::Replace,
        staging_names(),
    )
}

/// [`write_atomic`] without the fsync, for a file nothing needs after a crash: a reader still
/// sees the previous file or the whole new one, but after a power cut the name may hold the
/// old file, the new one, an empty or partly written one, or nothing — a reader must treat
/// what it cannot parse as absent.
pub fn write_atomic_unsynced(path: &Path, contents: &[u8], mode: u32) -> Result<(), anyhow::Error> {
    write_atomic_from(
        path,
        contents,
        mode,
        Durability::Unsynced,
        Publish::Replace,
        staging_names(),
    )
}

/// [`write_atomic`] where nothing is at `path` yet: publishing fails, with
/// [`std::io::ErrorKind::AlreadyExists`] in the chain, when something is — a file, a
/// directory, a symlink — and leaves it as it was. For a file that must never replace
/// another, such as a key.
///
/// Unlike [`write_atomic`], it fsyncs the directory once the name is published, so the name
/// survives a crash once this returns — as far as the filesystem honours a directory fsync,
/// which is attempted but not required to succeed.
pub fn write_new(path: &Path, contents: &[u8], mode: u32) -> Result<(), anyhow::Error> {
    write_atomic_from(
        path,
        contents,
        mode,
        Durability::Synced,
        Publish::NoReplace,
        staging_names(),
    )
}

/// Whether [`write_atomic_from`] fsyncs the staged file before publishing it.
#[derive(Clone, Copy)]
enum Durability {
    Synced,
    Unsynced,
}

/// Whether [`write_atomic_from`] publishes over what is at the path.
#[derive(Clone, Copy)]
enum Publish {
    Replace,
    NoReplace,
}

fn write_atomic_from(
    path: &Path,
    contents: &[u8],
    mode: u32,
    durability: Durability,
    publish: Publish,
    mut next_name: impl FnMut() -> Result<String, anyhow::Error>,
) -> Result<(), anyhow::Error> {
    let Some(final_name) = path.file_name() else {
        bail!("{path:?} is not a path a file can be written at");
    };
    let final_name = cstr(final_name)?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let parent_fd = open_dir(parent.unwrap_or(Path::new(".")))?;
    for _ in 0..STAGING_ATTEMPTS {
        let name = cstr(OsStr::new(&next_name()?))?;
        // SAFETY: the descriptor is live and the name is NUL-terminated and outlives the
        // call. `O_EXCL` is what makes the file this call's own — a symlink included.
        let fd = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                libc::c_uint::from(mode),
            )
        };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            // Skip existing names without removing them.
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(anyhow!(e).context(format!("staging a file for {path:?}")));
        }
        // SAFETY: `fd` is a fresh descriptor this call owns.
        let mut staged = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
        let written = std::io::Write::write_all(&mut staged, contents)
            .and_then(|()| match durability {
                Durability::Synced => staged.sync_all(),
                Durability::Unsynced => Ok(()),
            })
            .map_err(|e| anyhow!(e).context(format!("writing the staged file for {path:?}")))
            .and_then(|()| {
                let published = match publish {
                    Publish::Replace => {
                        // SAFETY: the descriptor is live and both names are NUL-terminated.
                        let rc = unsafe {
                            libc::renameat(
                                parent_fd.as_raw_fd(),
                                name.as_ptr(),
                                parent_fd.as_raw_fd(),
                                final_name.as_ptr(),
                            )
                        };
                        if rc == 0 {
                            Ok(())
                        } else {
                            Err(std::io::Error::last_os_error())
                        }
                    }
                    Publish::NoReplace => rename_noreplace(parent_fd.as_fd(), &name, &final_name)
                        .map(|()| sync_dir(parent_fd.as_fd())),
                };
                published.map_err(|e| anyhow!(e).context(format!("publishing {path:?}")))
            });
        if written.is_err() {
            // Best effort on the error path, through the descriptor this call opened the
            // directory with. It removes by name, which is safe here because the callers own
            // the directory; a shared one would want the `dir_admits_only_us` guard.
            // SAFETY: the descriptor is live and the name is NUL-terminated.
            let _ = unsafe { libc::unlinkat(parent_fd.as_raw_fd(), name.as_ptr(), 0) };
        }
        return written;
    }
    bail!("found no free staging name beside {path:?} in {STAGING_ATTEMPTS} tries")
}

/// Rename `from` to `to` in `dir` unless something is at `to`, failing with
/// [`std::io::ErrorKind::AlreadyExists`] if it is. Where the filesystem has no
/// `RENAME_NOREPLACE` (NFS, some FUSE), [`link_noreplace`] does the same.
fn rename_noreplace(dir: BorrowedFd<'_>, from: &CString, to: &CString) -> std::io::Result<()> {
    // SAFETY: the descriptor is live and both names are NUL-terminated. The raw syscall: not
    // every libc wraps `renameat2`.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            dir.as_raw_fd(),
            from.as_ptr(),
            dir.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP) => link_noreplace(dir, from, to),
        _ => Err(e),
    }
}

/// [`rename_noreplace`] by `linkat`, which never replaces, then unlinking `from`. Not atomic
/// as a rename is: if the unlink fails, `to` is published but `from` stays behind as a second
/// name for it, which is left rather than reported, since `to` is what the caller asked for.
fn link_noreplace(dir: BorrowedFd<'_>, from: &CString, to: &CString) -> std::io::Result<()> {
    // SAFETY: the descriptor is live and both names are NUL-terminated.
    let rc = unsafe {
        libc::linkat(
            dir.as_raw_fd(),
            from.as_ptr(),
            dir.as_raw_fd(),
            to.as_ptr(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: as above.
    let _ = unsafe { libc::unlinkat(dir.as_raw_fd(), from.as_ptr(), 0) };
    Ok(())
}

/// Best-effort fsync of the directory `dir` (an `O_PATH` descriptor, which `fsync` refuses,
/// hence the reopen), so names published in it survive a crash.
fn sync_dir(dir: BorrowedFd<'_>) {
    // SAFETY: the descriptor is live and the name is a NUL-terminated literal.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd >= 0 {
        // SAFETY: `fd` is a fresh descriptor this call owns.
        let _ = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) }).sync_all();
    }
}

/// [`open_dir_nofollow`] for one name in an already-open directory, so the directory is not
/// re-resolved: a symlink there is refused, not followed. `..` opens the directory's parent,
/// as the kernel sees it at the time — across a mount point, the parent of where it is
/// mounted; `/` is its own. `name` is one name: not empty, and without a `/`.
pub fn open_dir_in(dir: BorrowedFd<'_>, name: &OsStr) -> Result<OwnedFd, anyhow::Error> {
    openat_dir_raw(dir, &one_name(name)?)
        .map_err(|e| anyhow!(e).context(format!("opening {name:?}")))
}

/// Reopen `dir` for listing or `flock`, which an `O_PATH` descriptor from [`open_dir_in`]
/// cannot support. Opening `.` relative to `dir` preserves its inode even if its name changes.
pub fn reopen_dir(dir: BorrowedFd<'_>) -> Result<OwnedFd, anyhow::Error> {
    open_listing(dir).map_err(|e| anyhow!(e).context("reopening a directory to read it"))
}

/// List `dir` excluding `.` and `..`. Read through a separate descriptor ([`reopen_dir`]),
/// allowing `dir` to be an `O_PATH` descriptor.
pub fn dir_names(dir: BorrowedFd<'_>) -> Result<Vec<std::ffi::OsString>, anyhow::Error> {
    let listing = reopen_dir(dir)?;
    list_dir(&listing).context("listing a directory")
}

/// [`open_dir_in`] for the staging directory [`publish_into`] just made.
fn openat_dir(parent: BorrowedFd<'_>, name: &CString) -> Result<OwnedFd, anyhow::Error> {
    openat_dir_raw(parent, name)
        .map_err(|e| anyhow!(e).context(format!("opening the staging directory {name:?}")))
}

fn openat_dir_raw(parent: BorrowedFd<'_>, name: &CString) -> std::io::Result<OwnedFd> {
    // SAFETY: the descriptor is live and the name is NUL-terminated and outlives the call.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor this call owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// What [`chown_tree`] did.
#[derive(Debug, Default)]
pub struct ChownTree {
    /// Entries whose owner changed.
    pub changed: u64,
    /// Entries left as they are, whoever owns them: files also linked from outside the tree,
    /// and mount roots and entries on another device, which are not entered either.
    pub skipped: Vec<PathBuf>,
}

/// Transfer `dir` and its contents to `uid` as root, for the user who will run in it.
/// The user may already be writing there. Leave groups unchanged.
///
/// Nothing past `dir` is resolved by path, and `dir` itself is refused if it is a symlink.
/// Each entry is opened `O_PATH | O_NOFOLLOW` from its already-open parent, and the inode that
/// descriptor holds is the one inspected, changed and, for a directory, entered, so a name
/// swapped mid-walk cannot steer the change elsewhere. A symlink is changed itself, never what
/// it names.
///
/// A non-directory with more than one link is changed only once the walk has found as many
/// of its names in the tree as it has links; until then its descriptor is held, so its inode
/// number cannot pass to another file. One still short at the end is also linked from outside
/// and is left alone and reported, as is one past the first 256 such inodes held at once.
/// Names are counted as the walk opens them, so a user who moves a link it made ahead of the
/// walk counts it twice. That is only allowed with `fs.protected_hardlinks` set to 1, which
/// lets a user link only files it owns or can already read and write: the most such a move
/// wins is ownership of one of those. When the setting reads otherwise, or cannot be read,
/// every multiply-linked file is left alone and reported.
///
/// Entries on another device and mount roots, bind mounts of the same filesystem included,
/// are neither changed nor entered; mount roots are told by `STATX_ATTR_MOUNT_ROOT`, which
/// kernels before 5.8 do not report, leaving the device check alone there.
///
/// The walk recurses holding one directory descriptor per level besides the linked inodes
/// it holds, and fails on a tree nested deeper than 512 levels, which keeps it within the
/// usual 1024-descriptor limit and the stack.
pub fn chown_tree(dir: &Path, uid: u32) -> Result<ChownTree, anyhow::Error> {
    let protected =
        std::fs::read_to_string("/proc/sys/fs/protected_hardlinks").is_ok_and(|v| v.trim() == "1");
    chown_tree_linked(dir, uid, protected)
}

/// [`chown_tree`], changing multiply-linked files only when `links_protected` says
/// `fs.protected_hardlinks` is on.
fn chown_tree_linked(
    dir: &Path,
    uid: u32,
    links_protected: bool,
) -> Result<ChownTree, anyhow::Error> {
    let c_dir = cstr(dir.as_os_str())?;
    // SAFETY: the path is NUL-terminated and outlives the call.
    let fd = unsafe {
        libc::open(
            c_dir.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(
            anyhow!(std::io::Error::last_os_error()).context(format!("opening {}", dir.display()))
        );
    }
    // SAFETY: `fd` is a fresh descriptor this call owns.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let st = statx_fd(fd.as_fd()).with_context(|| format!("inspecting {}", dir.display()))?;
    let mut walk = ChownWalk {
        uid,
        dev: (st.stx_dev_major, st.stx_dev_minor),
        done: ChownTree::default(),
        links_protected,
        linked: std::collections::HashMap::new(),
    };
    if st.stx_uid != uid {
        walk.chown(fd.as_fd())
            .with_context(|| format!("chowning {}", dir.display()))?;
    }
    walk.entries(fd, dir, 1)?;
    let ChownWalk {
        mut done, linked, ..
    } = walk;
    let mut outside: Vec<PathBuf> = linked.into_values().map(|l| l.path).collect();
    outside.sort();
    done.skipped.extend(outside);
    Ok(done)
}

/// How many directory levels below its root [`chown_tree`] enters, one descriptor each.
const CHOWN_TREE_MAX_DEPTH: usize = 512;

/// How many multiply-linked inodes [`chown_tree`] holds open at once, waiting for their other
/// names. With [`CHOWN_TREE_MAX_DEPTH`], 256 descriptors short of the usual soft limit of
/// 1024, for the caller's own.
const CHOWN_TREE_MAX_LINKED: usize = 256;

/// [`chown_tree`]'s state across the walk.
struct ChownWalk {
    uid: u32,
    /// The root's device, which the walk does not leave.
    dev: (u32, u32),
    done: ChownTree,
    /// Whether multiply-linked files may change at all: see [`chown_tree`].
    links_protected: bool,
    /// Multiply-linked inodes by inode number, held until all their names are found.
    linked: std::collections::HashMap<u64, Linked>,
}

/// A multiply-linked inode whose names [`chown_tree`] has only partly found.
struct Linked {
    /// Holds the inode, so its number stays its own.
    _fd: OwnedFd,
    seen: u32,
    /// The first name found, for the report.
    path: PathBuf,
}

impl ChownWalk {
    /// Give the inode `fd` holds to the walk's user, a symlink included, and count it.
    fn chown(&mut self, fd: BorrowedFd<'_>) -> std::io::Result<()> {
        // SAFETY: `fd` is open and the empty name NUL-terminated; with `AT_EMPTY_PATH` the
        // change lands on the inode `fd` holds. -1 leaves the group as it is.
        let rc = unsafe {
            libc::fchownat(
                fd.as_raw_fd(),
                c"".as_ptr(),
                self.uid,
                libc::gid_t::MAX,
                libc::AT_EMPTY_PATH,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        self.done.changed += 1;
        Ok(())
    }

    /// Whether the inode `entry` holds, inspected as `st`, has had all its names found, the
    /// one at `path` included. Its descriptor is kept until then.
    fn all_links_found(&mut self, entry: OwnedFd, st: &Statx, path: PathBuf) -> bool {
        use std::collections::hash_map::Entry;
        if !self.links_protected {
            self.done.skipped.push(path);
            return false;
        }
        let held = self.linked.len();
        let seen = match self.linked.entry(st.stx_ino) {
            Entry::Occupied(mut linked) => {
                linked.get_mut().seen += 1;
                linked.get().seen
            }
            Entry::Vacant(_) if held >= CHOWN_TREE_MAX_LINKED => {
                self.done.skipped.push(path);
                return false;
            }
            Entry::Vacant(slot) => {
                slot.insert(Linked {
                    _fd: entry,
                    seen: 1,
                    path,
                });
                1
            }
        };
        // `st` is this name's fresh inspection, so a link added or removed since the inode
        // was first found counts.
        if seen < st.stx_nlink {
            return false;
        }
        self.linked.remove(&st.stx_ino);
        true
    }

    /// Walk the open directory `dir`; use `path` only for errors and the report.
    fn entries(&mut self, dir: OwnedFd, path: &Path, depth: usize) -> Result<(), anyhow::Error> {
        if depth > CHOWN_TREE_MAX_DEPTH {
            bail!(
                "{} is nested deeper than {CHOWN_TREE_MAX_DEPTH} levels",
                path.display()
            );
        }
        let fail = |e: std::io::Error, what: &str, name: &OsStr| {
            anyhow!(e).context(format!("{what} {}", path.join(name).display()))
        };
        // The names first, then the changes: the stream is closed before descending, so the
        // walk holds one directory stream at a time however deep the tree, and one descriptor
        // per level.
        let names = list_dir(&dir).with_context(|| format!("listing {}", path.display()))?;
        for name in names {
            let c_name = one_name(&name)?;
            // SAFETY: the descriptor is live and the name NUL-terminated.
            let fd = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    c_name.as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                let e = std::io::Error::last_os_error();
                // Gone since the listing: nothing left to hand over.
                if e.raw_os_error() == Some(libc::ENOENT) {
                    continue;
                }
                return Err(fail(e, "opening", &name));
            }
            // SAFETY: `fd` is a fresh descriptor this call owns.
            let entry = unsafe { OwnedFd::from_raw_fd(fd) };
            let st = statx_fd(entry.as_fd()).map_err(|e| fail(e, "inspecting", &name))?;
            let is_dir = u32::from(st.stx_mode) & libc::S_IFMT == libc::S_IFDIR;
            let mount_root =
                st.stx_attributes_mask & st.stx_attributes & STATX_ATTR_MOUNT_ROOT != 0;
            if (st.stx_dev_major, st.stx_dev_minor) != self.dev || mount_root {
                self.done.skipped.push(path.join(&name));
                continue;
            }
            if !is_dir && st.stx_nlink > 1 {
                // Changed through this name's descriptor, the same inode as the one held.
                let dup = entry.try_clone().map_err(|e| fail(e, "holding", &name))?;
                if self.all_links_found(dup, &st, path.join(&name)) && st.stx_uid != self.uid {
                    self.chown(entry.as_fd())
                        .map_err(|e| fail(e, "chowning", &name))?;
                }
                continue;
            }
            if st.stx_uid != self.uid {
                self.chown(entry.as_fd())
                    .map_err(|e| fail(e, "chowning", &name))?;
            }
            if is_dir {
                // `.` from `entry` is the directory just inspected, whatever its name says now.
                // SAFETY: `entry` is open and the name NUL-terminated.
                let fd = unsafe {
                    libc::openat(
                        entry.as_raw_fd(),
                        c".".as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(fail(std::io::Error::last_os_error(), "opening", &name));
                }
                // SAFETY: `fd` is a fresh descriptor this call owns.
                let sub = unsafe { OwnedFd::from_raw_fd(fd) };
                drop(entry);
                self.entries(sub, &path.join(&name), depth + 1)?;
            }
        }
        Ok(())
    }
}

/// What [`remove_tree_in`] did.
#[derive(Debug, Default)]
pub struct RemoveTree {
    /// Disk space the removed entries held, in bytes. A file also linked from elsewhere, whose
    /// space stays in use, is not counted.
    pub bytes: u64,
    /// Entries left in place, relative to the parent: mount roots, entries on another device
    /// and entries another user owns, none of which is entered either. The directories above
    /// one are left too.
    pub skipped: Vec<PathBuf>,
}

/// How many directory levels below its root [`remove_tree_in`] enters, one descriptor each.
const REMOVE_TREE_MAX_DEPTH: usize = 512;

/// Remove the directory `dir`, found as `name` in `parent`, and everything in it, never
/// following a symlink: a link is removed itself, never what it names.
///
/// `dir` is the directory the caller opened as `name` (with [`open_dir_in`], say) and judged
/// removable, and it is the one removed: unless `name` still leads to the same inode, nothing
/// is. The walk lists and enters `dir` itself, never the name again. The final
/// `unlinkat(AT_REMOVEDIR)` is by name, checked against `dir` just before; a directory swapped
/// in between is removed only if it is empty, which is all `AT_REMOVEDIR` takes.
///
/// Nothing past `parent` is resolved by path. Each entry is opened `O_PATH | O_NOFOLLOW` from
/// its already-open parent, and the inode that descriptor holds is the one inspected and, for
/// a directory, entered. Entries are unlinked by name through the parent's descriptor, so a
/// name swapped mid-walk can at most make it remove what was swapped in, never anything
/// outside the tree; a directory goes with `AT_REMOVEDIR`, which takes only an empty one.
///
/// Mount roots, entries on another device (bind mounts of the same filesystem included) and
/// entries another user owns are neither entered nor removed, and the directories holding them
/// stay; all are reported. `dir` itself is refused if it is not a directory, and reported
/// untouched if it is one of those. `name` is one name: not empty, `.` or `..`, and without a
/// `/`.
///
/// The walk recurses holding one directory descriptor per level and fails on a tree nested
/// deeper than 512 levels. An error stops it, leaving what it had not yet removed, and returns
/// no count of what it had.
pub fn remove_tree_in(
    parent: BorrowedFd<'_>,
    name: &OsStr,
    dir: BorrowedFd<'_>,
) -> Result<RemoveTree, anyhow::Error> {
    if name == "." || name == ".." {
        bail!("{name:?} is not an entry of its own");
    }
    let c_name = one_name(name)?;
    let shown = Path::new(name);
    let st = statx_fd(dir).with_context(|| format!("inspecting {}", shown.display()))?;
    if u32::from(st.stx_mode) & libc::S_IFMT != libc::S_IFDIR {
        bail!("{} is not a directory", shown.display());
    }
    still_named(parent, &c_name, &st, shown)?;
    let above = statx_fd(parent).context("inspecting the parent directory")?;
    let mut walk = RemoveWalk {
        dev: (above.stx_dev_major, above.stx_dev_minor),
        // SAFETY: `geteuid` reads this process's own id and cannot fail.
        uid: unsafe { libc::geteuid() },
        done: RemoveTree::default(),
    };
    if walk.foreign(&st) {
        walk.done.skipped.push(shown.to_path_buf());
        return Ok(walk.done);
    }
    let listing = open_listing(dir)
        .map_err(|e| anyhow!(e).context(format!("opening {}", shown.display())))?;
    walk.entries(listing, shown, 1)?;
    if walk.done.skipped.is_empty() {
        still_named(parent, &c_name, &st, shown)?;
        walk.unlink(parent, &c_name, &st, shown)?;
    }
    Ok(walk.done)
}

/// Refuse unless `name` in `parent` is, unfollowed, the inode inspected as `st`.
fn still_named(
    parent: BorrowedFd<'_>,
    name: &CString,
    st: &Statx,
    shown: &Path,
) -> Result<(), anyhow::Error> {
    let entry = openat_entry(parent, name)
        .map_err(|e| anyhow!(e).context(format!("opening {}", shown.display())))?;
    let now = statx_fd(entry.as_fd()).with_context(|| format!("inspecting {}", shown.display()))?;
    let id = |s: &Statx| (s.stx_dev_major, s.stx_dev_minor, s.stx_ino);
    if id(&now) != id(st) {
        bail!("{} is no longer the directory opened", shown.display());
    }
    Ok(())
}

/// [`remove_tree_in`]'s state across the walk.
struct RemoveWalk {
    /// The device of the tree's parent, which the walk does not leave.
    dev: (u32, u32),
    /// This user, the only one whose entries the walk removes.
    uid: u32,
    done: RemoveTree,
}

impl RemoveWalk {
    /// Whether the inode inspected as `st` is a mount root, on another device, or another
    /// user's.
    fn foreign(&self, st: &Statx) -> bool {
        (st.stx_dev_major, st.stx_dev_minor) != self.dev
            || st.stx_uid != self.uid
            || st.stx_attributes_mask & st.stx_attributes & STATX_ATTR_MOUNT_ROOT != 0
    }

    /// Unlink `name`, inspected as `st`, from `dir` — a directory with `AT_REMOVEDIR` — and
    /// count the space it held. One already gone counts nothing.
    fn unlink(
        &mut self,
        dir: BorrowedFd<'_>,
        name: &CString,
        st: &Statx,
        shown: &Path,
    ) -> Result<(), anyhow::Error> {
        let is_dir = u32::from(st.stx_mode) & libc::S_IFMT == libc::S_IFDIR;
        let flags = if is_dir { libc::AT_REMOVEDIR } else { 0 };
        // SAFETY: the descriptor is live and the name NUL-terminated.
        if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), flags) } != 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENOENT) {
                return Ok(());
            }
            return Err(anyhow!(e).context(format!("removing {}", shown.display())));
        }
        if st.stx_mask & STATX_BLOCKS != 0 && (is_dir || st.stx_nlink <= 1) {
            let bytes = st.stx_blocks.saturating_mul(512);
            self.done.bytes = self.done.bytes.saturating_add(bytes);
        }
        Ok(())
    }

    /// Empty the open directory `dir`; use `path` only for errors and the report.
    fn entries(&mut self, dir: OwnedFd, path: &Path, depth: usize) -> Result<(), anyhow::Error> {
        if depth > REMOVE_TREE_MAX_DEPTH {
            bail!(
                "{} is nested deeper than {REMOVE_TREE_MAX_DEPTH} levels",
                path.display()
            );
        }
        // The names first, then the removals: the stream is closed before descending.
        let names = list_dir(&dir).with_context(|| format!("listing {}", path.display()))?;
        for name in names {
            let c_name = one_name(&name)?;
            let shown = path.join(&name);
            let entry = match openat_entry(dir.as_fd(), &c_name) {
                Ok(entry) => entry,
                // Gone since the listing: nothing left to remove.
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
                Err(e) => return Err(anyhow!(e).context(format!("opening {}", shown.display()))),
            };
            let st = statx_fd(entry.as_fd())
                .with_context(|| format!("inspecting {}", shown.display()))?;
            if self.foreign(&st) {
                self.done.skipped.push(shown);
                continue;
            }
            if u32::from(st.stx_mode) & libc::S_IFMT == libc::S_IFDIR {
                let sub = open_listing(entry.as_fd())
                    .map_err(|e| anyhow!(e).context(format!("opening {}", shown.display())))?;
                drop(entry);
                let skipped = self.done.skipped.len();
                self.entries(sub, &shown, depth + 1)?;
                if self.done.skipped.len() > skipped {
                    continue;
                }
            }
            self.unlink(dir.as_fd(), &c_name, &st, &shown)?;
        }
        Ok(())
    }
}

/// Open the entry `name` in `dir` as an `O_PATH` descriptor on the entry itself, a symlink
/// included.
fn openat_entry(dir: BorrowedFd<'_>, name: &CString) -> std::io::Result<OwnedFd> {
    // SAFETY: the descriptor is live and the name NUL-terminated.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor this call owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Open the directory `entry` holds for listing. `.` from `entry` is the directory already
/// inspected, whatever its name says now.
fn open_listing(entry: BorrowedFd<'_>) -> std::io::Result<OwnedFd> {
    // SAFETY: `entry` is open and the name NUL-terminated.
    let fd = unsafe {
        libc::openat(
            entry.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor this call owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The part of the kernel's `struct statx` (`linux/stat.h`) the tree walks read, padded to the
/// whole struct `statx(2)` writes. `libc` declares it only for musl builds configured with
/// `RUST_LIBC_UNSTABLE_MUSL_V1_2_3`, which virtkit's is not.
#[repr(C)]
struct Statx {
    stx_mask: u32,
    _blksize: u32,
    stx_attributes: u64,
    stx_nlink: u32,
    stx_uid: u32,
    _gid: u32,
    stx_mode: u16,
    _spare0: u16,
    stx_ino: u64,
    _size: u64,
    stx_blocks: u64,
    stx_attributes_mask: u64,
    _times: [u64; 8],
    _rdev: [u32; 2],
    stx_dev_major: u32,
    stx_dev_minor: u32,
    _rest: [u64; 14],
}

const _: () = assert!(std::mem::size_of::<Statx>() == 256);

/// `STATX_TYPE | STATX_MODE | STATX_NLINK | STATX_UID | STATX_INO`: the [`Statx`] fields the
/// walk reads, which a filesystem must report for it to proceed. Spelled out for the same
/// reason as [`Statx`], as is [`STATX_ATTR_MOUNT_ROOT`] (both `linux/stat.h`).
const STATX_NEEDED: u32 = 0x010f;
/// `STATX_BLOCKS`: asked for too, for [`remove_tree_in`]'s count, but not required.
const STATX_BLOCKS: u32 = 0x0400;
const STATX_ATTR_MOUNT_ROOT: u64 = 0x2000;

/// Inspect the inode held by `fd` with `statx(2)`.
fn statx_fd(fd: BorrowedFd<'_>) -> std::io::Result<Statx> {
    let mut buf = std::mem::MaybeUninit::<Statx>::uninit();
    // SAFETY: `fd` is open for the borrow, the empty name is NUL-terminated, and the kernel
    // writes one `struct statx` through `buf`, which is exactly that size.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_statx,
            fd.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            STATX_NEEDED | STATX_BLOCKS,
            buf.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a successful `statx` filled the whole struct.
    let st = unsafe { buf.assume_init() };
    if st.stx_mask & STATX_NEEDED != STATX_NEEDED {
        return Err(std::io::Error::other(
            "statx reported no type, mode, link count, owner or inode number",
        ));
    }
    Ok(st)
}

/// List names in the open directory `dir`, excluding `.` and `..`.
fn list_dir(dir: &OwnedFd) -> std::io::Result<Vec<std::ffi::OsString>> {
    // `fdopendir` takes the descriptor over, so it gets a duplicate of its own.
    let dup = dir.try_clone()?;
    // SAFETY: `dup` is a fresh descriptor whose ownership passes to the stream.
    let stream = unsafe { libc::fdopendir(dup.as_raw_fd()) };
    if stream.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    std::mem::forget(dup);
    let mut names = Vec::new();
    let failed = loop {
        // `readdir` returns null at EOF and on error; errno distinguishes them.
        // SAFETY: errno is this thread's own.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: `stream` is open until the `closedir` below.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let e = std::io::Error::last_os_error();
            break (e.raw_os_error() != Some(0)).then_some(e);
        }
        // SAFETY: a non-null entry's `d_name` is NUL-terminated and valid until the next
        // `readdir` on the stream.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        let name = name.to_bytes();
        if name != b"." && name != b".." {
            names.push(std::ffi::OsString::from_vec(name.to_vec()));
        }
    };
    // SAFETY: `stream` is open, and closing it closes the duplicate it owns.
    unsafe { libc::closedir(stream) };
    match failed {
        Some(e) => Err(e),
        None => Ok(names),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-fs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The tree goes with its links, and nothing a link names; the space counted is the
    /// tree's own, a file also linked from outside excepted. A symlink or a file in the tree's
    /// place is refused.
    #[test]
    fn remove_tree_in_removes_the_tree_and_follows_no_link() {
        let root = scratch("remove-tree");
        let outside = scratch("remove-tree-outside");
        let tree = root.join("tree");
        std::fs::create_dir_all(tree.join("a/b")).unwrap();
        std::fs::write(tree.join("a/b/f"), vec![7u8; 64 * 1024]).unwrap();
        std::fs::write(outside.join("target"), b"x").unwrap();
        std::fs::write(outside.join("shared"), vec![7u8; 64 * 1024]).unwrap();
        std::fs::hard_link(outside.join("shared"), tree.join("shared")).unwrap();
        std::os::unix::fs::symlink(outside.join("target"), tree.join("a/link")).unwrap();
        std::os::unix::fs::symlink(&outside, tree.join("dirlink")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("toplink")).unwrap();
        std::fs::write(root.join("file"), b"x").unwrap();
        let parent = open_dir(&root).unwrap();
        let held = |name: &str| openat_entry(parent.as_fd(), &CString::new(name).unwrap()).unwrap();
        let remove = |name: &str, dir: &OwnedFd| {
            remove_tree_in(parent.as_fd(), OsStr::new(name), dir.as_fd())
        };

        let err = remove("toplink", &held("toplink")).unwrap_err();
        assert!(format!("{err:#}").contains("not a directory"), "{err:#}");
        assert!(remove("file", &held("file")).is_err());
        let dir = open_dir_in(parent.as_fd(), OsStr::new("tree")).unwrap();
        assert!(remove("..", &dir).is_err());
        assert!(remove("a/b", &dir).is_err());

        let done = remove("tree", &dir).unwrap();
        assert!(!tree.exists());
        assert!(done.skipped.is_empty(), "{:?}", done.skipped);
        // The 64 KiB file and the directories, not the file still linked from outside.
        assert!(done.bytes >= 64 * 1024, "{}", done.bytes);
        assert!(done.bytes < 2 * 64 * 1024, "{}", done.bytes);
        assert!(outside.join("target").is_file());
        assert!(outside.join("shared").is_file());
        assert!(root.join("toplink").is_symlink());
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// Only the directory opened goes: once its name leads elsewhere, nothing is removed.
    #[test]
    fn remove_tree_in_refuses_a_name_swapped_since_opened() {
        let root = scratch("remove-tree-swap");
        std::fs::create_dir_all(root.join("tree")).unwrap();
        std::fs::write(root.join("tree/f"), b"x").unwrap();
        let parent = open_dir(&root).unwrap();
        let opened = open_dir_in(parent.as_fd(), OsStr::new("tree")).unwrap();
        std::fs::rename(root.join("tree"), root.join("moved")).unwrap();
        std::fs::create_dir(root.join("tree")).unwrap();
        std::fs::write(root.join("tree/g"), b"x").unwrap();

        let err = remove_tree_in(parent.as_fd(), OsStr::new("tree"), opened.as_fd()).unwrap_err();
        assert!(format!("{err:#}").contains("no longer"), "{err:#}");
        assert!(root.join("tree/g").is_file());
        assert!(root.join("moved/f").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `dir_names` lists through an `O_PATH` descriptor, which cannot be read itself.
    #[test]
    fn dir_names_lists_an_o_path_directory() {
        let root = scratch("dir-names");
        std::fs::write(root.join("a"), b"x").unwrap();
        std::fs::create_dir(root.join("b")).unwrap();
        let dir = open_dir(&root).unwrap();
        let mut names = dir_names(dir.as_fd()).unwrap();
        names.sort();
        assert_eq!(names, ["a", "b"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The tree changes hands, links themselves rather than what they name, a file hard-linked
    /// only within the tree changes with it, one also linked from outside keeps its owner and
    /// is reported, and a final symlink is refused. Changing another user's ownership takes
    /// root, so the root branch is the one that checks the handover; without root only the
    /// no-op of handing the tree to its own owner and the refusal run.
    #[test]
    fn chown_tree_hands_over_the_tree_and_follows_no_link() {
        let dir = scratch("chown-tree");
        let outside = scratch("chown-tree-outside");
        std::fs::create_dir_all(dir.join("a/b")).unwrap();
        std::fs::write(dir.join("a/b/f"), b"x").unwrap();
        std::fs::write(outside.join("target"), b"x").unwrap();
        std::os::unix::fs::symlink(outside.join("target"), dir.join("a/link")).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("dirlink")).unwrap();
        // SAFETY: reads this process's own id.
        let me = unsafe { libc::geteuid() };
        let done = chown_tree(&dir, me).unwrap();
        assert_eq!((done.changed, done.skipped), (0, Vec::<PathBuf>::new()));
        // Without `fs.protected_hardlinks`, a file linked twice within the tree is left too.
        std::fs::write(dir.join("pair"), b"x").unwrap();
        std::fs::hard_link(dir.join("pair"), dir.join("a/pair")).unwrap();
        let mut done = chown_tree_linked(&dir, me, false).unwrap();
        done.skipped.sort();
        assert_eq!(done.skipped, [dir.join("a/pair"), dir.join("pair")]);
        std::fs::remove_file(dir.join("a/pair")).unwrap();
        std::fs::remove_file(dir.join("pair")).unwrap();
        let link = scratch("chown-tree-link");
        std::fs::remove_dir(&link).unwrap();
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert!(chown_tree(&link, me).is_err());
        if me == 0 {
            use std::os::unix::fs::MetadataExt;
            let owner = |p: &Path| std::fs::symlink_metadata(p).unwrap().uid();
            std::fs::write(outside.join("hard"), b"x").unwrap();
            std::fs::hard_link(outside.join("hard"), dir.join("a/hard")).unwrap();
            std::fs::write(dir.join("pair"), b"x").unwrap();
            std::fs::hard_link(dir.join("pair"), dir.join("a/b/pair")).unwrap();
            let done = chown_tree_linked(&dir, 4321, true).unwrap();
            // dir, a, a/b, a/b/f, a/link, dirlink, the pair's inode; not a/hard.
            assert_eq!(done.changed, 7);
            assert_eq!(done.skipped, [dir.join("a/hard")]);
            for p in [
                "", "a", "a/b", "a/b/f", "a/link", "dirlink", "pair", "a/b/pair",
            ] {
                assert_eq!(owner(&dir.join(p)), 4321, "{p}");
            }
            assert_eq!(owner(&outside.join("hard")), 0);
            assert_eq!(owner(&outside.join("target")), 0);
            assert_eq!(owner(&outside), 0);
        }
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// [`open_dir`] follows a symlinked directory; [`open_dir_nofollow`] refuses it.
    #[test]
    fn only_the_nofollow_open_refuses_a_symlinked_directory() {
        let dir = scratch("open-dir-link");
        let real = dir.join("real");
        let link = dir.join("link");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        open_dir(&link).expect("a link to a directory is a layout open_dir follows");
        let err = open_dir_nofollow(&link).unwrap_err();
        assert!(
            format!("{err:#}").contains("Not a directory"),
            "a symlink must be refused as one, not opened: {err:#}"
        );

        // The no-follow variant still opens the directory itself.
        open_dir_nofollow(&real).expect("the directory itself still opens");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [`open_dir_in`] opens one name under a descriptor, refuses a link there, and takes
    /// `..` to the parent — `/` being its own.
    #[test]
    fn opening_a_name_in_a_directory_never_follows_it() {
        use std::os::unix::fs::MetadataExt;
        let dir = scratch("open-dir-in");
        std::fs::create_dir(dir.join("real")).unwrap();
        std::os::unix::fs::symlink("real", dir.join("link")).unwrap();
        let id = |fd: &OwnedFd| {
            let m = std::fs::metadata(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
            (m.dev(), m.ino())
        };
        let path_id = |p: &Path| {
            let m = std::fs::metadata(p).unwrap();
            (m.dev(), m.ino())
        };
        let top = open_dir(&dir).unwrap();

        let real = open_dir_in(top.as_fd(), OsStr::new("real")).unwrap();
        assert_eq!(id(&real), path_id(&dir.join("real")));
        let err = open_dir_in(top.as_fd(), OsStr::new("link")).unwrap_err();
        assert!(format!("{err:#}").contains("\"link\""), "{err:#}");
        assert!(open_dir_in(top.as_fd(), OsStr::new("gone")).is_err());
        let up = open_dir_in(real.as_fd(), OsStr::new("..")).unwrap();
        assert_eq!(id(&up), path_id(&dir));
        let slash = open_dir(Path::new("/")).unwrap();
        let above = open_dir_in(slash.as_fd(), OsStr::new("..")).unwrap();
        assert_eq!(id(&above), path_id(Path::new("/")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The file is created with the mode asked for, published whole over what was there,
    /// and leaves no staging name behind.
    #[test]
    fn writing_publishes_the_whole_file_at_the_mode_asked_for() {
        let dir = scratch("write-atomic");
        let path = dir.join("ssh-config");

        write_atomic(&path, b"first", 0o600).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        write_atomic(&path, b"second", 0o600).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        // Unsynced, the same file the same way, at the mode asked for this time.
        write_atomic_unsynced(&path, b"third", 0o640).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"third");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, [std::ffi::OsString::from("ssh-config")], "{left:?}");

        // A directory that does not exist is reported as such, and nothing is published.
        let err = write_atomic(&dir.join("gone/x"), b"", 0o600).unwrap_err();
        assert!(format!("{err:#}").contains("No such file"), "{err:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Rename replaces an existing symlink without following it.
    #[test]
    fn writing_replaces_a_symlink_rather_than_following_it() {
        let dir = scratch("write-atomic-symlink");
        let decoy = dir.join("decoy");
        std::fs::write(&decoy, b"untouched").unwrap();
        let path = dir.join("ssh-config");
        std::os::unix::fs::symlink(&decoy, &path).unwrap();

        write_atomic(&path, b"published", 0o600).unwrap();
        assert_eq!(std::fs::read(&decoy).unwrap(), b"untouched");
        assert!(!path.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(&path).unwrap(), b"published");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Published whole where the name is free; refused where anything stands there, a
    /// dangling symlink included, which is left as it was along with no staging name.
    #[test]
    fn writing_new_never_replaces_what_is_there() {
        let dir = scratch("write-new");
        let path = dir.join("key");
        write_new(&path, b"first", 0o600).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let exists = |e: &anyhow::Error| {
            e.chain().any(|c| {
                c.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists)
            })
        };
        let err = write_new(&path, b"second", 0o600).unwrap_err();
        assert!(exists(&err), "{err:#}");
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        let link = dir.join("link");
        std::os::unix::fs::symlink(dir.join("nowhere"), &link).unwrap();
        let err = write_new(&link, b"x", 0o600).unwrap_err();
        assert!(exists(&err), "{err:#}");
        assert!(!dir.join("nowhere").exists());
        let mut left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        left.sort();
        assert_eq!(left, ["key", "link"], "{left:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The fallback for filesystems without `RENAME_NOREPLACE` publishes the staged file and
    /// removes the staging name, and refuses an occupied name, leaving both files as they were.
    #[test]
    fn linking_new_never_replaces_what_is_there() {
        let dir = scratch("link-new");
        let dir_fd = open_dir(&dir).unwrap();
        let (stage, key) = (CString::new("stage").unwrap(), CString::new("key").unwrap());
        std::fs::write(dir.join("stage"), b"first").unwrap();
        link_noreplace(dir_fd.as_fd(), &stage, &key).unwrap();
        assert_eq!(std::fs::read(dir.join("key")).unwrap(), b"first");
        assert!(!dir.join("stage").exists());
        std::fs::write(dir.join("stage"), b"second").unwrap();
        let err = link_noreplace(dir_fd.as_fd(), &stage, &key).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists, "{err}");
        assert_eq!(std::fs::read(dir.join("key")).unwrap(), b"first");
        assert_eq!(std::fs::read(dir.join("stage")).unwrap(), b"second");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Skip occupied staging names. If all candidates are taken, fail without changing
    /// existing entries or publishing the file.
    #[test]
    fn a_taken_staging_name_is_stepped_over_then_exhausted() {
        let dir = scratch("write-atomic-staging");
        let path = dir.join("ssh-config");

        // First candidate collides, the second is free: the write takes the second.
        std::fs::write(dir.join(".taken"), b"squatter").unwrap();
        let mut names = [".taken", ".free"].into_iter();
        let retry = move || Ok::<_, anyhow::Error>(names.next().unwrap().to_string());
        write_atomic_from(
            &path,
            b"x",
            0o600,
            Durability::Synced,
            Publish::Replace,
            retry,
        )
        .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
        assert_eq!(std::fs::read(dir.join(".taken")).unwrap(), b"squatter");

        // Every candidate taken: no free name, and the squatter is left as it was.
        std::fs::remove_file(&path).unwrap();
        let fixed = || Ok::<_, anyhow::Error>(".taken".to_string());
        let err = write_atomic_from(
            &path,
            b"y",
            0o600,
            Durability::Synced,
            Publish::Replace,
            fixed,
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("no free staging name"),
            "{err:#}"
        );
        assert_eq!(std::fs::read(dir.join(".taken")).unwrap(), b"squatter");
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A rename that fails removes the staging file and leaves the destination untouched.
    #[test]
    fn a_failed_publish_removes_its_staging_file() {
        let dir = scratch("write-atomic-rename-fail");
        // The destination is a non-empty directory, so renaming a file onto it fails; the
        // write must still not leave its staging file behind.
        let target = dir.join("ssh-config");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("keep"), b"keep").unwrap();

        let fixed = || Ok::<_, anyhow::Error>(".stage".to_string());
        let err = write_atomic_from(
            &target,
            b"x",
            0o600,
            Durability::Synced,
            Publish::Replace,
            fixed,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("publishing"), "{err:#}");
        assert!(target.is_dir());
        assert_eq!(std::fs::read(target.join("keep")).unwrap(), b"keep");
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, [std::ffi::OsString::from("ssh-config")], "{left:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The rename publishes over whatever is at the path, so a socket a previous server
    /// left behind is replaced — and replaced by one that is private in its own right.
    #[test]
    fn binding_replaces_a_socket_already_at_the_path() {
        use std::os::unix::fs::MetadataExt;

        let dir = scratch("bind-replace");
        let path = dir.join("agent.sock");

        let first = bind_private(&path).unwrap();
        let before = std::fs::metadata(&path).unwrap();
        drop(first);

        let _second = bind_private(&path).unwrap();
        let after = std::fs::metadata(&path).unwrap();
        assert_ne!(
            (before.dev(), before.ino()),
            (after.dev(), after.ino()),
            "the second bind must publish its own socket, not reuse the first"
        );
        assert_eq!(after.permissions().mode() & 0o777, 0o600);
        std::os::unix::net::UnixStream::connect(&path)
            .expect("the replacement must be the socket that is listening");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A path too long to bind is reported as such, not as an error naming the internal
    /// path it would have been staged under.
    #[test]
    fn binding_refuses_a_path_too_long_for_a_socket() {
        let dir = scratch("bind-too-long");
        let long = dir.join("z".repeat(SUN_PATH_MAX));

        let err = match bind_private(&long) {
            Ok(_) => panic!(
                "{} must not bind: it is longer than sun_path",
                long.display()
            ),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains("too long for a unix socket") && err.contains(&SUN_PATH_MAX.to_string()),
            "unhelpful error for an over-long path: {err}"
        );
        assert!(
            !long.exists(),
            "nothing may be published for a refused bind"
        );
        // Unless its clients reach it through a descriptor on its directory: then only the
        // final name has to fit behind one.
        let far = dir.join("f".repeat(SUN_PATH_MAX)).join("agent.sock");
        std::fs::create_dir_all(far.parent().unwrap()).unwrap();
        drop(bind_private_any_length(&far).unwrap());
        assert_eq!(
            std::fs::symlink_metadata(&far)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let err = format!("{:#}", bind_private_any_length(&long).unwrap_err());
        assert!(
            err.contains(&format!("{SUN_PATH_MAX}-byte name")),
            "unhelpful error for an over-long name: {err}"
        );
        assert!(!long.exists());
        let widest = far.with_file_name("n".repeat(MAX_NAME_VIA_DIR));
        drop(bind_private_any_length(&widest).unwrap());

        // Staging costs the caller nothing now that it happens under `/proc/self/fd`: a name
        // that fits binds, however deep the directory holding it.
        let deep = dir.join("d".repeat(SUN_PATH_MAX - 3 - dir.as_os_str().len() - 1));
        std::fs::create_dir_all(&deep).unwrap();
        let barely = deep.join("s");
        assert_eq!(barely.as_os_str().len(), SUN_PATH_MAX - 1);
        drop(bind_private(&barely).unwrap());
        assert_eq!(
            std::fs::metadata(&barely).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A staging name already taken is stepped over, never cleared: whatever holds it, this
    /// call did not make it, and what sits there may be a live bind's directory.
    #[test]
    fn binding_steps_over_a_taken_staging_name() {
        let dir = scratch("bind-collide");
        let path = dir.join("agent.sock");
        // Occupy the first names the generator below will hand out, each holding a file so a
        // recursive delete would leave a mark.
        for n in 0..2u64 {
            let taken = dir.join(format!(".taken{n}"));
            std::fs::create_dir(&taken).unwrap();
            std::fs::write(taken.join("keep"), b"x").unwrap();
        }

        let mut handed_out = 0u64;
        let listener = bind_private_from(
            &path,
            || {
                let n = handed_out;
                handed_out += 1;
                Ok(format!(".taken{n}"))
            },
            PathLen::MustFit,
        )
        .unwrap();
        drop(listener);

        assert_eq!(
            handed_out, 3,
            "each taken name must be tried, then stepped past"
        );
        for n in 0..2u64 {
            assert!(
                dir.join(format!(".taken{n}/keep")).exists(),
                "a staging name this call did not make was cleared"
            );
        }
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            !dir.join(".taken2").exists(),
            "the staging directory it did make must not outlive the bind"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A failed rename must remove both the staged socket and the directory made for it,
    /// while leaving the entry that prevented publication untouched.
    #[test]
    fn failed_publication_removes_its_staging_directory() {
        let dir = scratch("bind-publish-fail");
        let path = dir.join("occupied");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("keep"), b"x").unwrap();

        let err =
            bind_private_from(&path, || Ok(".staged".to_string()), PathLen::MustFit).unwrap_err();

        assert!(
            format!("{err:#}").contains("publishing the socket"),
            "unexpected publication error: {err:#}"
        );
        assert!(path.join("keep").exists(), "the destination was disturbed");
        assert!(
            !dir.join(".staged").exists(),
            "failed publication left its staging directory behind"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A umask wide enough to strip the owner bits off `mkdir`'s `0700` must not stop the
    /// listener. Set on the directory rather than through the process umask — which is the
    /// very thing this must not reach for, and would fail every test running beside it.
    #[test]
    fn publishing_restores_owner_bits_a_wide_umask_stripped() {
        let dir = scratch("bind-stripped");
        let parent_fd = open_dir(&dir).unwrap();
        // What `mkdir(0700)` is left with under `umask 0400`, `0100` and `0700`: private
        // either way, since a umask only clears bits, but missing the read bit an
        // `O_RDONLY` open needs, the execute bit `bind` needs, or both.
        for mode in [0o300, 0o600, 0o000] {
            let path = dir.join(format!("agent{mode:o}.sock"));
            let name = cstr(OsStr::new(&format!(".stripped{mode:o}"))).unwrap();
            assert_eq!(
                unsafe { libc::mkdirat(parent_fd.as_raw_fd(), name.as_ptr(), mode) },
                0
            );
            let final_name = cstr(path.file_name().unwrap()).unwrap();

            drop(
                publish_into(parent_fd.as_fd(), &name, &final_name, &path, true)
                    .unwrap_or_else(|e| panic!("mode {mode:o} must still publish: {e:#}")),
            );

            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600,
                "the socket staged under mode {mode:o} must still be private"
            );
            assert!(
                !dir.join(format!(".stripped{mode:o}")).exists(),
                "the staging directory must not outlive the publish"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Cleanup happens by name, and a name in a parent others may write is not this call's
    /// to act on by the time it would: the staging directory is left behind there instead.
    /// Empty, and — as `kept_staging_directories_do_not_exhaust_later_binds` holds — not in
    /// the way of the binds that follow, which never pick a name already standing.
    #[test]
    fn a_shared_parent_keeps_its_staging_directory() {
        let dir = scratch("bind-shared-parent");
        let path = dir.join("agent.sock");
        // World-writable and not sticky: anyone could swap a name here between two calls.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();

        drop(bind_private(&path).unwrap());

        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "the socket is private wherever it was staged"
        );
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.file_name().unwrap().as_encoded_bytes().starts_with(b"."))
            .collect();
        assert_eq!(
            left.len(),
            1,
            "expected one staging directory kept: {left:?}"
        );
        assert!(left[0].is_dir() && std::fs::read_dir(&left[0]).unwrap().next().is_none());

        // Sticky is the other way a name stays ours: only its maker may remove it.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1777)).unwrap();
        drop(bind_private(&dir.join("sticky.sock")).unwrap());
        let after = std::fs::read_dir(&dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .as_encoded_bytes()
                    .starts_with(b".")
            })
            .count();
        assert_eq!(after, 1, "a sticky parent must clean up after itself");

        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Staging directories a shared parent keeps must not use up the names a later bind can
    /// pick. One more bind here than there are candidates per bind: with a name built from
    /// the pid — fixed for the process, and identical again the next time that pid comes
    /// round — the last of these finds every candidate standing and fails for a socket path
    /// nothing holds.
    #[test]
    fn kept_staging_directories_do_not_exhaust_later_binds() {
        let dir = scratch("bind-exhaust");
        let path = dir.join("agent.sock");
        // World-writable and not sticky, so every bind below keeps its staging directory.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();

        for attempt in 0..=STAGING_ATTEMPTS {
            drop(
                bind_private_from(&path, staging_names(), PathLen::MustFit).unwrap_or_else(|e| {
                    panic!("bind {attempt} must succeed beside what is kept: {e:#}")
                }),
            );
        }

        let kept: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.file_name().unwrap().as_encoded_bytes().starts_with(b"."))
            .collect();
        assert_eq!(
            kept.len() as u32,
            STAGING_ATTEMPTS + 1,
            "each bind keeps one directory of its own: {kept:?}"
        );
        assert!(
            kept.iter()
                .all(|p| p.is_dir() && std::fs::read_dir(p).unwrap().next().is_none()),
            "what is kept must be empty: {kept:?}"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every branch of the rule, including the owners a test cannot create: a directory of
    /// root's or another user's, and another user's entry under the sticky bit.
    #[test]
    fn only_a_directory_of_ours_or_roots_keeps_its_names_ours() {
        let (us, them) = (1000, 1001);
        let admits = |dir_uid, mode, entry| admits_only(dir_uid, mode, entry, us);
        assert!(admits(us, 0o755, None) && admits(us, 0o755, Some(them)));
        assert!(admits(0, 0o755, Some(them)), "root's private directory");
        assert!(
            !admits(them, 0o700, Some(us)),
            "its owner may swap anything in it"
        );
        assert!(!admits(us, 0o775, Some(us)) && !admits(us, 0o757, None));
        assert!(!admits(0, 0o777, Some(0)), "shared and not sticky");
        assert!(
            admits(0, 0o1777, None),
            "a sticky /tmp, for a name this user makes"
        );
        assert!(admits(0, 0o1777, Some(us)) && admits(us, 0o1777, Some(0)));
        assert!(
            !admits(0, 0o1777, Some(them)),
            "their entry is theirs to swap"
        );
        assert!(
            !admits(them, 0o1777, Some(us)),
            "a sticky directory of theirs"
        );
    }

    /// [`entry_in`] reads an entry without following it, and trusts it by where it stands,
    /// a link or not.
    #[test]
    fn an_entry_is_ours_only_where_no_one_else_can_swap_it() {
        let dir = scratch("entry-in");
        std::fs::create_dir(dir.join("real")).unwrap();
        std::os::unix::fs::symlink("real", dir.join("link")).unwrap();
        let read = |mode, name| {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            entry_in(open_dir(&dir).unwrap().as_fd(), OsStr::new(name)).unwrap()
        };

        let link = read(0o755, "link");
        assert_eq!(link.link.as_deref(), Some(Path::new("real")));
        assert!(link.ours, "a private directory");
        assert!(!read(0o775, "link").ours, "a group-writable directory");
        assert!(read(0o1777, "link").ours, "sticky, and the link is ours");
        let real = read(0o755, "real");
        assert!(real.link.is_none() && real.ours);
        assert!(
            !read(0o757, "real").ours,
            "a directory is swapped like a link"
        );
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let fd = open_dir(&dir).unwrap();
        assert!(entry_in(fd.as_fd(), OsStr::new("gone")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Both walk one name at a time: a `/` would have the kernel walk the rest unchecked.
    /// [`entry_in`] also refuses `.` and `..`, which name no entry of their own.
    #[test]
    fn a_name_in_a_directory_is_one_name() {
        let dir = scratch("one-name");
        std::fs::create_dir_all(dir.join("a/b")).unwrap();
        let fd = open_dir(&dir).unwrap();
        for name in ["", "a/b", "/", "a/", "/a"] {
            let err = entry_in(fd.as_fd(), OsStr::new(name)).unwrap_err();
            assert!(format!("{err:#}").contains("not a single name"), "{err:#}");
            let err = open_dir_in(fd.as_fd(), OsStr::new(name)).unwrap_err();
            assert!(format!("{err:#}").contains("not a single name"), "{err:#}");
        }
        for name in [".", ".."] {
            assert!(entry_in(fd.as_fd(), OsStr::new(name)).is_err());
            assert!(open_dir_in(fd.as_fd(), OsStr::new(name)).is_ok());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `/tmp` is the case an ownership test alone gets wrong: root owns it, yet its sticky
    /// bit means no other unprivileged user can remove or rename an entry made there. Left
    /// unrecognised, every bind under it strands a staging directory.
    #[test]
    fn a_root_owned_sticky_directory_is_ours_to_clean() {
        use std::os::unix::fs::MetadataExt;

        let meta = std::fs::metadata("/tmp").unwrap();
        assert!(
            meta.uid() == 0 && meta.mode() & 0o1000 != 0,
            "this asserts against a stock root-owned sticky /tmp, found uid {} mode {:o}",
            meta.uid(),
            meta.mode() & 0o7777
        );
        assert!(
            dir_admits_only_us(open_dir(Path::new("/tmp")).unwrap().as_fd()),
            "a root-owned sticky directory keeps this process's entries its own"
        );

        // And end to end, in that same directory rather than wherever `TMPDIR` points: a
        // socket bound directly in `/tmp` strands nothing. Compared as a before-and-after
        // set, since a staging name is picked and not derived from anything to match on.
        let dotted = || -> std::collections::BTreeSet<std::ffi::OsString> {
            std::fs::read_dir("/tmp")
                .unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.file_name())
                .filter(|n| n.as_encoded_bytes().starts_with(b"."))
                .collect()
        };
        let path = Path::new("/tmp").join(format!("vk-fs-sticky-{}.sock", std::process::id()));
        let before = dotted();
        drop(bind_private(&path).unwrap());
        let left: Vec<_> = dotted().difference(&before).cloned().collect();
        assert!(left.is_empty(), "staging left behind in /tmp: {left:?}");
        let _ = std::fs::remove_file(&path);
    }
}
