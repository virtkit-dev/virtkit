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
//! [`bind_private`] applies all four to unix sockets, the only objects published here so far.
//! `vk-core` uses it for the agent's exec channel and `vk-registry` for its admin socket; both
//! require the published name to refer only to a socket already restricted to `0600`.
//!
//! [`open_dir`] and [`open_dir_nofollow`] expose the third rule to callers that anchor their
//! own `*at()` operations.

use anyhow::{Context, anyhow, bail};
use std::ffi::{CString, OsStr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
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
    bind_private_from(path, staging_names())
}

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

/// [`bind_private`], with the staging names supplied so a test can arrange a collision.
fn bind_private_from(
    path: &Path,
    mut next_name: impl FnMut() -> Result<String, anyhow::Error>,
) -> Result<UnixListener, anyhow::Error> {
    let Some(final_name) = path.file_name() else {
        bail!("{path:?} is not a path a socket can be bound at");
    };
    // `bind` sees only the short `/proc/self/fd` anchor below, and `renameat` sees a descriptor
    // plus the final component, so neither validates the address clients are given. Reject a
    // spelling they cannot pass back to `connect` before publishing a socket through it.
    let len = path.as_os_str().len();
    if len >= SUN_PATH_MAX {
        bail!(
            "{path:?} is too long for a unix socket: it is {len} bytes and {SUN_PATH_MAX} is \
             the limit — bind it on a shorter path"
        );
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
    // SAFETY: a zeroed `stat` is a valid destination, and `fd` is open for the call.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return false;
    }
    // The *effective* id: it is what the kernel checks when this creates and removes.
    // SAFETY: `geteuid` reads this process's own id and cannot fail.
    let ours = unsafe { libc::geteuid() };
    let owned_by_us_or_root = st.st_uid == ours || st.st_uid == 0;
    owned_by_us_or_root
        && (st.st_mode & (libc::S_IWGRP | libc::S_IWOTH) == 0 || st.st_mode & libc::S_ISVTX != 0)
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
/// The directory is resolved once and everything happens through that descriptor, so no
/// step can be sent elsewhere by a component changing under it. The staging name is picked
/// afresh from `/dev/urandom` and created with `O_EXCL`, so a name already standing is
/// stepped over rather than cleared — see [`bind_private`], which publishes sockets the
/// same way and for the same reasons.
///
/// The directory is not fsynced: the file's own contents are, so a crash between the two
/// costs the rename, not the data. Callers that need the name itself to survive a power cut
/// want more than this.
pub fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> Result<(), anyhow::Error> {
    let Some(final_name) = path.file_name() else {
        bail!("{path:?} is not a path a file can be written at");
    };
    let final_name = cstr(final_name)?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let parent_fd = open_dir(parent.unwrap_or(Path::new(".")))?;
    let mut next_name = staging_names();
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
            // Whatever holds this name, this call did not make it; take the next one.
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(anyhow!(e).context(format!("staging a file for {path:?}")));
        }
        // SAFETY: `fd` is a fresh descriptor this call owns.
        let mut staged = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
        let written = std::io::Write::write_all(&mut staged, contents)
            .and_then(|()| staged.sync_all())
            .map_err(|e| anyhow!(e).context(format!("writing the staged file for {path:?}")))
            .and_then(|()| {
                // SAFETY: both descriptors are live and both names are NUL-terminated.
                let rc = unsafe {
                    libc::renameat(
                        parent_fd.as_raw_fd(),
                        name.as_ptr(),
                        parent_fd.as_raw_fd(),
                        final_name.as_ptr(),
                    )
                };
                match rc {
                    0 => Ok(()),
                    _ => Err(anyhow!(std::io::Error::last_os_error())
                        .context(format!("publishing {path:?}"))),
                }
            });
        if written.is_err() {
            // Best effort, through the descriptor this call opened the directory with, so
            // only the name this call made is ever unlinked.
            // SAFETY: the descriptor is live and the name is NUL-terminated.
            let _ = unsafe { libc::unlinkat(parent_fd.as_raw_fd(), name.as_ptr(), 0) };
        }
        return written;
    }
    bail!("found no free staging name beside {path:?} in {STAGING_ATTEMPTS} tries")
}

/// [`open_dir`] for a name under an already-open directory, so the parent is not re-resolved.
fn openat_dir(parent: BorrowedFd<'_>, name: &CString) -> Result<OwnedFd, anyhow::Error> {
    // SAFETY: the descriptor is live and the name is NUL-terminated and outlives the call.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(anyhow!(std::io::Error::last_os_error())
            .context(format!("opening the staging directory {name:?}")));
    }
    // SAFETY: `fd` is a fresh descriptor this call owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
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
        let listener = bind_private_from(&path, || {
            let n = handed_out;
            handed_out += 1;
            Ok(format!(".taken{n}"))
        })
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

        let err = bind_private_from(&path, || Ok(".staged".to_string())).unwrap_err();

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
                bind_private_from(&path, staging_names()).unwrap_or_else(|e| {
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
