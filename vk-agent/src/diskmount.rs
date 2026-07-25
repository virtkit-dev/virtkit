//! Mount/unmount a block device inside the guest with the `mount(2)`/`umount2(2)`
//! syscalls — the building block for `COPY --from` / `RUN --mount=from`, where the
//! host attaches a source stage's ext4 as a read-only disk and the guest reads it.
//! Built into the agent (vs shelling to `mount`) so it works on any guest; invoked
//! over the existing exec channel as `vk-agent mount|umount …`, like `fsfreeze`.

use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;

use anyhow::{Context, Result, bail};

use vk_core::dockerignore::Ignore;

/// Tmpfs file (never persisted to the image) recording the mountpoints and bind-target
/// stubs the agent creates during a build — and only those that did not already exist in
/// the base. `cleanup` removes the empty ones before the stage image is committed, so the
/// ephemeral COPY/RUN scratch dirs, API-filesystem mountpoints and bind stubs that Docker
/// would not persist do not litter the artifact.
const CREATED_REGISTRY: &str = "/run/.virtkit-created";

/// The same record for the API-filesystem mountpoints, kept *in the image* instead of on
/// tmpfs so it survives being snapshotted into the build cache and restored.
///
/// Those mountpoints have to exist on the stage disk for the whole build (`/proc` above
/// all: the agent is reachable only as `/proc/self/exe`, since it lives nowhere in the
/// rootfs), so a mid-stage snapshot inevitably contains them. Without this, restoring such
/// a snapshot left them looking like part of the base — already present, so
/// [`note_created`] never recorded them and `cleanup` never dropped them — and the empty
/// `/proc`, `/sys`, `/dev`, `/run`, `/tmp` became a permanent part of every image built on
/// top. Recording them here instead makes the judgement travel with the bytes it describes.
/// `cleanup` removes this file along with the directories it names.
const EPHEMERAL_REGISTRY: &str = "/.virtkit-ephemeral";

/// The only paths the in-image registry may name — the API mountpoints
/// [`crate::init`] mounts. Unlike [`CREATED_REGISTRY`], which lives on this boot's tmpfs and
/// so can only ever hold what this agent wrote, that file ships inside the image: a base
/// image (or a build whose `cleanup` was interrupted) can hand us an arbitrary one, and
/// `cleanup` unmounts and deletes every path it names. Anything outside this set is ignored
/// rather than trusted. Keep in step with the mount table in `init::mount_api_filesystems`.
const EPHEMERAL_ALLOWED: &[&str] = &[
    "/proc", "/sys", "/dev", "/dev/pts", "/dev/shm", "/run", "/tmp",
];

/// The in-image registry's lines, restricted to the paths it is allowed to name.
fn ephemeral_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().filter(|l| EPHEMERAL_ALLOWED.contains(l))
}

/// Record `path` as agent-created (best-effort, one line appended).
pub fn note_created(path: &Path) {
    append_line(CREATED_REGISTRY, path);
}

/// Record `path` as an agent-created API mountpoint, in both registries: the tmpfs one that
/// drives this boot's `cleanup`, and the in-image one that tells a later boot restored from
/// a snapshot that this directory is still ours to drop.
pub fn note_ephemeral(path: &Path) {
    note_created(path);
    append_line(EPHEMERAL_REGISTRY, path);
}

/// The in-image registry's contents, read once for a caller that consults it for several
/// paths (see [`noted_ephemeral_in`]).
pub(crate) fn ephemeral_registry() -> String {
    fs::read_to_string(EPHEMERAL_REGISTRY).unwrap_or_default()
}

/// Whether `cleanup` will still change the image: a recorded path that is still there *and* is
/// image content — its own directory entry lives on the root fs. A mountpoint the agent created
/// on some other fs (`/dev/pts` and `/dev/shm` on the devtmpfs over `/dev`, a stub under the
/// disk-backed `/tmp`) is dropped from that fs, not from the image, so it must not cost the host
/// a re-push. Both registries matter — besides the API mountpoints, a `--mount` target's created
/// parent and a file bind stub outlive their step's `umount` and are dropped only here, so the
/// last step's snapshot differs from the export even on a base that ships `/proc`. A superset: a
/// recorded directory that kept real content survives `remove_dir`, so the host may re-push
/// bytes that did not change — idempotent, and far cheaper than answering "no" when the answer
/// is "yes".
pub fn cleanup_pending() -> bool {
    // `cleanup` always drops this file, and it is image content — so its mere presence is a
    // change, whatever it names. Keeps the answer true by construction rather than by the
    // argument that everything written to it is a path this function counts anyway.
    if Path::new(EPHEMERAL_REGISTRY).exists() {
        return true;
    }
    let Ok(root) = fs::metadata("/") else {
        return true; // cannot tell whose fs a path is on — answer the safe way
    };
    recorded_paths(
        &fs::read_to_string(CREATED_REGISTRY).unwrap_or_default(),
        &fs::read_to_string(EPHEMERAL_REGISTRY).unwrap_or_default(),
    )
    .iter()
    .any(|p| is_live_image_content(p, root.dev()))
}

/// Whether `p` is image content that is still there: its own directory entry exists and lives
/// on the root fs (`root_dev`). The *parent*'s device decides, not the path's own — a
/// mountpoint's entry belongs to the fs holding the directory it sits in, whatever is mounted
/// over it, so `/proc` counts while `/dev/pts` (an entry on the devtmpfs over `/dev`) does not.
fn is_live_image_content(p: &Path, root_dev: u64) -> bool {
    p.symlink_metadata().is_ok()
        && p.parent()
            .and_then(|d| fs::metadata(d).ok())
            .is_some_and(|m| m.dev() == root_dev)
}

/// The exit code `cleanup-pending` reports: 0 when `cleanup` will still change the image, so the
/// host's `matches!(…, Ok(0))` probe reads a shell-style "yes".
fn pending_exit_code(pending: bool) -> i32 {
    i32::from(!pending)
}

/// Whether `text` — the in-image registry's contents, from [`ephemeral_registry`] — records
/// `path` as an ephemeral mountpoint: it is present only because a snapshot captured it
/// mid-build, so this boot still owns it.
pub(crate) fn noted_ephemeral_in(text: &str, path: &Path) -> bool {
    ephemeral_lines(text).any(|l| Path::new(l) == path)
}

fn append_line(registry: &str, path: &Path) {
    use std::io::Write;
    if let Ok(mut f) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(registry)
    {
        let _ = f.write_all(path.as_os_str().as_bytes());
        let _ = f.write_all(b"\n");
    }
}

/// `create_dir_all` that records every directory level it actually creates, so `cleanup`
/// can drop the empty ones later. Pre-existing directories are left unrecorded (and kept).
fn create_dir_all_noting(dir: &Path) -> Result<()> {
    let mut missing = Vec::new();
    let mut cur = Some(dir);
    while let Some(p) = cur {
        if p.exists() {
            break;
        }
        missing.push(p.to_path_buf());
        cur = p.parent();
    }
    for p in missing.iter().rev() {
        fs::create_dir(p).with_context(|| format!("creating {}", p.display()))?;
        note_created(p);
    }
    Ok(())
}

/// Remove the agent-created ephemeral mountpoints/stubs recorded in the registry, then
/// flush — the last guest action before the host commits the stage image. Detach any that
/// are still mounted (the API filesystems) and drop the now-empty dir/stub; a directory
/// that still holds real content survives (`remove_dir` fails on non-empty). Best-effort.
pub fn cleanup() -> Result<()> {
    remove_created();
    quiesce_root();
    Ok(())
}

/// Detach and drop the agent-created ephemeral mountpoints/stubs recorded in the registry, so
/// the API-filesystem mountpoints and COPY/RUN scratch dirs Docker would not persist do not
/// litter the committed image. A directory that still holds real content survives
/// (`remove_dir` fails on non-empty). Best-effort.
fn remove_created() {
    // Both registries: this boot's own record, plus whatever an earlier boot left in the
    // image (a snapshot restored mid-build). Read in full before anything is removed, since
    // detaching `/run` takes the tmpfs registry with it.
    let recorded = recorded_paths(
        &fs::read_to_string(CREATED_REGISTRY).unwrap_or_default(),
        &fs::read_to_string(EPHEMERAL_REGISTRY).unwrap_or_default(),
    );
    for p in &recorded {
        let p = p.as_path();
        if let Ok(c) = CString::new(p.as_os_str().as_bytes()) {
            // SAFETY: valid C string; MNT_DETACH unmounts even a busy mountpoint.
            unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
        }
        if fs::remove_dir(p).is_err() {
            let _ = fs::remove_file(p);
        }
    }
    let _ = fs::remove_file(CREATED_REGISTRY);
    // Last: the in-image list is itself ephemeral, and leaving it behind would litter the
    // artifact it exists to keep clean.
    let _ = fs::remove_file(EPHEMERAL_REGISTRY);
}

/// The recorded paths to drop, deepest first. The two registries are deduplicated — an API
/// mountpoint is recorded in both — blank lines are ignored, so an absent or half-written
/// registry contributes nothing, and the in-image one is held to [`EPHEMERAL_ALLOWED`] since
/// it is base-image content.
fn recorded_paths(tmpfs: &str, in_image: &str) -> Vec<std::path::PathBuf> {
    let mut out: Vec<std::path::PathBuf> = Vec::new();
    for line in tmpfs.lines().chain(ephemeral_lines(in_image)) {
        let p = std::path::PathBuf::from(line);
        if !line.is_empty() && !out.contains(&p) {
            out.push(p);
        }
    }
    // A child has to be removed before its parent, or `remove_dir` finds the parent non-empty
    // and leaves both in the image. Each registry is appended to as directories are created, so
    // reversing one orders it deepest-first — but the concatenation of two is not ordered at
    // all: a parent recorded on tmpfs would precede a child recorded only in the image. Sort by
    // depth so the invariant holds by construction.
    out.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    out
}

/// Quiesce the root fs so the on-disk image is consistent. Freeze the root fs (FIFREEZE)
/// rather than a plain sync: freeze flushes *and* quiesces, so a host SIGKILL right after
/// cannot interrupt a background ext4 writeback mid-update — which would leave the committed
/// overlay (later read as a COPY --from source) intermittently missing directory entries. No
/// thaw: the guest is killed or powered off. Fall back to sync if the freeze is unavailable.
fn quiesce_root() {
    if crate::fsfreeze::freeze(Path::new("/")).is_err() {
        // SAFETY: sync takes no arguments and cannot fail.
        unsafe { libc::sync() };
    }
}

/// Mount `device` (an ext4 block device) read-only at `target`, creating `target`.
pub fn mount_ro(device: &str, target: &Path) -> Result<()> {
    create_dir_all_noting(target)
        .with_context(|| format!("creating mountpoint {}", target.display()))?;
    let dev = CString::new(device).context("device path has a NUL")?;
    let tgt = CString::new(target.as_os_str().as_bytes()).context("mountpoint has a NUL")?;
    let fstype = CString::new("ext4").unwrap();
    // SAFETY: valid C strings; data arg is null (no fs-specific options).
    let rc = unsafe {
        libc::mount(
            dev.as_ptr(),
            tgt.as_ptr(),
            fstype.as_ptr(),
            libc::MS_RDONLY,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("mounting {device} ro at {}", target.display()));
    }
    Ok(())
}

/// Mount `device` (an ext4) read-write at an existing `target` — the ephemeral, disk-backed
/// scratch fs a build guest uses for `/tmp` (VIRTKIT_TMP_DEV). `flags` carries the same
/// hardening the tmpfs path applies (`MS_NOSUID | MS_NODEV`). Returns an `io::Result` so the
/// caller can treat it uniformly with the tmpfs fallback. Assumes `target` exists.
pub fn mount_rw(device: &str, target: &Path, flags: libc::c_ulong) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    let bad = |what| Error::new(ErrorKind::InvalidInput, what);
    let dev = CString::new(device).map_err(|_| bad("device path has a NUL"))?;
    let tgt =
        CString::new(target.as_os_str().as_bytes()).map_err(|_| bad("mountpoint has a NUL"))?;
    let fstype = CString::new("ext4").unwrap();
    // SAFETY: valid C strings; data arg is null (no fs-specific options).
    let rc = unsafe {
        libc::mount(
            dev.as_ptr(),
            tgt.as_ptr(),
            fstype.as_ptr(),
            flags,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

/// Mount `device` (an empty ext4) read-write at `target`, creating `target`, as an
/// ephemeral writable scratch for `RUN --mount=type=bind,from=scratch,rw`. Hardened
/// (`MS_NOSUID | MS_NODEV`). Its contents are discarded when the guest tears down — the
/// backing device is separate and never part of the stage snapshot.
///
/// By default the root inode keeps the ext4 default `root:root 0755`, matching BuildKit (which
/// leaves a `from=scratch` mount root-owned). `uid`/`gid`/`mode` override that — a virtkit
/// extension (BuildKit rejects them on bind mounts) so a non-root `RUN` can write to the scratch.
pub fn mount_scratch(
    device: &str,
    target: &Path,
    uid: Option<u32>,
    gid: Option<u32>,
    mode: Option<u32>,
) -> Result<()> {
    create_dir_all_noting(target)
        .with_context(|| format!("creating scratch mountpoint {}", target.display()))?;
    mount_rw(device, target, libc::MS_NOSUID | libc::MS_NODEV)
        .with_context(|| format!("mounting scratch {device} at {}", target.display()))?;
    // The scratch device is reused across a stage's steps, so start every mount fresh:
    // empty any prior step's contents (BuildKit hands each from=scratch mount an empty dir,
    // with no lost+found), and reset ownership+mode so a prior step's uid/gid/mode doesn't
    // carry over. Defaults are the ext4/BuildKit root:root 0755, overridden by uid/gid/mode.
    empty_dir(target).with_context(|| format!("emptying scratch {}", target.display()))?;
    std::os::unix::fs::chown(target, Some(uid.unwrap_or(0)), Some(gid.unwrap_or(0)))
        .with_context(|| format!("chown scratch {}", target.display()))?;
    fs::set_permissions(target, fs::Permissions::from_mode(mode.unwrap_or(0o755)))
        .with_context(|| format!("chmod scratch {}", target.display()))?;
    Ok(())
}

/// The tmpfs mount `data` string for an optional `size=` value, validating its shape.
/// A tmpfs `size=` is a byte count with an optional `k`/`m`/`g` suffix, or a percentage of
/// RAM. The value goes verbatim into the comma-separated mount options, so anything outside
/// that shape is rejected — both to keep an extra option from being smuggled in past a comma
/// and to fail with a clear message instead of the kernel's opaque `EINVAL`.
fn tmpfs_mount_data(size: Option<&str>) -> Result<CString> {
    let opts = match size {
        Some(s) => {
            let digits = if let Some(pct) = s.strip_suffix('%') {
                pct
            } else {
                s.strip_suffix(|c: char| matches!(c, 'k' | 'K' | 'm' | 'M' | 'g' | 'G'))
                    .unwrap_or(s)
            };
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                bail!("mount --tmpfs: invalid size {s:?} (want NNN, NNN[k|m|g], or NNN%)");
            }
            format!("size={s}")
        }
        None => String::new(),
    };
    Ok(CString::new(opts).unwrap())
}

/// Mount a fresh RAM-backed tmpfs at `target` (creating it), for `RUN --mount=type=tmpfs`.
/// Hardened (`MS_NOSUID | MS_NODEV`). `size` is an optional tmpfs `size=` value (`1g`,
/// `512m`, `50%`, a byte count); unset leaves the kernel default (½ RAM). The mount is torn
/// down after the RUN, so its contents never enter the committed layer; the default 1777
/// mode lets a non-root RUN write to it.
pub fn mount_tmpfs(target: &Path, size: Option<&str>) -> Result<()> {
    create_dir_all_noting(target)
        .with_context(|| format!("creating tmpfs mountpoint {}", target.display()))?;
    let data = tmpfs_mount_data(size)?;
    let tgt = CString::new(target.as_os_str().as_bytes()).context("mountpoint has a NUL")?;
    let fstype = CString::new("tmpfs").unwrap();
    // SAFETY: valid C strings; data is the (possibly empty) tmpfs option string.
    let rc = unsafe {
        libc::mount(
            fstype.as_ptr(),
            tgt.as_ptr(),
            fstype.as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            data.as_ptr() as *const libc::c_void,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("mounting tmpfs at {}", target.display()));
    }
    Ok(())
}

/// Remove every entry under `dir` (files, dirs, symlinks) without following symlinks — used
/// to hand a reused scratch device a fresh, empty root each mount.
fn empty_dir(dir: &Path) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            fs::remove_dir_all(entry.path())?;
        } else {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

/// Parse a `mount --scratch` uid/gid/mode CLI token: `-` = unset, else a number in `radix`.
/// A leading `0o` is accepted only for the octal `mode`; a decimal uid/gid must be bare digits.
fn scratch_num(tok: &str, radix: u32, what: &str) -> Result<Option<u32>> {
    if tok == "-" {
        return Ok(None);
    }
    let digits = if radix == 8 {
        tok.trim_start_matches("0o")
    } else {
        tok
    };
    u32::from_str_radix(digits, radix)
        .map(Some)
        .with_context(|| format!("invalid scratch {what} {tok:?}"))
}

/// Bind-mount `src` at `target` read-only, creating `target` to match `src`'s type.
/// Used for `RUN --mount=type=bind,from=<stage>,source=…,target=…`: the source stage's
/// ext4 is mounted read-only elsewhere, and its `source` subtree is bound at `target`.
pub fn mount_bind_ro(src: &Path, target: &Path) -> Result<()> {
    let meta =
        fs::symlink_metadata(src).with_context(|| format!("stat bind source {}", src.display()))?;
    if meta.is_dir() {
        create_dir_all_noting(target).with_context(|| format!("creating {}", target.display()))?;
    } else {
        if let Some(p) = target.parent() {
            create_dir_all_noting(p)?;
        }
        if !target.exists() {
            fs::File::create(target).with_context(|| format!("creating {}", target.display()))?;
            note_created(target);
        }
    }
    let s = CString::new(src.as_os_str().as_bytes()).context("source has a NUL")?;
    let t = CString::new(target.as_os_str().as_bytes()).context("target has a NUL")?;
    // SAFETY: valid C strings; a bind mount takes no fstype/data.
    let rc = unsafe {
        libc::mount(
            s.as_ptr(),
            t.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("bind-mounting {} at {}", src.display(), target.display()));
    }
    // Make the bind read-only (a bind ignores MS_RDONLY until a remount). Best-effort:
    // the backing device is already read-only, so a write fails regardless.
    let _ = unsafe {
        libc::mount(
            s.as_ptr(),
            t.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
            std::ptr::null(),
        )
    };
    Ok(())
}

/// Unmount `target`, then remove the (now-empty) mountpoint best-effort — so a COPY/
/// mount scratch dir or a bind target Docker would not persist does not litter the
/// image. A non-empty/pre-existing directory is left in place (rmdir fails).
pub fn umount(target: &Path) -> Result<()> {
    let tgt = CString::new(target.as_os_str().as_bytes()).context("mountpoint has a NUL")?;
    // SAFETY: valid C string.
    let rc = unsafe { libc::umount2(tgt.as_ptr(), 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("unmounting {}", target.display()));
    }
    let _ = fs::remove_dir(target);
    Ok(())
}

/// Recursively copy `srcs` to `dst` (Docker COPY semantics): a directory source's
/// *contents* are copied into `dst`; a file source goes to `dst` (or `dst/<name>` when
/// `dst` is a directory — trailing `/`, multiple sources, or an existing dir). Mode and
/// owner are preserved from the source unless overridden by `chmod`/`chown`.
/// Create `dir` and any missing parent levels the way BuildKit materializes a COPY
/// target: every level this call creates is owned by `chown` (else root — the agent runs
/// as root) at mode `chmod`, else 0755. A level that already exists is left untouched, so
/// a target or parent an earlier stage set up is preserved — deliberately unlike Docker's
/// `--link`, which re-materializes and resets pre-existing directories.
fn ensure_copy_dir(dir: &Path, chown: Option<(u32, u32)>, chmod: Option<u32>) -> Result<()> {
    // Walk upward recording the levels that do not exist yet; stop at the first that does
    // (it and everything above it stay as-is).
    let mut missing = Vec::new();
    let mut cur = Some(dir);
    while let Some(p) = cur {
        if p.symlink_metadata().is_ok() {
            break;
        }
        missing.push(p);
        cur = p.parent();
    }
    let mode = chmod.unwrap_or(0o755);
    // Create top-down, stamping each level this call brings into being.
    for p in missing.iter().rev() {
        fs::create_dir(p).with_context(|| format!("creating {}", p.display()))?;
        if let Some((uid, gid)) = chown {
            lchown(p, uid, gid)?;
        }
        fs::set_permissions(p, fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {}", p.display()))?;
    }
    Ok(())
}

pub fn copy_spec(
    srcs: &[String],
    dst: &str,
    chown: Option<(u32, u32)>,
    chmod: Option<u32>,
    ignore: Option<&Ignore>,
) -> Result<()> {
    let dst_path = Path::new(dst);
    let into_dir = dst.ends_with('/') || srcs.len() > 1 || dst_path.is_dir();
    for src in srcs {
        let src = Path::new(src);
        // a top-level source has no excluded parent (the context root is never excluded).
        let ex = ignore.is_some_and(|ig| ig.excluded(src, false));
        let meta = fs::symlink_metadata(src).with_context(|| format!("stat {}", src.display()))?;
        if meta.is_dir() {
            if ex && !ignore.is_some_and(|ig| ig.could_reinclude_under(src)) {
                continue; // excluded dir with no possible re-include: prune
            }
            // The COPY *target* directory is not copied content, so it is never stamped
            // with the source dir's own owner/mode (that is what copy_tree does to the
            // contents). ensure_copy_dir applies the target rules: a pre-existing target
            // is left untouched, a created one (and any created parents) gets --chown
            // else root at --chmod else 0755.
            ensure_copy_dir(dst_path, chown, chmod)?;
            copy_tree(src, dst_path, chown, chmod, ignore, ex)?;
        } else if ex {
            continue;
        } else {
            let target = if into_dir {
                ensure_copy_dir(dst_path, chown, chmod)?;
                dst_path.join(src.file_name().context("source has no file name")?)
            } else {
                if let Some(p) = dst_path.parent() {
                    ensure_copy_dir(p, chown, chmod)?;
                }
                dst_path.to_path_buf()
            };
            copy_entry(src, &target, &meta, chown, chmod)?;
        }
    }
    Ok(())
}

/// Copy the contents of `src_dir` into `dst_dir` (already created), recursively,
/// applying `.dockerignore`. `parent_excluded` is whether `src_dir` itself is excluded;
/// each entry inherits it and patterns matching the entry override it (last wins).
///
/// `dst_dir`'s own owner/mode is the caller's concern, not this function's. A *nested*
/// directory is copied content, so it is stamped with the source's metadata here as it
/// is created — overwriting a pre-existing nested dir, as Docker does. The top-level
/// COPY target is handled by `copy_spec`, which (like Docker) never restamps it.
fn copy_tree(
    src_dir: &Path,
    dst_dir: &Path,
    chown: Option<(u32, u32)>,
    chmod: Option<u32>,
    ignore: Option<&Ignore>,
    parent_excluded: bool,
) -> Result<()> {
    for entry in fs::read_dir(src_dir).with_context(|| format!("reading {}", src_dir.display()))? {
        let entry = entry?;
        let from = entry.path();
        let ex = ignore.is_some_and(|ig| ig.excluded(&from, parent_excluded));
        let to = dst_dir.join(entry.file_name());
        let m = fs::symlink_metadata(&from)?;
        if m.is_dir() {
            // descend into an excluded dir only if a `!` could re-include something
            // under it; otherwise prune the whole subtree.
            if ex && !ignore.is_some_and(|ig| ig.could_reinclude_under(&from)) {
                continue;
            }
            fs::create_dir_all(&to)?;
            apply_meta(&to, &m, chown, chmod)?;
            copy_tree(&from, &to, chown, chmod, ignore, ex)?;
        } else if !ex {
            copy_entry(&from, &to, &m, chown, chmod)?;
        }
    }
    Ok(())
}

/// Copy one file or symlink `src` -> `dst`, then apply ownership/mode.
fn copy_entry(
    src: &Path,
    dst: &Path,
    meta: &fs::Metadata,
    chown: Option<(u32, u32)>,
    chmod: Option<u32>,
) -> Result<()> {
    if meta.file_type().is_symlink() {
        let target = fs::read_link(src)?;
        let _ = fs::remove_file(dst);
        symlink(&target, dst).with_context(|| format!("symlink {}", dst.display()))?;
    } else {
        // Replace, never write through a pre-existing symlink at dst (fs::copy follows it):
        // a COPY target can land on a base-image symlink (e.g. /lib -> /usr/lib).
        let _ = fs::remove_file(dst);
        fs::copy(src, dst)
            .with_context(|| format!("copying {} -> {}", src.display(), dst.display()))?;
    }
    apply_meta(dst, meta, chown, chmod)
}

/// Set `path`'s owner (chown override or the source's uid/gid) and, for non-symlinks,
/// its mode (chmod override or the source's mode).
fn apply_meta(
    path: &Path,
    meta: &fs::Metadata,
    chown: Option<(u32, u32)>,
    chmod: Option<u32>,
) -> Result<()> {
    let (uid, gid) = chown.unwrap_or((meta.uid(), meta.gid()));
    lchown(path, uid, gid)?;
    if !meta.file_type().is_symlink() {
        let mode = chmod.unwrap_or(meta.mode() & 0o7777);
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {}", path.display()))?;
    }
    Ok(())
}

fn lchown(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let c = CString::new(path.as_os_str().as_bytes()).context("path has a NUL")?;
    // SAFETY: valid C string; lchown does not follow the final symlink.
    if unsafe { libc::lchown(c.as_ptr(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("chown {}", path.display()));
    }
    Ok(())
}

/// Parse a `--chown` value `user[:group]`: each part is a numeric id or a name resolved
/// against the guest's passwd/group databases. A bare `user` uses that user's gid.
pub fn parse_chown(spec: &str) -> Result<(u32, u32)> {
    let (u, g) = spec
        .split_once(':')
        .map_or((spec, None), |(u, g)| (u, Some(g)));
    let uid = resolve_id(u, false)?;
    let gid = match g {
        Some(g) => resolve_id(g, true)?,
        None => primary_gid(u).unwrap_or(uid),
    };
    Ok((uid, gid))
}

/// Resolve a user (`group=false`) or group (`group=true`) to its numeric id: a number
/// as-is, else a `getpwnam`/`getgrnam` lookup in the guest's databases.
fn resolve_id(name: &str, group: bool) -> Result<u32> {
    if let Ok(n) = name.parse::<u32>() {
        return Ok(n);
    }
    let c = CString::new(name).context("name has a NUL")?;
    // SAFETY: getpwnam/getgrnam return a pointer into a static buffer (single-threaded
    // short-lived process); we only read one field before the next call.
    unsafe {
        if group {
            let g = libc::getgrnam(c.as_ptr());
            if g.is_null() {
                bail!("unknown group {name:?}");
            }
            Ok((*g).gr_gid)
        } else {
            let p = libc::getpwnam(c.as_ptr());
            if p.is_null() {
                bail!("unknown user {name:?}");
            }
            Ok((*p).pw_uid)
        }
    }
}

/// A user's primary gid (for a bare `--chown=user`), or None if unknown.
fn primary_gid(user: &str) -> Option<u32> {
    if let Ok(n) = user.parse::<u32>() {
        return Some(n);
    }
    let c = CString::new(user).ok()?;
    // SAFETY: as in resolve_id.
    unsafe {
        let p = libc::getpwnam(c.as_ptr());
        if p.is_null() { None } else { Some((*p).pw_gid) }
    }
}

/// CLI entry for `vk-agent mount|umount|copy|cleanup|cleanup-pending …`. Returns the process
/// exit code.
pub fn main(args: &[String]) -> i32 {
    let result = match args.first().map(String::as_str) {
        Some("mount") => match &args[1..] {
            [flag, device, target] if flag == "--ro" => mount_ro(device, Path::new(target)),
            [flag, device, target, uid, gid, mode] if flag == "--scratch" => {
                match (
                    scratch_num(uid, 10, "uid"),
                    scratch_num(gid, 10, "gid"),
                    scratch_num(mode, 8, "mode"),
                ) {
                    (Ok(u), Ok(g), Ok(m)) => mount_scratch(device, Path::new(target), u, g, m),
                    (Err(e), ..) | (_, Err(e), _) | (.., Err(e)) => Err(e),
                }
            }
            [flag, src, target] if flag == "--bind" => {
                mount_bind_ro(Path::new(src), Path::new(target))
            }
            [flag, target, size] if flag == "--tmpfs" => {
                mount_tmpfs(Path::new(target), (size != "-").then_some(size.as_str()))
            }
            _ => {
                return usage(
                    "mount --ro <device> <mp> | mount --scratch <device> <mp> <uid|-> <gid|-> <mode|-> | mount --bind <src> <target> | mount --tmpfs <target> <size|->",
                );
            }
        },
        Some("umount") => match &args[1..] {
            [target] => umount(Path::new(target)),
            _ => return usage("umount <mountpoint>"),
        },
        Some("copy") => copy_cmd(&args[1..]),
        Some("cleanup") => cleanup(),
        // Queried by the build host before it shuts a stage guest down: exit 0 when `cleanup`
        // still has paths to drop from this image, so the host knows the snapshot it pushed
        // mid-stage no longer describes what it will export. Asked while the guest is still
        // up, because answering needs the agent at all.
        Some("cleanup-pending") => match &args[1..] {
            [] => return pending_exit_code(cleanup_pending()),
            _ => return usage("cleanup-pending"),
        },
        _ => return usage("mount|umount|copy|cleanup|cleanup-pending …"),
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("vk-agent: {e:#}");
            // ECONNREFUSED/ENOTCONN from a filesystem op means the host-side virtio-fs server
            // backing a share stopped responding — most often the build context at
            // CONTEXT_MOUNT. That server is a HOST component (a virtiofsd process for
            // cloud-hypervisor, or in-process inside the libkrun VMM), never a guest process.
            // The bare errno ("Connection refused") is opaque; name the real cause. It stops
            // responding when the host kills/starves it or it hits a resource limit (open
            // files, memory) — all aggravated by running many build-stage microVMs at once.
            if virtiofs_backend_gone(&e) {
                eprintln!(
                    "vk-agent: ^ the host-side virtio-fs server backing this path stopped \
                     responding (it serves the build context / shares). Check host memory and \
                     open-file limits, or lower the build concurrency (--build-jobs)."
                );
            }
            1
        }
    }
}

/// Whether an error chain carries a virtio-fs transport failure: `ECONNREFUSED`/`ENOTCONN`
/// from a filesystem op, which the guest sees once the host-side share server (libkrun's
/// in-process virtio-fs, or a `virtiofsd` for cloud-hypervisor) dies.
fn virtiofs_backend_gone(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error)
            .is_some_and(|n| n == libc::ECONNREFUSED || n == libc::ENOTCONN)
    })
}

/// `copy [--chown u:g] [--chmod OCTAL] [--ignore-root DIR] <src>... <dst>`. With
/// `--ignore-root`, that directory's `.dockerignore` filters the copy (context COPY).
fn copy_cmd(mut args: &[String]) -> Result<()> {
    let (mut chown, mut chmod, mut ignore) = (None, None, None);
    while let [flag, value, rest @ ..] = args {
        match flag.as_str() {
            "--chown" => chown = Some(parse_chown(value)?),
            "--chmod" => {
                chmod = Some(u32::from_str_radix(value, 8).context("invalid --chmod (octal)")?)
            }
            "--ignore-root" => ignore = Some(Ignore::load(Path::new(value))),
            _ => break,
        }
        args = rest;
    }
    if args.len() < 2 {
        bail!(
            "usage: vk-agent copy [--chown u:g] [--chmod OCTAL] [--ignore-root DIR] <src>... <dst>"
        );
    }
    let (srcs, dst) = args.split_at(args.len() - 1);
    copy_spec(srcs, &dst[0], chown, chmod, ignore.as_ref())
}

fn usage(msg: &str) -> i32 {
    eprintln!("usage: vk-agent {msg}");
    2
}

#[cfg(test)]
mod tests {
    use super::{
        copy_spec, is_live_image_content, noted_ephemeral_in, pending_exit_code, recorded_paths,
        tmpfs_mount_data,
    };
    use std::path::Path;
    use vk_core::dockerignore::Ignore;

    #[test]
    fn tmpfs_mount_data_validates_size() {
        // Unset size yields empty options (kernel default).
        assert_eq!(tmpfs_mount_data(None).unwrap().to_str().unwrap(), "");
        // A byte count, a k/m/g suffix (any case), and a percentage are all accepted.
        for (input, opts) in [
            ("1024", "size=1024"),
            ("512m", "size=512m"),
            ("1G", "size=1G"),
            ("50%", "size=50%"),
        ] {
            assert_eq!(
                tmpfs_mount_data(Some(input)).unwrap().to_str().unwrap(),
                opts
            );
        }
        // Junk, a bad unit, a doubled/misplaced suffix, or a smuggled extra option is rejected.
        for bad in ["", "abc", "1z", "1g2m", "5%%", "1g,noexec", "%", "0x10"] {
            assert!(
                tmpfs_mount_data(Some(bad)).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    /// A child must never be preceded by its own parent, or `remove_dir` finds the parent
    /// non-empty and leaves both in the image. Asserted as the invariant rather than an exact
    /// order, since only the parent/child pairs matter.
    fn assert_children_first(got: &[std::path::PathBuf]) {
        for (i, p) in got.iter().enumerate() {
            for later in &got[i + 1..] {
                assert!(
                    !later.starts_with(p),
                    "{} precedes its child {}",
                    p.display(),
                    later.display()
                );
            }
        }
    }

    // The removal order is what keeps a child from outliving its parent, and the two
    // registries overlap: an API mountpoint is recorded in the in-image one *and* in this
    // boot's tmpfs one, so a naive concatenation would try to remove it twice.
    #[test]
    fn recorded_paths_are_deepest_first_and_deduplicated() {
        let tmpfs = "/proc\n/dev\n/dev/pts\n/mnt/src-build\n";
        let in_image = "/proc\n/dev\n/dev/pts\n";
        let got = recorded_paths(tmpfs, in_image);
        let want: Vec<std::path::PathBuf> = ["/dev/pts", "/mnt/src-build", "/proc", "/dev"]
            .iter()
            .map(std::path::PathBuf::from)
            .collect();
        assert_eq!(got, want, "deepest first, each path once");
        assert_children_first(&got);
        // A parent recorded on tmpfs must not precede a child recorded only in the image: the
        // two registries are ordered individually, their concatenation is not.
        let got = recorded_paths("/dev\n", "/dev\n/dev/pts\n");
        assert_eq!(
            got,
            ["/dev/pts", "/dev"]
                .iter()
                .map(std::path::PathBuf::from)
                .collect::<Vec<_>>()
        );
        assert_children_first(&got);
        // Missing or blank registries contribute nothing rather than a bare "" path, which
        // would resolve to the guest's own root.
        assert!(recorded_paths("", "").is_empty());
        assert!(recorded_paths("\n\n", "").is_empty());
        assert_eq!(recorded_paths("", "/tmp\n").len(), 1);
    }

    // What decides whether the host pays for a re-push: only a path whose own entry is in the
    // image counts. Getting this wrong either re-pushes every stage or none of them.
    #[test]
    fn only_a_live_entry_on_the_root_fs_is_image_content() {
        use std::os::unix::fs::MetadataExt;
        let tmp = std::env::temp_dir().join(format!("dm-content-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let file = tmp.join("stub");
        std::fs::write(&file, "").unwrap();
        let dev = std::fs::metadata(&tmp).unwrap().dev();

        assert!(is_live_image_content(&file, dev), "a stub in the image");
        assert!(is_live_image_content(&tmp, dev), "a directory too");
        // A path already gone changes nothing at cleanup...
        assert!(!is_live_image_content(&tmp.join("absent"), dev));
        // ...and neither does one whose entry lives on another fs, the way /dev/pts sits on the
        // devtmpfs mounted over /dev rather than in the image.
        assert!(!is_live_image_content(&file, dev.wrapping_add(1)));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // The host reads this exit code as a yes/no, and an inversion would silently mean "never
    // re-push" — the bug this registry exists to fix, with every other test still green.
    #[test]
    fn pending_is_reported_as_exit_zero() {
        assert_eq!(pending_exit_code(true), 0, "pending -> success");
        assert_eq!(pending_exit_code(false), 1);
    }

    // The in-image registry ships inside the image, so a base image can hand the agent an
    // arbitrary one — and `cleanup` unmounts and deletes every path it names. Only the API
    // mountpoints may be named; anything else is ignored rather than removed from the image
    // being built.
    #[test]
    fn the_in_image_registry_only_names_api_mountpoints() {
        let hostile = "/etc/ssl/certs/ca-certificates.crt\n/usr/bin\n/\n../escape\n/proc\n";
        assert_eq!(
            recorded_paths("", hostile),
            vec![std::path::PathBuf::from("/proc")],
            "only the allowlisted mountpoint survives"
        );
        assert!(noted_ephemeral_in(hostile, Path::new("/proc")));
        for rejected in ["/usr/bin", "/", "../escape"] {
            assert!(
                !noted_ephemeral_in(hostile, Path::new(rejected)),
                "{rejected} must not count as agent-created"
            );
        }
        // The tmpfs registry is written only by this agent, so it takes any path it records.
        assert_eq!(recorded_paths("/mnt/src-build\n", "").len(), 1);
    }

    #[test]
    fn copy_spec_dockerignore_negation() {
        let base = std::env::temp_dir().join(format!("dm-neg-{}", std::process::id()));
        let (ctx, dst) = (base.join("ctx"), base.join("dst"));
        std::fs::create_dir_all(ctx.join("build")).unwrap();
        std::fs::create_dir_all(ctx.join("src")).unwrap();
        // exclude *.log but keep keep.log; exclude build/ but re-include build/important.
        std::fs::write(
            ctx.join(".dockerignore"),
            "*.log\n!keep.log\nbuild\n!build/important\n",
        )
        .unwrap();
        std::fs::write(ctx.join("a.log"), "a").unwrap();
        std::fs::write(ctx.join("keep.log"), "k").unwrap();
        std::fs::write(ctx.join("src/main.rs"), "m").unwrap();
        std::fs::write(ctx.join("build/junk"), "j").unwrap();
        std::fs::write(ctx.join("build/important"), "i").unwrap();

        let ig = Ignore::load(&ctx);
        copy_spec(
            &[ctx.to_string_lossy().into_owned()],
            &dst.to_string_lossy(),
            None,
            None,
            Some(&ig),
        )
        .unwrap();

        assert!(dst.join("keep.log").exists(), "!keep.log should re-include");
        assert!(dst.join("src/main.rs").exists());
        assert!(
            dst.join("build/important").exists(),
            "!build/important should re-include into an excluded dir"
        );
        assert!(!dst.join("a.log").exists(), "*.log excluded");
        assert!(!dst.join("build/junk").exists(), "build/* excluded");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn copy_spec_applies_dockerignore() {
        let base = std::env::temp_dir().join(format!("dm-cp-{}", std::process::id()));
        let (ctx, dst) = (base.join("ctx"), base.join("dst"));
        std::fs::create_dir_all(ctx.join("build")).unwrap();
        std::fs::create_dir_all(ctx.join("task")).unwrap();
        std::fs::write(
            ctx.join(".dockerignore"),
            "*.secret\nbuild\ntask/**/*_test.go\n",
        )
        .unwrap();
        std::fs::write(ctx.join("keep.txt"), "k").unwrap();
        std::fs::write(ctx.join("app.secret"), "s").unwrap();
        std::fs::write(ctx.join("build/junk"), "j").unwrap();
        std::fs::write(ctx.join("task/main.go"), "m").unwrap();
        std::fs::write(ctx.join("task/main_test.go"), "t").unwrap();

        let ig = Ignore::load(&ctx);
        copy_spec(
            &[ctx.to_string_lossy().into_owned()],
            &dst.to_string_lossy(),
            None,
            None,
            Some(&ig),
        )
        .unwrap();

        assert!(dst.join("keep.txt").exists());
        assert!(dst.join("task/main.go").exists());
        assert!(!dst.join("app.secret").exists(), "*.secret not excluded");
        assert!(!dst.join("build").exists(), "build/ not excluded");
        assert!(
            !dst.join("task/main_test.go").exists(),
            "**/*_test.go not excluded"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn copy_spec_target_dir_mode_matches_docker() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        let mode =
            |p: &std::path::Path| fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777;

        let base = std::env::temp_dir().join(format!("dm-mode-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("file"), "f").unwrap();
        // Non-default source modes, so "preserved source mode" is distinguishable from
        // the 0755 default and from an untouched pre-existing target.
        fs::set_permissions(&src, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(src.join("sub"), fs::Permissions::from_mode(0o750)).unwrap();
        let cp = |dst: &std::path::Path| {
            copy_spec(
                &[src.to_string_lossy().into_owned()],
                &dst.to_string_lossy(),
                None,
                None,
                None,
            )
            .unwrap();
        };

        // Pre-existing target: its own mode is left untouched (Docker never restamps it),
        // while a pre-existing nested dir IS overwritten with the source's mode.
        let existing = base.join("existing");
        fs::create_dir_all(existing.join("sub")).unwrap();
        fs::set_permissions(&existing, fs::Permissions::from_mode(0o751)).unwrap();
        fs::set_permissions(existing.join("sub"), fs::Permissions::from_mode(0o711)).unwrap();
        cp(&existing);
        assert_eq!(mode(&existing), 0o751, "pre-existing target mode preserved");
        assert_eq!(
            mode(&existing.join("sub")),
            0o750,
            "nested dir stamped from source"
        );

        // Created target: 0755 default, NOT the source dir's 0700.
        let created = base.join("created");
        cp(&created);
        assert_eq!(
            mode(&created),
            0o755,
            "created target is 0755, not the source mode"
        );
        assert_eq!(
            mode(&created.join("sub")),
            0o750,
            "nested dir stamped from source"
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn copy_spec_created_target_levels_are_stamped_deterministically() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        let mode =
            |p: &std::path::Path| fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777;

        let base = std::env::temp_dir().join(format!("dm-parents-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("file"), "f").unwrap();

        // A deep, entirely-missing target with --chmod: every level this COPY creates —
        // leaf AND intermediate parents — gets 0o700 (matching BuildKit), not the umask
        // default. This is the fix for the parents that create_dir_all left umask-moded.
        let deep = base.join("d1/d2/d3");
        copy_spec(
            &[src.to_string_lossy().into_owned()],
            &format!("{}/", deep.to_string_lossy()),
            None,
            Some(0o700),
            None,
        )
        .unwrap();
        for lvl in [base.join("d1"), base.join("d1/d2"), deep.clone()] {
            assert_eq!(
                mode(&lvl),
                0o700,
                "created level {} gets --chmod",
                lvl.display()
            );
        }

        // A single file copied into a missing directory: the container dir is created at
        // the default 0o755 (BuildKit stamps it too, rather than leaving it unset).
        let fdir = base.join("fdir");
        copy_spec(
            &[src.join("file").to_string_lossy().into_owned()],
            &format!("{}/", fdir.to_string_lossy()),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            mode(&fdir),
            0o755,
            "file-copy container dir created at 0755"
        );
        assert!(fdir.join("file").exists());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn copy_spec_created_levels_get_chown() {
        use std::fs;
        use std::os::unix::fs::MetadataExt;
        let owner = |p: &std::path::Path| {
            let m = fs::symlink_metadata(p).unwrap();
            (m.uid(), m.gid())
        };

        let base = std::env::temp_dir().join(format!("dm-chown-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("file"), "f").unwrap();

        // Under root the test can chown created levels to an arbitrary id and observe the
        // change; without CAP_CHOWN it can only chown to its own id (still exercises the
        // stamping path and proves every created level carries the requested owner).
        // SAFETY: geteuid/getegid are always safe.
        let (want_uid, want_gid) = if unsafe { libc::geteuid() } == 0 {
            (1u32, 1u32)
        } else {
            (unsafe { libc::geteuid() }, unsafe { libc::getegid() })
        };

        let deep = base.join("d1/d2/d3");
        copy_spec(
            &[src.to_string_lossy().into_owned()],
            &format!("{}/", deep.to_string_lossy()),
            Some((want_uid, want_gid)),
            None,
            None,
        )
        .unwrap();
        for lvl in [base.join("d1"), base.join("d1/d2"), deep.clone()] {
            assert_eq!(
                owner(&lvl),
                (want_uid, want_gid),
                "created level {} gets --chown",
                lvl.display()
            );
        }

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn copy_spec_preexisting_intermediate_parent_untouched() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        let mode =
            |p: &std::path::Path| fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777;

        let base = std::env::temp_dir().join(format!("dm-parent-keep-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("file"), "f").unwrap();

        // A pre-existing *intermediate* parent (not the leaf) with a distinctive mode: the
        // COPY creates the missing leaf below it but must leave the parent's mode alone,
        // since the walk stops at the first existing level.
        let keep = base.join("keep");
        fs::create_dir(&keep).unwrap();
        fs::set_permissions(&keep, fs::Permissions::from_mode(0o701)).unwrap();

        let leaf = keep.join("leaf");
        copy_spec(
            &[src.to_string_lossy().into_owned()],
            &format!("{}/", leaf.to_string_lossy()),
            None,
            Some(0o700),
            None,
        )
        .unwrap();
        assert_eq!(
            mode(&keep),
            0o701,
            "pre-existing intermediate parent untouched"
        );
        assert_eq!(mode(&leaf), 0o700, "created leaf gets --chmod");

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn virtiofs_backend_gone_matches_transport_errnos() {
        use anyhow::Context;

        // ECONNREFUSED/ENOTCONN buried in the chain are detected, regardless of context depth.
        for errno in [libc::ECONNREFUSED, libc::ENOTCONN] {
            let e = Err::<(), _>(std::io::Error::from_raw_os_error(errno))
                .context("copying ctx -> dst")
                .unwrap_err();
            assert!(
                super::virtiofs_backend_gone(&e),
                "errno {errno} should match"
            );
        }

        // An unrelated filesystem errno must not trigger the hint.
        let other = Err::<(), _>(std::io::Error::from_raw_os_error(libc::ENOENT))
            .context("stat missing")
            .unwrap_err();
        assert!(!super::virtiofs_backend_gone(&other));
    }

    #[test]
    fn scratch_num_parses_sentinel_radix_and_errors() {
        use super::scratch_num;
        // `-` is the unset sentinel for every field.
        assert_eq!(scratch_num("-", 10, "uid").unwrap(), None);
        assert_eq!(scratch_num("-", 8, "mode").unwrap(), None);
        // uid/gid parse as decimal.
        assert_eq!(scratch_num("1000", 10, "uid").unwrap(), Some(1000));
        // mode parses as octal, with or without the `0o` prefix.
        assert_eq!(scratch_num("755", 8, "mode").unwrap(), Some(0o755));
        assert_eq!(scratch_num("0o700", 8, "mode").unwrap(), Some(0o700));
        // a non-numeric token is an error, not a silent default.
        assert!(scratch_num("root", 10, "uid").is_err());
        assert!(scratch_num("8", 8, "mode").is_err());
        // the `0o` prefix is octal-only: a decimal uid/gid must be bare digits.
        assert!(scratch_num("0o5", 10, "uid").is_err());
    }

    #[test]
    fn empty_dir_clears_all_entries_without_following_symlinks() {
        use super::empty_dir;
        use std::fs;
        use std::os::unix::fs::symlink;
        let base = std::env::temp_dir().join(format!("dm-empty-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let scratch = base.join("scratch");
        let outside = base.join("outside");
        fs::create_dir_all(&scratch).unwrap();
        fs::create_dir_all(&outside).unwrap();

        // A regular file, a populated subdirectory, and a symlink pointing outside the scratch.
        fs::write(scratch.join("file"), "data").unwrap();
        fs::create_dir_all(scratch.join("sub/nested")).unwrap();
        fs::write(scratch.join("sub/nested/f"), "x").unwrap();
        fs::write(outside.join("keep"), "keep").unwrap();
        symlink(&outside, scratch.join("link")).unwrap();

        empty_dir(&scratch).unwrap();

        // The scratch root is now empty…
        assert_eq!(fs::read_dir(&scratch).unwrap().count(), 0);
        // …and the symlink was removed as the link itself, not followed: its target survives.
        assert!(outside.join("keep").exists());
        let _ = fs::remove_dir_all(&base);
    }
}
