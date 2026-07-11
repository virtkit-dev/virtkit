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

/// Record `path` as agent-created (best-effort, one line appended).
pub fn note_created(path: &Path) {
    use std::io::Write;
    if let Ok(mut f) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(CREATED_REGISTRY)
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
    let list = fs::read_to_string(CREATED_REGISTRY).unwrap_or_default();
    for line in list.lines().rev() {
        let p = Path::new(line);
        if let Ok(c) = CString::new(p.as_os_str().as_bytes()) {
            // SAFETY: valid C string; MNT_DETACH unmounts even a busy mountpoint.
            unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
        }
        if fs::remove_dir(p).is_err() {
            let _ = fs::remove_file(p);
        }
    }
    let _ = fs::remove_file(CREATED_REGISTRY);
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
            fs::create_dir_all(dst_path)
                .with_context(|| format!("creating {}", dst_path.display()))?;
            copy_tree(src, dst_path, chown, chmod, ignore, ex)?;
        } else if ex {
            continue;
        } else {
            let target = if into_dir {
                fs::create_dir_all(dst_path)
                    .with_context(|| format!("creating {}", dst_path.display()))?;
                dst_path.join(src.file_name().context("source has no file name")?)
            } else {
                if let Some(p) = dst_path.parent() {
                    fs::create_dir_all(p).with_context(|| format!("creating {}", p.display()))?;
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
fn copy_tree(
    src_dir: &Path,
    dst_dir: &Path,
    chown: Option<(u32, u32)>,
    chmod: Option<u32>,
    ignore: Option<&Ignore>,
    parent_excluded: bool,
) -> Result<()> {
    let dir_meta = fs::symlink_metadata(src_dir)?;
    apply_meta(dst_dir, &dir_meta, chown, chmod)?;
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

/// CLI entry for `vk-agent mount|umount|copy …`. Returns the process exit code.
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
            _ => {
                return usage(
                    "mount --ro <device> <mp> | mount --scratch <device> <mp> <uid|-> <gid|-> <mode|-> | mount --bind <src> <target>",
                );
            }
        },
        Some("umount") => match &args[1..] {
            [target] => umount(Path::new(target)),
            _ => return usage("umount <mountpoint>"),
        },
        Some("copy") => copy_cmd(&args[1..]),
        Some("cleanup") => cleanup(),
        _ => return usage("mount|umount|copy|cleanup …"),
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
    use super::copy_spec;
    use vk_core::dockerignore::Ignore;

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
