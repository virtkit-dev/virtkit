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
    // Freeze the root fs (FIFREEZE) rather than a plain sync: freeze flushes *and*
    // quiesces, so the host's SIGKILL right after cannot interrupt a background ext4
    // writeback mid-update — which would leave the committed overlay (later read as a
    // COPY --from source) intermittently missing directory entries. No thaw: the guest is
    // killed. Fall back to sync if the freeze is unavailable.
    if crate::fsfreeze::freeze(Path::new("/")).is_err() {
        // SAFETY: sync takes no arguments and cannot fail.
        unsafe { libc::sync() };
    }
    Ok(())
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
fn parse_chown(spec: &str) -> Result<(u32, u32)> {
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
            [flag, src, target] if flag == "--bind" => {
                mount_bind_ro(Path::new(src), Path::new(target))
            }
            _ => return usage("mount --ro <device> <mp> | mount --bind <src> <target>"),
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
            1
        }
    }
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
}
