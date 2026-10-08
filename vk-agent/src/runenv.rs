//! The run's environment — image `ENV` plus the run's own `--env` — for the processes the agent
//! does not start itself, login shells above all: `/etc/profile` resets `PATH` (Debian's does),
//! and nothing else re-applies what the image declared.
//!
//! PID 1 publishes it at boot under `/run/vk` (a tmpfs: the values may be secrets, so they never
//! touch the root filesystem), one file per user allowed to read it, and `vk-agent env` prints
//! or applies the caller's own. A login-shell hook in `/etc/profile.d` runs that command; the
//! hook and a copy of the image's profile snippets live in `/run/vk`; the directory is
//! bind-mounted over `/etc/profile.d`, without writing to the rootfs.
//!
//! Each reader's file is `/run/vk/env/<uid>.json`, mode 0400, owned by that uid, in a directory
//! only root may write. Owning it lets a user change only what they themselves read back;
//! root's file is root's alone.

use std::ffi::{CString, OsString};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};

/// Where PID 1 publishes the environment, the login-shell hook and the agent binary the hook
/// runs. On the `/run` tmpfs, never in the image.
pub const RUN_VK: &str = "/run/vk";
/// The running agent, bind-mounted for guest processes: a byte-clean image does not carry it.
pub const AGENT_BIN: &str = "/run/vk/bin/vk-agent";
/// The directory of per-reader environment files, under [`RUN_VK`].
const ENV_DIR: &str = "env";
/// The hook's name in `/etc/profile.d`, chosen to follow most image snippets.
const PROFILE_D_NAME: &str = "zz-virtkit-env.sh";
/// The largest environment file read back: far beyond what any `execve` accepts.
const MAX_FILE: u64 = 64 << 20;

/// What a login shell sources. Silent and side-effect free when the agent or the caller's file
/// is missing: `vk-agent env` prints nothing at all unless it can print everything.
const HOOK_SCRIPT: &str = "\
# Restore the run environment after /etc/profile, only on a successful read.
if [ -x /run/vk/bin/vk-agent ]; then
    if _vk_env=$(/run/vk/bin/vk-agent env --export --login 2>/dev/null); then
        eval \"$_vk_env\"
    fi
    unset _vk_env
fi
";

/// Variables a login or the shell itself owns: replacing them with the image's would make the
/// session lie about who and where it is.
const IDENTITY: &[&str] = &[
    "HOME",
    "PWD",
    "OLDPWD",
    "SHLVL",
    "USER",
    "LOGNAME",
    "SHELL",
    "HOSTNAME",
    "TERM",
    "IFS",
    "_",
    "_vk_env",
    "VIRTKIT_SSH_PATH",
];

/// Whether `name` decides what a process executes or loads: what one user's settings must not
/// steer for another.
fn steers_execution(name: &str) -> bool {
    name == "PATH" || name.starts_with("LD_") || matches!(name, "GCONV_PATH" | "BASH_ENV" | "ENV")
}

/// One reader's environment file.
#[derive(Debug, Clone, PartialEq)]
pub struct EnvFile {
    /// The run user's uid — the user the image's settings were made for. `None` when the run
    /// user does not resolve in the image's passwd.
    pub run_uid: Option<u32>,
    /// The environment, in order.
    pub env: Vec<(String, String)>,
}

impl EnvFile {
    fn to_json(&self) -> String {
        serde_json::json!({ "run_uid": self.run_uid, "env": self.env }).to_string()
    }

    fn from_json(text: &str) -> Result<Self> {
        let mut v: serde_json::Value = serde_json::from_str(text)?;
        let run_uid = match v.get("run_uid") {
            None | Some(serde_json::Value::Null) => None,
            Some(n) => Some(
                n.as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| anyhow!("run_uid is not a uid"))?,
            ),
        };
        let env: Vec<(String, String)> = serde_json::from_value(
            v.get_mut("env")
                .map(serde_json::Value::take)
                .ok_or_else(|| anyhow!("no env"))?,
        )
        .context("env is not a list of [name, value] pairs")?;
        for (key, value) in &env {
            if key.is_empty() || key.contains(['=', '\0']) || value.contains('\0') {
                bail!("invalid environment entry {key:?}");
            }
        }
        Ok(EnvFile { run_uid, env })
    }
}

// ---------------------------------------------------------------------------------------------
// Publishing (PID 1)

/// Publish `file` under `base` for each `(uid, gid)` in `readers`: `env/<uid>.json`, 0400, owned
/// by the reader. `base` and `base/env` are created if missing and must otherwise be
/// directories only root (or this process's own user) may write.
pub fn publish(base: &Path, file: &EnvFile, readers: &[(u32, u32)]) -> Result<()> {
    let base_fd = ensure_dir(base, None, 0o755)?;
    let env_fd = ensure_dir(base, Some((base_fd.as_fd(), ENV_DIR)), 0o755)?;
    let json = file.to_json();
    write_fresh(base_fd.as_fd(), "env.json", json.as_bytes(), 0o400, None)?;
    for &(uid, gid) in readers {
        let name = format!("{uid}.json");
        write_fresh(
            env_fd.as_fd(),
            &name,
            json.as_bytes(),
            0o400,
            Some((uid, gid)),
        )
        .with_context(|| format!("writing {}/{ENV_DIR}/{name}", base.display()))?;
    }
    Ok(())
}

/// Copy the image's profile snippets to tmpfs, add our hook, and bind the directory
/// over the original. No placeholder or hook is written to the root disk.
pub fn hook_login_shells(base: &Path, profile_d: &Path) -> Result<bool> {
    let base_fd = ensure_dir(base, None, 0o755)?;
    let pd = match vk_fs::open_dir_nofollow(profile_d) {
        Ok(fd) => fd,
        Err(e) if is_not_found(&e) => return Ok(false),
        Err(e) => return Err(e),
    };
    trusted_dir(pd.as_fd())?;
    let mode = fstat(pd.as_fd())?.st_mode & 0o777;
    let copy_fd = ensure_dir(base, Some((base_fd.as_fd(), "profile.d")), mode)?;
    copy_directory_owner(pd.as_fd(), copy_fd.as_fd())?;
    let source = format!("/proc/self/fd/{}", pd.as_raw_fd());
    let copy = format!("/proc/self/fd/{}", copy_fd.as_raw_fd());
    copy_profiles(Path::new(&source), Path::new(&copy))?;
    write_fresh(
        copy_fd.as_fd(),
        PROFILE_D_NAME,
        HOOK_SCRIPT.as_bytes(),
        0o644,
        None,
    )?;
    mount(&copy, &source, libc::MS_BIND).context("mounting login profiles from tmpfs")?;
    Ok(true)
}

fn copy_profiles(source: &Path, dest: &Path) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        if entry.file_name() == PROFILE_D_NAME {
            continue;
        }
        let target = dest.join(entry.file_name());
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            std::os::unix::fs::symlink(std::fs::read_link(entry.path())?, &target)?;
        } else if kind.is_dir() {
            let child = vk_fs::open_dir_nofollow(&entry.path())?;
            trusted_dir(child.as_fd())?;
            let mode = fstat(child.as_fd())?.st_mode & 0o777;
            std::fs::DirBuilder::new().mode(mode).create(&target)?;
            let target_fd = vk_fs::open_dir_nofollow(&target)?;
            copy_directory_owner(child.as_fd(), target_fd.as_fd())?;
            let path = format!("/proc/self/fd/{}", child.as_raw_fd());
            let target_path = format!("/proc/self/fd/{}", target_fd.as_raw_fd());
            copy_profiles(Path::new(&path), Path::new(&target_path))?;
        } else if kind.is_file() {
            let mut input = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(entry.path())?;
            let st = fstat(input.as_fd())?;
            let mode = input.metadata()?.permissions().mode() & 0o777;
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(target)?;
            // Keep a private snippet private to its original owner.
            // SAFETY: output is an owned, freshly created descriptor.
            if unsafe { libc::fchown(output.as_raw_fd(), st.st_uid, st.st_gid) } != 0 {
                return Err(std::io::Error::last_os_error()).context("owning copied profile");
            }
            std::io::copy(&mut input, &mut output)?;
        } else {
            bail!("unsupported profile entry {}", entry.path().display());
        }
    }
    Ok(())
}

fn copy_directory_owner(source: BorrowedFd<'_>, dest: BorrowedFd<'_>) -> Result<()> {
    let st = fstat(source)?;
    // SAFETY: both descriptors are live. AT_EMPTY_PATH acts on dest itself, including
    // the O_PATH descriptors returned by vk_fs.
    if unsafe {
        libc::fchownat(
            dest.as_raw_fd(),
            c"".as_ptr(),
            st.st_uid,
            st.st_gid,
            libc::AT_EMPTY_PATH,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("owning copied profile directory");
    }
    Ok(())
}

/// Create the directory (`at` itself, or `name` inside `parent`) with `mode` if missing, and
/// open it — refusing it unless it is a real directory that only root or this process's own
/// user can write.
fn ensure_dir(
    at: &Path,
    inside: Option<(BorrowedFd<'_>, &str)>,
    mode: libc::mode_t,
) -> Result<OwnedFd> {
    let fd = match inside {
        None => {
            match std::fs::DirBuilder::new().mode(mode).create(at) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e).with_context(|| format!("creating {}", at.display())),
            }
            vk_fs::open_dir_nofollow(at)?
        }
        Some((parent, name)) => {
            let c = cstr(name)?;
            // SAFETY: the descriptor is live and the name is NUL-terminated.
            if unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), mode) } != 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(e).with_context(|| format!("creating {}/{name}", at.display()));
                }
            }
            vk_fs::open_dir_in(parent, name.as_ref())?
        }
    };
    let what = match inside {
        None => at.display().to_string(),
        Some((_, name)) => format!("{}/{name}", at.display()),
    };
    trusted_dir(fd.as_fd()).with_context(|| format!("refusing {what}"))?;
    Ok(fd)
}

/// Replace `name` in `dir` with a new file holding `bytes`, created with `mode` (never wider)
/// and given to `owner`.
fn write_fresh(
    dir: BorrowedFd<'_>,
    name: &str,
    bytes: &[u8],
    mode: libc::mode_t,
    owner: Option<(u32, u32)>,
) -> Result<()> {
    let c = cstr(name)?;
    // SAFETY: the descriptor is live and the name is NUL-terminated.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) } != 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(e).context("removing the previous file");
        }
    }
    // SAFETY: as above.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("creating");
    }
    // SAFETY: `fd` is a fresh descriptor this call owns.
    let mut f = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    if let Some((uid, gid)) = owner {
        // SAFETY: a plain syscall on a descriptor this function owns.
        if unsafe { libc::fchown(f.as_raw_fd(), uid, gid) } != 0 {
            return Err(std::io::Error::last_os_error()).context("chown");
        }
    }
    f.write_all(bytes).context("writing")
}

// ---------------------------------------------------------------------------------------------
// Reading (`vk-agent env`)

/// Read `euid`'s environment file under `base`, trusting it only as far as the descriptors
/// say: `base` and `base/env` directories only root or `euid` can write, the file a regular
/// one owned by `euid` that no one else can read or write.
pub fn load(base: &Path, euid: u32) -> Result<EnvFile> {
    let base_fd = vk_fs::open_dir_nofollow(base)?;
    trusted_dir_for(base_fd.as_fd(), euid)
        .with_context(|| format!("refusing {}", base.display()))?;
    let env_fd = vk_fs::open_dir_in(base_fd.as_fd(), ENV_DIR.as_ref())?;
    trusted_dir_for(env_fd.as_fd(), euid)
        .with_context(|| format!("refusing {}/{ENV_DIR}", base.display()))?;
    let name = format!("{euid}.json");
    let c = cstr(&name)?;
    // SAFETY: the descriptor is live and the name is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            env_fd.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    let shown = format!("{}/{ENV_DIR}/{name}", base.display());
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("opening {shown}"));
    }
    // SAFETY: `fd` is a fresh descriptor this call owns.
    let f = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let st = fstat(f.as_fd())?;
    if st.st_mode & libc::S_IFMT != libc::S_IFREG || st.st_uid != euid || st.st_mode & 0o077 != 0 {
        bail!("{shown} is not a private file of uid {euid}");
    }
    let mut text = String::new();
    f.take(MAX_FILE + 1)
        .read_to_string(&mut text)
        .with_context(|| format!("reading {shown}"))?;
    if text.len() as u64 > MAX_FILE {
        bail!("{shown} is larger than {MAX_FILE} bytes");
    }
    EnvFile::from_json(&text).with_context(|| format!("parsing {shown}"))
}

/// What `vk-agent env` leaves out unless asked for, and how it treats what is already set.
#[derive(Debug, Clone, Copy, Default)]
pub struct Policy {
    /// Login-shell mode: leave a variable the caller already has alone, except `PATH`, which
    /// becomes the run's entries followed by any of the caller's it lacks.
    pub login: bool,
}

/// The variables to apply for the caller `euid`, whose current environment `current` reads.
///
/// PATH and loader variables are only applied for the run user.
pub fn select(
    file: &EnvFile,
    euid: u32,
    policy: Policy,
    current: &dyn Fn(&str) -> Option<OsString>,
) -> Vec<(String, String)> {
    let trusted = file.run_uid == Some(euid);
    let mut out = Vec::new();
    for (k, v) in &file.env {
        if IDENTITY.contains(&k.as_str()) {
            continue;
        }
        if !trusted && steers_execution(k) {
            continue;
        }
        if policy.login {
            if k == "PATH" {
                let path = match current("VIRTKIT_SSH_PATH") {
                    Some(session) => match session.into_string() {
                        Ok(path) => path,
                        Err(_) => continue, // do not replace a non-UTF-8 session PATH
                    },
                    None => {
                        let now = current("PATH");
                        merge_path(v, now.as_ref().and_then(|p| p.to_str()))
                    }
                };
                out.push((k.clone(), path));
                continue;
            }
            if current(k).is_some() {
                continue;
            }
        }
        out.push((k.clone(), v.clone()));
    }
    out
}

/// `run`'s entries, then each of `current`'s that `run` lacks, in order. A `current` that is
/// not UTF-8 is dropped rather than mangled: the run's `PATH` is what this restores.
fn merge_path(run: &str, current: Option<&str>) -> String {
    let mut entries: Vec<&str> = run.split(':').collect();
    for e in current.into_iter().flat_map(|c| c.split(':')) {
        if !entries.contains(&e) {
            entries.push(e);
        }
    }
    entries.join(":")
}

/// Whether a POSIX shell can assign `name`: `[A-Za-z_][A-Za-z0-9_]*`.
fn is_shell_name(name: &str) -> bool {
    let mut b = name.bytes();
    b.next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        && b.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

/// `vars` as `export NAME='value'` lines for `eval`. A value is single-quoted, its own `'`
/// written `'\''`, so nothing in it is expanded and newlines stay part of it. An invalid name or NUL value
/// rejects the whole output before anything reaches stdout.
fn render_export(vars: &[(String, String)]) -> Result<String> {
    let mut out = String::new();
    for (k, v) in vars {
        if !is_shell_name(k) {
            bail!("{k:?} is not a shell variable name");
        }
        if v.contains('\0') {
            bail!("{k:?} contains a NUL");
        }
        out.push_str("export ");
        out.push_str(k);
        out.push_str("='");
        out.push_str(&v.replace('\'', r"'\''"));
        out.push_str("'\n");
    }
    Ok(out)
}

/// `vars` as `NAME=value\0` records.
fn render_print0(vars: &[(String, String)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, v) in vars {
        out.extend_from_slice(k.as_bytes());
        out.push(b'=');
        out.extend_from_slice(v.as_bytes());
        out.push(0);
    }
    out
}

const USAGE: &str = "\
usage: vk-agent env [--login] (--export | --print0 | --exec CMD [ARG]...)

The virtkit run's environment (image ENV plus --env), as published for the calling user.
  --export    print `export NAME='value'` lines, for eval \"$(vk-agent env --export)\"
  --print0    print NAME=value records, each ended by a NUL
  --exec      run CMD with the environment applied
  --login     keep variables already set, and put the run's PATH entries first
Prints nothing on stdout, and exits non-zero, unless it can print everything.";

#[derive(Debug, PartialEq)]
enum Mode {
    Export,
    Print0,
    Exec(Vec<String>),
}

fn parse_args(args: &[String]) -> Result<(Mode, Policy), String> {
    let mut policy = Policy::default();
    let mut mode = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let next = match a.as_str() {
            "--login" => {
                policy.login = true;
                continue;
            }
            "--export" => Mode::Export,
            "--print0" => Mode::Print0,
            "--exec" => {
                let argv: Vec<String> = it.by_ref().cloned().collect();
                if argv.is_empty() {
                    return Err("--exec needs a command".into());
                }
                Mode::Exec(argv)
            }
            other => return Err(format!("unexpected argument {other:?}")),
        };
        if mode.replace(next).is_some() {
            return Err("give one of --export, --print0, --exec".into());
        }
    }
    mode.map(|m| (m, policy))
        .ok_or_else(|| "give one of --export, --print0, --exec".into())
}

/// `vk-agent env …`: exit status 0 with the whole output, 1 with none, 2 for a usage error.
pub fn main(args: &[String]) -> i32 {
    if args.iter().any(|a| a == "-h" || a == "--help") && !args.iter().any(|a| a == "--exec") {
        println!("{USAGE}");
        return 0;
    }
    let (mode, policy) = match parse_args(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("vk-agent env: {e}\n{USAGE}");
            return 2;
        }
    };
    // SAFETY: geteuid reads this process's own id and cannot fail.
    let euid = unsafe { libc::geteuid() };
    let file = match load(Path::new(RUN_VK), euid) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("vk-agent env: {e:#}");
            return 1;
        }
    };
    let vars = select(&file, euid, policy, &|k| std::env::var_os(k));
    let out = match mode {
        Mode::Export => match render_export(&vars) {
            Ok(text) => text.into_bytes(),
            Err(e) => {
                eprintln!("vk-agent env: {e:#}");
                return 1;
            }
        },
        Mode::Print0 => render_print0(&vars),
        Mode::Exec(argv) => {
            let e = std::process::Command::new(&argv[0])
                .args(&argv[1..])
                .envs(vars)
                .exec();
            eprintln!("vk-agent env: {}: {e}", argv[0]);
            return if e.kind() == std::io::ErrorKind::NotFound {
                127
            } else {
                126
            };
        }
    };
    // Validate and render everything before writing any output.
    match std::io::stdout().lock().write_all(&out) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("vk-agent env: writing stdout: {e}");
            1
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Helpers

/// A directory root or this process's own user owns, which no one else may write.
fn trusted_dir(fd: BorrowedFd<'_>) -> Result<()> {
    // SAFETY: geteuid reads this process's own id and cannot fail.
    trusted_dir_for(fd, unsafe { libc::geteuid() })
}

fn trusted_dir_for(fd: BorrowedFd<'_>, euid: u32) -> Result<()> {
    let st = fstat(fd)?;
    if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
        bail!("not a directory");
    }
    if st.st_uid != 0 && st.st_uid != euid {
        bail!("owned by uid {}", st.st_uid);
    }
    if st.st_mode & (libc::S_IWGRP | libc::S_IWOTH) != 0 {
        bail!("writable by others (mode {:o})", st.st_mode & 0o7777);
    }
    Ok(())
}

fn fstat(fd: BorrowedFd<'_>) -> Result<libc::stat> {
    // SAFETY: `stat` is plain old data, for which all-zero bytes are a valid value.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is live and `st` is a writable `stat`.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error()).context("fstat");
    }
    Ok(st)
}

fn mount(src: &str, target: &str, flags: libc::c_ulong) -> std::io::Result<()> {
    crate::init::mount(src, target, "", flags)
}

fn cstr(s: &str) -> Result<CString> {
    CString::new(s).with_context(|| format!("{s:?} holds a NUL"))
}

fn is_not_found(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(run_uid: Option<u32>, env: &[(&str, &str)]) -> EnvFile {
        EnvFile {
            run_uid,
            env: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    fn none(_: &str) -> Option<OsString> {
        None
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-runenv-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn euid() -> u32 {
        unsafe { libc::geteuid() }
    }

    fn egid() -> u32 {
        unsafe { libc::getegid() }
    }

    /// Every value survives `sh -c 'eval "$(…)"'` byte for byte: newlines (a trailing one too),
    /// quotes of both kinds, `$`, backslashes, unicode.
    #[test]
    fn exported_values_come_back_whole_through_a_shell() {
        let values = [
            "line1\nline2",
            "trailing\n",
            "it's \"quoted\"",
            "''",
            "$HOME `id` \\n \\",
            "ü — 雪 \t tab",
            "",
        ];
        let vars: Vec<(String, String)> = values
            .iter()
            .enumerate()
            .map(|(i, v)| (format!("V{i}"), v.to_string()))
            .collect();
        let script = render_export(&vars).unwrap();
        for (i, want) in values.iter().enumerate() {
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("{script}\nprintf %s \"$V{i}\""))
                .env_clear()
                .output()
                .unwrap();
            assert!(out.status.success());
            assert_eq!(String::from_utf8(out.stdout).unwrap(), *want, "V{i}");
        }
    }

    #[test]
    fn export_quotes_single_quotes_and_rejects_invalid_entries() {
        let vars = vec![
            ("A".to_string(), "x'y".to_string()),
            ("1BAD".to_string(), "v".to_string()),
            ("has-dash".to_string(), "v".to_string()),
            ("_ok9".to_string(), "v".to_string()),
        ];
        assert_eq!(render_export(&vars[..1]).unwrap(), "export A='x'\\''y'\n");
        assert!(render_export(&vars).is_err());
        assert!(render_export(&[("A".into(), "nul\0".into())]).is_err());
        for good in ["A", "_", "a_1", "PATH"] {
            assert!(is_shell_name(good), "{good}");
        }
        for bad in ["", "1A", "A-B", "A.B", "é", "A B"] {
            assert!(!is_shell_name(bad), "{bad}");
        }
    }

    #[test]
    fn print0_ends_every_record_with_a_nul() {
        let vars = vec![
            ("A".to_string(), "1\n2".to_string()),
            ("B".to_string(), String::new()),
        ];
        assert_eq!(render_print0(&vars), b"A=1\n2\0B=\0");
    }

    /// Identity variables stay the session's; loader variables only reach the run user.
    #[test]
    fn policy_leaves_out_identity_and_another_users_loader_settings() {
        let f = file(
            Some(1000),
            &[
                ("HOME", "/app"),
                ("PATH", "/home/app/bin:/usr/bin"),
                ("LD_PRELOAD", "/home/app/x.so"),
                ("BASH_ENV", "/home/app/rc"),
                ("TOKEN", "s"),
            ],
        );
        let names = |v: Vec<(String, String)>| v.into_iter().map(|(k, _)| k).collect::<Vec<_>>();
        let p = Policy::default();
        assert_eq!(
            names(select(&f, 1000, p, &none)),
            ["PATH", "LD_PRELOAD", "BASH_ENV", "TOKEN"]
        );
        assert_eq!(names(select(&f, 0, p, &none)), ["TOKEN"]);
        assert_eq!(names(select(&f, 1001, p, &none)), ["TOKEN"]);
        let root = file(Some(0), &[("PATH", "/opt/bin:/usr/bin")]);
        assert!(select(&root, 1000, p, &none).is_empty());
        // A run user the image cannot resolve is nobody's to trust.
        let unknown = file(None, &[("PATH", "/x")]);
        assert!(select(&unknown, 0, p, &none).is_empty());
    }

    /// `--login` keeps what the session already set and restores PATH ahead of what the
    /// profile put there; applying it twice changes nothing more.
    #[test]
    fn login_mode_keeps_session_values_and_merges_path() {
        let f = file(
            Some(0),
            &[
                ("PATH", "/opt/tool/bin:/usr/bin:/bin"),
                ("FOO", "image"),
                ("NEW", "image"),
            ],
        );
        let login = Policy { login: true };
        let env = |path: &'static str| {
            move |k: &str| match k {
                "PATH" => Some(OsString::from(path)),
                "FOO" => Some(OsString::from("session")),
                _ => None,
            }
        };
        let once = select(&f, 0, login, &env("/usr/local/bin:/usr/bin:/bin"));
        assert_eq!(
            once,
            [
                (
                    "PATH".to_string(),
                    "/opt/tool/bin:/usr/bin:/bin:/usr/local/bin".to_string()
                ),
                ("NEW".to_string(), "image".to_string()),
            ]
        );
        let twice = select(
            &f,
            0,
            login,
            &env("/opt/tool/bin:/usr/bin:/bin:/usr/local/bin"),
        );
        assert_eq!(twice[0], once[0]);
    }

    #[test]
    fn login_preserves_the_ssh_sessions_path() {
        let f = file(
            Some(1000),
            &[("PATH", "/image/bin:/usr/bin"), ("TOKEN", "image")],
        );
        let current = |k: &str| match k {
            "PATH" => Some(OsString::from("/usr/bin:/bin")),
            "VIRTKIT_SSH_PATH" => Some(OsString::from("/session/bin:/usr/bin")),
            "TOKEN" => Some(OsString::from("session")),
            _ => None,
        };
        let selected = select(&f, 1000, Policy { login: true }, &current);
        assert_eq!(selected, [("PATH".into(), "/session/bin:/usr/bin".into())]);
    }

    #[test]
    fn profiles_are_copied_without_changing_the_source() {
        let dir = scratch("profiles");
        let source = dir.join("source");
        let dest = dir.join("dest");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&dest).unwrap();
        std::fs::write(source.join("original.sh"), "export ORIGINAL=yes\n").unwrap();
        std::os::unix::fs::symlink("original.sh", source.join("link.sh")).unwrap();
        std::fs::write(source.join(PROFILE_D_NAME), "old hook").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir(source.join("private")).unwrap();
        std::fs::set_permissions(
            source.join("private"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        copy_profiles(&source, &dest).unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.join("original.sh")).unwrap(),
            "export ORIGINAL=yes\n"
        );
        assert_eq!(
            std::fs::read_link(dest.join("link.sh")).unwrap(),
            Path::new("original.sh")
        );
        assert_eq!(
            std::fs::metadata(dest.join("private"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(!dest.join(PROFILE_D_NAME).exists());
        assert_eq!(
            std::fs::read_to_string(source.join(PROFILE_D_NAME)).unwrap(),
            "old hook"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn malformed_environment_rejects_the_entire_file() {
        for env in [
            vec![("GOOD", "ok"), ("BAD", "nul\0")],
            vec![("GOOD", "ok"), ("A=B", "bad")],
            vec![("", "empty name")],
        ] {
            assert!(EnvFile::from_json(&file(Some(0), &env).to_json()).is_err());
        }
    }

    #[test]
    fn args_take_one_mode_and_exec_takes_the_rest() {
        let a = |s: &[&str]| parse_args(&s.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(a(&["--export"]).unwrap().0, Mode::Export);
        let (mode, p) = a(&["--login", "--exec", "sh", "--export"]).unwrap();
        assert_eq!(mode, Mode::Exec(vec!["sh".into(), "--export".into()]));
        assert!(p.login);
        assert!(a(&[]).is_err());
        assert!(a(&["--export", "--print0"]).is_err());
        assert!(a(&["--exec"]).is_err());
        assert!(a(&["--bogus"]).is_err());
    }

    #[test]
    fn a_published_file_reads_back_for_its_owner() {
        let dir = scratch("roundtrip");
        let base = dir.join("vk");
        let f = file(Some(euid()), &[("MULTI", "a\nb\n"), ("Q", "it's")]);
        publish(&base, &f, &[(euid(), egid())]).unwrap();
        assert_eq!(load(&base, euid()).unwrap(), f);
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::metadata(base.join(ENV_DIR).join(format!("{}.json", euid()))).unwrap();
        assert_eq!(md.mode() & 0o777, 0o400);
        // Publishing again replaces the file rather than failing on it.
        publish(&base, &f, &[(euid(), egid())]).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Anything short of a private file of the caller's own, in directories no one else can
    /// write, is an error — never a partial or foreign environment.
    #[test]
    fn load_fails_closed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("closed");
        let base = dir.join("vk");
        // Missing.
        assert!(load(&base, euid()).is_err());
        let f = file(Some(0), &[("A", "1")]);
        publish(&base, &f, &[(euid(), egid())]).unwrap();
        let path = base.join(ENV_DIR).join(format!("{}.json", euid()));
        // Corrupt.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, "{\"env\": [[\"A\"]]}").unwrap();
        assert!(load(&base, euid()).is_err());
        std::fs::write(&path, "not json").unwrap();
        assert!(load(&base, euid()).is_err());
        // Readable by others.
        std::fs::write(&path, f.to_json()).unwrap();
        assert!(load(&base, euid()).is_ok());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&base, euid()).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        // A symlink in its place.
        std::fs::remove_file(&path).unwrap();
        let other = dir.join("other.json");
        std::fs::write(&other, f.to_json()).unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&other, &path).unwrap();
        assert!(load(&base, euid()).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::copy(&other, &path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load(&base, euid()).is_ok());
        // A directory others may write.
        std::fs::set_permissions(base.join(ENV_DIR), std::fs::Permissions::from_mode(0o777))
            .unwrap();
        assert!(load(&base, euid()).is_err());
        std::fs::set_permissions(base.join(ENV_DIR), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        // Unreadable.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        if euid() != 0 {
            assert!(load(&base, euid()).is_err());
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_hook_script_is_posix_and_guards_on_the_agent() {
        assert!(HOOK_SCRIPT.contains(AGENT_BIN));
        let out = std::process::Command::new("sh")
            .arg("-n")
            .arg("-c")
            .arg(HOOK_SCRIPT)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
    }

    /// Without the profile.d directory there is nothing to hook; with one, the hook file is
    /// written beside the environment (mounting it needs root, so it is not attempted here).
    #[test]
    fn no_profile_d_means_no_hook() {
        let dir = scratch("hook");
        let base = dir.join("vk");
        assert!(!hook_login_shells(&base, &dir.join("absent")).unwrap());
        assert!(!base.join("profile.d").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
