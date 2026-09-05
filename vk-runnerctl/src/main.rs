//! `vk-runnerctl` — sets gitlab-runner's `concurrent` from a number `vk` leaves in a file.
//!
//! This is the one virtkit component that runs as root, so it is built to be the smallest
//! thing that can do the job. It decides nothing: unprivileged `vk` measures the host's
//! memory pressure and writes what it would like the runner's concurrency to be, and this
//! clamps that request into a range its own root-owned config sets, edits the one key, and
//! puts the file back atomically.
//!
//! What it deliberately does not take is input that could point it elsewhere. There are no
//! arguments and no paths from the caller: every path comes from `/etc/virtkit/runnerctl.toml`,
//! which it refuses to read unless root alone can write it — that check is what the rest of
//! this rests on, since the file also names the command run as root. The worst an attacker who
//! owns the runner user can do is ask for a concurrency inside the range an administrator
//! already allowed — a throughput nuisance, not a way to write a file of their choosing.
//!
//! Run it as a root systemd timer (nothing needs privilege granted to anyone), or let the
//! runner user call it through a `NOPASSWD` sudoers rule that permits no arguments:
//!
//! ```text
//! gitlab-runner ALL=(root) NOPASSWD: /usr/local/lib/vk/vk-runnerctl ""
//! ```

mod edit;

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;

/// The only path this program takes on faith, and only once it has checked that root alone
/// can write it: everything it names is then an administrator's choice rather than the
/// caller's (see [`load_settings`]).
const CONFIG_PATH: &str = "/etc/virtkit/runnerctl.toml";

/// What an administrator allows, and where the two files live.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    /// gitlab-runner's own config, the file whose `concurrent` this sets.
    runner_config: PathBuf,
    /// Where `vk` writes the concurrency it would like — one integer. Written by the runner
    /// user, so it is a request, never an instruction: the range below is the authority.
    desired_file: PathBuf,
    /// The range a request is clamped into.
    min: u32,
    max: u32,
    /// The shortest interval between two writes, against a caller that flaps. Measured from
    /// the runner config's own mtime, so no state of our own has to be kept — and an
    /// operator's hand edit also buys the file one quiet interval. Default 60.
    #[serde(default = "default_cooldown")]
    cooldown_secs: u64,
    /// A request older than this is treated as gone: `vk` has stopped writing (its host is
    /// idle, or it died), and leaving the runner throttled on a stale number would strand
    /// it. Concurrency then walks back up to `max`, one step per run. Default 300.
    ///
    /// This guards against a producer that has stopped, not one that lies: the request's mtime
    /// belongs to whoever writes it, so a caller can keep a number fresh forever. It only ever
    /// holds a number the range already allows.
    #[serde(default = "default_stale")]
    stale_secs: u64,
    /// Run after a change to make the runner re-read its config, e.g.
    /// `["/usr/bin/systemctl", "kill", "-s", "HUP", "gitlab-runner"]`. Absolute, since a bare
    /// name would be resolved against the caller's `PATH`. Empty (the default) leaves it to
    /// gitlab-runner's own watch on the file.
    #[serde(default)]
    reload_command: Vec<String>,
}

fn default_cooldown() -> u64 {
    60
}
fn default_stale() -> u64 {
    300
}

fn main() -> ExitCode {
    // No arguments, ever: a sudoers rule that has to allow arguments is a wider grant than
    // this needs, and every path it uses comes from its own root-owned config. (The `""` in
    // the sudoers line above restricts the rule to an invocation with no arguments; it does
    // not pass one, so argv is just this program's name.)
    if std::env::args_os().len() > 1 {
        eprintln!(
            "vk-runnerctl takes no arguments: it applies the concurrency requested in the \
             desired_file named by {CONFIG_PATH}"
        );
        return ExitCode::FAILURE;
    }
    // Not setuid, ever. A setuid install would hand this program the caller's whole
    // environment — LD_*, and the PATH that resolves anything it execs — while running as
    // root, and none of the deployments below need it: sudo and a systemd timer both leave
    // the real and effective ids equal.
    // SAFETY: getuid/geteuid read this process's own ids and cannot fail.
    if unsafe { libc::getuid() != libc::geteuid() } {
        eprintln!(
            "vk-runnerctl: refusing to run setuid — grant it through a root systemd timer or a \
             NOPASSWD sudoers rule instead"
        );
        return ExitCode::FAILURE;
    }
    match run(Path::new(CONFIG_PATH)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vk-runnerctl: error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(config_path: &Path) -> Result<()> {
    let settings = load_settings(config_path)?;
    // The file this writes gets the same treatment as the config that named it — the whole
    // chain, not just its parent: unless root alone can replace it, the text read here and the
    // file replaced further down need not be the same file.
    if privileged() {
        root_writable_ancestors(&settings.runner_config)?;
    }
    let text = read_runner_config(&settings.runner_config)?;
    let current = edit::current_concurrent(&text);

    let Some(target) = target(&settings, current)? else {
        return Ok(()); // nothing to do, or too soon to do it again
    };
    if current == Some(target) {
        return Ok(());
    }

    let edited = edit::set_concurrent(&text, target)?;
    edit::verify(&text, &edited, target)?;
    back_up_once(&settings.runner_config)?;
    if !install(&settings.runner_config, &edited)? {
        // Another run is installing its own reading of the same request: say nothing and run
        // nothing, rather than journal a change this run did not make.
        return Ok(());
    }
    // Journalled: the one line that says the runner's capacity moved, and why.
    println!(
        "vk-runnerctl: concurrent {} -> {target} in {}",
        current.map_or("unset".to_string(), |c| c.to_string()),
        settings.runner_config.display()
    );
    // A warning, not a failure: the config is already installed and gitlab-runner's own watch
    // will pick it up: reporting the whole run failed would only send an operator looking for
    // a change that did happen.
    if let Err(e) = reload(&settings) {
        eprintln!("vk-runnerctl: warning: {e:#}");
    }
    Ok(())
}

/// The concurrency to write, or `None` when this run should leave the file alone.
///
/// A live request is clamped into the allowed range. A stale one (`vk` no longer writing)
/// walks the runner back up towards `max` a step at a time rather than leaving it throttled
/// on a number nobody is maintaining — a host with nothing measuring it should be a slow
/// return to normal, not a runner stuck at 1.
fn target(settings: &Settings, current: Option<u32>) -> Result<Option<u32>> {
    // The range itself was checked when the config was read, so `clamp` below cannot panic.
    if age(&settings.runner_config)? < Duration::from_secs(settings.cooldown_secs) {
        return Ok(None);
    }
    let requested = match read_desired(settings)? {
        Some(n) => n,
        // Stale or absent: one step back towards max.
        None => match current {
            Some(c) if c < settings.max => c + 1,
            Some(_) => return Ok(None),
            None => settings.max,
        },
    };
    Ok(Some(requested.clamp(settings.min, settings.max)))
}

/// The concurrency `vk` last asked for, if it is still fresh. Anything unreadable — missing,
/// empty, not a number, written too long ago — reads as "no request": this must not fail a
/// run over a file the unprivileged side controls.
///
/// The unprivileged side owns the directory this lives in, so the file is trusted no further
/// than its digits: opened without following a symlink and without blocking, refused unless
/// it is an ordinary file, and read a few bytes at most. A symlink or a fifo left here would
/// otherwise point this read somewhere else, or hang the privileged run on an open.
fn read_desired(settings: &Settings) -> Result<Option<u32>> {
    if age(&settings.desired_file).unwrap_or(Duration::MAX)
        > Duration::from_secs(settings.stale_secs)
    {
        return Ok(None);
    }
    let Ok(file) = File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&settings.desired_file)
    else {
        return Ok(None);
    };
    if !file.metadata().is_ok_and(|m| m.is_file()) {
        return Ok(None); // a device, a directory: not a request
    }
    // A u32 runs to ten digits; past that this is not the number it claims to be.
    let mut text = String::new();
    if (&file).take(16).read_to_string(&mut text).is_err() {
        return Ok(None);
    }
    Ok(text.trim().parse::<u32>().ok())
}

/// How long ago `path` was last written. A missing file is infinitely old. The link's own
/// time, not its target's: this path is never followed (see [`read_desired`]).
fn age(path: &Path) -> Result<Duration> {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Ok(Duration::MAX);
    };
    let modified = meta.modified().context("reading a modification time")?;
    match SystemTime::now().duration_since(modified) {
        Ok(age) => Ok(age),
        // Stamped in the future — a clock that stepped back, or a hand-set mtime. Reported
        // rather than silently treated as brand new, which would hold the cooldown open and
        // make this program quietly do nothing for as long as the stamp stays ahead.
        Err(_) => {
            eprintln!(
                "vk-runnerctl: warning: {} is modified in the future — treating it as new",
                path.display()
            );
            Ok(Duration::ZERO)
        }
    }
}

/// Read the one file this program takes on faith, having first checked that root alone can
/// write it. Everything else rests on that: it names the runner config, the request file, and
/// the command run as root after a change, so a config someone else can edit is a root shell
/// for them. Checked through the open descriptor rather than the path, and the directory too
/// — being able to replace the file is the same as being able to write it.
fn load_settings(path: &Path) -> Result<Settings> {
    // O_NONBLOCK for the same reason the other two readers use it: a fifo left here would hang
    // the privileged run before any check below could refuse it.
    let mut file = File::options()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    if privileged() {
        let meta = file
            .metadata()
            .with_context(|| format!("reading {}", path.display()))?;
        if !meta.is_file() {
            bail!("{} is not an ordinary file", path.display());
        }
        root_writable_only(&meta, path)?;
        root_writable_ancestors(path)?;
    }
    let mut text = String::new();
    file.read_to_string(&mut text)
        .with_context(|| format!("reading {}", path.display()))?;
    // The message and the offset, never the offending line — the same reason `edit::verify`
    // withholds it: this file is root-only, and whoever reads this program's stderr may be
    // exactly who is not allowed to read it.
    let settings: Settings = toml::from_str(&text).map_err(|e: toml::de::Error| {
        anyhow!(
            "{} does not parse at {:?}: {}",
            path.display(),
            e.span(),
            e.message()
        )
    })?;
    // Absolute or nothing. A relative path would resolve against the caller's working
    // directory — the one input this program's caller still chooses, and it would pick which
    // file the run writes and chowns.
    for named in [&settings.runner_config, &settings.desired_file] {
        if !named.is_absolute() {
            bail!(
                "{}: {} must be an absolute path, or the caller's working directory decides \
                 which file it is",
                path.display(),
                named.display()
            );
        }
    }
    // The range is an administrator's invariant, so it fails here rather than after this run
    // has read a request and taken a backup.
    if settings.min == 0 || settings.min > settings.max {
        bail!(
            "{}: min {} and max {} are not a usable range (min must be at least 1 and no more \
             than max)",
            path.display(),
            settings.min,
            settings.max
        );
    }
    Ok(settings)
}

/// Read the runner config, refusing to follow a symlink at its last component — the same way
/// [`install`] opens it to write. Reading it through a link and replacing the link's own path
/// would verify one file and rewrite another.
fn read_runner_config(config: &Path) -> Result<String> {
    let mut file = File::options()
        .read(true)
        // O_NONBLOCK for the same reason install uses it: a fifo left at this path would
        // otherwise hang the open, and with it the privileged run.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(config)
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP) => {
                anyhow!("{} is a symlink — refusing to follow it", config.display())
            }
            _ => anyhow::Error::new(e).context(format!("reading {}", config.display())),
        })?;
    let mut text = String::new();
    file.read_to_string(&mut text)
        .with_context(|| format!("reading {}", config.display()))?;
    Ok(text)
}

/// Whether this run has privilege worth protecting: root, or the setuid install [`main`]
/// refuses outright. Run as anyone else, the config can reach nothing its caller could not
/// reach already, so the ownership checks would only get in the way. A capability-granted
/// install (`setcap`) is *not* covered and is unsupported: it would have root's authority over
/// these files while looking unprivileged here.
fn privileged() -> bool {
    // SAFETY: geteuid/getuid read this process's own ids and cannot fail.
    unsafe { libc::geteuid() == 0 || libc::getuid() != libc::geteuid() }
}

/// Every directory above `path`, up to the root: being able to replace a directory in the chain
/// is being able to replace the file inside it. A group-writable `/etc` or `/usr/local` would
/// otherwise defeat the check on the file itself.
fn root_writable_ancestors(path: &Path) -> Result<()> {
    for dir in path
        .ancestors()
        .skip(1)
        .filter(|d| !d.as_os_str().is_empty())
    {
        let meta = std::fs::metadata(dir).with_context(|| format!("{}", dir.display()))?;
        root_writable_only(&meta, dir)?;
    }
    Ok(())
}

/// `path` with `suffix` appended to its whole filename. `Path::with_extension` would replace an
/// existing extension instead, so two configs differing only in theirs would share one name.
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut named = path.as_os_str().to_os_string();
    named.push(suffix);
    PathBuf::from(named)
}

/// Root's, and writable by nobody else.
///
/// A *sticky* directory is the one exception: `/tmp` and friends are world-writable by design,
/// and the sticky bit is exactly the rule that nobody may replace an entry they do not own — so
/// it grants no power over root's file inside it. The bit means nothing on a plain file, so it
/// is honoured only for directories.
fn root_writable_only(meta: &std::fs::Metadata, what: &Path) -> Result<()> {
    let sticky_dir = meta.is_dir() && meta.mode() & 0o1000 != 0;
    if meta.mode() & 0o022 != 0 && !sticky_dir {
        bail!(
            "{} is writable by group or other (mode {:o}) — anyone who can edit it can \
             choose what this program runs as root",
            what.display(),
            meta.mode() & 0o7777
        );
    }
    if meta.uid() != 0 {
        bail!(
            "{} is owned by uid {}, not root — this program trusts it to name the paths it \
             writes and the command it runs",
            what.display(),
            meta.uid()
        );
    }
    Ok(())
}

/// Keep the config as it was before this program first touched it. Written once and never
/// again, so it stays the operator's own version rather than yesterday's concurrency.
fn back_up_once(config: &Path) -> Result<()> {
    // Appended, not `with_extension`, which would replace an existing one: a config named
    // `runner.conf` must back up to `runner.conf.vk-orig` and not to `runner.vk-orig`.
    let backup = sibling(config, ".vk-orig");
    if backup.exists() {
        return Ok(()); // already kept; the link below is what makes that final
    }
    // Copied aside in full first, then linked into place: the backup appears complete or not
    // at all, so a run that dies mid-copy cannot leave a truncated file that the next one
    // takes for the operator's own. `create_new` refuses to follow a symlink left at either
    // predictable name, and `hard_link` refuses to replace an existing backup — which is the
    // "once", rather than the check above it.
    // Per-process, like the replacement's own staging name: two runs sharing one would have
    // each remove the other's file mid-copy, and the survivor hard-link a truncated backup
    // into place permanently — the one file here that is written once and never again.
    let staged = sibling(config, &format!(".vk-orig.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&staged); // a killed run's leftover, so create_new can have the name
    if let Err(e) = stage_copy(config, &staged) {
        // Nothing half-copied left behind: what it would hold is the runner's token.
        let _ = std::fs::remove_file(&staged);
        return Err(e);
    }
    let linked = match std::fs::hard_link(&staged, &backup) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
            Err(e).with_context(|| format!("writing {}", backup.display()))
        }
        _ => Ok(()),
    };
    let _ = std::fs::remove_file(&staged); // whichever way the link went
    linked
}

/// Copy `config` to `staged` whole, and no more readable than the original: this becomes a
/// permanent copy of gitlab-runner's config, which holds its registration token, so it must
/// not land at whatever the umask happens to allow.
fn stage_copy(config: &Path, staged: &Path) -> Result<()> {
    // Opened the way every other reader of this path is, so no one of them is the weak link.
    let mut src = File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(config)
        .with_context(|| format!("reading {}", config.display()))?;
    let meta = src
        .metadata()
        .with_context(|| format!("{}", config.display()))?;
    let mut dst = File::options()
        .write(true)
        .create_new(true)
        // Owner-only from the moment it exists; the original's own bits go on below, once
        // there is something in it worth reading.
        .mode(0o600)
        .open(staged)
        .with_context(|| format!("writing {}", staged.display()))?;
    std::io::copy(&mut src, &mut dst).with_context(|| format!("writing {}", staged.display()))?;
    dst.set_permissions(std::fs::Permissions::from_mode(meta.mode() & 0o777))?;
    // SAFETY: the fd is owned by `dst`, which outlives the call; fchown returns 0 or -1.
    if unsafe { libc::fchown(dst.as_raw_fd(), meta.uid(), meta.gid()) } != 0 {
        bail!(
            "restoring ownership of {}: {}",
            staged.display(),
            std::io::Error::last_os_error()
        );
    }
    dst.sync_all()
        .with_context(|| format!("writing {}", staged.display()))
}

/// Replace `config` with `text` in one step, keeping its mode and ownership. gitlab-runner
/// watches this file: it has to see either the old config or the new one, never a partial
/// write, and never one it can no longer read.
///
/// `false` when another run holds the config's lock, and its own write is the current one.
fn install(config: &Path, text: &str) -> Result<bool> {
    // Opened without following a link, and the mode and owner then read from that one
    // descriptor. Asking the path twice — once whether it is a link, once for its metadata —
    // leaves a moment in which it could become one, and the replacement would take the
    // target's owner.
    let current = File::options()
        .read(true)
        // O_NONBLOCK as well, for the same reason the request file is opened that way: a fifo
        // left at this path would otherwise hang the open, and with it the privileged run.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(config)
        .map_err(|e| match e.raw_os_error() {
            // O_NOFOLLOW's refusal. It guards the last component only — a link earlier in the
            // path is still followed, as it is for every other file named by this config.
            Some(libc::ELOOP) => {
                anyhow!("{} is a symlink — refusing to follow it", config.display())
            }
            _ => anyhow::Error::new(e).context(format!("opening {}", config.display())),
        })?;
    let meta = current
        .metadata()
        .with_context(|| format!("{}", config.display()))?;
    if !meta.is_file() {
        bail!(
            "{} is not an ordinary file — refusing to replace it",
            config.display()
        );
    }
    // One writer at a time. Both sanctioned deployments can fire at once — a root timer and
    // the sudoers rule — and the cooldown cannot separate them, since it reads an mtime none of
    // them has moved yet. Two runs interleaving on the staging name below would have one rename
    // a file the other had not finished writing over the runner's config.
    // SAFETY: the fd is owned by `current`, which outlives the call; flock returns 0 or -1.
    if unsafe { libc::flock(current.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let e = std::io::Error::last_os_error();
        // Only contention means "someone else has this in hand". Anything else — no locks
        // left, say — is a failure to report, not a reason to call the run a success.
        if e.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(e).with_context(|| format!("locking {}", config.display()));
        }
        return Ok(false); // another run holds it, and its write is the current one
    }
    // Per-process, so a leftover from a killed run can never be a live run's file, and named by
    // appending rather than by replacing an extension.
    let tmp = sibling(config, &format!(".vk-new.{}", std::process::id()));
    if let Err(e) = write_replacement(&tmp, text, &meta) {
        // Nothing left behind holding the runner's registration token.
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::rename(&tmp, config).with_context(|| format!("installing {}", config.display()))?;
    Ok(true)
}

/// Write the replacement config to `tmp`, carrying `meta`'s mode and ownership.
fn write_replacement(tmp: &Path, text: &str, meta: &std::fs::Metadata) -> Result<()> {
    // Whatever a crashed run left is removed first, then created exclusively: `create_new`
    // will not follow a symlink left at this predictable name. Owner-only from the moment it
    // exists — this holds the whole runner config, registration token included, and the
    // original's own bits go on below once there is something in it worth reading.
    let _ = std::fs::remove_file(tmp);
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    file.write_all(text.as_bytes())?;
    // Permission bits only: a config has no business carrying setuid, setgid or sticky,
    // and copying them from whatever is there now would only spread them.
    file.set_permissions(std::fs::Permissions::from_mode(meta.mode() & 0o777))?;
    // A config owned by the runner's own user must stay that way; only root reaches here,
    // so a new file would otherwise land as root's. Through the descriptor rather than the
    // path, which anyone who can write this directory could point elsewhere first.
    // SAFETY: the fd is owned by `file`, which outlives the call; fchown returns 0 or -1.
    if unsafe { libc::fchown(file.as_raw_fd(), meta.uid(), meta.gid()) } != 0 {
        bail!(
            "restoring ownership of {}: {}",
            tmp.display(),
            std::io::Error::last_os_error()
        );
    }
    file.sync_all()
        .with_context(|| format!("writing {}", tmp.display()))
}

/// Tell the runner to re-read its config, when the administrator configured a way to. Its
/// own watcher picks the change up regardless; this only shortens the wait.
fn reload(settings: &Settings) -> Result<()> {
    let Some((program, args)) = settings.reload_command.split_first() else {
        return Ok(());
    };
    // Named absolutely, and run in an environment of our own making. This is a root exec, and
    // both the PATH that would resolve a bare name and the variables the child reads come from
    // whoever invoked this program — not from the administrator who chose the command. A
    // `systemctl` found on the caller's PATH is a root shell for them.
    if !Path::new(program).is_absolute() {
        bail!(
            "reload_command must name an absolute path, not {program} — a bare name would be \
             resolved against the caller's PATH"
        );
    }
    let status = std::process::Command::new(program)
        .args(args)
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .stdin(std::process::Stdio::null())
        .status()
        .with_context(|| format!("running reload_command {program}"))?;
    if !status.success() {
        bail!("reload_command {program} exited {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Where a coreutils tool lives on this host — `reload` takes absolute paths only.
    /// Search `PATH` before the usual directories: the development VM has both
    /// `/usr/bin` and `/bin`, and neither holds `true`.
    /// Skip relative `PATH` entries because `reload` requires an absolute path.
    fn absolute_tool(name: &str) -> String {
        let path = std::env::var("PATH").unwrap_or_default();
        path.split(':')
            .map(PathBuf::from)
            .chain(["/usr/bin", "/bin"].iter().map(PathBuf::from))
            .filter(|dir| dir.is_absolute())
            .map(|dir| dir.join(name))
            .find(|p| p.is_file())
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| panic!("no {name} on PATH, in /usr/bin or in /bin"))
    }

    fn settings(dir: &Path, min: u32, max: u32) -> Settings {
        Settings {
            runner_config: dir.join("config.toml"),
            desired_file: dir.join("desired"),
            min,
            max,
            cooldown_secs: 0,
            stale_secs: 300,
            reload_command: Vec::new(),
        }
    }

    fn tmpdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-runnerctl-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_request_is_clamped_into_the_allowed_range() {
        let dir = tmpdir("clamp");
        let s = settings(&dir, 2, 8);
        std::fs::write(&s.runner_config, "concurrent = 4\n").unwrap();

        std::fs::write(&s.desired_file, "6\n").unwrap();
        assert_eq!(target(&s, Some(4)).unwrap(), Some(6));

        // Beyond the range in either direction, the range wins — this is the whole defence
        // against a caller that should not be trusted with the number.
        std::fs::write(&s.desired_file, "999").unwrap();
        assert_eq!(target(&s, Some(4)).unwrap(), Some(8));
        std::fs::write(&s.desired_file, "0").unwrap();
        assert_eq!(target(&s, Some(4)).unwrap(), Some(2));

        // Nonsense reads as no request at all, which walks back towards max.
        std::fs::write(&s.desired_file, "; rm -rf /").unwrap();
        assert_eq!(target(&s, Some(4)).unwrap(), Some(5));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_request_nobody_is_maintaining_walks_back_up() {
        let dir = tmpdir("stale");
        let s = settings(&dir, 1, 8);
        std::fs::write(&s.runner_config, "concurrent = 3\n").unwrap();

        // No file at all: one step towards max, not a jump.
        assert_eq!(target(&s, Some(3)).unwrap(), Some(4));
        // Already at max: nothing to write, so the file is not touched at all.
        assert_eq!(target(&s, Some(8)).unwrap(), None);
        // A config with no key at all starts from max rather than from a guess.
        assert_eq!(target(&s, None).unwrap(), Some(8));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_cooldown_holds_a_flapping_caller_off() {
        let dir = tmpdir("cooldown");
        let mut s = settings(&dir, 1, 8);
        s.cooldown_secs = 3600; // the config was just written, so it is inside the interval
        std::fs::write(&s.runner_config, "concurrent = 4\n").unwrap();
        std::fs::write(&s.desired_file, "8").unwrap();
        assert_eq!(target(&s, Some(4)).unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An unusable range is refused when the config is read, before the run has touched
    /// anything — not later, on the way to a clamp that would panic on it.
    #[test]
    fn an_impossible_range_is_refused_rather_than_applied() {
        let dir = tmpdir("range");
        let mut s = settings(&dir, 0, 8);
        std::fs::write(&s.runner_config, "concurrent = 4\n").unwrap();
        let config = dir.join("runnerctl.toml");

        std::fs::write(&config, settings_toml(&s)).unwrap();
        assert!(load_settings(&config).is_err(), "min of zero");
        s.min = 9;
        s.max = 8;
        std::fs::write(&config, settings_toml(&s)).unwrap();
        assert!(load_settings(&config).is_err(), "min above max");

        // And a range that is usable is accepted, so the check is not simply refusing everything.
        s.min = 1;
        std::fs::write(&config, settings_toml(&s)).unwrap();
        load_settings(&config).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A relative path in the config would resolve against the caller's working directory,
    /// which is the one thing the caller still chooses.
    #[test]
    fn a_relative_path_in_the_config_is_refused() {
        let dir = tmpdir("relative");
        let mut s = settings(&dir, 1, 8);
        let config = dir.join("runnerctl.toml");

        s.runner_config = PathBuf::from("config.toml");
        std::fs::write(&config, settings_toml(&s)).unwrap();
        assert!(load_settings(&config).is_err(), "relative runner_config");

        s.runner_config = dir.join("config.toml");
        s.desired_file = PathBuf::from("desired");
        std::fs::write(&config, settings_toml(&s)).unwrap();
        assert!(load_settings(&config).is_err(), "relative desired_file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// End to end on a real file: the config keeps its mode, its comments and its secret,
    /// and only the one key moves.
    #[test]
    fn applies_a_request_to_a_config_in_place() {
        let dir = tmpdir("apply");
        let s = settings(&dir, 1, 8);
        let original = "# ours\nconcurrent = 2\n\n[[runners]]\n  token = \"glrt-SECRET\"\n";
        std::fs::write(&s.runner_config, original).unwrap();
        std::fs::set_permissions(&s.runner_config, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&s.desired_file, "5\n").unwrap();
        std::fs::write(dir.join("runnerctl.toml"), settings_toml(&s)).unwrap();

        run(&dir.join("runnerctl.toml")).unwrap();

        let after = std::fs::read_to_string(&s.runner_config).unwrap();
        assert!(after.starts_with("# ours\nconcurrent = 5\n"), "{after}");
        assert!(after.contains("glrt-SECRET"));
        let mode = std::fs::metadata(&s.runner_config).unwrap().mode() & 0o7777;
        assert_eq!(mode, 0o600, "mode not preserved");
        // The operator's own version is kept once.
        assert_eq!(
            std::fs::read_to_string(dir.join("config.toml.vk-orig")).unwrap(),
            original
        );
        // And nothing token-bearing is left behind. Asserted on the directory's contents, not
        // on the staging names: those carry this process's pid, so naming them literally would
        // check for files that never existed.
        let mut left: Vec<std::ffi::OsString> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                "config.toml",
                "config.toml.vk-orig",
                "desired",
                "runnerctl.toml"
            ]
            .map(std::ffi::OsString::from),
            "a staging copy of the config survived the run"
        );
        // The backup is a copy of a file holding the runner's token, so it must be no more
        // readable than the original — not whatever the umask would have given it.
        let backup = dir.join("config.toml.vk-orig");
        assert_eq!(
            std::fs::metadata(&backup).unwrap().mode() & 0o777,
            0o600,
            "the backup widened the config's permissions"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn settings_toml(s: &Settings) -> String {
        format!(
            "runner_config = \"{}\"\ndesired_file = \"{}\"\nmin = {}\nmax = {}\n\
             cooldown_secs = 0\nreload_command = {:?}\n",
            s.runner_config.display(),
            s.desired_file.display(),
            s.min,
            s.max,
            s.reload_command,
        )
    }

    /// The check the rest of the design rests on: this config names the paths written and the
    /// command run as root, so anyone who can edit it chooses both.
    #[test]
    fn a_config_root_alone_cannot_write_is_refused() {
        let dir = tmpdir("trust");
        let path = dir.join("runnerctl.toml");
        std::fs::write(&path, "").unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let err = root_writable_only(&std::fs::metadata(&path).unwrap(), &path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("writable by group or other"), "{err}");

        // Tight enough now, so what is left is who owns it — which is whoever runs the tests.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let checked = root_writable_only(&std::fs::metadata(&path).unwrap(), &path);
        // SAFETY: geteuid reads this process's own id and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            checked.expect("root created it, so both checks pass");
        } else {
            assert!(checked.unwrap_err().to_string().contains("not root"));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Being able to replace a file is the same as being able to write it, so the whole
    /// directory chain has to be root's alone — not just the file, and not just its immediate
    /// parent. Only meaningful under a privileged euid, which is where the check applies.
    #[test]
    fn a_group_writable_directory_over_the_config_is_refused() {
        let dir = tmpdir("trust-dir");
        let nested = dir.join("etc");
        std::fs::create_dir(&nested).unwrap();
        let path = nested.join("runnerctl.toml");
        std::fs::write(&path, settings_toml(&settings(&dir, 1, 8))).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        // The immediate parent, then a grandparent: each must be enough on its own to refuse.
        for loose in [&nested, &dir] {
            std::fs::set_permissions(loose, std::fs::Permissions::from_mode(0o777)).unwrap();
            let err = std::fs::metadata(loose)
                .map_err(anyhow::Error::new)
                .and_then(|m| root_writable_only(&m, loose))
                .unwrap_err()
                .to_string();
            assert!(err.contains("writable by group or other"), "{err}");
            std::fs::set_permissions(loose, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        // A sticky world-writable directory is the exception, and has to be: every one of these
        // paths sits under /tmp, which is 1777 by design, and the sticky bit is exactly the rule
        // that nobody may replace an entry they do not own.
        // (Only the write-bits half is asserted here: who owns it is a separate refusal, and
        // these paths are owned by whoever runs the tests.)
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let sticky = root_writable_only(&std::fs::metadata(&nested).unwrap(), &nested);
        assert!(
            !sticky
                .as_ref()
                .err()
                .is_some_and(|e| e.to_string().contains("writable by group or other")),
            "a sticky directory grants no power over root's file inside it: {sticky:?}"
        );
        // The same bits on a plain file mean nothing of the sort.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o1666)).unwrap();
        let err = root_writable_only(&std::fs::metadata(&path).unwrap(), &path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("writable by group or other"), "{err}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o755)).unwrap();

        // And load_settings walks that chain rather than stopping at the parent: run as root
        // it refuses, run as anyone else the check does not apply and it reads normally.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let loaded = load_settings(&path);
        // SAFETY: geteuid reads this process's own id and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            assert!(
                loaded
                    .unwrap_err()
                    .to_string()
                    .contains("writable by group or other"),
                "a loose ancestor must be refused"
            );
        } else {
            loaded.expect("unprivileged, so the ownership checks do not apply");
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A link planted at the config's path would otherwise hand the replacement its target's
    /// owner, and write through to a file of someone else's choosing.
    #[test]
    fn a_symlinked_runner_config_is_refused() {
        let dir = tmpdir("symlink-config");
        let real = dir.join("elsewhere.toml");
        std::fs::write(&real, "concurrent = 1\n").unwrap();
        let link = dir.join("config.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err = install(&link, "concurrent = 2\n").unwrap_err().to_string();
        assert!(err.contains("symlink"), "{err}");
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "concurrent = 1\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The request lives in the runner user's own directory: read as an ordinary small file
    /// or not read at all.
    #[test]
    fn a_request_that_is_not_a_plain_number_is_ignored() {
        let dir = tmpdir("request");
        let s = settings(&dir, 1, 8);
        std::fs::write(dir.join("real"), "7\n").unwrap();
        std::os::unix::fs::symlink(dir.join("real"), &s.desired_file).unwrap();
        assert_eq!(read_desired(&s).unwrap(), None, "a symlink was followed");

        // The same number in an ordinary file is a request.
        std::fs::remove_file(&s.desired_file).unwrap();
        std::fs::write(&s.desired_file, "7\n").unwrap();
        assert_eq!(read_desired(&s).unwrap(), Some(7));

        // More than a number's worth of digits is not one.
        std::fs::write(&s.desired_file, "7".repeat(100)).unwrap();
        assert_eq!(read_desired(&s).unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The reload is a courtesy — gitlab-runner watches the file anyway — so a command that
    /// fails must not report a run that already installed its change as failed.
    #[test]
    fn a_failing_reload_does_not_undo_or_fail_the_run() {
        let dir = tmpdir("reload");
        let mut s = settings(&dir, 1, 8);
        // Absolute: a bare name would be resolved against the caller's PATH, which `reload`
        // refuses precisely because this runs as root.
        let (yes, no) = (absolute_tool("true"), absolute_tool("false"));
        s.reload_command = vec![no.clone()];
        assert!(reload(&s).is_err(), "a failing command is still reported");
        s.reload_command = vec![yes];
        reload(&s).unwrap();
        s.reload_command = vec!["false".into()];
        assert!(
            reload(&s).is_err_and(|e| e.to_string().contains("absolute")),
            "a bare name is refused rather than resolved on PATH"
        );
        s.reload_command = Vec::new();
        reload(&s).unwrap(); // none configured, nothing to run

        // Through `run`, the same failure is a warning and the edit stands.
        s.reload_command = vec![no];
        std::fs::write(&s.runner_config, "concurrent = 2\n").unwrap();
        std::fs::write(&s.desired_file, "5\n").unwrap();
        std::fs::write(dir.join("runnerctl.toml"), settings_toml(&s)).unwrap();
        run(&dir.join("runnerctl.toml")).unwrap();
        assert_eq!(
            std::fs::read_to_string(&s.runner_config).unwrap(),
            "concurrent = 5\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
