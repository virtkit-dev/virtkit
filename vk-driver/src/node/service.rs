//! `vk node service`: run `vk node run` under systemd. As root, a system unit in
//! `/etc/systemd/system`, running as root or as the user `--user` names; as any other user, a
//! user unit under `$XDG_CONFIG_HOME/systemd/user`, with lingering enabled so it outlives the
//! user's logins.
//!
//! The unit runs this command's resolved binary, the installed `vk` that updates replace in
//! place. It uses the config this command read, preserving the state dir `join` enrolled.

use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};

use crate::config::Config;

pub const UNIT: &str = "vk-node.service";

/// The unit file's first line, by which `install` and `uninstall` tell a unit of theirs from
/// one an administrator wrote.
const HEADER: &str = "# Written by `vk node service install`, which rewrites it.";

/// systemd's own `PATH`, the one a system unit runs with and a user manager starts from.
const SYSTEMD_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// `TimeoutStopSec`'s default. A stop with a managed runner waits for its jobs; an hour is
/// GitLab's default job timeout, so a job that started just before the stop can finish.
pub const DEFAULT_STOP_TIMEOUT: &str = "1h";

/// Which systemd manager the unit belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// root's: `/etc/systemd/system`, plain `systemctl`.
    System,
    /// The invoking user's: `systemctl --user`.
    User,
}

impl Scope {
    fn current() -> Scope {
        if euid() == 0 {
            Scope::System
        } else {
            Scope::User
        }
    }

    fn unit_dir(self) -> Result<PathBuf> {
        match self {
            Scope::System => Ok(PathBuf::from("/etc/systemd/system")),
            // Through `su` or `sudo -u`, `HOME` and the XDG variables may still be the
            // invoking user's; the passwd entry is this user's own.
            Scope::User => {
                user_unit_dir(own_dir(std::env::var_os("XDG_CONFIG_HOME"), euid()), || {
                    Ok(Account::of(euid())?.home)
                })
            }
        }
    }

    fn systemctl(self) -> Command {
        let mut cmd = Command::new("systemctl");
        if self == Scope::User {
            cmd.arg("--user");
            // Reached through `su` or `sudo -u`, the user manager is running but not found
            // without its runtime dir, or under the invoking user's.
            if own_dir(std::env::var_os("XDG_RUNTIME_DIR"), euid()).is_none() {
                let runtime = PathBuf::from(format!("/run/user/{}", euid()));
                if runtime.is_dir() {
                    cmd.env("XDG_RUNTIME_DIR", runtime);
                }
            }
        }
        cmd
    }
}

/// This process's effective uid.
fn euid() -> u32 {
    // SAFETY: `geteuid` reads this process's own id and cannot fail.
    unsafe { libc::geteuid() }
}

/// The directory `var` names, when `uid` owns it: one of another user's, inherited through
/// `su` or `sudo -u`, is not this user's to use.
fn own_dir(var: Option<std::ffi::OsString>, uid: u32) -> Option<PathBuf> {
    var.map(PathBuf::from)
        .filter(|p| std::fs::metadata(p).is_ok_and(|m| m.uid() == uid))
}

/// A user manager's unit directory: under `xdg`, the `XDG_CONFIG_HOME` given, when absolute
/// (XDG ignores a relative one), else under the `home` the passwd entry gives.
fn user_unit_dir(xdg: Option<PathBuf>, home: impl FnOnce() -> Result<PathBuf>) -> Result<PathBuf> {
    let config = match xdg.filter(|p| p.is_absolute()) {
        Some(config) => config,
        None => {
            let home = home()?;
            if !home.is_absolute() {
                bail!("this user's home directory, {home:?}, is not absolute");
            }
            home.join(".config")
        }
    };
    Ok(config.join("systemd").join("user"))
}

/// What the unit runs, and how.
pub struct Unit<'a> {
    pub scope: Scope,
    /// The user a system unit runs as. Named even for root: systemd sets `HOME` only for a
    /// unit with `User=`, and a managed runner's config defaults to one under it.
    pub user: Option<&'a str>,
    /// The `vk` to run, absolute.
    pub exe: &'a Path,
    /// The config to run it with, absolute; `None` for the built-in defaults.
    pub config: Option<&'a Path>,
    pub stop_timeout: Duration,
}

/// The unit file's text.
///
/// `Restart=on-failure` restarts `vk node run` after a crash, a release on trial killed by the
/// `SIGALRM` armed past its deadline, a start that found another `vk node` holding the lock (exit 75), and
/// every other failure. A refusal for good (`not_enrolled`, `bad_signature`, `revoked`) exits
/// 1 like a local failure, and a release on trial that exits 1 must still be restarted for the
/// previous binary to take the node back, so no status is exempt: the start limit is what
/// ends a node that fails on every start. Ten starts in ten minutes leaves room for a trial's
/// attempts and the rollback after them.
///
/// `OOMPolicy=continue`: the kernel killing one job's VM is that job's failure, not the
/// node's.
///
/// No sandboxing: the unit's processes are the runner, its executors and their VMs, which
/// need /dev/kvm, taps, the state dir and the installed `vk`'s directory; the VM is the
/// isolation boundary.
pub fn render(unit: &Unit<'_>) -> Result<String> {
    let mut exec = vec![exec_word(unit.exe)?];
    if let Some(config) = unit.config {
        exec.push("--config".to_string());
        exec.push(exec_word(config)?);
    }
    exec.extend(["node".to_string(), "run".to_string()]);
    let (wants, wanted_by) = match unit.scope {
        Scope::System => (
            "Wants=network-online.target\nAfter=network-online.target\n",
            "multi-user.target",
        ),
        // A user manager cannot see system targets; the node retries the hub itself.
        Scope::User => ("", "default.target"),
    };
    let user = unit.user.map(|u| format!("User={u}\n")).unwrap_or_default();
    let timeout = match unit.stop_timeout.as_secs() {
        0 => "infinity".to_string(),
        secs => format!("{secs}s"),
    };
    // `KillMode=mixed`: a stop's SIGTERM reaches the node alone, which quits a managed runner
    // and waits for its jobs. A node that exits on its own takes them with it all the same:
    // systemd kills what is left of the unit before restarting it.
    Ok(format!(
        "{HEADER}\n\
         [Unit]\n\
         Description=virtkit fleet node\n\
         {wants}\
         StartLimitIntervalSec=600\n\
         StartLimitBurst=10\n\
         \n\
         [Service]\n\
         {user}\
         ExecStart={exec}\n\
         KillMode=mixed\n\
         TimeoutStopSec={timeout}\n\
         OOMPolicy=continue\n\
         Restart=on-failure\n\
         RestartSec=10s\n\
         \n\
         [Install]\n\
         WantedBy={wanted_by}\n",
        exec = exec.join(" "),
    ))
}

/// `path` as one word of an `ExecStart=` command line: specifiers (`%`) and variables (`$`)
/// escaped, and quoted when it holds anything but plain path characters. vk-registry's
/// `unit_path`, for the unit it prints, refuses such paths rather than escape them.
fn exec_word(path: &Path) -> Result<String> {
    let text = path
        .to_str()
        .with_context(|| format!("{} is not UTF-8, which a unit file must be", path.display()))?;
    if text.chars().any(char::is_control) {
        bail!("{text:?} holds a control character");
    }
    let plain = !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._+-,:=@".contains(c));
    let mut word = String::with_capacity(text.len().saturating_add(2));
    if !plain {
        word.push('"');
    }
    for c in text.chars() {
        match c {
            '%' => word.push_str("%%"),
            '$' => word.push_str("$$"),
            '\\' => word.push_str("\\\\"),
            '"' => word.push_str("\\\""),
            c => word.push(c),
        }
    }
    if !plain {
        word.push('"');
    }
    Ok(word)
}

/// `vk node service install`, for the node to run as `user` when given; only root may name
/// one.
pub fn install(
    cfg: &Config,
    start: bool,
    stop_timeout: Duration,
    user: Option<&str>,
) -> Result<()> {
    let scope = Scope::current();
    let dir = super::dir(cfg);
    let account = match (scope, user) {
        (Scope::User, Some(_)) => bail!(
            "--user installs a system unit, which takes root; to run the node as this user, \
             leave it out"
        ),
        (Scope::User, None) => None,
        (Scope::System, Some(name)) => Some(Account::named(name)?),
        (Scope::System, None) => Some(Account::of(0)?),
    };
    match &account {
        Some(account) => owned_by(&dir, account).map_err(super::not_enrolled)?,
        None => super::check_private(&dir).map_err(super::not_enrolled)?,
    }
    super::read_enrollment(&dir).map_err(super::not_enrolled)?;
    let key = super::identity::key_path(&dir);
    std::fs::symlink_metadata(&key)
        .with_context(|| format!("reading {}", key.display()))
        .map_err(super::not_enrolled)?;
    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .context("resolving the running vk")?;
    if super::update::under(&exe, &dir) {
        bail!(
            "{} is a release inside the node's own directory; run this from the installed vk",
            exe.display()
        );
    }
    let config = cfg
        .source
        .as_deref()
        .map(|p| std::fs::canonicalize(p).with_context(|| format!("resolving {}", p.display())))
        .transpose()?;
    if let Some(account) = &account {
        reachable(account, &dir, &exe, config.as_deref())?;
    }
    if cfg.node.runner == vk_hub_proto::RunnerMode::Managed
        && cfg.node.gitlab_runner.is_none()
        && on_path("gitlab-runner", SYSTEMD_PATH).is_none()
    {
        bail!(
            "the service would not find gitlab-runner on systemd's PATH ({SYSTEMD_PATH}); set \
             [node] gitlab_runner to its absolute path"
        );
    }
    let unit_dir = scope.unit_dir()?;
    let path = unit_dir.join(UNIT);
    ours(&path)?;
    other_scope(scope, account.as_ref())?;
    // A node already holding the state dir would make every start of the unit exit 75. The
    // unit's own node holds it while active or on its way in or out; one stopping may still
    // be waiting for jobs, and is left to finish.
    match active_state(scope).as_str() {
        "active" => {}
        "inactive" | "failed" | "" => {
            if start {
                idle(&dir, super::LOCK_TRIES)?;
            }
        }
        state => bail!("{UNIT} is {state}; run this again once it is active or inactive"),
    }
    let text = render(&Unit {
        scope,
        user: account.as_ref().map(|a| a.name.as_str()),
        exe: &exe,
        config: config.as_deref(),
        stop_timeout,
    })?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(&unit_dir)
        .with_context(|| format!("creating {}", unit_dir.display()))?;
    vk_fs::write_atomic(&path, text.as_bytes(), 0o644)
        .with_context(|| format!("writing {}", path.display()))?;
    println!("vk node: wrote {}", path.display());
    if scope == Scope::User {
        linger();
    }
    let manager = |e: anyhow::Error| {
        e.context(format!(
            "{} is written, but the systemd manager could not take it",
            path.display()
        ))
    };
    systemctl(scope, &["daemon-reload"]).map_err(manager)?;
    let running = is_active(scope);
    // A node that hit the start limit starts again only once this clears it; on a unit that
    // never failed it does nothing, and its failure leaves the start below to report.
    let _ = scope
        .systemctl()
        .args(["reset-failed", UNIT])
        .stderr(std::process::Stdio::null())
        .status();
    systemctl(scope, &["enable", UNIT]).map_err(manager)?;
    if running {
        println!("vk node: restarting {UNIT}: the node stops once a managed runner's jobs finish");
        systemctl(scope, &["restart", UNIT]).map_err(manager)?;
        println!("vk node: {UNIT} enabled and restarted");
    } else if start {
        systemctl(scope, &["start", UNIT]).map_err(manager)?;
        println!("vk node: {UNIT} enabled and started");
    } else {
        println!("vk node: {UNIT} enabled, not started");
    }
    Ok(())
}

/// `vk node service uninstall`: stop and disable the unit and remove it; the enrollment stays.
pub fn uninstall() -> Result<()> {
    let scope = Scope::current();
    let path = scope.unit_dir()?.join(UNIT);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // A unit file deleted by hand can leave its enablement link behind.
            let _ = scope
                .systemctl()
                .args(["disable", UNIT])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            println!("vk node: {} is not installed", path.display());
            return Ok(());
        }
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    }
    ours(&path)?;
    if is_active(scope) {
        println!("vk node: stopping {UNIT}: the node stops once a managed runner's jobs finish");
    }
    systemctl(scope, &["disable", "--now", UNIT])?;
    std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    systemctl(scope, &["daemon-reload"])?;
    // A unit that failed stays listed, as failed, until this clears it.
    let _ = scope
        .systemctl()
        .args(["reset-failed", UNIT])
        .stderr(std::process::Stdio::null())
        .status();
    println!(
        "vk node: {UNIT} stopped and disabled; removed {}",
        path.display()
    );
    Ok(())
}

/// That `path`, when there is one, is a unit `install` wrote, not one of an administrator's.
fn ours(path: &Path) -> Result<()> {
    match std::fs::read(path) {
        Ok(text) if text.starts_with(HEADER.as_bytes()) => Ok(()),
        Ok(_) => bail!(
            "{} was not written by `vk node service install`; remove it first",
            path.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// That the other systemd manager runs no node as the same user. Two nodes for one user are
/// refused: they would usually share a state dir, and the one that lost would fail on every
/// start.
fn other_scope(scope: Scope, account: Option<&Account>) -> Result<()> {
    match (scope, account) {
        (Scope::System, Some(account)) => {
            let path = account.home.join(".config/systemd/user").join(UNIT);
            if path.exists() {
                bail!(
                    "{} has a user unit of its own, {}: remove it first, with `vk node service \
                     uninstall` run as {}",
                    account.name,
                    path.display(),
                    account.name
                );
            }
        }
        (Scope::User, _) => {
            let path = Path::new("/etc/systemd/system").join(UNIT);
            let me = Account::of(euid())?;
            if runs_as(&path, &me.name)? {
                bail!(
                    "{} already runs the node as {}: remove it first, with `sudo vk node service \
                     uninstall`",
                    path.display(),
                    me.name
                );
            }
        }
        (Scope::System, None) => {}
    }
    Ok(())
}

/// Whether the unit file at `path`, if any, runs as `user`.
fn runs_as(path: &Path, user: &str) -> Result<bool> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text
            .lines()
            .any(|line| line.trim().strip_prefix("User=") == Some(user))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// That no `vk node` holds the node dir `dir`, trying `tries` times as `vk node run` does. A
/// node dir without a lock file was never locked; the file is not created here, which as root
/// would leave it root's.
fn idle(dir: &Path, tries: u32) -> Result<()> {
    if !dir.join(super::LOCK_FILE).exists() {
        return Ok(());
    }
    match super::lock_tries(dir, tries) {
        Ok(_) => Ok(()),
        Err(e) if e.is::<super::Locked>() => bail!(
            "another `vk node` holds {}; stop it first (a foreground `vk node run`, or a unit of \
             your own)",
            dir.display()
        ),
        Err(e) => Err(e),
    }
}

/// `name` in the first directory of the `:`-separated `path` that holds it as an executable
/// file.
fn on_path(name: &str, path: &str) -> Option<PathBuf> {
    std::env::split_paths(path)
        .map(|dir| dir.join(name))
        .find(|p| std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.mode() & 0o111 != 0))
}

/// Run `systemctl` in `scope` with `args`, requiring success.
fn systemctl(scope: Scope, args: &[&str]) -> Result<()> {
    let line = || {
        let user = if scope == Scope::User { " --user" } else { "" };
        format!("systemctl{user} {}", args.join(" "))
    };
    let status = scope
        .systemctl()
        .args(args)
        .status()
        .with_context(|| format!("running {}", line()))?;
    if !status.success() {
        bail!("`{}` failed ({status})", line());
    }
    Ok(())
}

/// The unit's `ActiveState`; empty when the manager cannot be asked.
fn active_state(scope: Scope) -> String {
    scope
        .systemctl()
        .args(["show", "--property=ActiveState", "--value", UNIT])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// Whether the unit is running now.
fn is_active(scope: Scope) -> bool {
    scope
        .systemctl()
        .args(["is-active", "--quiet", UNIT])
        .status()
        .is_ok_and(|s| s.success())
}

/// Keep this user's manager, and so the node, running without a login session: enable
/// lingering, or say how to when this user may not.
fn linger() {
    // SAFETY: `getuid` reads this process's own id and cannot fail.
    let user = match Account::of(unsafe { libc::getuid() }) {
        Ok(account) => account.name,
        Err(e) => {
            println!("vk node: warning: cannot tell whether lingering is enabled: {e:#}");
            return;
        }
    };
    let lingering = Command::new("loginctl")
        .args(["show-user", &user, "--property=Linger", "--value"])
        .stderr(std::process::Stdio::null())
        .output()
        .is_ok_and(|out| out.status.success() && out.stdout.trim_ascii() == b"yes");
    if lingering {
        println!("vk node: lingering is enabled for {user}");
        return;
    }
    let enabled = Command::new("loginctl")
        .args(["--no-ask-password", "enable-linger"])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if enabled {
        println!("vk node: enabled lingering for {user}, so the node runs without a login");
    } else {
        println!(
            "vk node: warning: lingering is off for {user}, and this user may not enable it: \
             the node stops when {user}'s last session ends. Enable it with `sudo loginctl \
             enable-linger {user}`"
        );
    }
}

/// That the node dir `dir` belongs to `account` and is private to it, as `vk node run` running
/// as that user requires.
fn owned_by(dir: &Path, account: &Account) -> Result<()> {
    super::check_private_to(dir, account.uid).map_err(|e| {
        let owner = match std::fs::symlink_metadata(dir) {
            Ok(meta) if meta.is_dir() && meta.uid() != account.uid => meta.uid(),
            _ => return e,
        };
        let owner = Account::of(owner).map_or_else(|_| owner.to_string(), |a| a.name);
        anyhow!(
            "{} belongs to {owner}: this host was enrolled as {owner}. Install with `--user \
             {owner}`, or, to run the node as {name}, remove it from the hub (`vk-hub nodes \
             remove <id>`), delete {} as root or {owner}, and `vk node join` again as {name}",
            dir.display(),
            dir.display(),
            name = account.name,
        )
    })
}

/// Check that `account` can reach `dir`, run `exe` and read `config`, without substituting
/// the user's own config for the one this command read.
fn reachable(account: &Account, dir: &Path, exe: &Path, config: Option<&Path>) -> Result<()> {
    if !may(account, dir, 0o7)? {
        bail!("{} cannot reach {}", account.name, dir.display());
    }
    if !may(account, exe, 0o1)? {
        bail!("{} cannot execute {}", account.name, exe.display());
    }
    match config {
        Some(config) => {
            if !may(account, config, 0o4)? {
                bail!(
                    "{} cannot read {}, the config the node would run with: make it readable \
                     to that user, or name another with --config",
                    account.name,
                    config.display()
                );
            }
        }
        None => {
            // The service reads the user's own config when nothing names one, and that may
            // name another state dir than the one checked here.
            let own = account.home.join(".config/virtkit/config.toml");
            if own.exists() {
                bail!(
                    "{} has a config of its own, {}, which the node would read: name the \
                     config to run it with, with --config",
                    account.name,
                    own.display()
                );
            }
        }
    }
    if let Some(parent) = exe.parent()
        && !may(account, parent, 0o3)?
    {
        println!(
            "vk node: warning: {} cannot write {}, so the node refuses updates; install vk \
             where it can",
            account.name,
            parent.display()
        );
    }
    Ok(())
}

/// Whether `account` has the `want` bits (`0o4` read, `0o2` write, `0o1` execute or search)
/// on `path`, and search on every directory above it, as their mode bits say. `path` is
/// resolved. ACLs are not read.
fn may(account: &Account, path: &Path, want: u32) -> Result<bool> {
    if account.uid == 0 {
        return Ok(true);
    }
    let meta = |p: &Path| std::fs::metadata(p).with_context(|| format!("statting {}", p.display()));
    for dir in path.ancestors().skip(1) {
        let m = meta(dir)?;
        if !permits(account, m.uid(), m.gid(), m.mode(), 0o1) {
            return Ok(false);
        }
    }
    let m = meta(path)?;
    Ok(permits(account, m.uid(), m.gid(), m.mode(), want))
}

/// Whether mode bits `mode` of a file owned by `uid`:`gid` grant `account` `want`.
fn permits(account: &Account, uid: u32, gid: u32, mode: u32, want: u32) -> bool {
    let class = if uid == account.uid {
        mode >> 6
    } else if account.groups.contains(&gid) {
        mode >> 3
    } else {
        mode
    };
    class & want & 0o7 == want
}

/// A user the node may run as: its passwd entry and every group it is in. Read from
/// `/etc/passwd` and `/etc/group` alone: a static musl `vk` consults no NSS module, so an
/// LDAP or SSSD user is not found.
///
/// `hostpolicy::self_passwd` reads this process's own name and home as UTF-8 environment
/// values; this also looks users up by name and lists their groups.
#[derive(Debug)]
struct Account {
    name: String,
    uid: u32,
    home: PathBuf,
    groups: Vec<libc::gid_t>,
}

impl Account {
    /// The user called `name`, which must be a plain user name a unit file can hold.
    fn named(name: &str) -> Result<Account> {
        let plain = name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c));
        if name.is_empty() || name.starts_with('-') || !plain {
            bail!("{name:?} is not a user name");
        }
        let c_name = CString::new(name).context("a user name")?;
        passwd(|pwd, buf, result| {
            // SAFETY: every pointer is live and exclusively borrowed for the call, and the
            // length is `buf`'s own.
            unsafe { libc::getpwnam_r(c_name.as_ptr(), pwd, buf.as_mut_ptr(), buf.len(), result) }
        })?
        .with_context(|| {
            format!(
                "there is no user {name} in /etc/passwd, the only user database vk reads; to \
                 run the node as a user only LDAP or SSSD knows, run `vk node service install` \
                 as {name}, for a user unit"
            )
        })
    }

    /// The user with id `uid`.
    fn of(uid: u32) -> Result<Account> {
        passwd(|pwd, buf, result| {
            // SAFETY: as in `named`.
            unsafe { libc::getpwuid_r(uid, pwd, buf.as_mut_ptr(), buf.len(), result) }
        })?
        .with_context(|| format!("there is no user with uid {uid}"))
    }
}

/// The passwd entry `lookup` finds, with the user's groups, or `None` when there is none.
fn passwd(
    lookup: impl Fn(&mut libc::passwd, &mut [libc::c_char], &mut *mut libc::passwd) -> libc::c_int,
) -> Result<Option<Account>> {
    // SAFETY: `passwd` is a plain C struct of pointers and integers, for which all-zero is a
    // valid (empty) value; the lookup fills it in before anything reads it.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = lookup(&mut pwd, &mut buf, &mut result);
    if rc != 0 {
        return Err(std::io::Error::from_raw_os_error(rc)).context("reading the passwd database");
    }
    if result.is_null() || pwd.pw_name.is_null() {
        return Ok(None);
    }
    // SAFETY: the fields of a filled-in entry are NUL-terminated strings in `buf`, alive here.
    let name = unsafe { CStr::from_ptr(pwd.pw_name) };
    let home = if pwd.pw_dir.is_null() {
        PathBuf::new()
    } else {
        // SAFETY: as above.
        let dir = unsafe { CStr::from_ptr(pwd.pw_dir) };
        PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes()))
    };
    let groups = groups(name, pwd.pw_gid)?;
    Ok(Some(Account {
        name: name
            .to_str()
            .context("a user name that is not UTF-8")?
            .to_string(),
        uid: pwd.pw_uid,
        home,
        groups,
    }))
}

/// Every group `name` is in, `gid` its primary one included.
fn groups(name: &CStr, gid: libc::gid_t) -> Result<Vec<libc::gid_t>> {
    let mut len: libc::c_int = 64;
    for _ in 0..4 {
        let mut groups = vec![0 as libc::gid_t; usize::try_from(len).unwrap_or(64)];
        let mut n = len;
        // SAFETY: `groups` holds `n` entries, which the call writes at most of, and `name` is
        // NUL-terminated.
        let rc = unsafe { libc::getgrouplist(name.as_ptr(), gid, groups.as_mut_ptr(), &mut n) };
        if rc >= 0 {
            groups.truncate(usize::try_from(n).unwrap_or(0));
            return Ok(groups);
        }
        // Too few entries: `n` is how many there are.
        len = n.max(len.saturating_mul(2));
    }
    bail!("cannot list the groups of {}", name.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_user_unit_runs_the_node_under_its_config() {
        let text = render(&Unit {
            scope: Scope::User,
            user: None,
            exe: Path::new("/home/ci/.local/bin/vk"),
            config: Some(Path::new("/home/ci/.config/virtkit/config.toml")),
            stop_timeout: Duration::from_secs(3600),
        })
        .unwrap();
        assert_eq!(
            text,
            "# Written by `vk node service install`, which rewrites it.\n\
             [Unit]\n\
             Description=virtkit fleet node\n\
             StartLimitIntervalSec=600\n\
             StartLimitBurst=10\n\
             \n\
             [Service]\n\
             ExecStart=/home/ci/.local/bin/vk --config /home/ci/.config/virtkit/config.toml \
             node run\n\
             KillMode=mixed\n\
             TimeoutStopSec=3600s\n\
             OOMPolicy=continue\n\
             Restart=on-failure\n\
             RestartSec=10s\n\
             \n\
             [Install]\n\
             WantedBy=default.target\n"
        );
    }

    #[test]
    fn a_system_unit_pulls_in_the_network_and_starts_at_boot() {
        let text = render(&Unit {
            scope: Scope::System,
            user: Some("root"),
            exe: Path::new("/usr/local/bin/vk"),
            config: None,
            stop_timeout: Duration::from_secs(90),
        })
        .unwrap();
        assert_eq!(
            text,
            "# Written by `vk node service install`, which rewrites it.\n\
             [Unit]\n\
             Description=virtkit fleet node\n\
             Wants=network-online.target\n\
             After=network-online.target\n\
             StartLimitIntervalSec=600\n\
             StartLimitBurst=10\n\
             \n\
             [Service]\n\
             User=root\n\
             ExecStart=/usr/local/bin/vk node run\n\
             KillMode=mixed\n\
             TimeoutStopSec=90s\n\
             OOMPolicy=continue\n\
             Restart=on-failure\n\
             RestartSec=10s\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n"
        );
    }

    #[test]
    fn a_system_unit_runs_the_node_as_the_user_named() {
        let text = render(&Unit {
            scope: Scope::System,
            user: Some("gitlab-runner"),
            exe: Path::new("/usr/local/bin/vk"),
            config: Some(Path::new("/etc/virtkit/config.toml")),
            stop_timeout: Duration::from_secs(3600),
        })
        .unwrap();
        assert_eq!(
            text,
            "# Written by `vk node service install`, which rewrites it.\n\
             [Unit]\n\
             Description=virtkit fleet node\n\
             Wants=network-online.target\n\
             After=network-online.target\n\
             StartLimitIntervalSec=600\n\
             StartLimitBurst=10\n\
             \n\
             [Service]\n\
             User=gitlab-runner\n\
             ExecStart=/usr/local/bin/vk --config /etc/virtkit/config.toml node run\n\
             KillMode=mixed\n\
             TimeoutStopSec=3600s\n\
             OOMPolicy=continue\n\
             Restart=on-failure\n\
             RestartSec=10s\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n"
        );
    }

    #[test]
    fn mode_bits_are_read_for_the_user_its_groups_or_anyone() {
        let ci = Account {
            name: "ci".to_string(),
            uid: 1000,
            home: PathBuf::from("/home/ci"),
            groups: vec![1000, 27],
        };
        // Owner, group, other: each class read alone.
        assert!(permits(&ci, 1000, 0, 0o400, 0o4));
        assert!(!permits(&ci, 1000, 0, 0o044, 0o4));
        assert!(permits(&ci, 0, 27, 0o640, 0o4));
        assert!(!permits(&ci, 0, 5, 0o640, 0o4));
        assert!(permits(&ci, 0, 5, 0o644, 0o4));
        assert!(!permits(&ci, 0, 0, 0o750, 0o1));
        assert!(permits(&ci, 0, 0, 0o711, 0o1));
        assert!(!permits(&ci, 1000, 0, 0o500, 0o3));
        assert!(permits(&ci, 1000, 0, 0o700, 0o3));
    }

    #[test]
    fn only_a_plain_user_name_is_looked_up() {
        for bad in ["", "-x", "a b", "a%i", "a\nb", "a/b"] {
            assert!(Account::named(bad).is_err(), "{bad:?}");
        }
        assert_eq!(Account::named("root").unwrap().uid, 0);
        assert_eq!(Account::of(0).unwrap().name, "root");
    }

    #[test]
    fn no_stop_timeout_is_infinity() {
        let text = render(&Unit {
            scope: Scope::System,
            user: Some("root"),
            exe: Path::new("/usr/local/bin/vk"),
            config: None,
            stop_timeout: Duration::ZERO,
        })
        .unwrap();
        assert!(text.contains("\nTimeoutStopSec=infinity\n"), "{text}");
    }

    #[test]
    fn exec_start_words_are_quoted_and_escaped() {
        let text = render(&Unit {
            scope: Scope::User,
            user: None,
            exe: Path::new("/opt/vk tools/vk"),
            config: Some(Path::new("/srv/ci $HOME/100%/a\"b\\c.toml")),
            stop_timeout: Duration::from_secs(3600),
        })
        .unwrap();
        assert!(
            text.contains(
                "\nExecStart=\"/opt/vk tools/vk\" --config \
                 \"/srv/ci $$HOME/100%%/a\\\"b\\\\c.toml\" node run\n"
            ),
            "{text}"
        );
        assert_eq!(exec_word(Path::new("/a/b-c_d.e")).unwrap(), "/a/b-c_d.e");
        assert_eq!(exec_word(Path::new("/a/50%")).unwrap(), "\"/a/50%%\"");
        assert!(exec_word(Path::new("/a\nb")).is_err());
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-service-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn chmod(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn account(uid: u32, home: &Path) -> Account {
        Account {
            name: "ci".to_string(),
            uid,
            home: home.to_path_buf(),
            groups: Vec::new(),
        }
    }

    #[test]
    fn a_user_unit_goes_under_xdg_config_home_else_the_passwd_home() {
        let home = || Ok(PathBuf::from("/home/ci"));
        assert_eq!(
            user_unit_dir(Some("/srv/conf".into()), || unreachable!()).unwrap(),
            Path::new("/srv/conf/systemd/user")
        );
        assert_eq!(
            user_unit_dir(Some("conf".into()), home).unwrap(),
            Path::new("/home/ci/.config/systemd/user")
        );
        assert_eq!(
            user_unit_dir(None, home).unwrap(),
            Path::new("/home/ci/.config/systemd/user")
        );
        assert!(user_unit_dir(None, || Ok(PathBuf::from("ci"))).is_err());
    }

    #[test]
    fn an_xdg_dir_is_used_only_when_this_user_owns_it() {
        let dir = scratch("own-dir");
        let me = euid();
        assert_eq!(own_dir(Some(dir.clone().into()), me), Some(dir.clone()));
        assert_eq!(own_dir(Some(dir.clone().into()), me.wrapping_add(1)), None);
        assert_eq!(own_dir(Some(dir.join("none").into()), me), None);
        assert_eq!(own_dir(None, me), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_a_unit_install_wrote_is_rewritten_or_removed() {
        let dir = scratch("ours");
        let path = dir.join(UNIT);
        ours(&path).unwrap();
        let text = render(&Unit {
            scope: Scope::User,
            user: None,
            exe: Path::new("/usr/local/bin/vk"),
            config: None,
            stop_timeout: Duration::from_secs(60),
        })
        .unwrap();
        std::fs::write(&path, text).unwrap();
        ours(&path).unwrap();
        std::fs::write(&path, "[Service]\nExecStart=/usr/local/bin/vk node run\n").unwrap();
        let err = ours(&path).unwrap_err().to_string();
        assert!(err.contains("was not written by"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_system_unit_is_found_running_as_its_user() {
        let dir = scratch("runs-as");
        let path = dir.join(UNIT);
        assert!(!runs_as(&path, "ci").unwrap());
        std::fs::write(
            &path,
            "[Service]\nUser=ci\nExecStart=/usr/local/bin/vk node run\n",
        )
        .unwrap();
        assert!(runs_as(&path, "ci").unwrap());
        assert!(!runs_as(&path, "c").unwrap());
        assert!(!runs_as(&path, "gitlab-runner").unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_node_dir_another_node_holds_is_refused() {
        let dir = scratch("idle");
        idle(&dir, 1).unwrap();
        assert!(!dir.join(super::super::LOCK_FILE).exists());
        let held = super::super::lock_tries(&dir, 1).unwrap();
        let err = idle(&dir, 1).unwrap_err().to_string();
        assert!(err.contains("another `vk node` holds"), "{err}");
        drop(held);
        // A child another test forks keeps the flock until it execs; let that window pass.
        idle(&dir, 10).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn gitlab_runner_is_looked_up_as_an_executable_file() {
        let dir = scratch("on-path");
        let (a, b) = (dir.join("a"), dir.join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(b.join("gitlab-runner")).unwrap();
        std::fs::write(a.join("gitlab-runner"), "").unwrap();
        chmod(&a.join("gitlab-runner"), 0o644);
        let path = format!("{}:{}", a.display(), b.display());
        assert_eq!(on_path("gitlab-runner", &path), None);
        chmod(&a.join("gitlab-runner"), 0o755);
        assert_eq!(
            on_path("gitlab-runner", &path),
            Some(a.join("gitlab-runner"))
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_node_dir_must_be_the_users_and_private() {
        let dir = scratch("owned-by");
        let node = dir.join("node");
        std::fs::create_dir(&node).unwrap();
        chmod(&node, 0o700);
        owned_by(&node, &account(euid(), &dir)).unwrap();
        chmod(&node, 0o755);
        assert!(owned_by(&node, &account(euid(), &dir)).is_err());
        chmod(&node, 0o700);
        let err = owned_by(&node, &account(euid().wrapping_add(1), &dir))
            .unwrap_err()
            .to_string();
        assert!(err.contains("belongs to"), "{err}");
        let err = owned_by(&dir.join("none"), &account(euid(), &dir)).unwrap_err();
        assert!(super::super::is_not_found(&err), "{err:#}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_directory_above_that_denies_search_denies_everything_under_it() {
        let dir = scratch("may");
        let (closed, node) = (dir.join("closed"), dir.join("closed/node"));
        std::fs::create_dir_all(&node).unwrap();
        chmod(&node, 0o777);
        chmod(&closed, 0o700);
        let other = account(euid().wrapping_add(1), &dir);
        assert!(!may(&other, &node, 0o7).unwrap());
        let err = reachable(&other, &node, Path::new("/bin/sh"), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot reach"), "{err}");
        chmod(&closed, 0o711);
        assert!(may(&other, &node, 0o7).unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_config_of_the_users_own_is_refused_when_none_is_named() {
        let dir = scratch("reachable");
        let node = dir.join("node");
        std::fs::create_dir(&node).unwrap();
        chmod(&node, 0o700);
        let exe = dir.join("vk");
        std::fs::write(&exe, "").unwrap();
        chmod(&exe, 0o755);
        let me = account(euid(), &dir);
        reachable(&me, &node, &exe, None).unwrap();
        std::fs::create_dir_all(dir.join(".config/virtkit")).unwrap();
        std::fs::write(dir.join(".config/virtkit/config.toml"), "").unwrap();
        let err = reachable(&me, &node, &exe, None).unwrap_err().to_string();
        assert!(err.contains("has a config of its own"), "{err}");
        let named = dir.join("named.toml");
        std::fs::write(&named, "").unwrap();
        reachable(&me, &node, &exe, Some(&named)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
