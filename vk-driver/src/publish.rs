//! Host side of `vk publish`: accept local connections and, for each one, ask a
//! running guest's agent (over its exec control channel) to dial an address on its
//! own network and splice raw bytes — reusing `vk_core::exec::client` the same way
//! `vk exec` does, so the published port rides the agent's existing control channel.

use anyhow::{Context, Result, bail};
use log::{error, info, warn};
use vk_core::addr::SocketAddr;
use vk_core::exec::client::client_run_connect;
use vk_core::net::{RawListener, connect, raw_listen};

/// Retry interval and limit for accept errors, which may otherwise spin forever.
const ACCEPT_RETRY: std::time::Duration = std::time::Duration::from_millis(100);
const ACCEPT_FAILURES: u32 = 20;

/// Accept on `listen` and, per connection, dial `agent_addr`'s control channel and
/// ask it to reach `to`. Each connection gets its own session on that (already
/// multiplexing) channel, working against whatever the VM is already running.
/// Returns only on a bind error; a per-connection failure is logged and does not
/// stop the listener.
pub async fn run(agent_addr: &SocketAddr, listen: &SocketAddr, to: &str) -> Result<()> {
    let listener = raw_listen(listen)
        .await
        .with_context(|| format!("publish: binding {listen}"))?;
    serve_on(listener, agent_addr, listen, to).await
}

/// Serve a listener bound by this process or inherited through [`ensure`].
async fn serve_on(
    listener: RawListener,
    agent_addr: &SocketAddr,
    listen: &SocketAddr,
    to: &str,
) -> Result<()> {
    info!("publish: {listen} -> {to} (agent {agent_addr})");
    // Retry transient errors such as a disappearing peer or momentary EMFILE, but stop
    // persistent errors before the process spins and floods its unattended log.
    let mut failures = 0;
    loop {
        let local = match listener.accept().await {
            Ok(conn) => {
                failures = 0;
                conn
            }
            Err(e) => {
                failures += 1;
                warn!("publish: accept on {listen}: {e}");
                if failures >= ACCEPT_FAILURES {
                    bail!("publish: {failures} consecutive accept failures on {listen}: {e}");
                }
                tokio::time::sleep(ACCEPT_RETRY).await;
                continue;
            }
        };
        let agent_addr = agent_addr.clone();
        let target = to.to_string();
        tokio::spawn(async move {
            match connect(&agent_addr).await {
                Ok((stream, sink)) => {
                    if let Err(e) = client_run_connect(stream, sink, target, local).await {
                        error!("publish: session to {agent_addr}: {e}");
                    }
                }
                Err(e) => error!("publish: connecting to agent {agent_addr}: {e}"),
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Managed publishers
//
// Managed publishers keep a port available without making callers background the
// foreground `vk publish`, track its pid, or detect pid reuse.
//
// Each managed publisher owns two files under `<state-dir>/publish/`:
//
//   <name>.lock   flock held for the publisher's lifetime. The parent acquires it before
//                 spawning and transfers the descriptor, claiming the name without a
//                 gap. The lock, rather than the recorded pid, proves liveness.
//   <name>.json   what it publishes, and the pid to signal.
//
// `.op.lock` serializes the commands themselves, so two `ensure`s racing on one name
// cannot both decide to spawn.
// ---------------------------------------------------------------------------

use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// VM probe interval and tolerated consecutive misses. Multiple misses prevent a busy
/// agent from taking down a working publisher.
const VM_PROBE_EVERY: Duration = Duration::from_secs(5);
const VM_PROBE_MISSES: u32 = 3;

/// One managed publisher, as recorded in `<state-dir>/publish/<name>.json`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Entry {
    pub name: String,
    /// Normalized so equivalent address spellings compare equal.
    pub listen: String,
    pub to: String,
    /// The compose sibling whose agent dials `to` (`--via`); absent when the primary
    /// dials. Old `service` records still load; older `vk` versions ignore `via` and treat
    /// the publisher as dialing through the primary.
    #[serde(
        default,
        rename = "via",
        alias = "service",
        skip_serializing_if = "Option::is_none"
    )]
    pub service: Option<String>,
    pub pid: u32,
    #[serde(default)]
    pub created_secs: u64,
}

impl Entry {
    /// Fields that determine whether two `ensure` requests are equivalent.
    fn spec(&self) -> (&str, &str, Option<&str>) {
        (&self.listen, &self.to, self.service.as_deref())
    }
}

/// A distinct error that lets callers retry with another listen address.
#[derive(Debug)]
pub struct AddressInUse(pub String);

impl std::fmt::Display for AddressInUse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} is already in use", self.0)
    }
}

impl std::error::Error for AddressInUse {}

fn dir_of(state_dir: &Path) -> PathBuf {
    state_dir.join("publish")
}

/// Create the registry directory privately because its parent may be readable by guests
/// or other users.
fn make_dir(state_dir: &Path) -> Result<PathBuf> {
    let dir = dir_of(state_dir);
    // The run creates its state directory. Report a missing path instead of inventing a
    // directory tree.
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .or_else(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => Ok(()),
            _ => Err(e),
        })
        .with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

/// Validate a publisher name for use as a registry filename and list column.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        bail!("publisher name {name:?} must be 1..=64 characters");
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
    {
        bail!(
            "publisher name {name:?}: {bad:?} is not allowed (want letters, digits, '.', '_', '-')"
        );
    }
    // Leading dots collide with `.op.lock` and staged `.<name>.<pid>.json.tmp` records.
    if name.starts_with('.') {
        bail!("publisher name {name:?} may not begin with '.'");
    }
    Ok(())
}

/// Take an exclusive flock on `path`, creating it. `Ok(None)` means someone else holds it.
fn try_flock(path: &Path) -> Result<Option<std::fs::File>> {
    let f = lock_file(path)?;
    // SAFETY: the fd is owned by `f` and outlives the call; LOCK_NB never blocks.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(f));
    }
    let err = std::io::Error::last_os_error();
    // Only contention proves another holder. Treating EINTR or ENOLCK as contention could
    // make a live publisher unstoppable or an absent one appear alive.
    if err.kind() == std::io::ErrorKind::WouldBlock {
        Ok(None)
    } else {
        Err(err).with_context(|| format!("locking {}", path.display()))
    }
}

/// Open a lock file, creating the registry dir and the file private and without
/// following a symlink planted at either name.
fn lock_file(path: &Path) -> Result<std::fs::File> {
    if let Some(parent) = path.parent() {
        make_dir(parent.parent().unwrap_or(parent))?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))
}

/// Serialize managed commands. A racing `ensure` waits and observes its predecessor.
fn op_lock(state_dir: &Path) -> Result<std::fs::File> {
    let path = dir_of(state_dir).join(".op.lock");
    let f = lock_file(&path)?;
    // SAFETY: as `try_flock`; blocking, and only ever held for the length of a command.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("locking {}", path.display()));
    }
    Ok(f)
}

/// Open the operation lock without creating state. `Ok(None)` means this state directory
/// has never published; read-only commands must not leave directories behind.
fn op_lock_existing(state_dir: &Path) -> Result<Option<std::fs::File>> {
    if !dir_of(state_dir).is_dir() {
        return Ok(None);
    }
    op_lock(state_dir).map(Some)
}

/// Claim a publisher's lifetime lock. `Some` transfers or releases the claim; `None`
/// means a live publisher holds it.
fn claim(state_dir: &Path, name: &str) -> Result<Option<std::fs::File>> {
    try_flock(&dir_of(state_dir).join(format!("{name}.lock")))
}

fn entry_path(state_dir: &Path, name: &str) -> PathBuf {
    dir_of(state_dir).join(format!("{name}.json"))
}

fn read_entry(state_dir: &Path, name: &str) -> Option<Entry> {
    let bytes = std::fs::read(entry_path(state_dir, name)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_entry(state_dir: &Path, entry: &Entry) -> Result<()> {
    let dir = make_dir(state_dir)?;
    let path = entry_path(state_dir, &entry.name);
    // A hidden, pid-specific `create_new` path rejects planted symlinks and prevents
    // writers from sharing a staging file, matching `vms::record_in`.
    let tmp = dir.join(format!(".{}.{}.json.tmp", entry.name, std::process::id()));
    let json = serde_json::to_vec_pretty(entry).context("serializing the publisher entry")?;
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("writing {}", tmp.display()))?;
    f.write_all(&json).and_then(|()| f.sync_all())?;
    std::fs::rename(&tmp, &path).with_context(|| format!("publishing {}", path.display()))?;
    // Persist the rename: an invisible record could let the next command start a duplicate.
    let _ = std::fs::File::open(&dir).and_then(|d| d.sync_all());
    Ok(())
}

/// Drop a publisher record but retain its lock file. Deleting a held lock by name would
/// let `ensure` create and claim a replacement before the old publisher releases its
/// address.
fn forget_record(state_dir: &Path, name: &str) {
    let _ = std::fs::remove_file(entry_path(state_dir, name));
}

/// Drop record and lock file both — only for a name whose publisher is known to be gone.
fn forget_entry(state_dir: &Path, name: &str) {
    forget_record(state_dir, name);
    let dir = dir_of(state_dir);
    let _ = std::fs::remove_file(dir.join(format!("{name}.lock")));
    let _ = std::fs::remove_file(dir.join(format!("{name}.log")));
}

/// Whether a record's publisher was shown to be running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// Its lifetime lock is held, so the process behind the recorded pid is that publisher.
    Held,
    /// The lock could not be tested, for example because of a symlink or NFS `ENOLCK`.
    /// Retain the record, but trust neither its liveness nor its pid.
    Unknown,
}

impl Liveness {
    /// Whether the recorded pid is untrusted. Only `Held` grants trust, so future variants
    /// withhold it by default.
    pub fn unconfirmed(self) -> bool {
        self != Liveness::Held
    }
}

/// Return publishers not known to be gone and remove stale records.
///
/// The caller must hold [`op_lock`] so liveness claims cannot race an `ensure` handover.
fn live_entries(state_dir: &Path) -> Vec<(Entry, Liveness)> {
    let Ok(rd) = std::fs::read_dir(dir_of(state_dir)) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let path = e.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let Some(entry) = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Entry>(&b).ok())
        else {
            continue;
        };
        // Validate both the embedded name and filename before deriving paths or trusting
        // the adjacent pid; a planted `../../x` must not escape the registry.
        if validate_name(&entry.name).is_err()
            || path.file_stem().and_then(|s| s.to_str()) != Some(entry.name.as_str())
        {
            warn!(
                "publish: ignoring {}: its name is not its own",
                path.display()
            );
            continue;
        }
        match claim(state_dir, &entry.name) {
            // A claim proves the record stale. Remove its unused lock and log as well.
            Ok(Some(_)) => forget_entry(state_dir, &entry.name),
            Ok(None) => out.push((entry, Liveness::Held)),
            Err(e) => {
                warn!("publish: {}: {e:#}", entry.name);
                out.push((entry, Liveness::Unknown));
            }
        }
    }
    out.sort_by(|a, b| a.0.name.cmp(&b.0.name));
    out
}

/// What [`ensure`] did.
#[derive(Debug)]
pub enum Ensured {
    Started(Entry),
    AlreadyRunning(Entry),
}

/// Start a publisher for `name` unless an equivalent one is already running.
///
/// Bind before spawning and transfer the open descriptor without releasing the address.
/// The address is ready when this returns, and [`AddressInUse`] remains distinguishable.
/// An equivalent live publisher succeeds; a conflicting publisher with the same name
/// fails rather than silently serving the wrong request.
pub async fn ensure(
    state_dir: &Path,
    name: &str,
    agent_addr: &SocketAddr,
    listen: &SocketAddr,
    to: &str,
    service: Option<&str>,
) -> Result<Ensured> {
    validate_name(name)?;
    // Reject listener types that cannot cross fork/exec before starting an unwatched child.
    if !matches!(listen, SocketAddr::Tcp(_) | SocketAddr::Unix(_)) {
        bail!("vk publish ensure serves tcp:// and unix listen addresses only (got {listen})");
    }
    // Port 0 cannot work because the record, list, and child argv cannot report the port
    // selected by the kernel.
    if matches!(listen, SocketAddr::Tcp(a) if a.port() == 0) {
        bail!(
            "vk publish ensure needs a fixed port, not {listen}: a managed publisher has \
               to be able to say what it bound"
        );
    }
    let _op = op_lock(state_dir)?;

    let wanted = Entry {
        name: name.to_string(),
        listen: listen.to_string(),
        to: to.to_string(),
        service: service.map(str::to_string),
        pid: 0,
        created_secs: 0,
    };
    let mut claimed = claim(state_dir, name)?;
    if claimed.is_none() && read_entry(state_dir, name).is_none() {
        // A missing record with a held lock is normal during shutdown. Wait briefly for
        // the lock instead of treating the registry as corrupt.
        let _ = wait_gone_async(state_dir, name, Duration::from_secs(2)).await;
        claimed = claim(state_dir, name)?;
    }
    let Some(lock) = claimed else {
        // A held lock proves liveness; the record describes the publisher.
        let running = read_entry(state_dir, name).with_context(|| {
            format!(
                "publisher {name:?} is running but its record in {} is unreadable",
                dir_of(state_dir).display()
            )
        })?;
        if running.spec() != wanted.spec() {
            bail!(
                "publisher {name:?} already runs {} -> {}{}, not {} -> {}{} — stop it first \
                 (`vk publish stop {} --name {name}`)",
                running.listen,
                running.to,
                running
                    .service
                    .as_deref()
                    .map(|s| format!(" (via {s})"))
                    .unwrap_or_default(),
                wanted.listen,
                wanted.to,
                service.map(|s| format!(" (via {s})")).unwrap_or_default(),
                state_dir.display(),
            );
        }
        return Ok(Ensured::AlreadyRunning(running));
    };

    // Owning the lock proves any old record stale. Remove it before `live_entries`, which
    // would otherwise mistake our own refused claim for a live publisher.
    forget_record(state_dir, name);

    // Fail in the foreground if there is no VM to receive relayed connections.
    if let Err(e) = vk_core::status::get_status(agent_addr).await {
        bail!(
            "no VM is answering for {} — publish needs a running VM ({e})",
            state_dir.display()
        );
    }

    // `raw_listen` unlinks Unix paths before binding, so check records and the live socket
    // first to avoid silently replacing another listener.
    let want = listen.to_string();
    if let Some((other, _)) = live_entries(state_dir)
        .into_iter()
        .find(|(e, _)| e.listen == want && e.name != name)
    {
        return Err(anyhow::Error::new(AddressInUse(format!(
            "{want} (published as {:?})",
            other.name
        ))));
    }
    if let SocketAddr::Unix(path) = listen
        && std::os::unix::net::UnixStream::connect(path).is_ok()
    {
        return Err(anyhow::Error::new(AddressInUse(want)));
    }

    // Bind before spawning so failure is synchronous and the address remains continuously
    // held during handover.
    let listener = raw_listen(listen).await.map_err(|e| {
        if is_addr_in_use(&e) {
            anyhow::Error::new(AddressInUse(listen.to_string()))
        } else {
            e.context(format!("publish: binding {listen}"))
        }
    })?;
    let pid = spawn_publisher(state_dir, name, listen, to, service, &listener, &lock)?;
    // Write the pid after spawning but before transferring the lock, so every observable
    // claim has a record.
    let entry = Entry {
        pid,
        created_secs: crate::vms::unix_now(),
        ..wanted
    };
    if let Err(e) = write_entry(state_dir, &entry) {
        // Without a record the running child is invisible to `list` and `stop`; terminate
        // it instead of leaving an orphan that holds the address.
        // SAFETY: kill only delivers a signal; the pid is this process's own child.
        if let Ok(pid) = i32::try_from(entry.pid) {
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
        // Drop our copy first so claims remain blocked until the child releases its copy.
        drop(lock);
        if !wait_gone_async(state_dir, name, Duration::from_secs(2)).await {
            return Err(e.context(format!(
                "and its publisher (pid {}) is still running — stop it by hand",
                entry.pid
            )));
        }
        return Err(e);
    }
    drop(lock); // the publisher's copy keeps the claim
    // A newly free lock means the child died before serving; do not report a dead address.
    if wait_gone_async(state_dir, name, Duration::from_millis(200)).await {
        // Remove state but retain the log as the only account of the early failure.
        forget_record(state_dir, name);
        let _ = std::fs::remove_file(dir_of(state_dir).join(format!("{name}.lock")));
        bail!(
            "publisher {name:?} exited immediately — see {}",
            dir_of(state_dir).join(format!("{name}.log")).display()
        );
    }
    Ok(Ensured::Started(entry))
}

fn is_addr_in_use(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::AddrInUse)
    })
}

/// Arguments `ensure` passes to `vk publish serve`, excluding the program name. Kept
/// separate so a CLI parsing test catches flags renamed on only one side.
pub(crate) fn serve_argv(
    state_dir: &Path,
    name: &str,
    listen: &SocketAddr,
    to: &str,
    service: Option<&str>,
    listen_fd: RawFd,
    lock_fd: RawFd,
) -> Vec<std::ffi::OsString> {
    let mut argv: Vec<std::ffi::OsString> =
        vec!["publish".into(), "serve".into(), state_dir.into()];
    for arg in [
        "--name",
        name,
        "--listen",
        &listen.to_string(),
        "--to",
        to,
        "--listen-fd",
        &listen_fd.to_string(),
        "--lock-fd",
        &lock_fd.to_string(),
    ] {
        argv.push(arg.into());
    }
    if let Some(s) = service {
        argv.push("--via".into());
        argv.push(s.into());
    }
    argv
}

/// Spawn a detached `vk publish serve`, passing the listener and lock at their existing
/// descriptor numbers by clearing close-on-exec in the child.
fn spawn_publisher(
    state_dir: &Path,
    name: &str,
    listen: &SocketAddr,
    to: &str,
    service: Option<&str>,
    listener: &RawListener,
    lock: &std::fs::File,
) -> Result<u32> {
    let exe = std::env::current_exe().context("locating this vk binary")?;
    let log_path = dir_of(state_dir).join(format!("{name}.log"));
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&log_path)
        .with_context(|| format!("opening {}", log_path.display()))?;
    let listen_fd = listener.as_raw_fd();
    let lock_fd = lock.as_raw_fd();
    let mut cmd = std::process::Command::new(&exe);
    cmd.args(serve_argv(
        state_dir, name, listen, to, service, listen_fd, lock_fd,
    ))
    .stdin(std::process::Stdio::null())
    .stderr(log.try_clone().context("duplicating the publisher log")?)
    .stdout(log);
    // SAFETY: `pre_exec` runs after fork; `setsid` and `fcntl(F_SETFD)` are async-signal-safe.
    // `setsid` detaches the child, and clearing FD_CLOEXEC transfers both descriptors.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            for fd in [listen_fd, lock_fd] {
                if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .with_context(|| format!("spawning {}", exe.display()))?;
    Ok(child.id())
}

/// Adopt an inherited listener and serve until the VM disappears, SIGTERM arrives, or the
/// listener fails. Remove the record before exiting.
pub async fn serve(
    state_dir: &Path,
    name: &str,
    agent_addr: &SocketAddr,
    listen: &SocketAddr,
    to: &str,
    listen_fd: RawFd,
    lock_fd: RawFd,
) -> Result<()> {
    // Revalidate the name because `serve` also uses it to remove the record.
    validate_name(name)?;
    // The CLI supplies descriptors that this function owns. Verify their actual types so
    // a manual invocation cannot, for example, claim stderr as its lifetime lock.
    if !is_regular_file(lock_fd) {
        bail!("publish serve: fd {lock_fd} is not the lifetime lock — run `vk publish ensure`");
    }
    if !is_listening_socket(listen_fd, listen) {
        bail!(
            "publish serve: fd {listen_fd} is not a listening socket for {listen} — \
             run `vk publish ensure`"
        );
    }
    // Retain the lock for the process lifetime; `ensure`, `list`, and `stop` use it as the
    // liveness proof. SAFETY: the parent transferred sole ownership.
    let _lock = unsafe { std::fs::File::from_raw_fd(lock_fd) };
    // SAFETY: checked above to be a listening socket for `listen`, and passed to us by
    // our parent, so nothing in this process owns it yet.
    let listener = RawListener::adopt(listen, unsafe {
        std::os::fd::OwnedFd::from_raw_fd(listen_fd)
    })?;
    // Record the bound path's identity so cleanup cannot unlink a successor. `fstat` on
    // the descriptor reports a sockfs inode, not the filesystem node created by `bind`.
    let bound_id = match listen {
        SocketAddr::Unix(path) => path_identity(path),
        _ => None,
    };

    let result = tokio::select! {
        r = serve_on(listener, agent_addr, listen, to) => r,
        () = vm_gone(agent_addr) => {
            info!("publish {name}: its VM stopped answering — stopping too");
            Ok(())
        }
        () = crate::shutdown::terminate_signal() => {
            info!("publish {name}: stopping on SIGTERM");
            Ok(())
        }
    };
    forget_record(state_dir, name);
    // A Unix socket node outlives its process. Remove it only if `(dev, ino)` still matches.
    if let SocketAddr::Unix(path) = listen
        && bound_id.is_some()
        && path_identity(path) == bound_id
    {
        let _ = std::fs::remove_file(path);
    }
    result
}

/// Resolve when the target VM is gone, preventing an unusable address from remaining bound.
async fn vm_gone(agent_addr: &SocketAddr) {
    let mut misses = 0;
    loop {
        tokio::time::sleep(VM_PROBE_EVERY).await;
        if vk_core::status::get_status(agent_addr).await.is_ok() {
            misses = 0;
            continue;
        }
        misses += 1;
        if misses >= VM_PROBE_MISSES {
            return;
        }
    }
}

/// The publishers running for a state dir, dead records pruned, each with whether it was
/// shown to hold its lock. A state dir that never published has none, and nothing is
/// created for it. Blocks behind a `vk publish ensure|stop` in flight on the same state
/// dir: roughly `stop`'s timeout per publisher it waits on.
pub fn live(state_dir: &Path) -> Result<Vec<(Entry, Liveness)>> {
    Ok(match op_lock_existing(state_dir)? {
        Some(_op) => live_entries(state_dir),
        None => Vec::new(),
    })
}

/// `vk publish list`: what is published for this state dir, dead records pruned.
pub fn list_report(state_dir: &Path, json: bool) -> Result<String> {
    let entries = live(state_dir)?;
    if json {
        // Mirror the text list's "(unconfirmed)" so JSON consumers do not trust an
        // unverified pid. The key matches `vms::PublishedView::unconfirmed`, so both JSON
        // producers spell this marker the same way.
        let records: Vec<serde_json::Value> = entries
            .iter()
            .map(|(e, live)| {
                let mut v = serde_json::to_value(e).context("serializing a publisher entry")?;
                if live.unconfirmed()
                    && let Some(o) = v.as_object_mut()
                {
                    o.insert("unconfirmed".into(), true.into());
                }
                Ok(v)
            })
            .collect::<Result<_>>()?;
        return Ok(serde_json::to_string_pretty(&records).context("serializing the list")? + "\n");
    }
    if entries.is_empty() {
        return Ok(format!("no publishers for {}\n", state_dir.display()));
    }
    let width = entries
        .iter()
        .map(|(e, _)| e.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let listen_width = entries
        .iter()
        .map(|(e, _)| e.listen.len())
        .max()
        .unwrap_or(6)
        .max(6);
    let to_width = entries
        .iter()
        .map(|(e, _)| e.to.len())
        .max()
        .unwrap_or(2)
        .max(2);
    let mut out = format!(
        "{:<width$}  {:<listen_width$}  {:<to_width$}  {:>5}  PID\n",
        "NAME", "LISTEN", "TO", "AGE"
    );
    let now = crate::vms::unix_now();
    for (e, live) in &entries {
        // A publisher whose lock could not be read is listed, and listed as unproven: it
        // still holds an address, but its recorded pid stands for nothing.
        let pid = match live {
            Liveness::Held => e.pid.to_string(),
            Liveness::Unknown => format!("{} (unconfirmed)", e.pid),
        };
        out.push_str(&format!(
            "{:<width$}  {:<listen_width$}  {:<to_width$}  {:>5}  {pid}\n",
            e.name,
            e.listen,
            e.to,
            age(now.saturating_sub(e.created_secs)),
        ));
    }
    Ok(out)
}

/// A publisher's age, in the short form `vk list` uses for a VM's.
fn age(secs: u64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86400 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86400),
    }
}

/// Stop selected publishers and wait for their lifetime locks. Retain records for
/// publishers that do not stop because their addresses may remain bound.
pub fn stop(state_dir: &Path, name: Option<&str>, timeout: Duration) -> Result<(String, bool)> {
    let Some(_op) = op_lock_existing(state_dir)? else {
        return Ok((format!("no publishers for {}\n", state_dir.display()), true));
    };
    let selected: Vec<(Entry, Liveness)> = live_entries(state_dir)
        .into_iter()
        .filter(|(e, _)| name.is_none_or(|n| n == e.name))
        .collect();
    if selected.is_empty() {
        return Ok((
            match name {
                Some(n) => format!("no publisher {n:?} for {}\n", state_dir.display()),
                None => format!("no publishers for {}\n", state_dir.display()),
            },
            true,
        ));
    }
    let mut out = String::new();
    let mut all_down = true;
    for (e, live) in &selected {
        // Signal only when the held lock proves that the recorded pid belongs to this
        // publisher. An unconfirmed number may now belong to another process.
        if live.unconfirmed() {
            out.push_str(&format!(
                "{}: cannot confirm it is running, so it was not signalled — check {}\n",
                e.name,
                dir_of(state_dir).join(format!("{}.lock", e.name)).display()
            ));
            all_down = false;
            continue;
        }
        // Reject pids 0 and 1 and values above i32::MAX before signalling an untrusted pid
        // from disk.
        let Some(pid) = i32::try_from(e.pid).ok().filter(|p| *p > 1) else {
            out.push_str(&format!(
                "{}: record has an unusable pid {}\n",
                e.name, e.pid
            ));
            all_down = false;
            continue;
        };
        // SAFETY: kill only delivers a signal; an already-exited pid fails harmlessly.
        unsafe { libc::kill(pid, libc::SIGTERM) };
        if wait_gone(state_dir, &e.name, timeout) {
            forget_entry(state_dir, &e.name);
            out.push_str(&format!("stopped {} ({} -> {})\n", e.name, e.listen, e.to));
        } else {
            out.push_str(&format!(
                "{} (pid {}) did not stop after {}s\n",
                e.name,
                e.pid,
                timeout.as_secs()
            ));
            all_down = false;
        }
    }
    Ok((out, all_down))
}

/// Stop all publishers during VM teardown without reporting a secondary result.
pub fn stop_all_quietly(state_dir: &Path, timeout: Duration) {
    let _ = stop(state_dir, None, timeout);
}

/// Whether `fd` is a regular file — the shape of the lifetime lock.
fn is_regular_file(fd: RawFd) -> bool {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat writes one `struct stat` through the pointer and reads nothing else.
    if unsafe { libc::fstat(fd, st.as_mut_ptr()) } != 0 {
        return false;
    }
    // SAFETY: fstat returned 0, so the struct is initialised.
    let st = unsafe { st.assume_init() };
    st.st_mode & libc::S_IFMT == libc::S_IFREG
}

/// Verify that `fd` is listening in the family named by `bound` before calling `adopt`.
fn is_listening_socket(fd: RawFd, bound: &SocketAddr) -> bool {
    let opt = |name: libc::c_int| -> Option<libc::c_int> {
        let mut val: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: getsockopt writes at most `len` bytes into `val` and reads nothing else.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                name,
                (&raw mut val).cast::<libc::c_void>(),
                &raw mut len,
            )
        };
        (rc == 0).then_some(val)
    };
    let want = match bound {
        SocketAddr::Tcp(a) if a.is_ipv6() => libc::AF_INET6,
        SocketAddr::Tcp(_) => libc::AF_INET,
        SocketAddr::Unix(_) => libc::AF_UNIX,
        _ => return false,
    };
    if opt(libc::SO_ACCEPTCONN) != Some(1) || opt(libc::SO_DOMAIN) != Some(want) {
        return false;
    }
    // For Unix sockets, verify the path that `serve` will later unlink.
    match bound {
        SocketAddr::Unix(path) => socket_path(fd).is_some_and(|p| p == *path),
        _ => true,
    }
}

/// The path an `AF_UNIX` socket is bound to, as the kernel reports it.
fn socket_path(fd: RawFd) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let mut addr = std::mem::MaybeUninit::<libc::sockaddr_un>::zeroed();
    let mut len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    // SAFETY: getsockname writes at most `len` bytes into `addr` and updates `len`.
    if unsafe { libc::getsockname(fd, addr.as_mut_ptr().cast(), &raw mut len) } != 0 {
        return None;
    }
    // SAFETY: getsockname returned 0, so the struct is initialised up to `len`.
    let addr = unsafe { addr.assume_init() };
    let bytes: Vec<u8> = addr
        .sun_path
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    (!bytes.is_empty()).then(|| PathBuf::from(std::ffi::OsStr::from_bytes(&bytes)))
}

/// Return a path node's `(dev, ino)` without following symlinks.
fn path_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path)
        .ok()
        .map(|m| (m.dev(), m.ino()))
}

/// [`wait_gone`] for an async caller: the same poll, without parking a runtime worker.
async fn wait_gone_async(state_dir: &Path, name: &str, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if matches!(claim(state_dir, name), Ok(Some(_))) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Wait for the lifetime lock, proving the publisher exited rather than merely receiving
/// a signal.
fn wait_gone(state_dir: &Path, name: &str, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if matches!(claim(state_dir, name), Ok(Some(_))) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use vk_core::exec::server::run_server;

    /// A TCP echo server, standing in for a target reachable only from the guest's
    /// own network — the thing `vk publish` relays a local connection to.
    async fn echo_server() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut conn, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        match conn.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) if conn.write_all(&buf[..n]).await.is_err() => break,
                            Ok(_) => {}
                        }
                    }
                });
            }
        });
        addr
    }

    /// End to end through `run`'s own accept loop: a local TCP client -> `publish::run`
    /// -> a fake agent (a real `run_server`) -> an echo target on its "network". Proves
    /// the accept/dial/relay glue this module adds on top of `client_run_connect` (which
    /// `vk-core/tests/exec.rs` already covers directly) is wired correctly end to end.
    #[tokio::test]
    async fn relays_a_published_connection_to_the_target() {
        let agent_path = std::env::temp_dir().join(format!(
            "virtkit-publish-test-{}.socket",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&agent_path);
        let agent_addr = SocketAddr::Unix(agent_path.clone());
        let server_addr = agent_addr.clone();
        tokio::spawn(async move {
            run_server(&server_addr, Some(Duration::from_secs(60)), None, vec![])
                .await
                .unwrap();
        });
        while !agent_path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let echo_addr = echo_server().await;
        let target = format!("tcp://{echo_addr}");

        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();
        drop(front); // free the port for `run` to bind
        let listen: SocketAddr = format!("tcp://{front_addr}").parse().unwrap();
        tokio::spawn(async move {
            let _ = run(&agent_addr, &listen, &target).await;
        });

        let mut client = loop {
            if let Ok(c) = TcpStream::connect(front_addr).await {
                break c;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    async fn greeter_server() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut conn, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = conn.write_all(b"HELLO-BANNER\r\n").await;
                    let mut buf = [0u8; 64];
                    let _ = conn.read(&mut buf).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn relays_a_target_that_speaks_first() {
        let agent_path = std::env::temp_dir().join(format!(
            "virtkit-publish-test-greeter-{}.socket",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&agent_path);
        let agent_addr = SocketAddr::Unix(agent_path.clone());
        let server_addr = agent_addr.clone();
        tokio::spawn(async move {
            run_server(&server_addr, Some(Duration::from_secs(60)), None, vec![])
                .await
                .unwrap();
        });
        while !agent_path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let greet_addr = greeter_server().await;
        let target = format!("tcp://{greet_addr}");

        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();
        drop(front);
        let listen: SocketAddr = format!("tcp://{front_addr}").parse().unwrap();
        tokio::spawn(async move {
            let _ = run(&agent_addr, &listen, &target).await;
        });

        let mut client = loop {
            if let Ok(c) = TcpStream::connect(front_addr).await {
                break c;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        // Read only — the target speaks first, unprompted.
        let mut buf = [0u8; 14];
        tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut buf))
            .await
            .expect("timed out waiting for the unprompted banner")
            .unwrap();
        assert_eq!(&buf, b"HELLO-BANNER\r\n");
    }

    /// `--to` naming a host instead of an IP literal: `SocketAddr::from_str` can't
    /// parse it (that's the whole point — see `parse_publish_to`), so this exercises
    /// the fallback all the way through `run`'s accept loop, not just `--to`'s CLI
    /// validation. "localhost" stands in for a compose sibling's hostname.
    #[tokio::test]
    async fn relays_to_a_hostname_target() {
        let agent_path = std::env::temp_dir().join(format!(
            "virtkit-publish-test-hostname-{}.socket",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&agent_path);
        let agent_addr = SocketAddr::Unix(agent_path.clone());
        let server_addr = agent_addr.clone();
        tokio::spawn(async move {
            run_server(&server_addr, Some(Duration::from_secs(60)), None, vec![])
                .await
                .unwrap();
        });
        while !agent_path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let echo_addr = echo_server().await;
        let target = format!("tcp://localhost:{}", echo_addr.port());

        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();
        drop(front);
        let listen: SocketAddr = format!("tcp://{front_addr}").parse().unwrap();
        tokio::spawn(async move {
            let _ = run(&agent_addr, &listen, &target).await;
        });

        let mut client = loop {
            if let Ok(c) = TcpStream::connect(front_addr).await {
                break c;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut buf))
            .await
            .expect("timed out — the hostname was never resolved")
            .unwrap();
        assert_eq!(&buf, b"ping");
    }

    // ---- managed publishers ----

    struct TmpDir(PathBuf);
    impl Drop for TmpDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    fn state(tag: &str) -> TmpDir {
        let dir = std::env::temp_dir().join(format!("vk-pub-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TmpDir(dir)
    }

    /// A planted lock symlink makes `O_NOFOLLOW` fail, leaving liveness unconfirmed.
    #[test]
    #[allow(clippy::zombie_processes)]
    fn a_publisher_that_cannot_be_confirmed_is_listed_but_never_signalled() {
        let t = state("unconfirmed");
        // Use a real unrelated pid to prove the unconfirmed record cannot signal it.
        let mut victim = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let lock = fake_publisher(
            &t.0,
            "opaque",
            "tcp://127.0.0.1:8500",
            "tcp://svc:80",
            victim.id(),
            None,
        );
        drop(lock);
        let lock_path = dir_of(&t.0).join("opaque.lock");
        std::fs::remove_file(&lock_path).unwrap();
        std::os::unix::fs::symlink(t.0.join("nowhere"), &lock_path).unwrap();

        // Keep the entry because it may still hold an address.
        let live = live_entries(&t.0);
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].1, Liveness::Unknown);
        assert!(list_report(&t.0, false).unwrap().contains("unconfirmed"));
        let json = list_report(&t.0, true).unwrap();
        let raw: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(raw[0]["unconfirmed"], serde_json::json!(true), "{json}");

        // Do not trust or signal its unconfirmed pid.
        let (report, all_down) = stop(&t.0, Some("opaque"), Duration::from_millis(50)).unwrap();
        assert!(report.contains("cannot confirm"), "{report}");
        assert!(!all_down);
        assert!(
            victim.try_wait().unwrap().is_none(),
            "an unconfirmed record must not get a process killed"
        );
        let _ = victim.kill();
        let _ = victim.wait();
    }

    /// VM teardown stops its publishers before their addresses outlive the target.
    #[test]
    fn stopping_a_vm_stops_the_publishers_recorded_for_it() {
        let t = state("teardown");
        let mut victim = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let lock = fake_publisher(
            &t.0,
            "web",
            "tcp://127.0.0.1:8600",
            "vsock://80",
            victim.id(),
            None,
        );
        // The test holds the publisher's lock and drops it to model process exit.
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            drop(lock);
        });

        // Exercise signal-and-wait, not stale-record pruning: `stop` selects the held
        // entry before the delayed release.
        let (report, all_down) = stop(&t.0, None, Duration::from_secs(2)).unwrap();
        assert!(report.contains("stopped web"), "{report}");
        assert!(all_down);
        assert!(
            !entry_path(&t.0, "web").exists(),
            "a stopped publisher leaves no record behind"
        );
        let _ = victim.kill();
        let _ = victim.wait();
    }

    /// Model a live publisher by holding its lifetime lock beside its record. `service`
    /// names the compose sibling that dials, as `--via` does; `None` is the primary.
    fn fake_publisher(
        state_dir: &Path,
        name: &str,
        listen: &str,
        to: &str,
        pid: u32,
        service: Option<&str>,
    ) -> std::fs::File {
        let lock = claim(state_dir, name).unwrap().expect("nothing held it");
        write_entry(
            state_dir,
            &Entry {
                name: name.to_string(),
                listen: listen.to_string(),
                to: to.to_string(),
                service: service.map(str::to_string),
                pid,
                created_secs: 0,
            },
        )
        .unwrap();
        lock
    }

    #[test]
    fn a_publisher_name_stays_inside_the_registry_directory() {
        assert!(validate_name("runner").is_ok());
        assert!(validate_name("runner-2.https_x").is_ok());
        for bad in ["", "../escape", "a/b", "a b", "a\nb", "*"] {
            assert!(validate_name(bad).is_err(), "{bad:?} should be refused");
        }
        assert!(validate_name(&"a".repeat(65)).is_err());
    }

    #[test]
    fn liveness_follows_the_lock_and_never_the_recorded_pid() {
        let t = state("liveness");
        // Model pid reuse with this live process but no held lock. Liveness must follow
        // the lock, and the pid alone must never authorize a signal.
        write_entry(
            &t.0,
            &Entry {
                name: "ghost".into(),
                listen: "tcp://127.0.0.1:1".into(),
                to: "tcp://x:1".into(),
                service: None,
                pid: std::process::id(),
                created_secs: 0,
            },
        )
        .unwrap();
        assert!(live_entries(&t.0).is_empty(), "a lockless record is stale");
        assert!(
            !entry_path(&t.0, "ghost").exists(),
            "and reading the list prunes it"
        );

        // Held: alive, and listed.
        let lock = fake_publisher(
            &t.0,
            "runner",
            "tcp://127.0.0.1:8443",
            "tcp://runner:443",
            4242,
            None,
        );
        let live = live_entries(&t.0);
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].0.name, "runner");
        assert_eq!(live[0].0.pid, 4242);
        assert_eq!(live[0].1, Liveness::Held);

        // Kernel lock release makes even an abruptly killed publisher read as dead.
        drop(lock);
        assert!(live_entries(&t.0).is_empty());
    }

    #[tokio::test]
    async fn ensure_is_a_no_op_for_the_same_spec_and_an_error_for_a_different_one() {
        let t = state("ensure");
        let listen: SocketAddr = "tcp://127.0.0.1:8443".parse().unwrap();
        let agent: SocketAddr = "tcp://127.0.0.1:9".parse().unwrap();
        let _held = fake_publisher(
            &t.0,
            "runner",
            &listen.to_string(),
            "tcp://runner:443",
            4242,
            None,
        );

        // An equivalent live publisher satisfies concurrent `ensure` calls without
        // contacting the VM or creating a duplicate listener.
        let again = ensure(&t.0, "runner", &agent, &listen, "tcp://runner:443", None)
            .await
            .unwrap();
        assert!(matches!(again, Ensured::AlreadyRunning(e) if e.pid == 4242));

        // A conflicting target must fail rather than preserve the wrong route.
        let err = ensure(&t.0, "runner", &agent, &listen, "tcp://other:443", None)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("already runs") && msg.contains("tcp://other:443"),
            "{msg}"
        );

        // A different dialer is a different route too, and the message names it as the
        // flag does.
        let err = ensure(
            &t.0,
            "runner",
            &agent,
            &listen,
            "tcp://runner:443",
            Some("db"),
        )
        .await
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("(via db)"), "{msg}");

        // And the running publisher's own sibling is named the same way when the request
        // drops it.
        let t = state("ensure-via");
        let _dialled = fake_publisher(
            &t.0,
            "runner",
            &listen.to_string(),
            "tcp://runner:443",
            4242,
            Some("db"),
        );
        let err = ensure(&t.0, "runner", &agent, &listen, "tcp://runner:443", None)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("(via db)"), "{msg}");
    }

    #[tokio::test]
    async fn a_taken_listen_address_is_told_apart_from_other_bind_failures() {
        // The dedicated classifier lets address allocators retry. Test it directly because
        // reaching this path through `ensure` requires a running VM.
        let squatter = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let taken: SocketAddr = format!("tcp://{}", squatter.local_addr().unwrap())
            .parse()
            .unwrap();
        let Err(err) = raw_listen(&taken).await else {
            panic!("binding a taken address should fail");
        };
        assert!(is_addr_in_use(&err), "{err:#}");

        // An unbindable host is not an address-in-use retry.
        let unbindable: SocketAddr = "tcp://192.0.2.1:9".parse().unwrap();
        if let Err(e) = raw_listen(&unbindable).await {
            assert!(!is_addr_in_use(&e), "{e:#}");
        }
    }

    #[test]
    fn stopping_prunes_records_and_reports_nothing_to_stop() {
        let t = state("stop");
        let (report, all_down) = stop(&t.0, None, Duration::from_secs(1)).unwrap();
        assert!(all_down && report.contains("no publishers"), "{report}");

        // A stale record is not something to stop, and does not survive the attempt.
        write_entry(
            &t.0,
            &Entry {
                name: "ghost".into(),
                listen: "tcp://127.0.0.1:1".into(),
                to: "tcp://x:1".into(),
                service: None,
                pid: std::process::id(),
                created_secs: 0,
            },
        )
        .unwrap();
        let (report, all_down) = stop(&t.0, Some("ghost"), Duration::from_secs(1)).unwrap();
        assert!(all_down, "{report}");
        assert!(!entry_path(&t.0, "ghost").exists());
    }

    /// `vk list` reads publishers through `live`: none for a state dir that never published
    /// (and no `publish/` dir appears for asking), the held ones once it has.
    #[test]
    fn live_lists_the_held_publishers_and_creates_nothing() {
        let t = state("live");
        assert!(live(&t.0).unwrap().is_empty());
        assert!(
            !dir_of(&t.0).exists(),
            "listing must not create the publish dir"
        );
        let _held = fake_publisher(
            &t.0,
            "runner",
            "tcp://127.0.0.1:8443",
            "tcp://runner:443",
            7,
            None,
        );
        let live = live(&t.0).unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].0.name, "runner");
        assert_eq!(live[0].1, Liveness::Held);
    }

    #[test]
    fn the_list_reports_what_holds_its_lock() {
        let t = state("list");
        let _held = fake_publisher(
            &t.0,
            "runner",
            "tcp://127.0.0.1:8443",
            "tcp://runner:443",
            7,
            None,
        );
        let text = list_report(&t.0, false).unwrap();
        assert!(
            text.contains("runner") && text.contains("tcp://127.0.0.1:8443"),
            "{text}"
        );
        let json = list_report(&t.0, true).unwrap();
        let parsed: Vec<Entry> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].to, "tcp://runner:443");
        // Inspect raw keys: `Entry` ignores unknown keys and cannot detect an unwanted marker.
        let raw: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        let record = raw[0].as_object().unwrap();
        assert!(!record.contains_key("unconfirmed"), "{json}");
        // The primary dials, so there is no sibling to name — under either key, since the
        // old one is only an alias for reading.
        assert!(!record.contains_key("via"), "{json}");
        assert!(!record.contains_key("service"), "{json}");

        // A sibling-dialled publisher names it, under the new key only.
        let _dialled = fake_publisher(
            &t.0,
            "pg",
            "tcp://127.0.0.1:5432",
            "tcp://127.0.0.1:5432",
            8,
            Some("db"),
        );
        let json = list_report(&t.0, true).unwrap();
        let raw: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        let dialled = raw
            .iter()
            .find(|r| r["name"] == "pg")
            .and_then(|r| r.as_object())
            .expect("the sibling-dialled record is listed");
        assert_eq!(dialled["via"], "db", "{json}");
        assert!(!dialled.contains_key("service"), "{json}");
    }

    #[test]
    fn a_record_written_before_the_rename_still_names_its_sibling() {
        // `via` used to be `service`; a state dir surviving an upgrade holds the old key.
        let old: Entry = serde_json::from_str(
            r#"{"name":"pg","listen":"tcp://127.0.0.1:5432","to":"tcp://127.0.0.1:5432",
                "service":"db","pid":7}"#,
        )
        .unwrap();
        assert_eq!(old.service.as_deref(), Some("db"));
        // Written back under the new key only.
        let round = serde_json::to_value(&old).unwrap();
        assert_eq!(round["via"], "db");
        assert!(
            !round.as_object().unwrap().contains_key("service"),
            "{round}"
        );
    }
}
